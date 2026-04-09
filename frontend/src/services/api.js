import client from '../api/client';

function normalizeVerdict(value) {
  return value || 'suspicious';
}

function normalizeRiskLevel(value, verdict) {
  if (value === 'critical') {
    return 'high';
  }
  if (value) {
    return value;
  }
  if (verdict === 'phishing') {
    return 'high';
  }
  if (verdict === 'suspicious') {
    return 'medium';
  }
  return 'low';
}

function normalizeConfidence(payload) {
  if (typeof payload.confidence === 'number') {
    return payload.confidence;
  }
  if (typeof payload.confidence_score === 'number') {
    return payload.confidence_score;
  }
  return 0;
}

function buildReasons(payload) {
  if (Array.isArray(payload.reasons) && payload.reasons.length > 0) {
    return payload.reasons;
  }

  const features = payload.features || {};
  const reasons = [];

  if (features.has_mismatched_urls) {
    reasons.push('Links do not appear to match their displayed destination.');
  }
  if (features.suspicious_link_count > 0) {
    reasons.push('Suspicious links were detected in the content.');
  }
  if (features.subject_has_urgency || (features.urgency_score || 0) >= 0.5) {
    reasons.push('Urgent language may be attempting to pressure the user.');
  }
  if ((features.brand_impersonation_score || 0) >= 0.4) {
    reasons.push('Possible brand impersonation was detected.');
  }
  if (features.spf_result === 'fail' || features.dkim_result === 'fail' || features.dmarc_result === 'fail') {
    reasons.push('Email authentication checks reported failures.');
  }

  return reasons;
}

function normalizeUrlResult(payload) {
  const verdict = normalizeVerdict(payload.verdict);

  return {
    ...payload,
    verdict,
    confidence: normalizeConfidence(payload),
    confidence_score: normalizeConfidence(payload),
    risk_level: normalizeRiskLevel(payload.risk_level, verdict),
  };
}

function normalizeEmailResult(payload, emailText) {
  const verdict = normalizeVerdict(payload.verdict);

  return {
    ...payload,
    subject: payload.subject || 'Email',
    sender: payload.sender || undefined,
    raw_email: emailText,
    verdict,
    confidence: normalizeConfidence(payload),
    confidence_score: normalizeConfidence(payload),
    risk_level: normalizeRiskLevel(payload.risk_level, verdict),
    reasons: buildReasons(payload),
  };
}

function toFriendlyError(error) {
  return error?.response?.data?.message || 'Unable to analyze. Please try again.';
}

export async function checkUrl(url) {
  try {
    const { data } = await client.post('/extension/check', {
      url,
      check_cache: true,
    });

    return normalizeUrlResult(data);
  } catch (error) {
    throw new Error(toFriendlyError(error));
  }
}

export async function scanEmail(emailText) {
  try {
    const { data } = await client.post('/emails/scan', {
      email_text: emailText,
    });

    return normalizeEmailResult(data, emailText);
  } catch (error) {
    throw new Error(toFriendlyError(error));
  }
}
