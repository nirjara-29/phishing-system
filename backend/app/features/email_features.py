"""Email feature extraction for phishing detection.

Analyzes email headers for authentication status (SPF, DKIM, DMARC),
body content for urgency language and brand impersonation, extracts
embedded URLs, and evaluates attachment risk.
"""

import re
from email import policy
from email.parser import BytesParser, Parser
from typing import Any, Dict, List, Optional, Tuple

import structlog

logger = structlog.get_logger(__name__)

# Urgency keywords ranked by phishing correlation
URGENCY_KEYWORDS = {
    "tier_1": {  # Very strong phishing signal
        "account suspended",
        "account will be closed",
        "unauthorized transaction",
        "immediate action required",
        "your account has been compromised",
        "verify your identity immediately",
        "failure to respond will result in",
        "within 24 hours",
        "within 48 hours",
    },
    "tier_2": {  # Strong phishing signal
        "verify your account",
        "confirm your identity",
        "unusual activity",
        "suspicious activity",
        "security alert",
        "update your payment",
        "click here to verify",
        "reset your password",
        "unauthorized access",
        "limited time",
    },
    "tier_3": {  # Moderate signal
        "act now",
        "important notice",
        "action required",
        "please verify",
        "click the link below",
        "update required",
        "confirm your details",
        "congratulations",
        "you have been selected",
        "claim your",
    },
}

# Brand impersonation patterns
BRAND_PATTERNS = {
    "paypal": {
        "sender_patterns": [r"paypa[l1]", r"pay-?pal", r"pp.*service"],
        "subject_patterns": [r"paypal", r"payment.*received", r"transaction.*alert"],
        "body_patterns": [r"paypal\.com", r"paypal account", r"paypal security"],
    },
    "apple": {
        "sender_patterns": [r"app[l1]e", r"icloud", r"apple.*id"],
        "subject_patterns": [r"apple", r"icloud", r"app store", r"itunes"],
        "body_patterns": [r"apple\.com", r"apple id", r"icloud account"],
    },
    "microsoft": {
        "sender_patterns": [r"micr[o0]s[o0]ft", r"outlook", r"office.*365"],
        "subject_patterns": [r"microsoft", r"office 365", r"outlook", r"onedrive"],
        "body_patterns": [r"microsoft\.com", r"office365", r"outlook\.com"],
    },
    "amazon": {
        "sender_patterns": [r"amaz[o0]n", r"amazon.*prime"],
        "subject_patterns": [r"amazon", r"prime", r"your order"],
        "body_patterns": [r"amazon\.com", r"amazon account", r"prime membership"],
    },
    "google": {
        "sender_patterns": [r"g[o0][o0]g[l1]e", r"gmail"],
        "subject_patterns": [r"google", r"gmail", r"google account"],
        "body_patterns": [r"google\.com", r"gmail\.com", r"google account"],
    },
    "netflix": {
        "sender_patterns": [r"netf[l1]ix"],
        "subject_patterns": [r"netflix", r"subscription", r"membership"],
        "body_patterns": [r"netflix\.com", r"netflix account"],
    },
}

# Suspicious sender patterns
SUSPICIOUS_SENDER_PATTERNS = [
    r"noreply.*@(?!google|apple|microsoft|amazon)",
    r"support.*@(?!google|apple|microsoft|amazon)",
    r"security.*@(?!google|apple|microsoft|amazon)",
    r"admin.*@(?!google|apple|microsoft|amazon)",
    r".*@.*\.tk$",
    r".*@.*\.ml$",
    r".*@.*\.xyz$",
]

# URL extraction regex
URL_PATTERN = re.compile(
    r"https?://[^\s<>\"'\])]+"
    r"|www\.[^\s<>\"'\])]+"
)

# Email address regex
EMAIL_PATTERN = re.compile(
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
)


class EmailFeatureExtractor:
    """Extract features from email content for phishing detection.

    Analyzes three aspects of the email:
    1. Headers: SPF, DKIM, DMARC authentication
    2. Body: NLP urgency detection, brand impersonation
    3. Structure: Links, attachments, HTML tricks
    """

    def extract(self, raw_email: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        """Extract all email features.

        Can accept either raw email text (with headers) or individual
        fields (sender, subject, body_text, body_html, headers dict).
        """
        features = self._default_features()

        if raw_email:
            parsed = self._parse_raw_email(raw_email)
            sender = parsed.get("sender", "")
            subject = parsed.get("subject", "")
            body_text = parsed.get("body_text", "")
            body_html = parsed.get("body_html", "")
            headers = parsed.get("headers", {})
        else:
            sender = kwargs.get("sender", "")
            subject = kwargs.get("subject", "")
            body_text = kwargs.get("body_text", "")
            body_html = kwargs.get("body_html", "")
            headers = kwargs.get("headers", {})

        # Header authentication analysis
        features.update(self._analyze_authentication(headers))

        # Sender analysis
        features.update(self._analyze_sender(sender))

        # Subject analysis
        features.update(self._analyze_subject(subject))

        # Body content analysis
        body_features = self._analyze_body(body_text, body_html)
        features.update(body_features)

        # URL extraction and analysis
        all_text = f"{body_text} {body_html}"
        features.update(self._extract_and_analyze_urls(all_text))

        # Brand impersonation scoring
        features.update(
            self._score_brand_impersonation(sender, subject, all_text)
        )

        # Compute overall urgency score
        features["urgency_score"] = self._compute_urgency_score(features)

        # Compute email risk score
        features["email_risk_score"] = self._compute_email_risk(features)

        logger.debug(
            "Email features extracted",
            sender=sender[:50] if sender else "",
            urgency=features["urgency_score"],
            brand_score=features.get("brand_impersonation_score"),
        )

        return features

    def _parse_raw_email(self, raw_email: str) -> Dict[str, Any]:
        """Parse raw email text into structured components."""
        result = {
            "sender": "",
            "subject": "",
            "body_text": "",
            "body_html": "",
            "headers": {},
        }

        try:
            msg = Parser(policy=policy.default).parsestr(raw_email)

            result["sender"] = str(msg.get("From", ""))
            result["subject"] = str(msg.get("Subject", ""))

            # Extract all headers
            for key in msg.keys():
                result["headers"][key.lower()] = str(msg[key])

            # Extract body
            if msg.is_multipart():
                for part in msg.walk():
                    ct = part.get_content_type()
                    if ct == "text/plain":
                        payload = part.get_payload(decode=True)
                        if payload:
                            result["body_text"] = payload.decode("utf-8", errors="replace")
                    elif ct == "text/html":
                        payload = part.get_payload(decode=True)
                        if payload:
                            result["body_html"] = payload.decode("utf-8", errors="replace")
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    text = payload.decode("utf-8", errors="replace")
                    if msg.get_content_type() == "text/html":
                        result["body_html"] = text
                    else:
                        result["body_text"] = text

        except Exception as e:
            logger.warning("Email parsing failed", error=str(e))

        return result

    def _analyze_authentication(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze SPF, DKIM, and DMARC authentication results from headers."""
        features = {
            "spf_result": "none",
            "dkim_result": "none",
            "dmarc_result": "none",
            "auth_results_present": False,
        }

        # Check Authentication-Results header
        auth_results = headers.get("authentication-results", "").lower()
        if auth_results:
            features["auth_results_present"] = True

            # SPF
            spf_match = re.search(r"spf=(pass|fail|softfail|neutral|none|temperror|permerror)", auth_results)
            if spf_match:
                features["spf_result"] = spf_match.group(1)

            # DKIM
            dkim_match = re.search(r"dkim=(pass|fail|none|neutral|temperror|permerror)", auth_results)
            if dkim_match:
                features["dkim_result"] = dkim_match.group(1)

            # DMARC
            dmarc_match = re.search(r"dmarc=(pass|fail|none|bestguesspass|temperror|permerror)", auth_results)
            if dmarc_match:
                features["dmarc_result"] = dmarc_match.group(1)

        # Also check dedicated headers
        received_spf = headers.get("received-spf", "").lower()
        if received_spf:
            for result in ["pass", "fail", "softfail", "neutral"]:
                if result in received_spf:
                    features["spf_result"] = result
                    break

        dkim_signature = headers.get("dkim-signature", "")
        if dkim_signature:
            features["dkim_result"] = features.get("dkim_result", "present")

        return features

    def _analyze_sender(self, sender: str) -> Dict[str, Any]:
        """Analyze the sender address for suspicious patterns."""
        features = {
            "sender_domain": "",
            "sender_display_name": "",
            "sender_name_email_mismatch": False,
            "sender_is_freemail": False,
            "sender_suspicious_pattern": False,
            "sender_has_numbers": False,
        }

        if not sender:
            return features

        # Extract email from "Display Name <email@example.com>" format
        email_match = EMAIL_PATTERN.search(sender)
        if email_match:
            email_addr = email_match.group()
            domain = email_addr.split("@")[1].lower()
            features["sender_domain"] = domain

            # Display name vs email mismatch
            display_name = sender.split("<")[0].strip().strip('"').lower()
            features["sender_display_name"] = display_name
            if display_name and domain:
                # Check if display name looks like a different domain
                if "." in display_name and domain not in display_name:
                    features["sender_name_email_mismatch"] = True

            # Free email providers
            free_providers = {
                "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
                "aol.com", "icloud.com", "mail.com", "protonmail.com",
                "zoho.com", "yandex.com",
            }
            features["sender_is_freemail"] = domain in free_providers

            # Suspicious patterns
            for pattern in SUSPICIOUS_SENDER_PATTERNS:
                if re.search(pattern, email_addr, re.I):
                    features["sender_suspicious_pattern"] = True
                    break

            # Numbers in local part
            local_part = email_addr.split("@")[0]
            features["sender_has_numbers"] = bool(re.search(r"\d", local_part))

        return features

    def _analyze_subject(self, subject: str) -> Dict[str, Any]:
        """Analyze the email subject for urgency and phishing indicators."""
        features = {
            "subject_length": len(subject),
            "subject_has_urgency": False,
            "subject_has_re_fwd": False,
            "subject_all_caps_ratio": 0.0,
            "subject_has_special_chars": False,
            "subject_urgency_word_count": 0,
        }

        if not subject:
            return features

        subject_lower = subject.lower()

        # RE:/FWD: headers (social engineering)
        features["subject_has_re_fwd"] = bool(
            re.match(r"^(re|fwd|fw):\s", subject_lower)
        )

        # Caps ratio
        alpha = [c for c in subject if c.isalpha()]
        if alpha:
            features["subject_all_caps_ratio"] = sum(
                1 for c in alpha if c.isupper()
            ) / len(alpha)

        # Special characters
        features["subject_has_special_chars"] = bool(
            re.search(r"[!]{2,}|[?]{2,}|[\u26A0\u2757\u2755\u203C]", subject)
        )

        # Urgency keywords in subject
        urgency_count = 0
        for tier_keywords in URGENCY_KEYWORDS.values():
            for keyword in tier_keywords:
                if keyword in subject_lower:
                    urgency_count += 1
        features["subject_urgency_word_count"] = urgency_count
        features["subject_has_urgency"] = urgency_count > 0

        return features

    def _analyze_body(self, body_text: str, body_html: str) -> Dict[str, Any]:
        """Analyze email body content for phishing indicators."""
        features = {
            "body_length": len(body_text) + len(body_html),
            "body_urgency_tier1_count": 0,
            "body_urgency_tier2_count": 0,
            "body_urgency_tier3_count": 0,
            "has_html_body": bool(body_html),
            "html_to_text_ratio": 0.0,
            "has_hidden_text": False,
            "has_image_only_body": False,
        }

        combined_text = f"{body_text} {body_html}".lower()

        # Count urgency keywords by tier
        for keyword in URGENCY_KEYWORDS["tier_1"]:
            if keyword in combined_text:
                features["body_urgency_tier1_count"] += 1
        for keyword in URGENCY_KEYWORDS["tier_2"]:
            if keyword in combined_text:
                features["body_urgency_tier2_count"] += 1
        for keyword in URGENCY_KEYWORDS["tier_3"]:
            if keyword in combined_text:
                features["body_urgency_tier3_count"] += 1

        # HTML analysis
        if body_html:
            text_len = len(body_text) if body_text else 0
            html_len = len(body_html)
            if html_len > 0:
                features["html_to_text_ratio"] = text_len / html_len

            # Hidden text detection
            hidden_patterns = [
                r"display\s*:\s*none",
                r"visibility\s*:\s*hidden",
                r"font-size\s*:\s*0",
                r"color\s*:\s*(?:#fff|white|#ffffff)",
                r"opacity\s*:\s*0",
            ]
            for pattern in hidden_patterns:
                if re.search(pattern, body_html, re.I):
                    features["has_hidden_text"] = True
                    break

            # Image-only body (no meaningful text, just images)
            text_content = re.sub(r"<[^>]+>", "", body_html).strip()
            img_count = len(re.findall(r"<img\b", body_html, re.I))
            if img_count > 0 and len(text_content) < 50:
                features["has_image_only_body"] = True

        return features

    def _extract_and_analyze_urls(self, text: str) -> Dict[str, Any]:
        """Extract URLs from email content and analyze them."""
        urls = URL_PATTERN.findall(text)
        unique_urls = list(set(urls))

        features = {
            "link_count": len(unique_urls),
            "unique_domain_count": 0,
            "extracted_urls": unique_urls[:50],  # Cap at 50
            "has_mismatched_urls": False,
            "has_ip_url": False,
            "has_shortened_url": False,
            "suspicious_link_count": 0,
        }

        domains = set()
        suspicious_count = 0
        shorteners = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"}

        for url in unique_urls:
            try:
                from urllib.parse import urlparse

                parsed = urlparse(url)
                domain = parsed.netloc.lower()
                domains.add(domain)

                # IP-based URL
                if re.match(r"\d+\.\d+\.\d+\.\d+", domain):
                    features["has_ip_url"] = True
                    suspicious_count += 1

                # Shortened URL
                if domain in shorteners:
                    features["has_shortened_url"] = True
                    suspicious_count += 1

                # Suspicious TLDs
                if domain.endswith((".tk", ".ml", ".ga", ".cf", ".xyz")):
                    suspicious_count += 1

            except Exception:
                continue

        features["unique_domain_count"] = len(domains)
        features["suspicious_link_count"] = suspicious_count

        # URL/text mismatch: visible text looks like a URL but href is different
        href_pattern = re.compile(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>([^<]+)</a>', re.I)
        for href, text_content in href_pattern.findall(text):
            text_urls = URL_PATTERN.findall(text_content)
            if text_urls:
                # The visible text is a URL — check if it matches the href
                visible_domain = urlparse(text_urls[0]).netloc.lower()
                href_domain = urlparse(href).netloc.lower()
                if visible_domain and href_domain and visible_domain != href_domain:
                    features["has_mismatched_urls"] = True
                    break

        return features

    def _score_brand_impersonation(
        self, sender: str, subject: str, body: str
    ) -> Dict[str, Any]:
        """Score the likelihood of brand impersonation."""
        features = {
            "brand_impersonation_score": 0.0,
            "impersonated_brand": None,
        }

        max_score = 0.0
        detected_brand = None

        for brand, patterns in BRAND_PATTERNS.items():
            score = 0.0

            # Sender patterns
            for pattern in patterns["sender_patterns"]:
                if re.search(pattern, sender, re.I):
                    score += 0.3
                    break

            # Subject patterns
            for pattern in patterns["subject_patterns"]:
                if re.search(pattern, subject, re.I):
                    score += 0.3
                    break

            # Body patterns
            for pattern in patterns["body_patterns"]:
                if re.search(pattern, body, re.I):
                    score += 0.2
                    break

            # Check if sender domain matches the real brand domain
            sender_domain = ""
            email_match = EMAIL_PATTERN.search(sender)
            if email_match:
                sender_domain = email_match.group().split("@")[1].lower()

            # If the sender claims to be the brand but domain doesn't match
            if score > 0 and sender_domain:
                from app.features.content_features import BRAND_SIGNATURES

                brand_sigs = BRAND_SIGNATURES.get(brand, {})
                real_domains = brand_sigs.get("domains", [])
                if not any(sender_domain.endswith(d) for d in real_domains):
                    score += 0.2  # Domain mismatch boosts impersonation score

            if score > max_score:
                max_score = score
                detected_brand = brand

        features["brand_impersonation_score"] = min(max_score, 1.0)
        features["impersonated_brand"] = detected_brand

        return features

    def _compute_urgency_score(self, features: Dict[str, Any]) -> float:
        """Compute a normalized urgency score from keyword counts."""
        score = 0.0

        # Tier 1 keywords have the strongest weight
        score += features.get("body_urgency_tier1_count", 0) * 0.25
        score += features.get("body_urgency_tier2_count", 0) * 0.15
        score += features.get("body_urgency_tier3_count", 0) * 0.08

        # Subject urgency
        score += features.get("subject_urgency_word_count", 0) * 0.12

        # Subject emphasis (caps, special chars)
        if features.get("subject_all_caps_ratio", 0) > 0.5:
            score += 0.1
        if features.get("subject_has_special_chars"):
            score += 0.05

        return min(score, 1.0)

    def _compute_email_risk(self, features: Dict[str, Any]) -> float:
        """Compute an overall email risk score."""
        risk = 0.0

        # Authentication failures
        if features.get("spf_result") == "fail":
            risk += 0.20
        elif features.get("spf_result") != "pass":
            risk += 0.10

        if features.get("dkim_result") == "fail":
            risk += 0.15
        elif features.get("dkim_result") != "pass":
            risk += 0.07

        if features.get("dmarc_result") == "fail":
            risk += 0.15

        # Urgency and brand impersonation
        risk += features.get("urgency_score", 0) * 0.20
        risk += features.get("brand_impersonation_score", 0) * 0.25

        # Suspicious links
        link_count = features.get("link_count", 0)
        suspicious_links = features.get("suspicious_link_count", 0)
        if link_count > 0 and suspicious_links > 0:
            risk += (suspicious_links / max(link_count, 1)) * 0.15

        # URL mismatches
        if features.get("has_mismatched_urls"):
            risk += 0.15

        # Sender analysis
        if features.get("sender_name_email_mismatch"):
            risk += 0.10
        if features.get("sender_suspicious_pattern"):
            risk += 0.10

        return min(risk, 1.0)

    @staticmethod
    def _default_features() -> Dict[str, Any]:
        """Return default feature values."""
        return {
            "spf_result": "none",
            "dkim_result": "none",
            "dmarc_result": "none",
            "urgency_score": 0.0,
            "brand_impersonation_score": 0.0,
            "link_count": 0,
            "suspicious_link_count": 0,
            "email_risk_score": 0.0,
        }
