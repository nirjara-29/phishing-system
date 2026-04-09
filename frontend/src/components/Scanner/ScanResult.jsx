import React from 'react';
import { ShieldCheck, ShieldAlert, ShieldQuestion, Clock } from 'lucide-react';
import Badge from '../Common/Badge';
import FeatureBreakdown from './FeatureBreakdown';

const VERDICT_CONFIG = {
  phishing: {
    icon: ShieldAlert,
    color: 'text-danger-600',
    bg: 'bg-danger-50',
    border: 'border-danger-200',
    label: 'Phishing Detected',
  },
  suspicious: {
    icon: ShieldQuestion,
    color: 'text-warning-600',
    bg: 'bg-warning-50',
    border: 'border-warning-200',
    label: 'Suspicious',
  },
  safe: {
    icon: ShieldCheck,
    color: 'text-success-600',
    bg: 'bg-success-50',
    border: 'border-success-200',
    label: 'Safe',
  },
};

export default function ScanResult({ scan, type = 'url' }) {
  const verdict = scan.verdict || 'unknown';
  const config = VERDICT_CONFIG[verdict] || VERDICT_CONFIG.suspicious;
  const Icon = config.icon || ShieldQuestion;

  const confidenceValue = typeof scan.confidence === 'number' ? scan.confidence : scan.confidence_score || 0;
  const confidencePct = Math.round(confidenceValue * 100);

  return (
    <div className="space-y-4">
      {/* Verdict banner */}
      <div className={`card ${config.bg} border ${config.border}`}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Icon className={`h-10 w-10 ${config.color}`} />
            <div>
              <h3 className={`text-xl font-bold ${config.color}`}>{config.label}</h3>
              <p className="text-sm text-gray-600 mt-0.5">
                {type === 'url' ? scan.url : scan.sender || scan.subject || 'Email'}
              </p>
            </div>
          </div>
          <div className="text-right">
            <p className={`text-3xl font-bold ${config.color}`}>{confidencePct}%</p>
            <p className="text-xs text-gray-500">confidence</p>
          </div>
        </div>
      </div>

      {/* Score details */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="card">
          <p className="text-xs font-medium text-gray-500 uppercase">Verdict</p>
          <div className="mt-2"><Badge label={verdict} /></div>
        </div>
        <div className="card">
          <p className="text-xs font-medium text-gray-500 uppercase">Risk Level</p>
          <div className="mt-2"><Badge label={scan.risk_level || 'unknown'} /></div>
        </div>
        <div className="card">
          <p className="text-xs font-medium text-gray-500 uppercase">Scan ID</p>
          <p className="mt-2 text-sm font-mono text-gray-700 truncate">{scan.scan_id || 'N/A'}</p>
        </div>
        <div className="card">
          <p className="text-xs font-medium text-gray-500 uppercase">Duration</p>
          <div className="mt-2 flex items-center gap-1 text-sm text-gray-700">
            <Clock size={14} />
            {scan.scan_duration_ms ? `${scan.scan_duration_ms}ms` : 'N/A'}
          </div>
        </div>
      </div>

      {/* Model scores (URL scan) */}
      {type === 'url' && (scan.rf_score != null || scan.gb_score != null) && (
        <div className="card">
          <h4 className="text-sm font-semibold text-gray-700 mb-3">Model Scores</h4>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            {[
              { label: 'Random Forest', score: scan.rf_score },
              { label: 'Gradient Boosting', score: scan.gb_score },
              { label: 'BERT', score: scan.bert_score },
            ].map(({ label, score }) => (
              <div key={label} className="rounded-lg border border-gray-100 p-3">
                <p className="text-xs text-gray-500">{label}</p>
                <p className="text-lg font-bold text-gray-800">
                  {score != null ? `${Math.round(score * 100)}%` : '--'}
                </p>
                <div className="mt-1.5 h-1.5 w-full rounded-full bg-gray-100">
                  <div
                    className="h-1.5 rounded-full bg-brand-500 transition-all"
                    style={{ width: `${(score || 0) * 100}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Email-specific: auth results */}
      {type === 'email' && scan.auth_result && (
        <div className="card">
          <h4 className="text-sm font-semibold text-gray-700 mb-3">Email Authentication</h4>
          <div className="flex gap-4 flex-wrap">
            {['spf', 'dkim', 'dmarc'].map((mech) => {
              const result = scan.auth_result[`${mech}_result`] || 'none';
              return (
                <div key={mech} className="rounded-lg border border-gray-100 px-4 py-2">
                  <p className="text-xs text-gray-500 uppercase">{mech}</p>
                  <Badge label={result} />
                </div>
              );
            })}
          </div>
        </div>
      )}

      {Array.isArray(scan.reasons) && scan.reasons.length > 0 && (
        <div className="card">
          <h4 className="text-sm font-semibold text-gray-700 mb-3">Why flagged?</h4>
          <div className="space-y-2">
            {scan.reasons.map((reason, index) => (
              <div key={`${reason}-${index}`} className="rounded-lg border border-gray-100 px-3 py-2 text-sm text-gray-600">
                {reason}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Feature breakdown chart */}
      {scan.features && <FeatureBreakdown features={scan.features} />}
    </div>
  );
}
