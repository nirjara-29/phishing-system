import React, { useMemo } from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts';

const FEATURE_LABELS = {
  url_length: 'URL Length',
  domain_length: 'Domain Length',
  subdomain_count: 'Subdomain Count',
  digit_ratio: 'Digit Ratio',
  special_char_ratio: 'Special Char Ratio',
  url_entropy: 'URL Entropy',
  domain_entropy: 'Domain Entropy',
  has_ip_address: 'IP Address',
  is_punycode: 'Punycode',
  suspicious_keyword_count: 'Suspicious Keywords',
  domain_age_days: 'Domain Age (days)',
  external_resource_ratio: 'External Resources',
  brand_similarity_score: 'Brand Similarity',
  has_login_form: 'Login Form',
  phishing_keyword_count: 'Phishing Keywords',
  obfuscation_score: 'Obfuscation',
  urgency_score: 'Urgency Score',
  brand_impersonation_score: 'Brand Impersonation',
  email_risk_score: 'Email Risk',
};

function getBarColor(value) {
  if (value >= 0.7) return '#ef4444';
  if (value >= 0.4) return '#f59e0b';
  return '#22c55e';
}

export default function FeatureBreakdown({ features }) {
  const chartData = useMemo(() => {
    if (!features || typeof features !== 'object') return [];

    return Object.entries(features)
      .filter(([key, val]) => typeof val === 'number' && !key.endsWith('_count'))
      .map(([key, value]) => ({
        name: FEATURE_LABELS[key] || key.replace(/_/g, ' '),
        value: Math.min(Math.abs(value), 1),
        raw: value,
      }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 12);
  }, [features]);

  if (chartData.length === 0) return null;

  return (
    <div className="card">
      <h4 className="text-sm font-semibold text-gray-700 mb-4">Feature Importance</h4>
      <ResponsiveContainer width="100%" height={320}>
        <BarChart data={chartData} layout="vertical" margin={{ left: 120, right: 20 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#f3f4f6" />
          <XAxis type="number" domain={[0, 1]} tick={{ fontSize: 11 }} />
          <YAxis
            type="category"
            dataKey="name"
            tick={{ fontSize: 11 }}
            width={110}
          />
          <Tooltip
            formatter={(value) => [`${(value * 100).toFixed(1)}%`, 'Score']}
            contentStyle={{ fontSize: 12, borderRadius: 8 }}
          />
          <Bar dataKey="value" radius={[0, 4, 4, 0]} maxBarSize={20}>
            {chartData.map((entry, i) => (
              <Cell key={i} fill={getBarColor(entry.value)} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
