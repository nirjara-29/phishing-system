import React from 'react';
import { Globe, Mail, ShieldAlert, ShieldCheck, Activity, Clock } from 'lucide-react';

const STAT_CARDS = [
  { key: 'total_url_scans', label: 'URL Scans', icon: Globe, color: 'text-brand-600', bg: 'bg-brand-50' },
  { key: 'total_email_scans', label: 'Email Scans', icon: Mail, color: 'text-purple-600', bg: 'bg-purple-50' },
  { key: 'phishing_detected', label: 'Phishing Detected', icon: ShieldAlert, color: 'text-danger-600', bg: 'bg-danger-50' },
  { key: 'safe_detected', label: 'Safe', icon: ShieldCheck, color: 'text-success-600', bg: 'bg-success-50' },
  { key: 'scans_today', label: 'Scans Today', icon: Activity, color: 'text-indigo-600', bg: 'bg-indigo-50' },
  { key: 'avg_scan_time_ms', label: 'Avg Scan Time', icon: Clock, color: 'text-gray-600', bg: 'bg-gray-100', suffix: 'ms' },
];

export default function StatsCards({ stats }) {
  if (!stats) return null;

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
      {STAT_CARDS.map(({ key, label, icon: Icon, color, bg, suffix }) => (
        <div key={key} className="card flex items-center gap-4">
          <div className={`flex h-11 w-11 items-center justify-center rounded-lg ${bg}`}>
            <Icon className={`h-5 w-5 ${color}`} />
          </div>
          <div>
            <p className="text-xs font-medium text-gray-500">{label}</p>
            <p className="text-xl font-bold text-gray-900">
              {typeof stats[key] === 'number'
                ? key.includes('rate')
                  ? `${(stats[key] * 100).toFixed(1)}%`
                  : stats[key].toLocaleString()
                : '--'}
              {suffix && <span className="text-xs text-gray-400 ml-0.5">{suffix}</span>}
            </p>
          </div>
        </div>
      ))}
    </div>
  );
}
