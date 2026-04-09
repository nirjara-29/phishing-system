import React from 'react';
import { Globe, Mail } from 'lucide-react';
import Badge from '../Common/Badge';

export default function RecentScans({ scans }) {
  if (!scans || scans.length === 0) {
    return (
      <div className="card">
        <h3 className="text-sm font-semibold text-gray-700 mb-4">Recent Scans</h3>
        <p className="text-sm text-gray-400 py-4 text-center">No recent scan activity</p>
      </div>
    );
  }

  return (
    <div className="card">
      <h3 className="text-sm font-semibold text-gray-700 mb-4">Recent Scans</h3>
      <ul className="divide-y divide-gray-50">
        {scans.slice(0, 10).map((scan) => (
          <li key={scan.scan_id} className="flex items-center gap-3 py-3">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gray-100">
              {scan.scan_type === 'url' ? (
                <Globe className="h-4 w-4 text-brand-600" />
              ) : (
                <Mail className="h-4 w-4 text-purple-600" />
              )}
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm text-gray-800 truncate">{scan.target}</p>
              <p className="text-xs text-gray-400">
                {new Date(scan.created_at).toLocaleString()}
              </p>
            </div>
            <div className="flex items-center gap-2">
              {scan.confidence_score != null && (
                <span className="text-xs font-medium text-gray-500">
                  {Math.round(scan.confidence_score * 100)}%
                </span>
              )}
              <Badge label={scan.verdict || 'pending'} />
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
