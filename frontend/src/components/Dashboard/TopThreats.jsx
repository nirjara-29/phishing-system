import React from 'react';
import Badge from '../Common/Badge';

export default function TopThreats({ threats }) {
  if (!threats || threats.length === 0) {
    return (
      <div className="card">
        <h3 className="text-sm font-semibold text-gray-700 mb-4">Top Threat Domains</h3>
        <p className="text-sm text-gray-400 py-4 text-center">No threats detected recently</p>
      </div>
    );
  }

  return (
    <div className="card">
      <h3 className="text-sm font-semibold text-gray-700 mb-4">Top Threat Domains</h3>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-100 text-left text-xs font-medium uppercase text-gray-500">
              <th className="pb-3 pr-4">Domain</th>
              <th className="pb-3 pr-4">Detections</th>
              <th className="pb-3 pr-4">Severity</th>
              <th className="pb-3">Last Seen</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-50">
            {threats.map((t, i) => (
              <tr key={i} className="hover:bg-gray-50">
                <td className="py-2.5 pr-4 font-mono text-xs text-gray-800">{t.domain}</td>
                <td className="py-2.5 pr-4">
                  <span className="font-semibold text-gray-900">{t.count}</span>
                </td>
                <td className="py-2.5 pr-4">
                  <Badge label={t.severity} />
                </td>
                <td className="py-2.5 text-xs text-gray-500">
                  {t.last_seen
                    ? new Date(t.last_seen).toLocaleDateString()
                    : '--'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
