import React from 'react';
import { ArrowLeft } from 'lucide-react';
import Badge from '../Common/Badge';
import Button from '../Common/Button';

export default function ThreatDetail({ threat, onBack }) {
  if (!threat) return null;

  return (
    <div className="space-y-4">
      <button
        onClick={onBack}
        className="flex items-center gap-1 text-sm text-gray-500 hover:text-gray-700"
      >
        <ArrowLeft size={14} /> Back to list
      </button>

      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-gray-900">Threat Indicator</h2>
          <Badge label={threat.severity} />
        </div>

        <dl className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div>
            <dt className="text-xs font-medium text-gray-500 uppercase">Type</dt>
            <dd className="mt-1 text-sm text-gray-800">{threat.indicator_type}</dd>
          </div>
          <div>
            <dt className="text-xs font-medium text-gray-500 uppercase">Value</dt>
            <dd className="mt-1 text-sm font-mono text-gray-800 break-all">{threat.value}</dd>
          </div>
          <div>
            <dt className="text-xs font-medium text-gray-500 uppercase">Source</dt>
            <dd className="mt-1 text-sm text-gray-800">{threat.source || 'Unknown'}</dd>
          </div>
          <div>
            <dt className="text-xs font-medium text-gray-500 uppercase">Threat Type</dt>
            <dd className="mt-1 text-sm text-gray-800">{threat.threat_type || 'Unspecified'}</dd>
          </div>
          <div>
            <dt className="text-xs font-medium text-gray-500 uppercase">First Seen</dt>
            <dd className="mt-1 text-sm text-gray-800">
              {threat.first_seen ? new Date(threat.first_seen).toLocaleString() : '--'}
            </dd>
          </div>
          <div>
            <dt className="text-xs font-medium text-gray-500 uppercase">Last Seen</dt>
            <dd className="mt-1 text-sm text-gray-800">
              {threat.last_seen ? new Date(threat.last_seen).toLocaleString() : '--'}
            </dd>
          </div>
          <div>
            <dt className="text-xs font-medium text-gray-500 uppercase">Status</dt>
            <dd className="mt-1">
              <Badge label={threat.is_active ? 'Active' : 'Inactive'} variant={threat.is_active ? 'safe' : 'unknown'} />
            </dd>
          </div>
          <div>
            <dt className="text-xs font-medium text-gray-500 uppercase">Created</dt>
            <dd className="mt-1 text-sm text-gray-800">
              {new Date(threat.created_at).toLocaleString()}
            </dd>
          </div>
        </dl>

        {threat.tags && threat.tags.length > 0 && (
          <div className="mt-4">
            <dt className="text-xs font-medium text-gray-500 uppercase mb-2">Tags</dt>
            <div className="flex flex-wrap gap-2">
              {threat.tags.map((tag) => (
                <Badge key={tag} label={tag} variant="info" />
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
