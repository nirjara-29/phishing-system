import React, { useState } from 'react';
import ThreatList from '../components/Threats/ThreatList';
import ThreatDetail from '../components/Threats/ThreatDetail';

export default function ThreatsPage() {
  const [selected, setSelected] = useState(null);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Threat Intelligence</h1>
        <p className="text-sm text-gray-500 mt-1">
          Manage known threat indicators and IOC feeds
        </p>
      </div>

      {selected ? (
        <ThreatDetail threat={selected} onBack={() => setSelected(null)} />
      ) : (
        <ThreatList onSelect={setSelected} />
      )}
    </div>
  );
}
