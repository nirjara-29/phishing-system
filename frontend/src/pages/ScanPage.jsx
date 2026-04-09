import React, { useState } from 'react';
import { Globe, Mail } from 'lucide-react';
import UrlScanner from '../components/Scanner/UrlScanner';
import EmailScanner from '../components/Scanner/EmailScanner';

export default function ScanPage() {
  const [tab, setTab] = useState('url');

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Scan</h1>
        <p className="text-sm text-gray-500 mt-1">
          Analyze URLs and emails for phishing threats
        </p>
      </div>

      {/* Tab switcher */}
      <div className="flex gap-2 border-b border-gray-200 pb-0">
        <button
          onClick={() => setTab('url')}
          className={`flex items-center gap-2 border-b-2 px-4 py-2.5 text-sm font-medium transition-colors ${
            tab === 'url'
              ? 'border-brand-600 text-brand-600'
              : 'border-transparent text-gray-500 hover:text-gray-700'
          }`}
        >
          <Globe size={16} /> URL Scanner
        </button>
        <button
          onClick={() => setTab('email')}
          className={`flex items-center gap-2 border-b-2 px-4 py-2.5 text-sm font-medium transition-colors ${
            tab === 'email'
              ? 'border-purple-600 text-purple-600'
              : 'border-transparent text-gray-500 hover:text-gray-700'
          }`}
        >
          <Mail size={16} /> Email Scanner
        </button>
      </div>

      {/* Scanner content */}
      {tab === 'url' ? <UrlScanner /> : <EmailScanner />}
    </div>
  );
}
