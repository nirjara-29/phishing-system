import React, { useState } from 'react';
import { Search, Globe, AlertTriangle, ShieldCheck } from 'lucide-react';
import { useScanStore } from '../../stores/scanStore';
import Button from '../Common/Button';
import ScanResult from './ScanResult';
import toast from 'react-hot-toast';

export default function UrlScanner() {
  const [url, setUrl] = useState('');
  const { currentScan, scanLoading, scanError, scanUrlAction, clearScan } = useScanStore();

  const handleScan = async (e) => {
    e.preventDefault();
    const trimmed = url.trim();
    if (!trimmed) {
      toast.error('Please enter a URL');
      return;
    }
    try {
      await scanUrlAction(trimmed);
      toast.success('Scan complete');
    } catch {
      toast.error(scanError || 'Unable to analyze. Please try again.');
    }
  };

  const handleClear = () => {
    setUrl('');
    clearScan();
  };

  return (
    <div className="space-y-6">
      {/* Scan input */}
      <div className="card">
        <div className="flex items-center gap-3 mb-4">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-brand-50">
            <Globe className="h-5 w-5 text-brand-600" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-gray-900">URL Scanner</h2>
            <p className="text-sm text-gray-500">
              Enter a URL to analyze for phishing indicators
            </p>
          </div>
        </div>

        <form onSubmit={handleScan} className="flex gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-400" />
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://suspicious-site.example.com/login"
              className="input-field pl-10"
              disabled={scanLoading}
            />
          </div>
          <Button type="submit" loading={scanLoading}>
            Scan URL
          </Button>
          {currentScan && (
            <Button type="button" variant="ghost" onClick={handleClear}>
              Clear
            </Button>
          )}
        </form>

        {scanError && (
          <div className="mt-4 flex items-center gap-2 rounded-lg bg-danger-50 px-4 py-3 text-sm text-danger-700">
            <AlertTriangle size={16} />
            {scanError}
          </div>
        )}
      </div>

      {/* Quick tips */}
      {!currentScan && !scanLoading && (
        <div className="card bg-gray-50 border-dashed">
          <h3 className="text-sm font-medium text-gray-700 mb-3">What we analyze</h3>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {[
              { title: 'URL Structure', desc: 'Length, entropy, special chars, punycode' },
              { title: 'Domain Intel', desc: 'WHOIS age, registrar, DNS records' },
              { title: 'SSL Certificate', desc: 'Validity, issuer, expiration' },
              { title: 'Page Content', desc: 'Login forms, brand logos, obfuscation' },
            ].map((item) => (
              <div key={item.title} className="rounded-lg bg-white p-3 border border-gray-100">
                <p className="text-sm font-medium text-gray-800">{item.title}</p>
                <p className="text-xs text-gray-500 mt-1">{item.desc}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Loading state */}
      {scanLoading && (
        <div className="card text-center py-12">
          <div className="mx-auto mb-4 h-10 w-10 animate-spin rounded-full border-4 border-brand-200 border-t-brand-600" />
          <p className="text-sm text-gray-500">Analyzing URL across all detection engines...</p>
          <p className="text-xs text-gray-400 mt-1">
            Feature extraction, ML ensemble, threat intelligence lookup
          </p>
        </div>
      )}

      {/* Results */}
      {currentScan && !scanLoading && <ScanResult scan={currentScan} type="url" />}
    </div>
  );
}
