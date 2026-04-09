import React, { useState } from 'react';
import { Mail, AlertTriangle } from 'lucide-react';
import { useScanStore } from '../../stores/scanStore';
import Button from '../Common/Button';
import ScanResult from './ScanResult';
import toast from 'react-hot-toast';

export default function EmailScanner() {
  const [mode, setMode] = useState('raw');
  const [rawEmail, setRawEmail] = useState('');
  const [fields, setFields] = useState({
    sender: '',
    subject: '',
    body_text: '',
    headers: '',
  });

  const { currentScan, scanLoading, scanError, scanEmailAction, clearScan } = useScanStore();

  const handleScan = async (e) => {
    e.preventDefault();

    let emailText;
    if (mode === 'raw') {
      if (!rawEmail.trim()) {
        toast.error('Please paste email content');
        return;
      }
      emailText = rawEmail.trim();
    } else {
      if (!fields.subject && !fields.body_text) {
        toast.error('Please fill in at least subject or body');
        return;
      }
      emailText = [
        fields.sender ? `From: ${fields.sender}` : '',
        fields.subject ? `Subject: ${fields.subject}` : '',
        fields.body_text || '',
      ]
        .filter(Boolean)
        .join('\n');
    }

    try {
      await scanEmailAction(emailText);
      toast.success('Email scan complete');
    } catch {
      toast.error(scanError || 'Unable to analyze. Please try again.');
    }
  };

  return (
    <div className="space-y-6">
      <div className="card">
        <div className="flex items-center gap-3 mb-4">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-purple-50">
            <Mail className="h-5 w-5 text-purple-600" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-gray-900">Email Scanner</h2>
            <p className="text-sm text-gray-500">
              Paste raw email or fill in fields to check for phishing
            </p>
          </div>
        </div>

        {/* Mode toggle */}
        <div className="mb-4 flex gap-2">
          <button
            onClick={() => setMode('raw')}
            className={`rounded-lg px-4 py-2 text-sm font-medium transition-colors ${
              mode === 'raw'
                ? 'bg-brand-600 text-white'
                : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
            }`}
          >
            Raw Email
          </button>
          <button
            onClick={() => setMode('fields')}
            className={`rounded-lg px-4 py-2 text-sm font-medium transition-colors ${
              mode === 'fields'
                ? 'bg-brand-600 text-white'
                : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
            }`}
          >
            Individual Fields
          </button>
        </div>

        <form onSubmit={handleScan} className="space-y-4">
          {mode === 'raw' ? (
            <textarea
              value={rawEmail}
              onChange={(e) => setRawEmail(e.target.value)}
              placeholder="Paste full email content including headers..."
              rows={12}
              className="input-field font-mono text-xs"
              disabled={scanLoading}
            />
          ) : (
            <div className="space-y-3">
              <input
                placeholder="Sender (e.g. security@bank.com)"
                value={fields.sender}
                onChange={(e) => setFields((p) => ({ ...p, sender: e.target.value }))}
                className="input-field"
              />
              <input
                placeholder="Subject"
                value={fields.subject}
                onChange={(e) => setFields((p) => ({ ...p, subject: e.target.value }))}
                className="input-field"
              />
              <textarea
                placeholder="Email body text"
                rows={6}
                value={fields.body_text}
                onChange={(e) => setFields((p) => ({ ...p, body_text: e.target.value }))}
                className="input-field"
              />
            </div>
          )}

          {scanError && (
            <div className="flex items-center gap-2 rounded-lg bg-danger-50 px-4 py-3 text-sm text-danger-700">
              <AlertTriangle size={16} />
              {scanError}
            </div>
          )}

          <div className="flex gap-3">
            <Button type="submit" loading={scanLoading}>
              Analyze Email
            </Button>
            {currentScan && (
              <Button
                type="button"
                variant="ghost"
                onClick={() => {
                  clearScan();
                  setRawEmail('');
                }}
              >
                Clear
              </Button>
            )}
          </div>
        </form>
      </div>

      {scanLoading && (
        <div className="card text-center py-12">
          <div className="mx-auto mb-4 h-10 w-10 animate-spin rounded-full border-4 border-purple-200 border-t-purple-600" />
          <p className="text-sm text-gray-500">Analyzing email headers, content, and links...</p>
        </div>
      )}

      {currentScan && !scanLoading && <ScanResult scan={currentScan} type="email" />}
    </div>
  );
}
