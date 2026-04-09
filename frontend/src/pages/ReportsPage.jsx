import React, { useState } from 'react';
import { FileBarChart, Download } from 'lucide-react';
import { generateReport } from '../api/dashboard';
import Button from '../components/Common/Button';
import Loading from '../components/Common/Loading';
import toast from 'react-hot-toast';

export default function ReportsPage() {
  const [reportType, setReportType] = useState('weekly');
  const [format, setFormat] = useState('json');
  const [includeDetails, setIncludeDetails] = useState(true);
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState(null);

  const handleGenerate = async () => {
    setLoading(true);
    try {
      const data = await generateReport({
        report_type: reportType,
        format,
        include_details: includeDetails,
      });
      setReport(data);
      toast.success('Report generated');
    } catch {
      toast.error('Failed to generate report');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Reports</h1>
        <p className="text-sm text-gray-500 mt-1">Generate and download detection reports</p>
      </div>

      <div className="card">
        <div className="flex items-center gap-3 mb-6">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-indigo-50">
            <FileBarChart className="h-5 w-5 text-indigo-600" />
          </div>
          <h2 className="text-lg font-semibold text-gray-900">Generate Report</h2>
        </div>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Period</label>
            <select value={reportType} onChange={(e) => setReportType(e.target.value)} className="input-field">
              <option value="daily">Daily</option>
              <option value="weekly">Weekly</option>
              <option value="monthly">Monthly</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Format</label>
            <select value={format} onChange={(e) => setFormat(e.target.value)} className="input-field">
              <option value="json">JSON</option>
              <option value="csv">CSV</option>
              <option value="pdf">PDF</option>
            </select>
          </div>
          <div className="flex items-end">
            <label className="flex items-center gap-2 text-sm text-gray-700">
              <input
                type="checkbox"
                checked={includeDetails}
                onChange={(e) => setIncludeDetails(e.target.checked)}
                className="rounded border-gray-300 text-brand-600 focus:ring-brand-500"
              />
              Include scan details
            </label>
          </div>
        </div>

        <div className="mt-6">
          <Button onClick={handleGenerate} loading={loading}>
            <Download size={16} className="mr-2" /> Generate Report
          </Button>
        </div>
      </div>

      {loading && <Loading text="Generating report..." />}

      {report && (
        <div className="card">
          <h3 className="text-sm font-semibold text-gray-700 mb-4">Report Summary</h3>
          <dl className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            {[
              ['Total Scans', report.summary?.total_scans],
              ['URL Scans', report.summary?.url_scans],
              ['Email Scans', report.summary?.email_scans],
              ['Phishing Found', report.summary?.phishing_count],
              ['Detection Rate', report.summary?.detection_rate
                ? `${(report.summary.detection_rate * 100).toFixed(1)}%`
                : '--'],
              ['Avg Confidence', report.summary?.avg_confidence
                ? `${(report.summary.avg_confidence * 100).toFixed(1)}%`
                : '--'],
            ].map(([label, value]) => (
              <div key={label}>
                <dt className="text-xs font-medium text-gray-500 uppercase">{label}</dt>
                <dd className="mt-1 text-lg font-bold text-gray-900">{value ?? '--'}</dd>
              </div>
            ))}
          </dl>
          <p className="mt-4 text-xs text-gray-400">
            Report ID: {report.report_id} | Generated: {report.generated_at}
          </p>
        </div>
      )}
    </div>
  );
}
