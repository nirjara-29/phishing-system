import React, { useEffect, useState } from 'react';
import { Search, Plus, Trash2 } from 'lucide-react';
import { useThreatStore } from '../../stores/threatStore';
import Badge from '../Common/Badge';
import Button from '../Common/Button';
import Loading from '../Common/Loading';
import Modal from '../Common/Modal';
import toast from 'react-hot-toast';

export default function ThreatList({ onSelect }) {
  const { threats, totalThreats, loading, fetchThreats, addThreat, removeThreat } = useThreatStore();
  const [search, setSearch] = useState('');
  const [showAdd, setShowAdd] = useState(false);
  const [newThreat, setNewThreat] = useState({
    indicator_type: 'domain',
    value: '',
    severity: 'high',
    source: 'manual',
  });

  useEffect(() => {
    fetchThreats();
  }, [fetchThreats]);

  const handleAdd = async () => {
    try {
      await addThreat(newThreat);
      toast.success('Threat indicator added');
      setShowAdd(false);
      setNewThreat({ indicator_type: 'domain', value: '', severity: 'high', source: 'manual' });
    } catch {
      toast.error('Failed to add threat');
    }
  };

  const handleDelete = async (id) => {
    if (!confirm('Delete this threat indicator?')) return;
    await removeThreat(id);
    toast.success('Indicator removed');
  };

  const filtered = threats.filter((t) =>
    t.value.toLowerCase().includes(search.toLowerCase())
  );

  if (loading && threats.length === 0) return <Loading text="Loading threat indicators..." />;

  return (
    <div className="space-y-4">
      {/* Toolbar */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-400" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search indicators..."
            className="input-field pl-10"
          />
        </div>
        <Button onClick={() => setShowAdd(true)}>
          <Plus size={16} className="mr-1" /> Add
        </Button>
      </div>

      {/* Table */}
      <div className="card overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-100 text-left text-xs font-medium uppercase text-gray-500">
              <th className="pb-3 pr-4">Type</th>
              <th className="pb-3 pr-4">Value</th>
              <th className="pb-3 pr-4">Severity</th>
              <th className="pb-3 pr-4">Source</th>
              <th className="pb-3 pr-4">Active</th>
              <th className="pb-3">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-50">
            {filtered.map((t) => (
              <tr
                key={t.id}
                className="hover:bg-gray-50 cursor-pointer"
                onClick={() => onSelect?.(t)}
              >
                <td className="py-2.5 pr-4"><Badge label={t.indicator_type} variant="info" /></td>
                <td className="py-2.5 pr-4 font-mono text-xs text-gray-800 truncate max-w-xs">
                  {t.value}
                </td>
                <td className="py-2.5 pr-4"><Badge label={t.severity} /></td>
                <td className="py-2.5 pr-4 text-xs text-gray-500">{t.source || '--'}</td>
                <td className="py-2.5 pr-4">
                  <span className={`h-2 w-2 rounded-full inline-block ${t.is_active ? 'bg-success-500' : 'bg-gray-300'}`} />
                </td>
                <td className="py-2.5">
                  <button
                    onClick={(e) => { e.stopPropagation(); handleDelete(t.id); }}
                    className="rounded p-1 text-gray-400 hover:bg-danger-50 hover:text-danger-500"
                  >
                    <Trash2 size={14} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {filtered.length === 0 && (
          <p className="py-6 text-center text-sm text-gray-400">No indicators found</p>
        )}
      </div>

      {/* Add modal */}
      <Modal isOpen={showAdd} onClose={() => setShowAdd(false)} title="Add Threat Indicator">
        <div className="space-y-3">
          <select
            value={newThreat.indicator_type}
            onChange={(e) => setNewThreat((p) => ({ ...p, indicator_type: e.target.value }))}
            className="input-field"
          >
            <option value="domain">Domain</option>
            <option value="url">URL</option>
            <option value="ip">IP</option>
            <option value="email">Email</option>
            <option value="file_hash">File Hash</option>
          </select>
          <input
            placeholder="Indicator value"
            value={newThreat.value}
            onChange={(e) => setNewThreat((p) => ({ ...p, value: e.target.value }))}
            className="input-field"
          />
          <select
            value={newThreat.severity}
            onChange={(e) => setNewThreat((p) => ({ ...p, severity: e.target.value }))}
            className="input-field"
          >
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
          <div className="flex justify-end gap-2 pt-2">
            <Button variant="secondary" onClick={() => setShowAdd(false)}>Cancel</Button>
            <Button onClick={handleAdd}>Add Indicator</Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
