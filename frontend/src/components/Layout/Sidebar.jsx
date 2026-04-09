import React from 'react';
import { NavLink } from 'react-router-dom';
import { ScanSearch, ShieldAlert, FileBarChart, X } from 'lucide-react';
import clsx from 'clsx';

const NAV_ITEMS = [
  { to: '/scan', label: 'Scan', icon: ScanSearch },
  { to: '/threats', label: 'Threats', icon: ShieldAlert },
  { to: '/reports', label: 'Reports', icon: FileBarChart },
];

export default function Sidebar({ open, onClose }) {
  return (
    <aside
      className={clsx(
        'fixed inset-y-0 left-0 z-40 flex w-64 flex-col bg-gray-900 text-white transition-transform duration-200 md:relative md:translate-x-0',
        open ? 'translate-x-0' : '-translate-x-full'
      )}
    >
      {/* Header */}
      <div className="flex h-16 items-center justify-between px-5 border-b border-gray-800">
        <span className="text-lg font-bold tracking-tight">PhishGuard</span>
        <button onClick={onClose} className="rounded p-1 hover:bg-gray-800 md:hidden">
          <X size={18} />
        </button>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto px-3 py-4">
        <ul className="space-y-1">
          {NAV_ITEMS.map(({ to, label, icon: Icon }) => (
            <li key={to}>
              <NavLink
                to={to}
                end={to === '/'}
                onClick={onClose}
                className={({ isActive }) =>
                  clsx(
                    'flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors',
                    isActive
                      ? 'bg-brand-600 text-white'
                      : 'text-gray-400 hover:bg-gray-800 hover:text-white'
                  )
                }
              >
                <Icon size={18} />
                {label}
              </NavLink>
            </li>
          ))}
        </ul>
      </nav>

      {/* Footer */}
      <div className="border-t border-gray-800 px-5 py-4">
        <p className="text-xs text-gray-500">PhishGuard v1.0.0</p>
        <p className="text-xs text-gray-600">AI Phishing Detection</p>
      </div>
    </aside>
  );
}
