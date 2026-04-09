import React from 'react';
import { Menu, Bell, Shield } from 'lucide-react';
import { useAuthStore } from '../../stores/authStore';

export default function Header({ onMenuClick }) {
  const user = useAuthStore((s) => s.user);
  const logout = useAuthStore((s) => s.logout);

  return (
    <header className="sticky top-0 z-20 flex h-16 items-center justify-between border-b border-gray-200 bg-white px-4 md:px-6">
      {/* Left: mobile menu + logo */}
      <div className="flex items-center gap-3">
        <button
          onClick={onMenuClick}
          className="rounded-lg p-2 text-gray-500 hover:bg-gray-100 md:hidden"
          aria-label="Open sidebar"
        >
          <Menu size={20} />
        </button>
        <div className="flex items-center gap-2 text-brand-700 font-bold text-lg">
          <Shield size={22} />
          <span className="hidden sm:inline">PhishGuard</span>
        </div>
      </div>

      {/* Right: notifications + user */}
      <div className="flex items-center gap-4">
        <button className="relative rounded-lg p-2 text-gray-500 hover:bg-gray-100">
          <Bell size={18} />
          <span className="absolute right-1.5 top-1.5 h-2 w-2 rounded-full bg-danger-500" />
        </button>

        <div className="flex items-center gap-3">
          <div className="hidden text-right text-sm sm:block">
            <p className="font-medium text-gray-700">{user?.username || 'Analyst'}</p>
            <p className="text-xs text-gray-400">{user?.role || 'analyst'}</p>
          </div>
          <button
            onClick={logout}
            className="rounded-lg bg-gray-100 px-3 py-1.5 text-xs font-medium text-gray-600 hover:bg-gray-200 transition-colors"
          >
            Logout
          </button>
        </div>
      </div>
    </header>
  );
}
