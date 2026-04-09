import React, { useState } from 'react';
import { Key, User, Shield } from 'lucide-react';
import { useAuthStore } from '../stores/authStore';
import { changePassword, generateApiKey } from '../api/auth';
import Button from '../components/Common/Button';
import toast from 'react-hot-toast';

export default function SettingsPage() {
  const user = useAuthStore((s) => s.user);
  const [passwords, setPasswords] = useState({
    current_password: '',
    new_password: '',
    new_password_confirm: '',
  });
  const [apiKey, setApiKey] = useState(null);
  const [loading, setLoading] = useState(false);

  const handlePasswordChange = async (e) => {
    e.preventDefault();
    if (passwords.new_password !== passwords.new_password_confirm) {
      toast.error('New passwords do not match');
      return;
    }
    setLoading(true);
    try {
      await changePassword(passwords);
      toast.success('Password updated');
      setPasswords({ current_password: '', new_password: '', new_password_confirm: '' });
    } catch {
      toast.error('Failed to change password');
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateApiKey = async () => {
    try {
      const data = await generateApiKey();
      setApiKey(data.api_key);
      toast.success('API key generated');
    } catch {
      toast.error('Failed to generate API key');
    }
  };

  return (
    <div className="space-y-6 max-w-2xl">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Settings</h1>
        <p className="text-sm text-gray-500 mt-1">Manage your account and preferences</p>
      </div>

      {/* Profile section */}
      <div className="card">
        <div className="flex items-center gap-3 mb-4">
          <User className="h-5 w-5 text-gray-600" />
          <h2 className="text-lg font-semibold text-gray-900">Profile</h2>
        </div>
        <dl className="grid grid-cols-1 gap-3 sm:grid-cols-2 text-sm">
          <div>
            <dt className="text-gray-500">Username</dt>
            <dd className="font-medium text-gray-800">{user?.username || '--'}</dd>
          </div>
          <div>
            <dt className="text-gray-500">Email</dt>
            <dd className="font-medium text-gray-800">{user?.email || '--'}</dd>
          </div>
          <div>
            <dt className="text-gray-500">Role</dt>
            <dd className="font-medium text-gray-800 capitalize">{user?.role || '--'}</dd>
          </div>
          <div>
            <dt className="text-gray-500">Member since</dt>
            <dd className="font-medium text-gray-800">
              {user?.created_at ? new Date(user.created_at).toLocaleDateString() : '--'}
            </dd>
          </div>
        </dl>
      </div>

      {/* Change password */}
      <div className="card">
        <div className="flex items-center gap-3 mb-4">
          <Shield className="h-5 w-5 text-gray-600" />
          <h2 className="text-lg font-semibold text-gray-900">Change Password</h2>
        </div>
        <form onSubmit={handlePasswordChange} className="space-y-3">
          <input
            type="password"
            placeholder="Current password"
            value={passwords.current_password}
            onChange={(e) => setPasswords((p) => ({ ...p, current_password: e.target.value }))}
            className="input-field"
            required
          />
          <input
            type="password"
            placeholder="New password"
            value={passwords.new_password}
            onChange={(e) => setPasswords((p) => ({ ...p, new_password: e.target.value }))}
            className="input-field"
            required
            minLength={8}
          />
          <input
            type="password"
            placeholder="Confirm new password"
            value={passwords.new_password_confirm}
            onChange={(e) => setPasswords((p) => ({ ...p, new_password_confirm: e.target.value }))}
            className="input-field"
            required
          />
          <Button type="submit" loading={loading}>Update Password</Button>
        </form>
      </div>

      {/* API key */}
      <div className="card">
        <div className="flex items-center gap-3 mb-4">
          <Key className="h-5 w-5 text-gray-600" />
          <h2 className="text-lg font-semibold text-gray-900">API Key</h2>
        </div>
        <p className="text-sm text-gray-500 mb-3">
          Generate an API key for the browser extension or third-party integrations.
          This will replace any existing key.
        </p>
        {apiKey && (
          <div className="mb-3 rounded-lg bg-gray-50 p-3 font-mono text-xs text-gray-800 break-all border border-gray-200">
            {apiKey}
          </div>
        )}
        <Button variant="secondary" onClick={handleGenerateApiKey}>
          Generate New API Key
        </Button>
      </div>
    </div>
  );
}
