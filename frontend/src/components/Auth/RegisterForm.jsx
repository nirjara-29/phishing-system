import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuthStore } from '../../stores/authStore';
import toast from 'react-hot-toast';

export default function RegisterForm() {
  const navigate = useNavigate();
  const { register, isLoading, error, clearError } = useAuthStore();
  const [form, setForm] = useState({
    email: '',
    username: '',
    full_name: '',
    password: '',
    password_confirm: '',
  });

  const handleChange = (e) => {
    clearError();
    setForm((prev) => ({ ...prev, [e.target.name]: e.target.value }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (form.password !== form.password_confirm) {
      toast.error('Passwords do not match');
      return;
    }
    try {
      await register(form);
      toast.success('Account created! Please sign in.');
      navigate('/login');
    } catch {
      toast.error(error || 'Registration failed');
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Username</label>
          <input
            name="username"
            required
            value={form.username}
            onChange={handleChange}
            className="input-field"
            placeholder="Username"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Full Name</label>
          <input
            name="full_name"
            value={form.full_name}
            onChange={handleChange}
            className="input-field"
            placeholder="Full name (optional)"
          />
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">Email</label>
        <input
          name="email"
          type="email"
          required
          value={form.email}
          onChange={handleChange}
          className="input-field"
          placeholder="you@example.com"
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">Password</label>
        <input
          name="password"
          type="password"
          required
          minLength={8}
          value={form.password}
          onChange={handleChange}
          className="input-field"
          placeholder="Min 8 chars, uppercase, lowercase, digit, special"
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">Confirm Password</label>
        <input
          name="password_confirm"
          type="password"
          required
          value={form.password_confirm}
          onChange={handleChange}
          className="input-field"
          placeholder="Repeat password"
        />
      </div>

      {error && (
        <p className="text-sm text-danger-600 bg-danger-50 rounded-lg px-3 py-2">{error}</p>
      )}

      <button type="submit" disabled={isLoading} className="btn-primary w-full">
        {isLoading ? 'Creating account...' : 'Create Account'}
      </button>

      <p className="text-center text-sm text-gray-500">
        Already have an account?{' '}
        <Link to="/login" className="font-medium text-brand-600 hover:text-brand-700">
          Sign in
        </Link>
      </p>
    </form>
  );
}
