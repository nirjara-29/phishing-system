import React from 'react';
import { Shield } from 'lucide-react';
import LoginForm from '../components/Auth/LoginForm';

export default function LoginPage() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-gradient-to-br from-gray-900 via-gray-800 to-brand-950 px-4">
      <div className="w-full max-w-md">
        <div className="mb-8 text-center">
          <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-xl bg-brand-600 shadow-lg">
            <Shield className="h-7 w-7 text-white" />
          </div>
          <h1 className="text-2xl font-bold text-white">PhishNet</h1>
          <p className="mt-1 text-sm text-gray-400">
            AI-Powered Phishing Detection System
          </p>
        </div>

        <div className="rounded-xl bg-white p-6 shadow-xl">
          <h2 className="mb-5 text-lg font-semibold text-gray-900">Sign in to your account</h2>
          <LoginForm />
        </div>
      </div>
    </div>
  );
}
