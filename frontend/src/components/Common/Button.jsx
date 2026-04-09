import React from 'react';
import clsx from 'clsx';

const variants = {
  primary: 'btn-primary',
  secondary: 'btn-secondary',
  danger:
    'inline-flex items-center justify-center rounded-lg bg-danger-600 px-5 py-2.5 text-sm font-medium text-white shadow-sm hover:bg-danger-700 focus:ring-2 focus:ring-danger-300 focus:outline-none disabled:opacity-50 transition-colors',
  ghost:
    'inline-flex items-center justify-center rounded-lg px-5 py-2.5 text-sm font-medium text-gray-600 hover:bg-gray-100 focus:outline-none transition-colors',
};

const sizes = {
  sm: 'px-3 py-1.5 text-xs',
  md: '',
  lg: 'px-6 py-3 text-base',
};

export default function Button({
  children,
  variant = 'primary',
  size = 'md',
  loading = false,
  className,
  ...props
}) {
  return (
    <button
      className={clsx(variants[variant], sizes[size], className)}
      disabled={loading || props.disabled}
      {...props}
    >
      {loading && (
        <svg
          className="mr-2 h-4 w-4 animate-spin"
          xmlns="http://www.w3.org/2000/svg"
          fill="none"
          viewBox="0 0 24 24"
        >
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
        </svg>
      )}
      {children}
    </button>
  );
}
