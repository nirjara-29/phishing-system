import React from 'react';
import clsx from 'clsx';

const colorMap = {
  safe: 'bg-success-50 text-success-600',
  phishing: 'bg-danger-50 text-danger-600',
  suspicious: 'bg-warning-50 text-warning-600',
  unknown: 'bg-gray-100 text-gray-600',
  critical: 'bg-red-100 text-red-700',
  high: 'bg-orange-100 text-orange-700',
  medium: 'bg-yellow-100 text-yellow-700',
  low: 'bg-green-100 text-green-700',
  info: 'bg-blue-100 text-blue-700',
  pending: 'bg-gray-100 text-gray-500',
  completed: 'bg-brand-50 text-brand-700',
  error: 'bg-danger-50 text-danger-600',
};

export default function Badge({ label, variant, className }) {
  const color = colorMap[variant] || colorMap[label?.toLowerCase()] || colorMap.unknown;

  return (
    <span
      className={clsx(
        'inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium capitalize',
        color,
        className
      )}
    >
      {label || variant}
    </span>
  );
}
