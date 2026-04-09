import React from 'react';

export default function Loading({ text = 'Loading...', fullPage = false }) {
  const content = (
    <div className="flex flex-col items-center justify-center gap-3 py-12">
      <svg
        className="h-8 w-8 animate-spin text-brand-600"
        xmlns="http://www.w3.org/2000/svg"
        fill="none"
        viewBox="0 0 24 24"
      >
        <circle
          className="opacity-25"
          cx="12"
          cy="12"
          r="10"
          stroke="currentColor"
          strokeWidth="4"
        />
        <path
          className="opacity-75"
          fill="currentColor"
          d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z"
        />
      </svg>
      <p className="text-sm text-gray-500">{text}</p>
    </div>
  );

  if (fullPage) {
    return (
      <div className="flex h-screen items-center justify-center">{content}</div>
    );
  }

  return content;
}
