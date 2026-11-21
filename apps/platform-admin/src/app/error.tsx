'use client';

import React, { useEffect } from 'react';

export default function AdminErrorPage({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error('Platform Admin Error:', error);
  }, [error]);

  return (
    <div
      style={{
        padding: '48px',
        textAlign: 'center',
        backgroundColor: '#ffffff',
        borderRadius: '8px',
        border: '1px solid #cbd5e1',
        maxWidth: '500px',
        margin: '64px auto',
      }}
    >
      <h2 style={{ fontSize: '20px', fontWeight: 700, color: '#dc2626', marginBottom: '12px' }}>
        Platform Administration Error
      </h2>
      <p style={{ color: '#64748b', fontSize: '14px', marginBottom: '24px' }}>
        An unexpected error occurred in the platform administration portal.
      </p>
      <button
        onClick={() => reset()}
        style={{
          padding: '10px 20px',
          backgroundColor: '#0f172a',
          color: '#ffffff',
          borderRadius: '6px',
          border: 'none',
          cursor: 'pointer',
          fontWeight: 600,
        }}
      >
        Retry Action
      </button>
    </div>
  );
}
