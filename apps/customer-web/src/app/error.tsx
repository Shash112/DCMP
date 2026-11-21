'use client';

import React, { useEffect } from 'react';

export default function ErrorPage({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    // Log client error to monitoring service
    console.error('Customer Web Application Error:', error);
  }, [error]);

  return (
    <div
      style={{
        padding: '48px',
        textAlign: 'center',
        backgroundColor: '#ffffff',
        borderRadius: '8px',
        border: '1px solid #e2e8f0',
        maxWidth: '500px',
        margin: '64px auto',
      }}
    >
      <h2 style={{ fontSize: '20px', fontWeight: 700, color: '#ef4444', marginBottom: '12px' }}>
        Application Error
      </h2>
      <p style={{ color: '#64748b', fontSize: '14px', marginBottom: '24px' }}>
        An unexpected error occurred in the customer workspace.
      </p>
      <button
        onClick={() => reset()}
        style={{
          padding: '10px 20px',
          backgroundColor: '#4656c8',
          color: '#ffffff',
          borderRadius: '6px',
          border: 'none',
          cursor: 'pointer',
          fontWeight: 600,
        }}
      >
        Try Again
      </button>
    </div>
  );
}
