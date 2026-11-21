import React from 'react';
import Link from 'next/link';

export default function AdminNotFoundPage() {
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
      <h2 style={{ fontSize: '28px', fontWeight: 700, color: '#0f172a', marginBottom: '8px' }}>
        404
      </h2>
      <p style={{ fontSize: '16px', fontWeight: 600, color: '#475569', marginBottom: '12px' }}>
        Admin Resource Not Found
      </p>
      <p style={{ color: '#64748b', fontSize: '14px', marginBottom: '24px' }}>
        The requested administrative view does not exist.
      </p>
      <Link
        href="/"
        style={{
          display: 'inline-block',
          padding: '10px 20px',
          backgroundColor: '#0f172a',
          color: '#ffffff',
          borderRadius: '6px',
          fontWeight: 600,
          fontSize: '14px',
        }}
      >
        Return to Overview
      </Link>
    </div>
  );
}
