import React from 'react';

export function AdminHeader() {
  return (
    <header
      style={{
        height: '64px',
        backgroundColor: '#0f172a',
        borderBottom: '1px solid #1e293b',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '0 24px',
        color: '#ffffff',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        <div
          style={{
            width: '32px',
            height: '32px',
            borderRadius: '6px',
            backgroundColor: '#ef4444',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#ffffff',
            fontWeight: 800,
            fontSize: '14px',
          }}
        >
          PA
        </div>
        <span style={{ fontWeight: 700, fontSize: '16px', letterSpacing: '0.02em' }}>
          DCMP Platform Admin Portal
        </span>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        <span
          style={{
            fontSize: '12px',
            padding: '4px 10px',
            borderRadius: '4px',
            backgroundColor: '#1e293b',
            color: '#f87171',
            border: '1px solid #7f1d1d',
            fontWeight: 600,
          }}
        >
          Restricted Internal Area
        </span>
      </div>
    </header>
  );
}
