import React from 'react';

export function Header() {
  return (
    <header
      style={{
        height: '64px',
        backgroundColor: '#ffffff',
        borderBottom: '1px solid #e2e8f0',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '0 24px',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        <div
          style={{
            width: '32px',
            height: '32px',
            borderRadius: '6px',
            backgroundColor: '#4656c8',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#ffffff',
            fontWeight: 700,
            fontSize: '14px',
          }}
        >
          D
        </div>
        <span style={{ fontWeight: 600, fontSize: '16px', color: '#0f172a' }}>
          DCMP Customer Workspace
        </span>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        <span
          style={{
            fontSize: '12px',
            padding: '4px 10px',
            borderRadius: '9999px',
            backgroundColor: '#ecfdf5',
            color: '#047857',
            fontWeight: 500,
          }}
        >
          Active Workspace
        </span>
      </div>
    </header>
  );
}
