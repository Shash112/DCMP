import React from 'react';

export default function PlatformAdminOverviewPage() {
  return (
    <div>
      <div style={{ marginBottom: '24px' }}>
        <h1 style={{ fontSize: '24px', fontWeight: 700, color: '#0f172a' }}>
          Platform Owner Overview
        </h1>
        <p style={{ color: '#64748b', marginTop: '4px', fontSize: '14px' }}>
          SaaS Operations, Customer Tenants, Licensing & Diagnostics
        </p>
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
          gap: '20px',
          marginBottom: '32px',
        }}
      >
        <div
          style={{
            backgroundColor: '#ffffff',
            padding: '20px',
            borderRadius: '8px',
            border: '1px solid #cbd5e1',
          }}
        >
          <div style={{ fontSize: '13px', color: '#64748b', fontWeight: 500 }}>
            Registered Tenants
          </div>
          <div style={{ fontSize: '24px', fontWeight: 700, color: '#0f172a', marginTop: '8px' }}>
            0 Active
          </div>
          <div style={{ fontSize: '12px', color: '#94a3b8', marginTop: '4px' }}>
            Multi-Tenant Monolith Ready
          </div>
        </div>

        <div
          style={{
            backgroundColor: '#ffffff',
            padding: '20px',
            borderRadius: '8px',
            border: '1px solid #cbd5e1',
          }}
        >
          <div style={{ fontSize: '13px', color: '#64748b', fontWeight: 500 }}>
            Licensing Engine
          </div>
          <div style={{ fontSize: '24px', fontWeight: 700, color: '#059669', marginTop: '8px' }}>
            Operational
          </div>
          <div style={{ fontSize: '12px', color: '#94a3b8', marginTop: '4px' }}>
            Device Activation Service
          </div>
        </div>

        <div
          style={{
            backgroundColor: '#ffffff',
            padding: '20px',
            borderRadius: '8px',
            border: '1px solid #cbd5e1',
          }}
        >
          <div style={{ fontSize: '13px', color: '#64748b', fontWeight: 500 }}>
            Customer Privacy Guard
          </div>
          <div style={{ fontSize: '24px', fontWeight: 700, color: '#dc2626', marginTop: '8px' }}>
            Active
          </div>
          <div style={{ fontSize: '12px', color: '#94a3b8', marginTop: '4px' }}>
            Tenant Business Data Isolated
          </div>
        </div>
      </div>

      <div
        style={{
          backgroundColor: '#ffffff',
          borderRadius: '8px',
          border: '1px solid #cbd5e1',
          padding: '24px',
        }}
      >
        <h2 style={{ fontSize: '16px', fontWeight: 600, color: '#0f172a', marginBottom: '12px' }}>
          Platform Boundary Notice
        </h2>
        <p style={{ fontSize: '14px', color: '#475569', lineHeight: 1.6 }}>
          Platform administrators cannot inspect customer checklist responses or evidence without an
          approved, audited Customer Support Access Grant. Administrative actions are logged to
          immutable platform audit logs.
        </p>
      </div>
    </div>
  );
}
