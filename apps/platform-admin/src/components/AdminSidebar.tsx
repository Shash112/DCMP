import React from 'react';

const ADMIN_NAV = [
  { label: 'Overview', href: '/' },
  { label: 'Customer Tenants', href: '/tenants' },
  { label: 'Licenses & Plans', href: '/licenses' },
  { label: 'Device Registrations', href: '/devices' },
  { label: 'Platform Releases', href: '/releases' },
  { label: 'Support & Access', href: '/support' },
  { label: 'Platform Audit Logs', href: '/audit' },
  { label: 'System Health', href: '/health' },
];

export function AdminSidebar() {
  return (
    <aside
      style={{
        width: '240px',
        backgroundColor: '#1e293b',
        color: '#f8fafc',
        display: 'flex',
        flexDirection: 'column',
        padding: '24px 16px',
        gap: '8px',
      }}
    >
      <div
        style={{
          fontSize: '11px',
          textTransform: 'uppercase',
          color: '#94a3b8',
          fontWeight: 600,
          padding: '0 12px 12px',
        }}
      >
        Platform Administration
      </div>
      {ADMIN_NAV.map((item, idx) => (
        <div
          key={item.href}
          style={{
            padding: '10px 12px',
            borderRadius: '6px',
            fontSize: '14px',
            fontWeight: idx === 0 ? 600 : 400,
            backgroundColor: idx === 0 ? '#334155' : 'transparent',
            color: idx === 0 ? '#ffffff' : '#cbd5e1',
            cursor: 'pointer',
          }}
        >
          {item.label}
        </div>
      ))}
    </aside>
  );
}
