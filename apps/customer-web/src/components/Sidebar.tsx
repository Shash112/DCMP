import React from 'react';

const NAV_ITEMS = [
  { label: 'Overview', href: '/' },
  { label: 'Checklists', href: '/checklists' },
  { label: 'Assignments', href: '/assignments' },
  { label: 'Inspections', href: '/inspections' },
  { label: 'Issues', href: '/issues' },
  { label: 'Reports', href: '/reports' },
  { label: 'Settings', href: '/settings' },
];

export function Sidebar() {
  return (
    <aside
      style={{
        width: '240px',
        backgroundColor: '#0f172a',
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
          color: '#64748b',
          fontWeight: 600,
          padding: '0 12px 12px',
        }}
      >
        Organization
      </div>
      {NAV_ITEMS.map((item, idx) => (
        <div
          key={item.href}
          style={{
            padding: '10px 12px',
            borderRadius: '6px',
            fontSize: '14px',
            fontWeight: idx === 0 ? 600 : 400,
            backgroundColor: idx === 0 ? '#1e293b' : 'transparent',
            color: idx === 0 ? '#ffffff' : '#94a3b8',
            cursor: 'pointer',
          }}
        >
          {item.label}
        </div>
      ))}
    </aside>
  );
}
