import React from 'react';
import '../styles/globals.css';
import { AdminHeader } from '../components/AdminHeader';
import { AdminSidebar } from '../components/AdminSidebar';

export const metadata = {
  title: 'DCMP - Platform Owner Admin',
  description: 'Digital Checklist Management Platform - Internal Administration Portal',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <div style={{ display: 'flex', minHeight: '100vh', flexDirection: 'column' }}>
          <AdminHeader />
          <div style={{ display: 'flex', flex: 1 }}>
            <AdminSidebar />
            <main style={{ flex: 1, padding: '32px' }}>{children}</main>
          </div>
        </div>
      </body>
    </html>
  );
}
