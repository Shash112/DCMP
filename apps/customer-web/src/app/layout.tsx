import React from 'react';
import '../styles/globals.css';
import { Header } from '../components/Header';
import { Sidebar } from '../components/Sidebar';

export const metadata = {
  title: 'DCMP - Customer Workspace',
  description: 'Digital Checklist Management Platform - Customer Web Application',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <div style={{ display: 'flex', minHeight: '100vh', flexDirection: 'column' }}>
          <Header />
          <div style={{ display: 'flex', flex: 1 }}>
            <Sidebar />
            <main style={{ flex: 1, padding: '32px' }}>{children}</main>
          </div>
        </div>
      </body>
    </html>
  );
}
