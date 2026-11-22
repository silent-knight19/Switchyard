import type { Metadata } from 'next';
import React from 'react';

export const metadata: Metadata = {
  title: 'Switchyard — AI Inference Gateway Control Plane',
  description: 'Multi-Tenant AI Inference Gateway Control Plane',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body
        style={{
          fontFamily:
            '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
          margin: 0,
          padding: '2rem',
          backgroundColor: '#0f172a',
          color: '#f8fafc',
        }}
      >
        {children}
      </body>
    </html>
  );
}
