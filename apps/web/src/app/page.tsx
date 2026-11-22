import React from 'react';

export default function HomePage() {
  return (
    <main style={{ maxWidth: '800px', margin: '0 auto', lineHeight: 1.6 }}>
      <header
        style={{
          borderBottom: '1px solid #334155',
          paddingBottom: '1rem',
          marginBottom: '2rem',
        }}
      >
        <h1
          style={{
            fontSize: '1.75rem',
            fontWeight: 600,
            color: '#f8fafc',
            margin: 0,
          }}
        >
          Switchyard — AI Inference Gateway Control Plane
        </h1>
        <p style={{ color: '#94a3b8', marginTop: '0.5rem', marginBottom: 0 }}>
          Phase 1 Runtime Foundation
        </p>
      </header>

      <section
        style={{
          backgroundColor: '#1e293b',
          padding: '1.5rem',
          borderRadius: '8px',
          border: '1px solid #334155',
        }}
      >
        <h2 style={{ fontSize: '1.125rem', marginTop: 0, color: '#e2e8f0' }}>Runtime Status</h2>
        <p style={{ color: '#cbd5e1' }}>
          The web application runtime foundation is operational. Control Plane and interactive
          dashboard capabilities are scheduled for Phase 4.
        </p>
      </section>
    </main>
  );
}
