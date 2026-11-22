import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { GET } from '../app/health/ready/route.js';
import HomePage from '../app/page.js';

describe('apps/web: Minimal Next.js Web Runtime', () => {
  it('1. Root route HomePage renders expected application shell title and disclaimer', () => {
    const page = HomePage();
    expect(page).toBeDefined();

    // Verify application shell title
    const header = page.props.children[0];
    const h1 = header.props.children[0];
    expect(h1.props.children).toBe('Switchyard — AI Inference Gateway Control Plane');

    // Verify deferred dashboard notice
    const section = page.props.children[1];
    const p = section.props.children[1];
    expect(p.props.children).toContain(
      'Control Plane and interactive dashboard capabilities are scheduled for Phase 4',
    );
  });

  it('2. /health/ready returns status ready, service web, and valid ISO timestamp', async () => {
    const response = await GET();
    expect(response.status).toBe(200);

    const body = (await response.json()) as {
      status: string;
      service: string;
      timestamp: string;
      dependencies?: unknown;
    };

    expect(body.status).toBe('ready');
    expect(body.service).toBe('web');
    expect(new Date(body.timestamp).toISOString()).toBe(body.timestamp);

    // Invariant: Do not describe Gateway, PostgreSQL, or Redis as healthy merely because Next.js is running
    expect(body.dependencies).toBeUndefined();
    expect(JSON.stringify(body)).not.toContain('database');
    expect(JSON.stringify(body)).not.toContain('redis');
    expect(JSON.stringify(body)).not.toContain('gateway');
  });

  it('3. Verifies no sensitive credentials, KEKs, or provider secrets in web source', () => {
    const srcDir = path.resolve(__dirname, '..');
    const readDirRecursive = (dir: string): string[] => {
      let results: string[] = [];
      const list = fs.readdirSync(dir);
      for (const file of list) {
        const fullPath = path.join(dir, file);
        const stat = fs.statSync(fullPath);
        if (stat.isDirectory()) {
          if (!file.startsWith('.') && file !== 'node_modules' && file !== '__tests__') {
            results = results.concat(readDirRecursive(fullPath));
          }
        } else if (
          file.endsWith('.ts') ||
          file.endsWith('.tsx') ||
          file.endsWith('.js') ||
          file.endsWith('.mjs')
        ) {
          results.push(fullPath);
        }
      }
      return results;
    };

    const files = readDirRecursive(srcDir);
    expect(files.length).toBeGreaterThan(0);

    const forbiddenPatterns = [
      /sk-[a-zA-Z0-9]{20,}/,
      /MASTER_KEK/,
      /switchyard_dev_password/,
      /switchyard_app_password/,
      /POSTGRES_PASSWORD/,
      /REDIS_PASSWORD/,
    ];

    for (const file of files) {
      const content = fs.readFileSync(file, 'utf8');
      for (const pattern of forbiddenPatterns) {
        expect(content).not.toMatch(pattern);
      }
    }
  });

  it('4. Verifies no privileged management or admin routes exist in apps/web', () => {
    const appDir = path.resolve(__dirname, '../app');
    const appEntries = fs.readdirSync(appDir);
    const forbiddenRouteNames = ['admin', 'manage', 'api', 'dashboard', 'settings', 'keys'];

    for (const entry of appEntries) {
      expect(forbiddenRouteNames).not.toContain(entry.toLowerCase());
    }
  });
});
