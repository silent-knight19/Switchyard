import type { Fixture } from './types.js';
import { SUCCESS_JSON_FIXTURES, SUCCESS_SSE_FIXTURES } from './success.js';
import { HTTP_ERROR_FIXTURES, NETWORK_FAULT_FIXTURES } from './faults.js';

const REGISTRY = new Map<string, Fixture>();

function register(fixtures: Record<string, Fixture>): void {
  for (const [id, fixture] of Object.entries(fixtures)) {
    REGISTRY.set(id, Object.freeze(fixture));
  }
}

register(SUCCESS_JSON_FIXTURES);
register(SUCCESS_SSE_FIXTURES);
register(HTTP_ERROR_FIXTURES);
register(NETWORK_FAULT_FIXTURES);

export function getFixture(id: string): Fixture | undefined {
  return REGISTRY.get(id);
}

export function hasFixture(id: string): boolean {
  return REGISTRY.has(id);
}

export function getAllFixtureIds(): string[] {
  return Array.from(REGISTRY.keys()).sort();
}

export function registerAdditionalFixtures(fixtures: Record<string, Fixture>): void {
  register(fixtures);
}
