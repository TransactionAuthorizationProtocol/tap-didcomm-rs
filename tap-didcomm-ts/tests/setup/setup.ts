import { beforeAll, afterAll, afterEach, vi } from 'vitest';
import { DIDCommClient, DefaultDIDCommPlugin, PackingType } from '../../src';

// Global test state
declare global {
  var didCommClient: DIDCommClient;
}

// Setup test environment
beforeAll(() => {
  // Initialize any test setup
});

// Cleanup after each test
afterEach(() => {
  // Reset any mocks or test state
  vi.restoreAllMocks();
});

// Cleanup after all tests
afterAll(() => {
  // Clean up after all tests
  global.didCommClient = null as unknown as DIDCommClient;
});
