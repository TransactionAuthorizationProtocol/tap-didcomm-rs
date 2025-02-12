import { beforeAll, afterAll, afterEach } from "vitest";
import { DIDCommClient, DefaultDIDCommPlugin, PackingType } from "../../src";

// Global test state
declare global {
  // eslint-disable-next-line no-var
  var didCommClient: DIDCommClient;
}

// Setup test environment
beforeAll(async () => {
  // Initialize global client instance
  global.didCommClient = new DIDCommClient(
    {
      defaultPacking: PackingType.ANONCRYPT,
      useHttps: false,
    },
    new DefaultDIDCommPlugin(),
  );

  // Initialize WASM module
  await global.didCommClient.initialize();
});

// Cleanup after each test
afterEach(() => {
  // Reset any mocks or test state
});

// Cleanup after all tests
afterAll(async () => {
  // Cleanup any resources
  if (global.didCommClient) {
    // Add any necessary cleanup
  }
});
