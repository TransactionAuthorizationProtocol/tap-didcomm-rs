import { test, expect } from "@playwright/test";

test.describe("DIDComm Browser Tests", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
  });

  test("should initialize DIDComm client", async ({ page }) => {
    const results = await page.evaluate(() => window.runDIDCommTests());

    // Check initialization
    const initResult = results.find((r) => r.name === "init");
    expect(initResult?.success).toBe(true);
  });

  test("should encrypt and decrypt messages", async ({ page }) => {
    const results = await page.evaluate(() => window.runDIDCommTests());

    // Check encryption
    const encryptResult = results.find((r) => r.name === "encrypt");
    expect(encryptResult?.success).toBe(true);
    expect(encryptResult?.data).toBeDefined();

    // Check decryption
    const decryptResult = results.find((r) => r.name === "decrypt");
    expect(decryptResult?.success).toBe(true);
    expect(decryptResult?.data).toMatchObject({
      id: "test-msg-1",
      type: "test-type",
      body: { test: "data" },
    });
  });

  test("should handle WASM loading in different browsers", async ({
    page,
    browserName,
  }) => {
    // Add console listener to catch WASM-related errors
    const consoleMessages: string[] = [];
    page.on("console", (msg) => consoleMessages.push(msg.text()));

    const results = await page.evaluate(() => window.runDIDCommTests());

    // No WASM-related errors should be present
    expect(
      consoleMessages.filter(
        (msg) => msg.includes("WASM") && msg.includes("error"),
      ),
    ).toHaveLength(0);

    // All operations should succeed
    expect(results.every((r) => r.success)).toBe(true);

    test.info().annotations.push({
      type: "Browser Test",
      description: `Tested in ${browserName}`,
    });
  });
});

// Add TypeScript type declaration for the test function
declare global {
  interface Window {
    runDIDCommTests(): Promise<
      Array<{
        name: string;
        success: boolean;
        data?: unknown;
        error?: string;
      }>
    >;
  }
}
