import { DIDCommClient, DefaultDIDCommPlugin, PackingType } from "../../dist";

async function main() {
  try {
    console.log("Initializing DIDComm client...");

    // Initialize client with default plugin
    const client = new DIDCommClient(
      {
        defaultPacking: PackingType.ANONCRYPT,
        useHttps: true,
      },
      new DefaultDIDCommPlugin(),
    );

    // Initialize WASM
    const initResult = await client.initialize();
    if (!initResult.success) {
      throw new Error(`Failed to initialize: ${initResult.error?.message}`);
    }
    console.log("✓ DIDComm client initialized");

    // Create test message
    const message = {
      id: `test-${Date.now()}`,
      type: "example/1.0",
      body: {
        text: "Hello from Node.js!",
        timestamp: Date.now(),
      },
    };
    console.log("\nTest message created:");
    console.log(JSON.stringify(message, null, 2));

    // Example DIDs
    const senderDid = "did:example:sender";
    const recipientDid = "did:example:recipient";

    // Encrypt message
    console.log("\nEncrypting message...");
    const encryptResult = await client.encrypt(message, {
      to: [recipientDid],
      from: senderDid,
      packing: PackingType.AUTHCRYPT,
    });

    if (!encryptResult.success || !encryptResult.data) {
      throw new Error(`Encryption failed: ${encryptResult.error?.message}`);
    }
    console.log("✓ Message encrypted successfully");
    console.log("\nEncrypted message:");
    console.log(JSON.stringify(encryptResult.data, null, 2));

    // Decrypt message
    console.log("\nDecrypting message...");
    const decryptResult = await client.decrypt(encryptResult.data, {
      recipient: recipientDid,
      verifySignature: true,
    });

    if (!decryptResult.success || !decryptResult.data) {
      throw new Error(`Decryption failed: ${decryptResult.error?.message}`);
    }
    console.log("✓ Message decrypted successfully");
    console.log("\nDecrypted message:");
    console.log(JSON.stringify(decryptResult.data, null, 2));

    // Sign message
    console.log("\nSigning message...");
    const signResult = await client.sign(message, {
      signer: senderDid,
    });

    if (!signResult.success || !signResult.data) {
      throw new Error(`Signing failed: ${signResult.error?.message}`);
    }
    console.log("✓ Message signed successfully");
    console.log("\nSigned message:");
    console.log(JSON.stringify(signResult.data, null, 2));

    // Verify signature
    console.log("\nVerifying signature...");
    const verifyResult = await client.verify(signResult.data);

    if (!verifyResult.success) {
      throw new Error(`Verification failed: ${verifyResult.error?.message}`);
    }
    console.log("✓ Signature verified successfully");

    console.log("\nDemo completed successfully!");
  } catch (error) {
    console.error("\n❌ Error:", error.message);
    process.exit(1);
  }
}

main();
