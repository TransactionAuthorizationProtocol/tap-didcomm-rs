import {
  DIDCommClient,
  DefaultDIDCommPlugin,
  PackingType,
  type Message,
  type DIDCommResult,
} from "../src";

async function main() {
  try {
    // Initialize the client with default configuration
    const client = new DIDCommClient(
      {
        defaultPacking: PackingType.ANONCRYPT,
        useHttps: true,
      },
      new DefaultDIDCommPlugin(),
    );

    // Initialize WASM (required before any operations)
    const initResult = await client.initialize();
    if (!initResult.success) {
      throw new Error(`Failed to initialize: ${initResult.error?.message}`);
    }

    console.log("DIDComm client initialized successfully");

    // Create a test message
    const message: Message = {
      id: `test-${Date.now()}`,
      type: "example/1.0",
      body: {
        text: "Hello, DIDComm!",
        timestamp: Date.now(),
      },
    };

    // Example DIDs (replace with real DIDs in production)
    const senderDid = "did:example:sender";
    const recipientDid = "did:example:recipient";

    // Encrypt the message
    console.log("Encrypting message...");
    const encryptResult = await client.encrypt(message, {
      to: [recipientDid],
      from: senderDid,
      packing: PackingType.AUTHCRYPT, // Use authenticated encryption
    });

    if (!encryptResult.success || !encryptResult.data) {
      throw new Error(`Encryption failed: ${encryptResult.error?.message}`);
    }

    console.log("Message encrypted successfully");

    // Decrypt the message
    console.log("Decrypting message...");
    const decryptResult = await client.decrypt(encryptResult.data, {
      recipient: recipientDid,
      verifySignature: true,
    });

    if (!decryptResult.success || !decryptResult.data) {
      throw new Error(`Decryption failed: ${decryptResult.error?.message}`);
    }

    console.log("Message decrypted successfully");
    console.log("Decrypted message:", decryptResult.data);

    // Sign a message separately
    console.log("Signing message...");
    const signResult = await client.sign(message, {
      from: senderDid,
    });

    if (!signResult.success || !signResult.data) {
      throw new Error(`Signing failed: ${signResult.error?.message}`);
    }

    console.log("Message signed successfully");

    // Verify the signature
    console.log("Verifying signature...");
    const verifyResult = await client.verify(
      new TextEncoder().encode(JSON.stringify(message)),
      signResult.data,
      senderDid,
    );

    if (!verifyResult.success) {
      throw new Error(`Verification failed: ${verifyResult.error?.message}`);
    }

    console.log("Signature verified:", verifyResult.data);
  } catch (error) {
    console.error("Error:", error);
    process.exit(1);
  }
}

// Run the example
main().catch(console.error);
