import { DIDCommClient, DefaultDIDCommPlugin, PackingType } from '../../src';

async function main() {
  try {
    // Initialize the client
    const client = new DIDCommClient(
      {
        defaultPacking: PackingType.ANONCRYPT,
        useHttps: false,
      },
      new DefaultDIDCommPlugin()
    );

    // Initialize WASM module
    const initResult = await client.initialize();
    if (!initResult.success) {
      throw new Error(initResult.error?.message ?? 'Failed to initialize client');
    }

    console.log('✅ Client initialized successfully');

    // Example message
    const message = {
      id: `test-${Date.now()}`,
      type: 'example/1.0',
      body: {
        text: 'Hello from Node.js!',
        timestamp: Date.now(),
      },
    };

    // Encrypt message
    const encrypted = await client.encrypt(message, {
      to: ['did:example:recipient'],
    });

    if (!encrypted.success || !encrypted.data) {
      throw new Error(encrypted.error?.message ?? 'Failed to encrypt message');
    }

    console.log('✅ Message encrypted successfully');

    // Decrypt message
    const decrypted = await client.decrypt(encrypted.data, {});

    if (!decrypted.success || !decrypted.data) {
      throw new Error(decrypted.error?.message ?? 'Failed to decrypt message');
    }

    console.log('✅ Message decrypted successfully');
    console.log('\nDecrypted message:', JSON.stringify(decrypted.data, null, 2));
  } catch (error) {
    console.error('\n❌ Error:', error instanceof Error ? error.message : 'Unknown error occurred');
    process.exit(1);
  }
}

main();
