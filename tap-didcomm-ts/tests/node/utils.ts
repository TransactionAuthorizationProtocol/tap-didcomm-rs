import type { Message } from '../../src';

/**
 * Creates a test message with specified size
 */
export function createTestMessage(size: number): Message {
  return {
    id: `test-${Date.now()}`,
    type: 'test',
    body: { data: 'x'.repeat(size) },
  };
}

/**
 * Creates a batch of test messages
 */
export function createTestMessages(count: number, size: number): Message[] {
  return Array.from({ length: count }, (_, i) => ({
    id: `test-${i}-${Date.now()}`,
    type: 'test',
    body: { data: 'x'.repeat(size) },
  }));
}

/**
 * Simulates a message stream
 */
export async function* createMessageStream(
  count: number,
  size: number,
): AsyncGenerator<Message> {
  for (let i = 0; i < count; i++) {
    yield {
      id: `stream-${i}-${Date.now()}`,
      type: 'test',
      body: { chunk: i, data: 'x'.repeat(size) },
    };
    await new Promise(resolve => setTimeout(resolve, 10)); // Simulate delay
  }
}

/**
 * Measures memory usage during test execution
 */
export function measureMemoryUsage(): {
  before: NodeJS.MemoryUsage;
  after: NodeJS.MemoryUsage;
} {
  const before = process.memoryUsage();
  return {
    before,
    after: process.memoryUsage(),
  };
}

/**
 * Checks if memory usage is within acceptable limits
 */
export function isMemoryUsageAcceptable(
  before: NodeJS.MemoryUsage,
  after: NodeJS.MemoryUsage,
  maxIncreaseMB = 50,
): boolean {
  const heapIncrease = (after.heapUsed - before.heapUsed) / 1024 / 1024;
  return heapIncrease < maxIncreaseMB;
} 