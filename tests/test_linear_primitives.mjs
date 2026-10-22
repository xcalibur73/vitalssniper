// Comprehensive verification for Linear ArrayPool and AsyncLock primitives
// Strict compliance: strictly zero em-dashes and zero en-dashes

import assert from 'assert';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { ArrayPool, withSharedArray } from '../dist/utils/arrayPool.js';
import { AsyncLock } from '../dist/utils/asyncLock.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log('=== TEST SUITE: LINEAR PRIMITIVES (ARRAYPOOL & ASYNCLOCK) ===\n');

// 1. Verify popup.js bundle contains ArrayPool and AsyncLock symbols
console.log('--- 1. Testing popup.js bundle symbols ---');
const popupJsPath = path.resolve(__dirname, '../popup.js');
const popupJs = fs.readFileSync(popupJsPath, 'utf8');

const requiredSymbols = [
  'class ArrayPool',
  'withSharedArray',
  'class AsyncLock',
  'runShared',
  'runExclusive',
  'maxExclusiveQueueLength',
  'clearQueuedCallbacks'
];

for (const sym of requiredSymbols) {
  assert(popupJs.includes(sym), `popup.js must contain '${sym}'`);
}
console.log('PASS: ArrayPool and AsyncLock symbols are present in popup.js bundle.');

// 2. Test ArrayPool method poisoning
console.log('--- 2. Testing ArrayPool length-mutating method poisoning ---');
{
  const pool = new ArrayPool(1000);
  let checkedPoison = 0;

  pool.withSharedArray(10, (arr) => {
    // Assert length matches requested size exactly
    assert.strictEqual(arr.length, 10, 'Array length must match requested size exactly');

    // Index assignment must succeed
    arr[0] = { id: 1, name: 'perf-marker' };
    arr[1] = { id: 2, name: 'loaf-entry' };
    assert.strictEqual(arr[0].id, 1);
    assert.strictEqual(arr[1].name, 'loaf-entry');

    // Test push poison
    assert.throws(() => {
      arr.push({ id: 3 });
    }, /length-mutating method 'push' is prohibited/, 'push must throw');
    checkedPoison++;

    // Test pop poison
    assert.throws(() => {
      arr.pop();
    }, /length-mutating method 'pop' is prohibited/, 'pop must throw');
    checkedPoison++;

    // Test shift poison
    assert.throws(() => {
      arr.shift();
    }, /length-mutating method 'shift' is prohibited/, 'shift must throw');
    checkedPoison++;

    // Test unshift poison
    assert.throws(() => {
      arr.unshift({ id: 0 });
    }, /length-mutating method 'unshift' is prohibited/, 'unshift must throw');
    checkedPoison++;

    // Test splice poison
    assert.throws(() => {
      arr.splice(0, 1);
    }, /length-mutating method 'splice' is prohibited/, 'splice must throw');
    checkedPoison++;
  });

  assert.strictEqual(checkedPoison, 5, 'All 5 length-mutating methods must be poisoned');
  console.log('PASS: All 5 mutating methods (push, pop, shift, unshift, splice) correctly poisoned.');
}

// 3. Test ArrayPool element cleanup to prevent object retention
console.log('--- 3. Testing ArrayPool memory cleanup to prevent object retention ---');
{
  const pool = new ArrayPool(50);
  let leakedRef = null;

  pool.withSharedArray(5, (arr) => {
    leakedRef = arr;
    arr[0] = { data: 'heavy-retained-object' };
    arr[1] = { data: 'another-object' };
    arr[4] = { data: 'boundary-object' };
  });

  // Verify elements in the underlying array were wiped to undefined
  assert(leakedRef !== null, 'Captured array reference must exist');
  for (let i = 0; i < leakedRef.length; i++) {
    assert.strictEqual(leakedRef[i], undefined, `Element at index ${i} must be reset to undefined`);
  }
  // Verify methods are restored on the array
  assert.doesNotThrow(() => {
    leakedRef.push('can-push-after-loan');
  }, 'Methods must be unpoisoned after loan completes');

  console.log('PASS: Array elements wiped to undefined and methods restored.');
}

// 4. Test ArrayPool nested fallback
console.log('--- 4. Testing ArrayPool fallback to fresh array during concurrent loan ---');
{
  const pool = new ArrayPool(50);
  let outerRan = false;
  let innerRan = false;

  pool.withSharedArray(8, (outerArr) => {
    outerRan = true;
    outerArr[0] = 'outer';

    // Nested call while outer is in use must produce an unpoisoned fresh fallback array
    pool.withSharedArray(4, (innerArr) => {
      innerRan = true;
      assert.notStrictEqual(innerArr, outerArr, 'Inner fallback must be distinct from outer pooled array');
      // Fallback is a fresh standard array, so standard push works
      assert.doesNotThrow(() => {
        innerArr.push('fallback-element');
      }, 'Fallback array should allow push');
    });
  });

  assert(outerRan && innerRan, 'Both outer and inner loan callbacks must execute');
  console.log('PASS: Concurrent loan falls back to fresh array without collision.');
}

// 4b. Test ArrayPool dynamic size variation and exact lengths
console.log('--- 4b. Testing ArrayPool dynamic size variation ---');
{
  const pool = new ArrayPool(1000);
  pool.withSharedArray(5, (arr) => {
    assert.strictEqual(arr.length, 5, 'Initial size must be 5');
  });
  pool.withSharedArray(30, (arr) => {
    assert.strictEqual(arr.length, 30, 'Grown size must be 30');
  });
  pool.withSharedArray(3, (arr) => {
    assert.strictEqual(arr.length, 3, 'Shrunk size must be 3');
  });
  console.log('PASS: ArrayPool dynamically resizes to exact requested lengths without retention.');
}

// 4c. Test ArrayPool async callback lifecycle
console.log('--- 4c. Testing ArrayPool async callback lifecycle ---');
await (async () => {
  const pool = new ArrayPool(1000);
  const asyncResult = await pool.withSharedArray(6, async (arr) => {
    arr[0] = 'async-payload';
    await new Promise(r => setTimeout(r, 20));
    assert.strictEqual(arr[0], 'async-payload', 'Payload must persist during async suspension');
    return arr[0];
  });
  assert.strictEqual(asyncResult, 'async-payload');
  assert.strictEqual(pool.isPoolInUse(), false, 'Pool must be marked available after async completion');
  console.log('PASS: Async callback maintains pool loan throughout Promise lifecycle.');
})();

// 5. Test ArrayPool delayed release timer
console.log('--- 5. Testing ArrayPool delayed release timer ---');
await (async () => {
  const shortLivedPool = new ArrayPool(25);
  shortLivedPool.withSharedArray(16, (arr) => {
    arr[0] = 1;
  });
  assert.strictEqual(shortLivedPool.hasReleaseTimer(), true, 'Release timer must be active after loan');
  assert(shortLivedPool.getPoolCapacity() >= 16, 'Pool capacity must be preserved initially');

  // Wait for 35ms to let timer fire
  await new Promise(r => setTimeout(r, 35));
  assert.strictEqual(shortLivedPool.getPoolCapacity(), 0, 'Pool must be reclaimed after delayed timer fires');
  assert.strictEqual(shortLivedPool.hasReleaseTimer(), false, 'Timer must be cleared after reclaim');
  console.log('PASS: Delayed release timer cleanly reclaims pool buffer.');
})();

// 6. Test AsyncLock concurrent shared reads
console.log('--- 6. Testing AsyncLock concurrent shared reads ---');
await (async () => {
  const lock = new AsyncLock();
  let concurrentActive = 0;
  let peakConcurrent = 0;

  const reader = async (id) => {
    return lock.runShared(async () => {
      concurrentActive++;
      if (concurrentActive > peakConcurrent) {
        peakConcurrent = concurrentActive;
      }
      await new Promise(r => setTimeout(r, 20));
      concurrentActive--;
      return `read-${id}`;
    });
  };

  const results = await Promise.all([reader(1), reader(2), reader(3), reader(4), reader(5)]);
  assert.deepStrictEqual(results, ['read-1', 'read-2', 'read-3', 'read-4', 'read-5']);
  assert.strictEqual(peakConcurrent, 5, 'All 5 readers must run concurrently');
  assert.strictEqual(lock.getActiveReaderCount(), 0, 'Active readers must return to 0');
  console.log('PASS: Readers execute concurrently without blocking each other.');
})();

// 7. Test AsyncLock exclusive write isolation
console.log('--- 7. Testing AsyncLock exclusive write isolation ---');
await (async () => {
  const lock = new AsyncLock();
  const timeline = [];

  const task1 = lock.runShared(async () => {
    timeline.push('read1-start');
    await new Promise(r => setTimeout(r, 30));
    timeline.push('read1-end');
    return 'r1';
  });

  const task2 = lock.runExclusive(async () => {
    timeline.push('write1-start');
    assert.strictEqual(lock.isRunningExclusive(), true, 'isRunningExclusive must be true during exclusive run');
    await new Promise(r => setTimeout(r, 30));
    timeline.push('write1-end');
    return 'w1';
  });

  const task3 = lock.runShared(async () => {
    timeline.push('read2-start');
    await new Promise(r => setTimeout(r, 10));
    timeline.push('read2-end');
    return 'r2';
  });

  await Promise.all([task1, task2, task3]);

  // Assert order: read1 must end before write1 starts, write1 must end before read2 starts
  const read1EndIdx = timeline.indexOf('read1-end');
  const write1StartIdx = timeline.indexOf('write1-start');
  const write1EndIdx = timeline.indexOf('write1-end');
  const read2StartIdx = timeline.indexOf('read2-start');

  assert(read1EndIdx < write1StartIdx, 'Read 1 must finish before Write 1 starts');
  assert(write1EndIdx < read2StartIdx, 'Write 1 must finish before Read 2 starts');
  console.log('PASS: Exclusive write is fully isolated from concurrent reads.');
})();

// 8. Test AsyncLock backpressure queue shedding
console.log('--- 8. Testing AsyncLock backpressure queue shedding ---');
await (async () => {
  const lock = new AsyncLock({ maxExclusiveQueueLength: 2 });

  // Hold exclusive lock with a blocking worker
  let releaseWorker;
  const workerPromise = new Promise(res => { releaseWorker = res; });
  const blocker = lock.runExclusive(async () => {
    await workerPromise;
    return 'blocker-done';
  });

  // Enqueue up to max queue length (2)
  const queued1 = lock.runExclusive(async () => 'queued-1');
  const queued2 = lock.runExclusive(async () => 'queued-2');
  assert.strictEqual(lock.getExclusiveQueueLength(), 2, 'Exclusive queue length must be 2');

  // Next requests overflow queue and must be dropped/resolved with undefined
  const overflow1 = await lock.runExclusive(async () => 'overflow-1');
  const overflow2 = await lock.runExclusive(async () => 'overflow-2');

  assert.strictEqual(overflow1, undefined, 'Overflow request 1 must resolve to undefined');
  assert.strictEqual(overflow2, undefined, 'Overflow request 2 must resolve to undefined');

  // Release blocker and wait for queued tasks to finish
  releaseWorker();
  const blockerRes = await blocker;
  const q1Res = await queued1;
  const q2Res = await queued2;

  assert.strictEqual(blockerRes, 'blocker-done');
  assert.strictEqual(q1Res, 'queued-1');
  assert.strictEqual(q2Res, 'queued-2');
  assert.strictEqual(lock.getExclusiveQueueLength(), 0, 'Queue must be drained');
  console.log('PASS: Excessive exclusive requests shed backpressure with undefined.');
})();

// 8b. Test AsyncLock unlimited queue when maxExclusiveQueueLength is 0
console.log('--- 8b. Testing AsyncLock unlimited queue when maxExclusiveQueueLength is 0 ---');
await (async () => {
  const lock = new AsyncLock({ maxExclusiveQueueLength: 0 });
  let releaseWorker;
  const workerPromise = new Promise(res => { releaseWorker = res; });
  const blocker = lock.runExclusive(async () => {
    await workerPromise;
    return 'blocker-done';
  });

  // Enqueue 5 tasks: none should be shed because 0 indicates unlimited queue
  const q1 = lock.runExclusive(async () => 'task-1');
  const q2 = lock.runExclusive(async () => 'task-2');
  const q3 = lock.runExclusive(async () => 'task-3');

  releaseWorker();
  const [bRes, r1, r2, r3] = await Promise.all([blocker, q1, q2, q3]);
  assert.strictEqual(bRes, 'blocker-done');
  assert.strictEqual(r1, 'task-1');
  assert.strictEqual(r2, 'task-2');
  assert.strictEqual(r3, 'task-3');
  console.log('PASS: maxExclusiveQueueLength: 0 permits unlimited queued tasks without shedding.');
})();

// 9. Test AsyncLock clearQueuedCallbacks
console.log('--- 9. Testing AsyncLock clearQueuedCallbacks ---');
await (async () => {
  const lock = new AsyncLock({ maxExclusiveQueueLength: 10 });
  let releaseBlocker;
  const blockerPromise = new Promise(r => { releaseBlocker = r; });

  const active = lock.runExclusive(async () => {
    await blockerPromise;
    return 'active-done';
  });

  const queuedTask = lock.runExclusive(async () => 'queued-item');
  const queuedReader = lock.runShared(async () => 'queued-reader');

  assert.strictEqual(lock.getExclusiveQueueLength(), 1);
  assert.strictEqual(lock.getSharedQueueLength(), 1);

  // Clear queued callbacks
  lock.clearQueuedCallbacks();
  assert.strictEqual(lock.getExclusiveQueueLength(), 0);
  assert.strictEqual(lock.getSharedQueueLength(), 0);

  const [queuedRes, readerRes] = await Promise.all([queuedTask, queuedReader]);
  assert.strictEqual(queuedRes, undefined, 'Cleared exclusive task must resolve to undefined');
  assert.strictEqual(readerRes, undefined, 'Cleared shared reader must resolve to undefined');

  releaseBlocker();
  await active;
  console.log('PASS: clearQueuedCallbacks drains all queued writers and readers.');
})();

// 10. Verify zero em-dash and en-dash compliance
console.log('--- 10. Testing zero em-dash and en-dash compliance ---');
const filesToCheck = [
  path.resolve(__dirname, '../src/utils/arrayPool.ts'),
  path.resolve(__dirname, '../src/utils/asyncLock.ts'),
  path.resolve(__dirname, '../tests/test_linear_primitives.mjs')
];

for (const f of filesToCheck) {
  const content = fs.readFileSync(f, 'utf8');
  assert(!content.includes('\u2014'), `File ${f} must not contain em-dashes`);
  assert(!content.includes('\u2013'), `File ${f} must not contain en-dashes`);
}
console.log('PASS: Exactly zero em-dashes and zero en-dashes across all primitive files.');

console.log('\n=== ALL LINEAR PRIMITIVE TESTS PASSED (EXIT CODE 0) ===');
