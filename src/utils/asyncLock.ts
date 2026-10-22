// Linear AsyncLock (Reader-Writer Lock with Backpressure Shedding) for VitalsSniper
// Coordinates concurrent telemetry capture and prevents interaction contention
// Strictly zero em-dashes and zero en-dashes

interface QueuedEntry<T> {
  callback: () => Promise<T> | T;
  resolve: (value: T | undefined) => void;
  reject: (reason: any) => void;
}

export interface AsyncLockOptions {
  maxExclusiveQueueLength?: number;
}

export class AsyncLock {
  private activeReaders: number = 0;
  private exclusiveRunning: boolean = false;
  private readonly maxExclusiveQueueLength: number;
  private readonly exclusiveQueue: Array<QueuedEntry<any>> = [];
  private readonly sharedQueue: Array<QueuedEntry<any>> = [];

  constructor(options: AsyncLockOptions = {}) {
    this.maxExclusiveQueueLength = options.maxExclusiveQueueLength ?? 100;
  }

  public isRunningExclusive(): boolean {
    return this.exclusiveRunning;
  }

  public getActiveReaderCount(): number {
    return this.activeReaders;
  }

  public getExclusiveQueueLength(): number {
    return this.exclusiveQueue.length;
  }

  public getSharedQueueLength(): number {
    return this.sharedQueue.length;
  }

  public clearQueuedCallbacks(): void {
    while (this.exclusiveQueue.length > 0) {
      const entry = this.exclusiveQueue.shift();
      if (entry) {
        entry.resolve(undefined);
      }
    }
    while (this.sharedQueue.length > 0) {
      const entry = this.sharedQueue.shift();
      if (entry) {
        entry.resolve(undefined);
      }
    }
  }

  public async runShared<T>(callback: () => Promise<T> | T): Promise<T> {
    // If an exclusive write is running or waiting, queue reader to prevent writer starvation
    if (this.exclusiveRunning || this.exclusiveQueue.length > 0) {
      return new Promise<T>((resolve, reject) => {
        this.sharedQueue.push({
          callback,
          resolve: resolve as (val: any) => void,
          reject
        });
      });
    }

    this.activeReaders++;
    try {
      return await callback();
    } finally {
      this.activeReaders--;
      if (this.activeReaders === 0) {
        this.pumpQueue();
      }
    }
  }

  public async runExclusive<T>(callback: () => Promise<T> | T): Promise<T | undefined> {
    // Backpressure queue shedding: drops or resolves with undefined when exclusive queue overflows
    if (this.maxExclusiveQueueLength >= 1 && this.exclusiveQueue.length >= this.maxExclusiveQueueLength) {
      return Promise.resolve(undefined);
    }

    // If readers are active or another exclusive write is running, queue
    if (this.exclusiveRunning || this.activeReaders > 0) {
      return new Promise<T | undefined>((resolve, reject) => {
        this.exclusiveQueue.push({
          callback,
          resolve,
          reject
        });
      });
    }

    this.exclusiveRunning = true;
    try {
      return await callback();
    } finally {
      this.exclusiveRunning = false;
      this.pumpQueue();
    }
  }

  private pumpQueue(): void {
    if (this.exclusiveRunning) {
      return;
    }

    // Prioritize waiting exclusive writer once active readers reach zero
    if (this.exclusiveQueue.length > 0) {
      if (this.activeReaders === 0) {
        const nextWriter = this.exclusiveQueue.shift();
        if (nextWriter) {
          this.exclusiveRunning = true;
          (async () => {
            try {
              const res = await nextWriter.callback();
              nextWriter.resolve(res);
            } catch (err) {
              nextWriter.reject(err);
            } finally {
              this.exclusiveRunning = false;
              this.pumpQueue();
            }
          })();
        }
      }
      return;
    }

    // If no exclusive writers are queued, release all queued shared readers concurrently
    if (this.sharedQueue.length > 0) {
      const toDrain = this.sharedQueue.splice(0, this.sharedQueue.length);
      for (const nextReader of toDrain) {
        this.activeReaders++;
        (async () => {
          try {
            const res = await nextReader.callback();
            nextReader.resolve(res);
          } catch (err) {
            nextReader.reject(err);
          } finally {
            this.activeReaders--;
            if (this.activeReaders === 0) {
              this.pumpQueue();
            }
          }
        })();
      }
    }
  }
}

export const defaultAsyncLock = new AsyncLock();
