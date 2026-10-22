// Linear ArrayPool port for VitalsSniper LoAF profiling
// Prevents GC churn during 60 FPS animation frame measurements
// Strictly zero em-dashes and zero en-dashes

export class ArrayPool {
  private pool: any[] | null = null;
  private inUse: boolean = false;
  private releaseTimer: ReturnType<typeof setTimeout> | null = null;
  private lastUsedAt: number = 0;
  private readonly releaseDelayMs: number;

  constructor(releaseDelayMs = 30000) {
    this.releaseDelayMs = releaseDelayMs;
  }

  private growToSize(size: number): any[] {
    if (!this.pool) {
      this.pool = [];
    }
    const arr = this.pool;
    while (arr.length < size) {
      arr.push(undefined);
    }
    arr.length = size;
    return arr;
  }

  private cleanup(
    arr: any[],
    origPush: any,
    origPop: any,
    origShift: any,
    origUnshift: any,
    origSplice: any
  ): void {
    // Restore poisoned methods
    arr.push = origPush;
    arr.pop = origPop;
    arr.shift = origShift;
    arr.unshift = origUnshift;
    arr.splice = origSplice;

    // Clear all elements to undefined to prevent object retention
    for (let i = 0; i < arr.length; i++) {
      arr[i] = undefined;
    }

    this.inUse = false;
    this.lastUsedAt = Date.now();
    this.scheduleRelease();
  }

  private scheduleRelease(): void {
    if (this.releaseTimer !== null) {
      return;
    }
    this.releaseTimer = setTimeout(() => {
      this.releaseTimer = null;
      if (this.pool && !this.inUse && Date.now() - this.lastUsedAt >= this.releaseDelayMs) {
        this.pool = null;
      } else if (this.pool && !this.inUse) {
        const remaining = this.releaseDelayMs - (Date.now() - this.lastUsedAt);
        this.releaseTimer = setTimeout(() => {
          this.releaseTimer = null;
          if (this.pool && !this.inUse && Date.now() - this.lastUsedAt >= this.releaseDelayMs) {
            this.pool = null;
          }
        }, Math.max(remaining, 10));
        if (this.releaseTimer && typeof (this.releaseTimer as any).unref === 'function') {
          (this.releaseTimer as any).unref();
        }
      }
    }, this.releaseDelayMs);

    if (this.releaseTimer && typeof (this.releaseTimer as any).unref === 'function') {
      (this.releaseTimer as any).unref();
    }
  }

  public withSharedArray<T = any, R = any>(size: number, callback: (arr: T[]) => R): R {
    // Fallback to fresh array when pool is currently in use
    if (this.inUse) {
      const fallback = new Array<T>(size);
      return callback(fallback);
    }

    if (size < 0 || !Number.isInteger(size)) {
      throw new RangeError(`ArrayPool: Invalid array size ${size}`);
    }

    if (this.releaseTimer !== null) {
      clearTimeout(this.releaseTimer);
      this.releaseTimer = null;
    }

    this.inUse = true;
    let arr: any[];
    try {
      arr = this.growToSize(size);
    } catch (err) {
      this.inUse = false;
      this.scheduleRelease();
      throw err;
    }

    // Poison length-mutating methods during callback execution
    const poison = (methodName: string) => () => {
      throw new Error(`ArrayPool: length-mutating method '${methodName}' is prohibited on pooled array`);
    };

    const origPush = arr.push;
    const origPop = arr.pop;
    const origShift = arr.shift;
    const origUnshift = arr.unshift;
    const origSplice = arr.splice;

    arr.push = poison('push') as any;
    arr.pop = poison('pop') as any;
    arr.shift = poison('shift') as any;
    arr.unshift = poison('unshift') as any;
    arr.splice = poison('splice') as any;

    try {
      const result = callback(arr as T[]);
      if (result && typeof (result as any).then === 'function') {
        return ((result as unknown as Promise<any>).finally(() => {
          this.cleanup(arr, origPush, origPop, origShift, origUnshift, origSplice);
        }) as unknown) as R;
      }
      this.cleanup(arr, origPush, origPop, origShift, origUnshift, origSplice);
      return result;
    } catch (err) {
      this.cleanup(arr, origPush, origPop, origShift, origUnshift, origSplice);
      throw err;
    }
  }

  public isPoolInUse(): boolean {
    return this.inUse;
  }

  public getPoolCapacity(): number {
    return this.pool ? this.pool.length : 0;
  }

  public hasReleaseTimer(): boolean {
    return this.releaseTimer !== null;
  }

  public releaseNow(): void {
    if (this.releaseTimer !== null) {
      clearTimeout(this.releaseTimer);
      this.releaseTimer = null;
    }
    this.pool = null;
    this.inUse = false;
  }
}

export const defaultArrayPool = new ArrayPool(30000);

export function withSharedArray<T = any, R = any>(size: number, callback: (arr: T[]) => R): R {
  return defaultArrayPool.withSharedArray<T, R>(size, callback);
}
