// Chrome Manifest V3 Type Definitions for VitalsSniper Extension
declare namespace chrome {
  namespace storage {
    interface StorageArea {
      get(keys?: string | string[] | Record<string, any> | null): Promise<Record<string, any>>;
      set(items: Record<string, any>): Promise<void>;
      remove(keys: string | string[]): Promise<void>;
      clear(): Promise<void>;
    }
    const local: StorageArea;
    const sync: StorageArea;
  }

  namespace tabs {
    interface Tab {
      id?: number;
      index: number;
      windowId: number;
      highlighted: boolean;
      active: boolean;
      pinned: boolean;
      url?: string;
      title?: string;
      favIconUrl?: string;
      status?: string;
      incognito: boolean;
      width?: number;
      height?: number;
    }
    function query(queryInfo: { active?: boolean; currentWindow?: boolean }): Promise<Tab[]>;
    function create(createProperties: { url?: string; active?: boolean }, callback?: (tab: Tab) => void): Promise<Tab>;
  }

  namespace scripting {
    interface InjectionTarget {
      tabId: number;
      allFrames?: boolean;
      frameIds?: number[];
    }
    interface ScriptInjection<T = any> {
      target: InjectionTarget;
      func?: (...args: any[]) => T;
      args?: any[];
      files?: string[];
    }
    interface InjectionResult<T = any> {
      frameId: number;
      result: T;
    }
    function executeScript<T = any>(
      injection: ScriptInjection<T>,
      callback?: (results: InjectionResult<T>[]) => void
    ): Promise<InjectionResult<T>[]>;
  }
}
