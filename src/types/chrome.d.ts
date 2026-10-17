// Chrome Manifest V3 Type Definitions for VitalsSniper Extension
declare namespace chrome {
  namespace storage {
    interface StorageArea {
      get(keys?: string | string[] | Record<string, any> | null, callback?: (items: Record<string, any>) => void): Promise<Record<string, any>>;
      set(items: Record<string, any>, callback?: () => void): Promise<void>;
      remove(keys: string | string[], callback?: () => void): Promise<void>;
      clear(callback?: () => void): Promise<void>;
    }
    const local: StorageArea;
    const sync: StorageArea;
    const session: StorageArea;
  }

  namespace runtime {
    function sendMessage(message: any, responseCallback?: (response: any) => void): Promise<any>;
    const onMessage: {
      addListener(callback: (message: any, sender: any, sendResponse: (response?: any) => void) => boolean | void): void;
    };
    const onInstalled: {
      addListener(callback: (details?: any) => void): void;
    };
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
    function query(queryInfo: Record<string, any>, callback?: (result: Tab[]) => void): Promise<Tab[]>;
    function create(createProperties: { url?: string; active?: boolean }, callback?: (tab: Tab) => void): Promise<Tab>;
    function reload(tabId?: number, reloadProperties?: { bypassCache?: boolean }, callback?: () => void): Promise<void>;
  }

  namespace declarativeNetRequest {
    interface RuleAction {
      type: string;
      requestHeaders?: Array<{ header: string; operation: string; value?: string }>;
      responseHeaders?: Array<{ header: string; operation: string; value?: string }>;
    }
    interface RuleCondition {
      urlFilter?: string;
      resourceTypes?: string[];
    }
    interface Rule {
      id: number;
      priority: number;
      action: RuleAction;
      condition: RuleCondition;
    }
    interface UpdateRuleOptions {
      addRules?: Rule[];
      removeRuleIds?: number[];
    }
    function updateSessionRules(options: UpdateRuleOptions, callback?: () => void): Promise<void>;
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
