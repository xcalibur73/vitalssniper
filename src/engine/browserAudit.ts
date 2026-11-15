// In-Page Forensic Browser Auditor
// Injected into the active prospect tab via chrome.scripting.executeScript()
// Zero em-dash compliance: strictly hyphens or colons

import { detectTechnologies } from './techDetector';
import { TechnologyDetection, LoafAttribution, LoafScriptAttributionItem, LoadState, InpSubpartAttribution } from '../types/audit';
import { withSharedArray } from '../utils/arrayPool';
import { AsyncLock } from '../utils/asyncLock';

export function getLoadState(timestamp: number): LoadState {
  if (typeof document !== 'undefined' && document.readyState === 'loading') {
    return 'loading';
  }

  const navEntry = (typeof performance !== 'undefined' && typeof performance.getEntriesByType === 'function')
    ? (performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming | undefined)
    : undefined;

  if (navEntry) {
    if (navEntry.domInteractive && timestamp < navEntry.domInteractive) {
      return 'loading';
    }
    if (
      navEntry.domContentLoadedEventStart === 0 ||
      (navEntry.domContentLoadedEventStart && timestamp < navEntry.domContentLoadedEventStart)
    ) {
      return 'dom-interactive';
    }
    if (
      (navEntry.domContentLoadedEventEnd && timestamp < navEntry.domContentLoadedEventEnd) ||
      (navEntry.loadEventStart && timestamp < navEntry.loadEventStart) ||
      navEntry.domComplete === 0 ||
      (navEntry.domComplete && timestamp < navEntry.domComplete)
    ) {
      return 'dom-content-loaded';
    }
  }

  return 'complete';
}

export async function inspectPageForensics() {
  const scanStartTime = performance.now();

  // --- 1. CORE WEB VITALS & TIMING OBSERVERS (ASYNC BUFFERED DISPATCH) ---
  let lcpMs: number | null = null;
  let lcpSource: string = 'unavailable';
  let lcpElementSelector: string | null = null;
  let lcpElementType: string | null = null;
  let fcpMs: number | null = null;
  let cls = 0;
  let hasClsEntries = false;
  let inpMs: number | null = null;
  let inpObserved = false;
  let longTaskCount = 0;
  let longestTaskMs: number | null = null;
  let totalBlockingTimeMs = 0;

  function getSelector(node: any, maxLen = 100): string {
    if (!node) return '';
    if (node.nodeType === 3) node = node.parentNode;
    if (!node || node.nodeType !== 1) return '';
    let sel = '';
    try {
      let cur: any = node;
      while (cur && cur.nodeType === 1 && cur.nodeName.toLowerCase() !== 'html') {
        const el = cur;
        let part = el.nodeName.toLowerCase();
        if (el.id) {
          part += '#' + el.id;
          sel = sel ? part + ' > ' + sel : part;
          break;
        }
        if (el.className && typeof el.className === 'string') {
          const clsName = el.className.trim().split(/\s+/)[0];
          if (clsName) part += '.' + clsName;
        }
        sel = sel ? part + ' > ' + sel : part;
        cur = el.parentElement;
        if (sel.length > maxLen) break;
      }
    } catch (err) { console.debug('Telemetry probe suppressed:', err); }
    return sel || (node.tagName ? node.tagName.toLowerCase() : '');
  }

  const shadowRootsCache = new WeakMap<ParentNode, ShadowRoot[]>();

  function querySelectorAllDeep<T extends Element = Element>(root: ParentNode, selector: string): T[] {
    const results: T[] = [];
    try {
      const direct = root.querySelectorAll(selector);
      for (let i = 0; i < direct.length; i++) {
        results.push(direct[i] as T);
      }

      let shadowRoots = shadowRootsCache.get(root);
      if (!shadowRoots) {
        shadowRoots = [];
        const doc = (root as any).ownerDocument || (root as Document) || (typeof document !== 'undefined' ? document : null);
        if (doc && typeof doc.createTreeWalker === 'function') {
          const filter = typeof NodeFilter !== 'undefined' ? NodeFilter.SHOW_ELEMENT : 1;
          const walker = doc.createTreeWalker(root as Node, filter);
          let el = walker.nextNode() as Element | null;
          while (el) {
            if (el.shadowRoot) {
              shadowRoots.push(el.shadowRoot);
            }
            el = walker.nextNode() as Element | null;
          }
        } else {
          const allElements = root.querySelectorAll('*');
          for (let i = 0; i < allElements.length; i++) {
            const el = allElements[i];
            if (el.shadowRoot) {
              shadowRoots.push(el.shadowRoot);
            }
          }
        }
        shadowRootsCache.set(root, shadowRoots);
      }

      for (let i = 0; i < shadowRoots.length; i++) {
        const sub = querySelectorAllDeep<T>(shadowRoots[i], selector);
        for (let j = 0; j < sub.length; j++) {
          results.push(sub[j]);
        }
      }
    } catch (err) { console.debug('Telemetry probe suppressed:', err); }
    return results;
  }

  // A. Paint entries (FCP)
  try {
    const paintEntries = performance.getEntriesByType('paint');
    paintEntries.forEach((entry: any) => {
      if (entry.name === 'first-contentful-paint') {
        fcpMs = Math.round(entry.startTime);
      }
    });
  } catch (err) { console.debug('Telemetry probe suppressed:', err); }

  // B, C, D. Asynchronous PerformanceObservers with buffered entry window
  let poLcp: PerformanceObserver | null = null;
  let poCls: PerformanceObserver | null = null;
  let poLt: PerformanceObserver | null = null;
  let poLoaf: PerformanceObserver | null = null;
  let poInp: PerformanceObserver | null = null;

  let lcpEntry: any = null;
  const rawClsEntries: Array<{
    value: number;
    startTime: number;
    hadRecentInput: boolean;
    targetNode: any;
    sources: any[];
  }> = [];
  const rawLoafEntries: any[] = [];
  const interactionEntries: any[] = [];

  await new Promise<void>(resolve => {
    // 1. Google Web Vitals Largest Contentful Paint observer
    try {
      poLcp = new PerformanceObserver((entryList) => {
        const entries = entryList.getEntries();
        if (entries.length > 0) {
          lcpEntry = entries[entries.length - 1];
          lcpMs = Math.round(lcpEntry.renderTime || lcpEntry.loadTime || lcpEntry.startTime);
          lcpSource = document.readyState !== 'complete' ? 'navigation-observed' : 'buffered-active-tab';
          if (lcpEntry.element) {
            const el = lcpEntry.element;
            lcpElementType = el.tagName ? el.tagName.toLowerCase() : 'element';
            lcpElementSelector = getSelector(el);
          } else if (lcpEntry.url) {
            lcpElementType = 'image';
            lcpElementSelector = 'img[src="' + lcpEntry.url.substring(0, 50) + '..."]';
          }
        }
      });
      poLcp.observe({ type: 'largest-contentful-paint', buffered: true });
    } catch (err) { console.debug('Telemetry probe suppressed:', err); }

    // 2. Google Web Vitals Layout Shift observer (collect raw entries with bounding box sources)
    try {
      poCls = new PerformanceObserver((entryList) => {
        entryList.getEntries().forEach((entry: any) => {
          let targetNode: any = null;
          if (entry.sources && entry.sources.length > 0 && entry.sources[0].node) {
            targetNode = entry.sources[0].node;
          }
          rawClsEntries.push({
            value: entry.value,
            startTime: entry.startTime,
            hadRecentInput: Boolean(entry.hadRecentInput),
            targetNode,
            sources: Array.isArray(entry.sources) ? entry.sources : []
          });
        });
      });
      poCls.observe({ type: 'layout-shift', buffered: true });
    } catch (err) { console.debug('Telemetry probe suppressed:', err); }

    // 3. Long Tasks observer
    try {
      poLt = new PerformanceObserver((list) => {
        list.getEntries().forEach((entry: any) => {
          longTaskCount++;
          const duration = Math.round(entry.duration);
          if (longestTaskMs === null || duration > longestTaskMs) {
            longestTaskMs = duration;
          }
          if (duration > 50) {
            totalBlockingTimeMs += (duration - 50);
          }
        });
      });
      poLt.observe({ type: 'longtask', buffered: true });
    } catch (err) { console.debug('Telemetry probe suppressed:', err); }

    // 3b. Long Animation Frames (LoAF) observer (Chrome 123+)
    try {
      const supportedTypes = (typeof PerformanceObserver !== 'undefined' && PerformanceObserver.supportedEntryTypes)
        ? PerformanceObserver.supportedEntryTypes
        : [];
      if (supportedTypes.includes('long-animation-frame')) {
        poLoaf = new PerformanceObserver((list) => {
          list.getEntries().forEach((entry: any) => {
            rawLoafEntries.push(entry);
          });
        });
        (poLoaf as any).observe({ type: 'long-animation-frame', buffered: true });
      }
    } catch (err) { console.debug('Telemetry probe suppressed:', err); }

    // 4. Google Web Vitals INP (Event Timing observer)
    try {
      const supportedTypes = (typeof PerformanceObserver !== 'undefined' && PerformanceObserver.supportedEntryTypes)
        ? PerformanceObserver.supportedEntryTypes
        : [];
      if (supportedTypes.includes('event')) {
        poInp = new PerformanceObserver((list) => {
          list.getEntries().forEach((entry: any) => {
            interactionEntries.push(entry);
          });
        });
        (poInp as any).observe({ type: 'event', buffered: true, durationThreshold: 16 });
      } else if (supportedTypes.includes('first-input')) {
        poInp = new PerformanceObserver((list) => {
          list.getEntries().forEach((entry: any) => {
            interactionEntries.push(entry);
          });
        });
        poInp.observe({ type: 'first-input', buffered: true });
      }
    } catch (err) { console.debug('Telemetry probe suppressed:', err); }

    // Observation window of 200ms allows the browser event loop to flush buffered entries
    setTimeout(resolve, 200);
  });

  // Clean up observers and harvest all queued records before disconnection
  try {
    if (poLcp) {
      const records = (poLcp as PerformanceObserver).takeRecords();
      if (records.length > 0) {
        lcpEntry = records[records.length - 1];
        lcpMs = Math.round(lcpEntry.renderTime || lcpEntry.loadTime || lcpEntry.startTime);
        lcpSource = document.readyState !== 'complete' ? 'navigation-observed' : 'buffered-active-tab';
        if (lcpEntry.element) {
          const el = lcpEntry.element;
          lcpElementType = el.tagName ? el.tagName.toLowerCase() : 'element';
          lcpElementSelector = getSelector(el);
        } else if (lcpEntry.url) {
          lcpElementType = 'image';
          lcpElementSelector = 'img[src="' + lcpEntry.url.substring(0, 50) + '..."]';
        }
      }
      (poLcp as PerformanceObserver).disconnect();
    }
  } catch (err) { console.debug('Telemetry probe suppressed:', err); }

  try {
    if (poCls) {
      const records = (poCls as PerformanceObserver).takeRecords();
      records.forEach((entry: any) => {
        let targetNode: any = null;
        if (entry.sources && entry.sources.length > 0) {
          const validSource = entry.sources.find((s: any) => s.node && s.node.nodeType === 1) || entry.sources[0];
          if (validSource && validSource.node) {
            targetNode = validSource.node;
          }
        }
        rawClsEntries.push({
          value: entry.value,
          startTime: entry.startTime,
          hadRecentInput: Boolean(entry.hadRecentInput),
          targetNode,
          sources: Array.isArray(entry.sources) ? entry.sources : []
        });
      });
      (poCls as PerformanceObserver).disconnect();
    }
  } catch (err) { console.debug('Telemetry probe suppressed:', err); }

  try {
    if (poLt) {
      const records = (poLt as PerformanceObserver).takeRecords();
      records.forEach((entry: any) => {
        longTaskCount++;
        const duration = Math.round(entry.duration);
        if (longestTaskMs === null || duration > longestTaskMs) {
          longestTaskMs = duration;
        }
        if (duration > 50) {
          totalBlockingTimeMs += (duration - 50);
        }
      });
      (poLt as PerformanceObserver).disconnect();
    }
  } catch (err) { console.debug('Telemetry probe suppressed:', err); }

  try {
    if (poLoaf) {
      const records = (poLoaf as PerformanceObserver).takeRecords();
      records.forEach((entry: any) => {
        rawLoafEntries.push(entry);
      });
      (poLoaf as PerformanceObserver).disconnect();
    }
  } catch (err) { console.debug('Telemetry probe suppressed:', err); }

  try {
    if (poInp) {
      const records = (poInp as PerformanceObserver).takeRecords();
      records.forEach((entry: any) => {
        interactionEntries.push(entry);
      });
      (poInp as PerformanceObserver).disconnect();
    }
  } catch (err) { console.debug('Telemetry probe suppressed:', err); }

  // Calculate canonical CLS session windows reproducing Google Web Vitals logic:
  // 1s gap between shifts, 5s maximum session window length, hadRecentInput filtering, reporting maximum window.
  let largestShiftValue = 0;
  let largestShiftTarget: string | null = null;
  const shiftDetails: any[] = [];
  let largestShiftBoundingBox: any = null;

  function toBoundingBox(rect: any): any {
    if (!rect) return null;
    return {
      x: Math.round(rect.x || rect.left || 0),
      y: Math.round(rect.y || rect.top || 0),
      width: Math.round(rect.width || 0),
      height: Math.round(rect.height || 0),
      top: Math.round(rect.top || 0),
      right: Math.round(rect.right || 0),
      bottom: Math.round(rect.bottom || 0),
      left: Math.round(rect.left || 0)
    };
  }

  if (rawClsEntries.length > 0) {
    let maxSessionScore = 0;
    let currentSessionScore = 0;
    let currentSessionStart = 0;
    let currentSessionLast = 0;

    rawClsEntries.forEach(entry => {
      if (entry.hadRecentInput) return;
      hasClsEntries = true;

      const sources = entry.sources || [];
      let primarySource: any = null;
      let nodeSelector: string | null = null;
      let nodeTag: string | null = null;

      if (sources.length > 0) {
        primarySource = sources.find((s: any) => s.node && s.node.nodeType === 1) || sources[0];
        if (primarySource && primarySource.node) {
          nodeSelector = getSelector(primarySource.node);
          nodeTag = primarySource.node.tagName ? primarySource.node.tagName.toLowerCase() : null;
        }
      } else if (entry.targetNode) {
        nodeSelector = getSelector(entry.targetNode);
        nodeTag = entry.targetNode.tagName ? entry.targetNode.tagName.toLowerCase() : null;
      }

      const prevRect = primarySource && primarySource.previousRect ? toBoundingBox(primarySource.previousRect) : null;
      const currRect = primarySource && primarySource.currentRect ? toBoundingBox(primarySource.currentRect) : null;

      let deltaX = 0;
      let deltaY = 0;
      let distancePx = 0;
      let direction: 'down' | 'up' | 'left' | 'right' | 'diagonal' | 'none' = 'none';
      let impactAreaPx = 0;

      if (prevRect && currRect) {
        deltaX = currRect.left - prevRect.left;
        deltaY = currRect.top - prevRect.top;
        distancePx = Math.round(Math.hypot(deltaX, deltaY));
        impactAreaPx = Math.max(prevRect.width * prevRect.height, currRect.width * currRect.height);

        if (Math.abs(deltaY) > Math.abs(deltaX) * 1.5) {
          direction = deltaY > 0 ? 'down' : 'up';
        } else if (Math.abs(deltaX) > Math.abs(deltaY) * 1.5) {
          direction = deltaX > 0 ? 'right' : 'left';
        } else if (distancePx > 0) {
          direction = 'diagonal';
        }
      }

      if (entry.value > largestShiftValue) {
        largestShiftValue = entry.value;
        if (nodeSelector) {
          largestShiftTarget = nodeSelector;
        }
        if (currRect) {
          largestShiftBoundingBox = currRect;
        }
      }

      shiftDetails.push({
        score: entry.value,
        startTimeMs: Math.round(entry.startTime),
        hadRecentInput: Boolean(entry.hadRecentInput),
        elementSelector: nodeSelector,
        elementTag: nodeTag,
        previousRect: prevRect,
        currentRect: currRect,
        deltaX,
        deltaY,
        distancePx,
        direction,
        impactAreaPx
      });

      if (currentSessionScore > 0 &&
          (entry.startTime - currentSessionLast >= 1000 ||
           entry.startTime - currentSessionStart >= 5000)) {
        if (currentSessionScore > maxSessionScore) {
          maxSessionScore = currentSessionScore;
        }
        currentSessionScore = entry.value;
        currentSessionStart = entry.startTime;
        currentSessionLast = entry.startTime;
      } else {
        if (currentSessionScore === 0) {
          currentSessionStart = entry.startTime;
        }
        currentSessionScore += entry.value;
        currentSessionLast = entry.startTime;
      }
    });

    if (currentSessionScore > maxSessionScore) {
      maxSessionScore = currentSessionScore;
    }
    cls = maxSessionScore;

    shiftDetails.sort((a, b) => b.score - a.score);
    if (!largestShiftBoundingBox && shiftDetails.length > 0 && shiftDetails[0].currentRect) {
      largestShiftBoundingBox = shiftDetails[0].currentRect;
    }
    try {
      (window as any).__vitalssniper_last_shifts = shiftDetails;
    } catch (err) { console.debug('Telemetry probe suppressed:', err); }
  }

  // --- LoAF (Long Animation Frames) Telemetry Processing ---
  let loafCount = 0;
  let longestLoafMs: number | null = null;
  let totalLoafBlockingMs = 0;
  let primaryLoafCulprit: any = null;
  const loafFrames: any[] = [];
  const longScripts: LoafScriptAttributionItem[] = [];

  if (rawLoafEntries.length > 0) {
    loafCount = rawLoafEntries.length;
    const scriptAggregates = new Map<string, {
      invoker: string | null;
      invokerType: string | null;
      sourceUrl: string | null;
      sourceFunctionName: string | null;
      sourceCharPosition: number | null;
      executionDurationMs: number;
      forcedStyleAndLayoutMs: number;
      pauseDurationMs: number;
      compileDurationMs: number;
      totalDurationMs: number;
    }>();

    rawLoafEntries.forEach((frame: any) => {
      const durationMs = Math.round(frame.duration);
      const blockingDurationMs = Math.round(frame.blockingDuration || Math.max(0, durationMs - 50));
      totalLoafBlockingMs += blockingDurationMs;
      if (longestLoafMs === null || durationMs > longestLoafMs) {
        longestLoafMs = durationMs;
      }

      const startTimeMs = Math.round(frame.startTime);
      const preRenderDurationMs = Math.max(0, Math.round((frame.renderStart || (frame.startTime + frame.duration)) - frame.startTime));
      const styleAndLayoutDurationMs = frame.styleAndLayoutStart ? Math.max(0, Math.round(frame.startTime + frame.duration - frame.styleAndLayoutStart)) : 0;
      const renderDelayMs = frame.renderStart ? Math.max(0, Math.round(frame.startTime + frame.duration - frame.renderStart)) : 0;

      const frameScripts: any[] = [];
      let frameWorstScript: any = null;

      if (Array.isArray(frame.scripts)) {
        frame.scripts.forEach((script: any) => {
          const sDuration = Math.round(script.duration || 0);
          const sExecutionStart = script.executionStart !== undefined ? script.executionStart : script.startTime;
          const sCompile = Math.max(0, Math.round((sExecutionStart || script.startTime) - script.startTime));
          const sForcedLayout = Math.round(script.forcedStyleAndLayoutDuration || 0);
          const sPause = Math.round(script.pauseDuration || 0);
          const sBlocking = Math.max(0, sDuration - 50);

          const culpritObj = {
            invoker: script.invoker || null,
            invokerType: script.invokerType || null,
            sourceUrl: script.sourceURL || null,
            sourceFunctionName: script.sourceFunctionName || null,
            sourceCharPosition: script.sourceCharPosition !== undefined ? script.sourceCharPosition : null,
            executionDurationMs: sDuration,
            forcedStyleAndLayoutMs: sForcedLayout,
            pauseDurationMs: sPause,
            compileDurationMs: sCompile,
            totalDurationMs: sDuration
          };

          frameScripts.push(culpritObj);

          longScripts.push({
            scriptUrl: script.sourceURL || null,
            functionName: script.sourceFunctionName || null,
            invoker: script.invoker || null,
            invokerType: script.invokerType || null,
            sourceCharPosition: script.sourceCharPosition !== undefined ? script.sourceCharPosition : null,
            blockingDurationMs: sBlocking,
            executionDurationMs: sDuration,
            forcedStyleAndLayoutMs: sForcedLayout,
            pauseDurationMs: sPause
          });

          if (!frameWorstScript || sDuration > frameWorstScript.totalDurationMs) {
            frameWorstScript = culpritObj;
          }

          const key = `${script.sourceURL || 'inline'}::${script.invoker || 'script'}::${script.sourceFunctionName || 'anonymous'}`;
          const existing = scriptAggregates.get(key);
          if (existing) {
            existing.executionDurationMs += sDuration;
            existing.forcedStyleAndLayoutMs += sForcedLayout;
            existing.pauseDurationMs += sPause;
            existing.compileDurationMs += sCompile;
            existing.totalDurationMs += sDuration;
          } else {
            scriptAggregates.set(key, { ...culpritObj });
          }
        });
      }

      loafFrames.push({
        startTimeMs,
        durationMs,
        blockingDurationMs,
        preRenderDurationMs,
        styleAndLayoutDurationMs,
        renderDelayMs,
        scripts: frameScripts,
        primaryCulprit: frameWorstScript
      });
    });

    longScripts.sort((a, b) => b.executionDurationMs - a.executionDurationMs);

    let maxAggDuration = 0;
    scriptAggregates.forEach(agg => {
      if (agg.totalDurationMs > maxAggDuration) {
        maxAggDuration = agg.totalDurationMs;
        primaryLoafCulprit = agg;
      }
    });
  }

  const violates8msBudget = rawLoafEntries.some((f: any) => (f.duration || 0) > 8.3) || longScripts.some(s => s.executionDurationMs > 8.3);

  const loafAttribution: LoafAttribution = {
    totalFrames: loafCount,
    longestFrameMs: longestLoafMs || 0,
    totalBlockingMs: totalLoafBlockingMs,
    longScripts,
    violates8msBudget
  };

  // Fallback: If no buffered LCP entry exists, locate the largest visual element in viewport
  if (lcpMs === null) {
    try {
      const candidates = querySelectorAllDeep(document, 'img, video, h1, h2, p, header, [role="banner"]');
      let maxArea = 0;
      let bestCandidate: Element | null = null;
      const vpW = window.innerWidth;
      const vpH = window.innerHeight;

      candidates.forEach(el => {
        const rect = el.getBoundingClientRect();
        if (rect.top < vpH && rect.bottom > 0 && rect.left < vpW && rect.right > 0) {
          const visibleW = Math.min(rect.right, vpW) - Math.max(rect.left, 0);
          const visibleH = Math.min(rect.bottom, vpH) - Math.max(rect.top, 0);
          const area = visibleW * visibleH;
          if (area > maxArea) {
            maxArea = area;
            bestCandidate = el;
          }
        }
      });

      if (bestCandidate) {
        const el: Element = bestCandidate;
        lcpElementType = el.tagName.toLowerCase();
        lcpElementSelector = getSelector(el);
        lcpSource = 'heuristic';

        if (lcpElementType === 'img') {
          const imgSrc = (el as HTMLImageElement).currentSrc || (el as HTMLImageElement).src;
          if (imgSrc) {
            try {
              const resEntries = performance.getEntriesByName(imgSrc) as PerformanceResourceTiming[];
              if (resEntries && resEntries.length > 0) {
                const rt = resEntries[resEntries.length - 1];
                lcpMs = Math.round(rt.responseEnd || rt.startTime);
              }
            } catch (err) { console.debug('Telemetry probe suppressed:', err); }
          }
        }
      }
    } catch (err) { console.debug('Telemetry probe suppressed:', err); }
  }

  // --- 2. NAVIGATION TIMING & BODY SIZES ---
  let canonicalTtfbMs: number | null = null;
  let serverProcessingMs: number | null = null;
  let domLoadMs: number | null = null;
  let encodedBodyKB: number | null = null;
  let decodedBodyKB: number | null = null;
  let transferKB: number | null = null;
  let cacheState: 'likely cached' | 'service-worker mediated' | 'network-delivered' | 'unavailable/uncertain' | 'redirect' = 'network-delivered';

  try {
    const [navEntry]: any = performance.getEntriesByType('navigation');
    if (navEntry) {
      if (navEntry.responseStart > 0) {
        canonicalTtfbMs = Math.max(0, Math.round(navEntry.responseStart));
      }
      if (navEntry.responseStart > 0 && navEntry.requestStart > 0) {
        serverProcessingMs = Math.max(0, Math.round(navEntry.responseStart - navEntry.requestStart));
      }
      if (navEntry.domContentLoadedEventEnd > 0) {
        domLoadMs = Math.max(0, Math.round(navEntry.domContentLoadedEventEnd - navEntry.startTime));
      }
      if (navEntry.encodedBodySize !== undefined) {
        encodedBodyKB = Math.round(navEntry.encodedBodySize / 1024);
      }
      if (navEntry.decodedBodySize !== undefined) {
        decodedBodyKB = Math.round(navEntry.decodedBodySize / 1024);
      }
      if (navEntry.transferSize !== undefined) {
        transferKB = Math.round(navEntry.transferSize / 1024);
      }

      // Check cache / service worker delivery states without absolute claims
      if (navEntry.redirectCount > 0) {
        cacheState = 'redirect';
      } else if (navEntry.workerStart && navEntry.workerStart > 0) {
        cacheState = 'service-worker mediated';
      } else if (navEntry.deliveryType === 'cache' || navEntry.deliveryType === 'navigational-prefetch') {
        cacheState = 'likely cached';
      } else if (navEntry.transferSize === 0 && (navEntry.encodedBodySize > 0 || navEntry.decodedBodySize > 0)) {
        cacheState = 'likely cached';
      } else if (navEntry.transferSize && navEntry.transferSize > 0) {
        cacheState = 'network-delivered';
      } else {
        cacheState = 'unavailable/uncertain';
      }
    }
  } catch (err) { console.debug('Telemetry probe suppressed:', err); }

  // Google Web Vitals LCP subpart attribution
  let lcpTtfbMs: number | null = canonicalTtfbMs;
  let lcpLoadDelayMs: number | null = null;
  let lcpLoadDurationMs: number | null = null;
  let lcpRenderDelayMs: number | null = null;

  if (lcpEntry && lcpMs !== null) {
    const lcpUrl = lcpEntry.url;
    const lcpStartTime = Math.round(lcpEntry.startTime || lcpMs);
    const ttfbVal = canonicalTtfbMs || 0;

    if (lcpUrl) {
      let resTiming: PerformanceResourceTiming | null = null;
      try {
        const resources = performance.getEntriesByType('resource') as PerformanceResourceTiming[];
        for (let i = resources.length - 1; i >= 0; i--) {
          if (resources[i].name === lcpUrl) {
            resTiming = resources[i];
            break;
          }
        }
      } catch (err) { console.debug('Telemetry probe suppressed:', err); }

      if (resTiming) {
        const reqStart = Math.round(resTiming.requestStart || resTiming.startTime);
        const resEnd = Math.round(resTiming.responseEnd || resTiming.startTime);
        lcpLoadDelayMs = Math.max(0, reqStart - ttfbVal);
        lcpLoadDurationMs = Math.max(0, resEnd - reqStart);
        lcpRenderDelayMs = Math.max(0, lcpStartTime - resEnd);
      } else {
        lcpLoadDelayMs = 0;
        lcpLoadDurationMs = Math.max(0, lcpStartTime - ttfbVal);
        lcpRenderDelayMs = 0;
      }
    } else {
      lcpLoadDelayMs = 0;
      lcpLoadDurationMs = 0;
      lcpRenderDelayMs = Math.max(0, lcpStartTime - ttfbVal);
    }
  }

  const lcpAttribution = lcpMs !== null ? {
    elementSelector: lcpElementSelector,
    timeToFirstByteMs: lcpTtfbMs,
    resourceLoadDelayMs: lcpLoadDelayMs,
    resourceLoadDurationMs: lcpLoadDurationMs,
    elementRenderDelayMs: lcpRenderDelayMs,
    url: lcpEntry?.url || null
  } : null;

  const clsAttribution: any = hasClsEntries ? {
    sessionWindowScore: parseFloat(cls.toFixed(3)),
    largestShiftTarget,
    largestShiftValue: parseFloat(largestShiftValue.toFixed(3)),
    shiftDetails,
    totalShiftsCount: shiftDetails.length,
    largestShiftBoundingBox
  } : null;

  // Google Web Vitals INP attribution from interaction entries
  try {
    const syncEventEntries = performance.getEntriesByType('event');
    if (syncEventEntries && syncEventEntries.length > 0) {
      syncEventEntries.forEach((ev: any) => interactionEntries.push(ev));
    }
    const firstInputs = performance.getEntriesByType('first-input');
    if (firstInputs && firstInputs.length > 0) {
      firstInputs.forEach((fi: any) => interactionEntries.push(fi));
    }
  } catch (err) { console.debug('Telemetry probe suppressed:', err); }

  // Group interaction events into presentation frame groups using an 8ms tolerance window
  interface InteractionGroup {
    interactionId?: number;
    renderTime: number;
    maxDuration: number;
    events: any[];
  }

  const interactionGroups: InteractionGroup[] = [];

  if (interactionEntries.length > 0) {
    interactionEntries.forEach((entry: any) => {
      const dur = entry.duration || 0;
      const renderTime = (entry.renderTime !== undefined && entry.renderTime > 0)
        ? entry.renderTime
        : (entry.startTime + dur);

      let matchedGroup = interactionGroups.find(g => {
        if (entry.interactionId && g.interactionId && entry.interactionId === g.interactionId) {
          return true;
        }
        return Math.abs(renderTime - g.renderTime) <= 8;
      });

      if (matchedGroup) {
        matchedGroup.events.push(entry);
        if (dur > matchedGroup.maxDuration) {
          matchedGroup.maxDuration = dur;
        }
        if (!matchedGroup.interactionId && entry.interactionId) {
          matchedGroup.interactionId = entry.interactionId;
        }
      } else {
        interactionGroups.push({
          interactionId: entry.interactionId,
          renderTime,
          maxDuration: dur,
          events: [entry]
        });
      }
    });
  }

  let worstGroup: any = null;
  let worstInteraction: any = null;
  let maxInteractionDuration = 0;

  for (const group of interactionGroups) {
    if (!worstGroup || group.maxDuration > worstGroup.maxDuration) {
      worstGroup = group;
    }
  }

  if (worstGroup) {
    for (const ev of worstGroup.events) {
      const d = ev.duration || 0;
      if (!worstInteraction || d > (worstInteraction.duration || 0)) {
        worstInteraction = ev;
      }
    }
    if (worstInteraction) {
      maxInteractionDuration = worstInteraction.duration || 0;
    }
  }

  let inpTarget: string | null = null;
  let inpProcessingDelayMs: number | null = null;
  let inpInputDelayMs: number | null = null;
  let inpPresentationDelayMs: number | null = null;
  let inpAttribution: any = null;
  let inpDisplay = 'INP not recorded (Requires user tap/click)';

  if (worstGroup && worstInteraction && maxInteractionDuration > 0) {
    inpMs = Math.round(maxInteractionDuration);
    inpObserved = true;
    if (worstInteraction.target) {
      inpTarget = getSelector(worstInteraction.target);
    }
    const procStart = worstInteraction.processingStart || worstInteraction.startTime;
    const procEnd = worstInteraction.processingEnd || worstInteraction.processingStart || worstInteraction.startTime;
    inpInputDelayMs = Math.max(0, Math.round(procStart - worstInteraction.startTime));
    inpProcessingDelayMs = Math.max(0, Math.round(procEnd - procStart));
    inpPresentationDelayMs = Math.max(0, Math.round(worstInteraction.startTime + worstInteraction.duration - procEnd));

    // 3-Phase temporal correlation against overlapping LoAF entries
    let overlappingLoafFrame: any = null;
    let maxLoafOverlap = 0;
    let overlappingLoafCount = 0;
    const presentationEnd = worstInteraction.startTime + worstInteraction.duration;

    rawLoafEntries.forEach((frame: any) => {
      const fStart = frame.startTime || 0;
      const fEnd = fStart + (frame.duration || 0);
      const overlap = Math.max(0, Math.min(fEnd, presentationEnd) - Math.max(fStart, worstInteraction.startTime));
      if (overlap > 0) {
        overlappingLoafCount++;
      }
      if (overlap > maxLoafOverlap) {
        maxLoafOverlap = overlap;
        overlappingLoafFrame = frame;
      }
    });

    let totalCandidateScripts = 0;
    for (let i = 0; i < rawLoafEntries.length; i++) {
      const frame = rawLoafEntries[i];
      if (Array.isArray(frame?.scripts)) {
        totalCandidateScripts += frame.scripts.length;
      } else if (frame && (frame.startTime !== undefined || frame.sourceURL || frame.sourceUrl)) {
        totalCandidateScripts += 1;
      }
    }

    let worstInputScript: any = null;
    let maxInputIntersectingDuration = 0;
    let worstScript: any = null;
    let maxIntersectingDuration = 0;
    let maxIntersectingForcedStyle = 0;

    // Use Linear ArrayPool for transient LoAF script parsing and interaction attribution
    // to eliminate telemetry-induced garbage collection overhead during 60 FPS LoAF interaction profiling
    withSharedArray(totalCandidateScripts, (candidateScripts) => {
      let scriptCount = 0;
      for (let i = 0; i < rawLoafEntries.length; i++) {
        const frame = rawLoafEntries[i];
        if (Array.isArray(frame?.scripts)) {
          for (let s = 0; s < frame.scripts.length; s++) {
            candidateScripts[scriptCount++] = frame.scripts[s];
          }
        } else if (frame && (frame.startTime !== undefined || frame.sourceURL || frame.sourceUrl)) {
          candidateScripts[scriptCount++] = frame;
        }
      }

      // Phase 1: Input Delay Blocker Script Attribution
      if (inpInputDelayMs !== null && inpInputDelayMs > 0) {
        for (let i = 0; i < scriptCount; i++) {
          const script = candidateScripts[i];
          const sStart = script.executionStart !== undefined ? script.executionStart : (script.startTime || 0);
          const sDuration = script.duration || 0;
          const scriptEnd = sStart + sDuration;
          const inputIntersecting = Math.max(0, Math.min(scriptEnd, procStart) - Math.max(sStart, worstInteraction.startTime));
          if (inputIntersecting > maxInputIntersectingDuration) {
            maxInputIntersectingDuration = inputIntersecting;
            worstInputScript = script;
          }
        }
      }

      // Phase 2: Processing Delay Handler Script Attribution
      for (let i = 0; i < scriptCount; i++) {
        const script = candidateScripts[i];
        const sStart = script.executionStart !== undefined ? script.executionStart : (script.startTime || 0);
        const sDuration = script.duration || 0;
        const scriptEnd = sStart + sDuration;
        const intersectingDuration = Math.max(0, Math.min(scriptEnd, procEnd) - Math.max(sStart, procStart));
        if (intersectingDuration > maxIntersectingDuration) {
          maxIntersectingDuration = intersectingDuration;
          const forcedStyle = (sDuration && script.forcedStyleAndLayoutDuration)
            ? Math.round((intersectingDuration / sDuration) * script.forcedStyleAndLayoutDuration)
            : 0;
          maxIntersectingForcedStyle = forcedStyle;
          worstScript = script;
        }
      }
    });

    // Phase 3: Presentation Delay Breakdown (Style & Layout vs Render)
    let presentationDelayStyleAndLayoutMs: number | null = null;
    let presentationDelayRenderMs: number | null = null;
    let loafFrameDurationMs: number | null = null;
    let loafBlockingDurationMs: number | null = null;

    // For presentation delay, find the LoAF frame specifically overlapping the presentation phase [procEnd, presentationEnd]
    let presentationLoafFrame: any = null;
    let maxPresentationOverlap = 0;
    rawLoafEntries.forEach((frame: any) => {
      const fStart = frame.startTime || 0;
      const fEnd = fStart + (frame.duration || 0);
      const presOverlap = Math.max(0, Math.min(fEnd, presentationEnd) - Math.max(fStart, procEnd));
      if (presOverlap > maxPresentationOverlap) {
        maxPresentationOverlap = presOverlap;
        presentationLoafFrame = frame;
      }
    });

    const targetPresentationFrame = presentationLoafFrame || (overlappingLoafFrame && ((overlappingLoafFrame.startTime || 0) + (overlappingLoafFrame.duration || 0) >= procEnd) ? overlappingLoafFrame : null);

    if (targetPresentationFrame) {
      loafFrameDurationMs = Math.round(targetPresentationFrame.duration || 0);
      loafBlockingDurationMs = Math.round(targetPresentationFrame.blockingDuration || Math.max(0, (targetPresentationFrame.duration || 0) - 50));
      const fEnd = (targetPresentationFrame.startTime || 0) + (targetPresentationFrame.duration || 0);
      if (targetPresentationFrame.styleAndLayoutStart) {
        presentationDelayStyleAndLayoutMs = Math.max(0, Math.round(fEnd - targetPresentationFrame.styleAndLayoutStart));
      }
      if (targetPresentationFrame.renderStart) {
        presentationDelayRenderMs = Math.max(0, Math.round(fEnd - targetPresentationFrame.renderStart));
      }
    }

    // Require minimum 16ms execution threshold and at least 15% processing phase proportion
    const hasSignificantCulprit = Boolean(
      worstScript &&
      maxIntersectingDuration >= 16 &&
      maxIntersectingDuration >= (inpProcessingDelayMs || 0) * 0.15
    );

    const targetLabel = inpTarget ? ` on ${inpTarget}` : '';
    inpDisplay = `${inpMs} ms (${worstInteraction.name || 'interaction'}${targetLabel})`;
    const interactionLoadState = getLoadState(worstInteraction.startTime);
    const interactionTime = Math.round(worstInteraction.startTime);
    const nextPaintTime = Math.round(presentationEnd);

    inpAttribution = {
      interactionTarget: inpTarget,
      interactionType: worstInteraction.name || 'interaction',
      processingDelayMs: inpProcessingDelayMs,
      inputDelayMs: inpInputDelayMs,
      presentationDelayMs: inpPresentationDelayMs,
      loadState: interactionLoadState,
      inputDelay: inpInputDelayMs,
      processingDuration: inpProcessingDelayMs,
      presentationDelay: inpPresentationDelayMs,
      interactionTargetElement: inpTarget,
      interactionTime,
      nextPaintTime,
      overlappingLoafCount,
      culpritScriptUrl: hasSignificantCulprit ? (worstScript.sourceURL || worstScript.sourceUrl || 'inline') : null,
      culpritFunctionName: hasSignificantCulprit ? (worstScript.sourceFunctionName || null) : null,
      culpritExecutionMs: hasSignificantCulprit ? Math.round(maxIntersectingDuration) : null,
      culpritForcedStyleMs: hasSignificantCulprit ? maxIntersectingForcedStyle : null,
      groupedEventCount: worstGroup.events.length,
      groupedEvents: Array.from(new Set(worstGroup.events.map((e: any) => e.name || 'interaction'))),
      inputDelayCulpritScriptUrl: (worstInputScript && maxInputIntersectingDuration > 0) ? (worstInputScript.sourceURL || worstInputScript.sourceUrl || 'inline') : null,
      inputDelayCulpritExecutionMs: (worstInputScript && maxInputIntersectingDuration > 0) ? Math.round(maxInputIntersectingDuration) : null,
      inputDelayInvoker: (worstInputScript && maxInputIntersectingDuration > 0) ? (worstInputScript.invoker || worstInputScript.invokerType || null) : null,
      presentationDelayStyleAndLayoutMs,
      presentationDelayRenderMs,
      loafFrameDurationMs,
      loafBlockingDurationMs,
      invoker: worstScript ? (worstScript.invoker || null) : null,
      invokerType: worstScript ? (worstScript.invokerType || null) : null,
      sourceCharPosition: (worstScript && worstScript.sourceCharPosition !== undefined) ? worstScript.sourceCharPosition : null
    };
  }

  // --- 3. DOM RECURSION & SERIALIZED SIZE ---
  let totalElements = 0;
  let maxDepth = 0;
  let depthSum = 0;
  let deepBranchCount = 0;

  function walkDom(node: Node, depth: number) {
    if (node.nodeType !== 1) return;
    totalElements++;
    depthSum += depth;
    if (depth > maxDepth) maxDepth = depth;
    if (depth > 15) deepBranchCount++;

    const element = node as Element;
    const tag = element.tagName ? element.tagName.toLowerCase() : '';
    if (tag === 'svg' || tag === 'math') {
      return;
    }

    const children = element.children;
    for (let i = 0; i < children.length; i++) {
      walkDom(children[i], depth + 1);
    }

    const shadowRoot = element.shadowRoot;
    if (shadowRoot) {
      const shadowChildren = shadowRoot.children;
      for (let j = 0; j < shadowChildren.length; j++) {
        walkDom(shadowChildren[j], depth + 1);
      }
    }
  }
  walkDom(document.documentElement, 1);

  const averageDepth = totalElements > 0 ? parseFloat((depthSum / totalElements).toFixed(1)) : 1;
  const rawHtml = document.documentElement.outerHTML;
  const documentSerializedKB = Math.round(new Blob([rawHtml]).size / 1024);

  // --- 4. IMAGE FORENSICS (HIGH-DPI AWARE & NON-SCARE) ---
  const imgElements = querySelectorAllDeep<HTMLImageElement>(document, 'img');
  const images: any[] = [];
  let oversizedImagesCount = 0;
  let missingDimensionImagesCount = 0;
  const dpr = window.devicePixelRatio || 1;

  // Build resource timing map for actual transferred bytes
  const resourceMap: Record<string, number> = {};
  try {
    performance.getEntriesByType('resource').forEach((r: any) => {
      if (r.initiatorType === 'img' || (r.name && /\.(webp|avif|png|jpg|jpeg|gif|svg)($|\?)/i.test(r.name))) {
        resourceMap[r.name] = Math.round((r.transferSize || r.encodedBodySize || 0) / 1024);
      }
    });
  } catch (err) { console.debug('Telemetry probe suppressed:', err); }

  imgElements.slice(0, 50).forEach(img => {
    const rawSrc = img.currentSrc || img.src || '';
    if (!rawSrc) return;

    let format = 'unknown';
    try {
      const urlObj = new URL(rawSrc, window.location.href);
      const pathname = urlObj.pathname.toLowerCase();
      const search = urlObj.search.toLowerCase();
      const hostname = urlObj.hostname.toLowerCase();

      if (pathname.endsWith('.webp') || search.includes('format=webp') || search.includes('fm=webp') || search.includes('output=webp')) format = 'webp';
      else if (pathname.endsWith('.avif') || search.includes('format=avif') || search.includes('fm=avif') || search.includes('output=avif')) format = 'avif';
      else if (pathname.endsWith('.svg') || search.includes('format=svg')) format = 'svg';
      else if (pathname.endsWith('.png') || search.includes('format=png')) format = 'png';
      else if (pathname.endsWith('.jpg') || pathname.endsWith('.jpeg') || search.includes('format=jpg') || search.includes('format=jpeg')) format = 'jpeg';
      else if (pathname.endsWith('.gif') || search.includes('format=gif')) format = 'gif';
      else if (hostname.includes('shopify.com') || hostname.includes('wixstatic.com') || hostname.includes('.wp.com')) {
        // Modern CDN dynamic format auto-negotiation
        format = 'webp';
      }
    } catch (e) {
      if (/\.webp($|\?)/i.test(rawSrc) || /(?:format|fm|output)=webp/i.test(rawSrc)) format = 'webp';
      else if (/\.avif($|\?)/i.test(rawSrc) || /(?:format|fm|output)=avif/i.test(rawSrc)) format = 'avif';
      else if (/\.svg($|\?)/i.test(rawSrc)) format = 'svg';
      else if (/\.png($|\?)/i.test(rawSrc)) format = 'png';
      else if (/\.(jpg|jpeg)($|\?)/i.test(rawSrc)) format = 'jpeg';
    }

    const naturalW = img.naturalWidth || 0;
    const naturalH = img.naturalHeight || 0;
    const rect = img.getBoundingClientRect();
    const renderedW = Math.round(rect.width);
    const renderedH = Math.round(rect.height);

    const hasExplicitDimensions = Boolean(img.getAttribute('width') && img.getAttribute('height'));
    if (!hasExplicitDimensions) missingDimensionImagesCount++;

    const hasPictureParent = Boolean(img.closest('picture'));
    const hasSrcset = Boolean(img.getAttribute('srcset'));

    // High-DPI aware oversized detection:
    // Only flag if natural resolution exceeds 2.5x the rendered display geometry AND delta > 400px
    const expectedDpiMultiplier = Math.max(2, dpr) * 1.25;
    const isOversized = (renderedW > 0 && naturalW > (renderedW * expectedDpiMultiplier) && (naturalW - renderedW * dpr) > 400);
    if (isOversized) oversizedImagesCount++;

    const loadingAttr = (img.getAttribute('loading') || 'auto').toLowerCase();
    const fetchPriorityAttr = (img.getAttribute('fetchpriority') || 'auto').toLowerCase();
    const decodingAttr = (img.getAttribute('decoding') || 'auto').toLowerCase();
    const resourceKB = resourceMap[rawSrc] || null;

    images.push({
      src: rawSrc,
      currentSrc: img.currentSrc || '',
      format,
      naturalWidth: naturalW,
      naturalHeight: naturalH,
      renderedWidth: renderedW,
      renderedHeight: renderedH,
      isOversized,
      missingDimensions: !hasExplicitDimensions,
      hasPictureParent,
      hasSrcset,
      resourceKB,
      loading: loadingAttr,
      fetchPriority: fetchPriorityAttr,
      decoding: decodingAttr
    });
  });

  // --- 5. STRUCTURED DATA & SEARCH DISCOVERABILITY ---
  const schemaScripts = Array.from(document.querySelectorAll('script[type="application/ld+json"]'));
  const jsonLdDetected = schemaScripts.length > 0;
  let jsonLdValid = true;
  const schemaTypes: string[] = [];
  const graphTypes: string[] = [];
  const parsingErrors: string[] = [];

  schemaScripts.forEach(s => {
    const text = s.textContent || '';
    if (!text.trim()) return;
    try {
      const cleanText = text
        .replace(/<!--[\s\S]*?-->/g, '')
        .replace(/\/\*\s*<!\[CDATA\[[\s\S]*?\*\//g, '')
        .replace(/\/\*\s*\]\]>[\s\S]*?\*\//g, '')
        .replace(/\/\/<!\[CDATA\[/g, '')
        .replace(/\/\/\]\]>/g, '')
        .replace(/<!\[CDATA\[/g, '')
        .replace(/\]\]>/g, '')
        .trim();
      const parsed = JSON.parse(cleanText);
      if (parsed['@type']) {
        if (Array.isArray(parsed['@type'])) schemaTypes.push(...parsed['@type']);
        else schemaTypes.push(String(parsed['@type']));
      }
      if (parsed['@graph'] && Array.isArray(parsed['@graph'])) {
        parsed['@graph'].forEach((g: any) => {
          if (g && g['@type']) {
            if (Array.isArray(g['@type'])) graphTypes.push(...g['@type']);
            else graphTypes.push(String(g['@type']));
          }
        });
      }
    } catch (err: any) {
      jsonLdValid = false;
      parsingErrors.push(err.message || 'JSON-LD syntax parse failure');
    }
  });

  const titleEl = document.querySelector('title');
  const metaDescEl = document.querySelector('meta[name="description" i]');
  const canonicalEl = document.querySelector('link[rel="canonical" i]');
  const robotsEl = document.querySelector('meta[name="robots" i]');
  const h1Elements = Array.from(document.querySelectorAll('h1'));

  // Word Count Engine: Clone body, strip non-content tags, extract token count
  let wordCount = 0;
  try {
    if (document.body) {
      const bodyClone = document.body.cloneNode(true) as HTMLElement;
      const removeElements = bodyClone.querySelectorAll('script, style, noscript, meta, link');
      removeElements.forEach(el => el.remove());
      const bodyText = (bodyClone.innerText || bodyClone.textContent || '').trim();
      const tokens = bodyText.match(/\S+/g);
      wordCount = tokens ? tokens.length : 0;
    }
  } catch (err) { console.debug('Telemetry probe suppressed:', err); }

  // Heading Hierarchy Engine: Parse DOM order, track counts, skipped levels, and duplicate/missing H1
  // False-positive guard: exclude hidden navigation drawers, aria-hidden modals, and display:none containers
  const isVisibleHeading = (el: HTMLElement) => {
    if (el.closest('[aria-hidden="true"], [hidden], [style*="display: none"], [style*="display:none"]')) return false;
    if (el.offsetParent === null && window.getComputedStyle(el).display === 'none') return false;
    return true;
  };

  const headingElements = Array.from(document.querySelectorAll<HTMLElement>('h1, h2, h3, h4, h5, h6')).filter(isVisibleHeading);
  const headingTree: Array<{ tag: 'h1' | 'h2' | 'h3' | 'h4' | 'h5' | 'h6'; level: number; text: string }> = [];
  const skippedLevels: Array<{ fromTag: string; toTag: string; headingText: string }> = [];
  let h1Count = 0;
  let h2Count = 0;
  let h3Count = 0;
  let h4Count = 0;
  let h5Count = 0;
  let h6Count = 0;
  let prevHeadingLevel = 0;
  let prevHeadingTag = '';

  headingElements.forEach(el => {
    const tag = el.tagName.toLowerCase() as 'h1' | 'h2' | 'h3' | 'h4' | 'h5' | 'h6';
    const level = parseInt(tag.replace('h', ''), 10);
    const text = (el.textContent || '').trim();

    if (tag === 'h1') h1Count++;
    else if (tag === 'h2') h2Count++;
    else if (tag === 'h3') h3Count++;
    else if (tag === 'h4') h4Count++;
    else if (tag === 'h5') h5Count++;
    else if (tag === 'h6') h6Count++;

    if (prevHeadingLevel > 0 && level > prevHeadingLevel + 1) {
      skippedLevels.push({
        fromTag: prevHeadingTag,
        toTag: tag,
        headingText: text
      });
    }

    prevHeadingLevel = level;
    prevHeadingTag = tag;

    headingTree.push({
      tag,
      level,
      text
    });
  });

  const headingHierarchy = {
    tree: headingTree,
    totalCount: headingElements.length,
    h1Count,
    h2Count,
    h3Count,
    h4Count,
    h5Count,
    h6Count,
    missingH1: h1Count === 0,
    duplicateH1: h1Count > 1,
    skippedLevels
  };

  // Link Graph Engine: Parse links, classify internal vs external, check rel tokens, empty anchors
  const linkElements = Array.from(document.querySelectorAll<HTMLAnchorElement>('a[href]'));
  let linkTotal = 0;
  let internalCount = 0;
  let externalCount = 0;
  let nofollowCount = 0;
  let sponsoredCount = 0;
  let ugcCount = 0;
  let emptyAnchorCount = 0;
  const loc = window.location;

  linkElements.forEach(a => {
    const rawHref = (a.getAttribute('href') || '').trim();
    if (!rawHref) return;
    if (rawHref.toLowerCase().startsWith('javascript:')) return;
    if (rawHref.startsWith('#')) return;

    linkTotal++;

    try {
      const parsedUrl = new URL(a.href, loc.href);
      if (parsedUrl.origin === loc.origin) {
        internalCount++;
      } else {
        externalCount++;
      }
    } catch (e) {
      if (rawHref.startsWith('/') || !rawHref.includes('://')) {
        internalCount++;
      } else {
        externalCount++;
      }
    }

    const relAttr = (a.getAttribute('rel') || '').toLowerCase();
    const relTokens = relAttr.split(/\s+/);
    if (relTokens.includes('nofollow')) nofollowCount++;
    if (relTokens.includes('sponsored')) sponsoredCount++;
    if (relTokens.includes('ugc')) ugcCount++;

    const anchorText = (a.textContent || '').trim();
    const hasImgWithAlt = Array.from(a.querySelectorAll('img')).some(img => Boolean((img.getAttribute('alt') || '').trim()));
    if (anchorText.length === 0 && !hasImgWithAlt) {
      emptyAnchorCount++;
    }
  });

  const linkGraphSummary = {
    total: linkTotal,
    internalCount,
    externalCount,
    nofollowCount,
    sponsoredCount,
    ugcCount,
    emptyAnchorCount
  };

  // Meta & Canonical Match Engine (Normalized tracking parameters)
  const stripTrackingParams = (rawUrl: string): string => {
    try {
      const u = new URL(rawUrl);
      const trackingKeys = ['ref', 'gclid', 'fbclid', 'mc_eid', 'aff', 'source'];
      Array.from(u.searchParams.keys()).forEach(key => {
        const lowerKey = key.toLowerCase();
        if (lowerKey.startsWith('utm_') || trackingKeys.includes(lowerKey)) {
          u.searchParams.delete(key);
        }
      });
      const pathname = u.pathname.length > 1 ? u.pathname.replace(/\/+$/, '') : u.pathname;
      const search = u.search ? u.search : '';
      return `${u.origin}${pathname}${search}`;
    } catch {
      return (rawUrl || '').replace(/\/+$/, '');
    }
  };

  const canonicalFullHref = canonicalEl ? ((canonicalEl as HTMLLinkElement).href || canonicalEl.getAttribute('href') || '') : null;
  const canonicalMatchesUrl = canonicalFullHref
    ? stripTrackingParams(canonicalFullHref) === stripTrackingParams(window.location.href)
    : null;
  const robotsMetaContent = (robotsEl?.getAttribute('content') || '').toLowerCase();
  const isNoindex = robotsMetaContent.includes('noindex');
  const isNofollow = robotsMetaContent.includes('nofollow');
  const hreflangs = Array.from(document.querySelectorAll<HTMLLinkElement>('link[rel="alternate"][hreflang]')).map(el => ({
    hreflang: el.getAttribute('hreflang') || '',
    href: el.getAttribute('href') || el.href || ''
  }));

  const openGraph: Record<string, string> = {};
  Array.from(document.querySelectorAll('meta[property^="og:" i]')).forEach(el => {
    const prop = el.getAttribute('property');
    const content = el.getAttribute('content');
    if (prop && content) openGraph[prop] = content;
  });

  const twitter: Record<string, string> = {};
  Array.from(document.querySelectorAll('meta[name^="twitter:" i]')).forEach(el => {
    const name = el.getAttribute('name');
    const content = el.getAttribute('content');
    if (name && content) twitter[name] = content;
  });

  // --- 6. ACCESSIBILITY & VIEWPORT ---
  const vpMeta = document.querySelector('meta[name="viewport" i]');
  const vpContent = vpMeta ? (vpMeta.getAttribute('content') || '') : '';
  const vpMissing = !vpMeta;
  const vpLocked = /user-scalable=(?:no|0)|maximum-scale=(?:1|1\.0)(?![0-9])/i.test(vpContent);

  // Horizontal layout overflow
  const horizontalOverflow = document.documentElement.scrollWidth > window.innerWidth;

  // Touch targets inspection (Distinguish < 24px WCAG 2.5.8 target size concern from < 44px mobile usability heuristic)
  const interactiveElements = querySelectorAllDeep(document, 'button, a, input, select, textarea, [role="button"]');
  let undersizedTargets24px = 0;
  let undersizedTargets44px = 0;
  let smallestW = 9999;
  let smallestH = 9999;

  interactiveElements.forEach(el => {
    const rect = el.getBoundingClientRect();
    if (rect.width > 0 && rect.height > 0) {
      if (rect.width < 24 || rect.height < 24) undersizedTargets24px++;
      if (rect.width < 44 || rect.height < 44) undersizedTargets44px++;
      if (rect.width < smallestW) smallestW = Math.round(rect.width);
      if (rect.height < smallestH) smallestH = Math.round(rect.height);
    }
  });

  const missingAltCount = querySelectorAllDeep(document, 'img:not([alt]):not([aria-label]):not([aria-labelledby])').length;
  let emptyInteractiveCount = 0;
  interactiveElements.forEach(el => {
    const text = (el.textContent || '').trim();
    const aria = el.getAttribute('aria-label') || el.getAttribute('aria-labelledby') || el.getAttribute('title');
    if (!text && !aria && !el.querySelector('img, svg')) {
      emptyInteractiveCount++;
    }
  });

  const unlabeledControlCount = Array.from(document.querySelectorAll('input:not([type="hidden"]), select, textarea')).filter(ctrl => {
    const id = ctrl.getAttribute('id');
    const hasLabel = id ? Boolean(document.querySelector(`label[for="${id}"]`)) : false;
    const hasAria = ctrl.getAttribute('aria-label') || ctrl.getAttribute('aria-labelledby');
    return !hasLabel && !hasAria;
  }).length;

  // --- 7. RESOURCES & SCRIPTS ---
  const allScripts = Array.from(document.querySelectorAll('script'));
  const totalScripts = allScripts.length;
  let externalScripts = 0;
  let inlineScripts = 0;
  let thirdPartyScripts = 0;
  const currentHost = window.location.hostname;

  allScripts.forEach(s => {
    if (s.src) {
      externalScripts++;
      try {
        const srcHost = new URL(s.src).hostname;
        if (srcHost !== currentHost && !srcHost.endsWith('.' + currentHost)) {
          thirdPartyScripts++;
        }
      } catch (err) { console.debug('Telemetry probe suppressed:', err); }
    } else {
      inlineScripts++;
    }
  });

  const stylesheets = document.querySelectorAll('link[rel="stylesheet"]').length;
  let totalTransferBytes = 0;
  const detectedTelemetry: string[] = [];

  try {
    const resources = performance.getEntriesByType('resource');
    resources.forEach((r: any) => {
      if (r.transferSize) totalTransferBytes += r.transferSize;
      const n = (r.name || '').toLowerCase();
      if (n.includes('googletagmanager.com/gtm.js') && !detectedTelemetry.includes('GTM')) detectedTelemetry.push('GTM');
      if ((n.includes('google-analytics.com') || n.includes('analytics.google.com') || n.includes('gtag/js')) && !detectedTelemetry.includes('GA4')) detectedTelemetry.push('GA4');
      if ((n.includes('connect.facebook.net') || n.includes('facebook.com/tr')) && !detectedTelemetry.includes('Meta Pixel')) detectedTelemetry.push('Meta Pixel');
      if (n.includes('static.hotjar.com') && !detectedTelemetry.includes('Hotjar')) detectedTelemetry.push('Hotjar');
      if (n.includes('clarity.ms') && !detectedTelemetry.includes('MS Clarity')) detectedTelemetry.push('MS Clarity');
      if (n.includes('static.klaviyo.com') && !detectedTelemetry.includes('Klaviyo')) detectedTelemetry.push('Klaviyo');
      if (n.includes('analytics.tiktok.com') && !detectedTelemetry.includes('TikTok Pixel')) detectedTelemetry.push('TikTok Pixel');
      if (n.includes('hs-scripts.com') && !detectedTelemetry.includes('HubSpot')) detectedTelemetry.push('HubSpot');
    });
  } catch (err) { console.debug('Telemetry probe suppressed:', err); }

  // --- 8. TECHNOLOGY & CMS MULTI-SIGNAL DETECTION ---
  let techDetections: TechnologyDetection[] = [];
  try {
    if (typeof (detectTechnologies as any) === 'function') {
      techDetections = detectTechnologies(document, window, rawHtml);
    }
  } catch (e) {
    techDetections = [];
  }
  // techDetections is strictly determined by hardened detectTechnologies engine


  const scanDurationMs = Math.round(performance.now() - scanStartTime);

  // Format canonical display strings
  const lcpDisplay = lcpMs !== null
    ? `${lcpMs} ms (${lcpSource === 'navigation-observed' ? 'Navigation-observed LCP' : 'Buffered Active-Tab LCP'})`
    : (lcpSource === 'heuristic' && lcpElementSelector ? `Likely LCP Candidate: ${lcpElementSelector}` : 'Not measured');

  const fcpDisplay = fcpMs !== null ? `${fcpMs} ms (Measured FCP)` : 'Not measured';
  const clsDisplay = hasClsEntries ? cls.toFixed(3) : 'Not measured';
  const ttfbDisplay = canonicalTtfbMs !== null
    ? `${canonicalTtfbMs} ms (Browser-observed TTFB: ${cacheState})`
    : 'Not measured';

  // Return full observations and telemetry
  return {
    metadata: {
      url: window.location.href,
      domain: window.location.hostname.replace(/^www\./, ''),
      tabId: null,
      protocol: window.location.protocol,
      auditedAt: new Date().toISOString(),
      viewportWidth: window.innerWidth,
      viewportHeight: window.innerHeight,
      scanDurationMs,
      cacheState,
      measurementSource: 'In-Browser PerformanceObserver & Navigation Timing'
    },
    performance: {
      lcpMs,
      lcpSource: (lcpSource as any),
      lcpDisplay: lcpMs !== null ? `${lcpMs} ms` : 'Not observed',
      lcpElementSelector,
      lcpElementType,
      lcpTtfbMs,
      lcpLoadDelayMs,
      lcpLoadDurationMs,
      lcpRenderDelayMs,
      lcpAttribution,
      fcpMs,
      fcpDisplay: fcpMs !== null ? `${fcpMs} ms` : 'Not observed',
      inpMs,
      inpObserved,
      inpDisplay,
      inpTarget,
      inpProcessingDelayMs,
      inpInputDelayMs,
      inpPresentationDelayMs,
      inpAttribution,
      cls: hasClsEntries ? parseFloat(cls.toFixed(3)) : null,
      clsDisplay: hasClsEntries ? cls.toFixed(3) : '0.000',
      clsSessionScore: hasClsEntries ? parseFloat(cls.toFixed(3)) : null,
      clsAttribution,
      ttfbMs: canonicalTtfbMs,
      ttfbDisplay: canonicalTtfbMs !== null ? `${canonicalTtfbMs} ms` : 'Not observed',
      domLoadMs,
      loafAttribution
    },
    mainThread: {
      longTaskCount,
      longestTaskMs,
      totalBlockingTimeMs,
      loafCount,
      longestLoafMs,
      totalLoafBlockingMs,
      primaryLoafCulprit,
      loafFrames
    },
    dom: {
      totalElements,
      maxDepth,
      averageDepth,
      deepBranchCount
    },
    htmlSize: {
      documentSerializedKB,
      encodedBodyKB,
      decodedBodyKB,
      transferKB
    },
    images,
    seo: {
      jsonLdDetected,
      jsonLdValid,
      schemaTypes: Array.from(new Set(schemaTypes)),
      graphTypes: Array.from(new Set(graphTypes)),
      duplicateSchemas: schemaScripts.length > 3,
      parsingErrors,
      title: titleEl ? titleEl.innerText : null,
      metaDescription: metaDescEl ? metaDescEl.getAttribute('content') : null,
      canonical: canonicalEl ? canonicalEl.getAttribute('href') : null,
      robots: robotsEl ? robotsEl.getAttribute('content') : null,
      h1Count,
      h1Text: headingElements.length > 0 ? (headingElements.find(h => h.tagName.toLowerCase() === 'h1')?.textContent || '').trim() : null,
      openGraph,
      twitter,
      lang: document.documentElement.getAttribute('lang') || null,
      hreflangCount: hreflangs.length,
      headings: headingHierarchy,
      links: linkGraphSummary,
      wordCount,
      hreflangs,
      canonicalMatchesUrl,
      isNoindex,
      isNofollow
    },
    accessibility: {
      viewportPresent: !vpMissing,
      zoomRestricted: vpLocked,
      viewportContent: vpContent,
      horizontalOverflow,
      missingAltCount,
      emptyInteractiveCount,
      unlabeledControlCount,
      undersizedTargets24px,
      undersizedTargets44px,
      smallestTargetDimensions: undersizedTargets24px > 0 || undersizedTargets44px > 0 ? `${smallestW}x${smallestH}px` : null
    },
    resources: {
      totalScripts,
      inlineScripts,
      externalScripts,
      thirdPartyScripts,
      stylesheets,
      fonts: document.querySelectorAll('link[rel="preload"][as="font"]').length,
      imagesCount: imgElements.length,
      totalTransferKB: Math.round(totalTransferBytes / 1024),
      detectedTelemetry
    },
    technologies: techDetections,
    // Flat convenience bindings for legacy and UI consumption
    domStats: { totalElements, maxDepth },
    serializedSizeKB: documentSerializedKB,
    navTransferKB: transferKB || 0,
    vpMissing,
    vpLocked,
    hasSchema: jsonLdDetected,
    headings: headingHierarchy,
    links: linkGraphSummary,
    wordCount,
    cms: techDetections.map(t => t.name),
    imagesCount: imgElements.length,
    oversizedImagesCount,
    missingDimensionImages: missingDimensionImagesCount,
    interactiveCount: interactiveElements.length,
    undersizedTargets: undersizedTargets44px,
    undersizedTargets24px,
    smallestTarget: (undersizedTargets24px > 0 || undersizedTargets44px > 0) ? `${smallestW}x${smallestH}px` : null,
    ttfbMs: canonicalTtfbMs || 0,
    serverProcessingMs: serverProcessingMs || 0,
    domLoadMs: domLoadMs || 0,
    totalScripts,
    externalScripts,
    inlineScripts,
    stylesCount: stylesheets,
    totalResourceTransferKB: Math.round(totalTransferBytes / 1024),
    detectedTelemetry,
    cacheState,
    loafCount,
    longestLoafMs,
    totalLoafBlockingMs,
    primaryLoafCulprit,
    loafFrames,
    loafAttribution,
    shiftDetails
  };
}

/**
 * Removes any active layout shift canvas overlay or telemetry banner from the page.
 */
export function removeLayoutShiftOverlay(): void {
  try {
    if (typeof (window as any).__vitalssniper_cleanup_overlay === 'function') {
      (window as any).__vitalssniper_cleanup_overlay();
    }
    const existingCanvas = document.getElementById('vitalssniper-shift-canvas');
    if (existingCanvas) existingCanvas.remove();
    const existingBanner = document.getElementById('vitalssniper-shift-banner');
    if (existingBanner) existingBanner.remove();
  } catch (err) { console.debug('Telemetry probe suppressed:', err); }
}

/**
 * Renders a high-contrast, non-intrusive canvas overlay illustrating layout shift bounding boxes,
 * displacement vectors, and telemetry badges.
 */
export function renderLayoutShiftOverlay(shifts?: any[]): boolean {
  try {
    // 1. Clean up any previously injected overlay elements or event listeners
    if (typeof (window as any).__vitalssniper_cleanup_overlay === 'function') {
      (window as any).__vitalssniper_cleanup_overlay();
    }
    const prevCanvas = document.getElementById('vitalssniper-shift-canvas');
    if (prevCanvas) prevCanvas.remove();
    const prevBanner = document.getElementById('vitalssniper-shift-banner');
    if (prevBanner) prevBanner.remove();

    const targetShifts = (shifts && shifts.length > 0)
      ? shifts
      : ((window as any).__vitalssniper_last_shifts || []);

    const actionableShifts = targetShifts.filter((s: any) =>
      s && (s.currentRect || s.previousRect) && (s.score > 0 || s.distancePx > 0)
    );

    if (actionableShifts.length === 0) {
      return false;
    }

    const topShifts = actionableShifts.slice(0, 6);

    // 2. Smoothly bring primary shifting element into view if available
    const primaryShift = topShifts[0];
    if (primaryShift && primaryShift.elementSelector) {
      try {
        const primaryEl = document.querySelector(primaryShift.elementSelector);
        if (primaryEl && typeof primaryEl.scrollIntoView === 'function') {
          primaryEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
      } catch (err) { console.debug('Telemetry probe suppressed:', err); }
    }

    // 3. Create fixed canvas overlay
    const canvas = document.createElement('canvas');
    canvas.id = 'vitalssniper-shift-canvas';
    canvas.style.position = 'fixed';
    canvas.style.top = '0';
    canvas.style.left = '0';
    canvas.style.width = '100vw';
    canvas.style.height = '100vh';
    canvas.style.pointerEvents = 'none';
    canvas.style.zIndex = '2147483646';

    const ctx = canvas.getContext('2d');
    if (!ctx) return false;

    function resizeCanvas() {
      if (!ctx) return;
      const dpr = window.devicePixelRatio || 1;
      canvas.width = Math.round(window.innerWidth * dpr);
      canvas.height = Math.round(window.innerHeight * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }

    resizeCanvas();

    function draw() {
      if (!ctx) return;
      ctx.clearRect(0, 0, window.innerWidth, window.innerHeight);

      topShifts.forEach((shift: any, index: number) => {
        let prev = shift.previousRect;
        let curr = shift.currentRect;

        // If live DOM node exists, recalculate live coordinates relative to current viewport
        if (shift.elementSelector) {
          try {
            const liveNode = document.querySelector(shift.elementSelector);
            if (liveNode) {
              const liveRect = liveNode.getBoundingClientRect();
              if (liveRect.width > 0 && liveRect.height > 0) {
                const liveBox = {
                  left: Math.round(liveRect.left),
                  top: Math.round(liveRect.top),
                  width: Math.round(liveRect.width),
                  height: Math.round(liveRect.height),
                  right: Math.round(liveRect.right),
                  bottom: Math.round(liveRect.bottom),
                  x: Math.round(liveRect.left),
                  y: Math.round(liveRect.top)
                };
                curr = liveBox;
                prev = {
                  left: Math.round(liveBox.left - (shift.deltaX || 0)),
                  top: Math.round(liveBox.top - (shift.deltaY || 0)),
                  width: liveBox.width,
                  height: liveBox.height,
                  right: Math.round(liveBox.right - (shift.deltaX || 0)),
                  bottom: Math.round(liveBox.bottom - (shift.deltaY || 0)),
                  x: Math.round(liveBox.left - (shift.deltaX || 0)),
                  y: Math.round(liveBox.top - (shift.deltaY || 0))
                };
              }
            }
          } catch (err) { console.debug('Telemetry probe suppressed:', err); }
        }

        // 1. Draw previous rectangle (blue dashed outline with soft translucent tint)
        if (prev && prev.width > 0 && prev.height > 0) {
          ctx.save();
          ctx.fillStyle = 'rgba(59, 130, 246, 0.12)';
          ctx.fillRect(prev.left, prev.top, prev.width, prev.height);
          ctx.strokeStyle = '#2563eb';
          ctx.lineWidth = 2;
          ctx.setLineDash([5, 4]);
          ctx.strokeRect(prev.left, prev.top, prev.width, prev.height);
          ctx.restore();
        }

        // 2. Draw current rectangle (red solid outline with prominent alert tint)
        if (curr && curr.width > 0 && curr.height > 0) {
          ctx.save();
          ctx.fillStyle = 'rgba(239, 68, 68, 0.22)';
          ctx.fillRect(curr.left, curr.top, curr.width, curr.height);
          ctx.strokeStyle = '#dc2626';
          ctx.lineWidth = 2;
          ctx.setLineDash([]);
          ctx.strokeRect(curr.left, curr.top, curr.width, curr.height);
          ctx.restore();
        }

        // 3. Draw displacement vector arrow
        if (prev && curr) {
          const startX = prev.left + prev.width / 2;
          const startY = prev.top + prev.height / 2;
          const endX = curr.left + curr.width / 2;
          const endY = curr.top + curr.height / 2;
          const dist = Math.hypot(endX - startX, endY - startY);

          if (dist > 4) {
            ctx.save();
            ctx.beginPath();
            ctx.moveTo(startX, startY);
            ctx.lineTo(endX, endY);
            ctx.strokeStyle = '#dc2626';
            ctx.lineWidth = 2.5;
            ctx.stroke();

            const angle = Math.atan2(endY - startY, endX - startX);
            const headLen = 9;
            ctx.beginPath();
            ctx.moveTo(endX, endY);
            ctx.lineTo(
              endX - headLen * Math.cos(angle - Math.PI / 6),
              endY - headLen * Math.sin(angle - Math.PI / 6)
            );
            ctx.lineTo(
              endX - headLen * Math.cos(angle + Math.PI / 6),
              endY - headLen * Math.sin(angle + Math.PI / 6)
            );
            ctx.closePath();
            ctx.fillStyle = '#dc2626';
            ctx.fill();
            ctx.restore();
          }
        }

        // 4. Telemetry pill badge
        const anchorRect = curr || prev;
        if (anchorRect) {
          const shiftScore = typeof shift.score === 'number' ? shift.score.toFixed(3) : '0.000';
          const distText = shift.distancePx ? `${shift.direction} ${shift.distancePx}px` : 'shifted';
          const selectorText = shift.elementSelector ? shift.elementSelector.substring(0, 32) : 'element';
          const label = `#${index + 1} Shift: ${shiftScore} | ${distText} | ${selectorText}`;

          ctx.save();
          ctx.font = '600 11px ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace';
          const textMetrics = ctx.measureText(label);
          const padX = 8;
          const padY = 4;
          const badgeW = textMetrics.width + padX * 2;
          const badgeH = 20;

          let badgeX = anchorRect.left;
          let badgeY = anchorRect.top - badgeH - 4;

          if (badgeY < 10) badgeY = anchorRect.bottom + 4;
          if (badgeX + badgeW > window.innerWidth - 10) badgeX = window.innerWidth - badgeW - 10;
          if (badgeX < 10) badgeX = 10;

          ctx.fillStyle = 'rgba(15, 23, 42, 0.94)';
          ctx.beginPath();
          if (typeof ctx.roundRect === 'function') {
            ctx.roundRect(badgeX, badgeY, badgeW, badgeH, 4);
          } else {
            ctx.rect(badgeX, badgeY, badgeW, badgeH);
          }
          ctx.fill();
          ctx.strokeStyle = '#dc2626';
          ctx.lineWidth = 1;
          ctx.stroke();

          ctx.fillStyle = '#f8fafc';
          ctx.textBaseline = 'middle';
          ctx.fillText(label, badgeX + padX, badgeY + badgeH / 2);
          ctx.restore();
        }
      });
    }

    draw();

    // Event listeners to keep highlights aligned on scroll and resize
    const handleScroll = () => { draw(); };
    const handleResize = () => { resizeCanvas(); draw(); };
    window.addEventListener('scroll', handleScroll, { passive: true });
    window.addEventListener('resize', handleResize, { passive: true });

    document.documentElement.appendChild(canvas);

    // Floating UI chip with dismiss button
    const banner = document.createElement('div');
    banner.id = 'vitalssniper-shift-banner';
    banner.style.position = 'fixed';
    banner.style.top = '14px';
    banner.style.right = '14px';
    banner.style.zIndex = '2147483647';
    banner.style.background = '#0f172a';
    banner.style.color = '#f8fafc';
    banner.style.padding = '8px 12px';
    banner.style.borderRadius = '8px';
    banner.style.fontFamily = 'system-ui, -apple-system, sans-serif';
    banner.style.fontSize = '12px';
    banner.style.fontWeight = '500';
    banner.style.display = 'flex';
    banner.style.alignItems = 'center';
    banner.style.gap = '10px';
    banner.style.boxShadow = '0 10px 25px -5px rgba(0, 0, 0, 0.5), 0 0 0 1px rgba(220, 38, 38, 0.5)';
    banner.style.pointerEvents = 'auto';

    banner.innerHTML =
      '<span style="display:flex;align-items:center;gap:6px;">' +
      '<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#dc2626;"></span>' +
      '<span>Layout Shifts: ' + topShifts.length + ' observed</span>' +
      '</span>' +
      '<button id="vitalssniper-shift-close-btn" style="background:#dc2626;color:#ffffff;border:none;border-radius:4px;padding:3px 7px;font-size:11px;font-weight:600;cursor:pointer;">Dismiss</button>';

    document.documentElement.appendChild(banner);

    function cleanup() {
      window.removeEventListener('scroll', handleScroll);
      window.removeEventListener('resize', handleResize);
      const c = document.getElementById('vitalssniper-shift-canvas');
      if (c) c.remove();
      const b = document.getElementById('vitalssniper-shift-banner');
      if (b) b.remove();
      (window as any).__vitalssniper_cleanup_overlay = null;
    }

    (window as any).__vitalssniper_cleanup_overlay = cleanup;

    const closeBtn = document.getElementById('vitalssniper-shift-close-btn');
    if (closeBtn) {
      closeBtn.onclick = () => {
        cleanup();
      };
    }

    // Auto-remove overlay after 20 seconds
    setTimeout(() => {
      cleanup();
    }, 20000);

    return true;
  } catch (e) {
    return false;
  }
}
