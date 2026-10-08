// In-Page Forensic Browser Auditor
// Injected into the active prospect tab via chrome.scripting.executeScript()
// Zero em-dash compliance: strictly hyphens or colons

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
    } catch (e) {}
    return sel || (node.tagName ? node.tagName.toLowerCase() : '');
  }

  function querySelectorAllDeep<T extends Element = Element>(root: ParentNode, selector: string): T[] {
    const results: T[] = [];
    try {
      const direct = Array.from(root.querySelectorAll(selector)) as T[];
      results.push(...direct);
      const allElements = Array.from(root.querySelectorAll('*'));
      for (const el of allElements) {
        if (el.shadowRoot) {
          results.push(...querySelectorAllDeep<T>(el.shadowRoot, selector));
        }
      }
    } catch {}
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
  } catch (e) {}

  // B, C, D. Asynchronous PerformanceObservers with buffered entry window
  let poLcp: PerformanceObserver | null = null;
  let poCls: PerformanceObserver | null = null;
  let poLt: PerformanceObserver | null = null;
  let poInp: PerformanceObserver | null = null;

  let lcpEntry: any = null;
  const rawClsEntries: Array<{ value: number; startTime: number; hadRecentInput: boolean; targetNode: any }> = [];
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
    } catch (e) {}

    // 2. Google Web Vitals Layout Shift observer (collect raw entries for canonical session window)
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
            targetNode
          });
        });
      });
      poCls.observe({ type: 'layout-shift', buffered: true });
    } catch (e) {}

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
    } catch (e) {}

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
    } catch (e) {}

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
  } catch (e) {}

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
          targetNode
        });
      });
      (poCls as PerformanceObserver).disconnect();
    }
  } catch (e) {}

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
  } catch (e) {}

  try {
    if (poInp) {
      const records = (poInp as PerformanceObserver).takeRecords();
      records.forEach((entry: any) => {
        interactionEntries.push(entry);
      });
      (poInp as PerformanceObserver).disconnect();
    }
  } catch (e) {}

  // Calculate canonical CLS session windows reproducing Google Web Vitals logic:
  // 1s gap between shifts, 5s maximum session window length, hadRecentInput filtering, reporting maximum window.
  let largestShiftValue = 0;
  let largestShiftTarget: string | null = null;
  if (rawClsEntries.length > 0) {
    let maxSessionScore = 0;
    let currentSessionScore = 0;
    let currentSessionStart = 0;
    let currentSessionLast = 0;

    rawClsEntries.forEach(entry => {
      if (entry.hadRecentInput) return;
      hasClsEntries = true;

      if (entry.value > largestShiftValue) {
        largestShiftValue = entry.value;
        if (entry.targetNode) {
          largestShiftTarget = getSelector(entry.targetNode);
        }
      }

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
  }

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
            } catch (e) {}
          }
        }
      }
    } catch (e) {}
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
  } catch (e) {}

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
      } catch (e) {}

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

  const clsAttribution = hasClsEntries ? {
    sessionWindowScore: parseFloat(cls.toFixed(3)),
    largestShiftTarget,
    largestShiftValue: parseFloat(largestShiftValue.toFixed(3))
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
  } catch (e) {}

  let worstInteraction: any = null;
  let maxInteractionDuration = 0;
  if (interactionEntries.length > 0) {
    interactionEntries.forEach((entry: any) => {
      const dur = entry.duration || 0;
      if (dur > maxInteractionDuration) {
        maxInteractionDuration = dur;
        worstInteraction = entry;
      }
    });
  }

  let inpTarget: string | null = null;
  let inpProcessingDelayMs: number | null = null;
  let inpInputDelayMs: number | null = null;
  let inpPresentationDelayMs: number | null = null;
  let inpAttribution: any = null;
  let inpDisplay = 'INP not recorded (Requires user tap/click)';

  if (worstInteraction && maxInteractionDuration > 0) {
    inpMs = Math.round(maxInteractionDuration);
    inpObserved = true;
    if (worstInteraction.target) {
      inpTarget = getSelector(worstInteraction.target);
    }
    const procStart = worstInteraction.processingStart || worstInteraction.startTime;
    const procEnd = worstInteraction.processingEnd || worstInteraction.startTime;
    inpInputDelayMs = Math.max(0, Math.round(procStart - worstInteraction.startTime));
    inpProcessingDelayMs = Math.max(0, Math.round(procEnd - procStart));
    inpPresentationDelayMs = Math.max(0, Math.round(worstInteraction.startTime + worstInteraction.duration - procEnd));

    const targetLabel = inpTarget ? ` on ${inpTarget}` : '';
    inpDisplay = `${inpMs} ms (${worstInteraction.name || 'interaction'}${targetLabel})`;
    inpAttribution = {
      interactionTarget: inpTarget,
      interactionType: worstInteraction.name || 'interaction',
      processingDelayMs: inpProcessingDelayMs,
      inputDelayMs: inpInputDelayMs,
      presentationDelayMs: inpPresentationDelayMs
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
  } catch (e) {}

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
      } catch (e) {}
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
  } catch (e) {}

  // --- 8. TECHNOLOGY & CMS MULTI-SIGNAL DETECTION ---
  const techDetections: any[] = [];
  const hLower = rawHtml.toLowerCase();

  // WordPress
  const wpEvidence: string[] = [];
  if (hLower.includes('/wp-content/')) wpEvidence.push('Path: /wp-content/');
  if (hLower.includes('/wp-includes/')) wpEvidence.push('Path: /wp-includes/');
  if (document.querySelector('meta[name="generator"][content*="WordPress"]')) wpEvidence.push('Meta generator: WordPress');
  if (wpEvidence.length > 0) {
    techDetections.push({ name: 'WordPress', category: 'CMS', confidence: wpEvidence.length > 1 ? 'high' : 'medium', evidence: wpEvidence });
  }

  // Page Builders
  if (hLower.includes('elementor') || (window as any).elementorFrontend) {
    techDetections.push({ name: 'Elementor', category: 'Page Builder', confidence: 'high', evidence: ['Elementor DOM classes / frontend object'] });
  }
  if (hLower.includes('et_pb_') || hLower.includes('/themes/divi/')) {
    techDetections.push({ name: 'Divi', category: 'Page Builder', confidence: 'high', evidence: ['Divi et_pb class signatures'] });
  }
  if (hLower.includes('wpbakery') || hLower.includes('js_composer')) {
    techDetections.push({ name: 'WPBakery', category: 'Page Builder', confidence: 'high', evidence: ['WPBakery js_composer signatures'] });
  }
  if (hLower.includes('generatepress') || hLower.includes('generateblocks')) {
    techDetections.push({ name: 'GeneratePress', category: 'Page Builder', confidence: 'high', evidence: ['GeneratePress / GenerateBlocks tokens'] });
  }

  // SaaS Platforms
  if (hLower.includes('sqs-block') || (window as any).Static?.SQUARESPACE_CONTEXT) {
    techDetections.push({ name: 'Squarespace', category: 'CMS', confidence: 'high', evidence: ['Squarespace context / layout tokens'] });
  }
  if (document.documentElement.classList.contains('w-mod-js') || hLower.includes('data-wf-page')) {
    techDetections.push({ name: 'Webflow', category: 'CMS', confidence: 'high', evidence: ['Webflow data-wf attributes'] });
  }
  if (document.getElementById('__next') !== null || (window as any).__NEXT_DATA__ !== undefined) {
    techDetections.push({ name: 'Next.js', category: 'Framework', confidence: 'high', evidence: ['Next.js __NEXT_DATA__ hydration node'] });
  }
  if ((window as any).Shopify !== undefined || hLower.includes('cdn.shopify.com')) {
    techDetections.push({ name: 'Shopify', category: 'CMS', confidence: 'high', evidence: ['Shopify global object / CDN resources'] });
  }
  if ((window as any).wixBiSession !== undefined || hLower.includes('static.parastorage.com')) {
    techDetections.push({ name: 'Wix', category: 'CMS', confidence: 'high', evidence: ['Wix runtime session / Parastorage CDN'] });
  }

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
      domLoadMs
    },
    mainThread: {
      longTaskCount,
      longestTaskMs,
      totalBlockingTimeMs
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
      h1Count: h1Elements.length,
      h1Text: h1Elements.length > 0 ? (h1Elements[0].textContent || '').trim() : null,
      openGraph,
      twitter,
      lang: document.documentElement.getAttribute('lang') || null,
      hreflangCount: document.querySelectorAll('link[rel="alternate"][hreflang]').length
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
    cacheState
  };
}
