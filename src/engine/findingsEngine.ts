// Findings Engine: Evidence-Based Triage, Scoring, and Finding Generation
// Zero em-dash compliance: strictly hyphens or colons

import { Finding, AuditScorecard, SeverityLevel } from '../types/findings';

export class FindingsEngine {
  /**
   * Evaluates measured observations against evidence thresholds.
   * Produces grounded findings without fabricating unsupported claims or forcing flaws.
   */
  public static evaluateFindings(data: any, domain: string): AuditScorecard {
    const findings: Finding[] = [];

    const domStats = data.domStats || { totalElements: 0, maxDepth: 0 };
    const totalElements = domStats.totalElements;
    const maxDepth = domStats.maxDepth;
    const ttfbMs = data.ttfbMs || 0;
    const vpMissing = Boolean(data.vpMissing);
    const vpLocked = Boolean(data.vpLocked);
    const hasSchema = Boolean(data.hasSchema);
    const seoData = data.seo || {};
    const headingsData = seoData.headings || data.headings || null;
    const jsonLdValid = data.seo ? data.seo.jsonLdValid : true;
    const oversizedCount = (data.images || []).filter((i: any) => i.isOversized).length;
    const missingDimsCount = data.missingDimensionImages || 0;
    const longTaskCount = data.mainThread ? data.mainThread.longTaskCount : 0;
    const longestTaskMs = data.mainThread ? data.mainThread.longestTaskMs : null;
    const totalBlockingTimeMs = data.mainThread ? data.mainThread.totalBlockingTimeMs : 0;
    const horizontalOverflow = data.accessibility ? data.accessibility.horizontalOverflow : false;
    const undersizedCount24px = data.accessibility ? (data.accessibility.undersizedTargets24px || 0) : 0;
    const undersizedCount44px = data.accessibility ? (data.accessibility.undersizedTargets44px || 0) : (data.undersizedTargets || 0);
    const lcpMs = data.performance ? data.performance.lcpMs : null;
    const lcpSource = data.performance ? data.performance.lcpSource : 'Not measured';
    const lcpSelector = data.performance ? (data.performance.lcpElementSelector || data.performance.lcpAttribution?.elementSelector) : null;
    const lcpTtfb = data.performance ? (data.performance.lcpTtfbMs !== undefined && data.performance.lcpTtfbMs !== null ? data.performance.lcpTtfbMs : ttfbMs) : 0;
    const lcpLoadDelay = data.performance?.lcpLoadDelayMs || 0;
    const lcpLoadDuration = data.performance?.lcpLoadDurationMs || 0;
    const lcpRenderDelay = data.performance?.lcpRenderDelayMs || 0;

    const inpMs = data.performance ? data.performance.inpMs : null;
    const inpObserved = data.performance ? Boolean(data.performance.inpObserved) : false;
    const inpTarget = data.performance ? (data.performance.inpTarget || data.performance.inpAttribution?.interactionTarget) : null;
    const inpProcessingDelay = data.performance?.inpProcessingDelayMs || 0;
    const inpInputDelay = data.performance?.inpInputDelayMs || 0;
    const inpAttribution = data.performance?.inpAttribution || null;

    const cls = data.performance ? data.performance.cls : null;
    const clsTarget = data.performance?.clsAttribution?.largestShiftTarget || null;

    // --- 1. CORE WEB VITALS: MEASURED LCP WITH SUBPART ATTRIBUTION ---
    if (lcpMs !== null && lcpSource !== 'unavailable') {
      const subpartText = `TTFB: ${lcpTtfb}ms | Load Delay: ${lcpLoadDelay}ms | Load Duration: ${lcpLoadDuration}ms | Render Delay: ${lcpRenderDelay}ms`;
      if (lcpMs > 4000) {
        findings.push({
          id: 'critical-lcp',
          category: 'performance',
          severity: 'critical',
          badge: 'CRITICAL LCP',
          title: `Measured Largest Contentful Paint Delayed (${lcpMs} ms)`,
          evidence: [
            { label: 'Measured LCP Render Timing', value: `${lcpMs} ms`, context: 'Budget: < 2,500 ms' },
            { label: 'Observed LCP Element', value: lcpSelector || 'Hero Element' },
            { label: 'Subpart Attribution Breakdown', value: subpartText },
            { label: 'Measurement Source', value: 'Google Web Vitals Observer (Canonical LCP)' }
          ],
          confidence: 'high',
          explanation: `The primary above-the-fold content (${lcpSelector || 'hero element'}) required over 4 seconds to render. Attribution shows a ${lcpLoadDelay}ms resource load delay and ${lcpRenderDelay}ms element render delay.`,
          recommendation: 'Preload the hero asset, set fetchpriority="high", and optimize server response time.',
          improvements: [
            'Add <link rel="preload" as="image" fetchpriority="high"> for the primary hero asset',
            'Ensure the LCP image or container is not delayed by client-side JavaScript rendering',
            'Reduce server response latency (TTFB) to accelerate initial markup delivery'
          ]
        });
      } else if (lcpMs > 2500) {
        findings.push({
          id: 'warning-lcp',
          category: 'performance',
          severity: 'warning',
          badge: 'ELEVATED LCP',
          title: `Measured Largest Contentful Paint Exceeds Recommended Budget (${lcpMs} ms)`,
          evidence: [
            { label: 'Measured LCP Render Timing', value: `${lcpMs} ms`, context: 'Budget: < 2,500 ms' },
            { label: 'Observed LCP Element', value: lcpSelector || 'Hero Element' },
            { label: 'Subpart Attribution Breakdown', value: subpartText }
          ],
          confidence: 'high',
          explanation: `Measured LCP on ${lcpSelector || 'hero content'} exceeds the 2.5s threshold, delaying perceived page load on mobile connections.`,
          recommendation: 'Prioritize hero resource delivery and verify modern WebP/AVIF formatting.',
          improvements: [
            'Verify hero image delivers responsive dimensions matching mobile screen width',
            'Avoid lazy-loading above-the-fold hero images (remove loading="lazy" from hero elements)',
            'Profile render-blocking stylesheets delaying font and layout calculations'
          ]
        });
      }
    }

    // --- 2. CORE WEB VITALS: MEASURED INP WITH INTERACTION ATTRIBUTION ---
    if (inpObserved && inpMs !== null && inpMs > 200) {
      const isCriticalInp = inpMs > 500;
      const inpEvidence: any[] = [
        { label: 'Measured INP Latency', value: `${inpMs} ms`, context: 'Budget: < 200 ms' },
        { label: 'Observed Interaction Target', value: inpTarget || 'Interactive Element' },
        { label: 'Processing Delay', value: `${inpProcessingDelay} ms`, context: 'Main-thread handler execution' },
        { label: 'Input Delay', value: `${inpInputDelay} ms`, context: 'Event queue delay' },
        { label: 'Measurement Source', value: 'Google Web Vitals Event Timing Observer' }
      ];

      if (inpAttribution && inpAttribution.culpritScriptUrl) {
        inpEvidence.push({
          label: 'Offending Script Culprit',
          value: `${inpAttribution.culpritFunctionName || 'anonymous'} in ${inpAttribution.culpritScriptUrl.split('/').pop()}`,
          context: `${inpAttribution.culpritExecutionMs}ms execution (${inpAttribution.culpritForcedStyleMs}ms forced layout thrashing)`
        });
      }

      if (inpAttribution && inpAttribution.groupedEventCount && inpAttribution.groupedEventCount > 1) {
        inpEvidence.push({
          label: 'Grouped Interaction Events',
          value: `${(inpAttribution.groupedEvents || []).join(', ')} (${inpAttribution.groupedEventCount} events in 8ms frame window)`
        });
      }

      let inpExplanation = `User interaction on ${inpTarget || 'interactive elements'} took ${inpMs} ms to present the next frame, causing visible UI lag on mobile devices.`;
      if (inpAttribution && inpAttribution.culpritScriptUrl) {
        inpExplanation += ` Long Animation Frame telemetry identified ${inpAttribution.culpritFunctionName || 'handler'} in ${inpAttribution.culpritScriptUrl.split('/').pop()} executing for ${inpAttribution.culpritExecutionMs}ms during event processing.`;
      }

      findings.push({
        id: isCriticalInp ? 'critical-inp' : 'warning-inp',
        category: 'performance',
        severity: isCriticalInp ? 'critical' : 'warning',
        badge: isCriticalInp ? 'CRITICAL INP' : 'ELEVATED INP',
        title: `Interaction to Next Paint Exceeds Budget (${inpMs} ms)`,
        evidence: inpEvidence,
        confidence: 'high',
        explanation: inpExplanation,
        recommendation: 'De-prioritize heavy event listener logic, defer secondary tracking scripts, and yield the main thread during user clicks.',
        improvements: [
          `Profile event handlers bound to ${inpTarget || 'interactive buttons'} in Chrome DevTools`,
          'Break up synchronous JavaScript execution during click handlers using requestIdleCallback',
          'Defer non-essential analytics tracking triggered on user interactions'
        ]
      });
    }

    // --- 3. CORE WEB VITALS: MEASURED CLS ---
    if (cls !== null && cls > 0.1) {
      const isCriticalCls = cls > 0.25;
      const shiftDetails = data.performance?.clsAttribution?.shiftDetails || data.shiftDetails || [];
      const topShift = shiftDetails.length > 0 ? shiftDetails[0] : null;
      const clsEvidence: any[] = [
        { label: 'Observed CLS Score', value: cls.toFixed(3), context: 'Budget: < 0.10' },
        { label: 'Measurement Window', value: 'Canonical Session Window (Max 5s / 1s gap)' },
        ...(clsTarget ? [{ label: 'Largest Shift Target', value: clsTarget }] : [])
      ];

      if (topShift && topShift.distancePx > 0) {
        clsEvidence.push({
          label: 'Shift Displacement',
          value: `${topShift.direction} by ${topShift.distancePx}px (Impact: ${topShift.impactAreaPx.toLocaleString()} px²)`
        });
      }

      findings.push({
        id: isCriticalCls ? 'critical-cls' : 'warning-cls',
        category: 'performance',
        severity: isCriticalCls ? 'critical' : 'warning',
        badge: isCriticalCls ? 'CRITICAL LAYOUT SHIFT' : 'ELEVATED LAYOUT SHIFT',
        title: `Cumulative Layout Shift Detected (${cls.toFixed(3)})`,
        evidence: clsEvidence,
        confidence: 'high',
        explanation: 'Unsized elements or late-injected content caused layout instability during page rendering, shifting clickable buttons or content.',
        recommendation: 'Reserve explicit aspect-ratio and width/height dimensions for all images, banners, and dynamic embeds.',
        improvements: [
          'Add explicit width and height attributes to all image tags',
          'Reserve minimum height containers for dynamic embeds or banner containers',
          'Use CSS aspect-ratio on media wrappers to preserve layout geometry before asset load'
        ]
      });
    }

    // --- 3. MOBILE VIEWPORT: Missing Viewport Meta Tag ---
    if (vpMissing) {
      findings.push({
        id: 'missing-viewport',
        category: 'accessibility',
        severity: 'critical',
        badge: 'CRITICAL REGRESSION',
        title: 'Missing Viewport Meta Tag',
        evidence: [
          { label: 'Viewport Meta Tag', value: 'Absent in <head>' },
          { label: 'Observed Viewport Width', value: `${data.metadata?.viewportWidth || 'Desktop'} px` }
        ],
        confidence: 'high',
        explanation: 'Without a viewport meta tag, mobile browsers render pages in desktop emulation mode, causing unscaled layouts and horizontal panning on mobile devices.',
        recommendation: 'Add <meta name="viewport" content="width=device-width, initial-scale=1.0"> to document <head>.',
        improvements: [
          'Add standard viewport tag: <meta name="viewport" content="width=device-width, initial-scale=1.0">',
          'Audit container layouts on 390px and 430px viewports to verify fluid adaptation',
          'Verify touch targets maintain readable scale across screen resolutions'
        ]
      });
    }

    // --- 4. ACCESSIBILITY ADVISORY: Locked Viewport / Restricts User Scaling ---
    if (vpLocked) {
      findings.push({
        id: 'restricted-viewport',
        category: 'accessibility',
        severity: 'warning',
        badge: 'ACCESSIBILITY ADVISORY',
        title: 'Viewport Directive Restricts User Zooming',
        evidence: [
          { label: 'Viewport Directive', value: data.accessibility?.viewportContent || 'user-scalable=no / maximum-scale=1' },
          { label: 'Standard Reference', value: 'WCAG 2.2 Success Criterion 1.4.4 (Resize Text Advisory)' }
        ],
        confidence: 'high',
        explanation: 'The viewport configuration disables user scaling, which creates usability barriers for visitors with low vision who need pinch-to-zoom magnification. Note: Automated audit tools identify the directive; full WCAG conformance requires manual testing.',
        recommendation: 'Remove user-scalable=no and maximum-scale=1 directives to allow native browser pinch-to-zoom.',
        improvements: [
          'Update viewport meta content to: width=device-width, initial-scale=1.0',
          'Remove maximum-scale=1.0 and user-scalable=0 directives',
          'Verify layout containers adapt cleanly without horizontal overflow when zoomed'
        ]
      });
    }

    // --- 5. Horizontal Layout Overflow ---
    if (horizontalOverflow) {
      findings.push({
        id: 'horizontal-overflow',
        category: 'architecture',
        severity: 'warning',
        badge: 'LAYOUT OVERFLOW',
        title: 'Horizontal Page Overflow Detected',
        evidence: [
          { label: 'Document Scroll Width', value: 'Exceeds window.innerWidth' },
          { label: 'Observed Symptom', value: 'Horizontal scrollbar present on mobile viewport' }
        ],
        confidence: 'high',
        explanation: 'Elements with fixed pixel widths or unconstrained negative margins exceed the screen width, causing unintentional horizontal scrolling on mobile screens.',
        recommendation: 'Audit fixed-width containers and apply max-width: 100% with box-sizing: border-box.',
        improvements: [
          'Inspect full-width containers for fixed pixel width declarations',
          'Ensure all images have max-width: 100% and height: auto',
          'Audit elements using negative margins or unconstrained absolute positioning'
        ]
      });
    }

    // --- 6. DOM Tree Complexity & Depth ---
    if (totalElements > 2800 || maxDepth > 22) {
      findings.push({
        id: 'deep-dom-tree',
        category: 'performance',
        severity: 'critical',
        badge: 'CRITICAL DOM BLOAT',
        title: 'High DOM Element Count & Deep Tree Hierarchy',
        evidence: [
          { label: 'Total DOM Elements', value: totalElements.toLocaleString(), context: 'Standard guideline: < 1,400' },
          { label: 'Tree Depth', value: String(maxDepth), context: 'Guideline: < 15 levels' },
          { label: 'Maximum Tree Depth', value: `${maxDepth} levels`, context: 'Guideline: < 15 levels' },
          { label: 'Deep Branches (>15)', value: `${data.dom?.deepBranchCount || 0} nodes` }
        ],
        confidence: 'high',
        explanation: 'Heavily nested DOM hierarchies increase style recalculation and layout cost on mobile CPUs during scroll and user interactions.',
        recommendation: 'Flatten nested container structures and eliminate unneeded layout wrappers.',
        improvements: [
          'Flatten nested container wrappers in page templates',
          'Evaluate lighter layout patterns (CSS Grid / Flexbox instead of multi-level DIV nesting)',
          'Defer rendering of below-the-fold components using content-visibility: auto'
        ]
      });
    } else if (totalElements > 1400 || maxDepth > 16) {
      findings.push({
        id: 'deep-dom-tree',
        category: 'performance',
        severity: 'warning',
        badge: 'PERFORMANCE WARNING',
        title: 'Elevated DOM Node Count & Hierarchy Depth',
        evidence: [
          { label: 'DOM Elements', value: totalElements.toLocaleString(), context: 'Guideline: < 1,400' },
          { label: 'Tree Depth', value: String(maxDepth), context: 'Guideline: < 15 levels' },
          { label: 'Maximum Tree Depth', value: `${maxDepth} levels`, context: 'Guideline: < 15 levels' },
          { label: 'Serialized Markup', value: `${data.serializedSizeKB || 0} KB` }
        ],
        confidence: 'high',
        explanation: 'Elevated DOM node counts increase memory consumption and can delay style recalculation during mobile navigation.',
        recommendation: 'Profile component hierarchy in Chrome DevTools to identify heavily nested wrappers.',
        improvements: [
          'Profile DOM depth in Chrome DevTools Performance panel',
          'Reduce redundant layout containers across recurring section components',
          'Audit dynamic widgets injecting excessive wrapper elements'
        ]
      });
    }

    // --- 7. Main Thread Long Tasks & Contention ---
    const loafCount = data.mainThread?.loafCount || data.loafCount || 0;
    const loafCulprit = data.mainThread?.primaryLoafCulprit || data.primaryLoafCulprit || null;
    const totalLoafBlockingMs = data.mainThread?.totalLoafBlockingMs || data.totalLoafBlockingMs || 0;

    if (longTaskCount > 3 || (longestTaskMs !== null && longestTaskMs > 250) || loafCount > 0) {
      const mainThreadEvidence: any[] = [
        { label: 'Observed Long Tasks (>50ms)', value: String(longTaskCount) },
        { label: 'Longest Task Duration', value: longestTaskMs ? `${longestTaskMs} ms` : 'N/A' },
        { label: 'Total Blocking Time', value: `${totalBlockingTimeMs} ms` }
      ];

      if (loafCount > 0) {
        mainThreadEvidence.push({
          label: 'Long Animation Frames (LoAF)',
          value: `${loafCount} frames (${totalLoafBlockingMs} ms blocking)`
        });
      }

      if (loafCulprit) {
        const culpritDescriptor = loafCulprit.sourceUrl || loafCulprit.invoker || loafCulprit.sourceFunctionName || 'Inline Script Execution';
        mainThreadEvidence.push({
          label: 'LoAF Script Culprit',
          value: culpritDescriptor
        });
        if (loafCulprit.invoker && loafCulprit.sourceUrl) {
          mainThreadEvidence.push({
            label: 'LoAF Invoker Callback',
            value: `${loafCulprit.invokerType || 'callback'}: ${loafCulprit.invoker}`
          });
        }
        mainThreadEvidence.push({
          label: 'Culprit Execution Time',
          value: `${loafCulprit.executionDurationMs} ms (Forced Reflow: ${loafCulprit.forcedStyleAndLayoutMs} ms)`
        });
      }

      const hasCulprit = Boolean(loafCulprit && (loafCulprit.sourceUrl || loafCulprit.invoker || loafCulprit.sourceFunctionName));
      const culpritSummary = loafCulprit
        ? (loafCulprit.sourceUrl
          ? `${loafCulprit.sourceUrl}${loafCulprit.invoker ? ' via ' + loafCulprit.invoker : ''}`
          : (loafCulprit.invoker || loafCulprit.sourceFunctionName || 'inline script'))
        : '';

      findings.push({
        id: 'main-thread-long-tasks',
        category: 'performance',
        severity: 'warning',
        badge: 'MAIN THREAD CONTENTION',
        title: hasCulprit
          ? 'Script Culprit Blocking Main Thread (LoAF Telemetry)'
          : 'Long JavaScript Tasks Blocking Main Thread',
        evidence: mainThreadEvidence,
        confidence: 'high',
        explanation: hasCulprit
          ? `Main thread execution blocked by script culprit ${culpritSummary}, delaying user interaction and frame rendering.`
          : 'Long JavaScript tasks monopolize the browser main thread, delaying response to user taps and clicks.',
        recommendation: (loafCulprit && loafCulprit.forcedStyleAndLayoutMs > 0)
          ? 'Eliminate synchronous layout thrashing (forced reflow) and break up long-running script execution using requestIdleCallback or scheduler.yield().'
          : 'Break up long-running script execution using requestIdleCallback or scheduler.yield().',
        improvements: [
          'Profile JavaScript execution in Chrome DevTools Performance panel',
          'Audit third-party scripts running during initial page load',
          'Break up compute-heavy tasks into smaller chunks using requestIdleCallback',
          ...(loafCulprit && loafCulprit.forcedStyleAndLayoutMs > 0
            ? ['Eliminate forced synchronous reflows by avoiding DOM style reads immediately following DOM writes']
            : [])
        ]
      });
    }

    // --- 8. Server TTFB Response Latency ---
    if (ttfbMs > 500) {
      findings.push({
        id: 'high-ttfb',
        category: 'performance',
        severity: ttfbMs > 1000 ? 'critical' : 'warning',
        badge: ttfbMs > 1000 ? 'ELEVATED TTFB' : 'SLOW SERVER RESPONSE',
        title: 'Elevated Server Response Time (Browser-observed TTFB)',
        evidence: [
          { label: 'Browser-observed TTFB', value: `${ttfbMs} ms`, context: 'Target: < 500 ms' },
          { label: 'Server Processing Duration', value: `${data.serverProcessingMs || ttfbMs} ms` },
          { label: 'Delivery State', value: data.cacheState || 'network-delivered' }
        ],
        confidence: 'high',
        explanation: 'Browser-observed Time to First Byte reflects initial server and network delay before document bytes begin arriving.',
        recommendation: 'Enable edge page caching (CDN HTML caching) or profile slow database queries.',
        improvements: [
          'Implement full-page edge caching via Cloudflare or CDN',
          'Verify server-side object caching (Redis / Memcached) is active',
          'Profile backend application response times and slow database queries'
        ]
      });
    }

    // --- 9. Image Resolution & Dimension Opportunities ---
    if (oversizedCount > 2 || missingDimsCount > 5) {
      findings.push({
        id: 'image-optimization-opportunity',
        category: 'performance',
        severity: 'opportunity',
        badge: 'POTENTIALLY OVERSIZED IMAGES',
        title: 'Potentially Oversized Image Resources & Missing Dimensions',
        evidence: [
          { label: 'Potentially Oversized Assets', value: `${oversizedCount} assets`, context: 'Natural resolution exceeds layout display by > 1.25x DPR threshold and > 400px' },
          { label: 'Missing Dimensions', value: `${missingDimsCount} assets`, context: 'Missing explicit width/height attributes' },
          { label: 'Total Images Scanned', value: String(data.imagesCount || 0) }
        ],
        confidence: 'high',
        explanation: 'Serving image assets significantly larger than their rendered viewport dimensions consumes excess network transfer. In high-DPI displays (DPR 2x-3x), images up to 1.25x the display size are recognized as intentional high-density graphics; assets exceeding this threshold are flagged as potentially oversized. This is a diagnostic heuristic based on rendered geometry and does not assess file compression efficiency. Omitting explicit width/height attributes can additionally induce cumulative layout shifts.',
        recommendation: 'Specify explicit width/height attributes and serve responsive srcset dimensions tailored to mobile viewports.',
        improvements: [
          'Add explicit width and height attributes to all <img> tags to reserve layout space and mitigate CLS',
          'Implement responsive srcset and sizes to deliver appropriately scaled images for mobile viewports',
          'Ensure modern WebP or AVIF formats are delivered via responsive <picture> or content negotiation'
        ]
      });
    }

    // --- 10. Structured Data & Schema.org ---
    if (!hasSchema) {
      findings.push({
        id: 'missing-schema',
        category: 'seo',
        severity: 'opportunity',
        badge: 'STRUCTURED DATA GAP',
        title: 'Missing Schema.org JSON-LD Structured Data',
        evidence: [
          { label: 'JSON-LD Entity Graph', value: 'None detected' },
          { label: 'Search Discoverability', value: 'Opportunity for rich snippet qualification' }
        ],
        confidence: 'high',
        explanation: 'Schema.org JSON-LD provides structured entity context to search engine crawlers and knowledge graphs.',
        recommendation: 'Add valid JSON-LD entity markup for Organization, WebSite, and page-specific entities.',
        improvements: [
          'Implement Organization and WebSite JSON-LD structured data in document <head>',
          'Add breadcrumb list schema to establish topical hierarchy for search engines',
          'Validate structured data markup using the official Schema.org validator'
        ]
      });
    } else if (!jsonLdValid) {
      findings.push({
        id: 'malformed-schema',
        category: 'seo',
        severity: 'warning',
        badge: 'MALFORMED SCHEMA',
        title: 'Structured Data Detected But JSON-LD Parsing Failed',
        evidence: [
          { label: 'JSON-LD Tag', value: 'Detected in document' },
          { label: 'Parser Result', value: 'Syntax parse error in application/ld+json' },
          { label: 'Error Details', value: data.seo?.parsingErrors?.join('; ') || 'Parse failure' }
        ],
        confidence: 'high',
        explanation: 'A JSON-LD script contains malformed JSON syntax, preventing search crawlers from reading your structured data graph.',
        recommendation: 'Inspect and correct the JSON syntax error in your application/ld+json script tags.',
        improvements: [
          'Inspect the application/ld+json script block for unescaped quotes or trailing commas',
          'Verify JSON validity using an online JSON validator or Schema markup tool',
          'Ensure dynamic server-side template tags properly encode JSON characters'
        ]
      });
    }

    // --- 10b. On-Page SEO Architecture & Heading Structure ---
    if (headingsData?.missingH1) {
      findings.push({
        id: 'missing-h1',
        category: 'seo',
        severity: 'warning',
        badge: 'MISSING H1 HEADING',
        title: 'No Primary Heading (H1) Detected',
        evidence: [
          { label: 'Observed H1 Tags', value: '0 detected' },
          { label: 'Total Headings in Document', value: `${headingsData.totalCount} headings` }
        ],
        confidence: 'high',
        explanation: 'Search engines and screen readers rely on a primary <h1> heading to discern page topic and document structure.',
        recommendation: 'Add a single descriptive <h1> heading communicating the primary subject of the page.',
        improvements: [
          'Add a descriptive <h1> tag near the top of the main content area',
          'Ensure the <h1> clearly reflects the primary keyword intent of this page',
          'Avoid skipping directly to <h2> or styling non-heading elements to look like titles'
        ]
      });
    }

    if (headingsData?.duplicateH1) {
      findings.push({
        id: 'duplicate-h1',
        category: 'seo',
        severity: 'warning',
        badge: 'MULTIPLE H1 HEADINGS',
        title: `Multiple Primary Headings (${headingsData.h1Count} H1 Tags Detected)`,
        evidence: [
          { label: 'Observed H1 Tags', value: `${headingsData.h1Count} elements` },
          { label: 'SEO Standard', value: '1 primary H1 per document recommended' }
        ],
        confidence: 'high',
        explanation: `Multiple <h1> headings (${headingsData.h1Count}) dilute topical clarity for search engine crawlers and confuse assistive screen readers.`,
        recommendation: 'Reserve <h1> for the main page title and demote secondary section titles to <h2> or <h3>.',
        improvements: [
          'Consolidate the primary page title into a single <h1> heading tag',
          'Demote sub-section headings from <h1> to <h2> or <h3>',
          'Ensure a clear single-topic document outline for search crawlers'
        ]
      });
    }

    if (headingsData?.skippedLevels && headingsData.skippedLevels.length > 0) {
      const skippedSummary = headingsData.skippedLevels
        .map((s: any) => `${s.fromTag.toUpperCase()} -> ${s.toTag.toUpperCase()}`)
        .join(', ');
      findings.push({
        id: 'skipped-heading-hierarchy',
        category: 'seo',
        severity: 'opportunity',
        badge: 'HEADING HIERARCHY GAP',
        title: 'Skipped Heading Hierarchy Level Detected',
        evidence: [
          { label: 'Skipped Sequences', value: skippedSummary },
          { label: 'Total Skipped Instances', value: `${headingsData.skippedLevels.length} skipped level(s)` }
        ],
        confidence: 'high',
        explanation: `Heading tags jump across hierarchy levels (${skippedSummary}), breaking semantic outline structure for screen readers and search engines.`,
        recommendation: 'Restructure headings so levels step sequentially without skipping tiers (e.g. H1 to H2 to H3).',
        improvements: [
          'Step heading levels sequentially (H1 followed by H2, then H3)',
          'Use CSS classes rather than skipping heading tags to achieve desired typography scale',
          'Audit automated page builder heading presets for semantic tag accuracy'
        ]
      });
    }

    if (seoData?.canonical && seoData.canonicalMatchesUrl === false) {
      findings.push({
        id: 'canonical-mismatch',
        category: 'seo',
        severity: 'opportunity',
        badge: 'CANONICAL DIVERGENCE',
        title: 'Declared Canonical URL Diverges from Page Address',
        evidence: [
          { label: 'Declared Canonical Tag', value: seoData.canonical },
          { label: 'Current Address Match', value: 'Divergent Target' }
        ],
        confidence: 'high',
        explanation: 'The declared <link rel="canonical"> target does not match the active page address. Search crawlers will consolidate index signals toward the alternate canonical destination.',
        recommendation: 'Verify whether this page is intended to be self-canonicalized or intentionally pointing to an alternate address.',
        improvements: [
          'Ensure the canonical URL matches the preferred indexing destination for this page',
          'Standardize trailing slash formatting, http/https protocol, and domain host variations',
          'Prevent query parameter variations from creating unexpected canonical divergence'
        ]
      });
    }

    if (seoData?.isNoindex) {
      findings.push({
        id: 'noindex-directive',
        category: 'seo',
        severity: 'warning',
        badge: 'NOINDEX DIRECTIVE',
        title: 'Robots Noindex Directive Blocking Search Indexing',
        evidence: [
          { label: 'Robots Directive', value: seoData.robots || 'noindex' },
          { label: 'Discoverability Status', value: 'Excluded from search engine index' }
        ],
        confidence: 'high',
        explanation: 'A robots meta directive contains "noindex", preventing search engines from indexing this page or displaying it in search results.',
        recommendation: 'Remove the "noindex" directive from the robots meta tag if this page should receive organic search traffic.',
        improvements: [
          'Remove "noindex" from meta name="robots" if organic search indexing is intended',
          'Verify staging environment configuration tags were not deployed to production',
          'Inspect server HTTP X-Robots-Tag headers for duplicate noindex instructions'
        ]
      });
    }
    if (undersizedCount24px > 0) {
      findings.push({
        id: 'wcag-target-size-concern',
        category: 'accessibility',
        severity: 'warning',
        badge: 'POTENTIAL WCAG 2.5.8 CONCERN',
        title: 'Potential WCAG 2.5.8 Target Size Concern (< 24px)',
        evidence: [
          { label: 'Targets < 24x24px', value: `${undersizedCount24px} elements` },
          { label: 'Smallest Observed Target', value: data.smallestTarget || 'Undersized' },
          { label: 'Standard Reference', value: 'WCAG 2.5.8 Target Size (Minimum) - Level AA (Potential concern, exceptions may apply)' }
        ],
        confidence: 'medium',
        explanation: 'Interactive elements smaller than 24x24 CSS pixels can present touch usability challenges. WCAG 2.5.8 (Level AA) specifies a minimum target size of 24x24 CSS pixels, but permits exceptions for inline text links, sufficient spacing offsets, and equivalent larger controls. Observed geometry alone does not establish a formal WCAG 2.5.8 conformance failure. This finding reports observed dimensions and does not constitute a formal compliance verdict.',
        recommendation: 'Provide at least 24x24px target size or verify sufficient spacing offsets between adjacent interactive elements.',
        improvements: [
          'Increase padding around compact icon buttons and links to reach 24x24px minimum touch area',
          'Ensure at least 12px spacing between adjacent small interactive targets',
          'Verify inline text link and spacing exceptions before altering layout'
        ]
      });
    } else if (undersizedCount44px > 10) {
      findings.push({
        id: 'touch-target-usability',
        category: 'accessibility',
        severity: 'opportunity',
        badge: 'MOBILE USABILITY HEURISTIC',
        title: 'Compact Interactive Elements (< 44px)',
        evidence: [
          { label: 'Targets < 44x44px', value: `${undersizedCount44px} elements` },
          { label: 'Guideline Reference', value: 'Apple HIG / Google Material Usability Guideline (Informational, not WCAG AA failure)' }
        ],
        confidence: 'medium',
        explanation: 'Mobile design guidelines recommend 44x44px to 48x48px touch targets to minimize accidental taps on phone displays.',
        recommendation: 'Expand tap target padding on primary buttons and navigation links.',
        improvements: [
          'Add padding to compact buttons and icon links to reach 44x44px target area',
          'Ensure adequate spacing between adjacent navigation links',
          'Verify touch target comfort on handheld mobile devices'
        ]
      });
    }

    // --- 12. HEALTHY BASELINE: When site is well-engineered ---
    const hasCriticalOrWarning = findings.some(f => f.severity === 'critical' || f.severity === 'warning');

    if (!hasCriticalOrWarning) {
      findings.unshift({
        id: 'healthy-baseline',
        category: 'architecture',
        severity: 'healthy',
        badge: 'OPTIMIZED BASELINE',
        title: 'Well-Engineered Architecture & Clean Telemetry',
        evidence: [
          { label: 'DOM Elements', value: totalElements.toLocaleString(), context: 'Healthy baseline' },
          { label: 'Max Tree Depth', value: `${maxDepth} levels`, context: 'Well-structured' },
          { label: 'Mobile Viewport', value: 'Responsive & Scalable' },
          { label: 'Observed TTFB', value: ttfbMs > 0 ? `${ttfbMs} ms` : 'Optimal' }
        ],
        confidence: 'high',
        explanation: 'No major architectural issues detected. The DOM hierarchy, viewport scaling, and server response metrics reflect solid engineering standards.',
        recommendation: 'Maintain continuous Core Web Vitals monitoring and edge caching standards.',
        improvements: [
          'Maintain clean DOM nesting hygiene across new landing pages',
          'Monitor field Core Web Vitals (INP and LCP) in Google Search Console',
          'Keep third-party tag managers streamlined to prevent script bloat'
        ]
      });
    }

    // Determine primary finding:
    // If site has healthy baseline (no critical/warning), healthy-baseline is primary!
    let primaryFinding: Finding;
    if (!hasCriticalOrWarning) {
      primaryFinding = findings[0]; // healthy-baseline
    } else {
      const severityRank: Record<SeverityLevel, number> = {
        critical: 4,
        warning: 3,
        opportunity: 2,
        healthy: 1
      };
      findings.sort((a, b) => severityRank[b.severity] - severityRank[a.severity]);
      primaryFinding = findings[0];
    }

    // Compute VitalsSniper Proprietary Heuristic Index [20, 100]
    let score = 100;
    if (vpMissing) score -= 25;
    else if (vpLocked) score -= 10;

    if (totalElements > 3000) score -= 20;
    else if (totalElements > 1800) score -= 10;

    if (maxDepth > 24) score -= 10;
    else if (maxDepth > 18) score -= 5;

    if (data.serializedSizeKB > 150) score -= 15;
    else if (data.serializedSizeKB > 80) score -= 8;

    if (oversizedCount > 5) score -= 10;
    else if (oversizedCount > 2) score -= 5;

    if (ttfbMs > 1000) score -= 15;
    else if (ttfbMs > 500) score -= 8;

    if (lcpMs !== null && lcpMs > 4000) score -= 15;
    else if (lcpMs !== null && lcpMs > 2500) score -= 8;

    if (inpObserved && inpMs !== null && inpMs > 500) score -= 15;
    else if (inpObserved && inpMs !== null && inpMs > 200) score -= 8;

    if (cls !== null && cls > 0.25) score -= 15;
    else if (cls !== null && cls > 0.1) score -= 8;

    score = Math.max(20, Math.min(100, score));

    return {
      overallScore: score,
      scoreMethodology: 'VitalsSniper proprietary diagnostic heuristic (Not Google Lighthouse or CWV)',
      categoryScores: {
        performance: Math.max(30, score - (totalElements > 2000 ? 15 : 0) - (ttfbMs > 500 ? 10 : 0)),
        accessibility: vpMissing ? 40 : (vpLocked ? 70 : (undersizedCount24px > 0 ? 80 : 100)),
        seo: hasSchema ? (jsonLdValid ? 100 : 70) : 80,
        architecture: Math.max(40, 100 - (maxDepth > 18 ? 20 : 0) - (horizontalOverflow ? 20 : 0))
      },
      primaryFinding,
      allFindings: findings
    };
  }
}
