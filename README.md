# VitalsSniper: Proof-of-Flaw Web Performance Inspector

[![Chrome Web Store Version](https://img.shields.io/badge/Chrome_Web_Store-v1.6.5-4285F4?logo=googlechrome&logoColor=white)](https://chromewebstore.google.com/detail/vitalssniper-proof-of-fl/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0_Runtime-success.svg)](package.json)
[![Package Size](https://img.shields.io/badge/Package_Size-130.8_KB-informational.svg)](dist/)
[![Test Suite](https://img.shields.io/badge/Tests-100%25_Passing-brightgreen.svg)](tests/)
[![Manifest V3](https://img.shields.io/badge/Manifest-V3_Compliant-orange.svg)](manifest.json)

13/13 automated test suites passing. Zero runtime dependencies. Package size under 135KB.

[Install from Chrome Web Store](https://chromewebstore.google.com/detail/vitalssniper-proof-of-flaw/ohabpnaccigjhkkebjofhpmebofgpbeb) | [Cloud Workspace & Multi-Tab Reporting](https://webaudits.pro) | [Documentation](https://webaudits.pro/docs)

VitalsSniper is an open-source, client-side browser performance auditor and search crawler emulator built on Manifest V3. Operating directly inside the active tab execution context in under 50 milliseconds, it provides real-time Core Web Vitals profiling, subpart latency attribution, DOM bloat analysis, and search engine crawler simulation without remote server queues or external runtime dependencies.

---

## Architectural Overview

Most traditional web audit tools execute in headless server clusters running synthetic Chrome instances. While useful for coarse regression monitoring, remote lab audits introduce significant queue latency and cannot observe live, authenticated user interactions or dynamic single-page application state.

VitalsSniper executes locally inside the browser engine using native Chromium APIs:

```
+-----------------------------------------------------------------------------+
|                                ACTIVE BROWSER TAB                           |
|                                                                             |
|  +---------------------------+        +----------------------------------+  |
|  |     W3C Web Platform      |        |          DOM Tree Walker         |  |
|  |                           |        |                                  |  |
|  | - PerformanceObserver     |        | - Node recursion & max depth     |  |
|  | - Long Animation Frames   |        | - Deep shadow DOM traversal      |  |
|  | - Event Timing (web-vitals|        | - Serialized HTML byte weight    |  |
|  | - Navigation Timing Level |        | - V8 memory allocation modeling  |  |
|  +-------------+-------------+        +----------------+-----------------+  |
+----------------|---------------------------------------|--------------------+
                 |                                       |
                 +-------------------+-------------------+
                                     |
                                     v
+-----------------------------------------------------------------------------+
|                         VITALSSNIPER AUDIT ENGINE                           |
|                                                                             |
|  +---------------------------+        +----------------------------------+  |
|  |   Linear Memory Primitives|        |      Attribution & Heuristics    |  |
|  |                           |        |                                  |  |
|  | - ArrayPool (zero alloc)  |        | - 3-Phase INP subpart math       |  |
|  | - AsyncLock (R/W barrier) |        | - LoAF script culprit isolation  |  |
|  | - Monotonic timer cleanup |        | - 8ms VSYNC frame budget model   |  |
|  +---------------------------+        +----------------------------------+  |
|                                                                             |
|  +---------------------------+        +----------------------------------+  |
|  |  Technology Detection DAG |        |     Financial Latency Engine     |  |
|  |                           |        |                                  |  |
|  | - 60+ CMS/builder patterns|        | - Deloitte & Google decay curves |  |
|  | - Implies/excludes graph  |        | - Conversion loss calculation    |  |
|  | - SemVer regex extraction |        | - Local currency normalization   |  |
|  +---------------------------+        +----------------------------------+  |
+------------------------------------+----------------------------------------+
                                     |
                                     v
+------------------------------------+----------------------------------------+
|                      BACKGROUND SERVICE WORKER (MV3)                        |
|                                                                             |
|  - declarativeNetRequest session rules (Rule ID: 1001)                      |
|  - Tab-isolated User-Agent header modification                              |
|  - Target profiles: Googlebot Smartphone, Googlebot Desktop, Bingbot, GPTBot|
+-----------------------------------------------------------------------------+
```

---

## Core Capabilities

### 1. W3C Long Animation Frames (LoAF) API Correlation

Starting in Chrome 123, the Long Animation Frames API replaces crude 50ms Long Tasks by exposing fine-grained execution metrics directly from the Blink rendering engine. VitalsSniper captures buffered `long-animation-frame` entries via `PerformanceObserver`:

- Execution breakdown: measures total frame duration, blocking duration, pause duration, and forced style and layout recalculation time.
- Script-level attribution: extracts the invoker type (`classic-script`, `module-script`, `user-callback`, `event-listener`), source function name, source file URL, and character offset.
- Temporal intersection: correlates observed user interaction windows with overlapping LoAF instances, isolating the precise script execution block responsible for blocking the main thread.
- Frame budget evaluation: checks rendering duration against the 8.33ms VSYNC boundary (120Hz display interval) to detect render-blocking compositor delays.

### 2. Google web-vitals v4 3-Phase INP Attribution

VitalsSniper tracks Interaction to Next Paint (INP) using the official W3C Event Timing API and Google web-vitals v4 telemetry model:

- Mathematical latency decomposition:
  * Input Delay = `processingStart - startTime` (queue latency waiting for main thread availability).
  * Processing Duration = `processingEnd - processingStart` (synchronous execution time of registered event listeners).
  * Presentation Delay = `duration - (processingEnd - startTime)` (time required for forced style recalculation, layout, paint, and compositor commit).
- Interaction grouping: groups related event bursts (pointerdown, pointerup, click) occurring within an 8ms window to evaluate the worst-case interaction group.
- LoadState classification: attributes interaction timing against document lifecycle phase (`loading`, `dom-interactive`, `dom-content-loaded`, `complete`) to differentiate startup contention from runtime interaction decay.

### 3. Forensic DOM Bloat & Memory Overhead Scanner

Excessive DOM complexity degrades selector evaluation speeds, increases style recalculation costs, and multiplies JavaScript memory overhead. VitalsSniper analyzes live page markup in memory:

- Structural complexity: counts total DOM elements, computes average depth, and identifies branches exceeding 15 nested levels.
- Shadow DOM traversal: uses recursive tree walking combined with `WeakMap` caching to inspect open shadow roots across encapsulated web components.
- Container density: identifies single container elements with excessive direct children, flagging unvirtualized data tables and infinite lists.
- Memory consumption modeling: estimates V8 and Blink memory footprint based on active node count, detached elements, and DOM object wrapper overhead (~1KB per active node).
- Payload weight: compares uncompressed in-memory serialized HTML size against compressed network wire transfer size.

### 4. Tab-Isolated DeclarativeNetRequest Search Crawler Emulator

Auditing how search engines and AI scrapers perceive a page traditionally required external proxy tunnels or command-line curl sessions. VitalsSniper implements tab-scoped crawler emulation using the Manifest V3 `chrome.declarativeNetRequest` API:

- Scoped session rules: modifies outbound `User-Agent` headers dynamically using session rules (`updateSessionRules`), strictly confined to the active tab ID (`tabIds: [activeTabId]`).
- Clean separation: does not alter global browser traffic, network requests from other open tabs, or operating system proxy settings.
- Four crawler profiles:
  * Googlebot Smartphone (Android 6.0.1 Mobile Nexus 5X)
  * Googlebot Desktop
  * Bingbot
  * GPTBot (OpenAI Web Scraper)
- Cloaking and paywall diagnosis: reloads the active tab under the selected bot persona to reveal dynamic server-side rendering discrepancies, paywall gating differences, and crawler-specific resource blocking.

### 5. High-Throughput Linear Primitives

To guarantee zero latency impact on the monitored host application, VitalsSniper uses custom linear memory and concurrency primitives:

- ArrayPool: high-performance array borrower that eliminates garbage collection churn during rapid DOM iterations. Methods that mutate length (`push`, `pop`, `shift`, `unshift`, `splice`) are intentionally poisoned on borrowed instances. Buffer reclamation occurs via monotonic `performance.now()` expiration timers.
- AsyncLock: read/write synchronization primitive providing concurrent shared-read access and exclusive write isolation. Includes backpressure queue shedding to prevent race conditions during rapid state transitions in `chrome.storage.local`.

### 6. Technology Detection Directed Acyclic Graph (DAG)

Identifies 60+ frontend frameworks, content management systems, page builders, CDN providers, and analytics platforms via client-side signatures:

- Multi-signal detection: evaluates JavaScript global variables, meta tags, HTML script attributes, DOM markers, and HTTP response headers.
- Dependency resolution: DAG graph evaluates `implies` rules (e.g., WooCommerce implies WordPress; Next.js implies React) and `excludes` rules (e.g., Shopify storefront excludes WooCommerce false positives).
- SemVer extraction: parses precise software versions from script query strings and manifest objects to identify outdated or insecure dependencies.

### 7. Financial Latency Impact & Conversion Loss Calculator

Connects technical performance degradation to business revenue impact:

- Mathematical decay modeling: applies empirical conversion decay coefficients from published Google and Deloitte multi-vertical studies.
- Revenue loss calculation: models monthly and annual gross merchandise value (GMV) or lead conversion loss when LCP exceeds 2.5 seconds or INP exceeds 200 milliseconds.
- Localized calculations: accepts custom monthly traffic, average order value (AOV), and conversion rate baselines to calculate actionable ROI metrics.

---

---

## Companion CLI: Headless Terminal Auditing

For automated regression testing and terminal-driven workflows, VitalsSniper provides the zero-dependency `webaudits` CLI package.

### Instant Execution (No Global Installation Required)

```bash
# Run instant forensic audit on any URL
npx webaudits https://example.com

# Output raw JSON for scripting or CI assertions
npx webaudits https://example.com --json

# Display full HTTP response headers and security diagnostics
npx webaudits https://example.com --full
```

### Global Installation

```bash
npm install -g webaudits
webaudits https://example.com
```

### Sample Terminal Output Preview

```
--------------------------------------------------------------------------------
 WebAudits CLI : Forensic Performance & Schema Audit
 Target: https://example.com/
--------------------------------------------------------------------------------

  Overall Health:   A   92/100  (HTTP 200)

  CORE TELEMETRY METRICS:
  - Server TTFB:        184 ms (Google budget: 800ms)
  - Edge Network:       Cloudflare Anycast
  - Compression:        br (14.2 KB transfer)
  - Schema.org Graphs:  2 entities (WebSite, Organization)
  - AI Discovery:       Active (/llms.txt verified)
  - Transport Security: HSTS Active (max-age=31536000)

  DOM & THREAD DIAGNOSTICS:
  - DOM Elements:       312 nodes (depth: 7 levels)
  - Head Scripts:       2 render-blocking candidates
  - LoAF Support:       Supported (Chromium 123+)

  AUDIT FINDINGS:
  [PASS] Fast Server TTFB: 184ms
  [PASS] Modern Compression: Encoded with br
  [PASS] Single H1 Element Present
  [PASS] Knowledge Graph Schema Detected
  [PASS] /llms.txt Discovery Endpoint Responding
--------------------------------------------------------------------------------
```

### Continuous Integration (GitHub Actions)

Add automated performance checks to your pull request workflow:

```yaml
name: Performance Guardrail
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - name: Run WebAudits Performance Gate
        run: |
          RESULT=$(npx webaudits https://staging.example.com --json)
          echo "$RESULT" | jq .
          TTFB=$(echo "$RESULT" | jq .metrics.ttfb)
          if [ "$TTFB" -gt 600 ]; then
            echo "TTFB exceeded 600ms budget: ${TTFB}ms"
            exit 1
          fi
```

## Installation & Local Development

VitalsSniper runs natively in any Chromium-based browser (Google Chrome, Brave, Microsoft Edge, Arc, Opera) as an unpacked Manifest V3 extension.

### Prerequisites

- Chromium browser version 123 or higher (required for Long Animation Frames API support).
- Node.js 18.0.0 or higher (for compiling TypeScript source files).

### Running Unpacked from Source

1. Clone the repository:
   ```bash
   git clone https://github.com/xcalibur73/vitalssniper.git
   cd vitalssniper
   ```

2. Compile the TypeScript source code and build the bundle:
   ```bash
   node build.mjs
   ```
   This compiles all TypeScript files in `src/`, verifies the linear primitive and LoAF profiling test batteries, and generates the consolidated `popup.js` bundle (470KB unminified, 130.8KB packaged zip).

3. Open the Extensions management page in your browser:
   - Google Chrome: navigate to `chrome://extensions`
   - Brave: navigate to `brave://extensions`
   - Microsoft Edge: navigate to `edge://extensions`

4. Enable Developer Mode by toggling the switch in the top-right corner.

5. Click the "Load unpacked" button in the top-left toolbar.

6. Select the `vitalssniper` root directory containing `manifest.json`.

7. Pin VitalsSniper to your browser toolbar for quick access, or use the global keyboard shortcut:
   - Windows/Linux: `Ctrl+Shift+A`
   - macOS: `Command+Shift+A`

---

## Automated Test Battery

The project maintains deterministic, zero-dependency test suites verifying core algorithms and invariants:

```bash
# Execute linear memory primitive tests (ArrayPool and AsyncLock)
node tests/test_linear_primitives.mjs

# Execute LoAF attribution, 8ms VSYNC budget, and 3-phase INP profiling tests
node tests/test_loaf_and_inp_profiling.mjs

# Execute technology detector DAG and SemVer resolution tests
node tests/test_tech_detector_dag.mjs

# Execute DeclarativeNetRequest crawler emulation and manifest tests
node tests/test_bot_emulation_dnr.mjs

# Execute full attribution and edge-case test suite
node tests/test_audit_and_attribution_edge_cases.mjs
```

All test scripts execute in Node.js standard runtime and return exit code 0 upon validation.

---

## Permissions & Manifest V3 Compliance

VitalsSniper adheres strictly to the Chrome Web Store Principle of Least Privilege:

- `activeTab`: accesses the active webpage DOM and performance timing buffers exclusively upon explicit user invocation (clicking the toolbar action or pressing `Ctrl+Shift+A`). Never runs in background tabs.
- `tabs`: reads active tab URL, title, and favicon for the audit header, and detects navigation events during active inspection.
- `scripting`: injects non-destructive read-only telemetry scripts into the active page context to measure DOM node hierarchy, script elements, and performance entries.
- `storage`: persists local audit logs, user preferences, and CRM status flags in `chrome.storage.local`.
- `declarativeNetRequest`: modifies outbound request headers during search bot simulation via tab-scoped session rules.
- `<all_urls>` host permission: allows auditing arbitrary client websites and competitor URLs selected by the user.

Privacy Guarantee: VitalsSniper runs entirely inside your local browser sandbox. It contains zero third-party tracking scripts, collects zero personal information (PII), and does not transmit inspected page data to remote servers.

---

## Official Links & Attribution

- Chrome Web Store Extension: [VitalsSniper on Chrome Web Store](https://chromewebstore.google.com/detail/vitalssniper-proof-of-fl/)
- Companion Web Platform: [WebAudits Pro](https://webaudits.pro)
- Free DOM Bloat Checker: [WebAudits Pro DOM Checker](https://webaudits.pro/tools/dom-bloat-checker)
- Mobile LCP Element Finder: [WebAudits Pro LCP Finder](https://webaudits.pro/tools/lcp-checker)
- 500 Enterprise SaaS Performance Benchmark: [Web Performance Industry Study](https://webaudits.pro/articles/500-ecommerce-saas-web-performance-benchmark-2026)

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
