# VitalsSniper: Chrome Web Store Listing & Distribution Package

## Store Listing Metadata

- Name: VitalsSniper: Proof-of-Flaw Web Inspector
- Short Description (132 char limit): Core Web Vitals INP inspector, Googlebot crawler emulator, DOM bloat scanner, and client audit pitch deck generator.
- Version: 1.6.5
- Category: Developer Tools
- Primary Language: English
- Pricing: Free (with optional cloud sync and PRO account via WebAudits.pro)
- Support URL: https://webaudits.pro/about
- Privacy Policy URL: https://webaudits.pro/privacy
- Website: https://webaudits.pro

---

## Single-Purpose Explanation

VitalsSniper has a single, focused purpose: to inspect the active browser tab for technical performance bottlenecks, DOM bloat, and CMS signatures, with optional client audit teardown exports.

---

## Detailed Store Description

VitalsSniper is an in-browser Core Web Vitals INP inspector, Googlebot crawler emulator, DOM bloat scanner, and client audit pitch deck engine for web developers, technical SEO consultants, and digital agency teams seeking faster, queue-free Lighthouse alternatives.

Most site audit tools rely on third-party server queues, taking minutes to crawl or returning simulated metrics that fail to reflect live client-side DOM reality. As one of the premier browser-based Lighthouse alternatives, VitalsSniper inspects the live DOM of the active tab directly in your local browser engine without server queue delays.

### What is New in Version 1.6.5

- Google web-vitals v4 Deep INP Attribution: Detailed breakdown of Input Delay, Processing Duration, and Presentation Delay with target element selectors.
- Long Animation Frame (LoAF) Correlation: Measures overlapping frame counts and isolates main-thread blocking scripts.
- Page Load State: Classifies interaction timing across loading, dom-interactive, dom-content-loaded, and complete.
- Telemetry Stability: Hardened internal error boundaries and DevTools logging.

### What is New in Version 1.6.4

- Hardened Build & ArrayPool Determinism: Switched ArrayPool expiry timestamps to monotonic performance.now() timing and locked bundler execution to argument-array execFileSync invocations.
- Storage & Telemetry Diagnostics: Added explicit background quota and local storage read failure logging across storageService and MV3 service worker handlers.
- UI & CWS Compliance Sync: Aligned popup footer version indicator (v1.6.4 PRO) and synchronized WebAudits.pro product metadata and permission disclosures.

### What is New in Version 1.6.3

- Direct Post-Install Onboarding: Automatic product tour tab opening upon initial installation, guiding users through core in-tab audit workflows and keyboard shortcuts (Ctrl+Shift+A). Strictly isolated to fresh installs so existing users are never interrupted during background updates.
- Streamlined Host Permissions: Consolidated extension host permissions strictly to `<all_urls>` with formal single-purpose disclosure, removing redundant subdomains while maintaining declarativeNetRequest search bot header emulation across client websites.
- Direct Platform Navigation: Direct integration with WebAudits.pro canonical product workflows, eliminating redirect latency and establishing end-to-end attribution tracking.

### What is New in Version 1.6.2

- Security Hardening and Licensing Verification: Hardened license validation routines, fail-closed cryptographic Ed25519 payload authentication, and cloud synchronization resilience.
- Browser Storage Error Resilience: Enhanced local quota management ensuring high-volume audit sessions recover smoothly without data loss.
- Interaction to Next Paint (INP) Telemetry Polish: Enhanced 3-phase latency subpart attribution (Input Delay, Processing Duration, and Presentation Delay) with detailed Long Animation Frame (LoAF) script culprit identification.
- Modernized 4-Tab Navigation: Refined 440px wide workspace layout with dedicated Overview, Forensics, On-Page SEO Tree, and Client Pitch decks.

### What is New in Version 1.6.1

- Full-Stack Technology Detection Engine: Real-time runtime detection across 60+ CMS platforms, visual site builders, analytics pixels, and frontend application frameworks.
- Financial Revenue Leakage and Conversion ROI Calculator: Computes estimated monthly and annual revenue loss based on Google and Deloitte latency decay curves when Core Web Vitals exceed thresholds.
- HTTP Header and Edge Cache Forensics: Parses x-robots-tag indexing directives, canonical URL parity, CDN edge cache status, and redirect hops.
- Long Animation Frames (LoAF) Script Attribution: Tracks main-thread blocking scripts with exact duration, invoker type, and source URL to diagnose Interaction to Next Paint (INP) issues.
- Layout Shift Live Tracking: Identifies cumulative layout shifts and flags shifting DOM elements with visual coordinates.
- On-Page SEO Heading Hierarchy: Complete H1-H6 outline inspection with automated alerts for missing primary H1 tags, duplicates, and skipped-level hierarchy breaks.
- Link Graph Forensics: Classifies internal vs external links, audits nofollow, sponsored, and UGC tags, and warns on empty anchor elements.
- Search Bot Header Emulation: Simulates Googlebot, Bingbot, and GPTBot session headers to audit mobile-first cloaking and paywall gating.

### Core Audit Capabilities

1. Core Web Vitals INP Inspector & LoAF Profiler
Measures 3-phase latency subparts (Input Delay, Processing Duration, Presentation Delay) and correlates main-thread blocking scripts with Long Animation Frames (LoAF) to diagnose interaction responsiveness.

2. CMS and Page Builder Detection
Instantly detects active content management systems, visual site builders, and frontend application frameworks from live runtime signatures and script fingerprints.

3. DOM Bloat Scanner and Tree Depth Analysis
Measures total DOM node count, maximum nesting depth, and flags deep branches exceeding 15 levels that degrade browser layout passes and interaction response times.

4. Googlebot Crawler Emulator & Search Bot Testing
Simulates Googlebot Smartphone, Googlebot Desktop, Bingbot, and GPTBot session headers to audit mobile cloaking, crawler-specific payloads, and bot rendering disparity.

5. Fast, Local Lighthouse Alternatives Engine
Provides instant in-tab metric triangulation without remote queuing or synthetic throttling distortion.

6. Document Payload and Transfer Weights
Measures in-memory HTML size, wire transfer weight, and asset distribution to pinpoint oversized payloads that slow mobile first contentful paint.

7. Script Contention & Long Animation Frames (LoAF)
Attributes main-thread interaction delays to specific script URLs, execution durations, and invokers to isolate Interaction to Next Paint (INP) bottlenecks.

8. Layout Shift and Visual Stability Diagnostics
Monitors cumulative layout shifts with live element coordinates to detect shifting layout elements and reflow triggers.

9. Heading Hierarchy and On-Page SEO Structure
Maps complete H1-H6 heading outlines in DOM sequence, identifying missing primary H1 tags, duplicate H1s, and skipped-level hierarchy breaks.

10. Link Graph and Anchor Quality Audit
Inventories internal versus external link ratios, inspects nofollow, sponsored, and UGC attributes, and flags empty anchor tags without accessible text.

11. Viewport and Accessibility Checks
Evaluates viewport meta configuration to identify user-scalable restrictions that impair pinch-to-zoom accessibility under WCAG 2.2 Criterion 1.4.4.

12. Schema.org JSON-LD Verification
Parses and checks structured data blocks for syntax validity, entity graph connections, and missing required properties.

13. Third-Party Script Contention
Inventories external, inline, and asynchronous scripts competing for main-thread execution time.

14. Evidence-Grounded Outreach Teardowns
Generates structured diagnostic teardowns (email copy, LinkedIn DM, and video teardown outlines) directly from observed technical flaws, citing measured values instead of vague generalizations.

15. Client Audit Pitch Deck & 1-Page Teardowns
Saves reviewed prospect sites locally and generates client audit pitch deck briefs with financial ROI calculations, revenue leakage estimates, and RFC 4180 CSV exports.
Saves reviewed prospect sites locally and exports client-ready 1-page PDF teardown briefs or RFC 4180 CSV logs.

### Companion Web Diagnostic Tools

- Free DOM Bloat Checker: https://webaudits.pro/tools/dom-bloat-checker
- Mobile LCP Element Finder: https://webaudits.pro/tools/lcp-checker
- Core Web Vitals Benchmark: https://webaudits.pro/articles/500-ecommerce-saas-web-performance-benchmark-2026

### Technical Architecture and Privacy

VitalsSniper runs client-side inside your browser sandbox. Your browsing history, visited URLs, and client audit data are never sold and never sent to external tracking servers. Optional account authentication occurs only if connecting to your WebAudits.pro workspace.

---

## Permission Justifications

Each requested permission adheres to the Chrome Web Store Principle of Least Privilege:

- activeTab:
Required to access the DOM and runtime performance metrics of the currently active website when the user clicks the extension action icon. Does not run on background or inactive tabs.

- tabs:
Required to query the active tab URL, title, and favicon for the inspector header display, and to detect tab navigation events during an active audit session.

- scripting:
Required to inject lightweight, non-destructive audit routines into the active tab context to read DOM node counts, tree depth, and script tags.

- storage:
Required to save user preferences, local audit history, CRM prospect status records, and API key settings in local browser storage (`chrome.storage.local`).

- declarativeNetRequest:
Required to enable tab-isolated search crawler simulation (Googlebot Smartphone, Googlebot Desktop, Bingbot, and GPTBot) via session-scoped request header modification rules (`declarativeNetRequest.updateSessionRules`). This allows auditors to detect mobile cloaking, paywall gating, and crawler rendering on the active tab without altering global browser network traffic.

- host_permissions:
  - `<all_urls>`: Required to allow the user to audit any arbitrary website they choose to inspect via activeTab invocation and compare against competitor URLs.
  - `https://vitalssniper-web.vercel.app/*` and `https://webaudits.pro/*`: Required for cloud report synchronization and validating WebAudits.pro API keys.
  - `https://www.googleapis.com/*`: Required for optional direct querying of the official Google PageSpeed Insights (PSI) and Chrome User Experience (CrUX) APIs when external lab data is requested.

---

## Privacy Policy and Data Handling Declarations

- User Data Collection:
VitalsSniper PRO does NOT collect, store, or sell personally identifiable information (PII), browsing history, or user keystrokes.

- Target Website Data:
All DOM analysis occurs in memory within the local browser process. URLs and technical metrics inspected are stored solely on the user device in `chrome.storage.local`.

- Remote Code Policy:
The extension contains zero remotely hosted executable code. All audit scripts, styling, and dependencies are bundled within the extension package in compliance with Manifest V3 policy.

- Privacy Policy:
The complete privacy policy is hosted at https://webaudits.pro/privacy.

---

## Manifest V3 Validation Summary

- Manifest Version: 3
- Action API: popup (`popup.html`) with 16x16, 48x48, and 128x128 PNG icons.
- Background: Service worker (`background.js`).
- Content Security Policy: Strict MV3 default; no `unsafe-eval` or external script execution.
- Keyboard Shortcut: `Ctrl+Shift+A` (Mac: `Command+Shift+A`) configured under `_execute_action`.
- Firefox Compatibility: Gecko ID `vitalssniper@nbsolutions.com` declared with strict minimum version 109.0.
