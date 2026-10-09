# VitalsSniper: Chrome Web Store Listing & Distribution Package

## Store Listing Metadata

- Name: VitalsSniper: Proof-of-Flaw Web Inspector
- Short Description (132 char limit): 1-Click CMS & Builder detector, DOM bloat scanner, Core Web Vitals audit, and client outreach email generator.
- Version: 1.5.2
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

VitalsSniper is an in-browser technical website auditor and proof-of-flaw inspector for web developers, technical SEO consultants, and digital agency teams.

Most site audit tools rely on third-party server queues, taking minutes to crawl or returning simulated metrics that fail to reflect live client-side DOM reality. VitalsSniper inspects the live DOM of the active tab directly in your local browser engine without server queue delays.

### Core Audit Capabilities

1. CMS and Page Builder Detection
Instantly detects active content management systems, visual site builders, and frontend application frameworks from live runtime signatures and script fingerprints.

2. DOM Bloat and Tree Depth Analysis
Measures total DOM node count, maximum nesting depth, and flags deep branches exceeding 15 levels that degrade browser layout passes and interaction response times.

3. Document Payload and Transfer Weights
Measures in-memory HTML size, wire transfer weight, and asset distribution to pinpoint oversized payloads that slow mobile first contentful paint.

4. Viewport and Accessibility Checks
Evaluates viewport meta configuration to identify user-scalable restrictions that impair pinch-to-zoom accessibility under WCAG 2.2 Criterion 1.4.4.

5. Schema.org JSON-LD Verification
Parses and checks structured data blocks for syntax validity, entity graph connections, and missing required properties.

6. Third-Party Script Contention
Inventories external, inline, and asynchronous scripts competing for main-thread execution time.

7. Evidence-Grounded Outreach Teardowns
Generates structured diagnostic teardowns (email copy, LinkedIn DM, and video teardown outlines) directly from observed technical flaws, citing measured values instead of vague generalizations.

8. Teardown Briefs and CRM Exports
Saves reviewed prospect sites locally and exports client-ready 1-page PDF teardown briefs or RFC 4180 CSV logs.

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
