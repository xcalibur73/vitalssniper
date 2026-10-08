# VitalsSniper PRO

In-Browser Website Performance & Technical Architecture Inspector

VitalsSniper PRO is a Manifest V3 browser extension built for web performance specialists, technical consultants, and digital agencies. It evaluates live web pages in the active browser tab, measuring DOM complexity, payload transfer weights, viewport configuration, and structured data validity without third-party API dependencies.

---

## Technical Auditing Engine

The extension inspects the active browser DOM in under 50ms, evaluating key architectural signals:
- CMS and page builder signatures: detects common content management systems, visual site builders, and frontend frameworks.
- DOM hierarchy and nesting depth: measures total node count, maximum tree recursion depth, and branches exceeding 15 levels.
- Document payload footprint: measures serialized in-memory markup and network wire transfer sizes.
- Viewport scaling directives: flags missing viewport tags or user-scalable restrictions that impair mobile accessibility.
- Structured data validation: parses Schema.org JSON-LD blocks, verifying entity types, nesting integrity, and Knowledge Graph connections.
- Third-party script contention: inventories external, inline, and asynchronous script tags affecting main-thread availability.
- Canonical TTFB measurement: measures navigation start to response start latency with cache status detection.

---

## Prospecting and Reporting Workflow

1. Active tab inspection: run audits directly from the browser toolbar without sending URLs to external processing queues.
2. Evidence-grounded outreach copy: generates structured outreach drafts (email, LinkedIn message, video script outline) citing observed metrics rather than generic claims.
3. Client CRM: track prospects across stages (New, Contacted, Replied, Won) with local browser persistence and RFC 4180 CSV export.
4. One-page teardown dossier: exports print-ready PDF and HTML audit briefs using professional design tokens.

---

## Installation

1. Download or clone the extension package.
2. Open the extensions manager in any Chromium-based browser:
   - Chrome: `chrome://extensions/`
   - Brave: `brave://extensions/`
   - Edge: `edge://extensions/`
3. Enable Developer Mode.
4. Click "Load unpacked" and select the `vitalssniper_extension` directory.
5. Pin the extension to your toolbar.

---

## Compatibility

- Browsers: Google Chrome, Brave, Microsoft Edge, Arc, and other Chromium-based browsers.
- Manifest Version: V3.
- License: Commercial License.
