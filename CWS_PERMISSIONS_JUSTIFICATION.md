# Chrome Web Store Permissions Justification

This document provides single-purpose permission justifications for the Chrome Web Store Developer Console for VitalsSniper v1.6.3.

## Permission: <all_urls>

### Single Purpose Declaration
Required for chrome.declarativeNetRequest session rules to modify request headers when the user activates bot emulation (Googlebot-Smartphone, Googlebot-Desktop, Bingbot, GPTBot) on arbitrary audit targets.

### Technical Context
When an auditor tests mobile cloaking, paywall gating, or bot-specific responses across arbitrary target domains, session-scoped rules rewrite User-Agent and client request headers. The permission is scoped strictly to header rule application without reading, intercepting, or storing traffic.

## Permission: activeTab

### Single Purpose Declaration
Required for on-demand performance telemetry and element highlighting via chrome.scripting.executeScript when the user opens the extension action popup.

### Technical Context
The extension inspects live client-side DOM metrics (Core Web Vitals, layout shifts, DOM depth, and heading hierarchy) only on the user-selected active tab upon user interaction.

## Permission: declarativeNetRequest

### Single Purpose Declaration
Required for dynamic bot request header rewriting without intercepting or capturing network payloads.

### Technical Context
Allows programmatic registration and clearing of session-scoped request header modifications via chrome.declarativeNetRequest.updateSessionRules, eliminating the need for broader webRequest permissions or payload inspection.
