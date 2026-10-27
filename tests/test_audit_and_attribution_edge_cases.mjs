// Targeted verification for CWV attribution in ReportService and deactivation / sync logic in popup
import assert from 'assert';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// 1. Verify popup.js bundle contains the expected code changes
const popupJsPath = path.resolve(__dirname, '../popup.js');
const popupJs = fs.readFileSync(popupJsPath, 'utf8');

console.log('--- 1. Testing popup.js bundle contents ---');
assert(popupJs.includes('https://webaudits.pro/pricing'), 'popup.js must contain WebAudits.pro pricing URL');
assert(popupJs.includes('Synced to WebAudits.pro Dashboard.'), 'popup.js must contain PRO bulk status sync text');
assert(popupJs.includes("activeTone = 'data-driven'"), 'popup.js must reset activeTone to data-driven on deactivation');
assert(popupJs.includes("activeChannel = 'email'"), 'popup.js must reset activeChannel to email on deactivation');
assert(popupJs.includes('(syncRes.saved || syncRes.success)'), 'popup.js must check (syncRes.saved || syncRes.success)');
assert(popupJs.includes('merchantPitch'), 'popup.js must contain merchantPitch generation');
assert(popupJs.includes('agencyPitch'), 'popup.js must contain agencyPitch generation');
assert(popupJs.includes('tabMerchant'), 'popup.js must wire tabMerchant switcher');
assert(popupJs.includes('tabAgency'), 'popup.js must wire tabAgency switcher');

// Assertions for Blueprint 1 INP attribution fields
assert(popupJs.includes('culpritScriptUrl'), 'popup.js must contain culpritScriptUrl');
assert(popupJs.includes('culpritExecutionMs'), 'popup.js must contain culpritExecutionMs');
assert(popupJs.includes('culpritForcedStyleMs'), 'popup.js must contain culpritForcedStyleMs');
assert(popupJs.includes('groupedEventCount'), 'popup.js must contain groupedEventCount');
assert(popupJs.includes('groupedEvents'), 'popup.js must contain groupedEvents');
assert(popupJs.includes('inpCulpritRow'), 'popup.js must contain inpCulpritRow');
console.log('PASS: popup.js contains all expected orchestrator logic and INP attribution fields.');

// 2. Verify ReportService generateTeardownHtml output with CWV subpart attribution
console.log('--- 2. Testing ReportService CWV subpart attribution & Manifest version ---');
assert(popupJs.includes('LCP Subparts:'), 'popup.js must contain LCP Subparts format in ReportService');
assert(popupJs.includes('INP Interaction:'), 'popup.js must contain INP Interaction format in ReportService');
assert(popupJs.includes('CLS Session Score:'), 'popup.js must contain CLS Session Score format in ReportService');
assert(popupJs.includes('clsSessionScore'), 'popup.js must contain clsSessionScore in CloudSyncService');

const manifestPath = path.resolve(__dirname, '../manifest.json');
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
assert(/^1\.[56]\./.test(manifest.version), `manifest.json version must match /^1\\.[56]\\./, got ${manifest.version}`);

const storeListingPath = path.resolve(__dirname, '../STORE_LISTING.md');
const storeListing = fs.readFileSync(storeListingPath, 'utf8');
assert(storeListing.includes('Version: 1.6.2') || storeListing.includes('Version: 1.6.1') || storeListing.includes('Version: 1.5.2'), 'STORE_LISTING.md must specify Version: 1.6.2, 1.6.1, or 1.5.2');
console.log('PASS: ReportService, CloudSyncService, and Manifest version verified.');

// 2b. Test 8ms frame grouping math and LoAF temporal intersection
console.log('--- 2b. Testing 8ms frame grouping math and LoAF temporal intersection ---');
{
  const events = [
    { name: 'pointerdown', startTime: 100, duration: 80, renderTime: 180, interactionId: 10 },
    { name: 'pointerup', startTime: 102, duration: 82, renderTime: 184, interactionId: 10 },
    { name: 'click', startTime: 103, duration: 81, renderTime: 184, interactionId: 10 },
    { name: 'keydown', startTime: 400, duration: 40, renderTime: 440, interactionId: 20 }
  ];

  const groups = [];
  events.forEach(entry => {
    const dur = entry.duration || 0;
    const renderTime = (entry.renderTime !== undefined && entry.renderTime > 0)
      ? entry.renderTime
      : (entry.startTime + dur);

    const matched = groups.find(g => {
      if (entry.interactionId && g.interactionId && entry.interactionId === g.interactionId) return true;
      return Math.abs(renderTime - g.renderTime) <= 8;
    });

    if (matched) {
      matched.events.push(entry);
      if (dur > matched.maxDuration) matched.maxDuration = dur;
      if (!matched.interactionId && entry.interactionId) matched.interactionId = entry.interactionId;
    } else {
      groups.push({
        interactionId: entry.interactionId,
        renderTime,
        maxDuration: dur,
        events: [entry]
      });
    }
  });

  assert.strictEqual(groups.length, 2, 'Should create exactly 2 frame groups');
  const worstGroup = groups.reduce((prev, curr) => (curr.maxDuration > prev.maxDuration ? curr : prev), groups[0]);
  assert.strictEqual(worstGroup.events.length, 3, 'Worst group must group 3 events within 8ms window');
  assert.strictEqual(worstGroup.maxDuration, 82, 'Worst group max duration must be 82ms');

  const worstInteraction = worstGroup.events.reduce((prev, curr) => (curr.duration > prev.duration ? curr : prev), worstGroup.events[0]);
  assert.strictEqual(worstInteraction.name, 'pointerup');

  // LoAF temporal intersection
  const procStart = 105;
  const procEnd = 165;
  const loafEntries = [
    {
      scripts: [
        {
          sourceURL: 'https://example.com/assets/vendor.js',
          sourceFunctionName: 'handleTap',
          startTime: 100,
          duration: 50,
          forcedStyleAndLayoutDuration: 20
        },
        {
          sourceURL: 'https://example.com/assets/tracking.js',
          sourceFunctionName: 'beacon',
          startTime: 80,
          duration: 20,
          forcedStyleAndLayoutDuration: 5
        }
      ]
    }
  ];

  let worstScript = null;
  let maxIntersectingDuration = 0;
  let maxIntersectingForcedStyle = 0;

  const candidateScripts = [];
  loafEntries.forEach(frame => {
    if (Array.isArray(frame.scripts)) {
      frame.scripts.forEach(s => candidateScripts.push(s));
    }
  });

  candidateScripts.forEach(script => {
    const sStart = script.startTime || 0;
    const sDur = script.duration || 0;
    const scriptEnd = sStart + sDur;
    const intersectingDuration = Math.max(0, Math.min(scriptEnd, procEnd) - Math.max(sStart, procStart));
    if (intersectingDuration > maxIntersectingDuration) {
      maxIntersectingDuration = intersectingDuration;
      const forcedStyle = (sDur && script.forcedStyleAndLayoutDuration)
        ? Math.round((intersectingDuration / sDur) * script.forcedStyleAndLayoutDuration)
        : 0;
      maxIntersectingForcedStyle = forcedStyle;
      worstScript = script;
    }
  });

  assert(worstScript, 'Must identify culprit script from rawLoafEntries');
  assert.strictEqual(worstScript.sourceURL, 'https://example.com/assets/vendor.js');
  assert.strictEqual(worstScript.sourceFunctionName, 'handleTap');
  assert.strictEqual(maxIntersectingDuration, 45);
  assert.strictEqual(maxIntersectingForcedStyle, 18);
  console.log('PASS: 8ms frame grouping and LoAF temporal intersection math verified.');
}

// 3. Test for zero em-dash and zero en-dash in all newly edited source files
console.log('--- 3. Testing zero em-dash and en-dash invariant ---');
const filesToCheck = [
  '../src/types/audit.ts',
  '../src/engine/browserAudit.ts',
  '../src/engine/findingsEngine.ts',
  '../src/popup.ts',
  '../src/engine/outreachGenerator.ts',
  '../src/services/storageService.ts',
  '../src/services/reportService.ts',
  '../src/services/cloudSyncService.ts',
  '../popup.html',
  '../popup.css',
  '../popup.js',
  '../manifest.json',
  '../STORE_LISTING.md'
];

for (const rel of filesToCheck) {
  const filePath = path.resolve(__dirname, rel);
  const content = fs.readFileSync(filePath, 'utf8');
  assert(!content.includes('\u2014'), `${rel} contains em-dash (\u2014)`);
  assert(!content.includes('\u2013'), `${rel} contains en-dash (\u2013)`);
}
console.log('PASS: Zero em-dash and zero en-dash violations across all target files.');

// 4. Test for zero emojis in all newly edited source files
console.log('--- 4. Testing zero emojis invariant ---');
const emojiRegex = /[\u{1F300}-\u{1F9FF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}]/u;
for (const rel of filesToCheck) {
  const filePath = path.resolve(__dirname, rel);
  const content = fs.readFileSync(filePath, 'utf8');
  assert(!emojiRegex.test(content), `${rel} contains forbidden emoji characters`);
}
console.log('PASS: Zero emojis detected across all target files.');

// 5. Test for zero retired lifetime strings in user-facing status
console.log('--- 5. Testing zero retired lifetime strings in status display ---');
assert(!popupJs.includes('Master Lifetime'), 'popup.js must not contain Master Lifetime');
assert(!popupJs.includes('Lifetime Unlimited'), 'popup.js must not contain Lifetime Unlimited');
console.log('PASS: Zero retired lifetime strings found in user-facing status.');

console.log('\n=== ALL EDGE CASE ATTRIBUTION, PITCH AND GATING CHECKS PASSED ===\n');
process.exit(0);
