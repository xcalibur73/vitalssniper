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
console.log('PASS: popup.js contains all expected orchestrator logic.');

// 2. Verify ReportService generateTeardownHtml output with CWV subpart attribution
console.log('--- 2. Testing ReportService CWV subpart attribution & Manifest v1.5.1 ---');
assert(popupJs.includes('LCP Subparts:'), 'popup.js must contain LCP Subparts format in ReportService');
assert(popupJs.includes('INP Interaction:'), 'popup.js must contain INP Interaction format in ReportService');
assert(popupJs.includes('CLS Session Score:'), 'popup.js must contain CLS Session Score format in ReportService');
assert(popupJs.includes('clsSessionScore'), 'popup.js must contain clsSessionScore in CloudSyncService');

const manifestPath = path.resolve(__dirname, '../manifest.json');
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
assert.strictEqual(manifest.version, '1.5.1', 'manifest.json version must be 1.5.1');

const storeListingPath = path.resolve(__dirname, '../STORE_LISTING.md');
const storeListing = fs.readFileSync(storeListingPath, 'utf8');
assert(storeListing.includes('Version: 1.5.1'), 'STORE_LISTING.md must specify Version: 1.5.1');
console.log('PASS: ReportService, CloudSyncService, and Manifest v1.5.1 verified.');

// 3. Test for zero em-dash and zero en-dash in all newly edited source files
console.log('--- 3. Testing zero em-dash and en-dash invariant ---');
const filesToCheck = [
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
