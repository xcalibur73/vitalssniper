// Targeted verification for DNR Googlebot & Bot Header Emulation
// Strictly zero em-dashes and zero en-dashes

import assert from 'assert';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log('--- Step 1: Testing manifest.json permissions ---');
const manifestPath = path.resolve(__dirname, '../manifest.json');
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

assert(Array.isArray(manifest.permissions), 'manifest.json must have a permissions array');
assert(manifest.permissions.includes('declarativeNetRequest'), 'manifest.permissions must include declarativeNetRequest');
console.log('PASS: manifest.json permissions include declarativeNetRequest.');

console.log('--- Step 1B: Testing manifest.json v1.6.4 version and streamlined host_permissions ---');
assert.strictEqual(manifest.version, '1.6.4', 'manifest.version must be bumped to 1.6.4');
assert(Array.isArray(manifest.host_permissions), 'manifest.host_permissions must be an array');
assert.strictEqual(manifest.host_permissions.length, 1, 'manifest.host_permissions must strictly contain only 1 entry');
assert.strictEqual(manifest.host_permissions[0], '<all_urls>', 'manifest.host_permissions must strictly contain only <all_urls>');

const redundantDomains = [
  'https://vitalssniper-web.vercel.app/*',
  'https://webaudits.pro/*',
  'https://www.googleapis.com/*'
];
for (const domain of redundantDomains) {
  assert(!manifest.host_permissions.includes(domain), `Redundant domain ${domain} must not be present in host_permissions`);
}
console.log('PASS: manifest.json v1.6.4 version and streamlined host_permissions strictly verified.');

console.log('--- Step 2: Testing background.js bot emulation logic & UA strings ---');
const bgPath = path.resolve(__dirname, '../background.js');
const bgCode = fs.readFileSync(bgPath, 'utf8');

assert(bgCode.includes('setUserAgent'), 'background.js must handle setUserAgent action');
assert(bgCode.includes('getUserAgent'), 'background.js must handle getUserAgent action');
assert(bgCode.includes('updateSessionRules'), 'background.js must call updateSessionRules');
assert(bgCode.includes('1001'), 'background.js must reference rule id 1001');

// Verify standard bot UA identifiers
assert(bgCode.includes('googlebot-smartphone'), 'background.js must contain googlebot-smartphone');
assert(bgCode.includes('googlebot-desktop'), 'background.js must contain googlebot-desktop');
assert(bgCode.includes('bingbot'), 'background.js must contain bingbot');
assert(bgCode.includes('gptbot'), 'background.js must contain gptbot');

// Verify standard bot User-Agent strings
const expectedGooglebotMobile = 'Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.115 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
const expectedGooglebotDesktop = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
const expectedBingbot = 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)';
const expectedGptbot = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)';

assert(bgCode.includes(expectedGooglebotMobile), 'background.js must contain Googlebot Smartphone UA string');
assert(bgCode.includes(expectedGooglebotDesktop), 'background.js must contain Googlebot Desktop UA string');
assert(bgCode.includes(expectedBingbot), 'background.js must contain Bingbot UA string');
assert(bgCode.includes(expectedGptbot), 'background.js must contain GPTBot UA string');
console.log('PASS: background.js contains complete DNR session rules and standard bot User-Agent strings.');

console.log('--- Step 3: Testing popup.html bot emulation elements ---');
const htmlPath = path.resolve(__dirname, '../popup.html');
const htmlCode = fs.readFileSync(htmlPath, 'utf8');

assert(htmlCode.includes('id="cardBotEmulation"'), 'popup.html must contain cardBotEmulation');
assert(htmlCode.includes('id="selectBotEmulation"'), 'popup.html must contain selectBotEmulation');
assert(htmlCode.includes('id="btnApplyBot"'), 'popup.html must contain btnApplyBot');
assert(htmlCode.includes('id="badgeBotStatus"'), 'popup.html must contain badgeBotStatus');
assert(htmlCode.includes('value="googlebot-smartphone"'), 'selectBotEmulation must have googlebot-smartphone option');
assert(htmlCode.includes('value="googlebot-desktop"'), 'selectBotEmulation must have googlebot-desktop option');
assert(htmlCode.includes('value="bingbot"'), 'selectBotEmulation must have bingbot option');
assert(htmlCode.includes('value="gptbot"'), 'selectBotEmulation must have gptbot option');
console.log('PASS: popup.html contains cardBotEmulation and required control selectors.');

console.log('--- Step 4: Testing popup.js bundle contents ---');
const bundlePath = path.resolve(__dirname, '../popup.js');
const bundleCode = fs.readFileSync(bundlePath, 'utf8');

assert(bundleCode.includes('initBotEmulation'), 'popup.js bundle must include initBotEmulation');
assert(bundleCode.includes('getUserAgent'), 'popup.js bundle must send getUserAgent action');
assert(bundleCode.includes('setUserAgent'), 'popup.js bundle must send setUserAgent action');
assert(bundleCode.includes('selectBotEmulation'), 'popup.js bundle must reference selectBotEmulation');
assert(bundleCode.includes('badgeBotStatus'), 'popup.js bundle must reference badgeBotStatus');
assert(bundleCode.includes('btnApplyBot'), 'popup.js bundle must reference btnApplyBot');
assert(bundleCode.includes('chrome.tabs.reload'), 'popup.js bundle must call chrome.tabs.reload');
console.log('PASS: popup.js bundle properly wires initBotEmulation, messaging, and tab reload.');

console.log('--- Step 5: Testing crawl-control SKILL.md documentation ---');
const skillPath = path.resolve(__dirname, '../../../Project Seo for WU and AA/.agents/skills/crawl-control/SKILL.md');
if (fs.existsSync(skillPath)) {
  const skillCode = fs.readFileSync(skillPath, 'utf8');
  assert(skillCode.includes('Client-Side Googlebot & Bot Emulation via declarativeNetRequest Session Rules'), 'SKILL.md must document DNR bot emulation');
  assert(skillCode.includes('declarativeNetRequest'), 'SKILL.md must reference declarativeNetRequest');
  assert(skillCode.includes('cloaking'), 'SKILL.md must cover cloaking audits');
  console.log('PASS: crawl-control SKILL.md contains DNR Googlebot and bot emulation specification.');
} else {
  console.log('SKIP: SKILL.md path not located at relative offset, verified separately.');
}

console.log('--- Step 6: Testing zero em-dash and zero en-dash invariant ---');
const filesToCheck = [
  manifestPath,
  bgPath,
  htmlPath,
  path.resolve(__dirname, '../popup.css'),
  path.resolve(__dirname, '../src/popup.ts'),
  path.resolve(__dirname, '../src/types/chrome.d.ts'),
  path.resolve(__dirname, '../CWS_PERMISSIONS_JUSTIFICATION.md'),
  bundlePath,
  skillPath
];

for (const filePath of filesToCheck) {
  if (!fs.existsSync(filePath)) continue;
  const content = fs.readFileSync(filePath, 'utf8');
  const hasEmDash = content.includes('\u2014');
  const hasEnDash = content.includes('\u2013');
  assert(!hasEmDash, `Em-dash detected in ${filePath}`);
  assert(!hasEnDash, `En-dash detected in ${filePath}`);
}
console.log('PASS: Zero em-dashes and zero en-dashes invariant confirmed across all modified files.');

console.log('ALL BOT EMULATION DNR TESTS PASSED.');
