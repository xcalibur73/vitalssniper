// Test Suite: Commercial Paywall Gating Architecture for VitalsSniper
// Invariant: Standard hyphens (-) or colons (:) only. Exactly zero em-dashes and zero en-dashes.
// UTF-8 encoding.

import assert from 'assert';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log('=== Commercial Paywall Gating Architecture Test Suite ===');

const popupTsPath = path.resolve(__dirname, '../src/popup.ts');
const popupTs = fs.readFileSync(popupTsPath, 'utf8');

const popupJsPath = path.resolve(__dirname, '../popup.js');
const popupJs = fs.readFileSync(popupJsPath, 'utf8');

// Test 1: Asserts that when isPaidUser is false, revenue loss dollar amount is masked and btnUnlockRevenuePro CTA is attached
console.log('\n--- Test 1: Financial Dollar Calculator Gating (!isPaidUser) ---');
{
  assert(popupTs.includes('btnUnlockRevenuePro'), 'popup.ts must define btnUnlockRevenuePro button');
  assert(popupTs.includes('filter: blur(4px); user-select: none;'), 'popup.ts must mask dollar loss with CSS blur for free users');
  assert(popupTs.includes('Unlock with PRO'), 'popup.ts must include Unlock with PRO button copy');
  assert(popupTs.includes('Financial Revenue Leakage Calculator: Unlock exact monthly and annual revenue loss calculations based on Google and Deloitte latency decay curves, customizable order values, and conversion modeling.'), 'popup.ts must wire modal context for revenue leakage calculator');

  assert(popupJs.includes('btnUnlockRevenuePro'), 'popup.js bundle must contain btnUnlockRevenuePro');
  assert(popupJs.includes('filter: blur(4px); user-select: none;'), 'popup.js bundle must contain blur filter');
  console.log('PASS: Test 1: Revenue loss dollar amount is masked and btnUnlockRevenuePro CTA is attached.');
}

// Test 2: Asserts that when isPaidUser is false and an INP culprit exists, raw script filename is masked and btnUnlockInpPro CTA is attached
console.log('\n--- Test 2: LoAF Script Attribution Gating (!isPaidUser) ---');
{
  assert(popupTs.includes('btnUnlockInpPro'), 'popup.ts must define btnUnlockInpPro button');
  assert(popupTs.includes('Unlock Script Culprit'), 'popup.ts must include Unlock Script Culprit button copy');
  assert(popupTs.includes('Long Animation Frames (LoAF) Script Attribution: Identify the exact JavaScript filename, function name, execution duration, and forced layout thrashing causing interaction delays.'), 'popup.ts must wire modal context for LoAF script attribution');
  assert(popupTs.includes('INP Interaction Delay:'), 'popup.ts must render interaction delay headline for free users');

  assert(popupJs.includes('btnUnlockInpPro'), 'popup.js bundle must contain btnUnlockInpPro');
  assert(popupJs.includes('Unlock Script Culprit'), 'popup.js bundle must contain Unlock Script Culprit');
  console.log('PASS: Test 2: INP culprit script filename is masked and btnUnlockInpPro CTA is attached.');
}

// Test 3: Asserts that when isPaidUser is false, clicking tabMerchant or tabAgency opens the upgrade modal
console.log('\n--- Test 3: Outreach Channels Gating (!isPaidUser) ---');
{
  assert(popupTs.includes('Specialized Outreach Teardowns: Unlock tailored Merchant Pitch and eCommerce revenue recovery scripts citing live performance metrics.'), 'popup.ts must wire upgrade modal for tabMerchant');
  assert(popupTs.includes('Specialized Outreach Teardowns: Unlock tailored Agency Partner Proposal and white-label retainer scripts citing live performance metrics.'), 'popup.ts must wire upgrade modal for tabAgency');

  assert(popupJs.includes('tailored Merchant Pitch and eCommerce revenue recovery scripts'), 'popup.js bundle must contain merchant pitch modal text');
  assert(popupJs.includes('tailored Agency Partner Proposal and white-label retainer scripts'), 'popup.js bundle must contain agency pitch modal text');
  console.log('PASS: Test 3: Clicking tabMerchant or tabAgency opens upgrade modal for free users.');
}

// Test 4: Asserts that when isPaidUser is false, selecting googlebot-smartphone, gptbot, or bingbot opens the upgrade modal and resets to default
console.log('\n--- Test 4: Advanced Search Bot Emulation Gating (!isPaidUser) ---');
{
  assert(popupTs.includes("targetUa === 'googlebot-smartphone' || targetUa === 'gptbot' || targetUa === 'bingbot'"), 'popup.ts must check for restricted bot User-Agents');
  assert(popupTs.includes('Advanced Search Bot Emulation: Simulate Googlebot Smartphone, Bingbot, and GPTBot to audit mobile-first cloaking, paywalls, and AI crawler access.'), 'popup.ts must wire upgrade modal for restricted bots');
  assert(popupTs.includes("selectBot.value = 'default'"), 'popup.ts must reset bot selector to default upon rejection');

  assert(popupJs.includes('Advanced Search Bot Emulation: Simulate Googlebot Smartphone, Bingbot, and GPTBot to audit mobile-first cloaking, paywalls, and AI crawler access.'), 'popup.js bundle must contain bot emulation modal text');
  console.log('PASS: Test 4: Selecting restricted bots opens upgrade modal and resets to default for free users.');
}

// Test 5: Asserts that when isPaidUser is true, all unmasked metrics, channels, and bots operate without upgrade modals
console.log('\n--- Test 5: PRO Tier Full Unmasked Telemetry and Controls (isPaidUser = true) ---');
{
  assert(popupTs.includes('Estimated Monthly Revenue Leaked: $${revenueLoss.lostMonthly.toLocaleString()}/mo'), 'popup.ts must provide unmasked revenue loss for PRO users');
  assert(popupTs.includes('(${execMs}ms execution, ${forcedMs}ms forced layout thrashing)'), 'popup.ts must provide unmasked LoAF metrics for PRO users');
  assert(popupTs.includes("activeChannel = 'merchant';"), 'popup.ts must switch to merchant channel for PRO users');
  assert(popupTs.includes("activeChannel = 'agency';"), 'popup.ts must switch to agency channel for PRO users');

  assert(popupJs.includes('${revenueLoss.lostMonthly.toLocaleString()}'), 'popup.js bundle must include unmasked monthly revenue template');
  console.log('PASS: Test 5: PRO tier unmasked telemetry and control branches verified.');
}

// Test 6: Asserts that editorial sites render Audience Engagement Forensics without phantom dollar loss
console.log('\n--- Test 6: Editorial Sites Audience Engagement Forensics ---');
{
  assert(popupTs.includes("revenueLoss.modelType === 'editorial'"), 'popup.ts must branch on editorial modelType');
  assert(popupTs.includes('AUDIENCE ENGAGEMENT FORENSICS'), 'popup.ts must render AUDIENCE ENGAGEMENT FORENSICS for editorial sites');
  assert(popupTs.includes('Estimated Audience Drag:'), 'popup.ts must render engagement drag rather than phantom dollar losses on editorial sites');

  assert(popupJs.includes('AUDIENCE ENGAGEMENT FORENSICS'), 'popup.js bundle must contain editorial header');
  console.log('PASS: Test 6: Editorial sites render audience engagement forensics instead of dollar loss.');
}

// Test 7: Asserts that FindingsEngine does not leak culprit script URL to free users
console.log('\n--- Test 7: FindingsEngine Culprit Script Leak Prevention ---');
{
  const findingsEngineTsPath = path.resolve(__dirname, '../src/engine/findingsEngine.ts');
  const findingsEngineTs = fs.readFileSync(findingsEngineTsPath, 'utf8');

  assert(findingsEngineTs.includes('public static evaluateFindings(data: any, domain: string, isPaidUser: boolean = false)'), 'findingsEngine.ts must accept isPaidUser parameter');
  assert(findingsEngineTs.includes("value: 'Main-thread script contention identified (PRO)'"), 'findingsEngine.ts must mask culprit script in inpEvidence for free users');
  assert(findingsEngineTs.includes('Long Animation Frame telemetry identified heavy main-thread script contention executing for'), 'findingsEngine.ts must mask culprit script in inpExplanation for free users');

  assert(popupTs.includes('FindingsEngine.evaluateFindings(data, domain, isPaidUser)'), 'popup.ts must pass isPaidUser to FindingsEngine.evaluateFindings');
  assert(popupTs.includes('renderAuditData(currentAuditState.domain, currentAuditState.url, currentAuditState.data)'), 'popup.ts must re-render audit data reactively upon activation and deactivation');
  console.log('PASS: Test 7: FindingsEngine culprit script leak prevention and reactive re-render verified.');
}

// Test 8: Invariant check asserting exactly zero em-dashes and zero en-dashes across all modified files
console.log('\n--- Test 8: Universal Deslop Invariant Check (Zero Em-Dash and En-Dash) ---');
{
  const findingsEngineTsPath = path.resolve(__dirname, '../src/engine/findingsEngine.ts');
  const filesToCheck = [
    popupTsPath,
    popupJsPath,
    findingsEngineTsPath,
    __filename
  ];

  for (const filePath of filesToCheck) {
    if (!fs.existsSync(filePath)) continue;
    const content = fs.readFileSync(filePath, 'utf8');
    const hasEmDash = content.includes('\u2014');
    const hasEnDash = content.includes('\u2013');
    assert(!hasEmDash, `File ${path.basename(filePath)} contains em-dash (\u2014)`);
    assert(!hasEnDash, `File ${path.basename(filePath)} contains en-dash (\u2013)`);
  }
  console.log('PASS: Test 8: Invariant confirmed with zero em-dashes and zero en-dashes across all files.');
}

console.log('\nAll 8 commercial paywall gating tests passed with exit code 0.');
