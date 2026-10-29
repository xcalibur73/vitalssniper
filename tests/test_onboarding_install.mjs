// Automated verification for post-install onboarding tab opening
// Invariant: Standard hyphens and colons only, zero em-dashes and zero en-dashes

import assert from 'assert';
import fs from 'fs';
import path from 'path';
import vm from 'vm';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const EXPECTED_ONBOARDING_URL = 'https://webaudits.pro/products/vitalssniper-pro?utm_source=cws_install&utm_medium=extension';

console.log('--- Step 1: Static source verification of background.js ---');
const bgPath = path.resolve(__dirname, '../background.js');
assert(fs.existsSync(bgPath), 'background.js must exist');
const bgCode = fs.readFileSync(bgPath, 'utf8');

assert(
  bgCode.includes("details.reason === 'install'"),
  "background.js must check details.reason === 'install'"
);
assert(
  bgCode.includes(EXPECTED_ONBOARDING_URL),
  `background.js must contain onboarding URL: ${EXPECTED_ONBOARDING_URL}`
);
console.log('PASS: background.js contains install reason check and onboarding URL.');

console.log('--- Step 2: Mock execution of onInstalled listener ---');

let unhandledRejections = [];
process.on('unhandledRejection', (reason) => {
  unhandledRejections.push(reason);
});

function loadBackgroundContext(options = {}) {
  let installedListener = null;
  const createdTabs = [];
  const sessionRuleRemovals = [];

  const mockChrome = {
    runtime: {
      onInstalled: {
        addListener: (fn) => {
          installedListener = fn;
        }
      },
      onMessage: {
        addListener: () => {}
      }
    },
    declarativeNetRequest: {
      updateSessionRules: async (ruleOptions) => {
        if (ruleOptions && Array.isArray(ruleOptions.removeRuleIds)) {
          sessionRuleRemovals.push(...ruleOptions.removeRuleIds);
        }
        if (options.rejectDNR) {
          throw new Error('DNR error');
        }
        return true;
      }
    },
    tabs: {
      create: async (tabOptions) => {
        if (options.rejectTabsCreate) {
          throw new Error('tabs.create rejected');
        }
        createdTabs.push(tabOptions);
        return { id: 101, ...tabOptions };
      }
    },
    storage: {
      session: null,
      local: null
    }
  };

  const sandbox = {
    chrome: mockChrome,
    console: {
      log: () => {},
      error: () => {},
      warn: () => {}
    }
  };

  vm.createContext(sandbox);
  vm.runInContext(bgCode, sandbox);

  assert(
    typeof installedListener === 'function',
    'chrome.runtime.onInstalled listener must be registered'
  );

  return {
    triggerInstalled: (details) => installedListener(details),
    createdTabs,
    sessionRuleRemovals
  };
}

// Subtest 2A: details.reason === 'install' triggers chrome.tabs.create with expected URL
{
  const env = loadBackgroundContext();
  env.triggerInstalled({ reason: 'install' });
  assert.strictEqual(env.createdTabs.length, 1, 'Exactly one tab must be created on install');
  assert.strictEqual(env.createdTabs[0].url, EXPECTED_ONBOARDING_URL, 'Tab URL must match onboarding URL');
  assert.strictEqual(env.sessionRuleRemovals.length, 1, 'Session rules must be reset');
  console.log('PASS: reason === "install" creates onboarding tab.');
}

// Subtest 2B: details.reason === 'update' does NOT trigger chrome.tabs.create
{
  const env = loadBackgroundContext();
  env.triggerInstalled({ reason: 'update' });
  assert.strictEqual(env.createdTabs.length, 0, 'No tabs must be created on update');
  assert.strictEqual(env.sessionRuleRemovals.length, 1, 'Session rules must still be reset on update');
  console.log('PASS: reason === "update" does not create tab.');
}

// Subtest 2C: details.reason === 'chrome_update' does NOT trigger chrome.tabs.create
{
  const env = loadBackgroundContext();
  env.triggerInstalled({ reason: 'chrome_update' });
  assert.strictEqual(env.createdTabs.length, 0, 'No tabs must be created on chrome_update');
  assert.strictEqual(env.sessionRuleRemovals.length, 1, 'Session rules must still be reset on chrome_update');
  console.log('PASS: reason === "chrome_update" does not create tab.');
}

// Subtest 2D: Undefined details does not throw
{
  const env = loadBackgroundContext();
  assert.doesNotThrow(() => {
    env.triggerInstalled(undefined);
  }, 'Undefined details must not throw an exception');
  assert.strictEqual(env.createdTabs.length, 0, 'No tabs must be created when details is undefined');
  console.log('PASS: undefined details handled safely without throwing.');
}

// Subtest 2E: Rejection in chrome.tabs.create is caught safely
{
  const env = loadBackgroundContext({ rejectTabsCreate: true });
  assert.doesNotThrow(() => {
    env.triggerInstalled({ reason: 'install' });
  }, 'Rejection in tabs.create must be handled safely');
  console.log('PASS: tabs.create rejection caught safely without throwing.');
}

// Allow microtasks to settle to verify no unhandled promise rejections
await new Promise((resolve) => setTimeout(resolve, 50));
assert.strictEqual(
  unhandledRejections.length,
  0,
  `Unhandled promise rejections encountered: ${unhandledRejections.map(r => r && r.message ? r.message : r).join(', ')}`
);
console.log('PASS: Zero unhandled promise rejections detected.');

console.log('--- Step 3: Zero em-dash and zero en-dash invariant check ---');
const filesToVerify = [
  bgPath,
  __filename
];

for (const targetPath of filesToVerify) {
  const content = fs.readFileSync(targetPath, 'utf8');
  assert(!content.includes('\u2014'), `Em-dash detected in ${targetPath}`);
  assert(!content.includes('\u2013'), `En-dash detected in ${targetPath}`);
}
console.log('PASS: Zero em-dashes and zero en-dashes invariant confirmed.');

console.log('ALL ONBOARDING INSTALL TESTS PASSED.');
