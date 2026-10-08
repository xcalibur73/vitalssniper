// Phase 5 Test Suite: Chrome Extension Hardening (Findings 26 & 27)
// Punctuation Invariant: Standard hyphens (-) or colons (:) only. Strictly zero em-dashes and zero en-dashes.

import assert from 'assert';
import fs from 'fs';
import path from 'path';

console.log('====================================================');
console.log('PHASE 5: CHROME EXTENSION HARDENING TEST SUITE');
console.log('====================================================');

let passedChecks = 0;
let totalChecks = 0;

function check(name, fn) {
  totalChecks++;
  try {
    fn();
    console.log(`  PASS: ${name}`);
    passedChecks++;
  } catch (err) {
    console.error(`  FAIL: ${name}`);
    console.error(`    ${err.message}`);
    process.exitCode = 1;
  }
}

// -----------------------------------------------------------------------------
// GROUP 1: Elimination of Developer Testing Key Bypass (Finding 26)
// -----------------------------------------------------------------------------
console.log('\n[GROUP 1] Backdoor Elimination (Finding 26):');

check('License Service: No r3dxlost88 bypass key exists in licenseService.ts', () => {
  const licenseCode = fs.readFileSync('src/services/licenseService.ts', 'utf8');
  assert(!licenseCode.includes('r3dxlost88'), 'licenseService.ts must not contain r3dxlost88');
});

check('Cloud Sync Service: No r3dxlost88 bypass key exists in cloudSyncService.ts', () => {
  const syncCode = fs.readFileSync('src/services/cloudSyncService.ts', 'utf8');
  assert(!syncCode.includes('r3dxlost88'), 'cloudSyncService.ts must not contain r3dxlost88');
});

check('Storage Service: No r3dxlost88 bypass key exists in storageService.ts', () => {
  const storageCode = fs.readFileSync('src/services/storageService.ts', 'utf8');
  assert(!storageCode.includes('r3dxlost88'), 'storageService.ts must not contain r3dxlost88');
});

check('Entire Extension Source: Zero occurrences of r3dxlost88 across all source files', () => {
  function scanDir(dir) {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory() && entry.name !== 'node_modules' && entry.name !== '.git') {
        scanDir(fullPath);
      } else if (entry.isFile() && (entry.name.endsWith('.ts') || entry.name.endsWith('.js'))) {
        if (entry.name === 'test_extension_hardening.mjs') continue;
        const code = fs.readFileSync(fullPath, 'utf8');
        assert(!code.includes('r3dxlost88'), `File ${fullPath} contains r3dxlost88 bypass key`);
      }
    }
  }
  scanDir('src');
});

// -----------------------------------------------------------------------------
// GROUP 2: Shadow DOM & Web Components Deep Traversal (Finding 27)
// -----------------------------------------------------------------------------
console.log('\n[GROUP 2] Shadow DOM & Web Components Traversal (Finding 27):');

check('Browser Auditor: walkDom pierces open shadow roots', () => {
  const auditorCode = fs.readFileSync('src/engine/browserAudit.ts', 'utf8');
  assert(auditorCode.includes('element.shadowRoot'), 'walkDom must check for element.shadowRoot');
  assert(auditorCode.includes('shadowChildren = shadowRoot.children'), 'walkDom must iterate shadowRoot.children');
  assert(auditorCode.includes("tag === 'svg' || tag === 'math'"), 'walkDom must treat svg and math as atomic root elements');
});

check('Browser Auditor: querySelectorAllDeep traverses shadow roots for LCP & accessibility', () => {
  const auditorCode = fs.readFileSync('src/engine/browserAudit.ts', 'utf8');
  assert(auditorCode.includes('function querySelectorAllDeep'), 'Must implement querySelectorAllDeep helper');
  assert(auditorCode.includes('el.shadowRoot'), 'querySelectorAllDeep must inspect el.shadowRoot');
  assert(auditorCode.includes('querySelectorAllDeep(document, \'img, video'), 'LCP fallback candidates must use querySelectorAllDeep');
  assert(auditorCode.includes('querySelectorAllDeep<HTMLImageElement>(document, \'img\')'), 'Image forensics must use querySelectorAllDeep');
  assert(auditorCode.includes('querySelectorAllDeep(document, \'button, a, input'), 'Interactive elements must use querySelectorAllDeep');
});

// -----------------------------------------------------------------------------
// GROUP 3: Punctuation Invariant Verification
// -----------------------------------------------------------------------------
console.log('\n[GROUP 3] Punctuation & Dash Invariant:');

const extensionFiles = [
  'src/services/licenseService.ts',
  'src/services/cloudSyncService.ts',
  'src/services/storageService.ts',
  'src/engine/browserAudit.ts',
];

extensionFiles.forEach((file) => {
  check(`Invariant Check (${path.basename(file)}): Zero em-dashes and en-dashes`, () => {
    const content = fs.readFileSync(file, 'utf8');
    const emDashMatch = content.match(/\u2014/g);
    const enDashMatch = content.match(/\u2013/g);
    assert.strictEqual(emDashMatch, null, `File ${file} contains em-dashes`);
    assert.strictEqual(enDashMatch, null, `File ${file} contains en-dashes`);
  });
});

console.log('\n====================================================');
console.log(`TOTAL CHECKS: ${totalChecks} | PASSED: ${passedChecks} | FAILED: ${totalChecks - passedChecks}`);
console.log('====================================================\n');

if (passedChecks === totalChecks) {
  process.exit(0);
} else {
  process.exit(1);
}
