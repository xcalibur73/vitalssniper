// Build script for VitalsSniper Extension
// Runs tsc to compile TypeScript to dist/, then concatenates into clean, unminified, readable ES6 popup.js
// Strictly zero em-dashes

import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log('--- Step 1: Compiling TypeScript with tsc ---');

const tscBin = path.resolve(__dirname, '../vitalssniper_web/node_modules/typescript/bin/tsc');
const tsconfigPath = path.resolve(__dirname, 'tsconfig.json');

execSync(`node "${tscBin}" -p "${tsconfigPath}"`, { stdio: 'inherit' });

console.log('--- Step 2: Bundling Compiled Modules ---');

const header = `/**
 * VitalsSniper: Evidence-Based Website Intelligence Inspector
 * 
 * Unified 6-Layer Architecture:
 * 
 *                  VITALSSNIPER
 *                        │
 *                ┌───────┴────────┐
 *                │                │
 *           Browser Audit     External Audit
 *                │                │
 *                ▼                ▼
 *         ┌─────────────┐   ┌──────────────┐
 *         │ Raw Metrics │   │ Lighthouse / │
 *         │ (DOM/CSS/JS)│   │ PSI / CrUX   │
 *         └──────┬──────┘   └───────┬──────┘
 *                │                  │
 *                └────────┬─────────┘
 *                         ▼
 *                  EVIDENCE ENGINE
 *           (Triangulation & Heuristics)
 *                         │
 *              ┌──────────┼───────────┐
 *              ▼          ▼           ▼
 *           Critical   Warning    Opportunity
 *              │          │           │
 *              └──────────┼───────────┘
 *                         ▼
 *                   AI INTERPRETER
 *              (Evidence-First Copy)
 *                         │
 *              ┌──────────┼──────────┐
 *              ▼          ▼          ▼
 *            Email       DM        Loom
 *                         │
 *                         ▼
 *                   Lead Pipeline
 *              (CRM & RFC 4180 CSV)
 *                         │
 *                         ▼
 *                 Client PDF Report
 *           (1-Page Teardown Dossier)
 * 
 * Standards Compliance: WEBAUDITS_RULES.md | Least-Privilege MV3 | WCAG 2.2 AA
 */
`;

function stripEsm(code) {
  return code
    .replace(/^import\s+.*?from\s+['"].*?['"];?\r?\n/gm, '')
    .replace(/^import\s+['"].*?['"];?\r?\n/gm, '')
    .replace(/^export\s+(async\s+)?(class|function|const|let|var)\s+/gm, (m, p1, p2) => (p1 || '') + p2 + ' ')
    .replace(/^export\s+\{.*?\};?\r?\n/gm, '')
    .replace(/^export\s+default\s+.*?;?\r?\n/gm, '');
}

const distOrder = [
  'dist/utils/security.js',
  'dist/services/storageService.js',
  'dist/services/licenseService.js',
  'dist/services/cloudSyncService.js',
  'dist/services/competitorService.js',
  'dist/services/reportService.js',
  'dist/engine/techDetector.js',
  'dist/engine/revenueLossEngine.js',
  'dist/engine/httpHeaderAudit.js',
  'dist/engine/externalAudit.js',
  'dist/engine/browserAudit.js',
  'dist/engine/findingsEngine.js',
  'dist/engine/outreachGenerator.js',
  'dist/popup.js'
];

let bundleBody = '';

for (const relPath of distOrder) {
  const fullPath = path.resolve(__dirname, relPath);
  let content = fs.readFileSync(fullPath, 'utf8');
  content = stripEsm(content);
  bundleBody += `\n// ====================================================================\n// MODULE: ${relPath}\n// ====================================================================\n\n` + content.trim() + '\n';
}

// Ensure zero em-dashes or en-dashes
bundleBody = bundleBody.replace(/[\u2014\u2013]/g, '-');

const finalBundle = header + '\n' + bundleBody;

const prodPath = path.resolve(__dirname, 'popup.js');

fs.writeFileSync(prodPath, finalBundle, 'utf8');

console.log(`Bundle created successfully:`);
console.log(`  -> ${prodPath} (${(finalBundle.length / 1024).toFixed(1)} KB)`);

console.log('--- Step 3: Packaging Release Distribution Zip ---');
try {
  execSync(`powershell -ExecutionPolicy Bypass -File "${path.resolve(__dirname, 'package_zip.ps1')}"`, { stdio: 'inherit' });
} catch (err) {
  console.error('Failed to package release zip:', err.message);
}
