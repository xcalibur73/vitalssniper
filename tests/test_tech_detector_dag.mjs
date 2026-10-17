// Test Suite: Wappalyzer SemVer Regex Intelligence and Dependency DAG (implies/excludes)
// Invariant: Standard hyphens (-) or colons (:) only. Exactly zero em-dashes and zero en-dashes.
// UTF-8 encoding.

import assert from 'assert';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { detectTechnologies, resolveImplies, resolveExcludes, extractTechVersion } from '../dist/engine/techDetector.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log('=== Tech Detector DAG & SemVer Intelligence Test Suite ===');

// 1. Test resolveImplies adds WordPress when WooCommerce is detected
console.log('\n--- 1. Testing resolveImplies: WooCommerce implies WordPress ---');
{
  const input = [
    { name: 'WooCommerce', category: 'Ecommerce', confidence: 'high', evidence: ['Scoped DOM signature'] }
  ];
  const output = resolveImplies(input);
  const wp = output.find(d => d.name === 'WordPress');
  assert(wp, 'WordPress must be added to detections when WooCommerce is detected');
  assert.strictEqual(wp.category, 'CMS', 'WordPress category must be CMS');
  assert.strictEqual(wp.confidence, 'high', 'WordPress confidence must be high');
  assert(wp.evidence.includes('Inferred by dependency: WooCommerce implies WordPress'), 'WordPress must have implies evidence');
  console.log('PASS: WooCommerce implies WordPress correctly.');
}

// 1b. Test resolveImplies for Elementor, Divi, GeneratePress
console.log('\n--- 1b. Testing resolveImplies: Builders imply WordPress ---');
{
  const inputElem = [{ name: 'Elementor', category: 'Page Builder', confidence: 'high', evidence: ['DOM class'] }];
  const outElem = resolveImplies(inputElem);
  assert(outElem.some(d => d.name === 'WordPress' && d.evidence.includes('Inferred by dependency: Elementor implies WordPress')), 'Elementor implies WordPress');

  const inputDivi = [{ name: 'Divi', category: 'Page Builder', confidence: 'high', evidence: ['Theme path'] }];
  const outDivi = resolveImplies(inputDivi);
  assert(outDivi.some(d => d.name === 'WordPress' && d.evidence.includes('Inferred by dependency: Divi implies WordPress')), 'Divi implies WordPress');

  const inputGp = [{ name: 'GeneratePress', category: 'Page Builder', confidence: 'high', evidence: ['Theme token'] }];
  const outGp = resolveImplies(inputGp);
  assert(outGp.some(d => d.name === 'WordPress' && d.evidence.includes('Inferred by dependency: GeneratePress implies WordPress')), 'GeneratePress implies WordPress');
  console.log('PASS: Page builders imply WordPress correctly.');
}

// 2. Test resolveImplies adds React when Next.js is detected
console.log('\n--- 2. Testing resolveImplies: Next.js implies React ---');
{
  const input = [
    { name: 'Next.js', category: 'Framework', confidence: 'high', evidence: ['Hydration data'] }
  ];
  const output = resolveImplies(input);
  const react = output.find(d => d.name === 'React');
  assert(react, 'React must be added to detections when Next.js is detected');
  assert.strictEqual(react.category, 'Framework', 'React category must be Framework');
  assert.strictEqual(react.confidence, 'high', 'React confidence must be high');
  assert(react.evidence.includes('Inferred by dependency: Next.js implies React'), 'React must have implies evidence');

  // Also test Nuxt.js implies Vue.js
  const nuxtInput = [
    { name: 'Nuxt.js', category: 'Framework', confidence: 'high', evidence: ['Path: /_nuxt/'] }
  ];
  const nuxtOutput = resolveImplies(nuxtInput);
  const vue = nuxtOutput.find(d => d.name === 'Vue.js');
  assert(vue, 'Vue.js must be added when Nuxt.js is detected');
  assert(vue.evidence.includes('Inferred by dependency: Nuxt.js implies Vue.js'), 'Vue.js must have implies evidence');
  console.log('PASS: Next.js implies React and Nuxt.js implies Vue.js.');
}

// 2b. Test that resolveImplies does not duplicate if target is already present
console.log('\n--- 2b. Testing resolveImplies: No duplicate insertions ---');
{
  const input = [
    { name: 'WooCommerce', category: 'Ecommerce', confidence: 'high', evidence: ['Scoped DOM signature'] },
    { name: 'Elementor', category: 'Page Builder', confidence: 'high', evidence: ['DOM class'] },
    { name: 'WordPress', category: 'CMS', confidence: 'high', evidence: ['Meta generator: WordPress'] }
  ];
  const output = resolveImplies(input);
  const wpCount = output.filter(d => d.name === 'WordPress').length;
  assert.strictEqual(wpCount, 1, 'WordPress must not be duplicated');
  console.log('PASS: No duplicates inserted by implies DAG.');
}

// 3. Test resolveExcludes removes WooCommerce when Shopify is detected
console.log('\n--- 3. Testing resolveExcludes: Shopify excludes WooCommerce and Magento ---');
{
  const input = [
    { name: 'Shopify', category: 'Ecommerce', confidence: 'high', evidence: ['CDN resource: cdn.shopify.com'] },
    { name: 'WooCommerce', category: 'Ecommerce', confidence: 'high', evidence: ['False positive class'] },
    { name: 'Magento', category: 'Ecommerce', confidence: 'high', evidence: ['False positive script'] }
  ];
  const output = resolveExcludes(input);
  assert(!output.some(d => d.name === 'WooCommerce'), 'WooCommerce must be removed when Shopify is detected');
  assert(!output.some(d => d.name === 'Magento'), 'Magento must be removed when Shopify is detected');
  assert(output.some(d => d.name === 'Shopify'), 'Shopify must remain');
  console.log('PASS: Shopify successfully excludes WooCommerce and Magento false positives.');
}

// 3b. Test resolveExcludes allows WooCommerce if explicit shopify-buy button is present
console.log('\n--- 3b. Testing resolveExcludes: Shopify Buy Button preserves self-hosted WooCommerce ---');
{
  const input = [
    { name: 'Shopify', category: 'Ecommerce', confidence: 'high', evidence: ['Shopify Buy Button integration'] },
    { name: 'WooCommerce', category: 'Ecommerce', confidence: 'high', evidence: ['Scoped DOM signature'] }
  ];
  const output = resolveExcludes(input);
  assert(output.some(d => d.name === 'WooCommerce'), 'WooCommerce must be preserved when Shopify Buy Button is present');
  console.log('PASS: Shopify Buy Button preserves self-hosted WooCommerce.');
}

// 3c. Test resolveExcludes: Wix and Squarespace exclude WordPress
console.log('\n--- 3c. Testing resolveExcludes: Wix and Squarespace exclude WordPress ---');
{
  const wixInput = [
    { name: 'Wix', category: 'CMS', confidence: 'high', evidence: ['CDN resource: parastorage'] },
    { name: 'WordPress', category: 'CMS', confidence: 'high', evidence: ['False positive token'] }
  ];
  const wixOutput = resolveExcludes(wixInput);
  assert(!wixOutput.some(d => d.name === 'WordPress'), 'WordPress must be removed when Wix is detected');

  const sqsInput = [
    { name: 'Squarespace', category: 'CMS', confidence: 'high', evidence: ['Markup signature: sqs-block'] },
    { name: 'WordPress', category: 'CMS', confidence: 'high', evidence: ['False positive token'] }
  ];
  const sqsOutput = resolveExcludes(sqsInput);
  assert(!sqsOutput.some(d => d.name === 'WordPress'), 'WordPress must be removed when Squarespace is detected');
  console.log('PASS: Wix and Squarespace successfully exclude WordPress false positives.');
}

// 4. Test SemVer extraction parses 'WordPress 6.5.2' into version '6.5.2'
console.log('\n--- 4. Testing SemVer extraction for WordPress ---');
{
  // Test direct text input
  const ver1 = extractTechVersion('WordPress', null, {}, 'WordPress 6.5.2');
  assert.strictEqual(ver1, '6.5.2', 'SemVer extraction must parse "WordPress 6.5.2" into "6.5.2"');

  // Test meta generator tag
  const ver2 = extractTechVersion('WordPress', null, {}, '<meta name="generator" content="WordPress 6.5.2">');
  assert.strictEqual(ver2, '6.5.2', 'SemVer extraction must parse meta generator into "6.5.2"');

  // Test script URL with wp-includes / wp-embed
  const ver3 = extractTechVersion('WordPress', null, {}, '<script src="/wp-includes/js/wp-embed.min.js?ver=6.5.2"></script>');
  assert.strictEqual(ver3, '6.5.2', 'SemVer extraction must parse wp-embed script URL into "6.5.2"');

  // Test full detectTechnologies pipeline
  const detections = detectTechnologies(null, {}, '<meta name="generator" content="WordPress 6.5.2">');
  const wp = detections.find(d => d.name === 'WordPress');
  assert(wp, 'WordPress must be detected');
  assert.strictEqual(wp.version, '6.5.2', 'WordPress detection object must contain version "6.5.2"');
  console.log('PASS: WordPress SemVer extraction verified.');
}

// 5. Test SemVer extraction parses 'WooCommerce 8.7.0' into version '8.7.0'
console.log('\n--- 5. Testing SemVer extraction for WooCommerce ---');
{
  // Test direct text input
  const ver1 = extractTechVersion('WooCommerce', null, {}, 'WooCommerce 8.7.0');
  assert.strictEqual(ver1, '8.7.0', 'SemVer extraction must parse "WooCommerce 8.7.0" into "8.7.0"');

  // Test meta generator tag
  const ver2 = extractTechVersion('WooCommerce', null, {}, '<meta name="generator" content="WooCommerce 8.7.0">');
  assert.strictEqual(ver2, '8.7.0', 'SemVer extraction must parse meta generator into "8.7.0"');

  // Test script URL with woocommerce asset
  const ver3 = extractTechVersion('WooCommerce', null, {}, '<script src="/plugins/woocommerce/assets/js/frontend/woocommerce.min.js?ver=8.7.0"></script>');
  assert.strictEqual(ver3, '8.7.0', 'SemVer extraction must parse woocommerce script URL into "8.7.0"');

  // Test full detectTechnologies pipeline (with WooCommerce implying WordPress)
  const detections = detectTechnologies(null, {}, '<meta name="generator" content="WooCommerce 8.7.0">');
  const woo = detections.find(d => d.name === 'WooCommerce');
  assert(woo, 'WooCommerce must be detected');
  assert.strictEqual(woo.version, '8.7.0', 'WooCommerce detection object must contain version "8.7.0"');
  const wp = detections.find(d => d.name === 'WordPress');
  assert(wp, 'WordPress must also be detected via WooCommerce implies');
  console.log('PASS: WooCommerce SemVer extraction and implied WordPress verified.');
}

// 5b. Test SemVer extraction for Elementor, Next.js, React, Vue.js, GeneratePress
console.log('\n--- 5b. Testing SemVer extraction for other technologies ---');
{
  // Elementor
  const elemVer = extractTechVersion('Elementor', null, { elementorFrontendConfig: { version: '3.19.2' } }, '');
  assert.strictEqual(elemVer, '3.19.2', 'Elementor version from elementorFrontendConfig');

  // Next.js
  const nextVer = extractTechVersion('Next.js', null, { next: { version: '14.1.0' } }, '');
  assert.strictEqual(nextVer, '14.1.0', 'Next.js version from window.next');

  // React
  const reactVer = extractTechVersion('React', null, { React: { version: '18.2.0' } }, '');
  assert.strictEqual(reactVer, '18.2.0', 'React version from window.React');

  const reactUrlVer = extractTechVersion('React', null, {}, '<script src="https://unpkg.com/react@18.2.0/umd/react.production.min.js"></script>');
  assert.strictEqual(reactUrlVer, '18.2.0', 'React version from script URL');

  // Vue.js
  const vueVer = extractTechVersion('Vue.js', null, { Vue: { version: '3.4.15' } }, '');
  assert.strictEqual(vueVer, '3.4.15', 'Vue.js version from window.Vue');

  // GeneratePress
  const gpVer = extractTechVersion('GeneratePress', null, {}, '<link rel="stylesheet" href="/themes/generatepress/style.min.css?ver=3.4.0">');
  assert.strictEqual(gpVer, '3.4.0', 'GeneratePress version from style URL');
  console.log('PASS: Elementor, Next.js, React, Vue.js, and GeneratePress SemVer extraction verified.');
}

// 6. Test popup.js version formatting in renderAuditData
console.log('\n--- 6. Testing popup.js version display format ---');
{
  const popupJsPath = path.resolve(__dirname, '../popup.js');
  const popupJs = fs.readFileSync(popupJsPath, 'utf8');
  assert(popupJs.includes('item.version ? `${item.name} v${item.version}` : item.name') ||
         popupJs.includes('item.version ? `${item.name} v${item.version}` : item.name') ||
         popupJs.includes('item.version ? `${item.name} v${item.version}`'),
         'popup.js must format displayed tech name with version');
  console.log('PASS: popup.js renders tech name with version badge correctly.');
}

// 7. Test zero em/en-dash invariant across newly touched files
console.log('\n--- 7. Testing zero em-dash and zero en-dash invariant ---');
{
  const touchedFiles = [
    path.resolve(__dirname, '../src/types/audit.ts'),
    path.resolve(__dirname, '../src/engine/techDetector.ts'),
    path.resolve(__dirname, '../src/popup.ts'),
    path.resolve(__dirname, '../popup.js'),
    __filename
  ];

  for (const file of touchedFiles) {
    const content = fs.readFileSync(file, 'utf8');
    const hasEmDash = content.includes('\u2014');
    const hasEnDash = content.includes('\u2013');
    assert(!hasEmDash, `File ${path.basename(file)} must not contain em-dashes (\\u2014)`);
    assert(!hasEnDash, `File ${path.basename(file)} must not contain en-dashes (\\u2013)`);
  }
  console.log('PASS: Exactly zero em-dashes and zero en-dashes across all touched files.');
}

console.log('\n======================================================');
console.log('ALL TECH DETECTOR DAG & SEMVER INTELLIGENCE TESTS PASS');
console.log('======================================================\n');
