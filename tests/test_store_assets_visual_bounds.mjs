import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const require = createRequire(import.meta.url);

const playwrightPath = path.resolve(__dirname, '../../vitalssniper_web/node_modules/playwright');
const { chromium } = require(playwrightPath);

function hexToRgb(hex) {
  const cleanHex = hex.replace('#', '');
  const r = parseInt(cleanHex.substring(0, 2), 16);
  const g = parseInt(cleanHex.substring(2, 4), 16);
  const b = parseInt(cleanHex.substring(4, 6), 16);
  return [r, g, b];
}

function parseRgbString(str) {
  const match = str.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)/);
  if (match) {
    return [parseInt(match[1], 10), parseInt(match[2], 10), parseInt(match[3], 10)];
  }
  return null;
}

function getRelativeLuminance(r, g, b) {
  const [rs, gs, bs] = [r, g, b].map(c => {
    const s = c / 255;
    return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
  });
  return 0.2126 * rs + 0.7152 * gs + 0.0722 * bs;
}

function calculateContrastRatio(rgb1, rgb2) {
  const l1 = getRelativeLuminance(...rgb1);
  const l2 = getRelativeLuminance(...rgb2);
  const lighter = Math.max(l1, l2);
  const darker = Math.min(l1, l2);
  return (lighter + 0.05) / (darker + 0.05);
}

async function runVisualBoundsStressTest() {
  console.log('=== Playwright Visual Bounds & Contrast Stress Test ===');
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ deviceScaleFactor: 1 });
  const page = await context.newPage();

  const storeAssetsDir = path.resolve(__dirname, '../store_assets');

  // Test 1: Marquee Banner Eyebrow Pill Bounding Box & Clearance
  console.log('\n--- 1. Testing Marquee Banner Pill Bounding Box & Clearance ---');
  const marqueeSvgPath = path.join(storeAssetsDir, 'marquee_banner_1400x560.svg');
  const marqueeSvgContent = fs.readFileSync(marqueeSvgPath, 'utf8');

  await page.setViewportSize({ width: 1400, height: 560 });
  await page.setContent(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    html, body { width: 1400px; height: 560px; overflow: hidden; background: transparent; }
    svg { width: 1400px; height: 560px; display: block; }
  </style>
</head>
<body>
  ${marqueeSvgContent}
</body>
</html>`, { waitUntil: 'load' });

  await page.evaluate(() => document.fonts.ready);

  const marqueeMeasurements = await page.evaluate(() => {
    const textEls = Array.from(document.querySelectorAll('text'));
    const targetText = textEls.find(el => el.textContent.includes('CHROME EXTENSION : PRO EDITION'));
    if (!targetText) throw new Error('Target text element not found');

    const parentG = targetText.closest('g');
    const pillRect = parentG.querySelector('rect');
    if (!pillRect) throw new Error('Pill rect not found');

    const textBBox = targetText.getBBox();
    const rectBBox = pillRect.getBBox();

    const textClient = targetText.getBoundingClientRect();
    const rectClient = pillRect.getBoundingClientRect();

    const textStyle = window.getComputedStyle(targetText);
    const rectStyle = window.getComputedStyle(pillRect);

    return {
      text: {
        content: targetText.textContent,
        bbox: { x: textBBox.x, y: textBBox.y, width: textBBox.width, height: textBBox.height },
        client: { x: textClient.x, y: textClient.y, width: textClient.width, height: textClient.height },
        fill: textStyle.fill || targetText.getAttribute('fill'),
        fontSize: textStyle.fontSize,
        fontFamily: textStyle.fontFamily
      },
      rect: {
        widthAttr: parseFloat(pillRect.getAttribute('width')),
        heightAttr: parseFloat(pillRect.getAttribute('height')),
        bbox: { x: rectBBox.x, y: rectBBox.y, width: rectBBox.width, height: rectBBox.height },
        client: { x: rectClient.x, y: rectClient.y, width: rectClient.width, height: rectClient.height },
        fill: rectStyle.fill || pillRect.getAttribute('fill')
      }
    };
  });

  const textRightSVG = marqueeMeasurements.text.bbox.x + marqueeMeasurements.text.bbox.width;
  const rectRightSVG = marqueeMeasurements.rect.bbox.x + marqueeMeasurements.rect.bbox.width;
  const clearanceSVG = rectRightSVG - textRightSVG;
  const overflowSVG = textRightSVG > rectRightSVG;

  const textRightClient = marqueeMeasurements.text.client.x + marqueeMeasurements.text.client.width;
  const rectRightClient = marqueeMeasurements.rect.client.x + marqueeMeasurements.rect.client.width;
  const clearanceClient = rectRightClient - textRightClient;
  const overflowClient = textRightClient > rectRightClient;

  console.log(`Text content: "${marqueeMeasurements.text.content}"`);
  console.log(`Text BBox: x=${marqueeMeasurements.text.bbox.x.toFixed(1)}, width=${marqueeMeasurements.text.bbox.width.toFixed(1)}, right=${textRightSVG.toFixed(1)}`);
  console.log(`Rect BBox: x=${marqueeMeasurements.rect.bbox.x.toFixed(1)}, width=${marqueeMeasurements.rect.bbox.width.toFixed(1)}, right=${rectRightSVG.toFixed(1)}`);
  console.log(`SVG Clearance: ${clearanceSVG.toFixed(1)}px (Overflow: ${overflowSVG})`);
  console.log(`Client Clearance: ${clearanceClient.toFixed(1)}px (Overflow: ${overflowClient})`);

  if (overflowSVG || overflowClient) {
    throw new Error(`FAIL: Text overflows pill container! Clearance SVG: ${clearanceSVG}, Client: ${clearanceClient}`);
  }
  if (clearanceSVG <= 0 || clearanceClient <= 0) {
    throw new Error(`FAIL: Clearance is not positive! Clearance SVG: ${clearanceSVG}, Client: ${clearanceClient}`);
  }
  console.log('PASS: 0 overflow and positive clearance confirmed.');

  // Test 2: Eyebrow Pill Contrast Measurements Across All 5 Store Assets
  console.log('\n--- 2. Testing Eyebrow Pill Text Contrast Across All Assets ---');

  const assetSpecs = [
    {
      file: 'marquee_banner_1400x560.svg',
      width: 1400,
      height: 560,
      checks: [
        { label: 'Marquee Eyebrow Pill', selectorText: 'CHROME EXTENSION : PRO EDITION', bgFill: '#1a1a1a', expectedFg: '#ffffff' },
        { label: 'Marquee Outreach Pill', selectorText: 'CHANNEL: COLD EMAIL', bgFill: '#f7f7f7', expectedFg: '#1a1a1a' }
      ]
    },
    {
      file: 'screenshot_1_dom_bloat_1280x800.svg',
      width: 1280,
      height: 800,
      checks: [
        { label: 'Screenshot 1 Eyebrow Pill', selectorText: 'SCREENSHOT 1 : OVERVIEW & STACK DETECTION', bgFill: '#1a1a1a', expectedFg: '#ffffff' }
      ]
    },
    {
      file: 'screenshot_2_outreach_engine_1280x800.svg',
      width: 1280,
      height: 800,
      checks: [
        { label: 'Screenshot 2 Eyebrow Pill', selectorText: 'SCREENSHOT 2 : DEEP FORENSICS & ATTRIBUTION', bgFill: '#1a1a1a', expectedFg: '#ffffff' }
      ]
    },
    {
      file: 'screenshot_3_competitor_vs_1280x800.svg',
      width: 1280,
      height: 800,
      checks: [
        { label: 'Screenshot 3 Eyebrow Pill', selectorText: 'SCREENSHOT 3 : SEO HEADING & LINK FORENSICS', bgFill: '#1a1a1a', expectedFg: '#ffffff' }
      ]
    },
    {
      file: 'screenshot_4_outreach_1280x800.svg',
      width: 1280,
      height: 800,
      checks: [
        { label: 'Screenshot 4 Eyebrow Pill', selectorText: 'SCREENSHOT 4 : OUTREACH TEARDOWN ENGINE', bgFill: '#1a1a1a', expectedFg: '#ffffff' }
      ]
    },
    {
      file: 'screenshot_5_competitor_vs_1280x800.svg',
      width: 1280,
      height: 800,
      checks: [
        { label: 'Screenshot 5 Eyebrow Pill', selectorText: 'SCREENSHOT 5 : COMPETITOR BENCHMARK MATRIX', bgFill: '#1a1a1a', expectedFg: '#ffffff' }
      ]
    },
    {
      file: 'promo_tile_440x280.svg',
      width: 440,
      height: 280,
      checks: [
        { label: 'Promo Tile Eyebrow Pill', selectorText: 'EVIDENCE ENGINE: PRO EDITION', bgFill: '#1a1a1a', expectedFg: '#ffffff' }
      ]
    }
  ];

  const contrastResults = [];

  for (const asset of assetSpecs) {
    const assetSvgPath = path.join(storeAssetsDir, asset.file);
    const assetSvgContent = fs.readFileSync(assetSvgPath, 'utf8');

    await page.setViewportSize({ width: asset.width, height: asset.height });
    await page.setContent(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    html, body { width: ${asset.width}px; height: ${asset.height}px; overflow: hidden; background: #f7f7f7; }
    svg { width: ${asset.width}px; height: ${asset.height}px; display: block; }
  </style>
</head>
<body>
  ${assetSvgContent}
</body>
</html>`, { waitUntil: 'load' });
    await page.evaluate(() => document.fonts.ready);

    for (const check of asset.checks) {
      const elementData = await page.evaluate((targetSubstring) => {
        const textNodes = Array.from(document.querySelectorAll('text'));
        const el = textNodes.find(t => t.textContent.includes(targetSubstring));
        if (!el) return null;
        const style = window.getComputedStyle(el);
        return {
          fillAttr: el.getAttribute('fill'),
          computedFill: style.fill,
          computedColor: style.color
        };
      }, check.selectorText);

      if (!elementData) {
        throw new Error(`FAIL: Element "${check.selectorText}" not found in ${asset.file}`);
      }

      const fgColor = elementData.fillAttr || elementData.computedFill || elementData.computedColor;
      const fgRgb = fgColor.startsWith('#') ? hexToRgb(fgColor) : parseRgbString(fgColor);
      const bgRgb = hexToRgb(check.bgFill);

      const ratio = calculateContrastRatio(fgRgb, bgRgb);
      const passAA = ratio >= 4.5;
      const passAAA = ratio >= 7.0;

      contrastResults.push({
        asset: asset.file,
        label: check.label,
        text: check.selectorText,
        fg: fgColor,
        bg: check.bgFill,
        ratio: ratio.toFixed(2),
        passAA,
        passAAA
      });

      console.log(`[${passAAA ? 'PASS AAA' : (passAA ? 'PASS AA' : 'FAIL')}] ${check.label} ("${check.selectorText}")`);
      console.log(`  FG: ${fgColor} | BG: ${check.bgFill} | Contrast Ratio: ${ratio.toFixed(2)}:1 (Min AA: 4.5:1, Min AAA: 7.0:1)`);

      if (!passAA) {
        throw new Error(`FAIL: Contrast ratio ${ratio.toFixed(2)}:1 is below WCAG AA 4.5:1 requirement`);
      }
    }
  }

  // Test 3: Font Fallback Clearance Stress Test for Marquee Eyebrow Pill
  console.log('\n--- 3. Stress-Testing Font Fallbacks on Marquee Eyebrow Pill ---');
  const fallbackFonts = ['Segoe UI', 'Arial', 'Roboto', 'Inter', 'Helvetica Neue', 'sans-serif', 'system-ui'];
  for (const fontName of fallbackFonts) {
    const fallbackSvg = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    html, body { width: 400px; height: 100px; overflow: hidden; background: #f7f7f7; }
    svg { width: 400px; height: 100px; display: block; }
  </style>
</head>
<body>
  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 100" width="400" height="100">
    <g transform="translate(20, 20)">
      <rect width="242" height="26" rx="13" fill="#1a1a1a"/>
      <circle cx="13" cy="13" r="4" fill="#e63946"/>
      <text id="test-text" x="24" y="17" font-family="${fontName}" font-size="10.5" font-weight="700" fill="#ffffff" letter-spacing="0.06em">CHROME EXTENSION : PRO EDITION</text>
    </g>
  </svg>
</body>
</html>`;
    await page.setContent(fallbackSvg, { waitUntil: 'load' });
    await page.evaluate(() => document.fonts.ready);

    const metrics = await page.evaluate(() => {
      const textEl = document.getElementById('test-text');
      const pillEl = textEl.parentElement.querySelector('rect');
      const tBox = textEl.getBBox();
      const rBox = pillEl.getBBox();
      return {
        textRight: tBox.x + tBox.width,
        rectRight: rBox.x + rBox.width,
        textWidth: tBox.width,
        rectWidth: rBox.width
      };
    });

    const clearance = metrics.rectRight - metrics.textRight;
    const isOverflow = metrics.textRight > metrics.rectRight;
    console.log(`[Font: ${fontName.padEnd(14)}] Text right: ${metrics.textRight.toFixed(1)}px | Pill right: ${metrics.rectRight.toFixed(1)}px | Clearance: ${clearance.toFixed(1)}px | Overflow: ${isOverflow}`);
    if (isOverflow || clearance <= 0) {
      throw new Error(`FAIL: Font ${fontName} caused pill overflow! Clearance: ${clearance}`);
    }
  }
  console.log('PASS: All font fallbacks maintain positive clearance and 0 overflow.');

  await browser.close();
  console.log('\n=== ALL PLAYWRIGHT VISUAL BOUNDS & CONTRAST TESTS PASSED! ===');
  return {
    marqueeMeasurements,
    clearanceSVG,
    clearanceClient,
    contrastResults
  };
}

runVisualBoundsStressTest().then(() => {
  process.exit(0);
}).catch(err => {
  console.error('Playwright Test Failed:', err);
  process.exit(1);
});
