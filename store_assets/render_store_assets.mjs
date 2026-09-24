import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const require = createRequire(import.meta.url);

const playwrightPath = path.resolve(__dirname, '../../vitalssniper_web/node_modules/playwright');
const { chromium } = require(playwrightPath);

async function renderAssets() {
  console.log('--- Rendering Store Visual Assets to PNG via Chromium ---');
  const browser = await chromium.launch();
  const context = await browser.newContext({
    deviceScaleFactor: 1
  });
  const page = await context.newPage();

  const assets = [
    {
      file: 'promo_tile_440x280.svg',
      output: 'promo_tile_440x280.png',
      width: 440,
      height: 280
    },
    {
      file: 'marquee_banner_1400x560.svg',
      output: 'marquee_banner_1400x560.png',
      width: 1400,
      height: 560
    },
    {
      file: 'screenshot_1_dom_bloat_1280x800.svg',
      output: 'screenshot_1_dom_bloat_1280x800.png',
      width: 1280,
      height: 800
    },
    {
      file: 'screenshot_2_outreach_engine_1280x800.svg',
      output: 'screenshot_2_outreach_engine_1280x800.png',
      width: 1280,
      height: 800
    },
    {
      file: 'screenshot_3_competitor_vs_1280x800.svg',
      output: 'screenshot_3_competitor_vs_1280x800.png',
      width: 1280,
      height: 800
    }
  ];

  for (const asset of assets) {
    const svgPath = path.resolve(__dirname, asset.file);
    const outputPath = path.resolve(__dirname, asset.output);
    const svgContent = fs.readFileSync(svgPath, 'utf8');

    await page.setViewportSize({ width: asset.width, height: asset.height });
    const htmlContent = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    html, body { width: ${asset.width}px; height: ${asset.height}px; overflow: hidden; background: transparent; }
    svg { width: ${asset.width}px; height: ${asset.height}px; display: block; }
  </style>
</head>
<body>
  ${svgContent}
</body>
</html>`;

    await page.setContent(htmlContent, { waitUntil: 'load' });
    await page.evaluate(() => document.fonts.ready);
    await page.screenshot({ path: outputPath, type: 'png', omitBackground: false });
    const stats = fs.statSync(outputPath);
    console.log(`Rendered: ${asset.output} (${asset.width}x${asset.height}px, ${(stats.size / 1024).toFixed(1)} KB)`);
  }

  await browser.close();
  console.log('All store visual assets rendered successfully.');
}

renderAssets().catch(err => {
  console.error('Asset rendering error:', err);
  process.exit(1);
});
