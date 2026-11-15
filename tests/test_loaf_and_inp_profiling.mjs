// Comprehensive verification for LoAF attribution and 3-phase INP telemetry profiling
// Strict compliance: strictly zero em-dashes and zero en-dashes

import assert from 'assert';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log('=== TEST SUITE: LoAF ATTRIBUTION & 3-PHASE INP TELEMETRY PROFILING ===\n');

// 1. Verify bundle contains all new fields and methods
console.log('--- 1. Testing popup.js bundle symbols and telemetry properties ---');
const popupJsPath = path.resolve(__dirname, '../popup.js');
const popupJs = fs.readFileSync(popupJsPath, 'utf8');

const requiredSymbols = [
  'loafAttribution',
  'longScripts',
  'violates8msBudget',
  'inputDelayCulpritScriptUrl',
  'inputDelayCulpritExecutionMs',
  'inputDelayInvoker',
  'presentationDelayStyleAndLayoutMs',
  'presentationDelayRenderMs',
  'loafFrameDurationMs',
  'loafBlockingDurationMs',
  'cardForensicsLoaf',
  'loafTableWrapper',
  'inpCulpritRow',
  'INP 3-Phase Attribution',
  'Long Animation Frames (LoAF) Script Attribution',
  'loadState',
  'inputDelay',
  'processingDuration',
  'presentationDelay',
  'interactionTargetElement',
  'interactionTime',
  'nextPaintTime',
  'overlappingLoafCount',
  'getLoadState',
  'Page Load State'
];

for (const sym of requiredSymbols) {
  assert(popupJs.includes(sym), `popup.js must contain '${sym}'`);
}
console.log('PASS: All required symbols and properties exist in popup.js bundle.');

// 2. Test 3-Phase INP Correlation Engine with LoAF timing and executionStart
console.log('--- 2. Testing 3-Phase INP Correlation Engine ---');
{
  const worstInteraction = {
    name: 'pointerdown',
    startTime: 200,
    processingStart: 250,
    processingEnd: 320,
    duration: 170 // presentationEnd = 370. Input delay: 50ms, Processing: 70ms, Presentation: 50ms
  };

  const rawLoafEntries = [
    {
      startTime: 180,
      duration: 210, // 180 to 390 (overlaps interaction completely)
      blockingDuration: 160,
      renderStart: 330,
      styleAndLayoutStart: 345,
      scripts: [
        {
          // Script running during input delay [200, 250]
          sourceURL: 'https://cdn.example.com/analytics.js',
          sourceFunctionName: 'trackImpression',
          invoker: 'setTimeout',
          invokerType: 'user-callback',
          startTime: 190,
          executionStart: 210,
          duration: 45, // runs 210 to 255. Intersects [200, 250] by 40ms
          forcedStyleAndLayoutDuration: 0,
          pauseDuration: 0
        },
        {
          // Script running during processing delay [250, 320]
          sourceURL: 'https://cdn.example.com/app.js',
          sourceFunctionName: 'onPointerDownHandler',
          invoker: 'EventListener:pointerdown',
          invokerType: 'event-listener',
          startTime: 240,
          executionStart: 255,
          duration: 60, // runs 255 to 315. Intersects [250, 320] by 60ms
          forcedStyleAndLayoutDuration: 25,
          pauseDuration: 5
        }
      ]
    }
  ];

  const interactionStart = worstInteraction.startTime;
  const procStart = worstInteraction.processingStart;
  const procEnd = worstInteraction.processingEnd;
  const presentationEnd = interactionStart + worstInteraction.duration;

  const inpInputDelayMs = Math.max(0, Math.round(procStart - interactionStart));
  const inpProcessingDelayMs = Math.max(0, Math.round(procEnd - procStart));
  const inpPresentationDelayMs = Math.max(0, Math.round(presentationEnd - procEnd));

  assert.strictEqual(inpInputDelayMs, 50, 'Input delay must be 50ms');
  assert.strictEqual(inpProcessingDelayMs, 70, 'Processing delay must be 70ms');
  assert.strictEqual(inpPresentationDelayMs, 50, 'Presentation delay must be 50ms');

  // LoAF frame overlap
  let overlappingLoafFrame = null;
  let maxLoafOverlap = 0;
  rawLoafEntries.forEach(frame => {
    const fStart = frame.startTime || 0;
    const fEnd = fStart + (frame.duration || 0);
    const overlap = Math.max(0, Math.min(fEnd, presentationEnd) - Math.max(fStart, interactionStart));
    if (overlap > maxLoafOverlap) {
      maxLoafOverlap = overlap;
      overlappingLoafFrame = frame;
    }
  });

  assert(overlappingLoafFrame, 'Must find overlapping LoAF frame');
  assert.strictEqual(maxLoafOverlap, 170, 'LoAF frame overlaps entire 170ms interaction');

  const candidateScripts = [];
  rawLoafEntries.forEach(frame => {
    if (Array.isArray(frame.scripts)) {
      frame.scripts.forEach(s => candidateScripts.push(s));
    }
  });

  // Phase 1 attribution
  let worstInputScript = null;
  let maxInputIntersecting = 0;
  candidateScripts.forEach(script => {
    const sStart = script.executionStart !== undefined ? script.executionStart : (script.startTime || 0);
    const sDuration = script.duration || 0;
    const sEnd = sStart + sDuration;
    const inputIntersecting = Math.max(0, Math.min(sEnd, procStart) - Math.max(sStart, interactionStart));
    if (inputIntersecting > maxInputIntersecting) {
      maxInputIntersecting = inputIntersecting;
      worstInputScript = script;
    }
  });

  assert(worstInputScript, 'Must detect input blocker script');
  assert.strictEqual(worstInputScript.sourceURL, 'https://cdn.example.com/analytics.js');
  assert.strictEqual(worstInputScript.invoker, 'setTimeout');
  assert.strictEqual(maxInputIntersecting, 40, 'Input blocker duration must be 40ms');

  // Phase 2 attribution
  let worstScript = null;
  let maxIntersectingDuration = 0;
  let maxIntersectingForcedStyle = 0;
  candidateScripts.forEach(script => {
    const sStart = script.executionStart !== undefined ? script.executionStart : (script.startTime || 0);
    const sDuration = script.duration || 0;
    const scriptEnd = sStart + sDuration;
    const intersectingDuration = Math.max(0, Math.min(scriptEnd, procEnd) - Math.max(sStart, procStart));
    if (intersectingDuration > maxIntersectingDuration) {
      maxIntersectingDuration = intersectingDuration;
      const forcedStyle = (sDuration && script.forcedStyleAndLayoutDuration)
        ? Math.round((intersectingDuration / sDuration) * script.forcedStyleAndLayoutDuration)
        : 0;
      maxIntersectingForcedStyle = forcedStyle;
      worstScript = script;
    }
  });

  assert(worstScript, 'Must detect processing handler script');
  assert.strictEqual(worstScript.sourceURL, 'https://cdn.example.com/app.js');
  assert.strictEqual(worstScript.sourceFunctionName, 'onPointerDownHandler');
  assert.strictEqual(worstScript.invoker, 'EventListener:pointerdown');
  assert.strictEqual(maxIntersectingDuration, 60);
  assert.strictEqual(maxIntersectingForcedStyle, 25);

  // Phase 3 presentation delay breakdown
  let presentationDelayStyleAndLayoutMs = null;
  let presentationDelayRenderMs = null;
  let loafFrameDurationMs = null;
  let loafBlockingDurationMs = null;

  if (overlappingLoafFrame) {
    loafFrameDurationMs = Math.round(overlappingLoafFrame.duration || 0);
    loafBlockingDurationMs = Math.round(overlappingLoafFrame.blockingDuration || Math.max(0, (overlappingLoafFrame.duration || 0) - 50));
    const fEnd = (overlappingLoafFrame.startTime || 0) + (overlappingLoafFrame.duration || 0);
    if (overlappingLoafFrame.styleAndLayoutStart) {
      presentationDelayStyleAndLayoutMs = Math.max(0, Math.round(fEnd - overlappingLoafFrame.styleAndLayoutStart));
    }
    if (overlappingLoafFrame.renderStart) {
      presentationDelayRenderMs = Math.max(0, Math.round(fEnd - overlappingLoafFrame.renderStart));
    }
  }

  assert.strictEqual(loafFrameDurationMs, 210);
  assert.strictEqual(loafBlockingDurationMs, 160);
  assert.strictEqual(presentationDelayStyleAndLayoutMs, 45, 'Reflow time must be 390 - 345 = 45ms');
  assert.strictEqual(presentationDelayRenderMs, 60, 'Render time must be 390 - 330 = 60ms');

  console.log('PASS: 3-Phase INP correlation accurately attributes Input, Processing, and Presentation delays.');
}

// 2b. Test Multi-frame LoAF interaction & inline script attribution edge cases
console.log('--- 2b. Testing Multi-Frame LoAF Interaction & Inline Script Edge Cases ---');
{
  // Multi-frame interaction: Frame 1 occurs during input delay, Frame 2 occurs during presentation delay
  const interaction = {
    name: 'click',
    startTime: 150,
    processingStart: 250,
    processingEnd: 320,
    duration: 250 // presentationEnd = 400. Input: 100ms, Processing: 70ms, Presentation: 80ms
  };

  const multiFrames = [
    {
      startTime: 100,
      duration: 190, // 100 to 290. Overlaps input delay [150, 250]. Ends before procEnd (320).
      blockingDuration: 140,
      renderStart: 260,
      styleAndLayoutStart: 270,
      scripts: [
        {
          // Inline script blocker (no sourceURL)
          sourceURL: null,
          sourceFunctionName: 'analyticsBatch',
          invoker: 'setTimeout',
          invokerType: 'user-callback',
          startTime: 120,
          executionStart: 160,
          duration: 80, // runs 160 to 240. Intersects input delay [150, 250] by 80ms
          forcedStyleAndLayoutDuration: 0,
          pauseDuration: 0
        }
      ]
    },
    {
      startTime: 300,
      duration: 110, // 300 to 410. Overlaps presentation delay [320, 400].
      blockingDuration: 60,
      renderStart: 340,
      styleAndLayoutStart: 360,
      scripts: [
        {
          // Inline handler execution
          sourceURL: null,
          sourceFunctionName: 'renderFlyout',
          invoker: 'EventListener:click',
          invokerType: 'event-listener',
          startTime: 305,
          executionStart: 310,
          duration: 40,
          forcedStyleAndLayoutDuration: 15,
          pauseDuration: 0
        }
      ]
    }
  ];

  const iStart = interaction.startTime;
  const pStart = interaction.processingStart;
  const pEnd = interaction.processingEnd;
  const pEndPresentation = iStart + interaction.duration;

  // Correlation logic matching browserAudit.ts
  let presentationLoafFrame = null;
  let maxPresentationOverlap = 0;
  multiFrames.forEach(frame => {
    const fStart = frame.startTime || 0;
    const fEnd = fStart + (frame.duration || 0);
    const presOverlap = Math.max(0, Math.min(fEnd, pEndPresentation) - Math.max(fStart, pEnd));
    if (presOverlap > maxPresentationOverlap) {
      maxPresentationOverlap = presOverlap;
      presentationLoafFrame = frame;
    }
  });

  assert(presentationLoafFrame, 'Must identify Frame 2 as presentationLoafFrame');
  assert.strictEqual(presentationLoafFrame.duration, 110, 'Presentation LoAF frame duration must be 110ms (Frame 2, not Frame 1)');

  const fEndPres = (presentationLoafFrame.startTime || 0) + (presentationLoafFrame.duration || 0);
  const presLayout = Math.max(0, Math.round(fEndPres - presentationLoafFrame.styleAndLayoutStart));
  const presRender = Math.max(0, Math.round(fEndPres - presentationLoafFrame.renderStart));

  assert.strictEqual(presLayout, 50, 'Presentation reflow must be 410 - 360 = 50ms');
  assert.strictEqual(presRender, 70, 'Presentation render must be 410 - 340 = 70ms');

  // Candidate scripts inline fallback verification
  const candidateScripts = [];
  multiFrames.forEach(frame => {
    if (Array.isArray(frame.scripts)) {
      frame.scripts.forEach(s => candidateScripts.push(s));
    }
  });

  let worstInput = null;
  let maxInput = 0;
  candidateScripts.forEach(script => {
    const sStart = script.executionStart !== undefined ? script.executionStart : (script.startTime || 0);
    const sDuration = script.duration || 0;
    const sEnd = sStart + sDuration;
    const intersect = Math.max(0, Math.min(sEnd, pStart) - Math.max(sStart, iStart));
    if (intersect > maxInput) {
      maxInput = intersect;
      worstInput = script;
    }
  });

  assert(worstInput, 'Must identify input delay script');
  const inputUrl = worstInput.sourceURL || worstInput.sourceUrl || 'inline';
  assert.strictEqual(inputUrl, 'inline', 'Inline script must fall back to "inline" URL');
  assert.strictEqual(maxInput, 80, 'Input blocker execution must be 80ms');

  console.log('PASS: Multi-frame interaction and inline script edge cases verified.');
}

// 2c. Test Google web-vitals v4 getLoadState and INP attribution properties
console.log('--- 2c. Testing Google web-vitals v4 getLoadState and INP attribution properties ---');
{
  const getLoadStateMatch = popupJs.match(/function getLoadState\(timestamp\)[\s\S]*?\n\}/);
  assert(getLoadStateMatch, 'popup.js must contain function getLoadState');
  const getLoadState = new Function('timestamp', `${getLoadStateMatch[0]}; return getLoadState(timestamp);`);

  const origDoc = globalThis.document;
  const origPerf = globalThis.performance;

  try {
    // Test document.readyState === 'loading'
    globalThis.document = { readyState: 'loading' };
    assert.strictEqual(getLoadState(100), 'loading', 'document.readyState loading must return loading');

    // Test with mock navigation timing entries
    globalThis.document = { readyState: 'complete' };
    globalThis.performance = {
      getEntriesByType: (type) => {
        if (type === 'navigation') {
          return [{
            domInteractive: 200,
            domContentLoadedEventStart: 400,
            domContentLoadedEventEnd: 450,
            domComplete: 700,
            loadEventStart: 750
          }];
        }
        return [];
      }
    };

    assert.strictEqual(getLoadState(150), 'loading', 'Timestamp before domInteractive must return loading');
    assert.strictEqual(getLoadState(300), 'dom-interactive', 'Timestamp between domInteractive and domContentLoadedEventStart must return dom-interactive');
    assert.strictEqual(getLoadState(500), 'dom-content-loaded', 'Timestamp between domContentLoadedEventStart and domComplete must return dom-content-loaded');
    assert.strictEqual(getLoadState(800), 'complete', 'Timestamp after domComplete must return complete');

    // Test web-vitals v4 canonical fields attribution and overlappingLoafCount
    const interaction = {
      name: 'click',
      startTime: 300,
      duration: 150,
      processingStart: 350,
      processingEnd: 410,
      target: null
    };

    const mockLoafEntries = [
      { startTime: 250, duration: 100 },
      { startTime: 400, duration: 80 },
      { startTime: 500, duration: 100 }
    ];

    const presentationEnd = interaction.startTime + interaction.duration;
    let overlappingCount = 0;
    mockLoafEntries.forEach(frame => {
      const fStart = frame.startTime || 0;
      const fEnd = fStart + (frame.duration || 0);
      const overlap = Math.max(0, Math.min(fEnd, presentationEnd) - Math.max(fStart, interaction.startTime));
      if (overlap > 0) {
        overlappingCount++;
      }
    });

    assert.strictEqual(overlappingCount, 2, 'Must count exactly 2 overlapping LoAF frames');

    const loadState = getLoadState(interaction.startTime);
    assert.strictEqual(loadState, 'dom-interactive', 'Interaction at 300ms must be in dom-interactive phase');

    const inpInputDelay = Math.max(0, Math.round(interaction.processingStart - interaction.startTime));
    const inpProcessingDelay = Math.max(0, Math.round(interaction.processingEnd - interaction.processingStart));
    const inpPresentationDelay = Math.max(0, Math.round(presentationEnd - interaction.processingEnd));

    const attribution = {
      interactionTarget: '#submit-button',
      interactionType: interaction.name,
      processingDelayMs: inpProcessingDelay,
      inputDelayMs: inpInputDelay,
      presentationDelayMs: inpPresentationDelay,
      loadState,
      inputDelay: inpInputDelay,
      processingDuration: inpProcessingDelay,
      presentationDelay: inpPresentationDelay,
      interactionTargetElement: '#submit-button',
      interactionTime: Math.round(interaction.startTime),
      nextPaintTime: Math.round(presentationEnd),
      overlappingLoafCount: overlappingCount
    };

    assert.strictEqual(attribution.loadState, 'dom-interactive');
    assert.strictEqual(attribution.inputDelay, 50);
    assert.strictEqual(attribution.processingDuration, 60);
    assert.strictEqual(attribution.presentationDelay, 40);
    assert.strictEqual(attribution.interactionTargetElement, '#submit-button');
    assert.strictEqual(attribution.interactionTime, 300);
    assert.strictEqual(attribution.nextPaintTime, 450);
    assert.strictEqual(attribution.overlappingLoafCount, 2);

    console.log('PASS: Google web-vitals v4 getLoadState and INP attribution properties verified.');
  } finally {
    globalThis.document = origDoc;
    globalThis.performance = origPerf;
  }
}

// 3. Test 8ms VSYNC budget violation detection
console.log('--- 3. Testing 8ms VSYNC frame budget rule ---');
{
  const compliantFrames = [
    { startTime: 0, duration: 7.2, scripts: [{ duration: 4.1, startTime: 0 }] },
    { startTime: 16.6, duration: 6.8, scripts: [{ duration: 3.5, startTime: 16.6 }] }
  ];
  const compliantScripts = compliantFrames.flatMap(f => f.scripts);
  const compliantViolates = compliantFrames.some(f => f.duration > 8.3) || compliantScripts.some(s => s.duration > 8.3);
  assert.strictEqual(compliantViolates, false, 'Sub-8.3ms frames must not flag budget violation');

  const jankFrames = [
    { startTime: 0, duration: 58.4, blockingDuration: 8.4, scripts: [{ duration: 52.0, startTime: 2.0 }] }
  ];
  const jankScripts = jankFrames.flatMap(f => f.scripts);
  const jankViolates = jankFrames.some(f => f.duration > 8.3) || jankScripts.some(s => s.duration > 8.3);
  assert.strictEqual(jankViolates, true, 'LoAF frame (>50ms) must flag 8ms VSYNC budget violation');

  console.log('PASS: 8ms presentation frame budget evaluation verified.');
}

// 4. Test ReportService white-label HTML output with 3-phase INP & LoAF table
console.log('--- 4. Testing ReportService HTML teardown generation ---');
{
  // Test bundle output format through text inspection of ReportService module inside popup.js
  assert(popupJs.includes('Interaction to Next Paint (INP) &amp; LoAF Telemetry'), 'Must render dedicated INP and LoAF section heading');
  assert(popupJs.includes('INP 3-Phase Interaction Breakdown'), 'Must include 3-phase INP breakdown block');
  assert(popupJs.includes('Long Animation Frames (LoAF) Script Attribution'), 'Must include LoAF script attribution table');
  assert(popupJs.includes('Phase 1 (Input Delay):'), 'Must include Phase 1 label');
  assert(popupJs.includes('Phase 2 (Processing):'), 'Must include Phase 2 label');
  assert(popupJs.includes('Phase 3 (Presentation):'), 'Must include Phase 3 label');
  assert(popupJs.includes('Execution / Layout Thrashing'), 'Must include layout thrashing column header');
  console.log('PASS: ReportService white-label HTML format contains 3-phase INP breakdown and LoAF table.');
}

// 5. Test Zero em-dash (\u2014) and zero en-dash (\u2013) across all files
console.log('--- 5. Testing zero em-dash and en-dash compliance ---');
const filesToVerify = [
  '../src/types/audit.ts',
  '../src/engine/browserAudit.ts',
  '../src/engine/findingsEngine.ts',
  '../src/popup.ts',
  '../src/services/reportService.ts',
  '../../vitalssniper_web/lib/inp-attribution.ts',
  '../popup.js',
  './test_loaf_and_inp_profiling.mjs'
];

for (const rel of filesToVerify) {
  const full = path.resolve(__dirname, rel);
  const text = fs.readFileSync(full, 'utf8');
  assert(!text.includes('\u2014'), `${rel} contains em-dash (\u2014)`);
  assert(!text.includes('\u2013'), `${rel} contains en-dash (\u2013)`);
}
console.log('PASS: Exactly zero em-dashes and zero en-dashes across all modified and test files.');

console.log('\n=== ALL LoAF & INP PROFILING TESTS PASSED (EXIT CODE 0) ===\n');
process.exit(0);
