// Report Service: 1-Page Printable Teardown Dossier
// Strict compliance with WEBAUDITS_RULES.md design tokens and security invariants
// Zero em-dash compliance: strictly hyphens or colons

import { escapeHtml, isSafeUrl } from '../utils/security';
import { AgencySettings } from '../types/pipeline';
import { Finding } from '../types/findings';
import { ExternalMetrics } from '../types/audit';

export class ReportService {
  public static generateTeardownHtml(
    domain: string,
    currentUrl: string,
    score: number,
    data: any,
    finding: Finding,
    agencySettings: AgencySettings,
    externalMetrics?: ExternalMetrics | null,
    isPro: boolean = false
  ): string {
    const agencyName = isPro ? escapeHtml(agencySettings.agencyName || '') : '';
    const auditorName = isPro ? escapeHtml(agencySettings.auditorName || 'Technical Auditor') : 'WebAudits.pro';
    const logoUrl = isPro && isSafeUrl(agencySettings.logoUrl) ? agencySettings.logoUrl : '';
    const bookingUrl = isPro && isSafeUrl(agencySettings.bookingUrl) ? agencySettings.bookingUrl : '';

    const badgeColor = finding.severity === 'critical'
      ? 'background: #FDF1F0; color: #A8231B; border-color: #F7BDB9;'
      : (finding.severity === 'warning'
        ? 'background: #FEF7EA; color: #8A5308; border-color: #F7DCA8;'
        : (finding.severity === 'healthy'
          ? 'background: #EAF2F8; color: #1A5276; border-color: #AED6F1;'
          : 'background: #EAF7EE; color: #1B6E38; border-color: #BCE6C8;'));

    const domTotal = data.domStats ? data.domStats.totalElements : (data.domElements || 0);
    const domDepth = data.domStats ? data.domStats.maxDepth : 0;
    const serializedKB = data.serializedSizeKB || 0;
    const ttfb = data.ttfbMs !== undefined ? data.ttfbMs : 0;
    const lcpDisplay = data.performance?.lcpDisplay || (data.performance?.lcpMs ? `${data.performance.lcpMs} ms` : 'Not measured');
    const clsDisplay = data.performance?.clsDisplay || (data.performance?.cls !== null && data.performance?.cls !== undefined ? String(data.performance.cls) : 'Not measured');
    const cacheState = data.metadata?.cacheState || data.cacheState || 'network';

    const inpAttr = data.performance?.inpAttribution;
    const loafAttr = data.performance?.loafAttribution || data.loafAttribution;
    const hasInpOrLoaf = Boolean(data.performance?.inpObserved || (loafAttr && loafAttr.longScripts && loafAttr.longScripts.length > 0));

    let telemetryCardHtml = '';
    if (hasInpOrLoaf) {
      let inpBreakdownHtml = '';
      if (data.performance?.inpObserved && inpAttr) {
        const inputBlocker = inpAttr.inputDelayCulpritScriptUrl
          ? `Blocker: <code>${escapeHtml(inpAttr.inputDelayCulpritScriptUrl.split('/').pop() || '')}</code> (${inpAttr.inputDelayCulpritExecutionMs || 0}ms${inpAttr.inputDelayInvoker ? ', ' + escapeHtml(inpAttr.inputDelayInvoker) : ''})`
          : ((inpAttr.inputDelayMs || 0) > 0 ? 'Queue latency (unattributed main-thread contention)' : 'Queue clear');
        const handlerScript = inpAttr.culpritScriptUrl
          ? `Handler: ${escapeHtml(inpAttr.culpritFunctionName || 'anonymous')} in <code>${escapeHtml(inpAttr.culpritScriptUrl.split('/').pop() || '')}</code> (${inpAttr.culpritExecutionMs || 0}ms exec, ${inpAttr.culpritForcedStyleMs || 0}ms forced reflow${inpAttr.invoker ? ', ' + escapeHtml(inpAttr.invoker) : ''})`
          : 'Event processing';
        const presentationInfo = inpAttr.presentationDelayStyleAndLayoutMs !== null && inpAttr.presentationDelayStyleAndLayoutMs !== undefined
          ? `Reflow: ${inpAttr.presentationDelayStyleAndLayoutMs}ms | Render: ${inpAttr.presentationDelayRenderMs || 0}ms`
          : 'Presentation rendering';
        const loafInfo = inpAttr.loafFrameDurationMs
          ? ` &bull; LoAF: ${inpAttr.loafFrameDurationMs}ms frame (${inpAttr.loafBlockingDurationMs || 0}ms blocking)`
          : '';

        inpBreakdownHtml = `
          <div style="margin-bottom: 12px; padding: 10px; background: #fafafa; border: 1px solid var(--border); border-radius: 8px;">
            <div style="font-weight: 700; font-size: 12px; color: var(--dark); margin-bottom: 6px;">
              INP 3-Phase Interaction Breakdown (${data.performance.inpMs || 0} ms on ${escapeHtml(inpAttr.interactionTarget || 'Interactive Element')})
            </div>
            <div style="font-size: 11.5px; line-height: 1.6; color: var(--text);">
              <div><strong>Phase 1 (Input Delay):</strong> ${inpAttr.inputDelayMs ?? 0}ms &bull; ${inputBlocker}</div>
              <div><strong>Phase 2 (Processing):</strong> ${inpAttr.processingDelayMs ?? 0}ms &bull; ${handlerScript}</div>
              <div><strong>Phase 3 (Presentation):</strong> ${inpAttr.presentationDelayMs ?? 0}ms &bull; ${presentationInfo}${loafInfo}</div>
            </div>
          </div>
        `;
      }

      let loafTableHtml = '';
      if (loafAttr && loafAttr.longScripts && loafAttr.longScripts.length > 0) {
        const budgetText = loafAttr.violates8msBudget ? ' <span style="color:var(--amber); font-weight:600;">(8ms VSYNC Budget Exceeded)</span>' : '';
        let scriptRows = '';
        loafAttr.longScripts.slice(0, 5).forEach((s: any) => {
          const file = s.scriptUrl ? (s.scriptUrl.split('/').pop() || s.scriptUrl) : 'inline';
          const fn = s.functionName ? `fn: ${escapeHtml(s.functionName)}` : (s.invoker ? `invoker: ${escapeHtml(s.invoker)}` : '');
          const reflow = s.forcedStyleAndLayoutMs > 0 ? `<span style="color:var(--amber); font-weight:600;">[Reflow: ${s.forcedStyleAndLayoutMs}ms]</span>` : '';
          const block = s.blockingDurationMs > 0 ? ` (${s.blockingDurationMs}ms block)` : '';
          scriptRows += `
            <tr style="border-bottom: 1px solid var(--border);">
              <td style="padding: 6px 8px; font-size: 11px;">
                <div style="font-weight: 600;">${escapeHtml(file)}</div>
                ${fn ? `<div style="font-size: 10px; color: var(--muted);">${fn}</div>` : ''}
              </td>
              <td style="padding: 6px 8px; font-size: 11px; text-align: right; font-weight: 700; color: var(--red); white-space: nowrap;">
                ${s.executionDurationMs}ms${block} ${reflow}
              </td>
            </tr>
          `;
        });

        loafTableHtml = `
          <div style="margin-top: 10px;">
            <div style="font-weight: 700; font-size: 12px; color: var(--dark); margin-bottom: 6px;">
              Long Animation Frames (LoAF) Script Attribution${budgetText}
            </div>
            <table style="width: 100%; border-collapse: collapse; background: #fafafa; border: 1px solid var(--border); border-radius: 6px;">
              <thead>
                <tr style="border-bottom: 1px solid var(--border); background: #f0f0f0; font-size: 10px; text-transform: uppercase; color: var(--muted);">
                  <th style="padding: 6px 8px; text-align: left;">Script / Invoker</th>
                  <th style="padding: 6px 8px; text-align: right;">Execution / Layout Thrashing</th>
                </tr>
              </thead>
              <tbody>
                ${scriptRows}
              </tbody>
            </table>
          </div>
        `;
      }

      telemetryCardHtml = `
        <div class="card">
          <div class="card-heading">Interaction to Next Paint (INP) &amp; LoAF Telemetry</div>
          ${inpBreakdownHtml}
          ${loafTableHtml}
        </div>
      `;
    }

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Technical Diagnostic Teardown: ${escapeHtml(domain)}</title>
  <style>
    :root {
      --bg: #f7f7f7;
      --surface: #ffffff;
      --text: #1a1a1a;
      --muted: #5e5e5e;
      --border: #e3e3e3;
      --accent: #e63946;
      --dark: #1a1a1a;
      --green: #1b6e38;
      --amber: #8a5308;
      --red: #a8231b;
      --blue: #1a5276;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      padding: 40px 24px;
      color: var(--text);
      background-color: var(--bg);
      max-width: 820px;
      margin: auto;
      line-height: 1.55;
      -webkit-font-smoothing: antialiased;
    }
    .header {
      border-bottom: 2px solid var(--border);
      padding-bottom: 18px;
      margin-bottom: 24px;
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
    }
    .title { font-size: 20px; font-weight: 700; color: var(--dark); letter-spacing: -0.3px; }
    .meta { color: var(--muted); font-size: 12px; margin-top: 4px; }
    .badge {
      font-size: 11px; font-weight: 600; padding: 5px 10px;
      border-radius: 999px; background: var(--surface);
      border: 1px solid var(--border); text-transform: uppercase; letter-spacing: 0.5px;
    }
    .grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 20px; }
    .stat { background: var(--surface); border: 1px solid var(--border); padding: 14px; border-radius: 12px; }
    .stat-label { font-size: 11px; color: var(--muted); font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
    .stat-val { font-size: 18px; font-weight: 700; color: var(--dark); margin-top: 4px; }
    .stat-val.red { color: var(--red); }
    .stat-val.green { color: var(--green); }
    .stat-val.amber { color: var(--amber); }
    .stat-val.blue { color: var(--blue); }
    .stat-sub { font-size: 11px; color: var(--muted); margin-top: 2px; }
    .card {
      border: 1px solid var(--border); border-radius: 12px;
      padding: 18px; margin-bottom: 16px; background: var(--surface);
    }
    .card-heading {
      font-size: 12px; font-weight: 700; color: var(--dark);
      margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px;
    }
    .flaw-box { border-left: 3px solid var(--accent); padding-left: 12px; }
    .flaw-title { font-size: 14px; font-weight: 600; color: var(--dark); margin-bottom: 4px; }
    .flaw-evidence { font-size: 12.5px; color: var(--text); margin-bottom: 6px; }
    .flaw-impact { font-size: 12.5px; color: var(--muted); }
    .remediation-list { margin: 0; padding-left: 18px; font-size: 13px; line-height: 1.65; color: var(--text); }
    .audit-conditions {
      font-size: 11px; color: var(--muted); border-top: 1px dashed var(--border);
      padding-top: 10px; margin-top: 14px; display: grid; grid-template-columns: repeat(2, 1fr); gap: 6px;
    }
    .booking-box {
      border: 1px solid var(--border); background: var(--surface);
      text-align: center; padding: 20px; border-radius: 6px; margin-top: 16px;
    }
    .booking-btn {
      display: inline-block; background: var(--dark); color: #ffffff;
      font-weight: 600; font-size: 12.5px; padding: 8px 20px;
      border-radius: 6px; text-decoration: none; margin-top: 10px;
    }
    .footer {
      margin-top: 36px; font-size: 11.5px; color: var(--muted);
      text-align: center; border-top: 1px solid var(--border); padding-top: 16px;
    }
    .action-bar {
      background: var(--dark);
      color: #ffffff;
      padding: 10px 16px;
      border-radius: 8px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 24px;
      box-shadow: 0 1px 3px rgba(26, 26, 26, 0.1);
    }
    .action-bar-title {
      font-size: 12px;
      font-weight: 600;
      letter-spacing: 0.3px;
    }
    .action-bar-btn {
      background: #ffffff;
      color: var(--dark);
      border: 1px solid var(--border);
      font-size: 11px;
      font-weight: 700;
      padding: 6px 14px;
      border-radius: 6px;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      text-decoration: none;
      transition: background 0.15s ease;
    }
    .action-bar-btn:hover {
      background: #f5f5f5;
    }
    .action-bar-btn.secondary {
      background: rgba(255, 255, 255, 0.15);
      color: #ffffff;
      border: 1px solid rgba(255, 255, 255, 0.2);
    }
    .action-bar-btn.secondary:hover {
      background: rgba(255, 255, 255, 0.25);
    }
    @media print {
      body { padding: 0 !important; background: #fff !important; }
      .no-print { display: none !important; }
      .booking-box { display: none !important; }
    }
  </style>
</head>
<body>
  <div class="action-bar no-print">
    <div class="action-bar-title">Technical Teardown Dossier: ${escapeHtml(domain)}</div>
    <div style="display: flex; gap: 8px; align-items: center;">
      <button class="action-bar-btn" onclick="window.print()">Print / Save as PDF</button>
      <button class="action-bar-btn secondary" id="btnCopySummary" data-summary="${escapeHtml(`Technical Audit for ${domain}: Score ${score}/100. Primary Finding: ${finding.title} (${finding.explanation})`)}">Copy Summary</button>
    </div>
  </div>
  <div class="header">
    <div>
      ${logoUrl ? `<img src="${escapeHtml(logoUrl)}" alt="${agencyName || 'Agency Logo'}" style="max-height: 40px; max-width: 200px; object-fit: contain; margin-bottom: 8px; display: block;">` : ''}
      <div class="title">${agencyName ? agencyName + ' : ' : ''}Technical Architecture Diagnostic</div>
      <div class="meta">Target: ${escapeHtml(domain)} &bull; VitalsSniper Proprietary Heuristic: ${score}/100 &bull; Generated: ${new Date().toLocaleDateString()}</div>
    </div>
    <div class="badge" style="${badgeColor}">${escapeHtml(finding.badge || 'TECHNICAL AUDIT')}</div>
  </div>

  <div class="grid">
    <div class="stat">
      <div class="stat-label">DOM Hierarchy</div>
      <div class="stat-val ${domTotal > 2200 ? 'red' : 'green'}">
        ${domTotal.toLocaleString()} Elements
      </div>
      <div class="stat-sub">Max Depth: ${domDepth} levels</div>
    </div>
    <div class="stat">
      <div class="stat-label">Serialized Markup</div>
      <div class="stat-val ${serializedKB > 80 ? 'amber' : 'green'}">${serializedKB} KB</div>
      <div class="stat-sub">In-Memory DOM Size</div>
    </div>
    <div class="stat">
      <div class="stat-label">Mobile Viewport</div>
      <div class="stat-val ${data.vpMissing || data.vpLocked ? 'amber' : 'green'}">${data.vpMissing ? 'MISSING' : (data.vpLocked ? 'RESTRICTED' : 'RESPONSIVE')}</div>
      <div class="stat-sub">WCAG 1.4.4 Advisory</div>
    </div>
    <div class="stat">
      <div class="stat-label">Structured Data</div>
      <div class="stat-val ${data.hasSchema ? 'green' : 'amber'}">${data.hasSchema ? 'DETECTED' : 'OPPORTUNITY'}</div>
      <div class="stat-sub">Schema.org JSON-LD</div>
    </div>
    <div class="stat">
      <div class="stat-label">Largest Contentful Paint</div>
      <div class="stat-val">${escapeHtml(lcpDisplay)}</div>
      <div class="stat-sub">In-Page PerformanceObserver</div>
    </div>
    <div class="stat">
      <div class="stat-label">Observed Latency (TTFB)</div>
      <div class="stat-val ${ttfb > 500 ? 'amber' : 'green'}">${ttfb > 0 ? ttfb + ' ms' : 'OPTIMAL'}</div>
      <div class="stat-sub">${cacheState === 'cache' ? 'Cached Response' : (cacheState === 'service-worker' ? 'Service Worker' : 'Navigation Start to Response')}</div>
    </div>
  </div>

  ${externalMetrics ? `
  <div class="card" style="margin-bottom: 16px;">
    <div class="card-heading">Authoritative Lab Telemetry (Google PageSpeed / Lighthouse Mobile)</div>
    <div class="grid" style="margin-bottom: 0;">
      <div class="stat">
        <div class="stat-label">Lighthouse Mobile</div>
        <div class="stat-val ${externalMetrics.lighthouseScore >= 80 ? 'green' : (externalMetrics.lighthouseScore >= 50 ? 'amber' : 'red')}">${externalMetrics.lighthouseScore}/100</div>
        <div class="stat-sub">Synthetic Mobile Lab Run</div>
      </div>
      <div class="stat">
        <div class="stat-label">Lab LCP (Simulated)</div>
        <div class="stat-val">${escapeHtml(externalMetrics.lab?.lcpDisplay || externalMetrics.lcpDisplay || 'N/A')}</div>
        <div class="stat-sub">Throttled 4G Network</div>
      </div>
      <div class="stat">
        <div class="stat-label">Lab CLS (Simulated)</div>
        <div class="stat-val">${escapeHtml(externalMetrics.lab?.clsDisplay || externalMetrics.clsDisplay || 'N/A')}</div>
        <div class="stat-sub">Target budget: &lt; 0.10</div>
      </div>
    </div>
    ${externalMetrics.field && externalMetrics.field.available ? `
    <div style="margin-top: 10px; padding-top: 10px; border-top: 1px solid var(--border); font-size: 11px; color: var(--muted);">
      <strong>Real-World Field Telemetry (Chrome UX Report 75th Percentile):</strong>
      LCP: ${escapeHtml(externalMetrics.field.lcpDisplay)} &bull; CLS: ${escapeHtml(externalMetrics.field.clsDisplay)} &bull; INP: ${escapeHtml(externalMetrics.field.inpDisplay)}
    </div>` : ''}
  </div>` : ''}

  <div class="card">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
      <div class="card-heading" style="margin-bottom: 0;">Primary Diagnostic Finding</div>
      <span style="font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 999px; text-transform: uppercase; ${badgeColor}">${escapeHtml(finding.badge || 'OPPORTUNITY')}</span>
    </div>
    <div class="flaw-box">
      <div class="flaw-title">${escapeHtml(finding.title)}</div>
      <div class="flaw-evidence">
        <strong>Observed Evidence:</strong>
        ${finding.evidence.map(ev => `${escapeHtml(ev.label)}: <strong>${escapeHtml(String(ev.value))}</strong>`).join(' &bull; ')}
      </div>
      <p class="flaw-impact">${escapeHtml(finding.explanation)}</p>
    </div>
  </div>
  ${telemetryCardHtml}
  <div class="card">
    <div class="card-heading">Recommended Investigation Points</div>
    <ul class="remediation-list">
      ${(finding.improvements || []).map(imp => `<li>${escapeHtml(imp)}</li>`).join('')}
    </ul>
    <div class="audit-conditions">
      <span><strong>Target URL:</strong> ${escapeHtml(currentUrl)}</span>
      <span><strong>Audited At:</strong> ${new Date().toISOString()}</span>
      <span><strong>Methodology:</strong> In-Browser DOM and Navigation Timing Profiling</span>
      <span><strong>Measurement Source:</strong> PerformanceObserver &amp; DOM Hierarchy</span>
      <span><strong>Viewport Size:</strong> ${data.metadata?.viewportWidth || 390}x${data.metadata?.viewportHeight || 844} px</span>
      <span><strong>Cache State:</strong> ${escapeHtml(cacheState)}</span>
      ${data.performance?.lcpElementSelector ? `<span><strong>LCP Element:</strong> ${escapeHtml(data.performance.lcpElementSelector)}</span>` : ''}
      ${(data.performance?.lcpTtfbMs !== undefined && data.performance?.lcpTtfbMs !== null) ? `<span><strong>LCP Subparts:</strong> TTFB: ${data.performance.lcpTtfbMs}ms | Load Delay: ${data.performance.lcpLoadDelayMs ?? 0}ms | Load Duration: ${data.performance.lcpLoadDurationMs ?? 0}ms | Render Delay: ${data.performance.lcpRenderDelayMs ?? 0}ms</span>` : ''}
      ${data.performance?.inpObserved ? `<span><strong>INP Interaction:</strong> ${escapeHtml(data.performance.inpTarget || 'Interaction Target')} (${data.performance.inpDisplay || data.performance.inpMs + 'ms'} - Input Delay: ${data.performance.inpInputDelayMs ?? 0}ms, Processing: ${data.performance.inpProcessingDelayMs ?? 0}ms, Presentation: ${data.performance.inpPresentationDelayMs ?? 0}ms)</span>` : ''}
      ${(data.performance?.clsSessionScore !== undefined && data.performance?.clsSessionScore !== null) ? `<span><strong>CLS Session Score:</strong> ${data.performance.clsSessionScore} (Canonical Session Window${data.performance?.clsAttribution?.largestShiftTarget ? ' | Max Shift: ' + escapeHtml(data.performance.clsAttribution.largestShiftTarget) : ''})</span>` : ''}
    </div>
  </div>

  ${bookingUrl ? `
  <div class="booking-box">
    <div style="font-size: 14px; font-weight: 700; color: var(--dark); margin-bottom: 4px;">Schedule Technical Diagnostic Review</div>
    <p style="font-size: 12.5px; color: var(--muted); margin-bottom: 10px;">Review staging architecture and Core Web Vitals profiling with our engineering team.</p>
    <a href="${escapeHtml(bookingUrl)}" target="_blank" class="booking-btn">Schedule Review Session &rarr;</a>
  </div>` : ''}

  <div class="footer">
    ${isPro ? `Report generated by ${auditorName}${agencyName ? ' | ' + agencyName : ''} &bull; VitalsSniper PRO Technical Intelligence` : 'Report generated by WebAudits.pro | VitalsSniper Inspector &bull; https://webaudits.pro'}
  </div>
  <script>
    (function () {
      var btn = document.getElementById('btnCopySummary');
      if (!btn) return;
      btn.addEventListener('click', function () {
        var text = btn.dataset ? (btn.dataset.summary || '') : (btn.getAttribute('data-summary') || '');
        if (!navigator.clipboard || !navigator.clipboard.writeText) return;
        navigator.clipboard.writeText(text).then(function () {
          btn.innerText = 'Summary Copied';
          setTimeout(function () { btn.innerText = 'Copy Summary'; }, 2000);
        });
      });
    })();
  </script>
</body>
</html>`;
  }

  public static exportReport(htmlContent: string): void {
    const blob = new Blob([htmlContent], { type: 'text/html;charset=utf-8' });
    const reportUrl = URL.createObjectURL(blob);
    if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.create) {
      chrome.tabs.create({ url: reportUrl }, () => {
        setTimeout(() => URL.revokeObjectURL(reportUrl), 60000);
      });
    } else {
      window.open(reportUrl, '_blank');
      setTimeout(() => URL.revokeObjectURL(reportUrl), 60000);
    }
  }
}
