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
    externalMetrics?: ExternalMetrics | null
  ): string {
    const agencyName = escapeHtml(agencySettings.agencyName || '');
    const auditorName = escapeHtml(agencySettings.auditorName || 'Technical Auditor');
    const logoUrl = isSafeUrl(agencySettings.logoUrl) ? agencySettings.logoUrl : '';
    const bookingUrl = isSafeUrl(agencySettings.bookingUrl) ? agencySettings.bookingUrl : '';

    const badgeColor = finding.severity === 'critical'
      ? 'background: #fee2e2; color: #991b1b; border-color: #fca5a5;'
      : (finding.severity === 'warning'
        ? 'background: #fef3c7; color: #92400e; border-color: #fcd34d;'
        : (finding.severity === 'healthy'
          ? 'background: #e0f2fe; color: #0369a1; border-color: #7dd3fc;'
          : 'background: #dcfce7; color: #166534; border-color: #86efac;'));

    const domTotal = data.domStats ? data.domStats.totalElements : (data.domElements || 0);
    const domDepth = data.domStats ? data.domStats.maxDepth : 0;
    const serializedKB = data.serializedSizeKB || 0;
    const ttfb = data.ttfbMs !== undefined ? data.ttfbMs : 0;
    const lcpDisplay = data.performance?.lcpDisplay || (data.performance?.lcpMs ? `${data.performance.lcpMs} ms` : 'Not measured');
    const clsDisplay = data.performance?.clsDisplay || (data.performance?.cls !== null && data.performance?.cls !== undefined ? String(data.performance.cls) : 'Not measured');
    const cacheState = data.metadata?.cacheState || data.cacheState || 'network';

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Technical Diagnostic Teardown: ${escapeHtml(domain)}</title>
  <style>
    :root {
      --bg: #F7F4EE;
      --surface: #FFFFFF;
      --text: #20201E;
      --muted: #716C64;
      --border: #DDD7CE;
      --accent: #B76345;
      --dark: #242321;
      --green: #2e7d32;
      --amber: #b45309;
      --red: #c62828;
      --blue: #0284c7;
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
      border-radius: 4px; background: var(--surface);
      border: 1px solid var(--border); text-transform: uppercase; letter-spacing: 0.5px;
    }
    .grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 20px; }
    .stat { background: var(--surface); border: 1px solid var(--border); padding: 14px; border-radius: 6px; }
    .stat-label { font-size: 11px; color: var(--muted); font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
    .stat-val { font-size: 18px; font-weight: 700; color: var(--dark); margin-top: 4px; }
    .stat-val.red { color: var(--red); }
    .stat-val.green { color: var(--green); }
    .stat-val.amber { color: var(--amber); }
    .stat-val.blue { color: var(--blue); }
    .stat-sub { font-size: 11px; color: var(--muted); margin-top: 2px; }
    .card {
      border: 1px solid var(--border); border-radius: 6px;
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
      display: inline-block; background: var(--dark); color: #F7F4EE;
      font-weight: 600; font-size: 12.5px; padding: 8px 20px;
      border-radius: 4px; text-decoration: none; margin-top: 10px;
    }
    .footer {
      margin-top: 36px; font-size: 11.5px; color: var(--muted);
      text-align: center; border-top: 1px solid var(--border); padding-top: 16px;
    }
    @media print {
      body { padding: 0 !important; background: #fff !important; }
      .booking-box { display: none !important; }
    }
  </style>
</head>
<body>
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
      <span style="font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 4px; text-transform: uppercase; ${badgeColor}">${escapeHtml(finding.badge || 'OPPORTUNITY')}</span>
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
    </div>
  </div>

  ${bookingUrl ? `
  <div class="booking-box">
    <div style="font-size: 14px; font-weight: 700; color: var(--dark); margin-bottom: 4px;">Schedule Technical Diagnostic Review</div>
    <p style="font-size: 12.5px; color: var(--muted); margin-bottom: 10px;">Review staging architecture and Core Web Vitals profiling with our engineering team.</p>
    <a href="${escapeHtml(bookingUrl)}" target="_blank" class="booking-btn">Schedule Review Session &rarr;</a>
  </div>` : ''}

  <div class="footer">
    Report generated by ${auditorName}${agencyName ? ' | ' + agencyName : ''} &bull; VitalsSniper PRO Technical Intelligence
  </div>
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
