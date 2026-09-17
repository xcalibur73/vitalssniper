// External Audit Engine: Google PageSpeed Insights v5 REST API Client
// Strictly separates synthetic lab benchmarks (Lighthouse) from 28-day field telemetry (CrUX)
// Zero em-dash compliance: strictly hyphens or colons

import { ExternalMetrics, LabMetrics, FieldMetrics } from '../types/audit';
import { isSafeUrl } from '../utils/security';

export class ExternalAudit {
  public static async runPSI(targetUrl: string, apiKey: string = ''): Promise<ExternalMetrics | null> {
    if (!targetUrl || !isSafeUrl(targetUrl)) return null;

    try {
      let endpoint = `https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=${encodeURIComponent(targetUrl)}&strategy=mobile`;
      if (apiKey && typeof apiKey === 'string' && apiKey.trim().length > 0) {
        endpoint += `&key=${encodeURIComponent(apiKey.trim())}`;
      }

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 14000);

      const resp = await fetch(endpoint, {
        method: 'GET',
        headers: { 'Accept': 'application/json' },
        signal: controller.signal
      });
      clearTimeout(timeoutId);

      if (!resp.ok) {
        console.warn(`PageSpeed API returned HTTP ${resp.status}`);
        return null;
      }

      const data = await resp.json();
      const lighthouse = data.lighthouseResult || {};
      const categories = lighthouse.categories || {};
      const audits = lighthouse.audits || {};
      const loadingExp = data.loadingExperience || {};
      const cruxMetrics = loadingExp.metrics || {};

      // 1. Synthetic Lab Telemetry (Simulated Throttled Mobile Run)
      const lcpAudit = audits['largest-contentful-paint'] || {};
      const clsAudit = audits['cumulative-layout-shift'] || {};
      const tbtAudit = audits['total-blocking-time'] || {};
      const fcpAudit = audits['first-contentful-paint'] || {};
      const speedIndexAudit = audits['speed-index'] || {};

      const lab: LabMetrics = {
        lighthouseScore: Math.round((categories.performance?.score || 0) * 100),
        seoScore: Math.round((categories.seo?.score || 0) * 100),
        accessibilityScore: Math.round((categories.accessibility?.score || 0) * 100),
        bestPracticesScore: Math.round((categories['best-practices']?.score || 0) * 100),
        lcpMs: lcpAudit.numericValue ? Math.round(lcpAudit.numericValue) : null,
        lcpDisplay: lcpAudit.displayValue || (lcpAudit.numericValue ? `${(lcpAudit.numericValue / 1000).toFixed(1)} s (Lab)` : 'N/A'),
        clsScore: clsAudit.numericValue !== undefined ? parseFloat(clsAudit.numericValue.toFixed(3)) : null,
        clsDisplay: clsAudit.displayValue || (clsAudit.numericValue !== undefined ? clsAudit.numericValue.toFixed(2) : 'N/A'),
        tbtMs: tbtAudit.numericValue ? Math.round(tbtAudit.numericValue) : null,
        tbtDisplay: tbtAudit.displayValue || (tbtAudit.numericValue ? `${Math.round(tbtAudit.numericValue)} ms` : 'N/A'),
        fcpMs: fcpAudit.numericValue ? Math.round(fcpAudit.numericValue) : null,
        fcpDisplay: fcpAudit.displayValue || (fcpAudit.numericValue ? `${(fcpAudit.numericValue / 1000).toFixed(1)} s` : 'N/A'),
        speedIndexMs: speedIndexAudit.numericValue ? Math.round(speedIndexAudit.numericValue) : null
      };

      // 2. Real-World Field Telemetry (CrUX 28-day Aggregated Data)
      const hasCruxData = Boolean(cruxMetrics && Object.keys(cruxMetrics).length > 0);
      const cruxLcp = cruxMetrics['LARGEST_CONTENTFUL_PAINT_MS'];
      const cruxCls = cruxMetrics['CUMULATIVE_LAYOUT_SHIFT_SCORE'];
      const cruxInp = cruxMetrics['INTERACTION_TO_NEXT_PAINT'];
      const cruxFcp = cruxMetrics['FIRST_CONTENTFUL_PAINT_MS'];

      const field: FieldMetrics = {
        available: hasCruxData,
        lcpMs: cruxLcp ? cruxLcp.percentile : null,
        lcpDisplay: cruxLcp ? `${(cruxLcp.percentile / 1000).toFixed(1)} s (Field 75th %)` : 'Insufficient Field Data',
        clsScore: cruxCls ? cruxCls.percentile / 100 : null,
        clsDisplay: cruxCls ? `${(cruxCls.percentile / 100).toFixed(2)} (Field 75th %)` : 'Insufficient Field Data',
        inpMs: cruxInp ? cruxInp.percentile : null,
        inpDisplay: cruxInp ? `${cruxInp.percentile} ms (Field 75th %)` : 'Insufficient Field Data',
        fcpMs: cruxFcp ? cruxFcp.percentile : null,
        fcpDisplay: cruxFcp ? `${(cruxFcp.percentile / 1000).toFixed(1)} s (Field 75th %)` : 'Insufficient Field Data'
      };

      return {
        // Flat legacy convenience properties (strictly tied to Lab to prevent mixing)
        lighthouseScore: lab.lighthouseScore,
        seoScore: lab.seoScore,
        accessibilityScore: lab.accessibilityScore,
        bestPracticesScore: lab.bestPracticesScore,
        lcpMs: lab.lcpMs,
        lcpDisplay: lab.lcpDisplay,
        clsScore: lab.clsScore,
        clsDisplay: lab.clsDisplay,
        inpMs: field.inpMs,
        inpDisplay: field.inpDisplay,
        fcpMs: lab.fcpMs,
        fcpDisplay: lab.fcpDisplay,
        auditedAt: new Date().toISOString(),
        lab,
        field
      };
    } catch (e) {
      console.warn('ExternalAudit PSI fetch failed or timed out:', e);
      return null;
    }
  }
}
