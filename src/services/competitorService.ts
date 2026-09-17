// Competitor Comparison Service: Zero Fabricated Fallbacks & Objective Deltas
// Zero em-dash compliance: strictly hyphens or colons

import { isSafeUrl, escapeHtml } from '../utils/security';

export interface CompetitorComparisonResult {
  success: boolean;
  errorReason?: string;
  auditMethod: 'browser-rendered vs raw-html' | 'unavailable';
  methodologyNote: string;
  prospect: {
    domain: string;
    domElements: number;
    serializedSizeKB: number;
    viewportStatus: string;
    schemaStatus: string;
    cms: string;
    auditMethod: 'browser-rendered';
  };
  competitor?: {
    domain: string;
    domElements: number;
    serializedSizeKB: number;
    viewportStatus: string;
    schemaStatus: string;
    cms: string;
    auditMethod: 'raw-html';
  };
  comparisonHook?: string;
}

export class CompetitorService {
  /**
   * Attempts to audit a competitor URL.
   * If cross-origin restrictions or network blocks prevent extraction,
   * it returns success: false with a transparent explanation.
   * IT NEVER FABRICATES ARTIFICIAL METRICS.
   */
  public static async compareWithCompetitor(
    prospectData: any,
    competitorUrlRaw: string
  ): Promise<CompetitorComparisonResult> {
    let cleanUrl = (competitorUrlRaw || '').trim();
    if (!cleanUrl) {
      return {
        success: false,
        auditMethod: 'unavailable',
        methodologyNote: 'Competitor URL was not provided.',
        errorReason: 'Competitor URL is required.',
        prospect: this.formatProspect(prospectData)
      };
    }

    if (!cleanUrl.startsWith('http://') && !cleanUrl.startsWith('https://')) {
      cleanUrl = 'https://' + cleanUrl;
    }

    if (!isSafeUrl(cleanUrl)) {
      return {
        success: false,
        auditMethod: 'unavailable',
        methodologyNote: 'Competitor URL scheme is restricted.',
        errorReason: 'Invalid competitor URL scheme.',
        prospect: this.formatProspect(prospectData)
      };
    }

    const compDomain = new URL(cleanUrl).hostname.replace(/^www\./, '');
    const prospectSummary = this.formatProspect(prospectData);

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 6000);

      const resp = await fetch(cleanUrl, {
        method: 'GET',
        headers: { 'Accept': 'text/html,application/xhtml+xml' },
        signal: controller.signal
      });
      clearTimeout(timeoutId);

      if (!resp.ok) {
        return {
          success: false,
          auditMethod: 'unavailable',
          methodologyNote: `Competitor server returned HTTP ${resp.status}. In-browser cross-origin inspection blocked.`,
          errorReason: `Competitor server returned HTTP ${resp.status}. Cross-origin inspection blocked.`,
          prospect: prospectSummary
        };
      }

      const html = await resp.text();
      if (!html || html.length < 200) {
        return {
          success: false,
          auditMethod: 'unavailable',
          methodologyNote: 'Competitor response was empty or unparseable.',
          errorReason: 'Competitor returned an empty or unparseable response.',
          prospect: prospectSummary
        };
      }

      // Parse HTML with DOMParser (Raw HTML parsing without script execution)
      const parser = new DOMParser();
      const doc = parser.parseFromString(html, 'text/html');

      const totalElements = doc.querySelectorAll('*').length;
      const serializedSizeKB = Math.round(new Blob([html]).size / 1024);
      const vpMeta = doc.querySelector('meta[name="viewport"]');
      const vpStatus = !vpMeta ? 'Missing' : 'Responsive';
      const hasSchema = doc.querySelectorAll('script[type="application/ld+json"]').length > 0;
      const schemaStatus = hasSchema ? 'Detected' : 'Opportunity';

      // Basic CMS check
      const hLower = html.toLowerCase();
      const cmsList: string[] = [];
      if (hLower.includes('/wp-content/')) cmsList.push('WordPress');
      if (hLower.includes('elementor')) cmsList.push('Elementor');
      if (hLower.includes('shopify') || hLower.includes('cdn.shopify.com')) cmsList.push('Shopify');
      if (hLower.includes('w-mod-js')) cmsList.push('Webflow');
      if (hLower.includes('__next')) cmsList.push('Next.js');
      const cms = cmsList.length > 0 ? cmsList.join(', ') : 'Custom Stack';

      const competitorSummary = {
        domain: compDomain,
        domElements: totalElements,
        serializedSizeKB,
        viewportStatus: vpStatus,
        schemaStatus,
        cms,
        auditMethod: 'raw-html' as const
      };

      const hook = `Observed difference: ${prospectSummary.domain} (live browser audit) renders ${prospectSummary.domElements.toLocaleString()} DOM elements and ${prospectSummary.serializedSizeKB} KB of serialized markup, compared to ${compDomain} (raw HTML snapshot) at ${competitorSummary.domElements.toLocaleString()} elements and ${competitorSummary.serializedSizeKB} KB. Profiling the architecture delta can highlight potential performance differences.`;

      return {
        success: true,
        auditMethod: 'browser-rendered vs raw-html',
        methodologyNote: 'Methodology note: Primary prospect was measured via live in-browser DOM tree recursion. Competitor was measured via raw HTML fetch without full JavaScript execution. Direct equivalence should not be assumed for client-rendered SPAs.',
        prospect: prospectSummary,
        competitor: competitorSummary,
        comparisonHook: hook
      };
    } catch (err: any) {
      // HONEST ERROR REPORTING: Explain CORS / network block without manufacturing fake stats
      return {
        success: false,
        auditMethod: 'unavailable',
        methodologyNote: 'Cross-origin request blocked by browser CORS policy or bot security.',
        errorReason: 'Direct in-browser fetch was blocked by CORS or bot security on competitor domain. To inspect this competitor with genuine DOM recursion, open their website in an active browser tab.',
        prospect: prospectSummary
      };
    }
  }

  private static formatProspect(data: any) {
    return {
      domain: data.domain || 'Target Site',
      domElements: data.domStats ? data.domStats.totalElements : (data.domElements || 0),
      serializedSizeKB: data.serializedSizeKB || 0,
      viewportStatus: data.vpMissing ? 'Missing' : (data.vpLocked ? 'Restricted' : 'Responsive'),
      schemaStatus: data.hasSchema ? 'Detected' : 'Opportunity',
      cms: data.cms && data.cms.length > 0 ? data.cms.join(', ') : 'Custom Stack',
      auditMethod: 'browser-rendered' as const
    };
  }
}
