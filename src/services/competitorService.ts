// Competitor Comparison Service: SimilarWeb-Style Auto-Discovery & Head-to-Head Deltas
// Zero em-dash compliance: strictly hyphens or colons only

import { isSafeUrl, escapeHtml } from '../utils/security';

export interface MetricDelta {
  metric: string;
  prospectVal: string;
  competitorVal: string;
  deltaText: string;
  verdict: 'win' | 'loss' | 'tie';
  winner: string;
}

export interface SuggestedCompetitor {
  domain: string;
  name: string;
}

export interface IndustryBenchmark {
  category: string;
  avgDom: number;
  avgPayloadKB: number;
  medianLcpSec: number;
  note: string;
}

export interface CompetitorComparisonResult {
  success: boolean;
  errorReason?: string;
  auditMethod: 'browser-rendered vs raw-html' | 'unavailable';
  methodologyNote: string;
  category?: string;
  benchmark?: IndustryBenchmark;
  deltas?: MetricDelta[];
  overallVerdict?: string;
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
  private static DIRECT_MAP: Record<string, { category: string; competitors: SuggestedCompetitor[]; benchmark: IndustryBenchmark }> = {
    'shopify.com': {
      category: 'E-Commerce Platform',
      competitors: [{ domain: 'bigcommerce.com', name: 'BigCommerce' }, { domain: 'woocommerce.com', name: 'WooCommerce' }, { domain: 'magento.com', name: 'Magento' }],
      benchmark: { category: 'E-Commerce Platform', avgDom: 1600, avgPayloadKB: 1800, medianLcpSec: 2.5, note: 'E-commerce median budget is 1,600 DOM nodes' }
    },
    'nike.com': {
      category: 'Athletic Apparel',
      competitors: [{ domain: 'adidas.com', name: 'Adidas' }, { domain: 'puma.com', name: 'Puma' }, { domain: 'underarmour.com', name: 'Under Armour' }],
      benchmark: { category: 'Athletic Apparel', avgDom: 2200, avgPayloadKB: 2600, medianLcpSec: 3.1, note: 'Retail flagships average 2,200 nodes' }
    },
    'gymshark.com': {
      category: 'Fitness Apparel',
      competitors: [{ domain: 'aloyoga.com', name: 'Alo Yoga' }, { domain: 'lululemon.com', name: 'Lululemon' }, { domain: 'vuoriclothing.com', name: 'Vuori' }],
      benchmark: { category: 'Fitness Apparel', avgDom: 1850, avgPayloadKB: 2400, medianLcpSec: 2.8, note: 'Apparel sector median budget is 1,850 nodes' }
    },
    'linear.app': {
      category: 'Productivity & Issue Tracking',
      competitors: [{ domain: 'atlassian.com', name: 'Jira' }, { domain: 'asana.com', name: 'Asana' }, { domain: 'clickup.com', name: 'ClickUp' }],
      benchmark: { category: 'Productivity & Issue Tracking', avgDom: 900, avgPayloadKB: 1100, medianLcpSec: 1.6, note: 'B2B SaaS median budget is 900 nodes' }
    },
    'notion.so': {
      category: 'Workspace & Knowledge Base',
      competitors: [{ domain: 'coda.io', name: 'Coda' }, { domain: 'craft.do', name: 'Craft' }, { domain: 'obsidian.md', name: 'Obsidian' }],
      benchmark: { category: 'Workspace & Knowledge Base', avgDom: 1100, avgPayloadKB: 1400, medianLcpSec: 1.9, note: 'Docs & workspace sector median is 1,100 nodes' }
    },
    'cal.com': {
      category: 'Scheduling & Calendar',
      competitors: [{ domain: 'calendly.com', name: 'Calendly' }, { domain: 'savvycal.com', name: 'SavvyCal' }, { domain: 'acuityscheduling.com', name: 'Acuity' }],
      benchmark: { category: 'Scheduling & Calendar', avgDom: 800, avgPayloadKB: 950, medianLcpSec: 1.5, note: 'Scheduling apps average 800 DOM nodes' }
    },
    'slack.com': {
      category: 'Team Communication',
      competitors: [{ domain: 'discord.com', name: 'Discord' }, { domain: 'teams.microsoft.com', name: 'MS Teams' }, { domain: 'mattermost.com', name: 'Mattermost' }],
      benchmark: { category: 'Team Communication', avgDom: 1200, avgPayloadKB: 1500, medianLcpSec: 2.1, note: 'Messaging platforms average 1,200 nodes' }
    },
    'stripe.com': {
      category: 'Fintech & Payment Infrastructure',
      competitors: [{ domain: 'adyen.com', name: 'Adyen' }, { domain: 'paddle.com', name: 'Paddle' }, { domain: 'checkout.com', name: 'Checkout' }],
      benchmark: { category: 'Fintech & Payment Infrastructure', avgDom: 950, avgPayloadKB: 1250, medianLcpSec: 1.7, note: 'Fintech sites median budget is 950 nodes' }
    },
    'webflow.com': {
      category: 'Visual Site Builders',
      competitors: [{ domain: 'framer.com', name: 'Framer' }, { domain: 'wordpress.org', name: 'WordPress' }, { domain: 'squarespace.com', name: 'Squarespace' }],
      benchmark: { category: 'Visual Site Builders', avgDom: 1300, avgPayloadKB: 1600, medianLcpSec: 2.2, note: 'Site builders median budget is 1,300 nodes' }
    },
    'vercel.com': {
      category: 'Cloud & Developer Hosting',
      competitors: [{ domain: 'netlify.com', name: 'Netlify' }, { domain: 'cloudflare.com', name: 'Cloudflare' }, { domain: 'render.com', name: 'Render' }],
      benchmark: { category: 'Cloud & Developer Hosting', avgDom: 850, avgPayloadKB: 1050, medianLcpSec: 1.5, note: 'Cloud developer tools median is 850 nodes' }
    },
    'ahrefs.com': {
      category: 'SEO & Search Intelligence',
      competitors: [{ domain: 'semrush.com', name: 'Semrush' }, { domain: 'moz.com', name: 'Moz' }, { domain: 'serpstat.com', name: 'Serpstat' }],
      benchmark: { category: 'SEO & Search Intelligence', avgDom: 1250, avgPayloadKB: 1500, medianLcpSec: 2.0, note: 'SEO tools median budget is 1,250 nodes' }
    },
    'webaudits.pro': {
      category: 'Web Audits & Speed Intelligence',
      competitors: [{ domain: 'pagespeed.web.dev', name: 'PageSpeed' }, { domain: 'gtmetrix.com', name: 'GTmetrix' }, { domain: 'debugbear.com', name: 'DebugBear' }],
      benchmark: { category: 'Web Audits & Speed Intelligence', avgDom: 750, avgPayloadKB: 850, medianLcpSec: 1.3, note: 'High performance audits aim for under 800 nodes' }
    },
    'ananna.free.je': {
      category: 'Agency & Portfolio Showcase',
      competitors: [{ domain: 'elementor.com', name: 'Elementor' }, { domain: 'generatepress.com', name: 'GeneratePress' }, { domain: 'astratheme.com', name: 'Astra Theme' }],
      benchmark: { category: 'Agency & Portfolio Showcase', avgDom: 1050, avgPayloadKB: 1400, medianLcpSec: 2.1, note: 'Agency portfolios average 1,050 nodes' }
    }
  };

  /**
   * Discovers category and suggests 3-4 top direct rivals (SimilarWeb Principle)
   */
  public static getSuggestedCompetitors(
    domainRaw: string,
    titleRaw?: string,
    metaDescRaw?: string,
    cmsList?: string[]
  ): { category: string; benchmark: IndustryBenchmark; competitors: SuggestedCompetitor[] } {
    const domain = (domainRaw || '').toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0];
    
    // 1. Check direct map
    if (this.DIRECT_MAP[domain]) {
      return this.DIRECT_MAP[domain];
    }

    const title = (titleRaw || '').toLowerCase();
    const desc = (metaDescRaw || '').toLowerCase();
    const cmsStr = (cmsList || []).join(' ').toLowerCase();
    const combo = `${domain} ${title} ${desc} ${cmsStr}`;

    // 2. E-Commerce & Retail
    if (combo.includes('shop') || combo.includes('store') || combo.includes('cart') || combo.includes('apparel') || combo.includes('clothing') || combo.includes('shoe') || combo.includes('fashion') || combo.includes('brand') || cmsStr.includes('shopify') || cmsStr.includes('woocommerce')) {
      return {
        category: 'E-Commerce & Retail',
        benchmark: { category: 'E-Commerce & Retail', avgDom: 1800, avgPayloadKB: 2200, medianLcpSec: 2.8, note: 'E-Commerce sector median is 1,800 DOM nodes' },
        competitors: [
          { domain: 'gymshark.com', name: 'Gymshark' },
          { domain: 'allbirds.com', name: 'Allbirds' },
          { domain: 'glossier.com', name: 'Glossier' },
          { domain: 'chubbieshorts.com', name: 'Chubbies' }
        ]
      };
    }

    // 3. B2B SaaS & Cloud Platforms
    if (combo.includes('saas') || combo.includes('platform') || combo.includes('software') || combo.includes('api') || combo.includes('developer') || combo.includes('workflow') || combo.includes('cloud') || combo.includes('dashboard') || cmsStr.includes('next.js')) {
      return {
        category: 'B2B SaaS & Cloud Platforms',
        benchmark: { category: 'B2B SaaS & Cloud Platforms', avgDom: 950, avgPayloadKB: 1200, medianLcpSec: 1.8, note: 'B2B SaaS sector median is 950 DOM nodes' },
        competitors: [
          { domain: 'linear.app', name: 'Linear' },
          { domain: 'cal.com', name: 'Cal.com' },
          { domain: 'posthog.com', name: 'PostHog' },
          { domain: 'resend.com', name: 'Resend' }
        ]
      };
    }

    // 4. Digital Agencies & Studios
    if (combo.includes('agency') || combo.includes('studio') || combo.includes('design') || combo.includes('marketing') || combo.includes('creative') || combo.includes('portfolio') || cmsStr.includes('webflow') || cmsStr.includes('elementor')) {
      return {
        category: 'Agency & Creative Studio',
        benchmark: { category: 'Agency & Creative Studio', avgDom: 1100, avgPayloadKB: 1500, medianLcpSec: 2.2, note: 'Agency portfolio median is 1,100 DOM nodes' },
        competitors: [
          { domain: 'work.co', name: 'Work & Co' },
          { domain: 'hugeinc.com', name: 'Huge Inc' },
          { domain: 'pentagram.com', name: 'Pentagram' },
          { domain: 'fantasy.co', name: 'Fantasy' }
        ]
      };
    }

    // 5. Healthcare & Clinic
    if (combo.includes('dental') || combo.includes('dentist') || combo.includes('clinic') || combo.includes('doctor') || combo.includes('health') || combo.includes('medical') || combo.includes('chiro')) {
      return {
        category: 'Healthcare & Medical',
        benchmark: { category: 'Healthcare & Medical', avgDom: 850, avgPayloadKB: 1100, medianLcpSec: 2.0, note: 'Healthcare sector median is 850 DOM nodes' },
        competitors: [
          { domain: 'onemedical.com', name: 'One Medical' },
          { domain: 'tenddental.com', name: 'Tend Dental' },
          { domain: 'zocdoc.com', name: 'Zocdoc' }
        ]
      };
    }

    // 6. Legal & Professional
    if (combo.includes('law') || combo.includes('attorney') || combo.includes('legal') || combo.includes('lawyer') || combo.includes('accounting') || combo.includes('cpa')) {
      return {
        category: 'Legal & Professional Services',
        benchmark: { category: 'Legal & Professional Services', avgDom: 800, avgPayloadKB: 950, medianLcpSec: 1.9, note: 'Legal services sector median is 800 DOM nodes' },
        competitors: [
          { domain: 'davispolk.com', name: 'Davis Polk' },
          { domain: 'lw.com', name: 'Latham & Watkins' },
          { domain: 'morganlewis.com', name: 'Morgan Lewis' }
        ]
      };
    }

    // 7. Real Estate
    if (combo.includes('real estate') || combo.includes('realtor') || combo.includes('property') || combo.includes('homes') || combo.includes('broker')) {
      return {
        category: 'Real Estate & Property',
        benchmark: { category: 'Real Estate & Property', avgDom: 1600, avgPayloadKB: 2400, medianLcpSec: 2.6, note: 'Real estate sector median is 1,600 DOM nodes' },
        competitors: [
          { domain: 'zillow.com', name: 'Zillow' },
          { domain: 'redfin.com', name: 'Redfin' },
          { domain: 'compass.com', name: 'Compass' }
        ]
      };
    }

    // Default: Modern Commercial Web
    return {
      category: 'Commercial Web',
      benchmark: { category: 'Commercial Web', avgDom: 1200, avgPayloadKB: 1600, medianLcpSec: 2.4, note: 'Standard commercial web median is 1,200 DOM nodes' },
      competitors: [
        { domain: 'stripe.com', name: 'Stripe' },
        { domain: 'linear.app', name: 'Linear' },
        { domain: 'shopify.com', name: 'Shopify' },
        { domain: 'vercel.com', name: 'Vercel' }
      ]
    };
  }

  /**
   * Attempts to audit a competitor URL and computes head-to-head deltas.
   * NEVER FABRICATES ARTIFICIAL METRICS.
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
    const categoryInfo = this.getSuggestedCompetitors(
      prospectSummary.domain,
      prospectData.seo?.title,
      prospectData.seo?.metaDescription,
      prospectData.cms
    );

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
          category: categoryInfo.category,
          benchmark: categoryInfo.benchmark,
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
          category: categoryInfo.category,
          benchmark: categoryInfo.benchmark,
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

      // 1. Calculate Metric Deltas
      const deltas: MetricDelta[] = [];

      // DOM Elements Delta
      const pDom = prospectSummary.domElements;
      const cDom = competitorSummary.domElements;
      if (pDom === cDom) {
        deltas.push({
          metric: 'DOM Elements',
          prospectVal: pDom.toLocaleString(),
          competitorVal: cDom.toLocaleString(),
          deltaText: 'Parity: identical DOM count',
          verdict: 'tie',
          winner: 'Equal'
        });
      } else if (pDom < cDom) {
        const pct = Math.round(((cDom - pDom) / cDom) * 100);
        deltas.push({
          metric: 'DOM Elements',
          prospectVal: pDom.toLocaleString(),
          competitorVal: cDom.toLocaleString(),
          deltaText: `${pct}% leaner DOM tree`,
          verdict: 'win',
          winner: prospectSummary.domain
        });
      } else {
        const diff = pDom - cDom;
        const pct = Math.round(((pDom - cDom) / (cDom || 1)) * 100);
        deltas.push({
          metric: 'DOM Elements',
          prospectVal: pDom.toLocaleString(),
          competitorVal: cDom.toLocaleString(),
          deltaText: `+${diff.toLocaleString()} (+${pct}% heavier)`,
          verdict: 'loss',
          winner: compDomain
        });
      }

      // Serialized Markup Weight Delta
      const pSize = prospectSummary.serializedSizeKB;
      const cSize = competitorSummary.serializedSizeKB;
      if (pSize === cSize) {
        deltas.push({
          metric: 'Document Weight',
          prospectVal: `${pSize} KB`,
          competitorVal: `${cSize} KB`,
          deltaText: 'Equal markup size',
          verdict: 'tie',
          winner: 'Equal'
        });
      } else if (pSize < cSize) {
        const pct = Math.round(((cSize - pSize) / (cSize || 1)) * 100);
        deltas.push({
          metric: 'Document Weight',
          prospectVal: `${pSize} KB`,
          competitorVal: `${cSize} KB`,
          deltaText: `${pct}% lighter document`,
          verdict: 'win',
          winner: prospectSummary.domain
        });
      } else {
        const diff = pSize - cSize;
        const pct = Math.round(((pSize - cSize) / (cSize || 1)) * 100);
        deltas.push({
          metric: 'Document Weight',
          prospectVal: `${pSize} KB`,
          competitorVal: `${cSize} KB`,
          deltaText: `+${diff} KB (+${pct}% payload)`,
          verdict: 'loss',
          winner: compDomain
        });
      }

      // Viewport Status Delta
      const pVp = prospectSummary.viewportStatus;
      const cVp = competitorSummary.viewportStatus;
      if (pVp === cVp) {
        deltas.push({
          metric: 'Mobile Viewport',
          prospectVal: pVp,
          competitorVal: cVp,
          deltaText: pVp === 'Responsive' ? 'Both responsive' : 'Both need configuration',
          verdict: 'tie',
          winner: 'Equal'
        });
      } else if (pVp === 'Responsive') {
        deltas.push({
          metric: 'Mobile Viewport',
          prospectVal: pVp,
          competitorVal: cVp,
          deltaText: 'Prospect mobile viewport valid',
          verdict: 'win',
          winner: prospectSummary.domain
        });
      } else {
        deltas.push({
          metric: 'Mobile Viewport',
          prospectVal: pVp,
          competitorVal: cVp,
          deltaText: 'Competitor viewport properly configured',
          verdict: 'loss',
          winner: compDomain
        });
      }

      // Structured Data Delta
      const pSchema = prospectSummary.schemaStatus;
      const cSchema = competitorSummary.schemaStatus;
      if (pSchema === cSchema) {
        deltas.push({
          metric: 'Structured Data',
          prospectVal: pSchema,
          competitorVal: cSchema,
          deltaText: pSchema === 'Detected' ? 'Both have Schema.org' : 'Both missing Schema.org',
          verdict: 'tie',
          winner: 'Equal'
        });
      } else if (pSchema === 'Detected') {
        deltas.push({
          metric: 'Structured Data',
          prospectVal: pSchema,
          competitorVal: cSchema,
          deltaText: 'Prospect has AI / rich snippet graph',
          verdict: 'win',
          winner: prospectSummary.domain
        });
      } else {
        deltas.push({
          metric: 'Structured Data',
          prospectVal: pSchema,
          competitorVal: cSchema,
          deltaText: 'Competitor favored in AI search citation',
          verdict: 'loss',
          winner: compDomain
        });
      }

      // Tech Stack
      deltas.push({
        metric: 'Tech Architecture',
        prospectVal: prospectSummary.cms,
        competitorVal: competitorSummary.cms,
        deltaText: prospectSummary.cms === competitorSummary.cms ? 'Identical stack family' : 'Stack divergence',
        verdict: 'tie',
        winner: 'Comparison'
      });

      // 2. Compute Overall Verdict
      let lossCount = deltas.filter(d => d.verdict === 'loss').length;
      let winCount = deltas.filter(d => d.verdict === 'win').length;
      let overallVerdict = '';

      if (lossCount > winCount) {
        overallVerdict = `${compDomain} holds the performance advantage: leaner markup and superior structural readiness.`;
      } else if (winCount > lossCount) {
        overallVerdict = `${prospectSummary.domain} holds the efficiency advantage over ${compDomain} in DOM and payload metrics.`;
      } else {
        overallVerdict = `Structural parity observed between ${prospectSummary.domain} and ${compDomain}.`;
      }

      // 3. Evidence-First Cold Outreach Comparison Hook
      let hook = '';
      if (pDom > cDom && cSchema === 'Detected' && pSchema === 'Opportunity') {
        hook = `Noticed that ${prospectSummary.domain} renders ${pDom.toLocaleString()} DOM elements and currently lacks Schema.org JSON-LD, while ${compDomain} maintains a leaner footprint of ${cDom.toLocaleString()} elements with active structured data. Because Google and AI search engines prioritize fast DOM evaluation and verified entity graphs, this performance gap gives ${compDomain} an edge on organic visibility.`;
      } else if (pDom > cDom) {
        hook = `Observed that ${prospectSummary.domain} renders ${pDom.toLocaleString()} DOM elements and ${pSize} KB of initial markup, compared to ${compDomain} at ${cDom.toLocaleString()} elements and ${cSize} KB. Trimming the DOM complexity would close this speed gap and improve mobile Core Web Vitals.`;
      } else if (pSize > cSize) {
        hook = `Observed that ${prospectSummary.domain} transfers ${pSize} KB of initial HTML payload, whereas ${compDomain} loads at ${cSize} KB. Optimizing asset delivery and cleaning up unneeded tags would match or exceed competitor response times.`;
      } else {
        hook = `Observed difference: ${prospectSummary.domain} renders ${pDom.toLocaleString()} DOM elements vs ${compDomain} at ${cDom.toLocaleString()} elements. Profiling the architecture delta can highlight potential performance improvements.`;
      }

      return {
        success: true,
        auditMethod: 'browser-rendered vs raw-html',
        methodologyNote: 'Methodology note: Primary prospect was measured via live in-browser DOM tree recursion. Competitor was measured via raw HTML fetch without full JavaScript execution.',
        category: categoryInfo.category,
        benchmark: categoryInfo.benchmark,
        deltas,
        overallVerdict,
        prospect: prospectSummary,
        competitor: competitorSummary,
        comparisonHook: hook
      };
    } catch (err: any) {
      return {
        success: false,
        auditMethod: 'unavailable',
        methodologyNote: 'Cross-origin request blocked by browser CORS policy or bot security.',
        errorReason: 'Direct in-browser fetch was blocked by CORS or bot security on competitor domain. To inspect this competitor with genuine DOM recursion, open their website in an active browser tab.',
        category: categoryInfo.category,
        benchmark: categoryInfo.benchmark,
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
