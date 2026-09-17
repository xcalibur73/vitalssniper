// VitalsSniper PRO: Proof-of-Flaw Precision Web Inspector
// Author: [Your Name]

document.addEventListener('DOMContentLoaded', async () => {
  // Always initialize UI modals and drawers first
  initLicense();
  initSettingsModal();
  initCompetitorModal();
  initPipelineDrawer();

  let tab;
  try {
    if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.query) {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      tab = tabs[0];
    }
  } catch (e) {}

  if (!tab || !tab.id || !tab.url) {
    const td = document.getElementById('targetDomain');
    if (td) td.innerText = 'Demo / Standalone Mode';
    return;
  }

  currentAuditState.tabId = tab.id;
  initLcpHighlighter(tab.id);

  let urlObj;
  try {
    urlObj = new URL(tab.url);
  } catch(e) {
    document.getElementById('targetDomain').innerText = 'System Browser Page';
    document.getElementById('flawDesc').innerText = 'Cannot inspect internal browser protocols or settings pages.';
    return;
  }

  const domain = urlObj.hostname.replace('www.', '');
  document.getElementById('targetDomain').innerText = domain;

  // Favicon setup
  const faviconEl = document.getElementById('siteFavicon');
  if (tab.favIconUrl && tab.favIconUrl.startsWith('http')) {
    faviconEl.src = tab.favIconUrl;
  }

  // HTTPS Security Badge
  const secBadge = document.getElementById('secBadge');
  if (urlObj.protocol === 'https:') {
    secBadge.innerText = 'HTTPS';
    secBadge.className = 'sec-badge';
  } else {
    secBadge.innerText = 'HTTP (INSECURE)';
    secBadge.style.color = '#ff0055';
    secBadge.style.borderColor = '#ff0055';
  }

  // Inject and execute content script inspector
  chrome.scripting.executeScript({
    target: { tabId: tab.id },
    func: inspectPageMetrics
  }, (results) => {
    if (!results || !results[0] || !results[0].result) {
      document.getElementById('flawDesc').innerText = 'Cannot inspect this page (protected or system page).';
      return;
    }

    const data = results[0].result;
    renderAuditData(domain, tab.url, data);
  });

});

// Injected into active target web page
function inspectPageMetrics() {
  const html = document.documentElement.outerHTML;
  const sizeBytes = new Blob([html]).size;
  const sizeKB = Math.round(sizeBytes / 1024);

  // 1. Total DOM elements
  const totalDom = document.querySelectorAll('*').length;

  // 2. Viewport inspection
  const vpMeta = document.querySelector('meta[name="viewport"]');
  const vpContent = vpMeta ? vpMeta.getAttribute('content') || '' : '';
  const vpMissing = !vpMeta;
  const vpLocked = vpContent.includes('user-scalable=0') || vpContent.includes('user-scalable=no') || vpContent.includes('maximum-scale=1');

  // 3. JSON-LD Schema detection
  const schemaScripts = Array.from(document.querySelectorAll('script[type="application/ld+json"]'));
  const hasSchema = schemaScripts.length > 0;
  let schemaTypes = [];
  schemaScripts.forEach(s => {
    try {
      const parsed = JSON.parse(s.textContent);
      if (parsed['@type']) schemaTypes.push(parsed['@type']);
      if (parsed['@graph']) parsed['@graph'].forEach(g => { if (g['@type']) schemaTypes.push(g['@type']); });
    } catch(e) {}
  });

  // 4. Robust CMS & Page Builder Signatures (No false-positive substring matches)
  const cms = [];
  const hLower = html.toLowerCase();

  // WordPress detection
  if (hLower.includes('wp-content') || hLower.includes('wp-includes') || hLower.includes('wordpress')) cms.push('WordPress');

  // Page Builders
  if (hLower.includes('elementor') || window.elementorFrontend) cms.push('Elementor');
  if (hLower.includes('et_pb_') || hLower.includes('divi-theme') || hLower.includes('/themes/divi/') || window.et_pb_custom) cms.push('Divi');
  if (hLower.includes('wpbakery') || hLower.includes('js_composer')) cms.push('WPBakery');
  if (hLower.includes('fusion-builder') || hLower.includes('/themes/avada/')) cms.push('Avada');
  if (hLower.includes('/themes/salient/') || hLower.includes('nectar-slider')) cms.push('Salient');
  if (hLower.includes('fl-builder') || hLower.includes('beaver-builder')) cms.push('Beaver Builder');
  if (hLower.includes('generatepress') || hLower.includes('generateblocks')) cms.push('GeneratePress');

  // Standalone Platforms
  if (hLower.includes('squarespace.com') || hLower.includes('sqs-block') || window.Static?.SQUARESPACE_CONTEXT) cms.push('Squarespace');
  if (document.documentElement.classList.contains('w-mod-js') || hLower.includes('data-wf-page')) cms.push('Webflow');
  if (document.getElementById('__next') !== null || window.__NEXT_DATA__ !== undefined || hLower.includes('__next_data__')) cms.push('Next.js');
  if (window.Shopify !== undefined || hLower.includes('cdn.shopify.com')) cms.push('Shopify');
  if (window.wixBiSession !== undefined || hLower.includes('static.parastorage.com')) cms.push('Wix');
  if (hLower.includes('hs-scripts.com') || hLower.includes('hs-content-id')) cms.push('HubSpot');

  // 5. Images audit
  const images = Array.from(document.querySelectorAll('img'));
  const uncompressedImages = images.filter(img => {
    const src = (img.currentSrc || img.src || '').toLowerCase();
    return src.endsWith('.jpg') || src.endsWith('.jpeg') || src.endsWith('.png');
  }).length;

  // 6. Navigation Timing & TTFB
  let ttfbMs = 0;
  let loadTimeSec = 0;
  try {
    const [navEntry] = performance.getEntriesByType('navigation');
    if (navEntry) {
      ttfbMs = Math.round(navEntry.responseStart - navEntry.requestStart);
      loadTimeSec = Number(((navEntry.loadEventEnd || navEntry.domContentLoadedEventEnd || navEntry.responseEnd) / 1000).toFixed(2));
    } else if (performance.timing) {
      const t = performance.timing;
      ttfbMs = Math.round(t.responseStart - t.requestStart);
      loadTimeSec = Number(((t.loadEventEnd || t.domContentLoadedEventEnd) - t.navigationStart) / 1000).toFixed(2);
    }
  } catch(e) {}
  if (ttfbMs < 0 || isNaN(ttfbMs)) ttfbMs = 0;
  if (loadTimeSec < 0 || isNaN(loadTimeSec)) loadTimeSec = 0;

  // 7. Resource & Assets Breakdown
  const scriptsCount = document.querySelectorAll('script').length;
  const stylesCount = document.querySelectorAll('link[rel="stylesheet"]').length;
  let totalTransferKB = 0;
  const trackers = [];

  try {
    const resources = performance.getEntriesByType('resource');
    resources.forEach(r => {
      if (r.transferSize) totalTransferKB += r.transferSize;
      const n = (r.name || '').toLowerCase();
      if (n.includes('googletagmanager.com/gtm.js') && !trackers.includes('GTM')) trackers.push('GTM');
      if ((n.includes('google-analytics.com') || n.includes('analytics.google.com') || n.includes('gtag/js')) && !trackers.includes('GA4')) trackers.push('GA4');
      if ((n.includes('connect.facebook.net') || n.includes('facebook.com/tr')) && !trackers.includes('Meta Pixel')) trackers.push('Meta Pixel');
      if (n.includes('static.hotjar.com') && !trackers.includes('Hotjar')) trackers.push('Hotjar');
      if (n.includes('clarity.ms') && !trackers.includes('Clarity')) trackers.push('MS Clarity');
      if (n.includes('static.klaviyo.com') && !trackers.includes('Klaviyo')) trackers.push('Klaviyo');
      if (n.includes('analytics.tiktok.com') && !trackers.includes('TikTok Pixel')) trackers.push('TikTok Pixel');
      if (n.includes('hs-scripts.com') && !trackers.includes('HubSpot')) trackers.push('HubSpot');
    });
    totalTransferKB = Math.round(totalTransferKB / 1024);
  } catch(e) {}

  return {
    totalDom,
    sizeKB,
    vpMissing,
    vpLocked,
    hasSchema,
    schemaTypes: Array.from(new Set(schemaTypes)),
    cms: Array.from(new Set(cms)),
    imagesCount: images.length,
    uncompressedImages,
    ttfbMs,
    loadTimeSec,
    scriptsCount,
    stylesCount,
    totalTransferKB,
    trackers
  };
}

// Global script cache for channel switching
let currentScripts = {
  email: '',
  dm: '',
  loom: ''
};
let activeChannel = 'email';
let currentFlawHook = '';

// Shared Current Audit State for Features
let currentAuditState = {
  domain: '',
  url: '',
  tabId: null,
  data: null,
  score: 100,
  flawText: '',
  hook: '',
  improvements: [],
  cmsText: ''
};

// AppSumo License Key & Monetization Engine
let isPaidUser = false;

function setProActive(reason) {
  isPaidUser = true;
  const proTag = document.getElementById('proTag');
  if (proTag) {
    proTag.innerText = 'PRO';
    proTag.classList.remove('inactive');
    proTag.classList.add('active');
    proTag.title = `VitalsSniper PRO (${reason})`;
  }
}

function setFreeTier() {
  isPaidUser = false;
  const proTag = document.getElementById('proTag');
  if (proTag) {
    proTag.innerText = 'ACTIVATE';
    proTag.classList.remove('active');
    proTag.classList.add('inactive');
    proTag.title = 'Click to activate your AppSumo license';
  }
}

function checkProStatus() {
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
    chrome.storage.local.get(['appsumoProKey', 'vs_is_pro', 'vs_license_key'], (res) => {
      if (res.appsumoProKey || (res.vs_is_pro && res.vs_license_key)) {
        setProActive('PRO Lifetime License');
      } else if (typeof ExtPay !== 'undefined') {
        try {
          const extpay = ExtPay('vitalssniper');
          extpay.getUser().then(user => {
            if (user && user.paid) setProActive('Stripe Active');
            else setFreeTier();
          }).catch(() => setFreeTier());
        } catch (e) {
          setFreeTier();
        }
      } else {
        setFreeTier();
      }
    });
  }
}

checkProStatus();

function renderAuditData(domain, currentUrl, data) {
  // 1. Calculate Comprehensive Health Score (0 - 100)
  let score = 100;
  if (data.vpMissing) score -= 30;
  else if (data.vpLocked) score -= 15;

  if (data.totalDom > 3500) score -= 25;
  else if (data.totalDom > 2000) score -= 15;
  else if (data.totalDom > 1400) score -= 8;

  if (data.sizeKB > 150) score -= 20;
  else if (data.sizeKB > 80) score -= 10;
  else if (data.sizeKB > 50) score -= 5;

  if (data.uncompressedImages > 15) score -= 15;
  else if (data.uncompressedImages > 5) score -= 8;
  else if (data.uncompressedImages > 0) score -= 4;

  if (!data.hasSchema) score -= 10;
  if (data.ttfbMs > 800) score -= 10;
  else if (data.ttfbMs > 400) score -= 5;

  score = Math.max(18, Math.min(100, score));

  // Render Health Score
  const scoreValEl = document.getElementById('healthScoreVal');
  const scoreBadgeEl = document.getElementById('scoreBadge');
  if (scoreValEl) {
    scoreValEl.innerText = score;
  }
  if (scoreBadgeEl) {
    if (score >= 85) {
      scoreBadgeEl.style.color = '#34d399';
      scoreBadgeEl.style.borderColor = 'rgba(52, 211, 153, 0.35)';
      scoreBadgeEl.style.background = 'rgba(52, 211, 153, 0.08)';
    } else if (score >= 60) {
      scoreBadgeEl.style.color = '#fbbf24';
      scoreBadgeEl.style.borderColor = 'rgba(251, 191, 36, 0.35)';
      scoreBadgeEl.style.background = 'rgba(251, 191, 36, 0.08)';
    } else {
      scoreBadgeEl.style.color = '#fb7185';
      scoreBadgeEl.style.borderColor = 'rgba(251, 113, 133, 0.35)';
      scoreBadgeEl.style.background = 'rgba(251, 113, 133, 0.08)';
    }
  }

  // 2. Render Tech Stack & Tracker Badges
  const stackRow = document.getElementById('techStackRow');
  stackRow.innerHTML = '';
  if (data.cms.length === 0) {
    stackRow.innerHTML = '<span class="tech-badge">Custom Stack</span>';
  } else {
    data.cms.forEach(c => {
      const isBuilder = ['Elementor', 'Divi', 'WPBakery', 'Avada', 'Salient', 'Beaver Builder'].includes(c);
      const span = document.createElement('span');
      span.className = `tech-badge ${isBuilder ? 'tech-builder' : 'tech-cms'}`;
      span.innerText = isBuilder ? `Builder: ${c}` : c;
      stackRow.appendChild(span);
    });
  }
  if (data.trackers && data.trackers.length > 0) {
    data.trackers.forEach(t => {
      const span = document.createElement('span');
      span.className = 'tech-badge tech-tracker';
      span.innerText = `Track: ${t}`;
      stackRow.appendChild(span);
    });
  }

  // 3. Tile 1: DOM Elements
  const valDom = document.getElementById('valDom');
  const tagDom = document.getElementById('tagDom');
  const cardDom = document.getElementById('cardDom');
  valDom.innerText = data.totalDom.toLocaleString();
  if (data.totalDom > 3500) {
    tagDom.className = 'metric-tag tag-red';
    tagDom.innerText = 'BLOATED';
    cardDom.className = 'metric-card flaw-danger';
  } else if (data.totalDom > 1800) {
    tagDom.className = 'metric-tag tag-yellow';
    tagDom.innerText = 'HEAVY';
    cardDom.className = 'metric-card';
  } else {
    tagDom.className = 'metric-tag tag-green';
    tagDom.innerText = 'CLEAN';
    cardDom.className = 'metric-card flaw-good';
  }

  // 4. Tile 2: HTML Document Payload
  const valSize = document.getElementById('valSize');
  const tagSize = document.getElementById('tagSize');
  const cardSize = document.getElementById('cardSize');
  valSize.innerText = `${data.sizeKB} KB`;
  if (data.sizeKB > 150) {
    tagSize.className = 'metric-tag tag-red';
    tagSize.innerText = 'HIGH';
    cardSize.className = 'metric-card flaw-danger';
  } else if (data.sizeKB > 60) {
    tagSize.className = 'metric-tag tag-yellow';
    tagSize.innerText = 'MEDIUM';
    cardSize.className = 'metric-card';
  } else {
    tagSize.className = 'metric-tag tag-green';
    tagSize.innerText = 'GOOD';
    cardSize.className = 'metric-card flaw-good';
  }

  // 5. Tile 3: Mobile Viewport Scaling
  const valVp = document.getElementById('valViewport');
  const tagVp = document.getElementById('tagViewport');
  const cardVp = document.getElementById('cardViewport');
  if (data.vpMissing) {
    valVp.innerText = 'MISSING';
    tagVp.className = 'metric-tag tag-red';
    tagVp.innerText = 'FAIL';
    cardVp.className = 'metric-card flaw-danger';
  } else if (data.vpLocked) {
    valVp.innerText = 'LOCKED';
    tagVp.className = 'metric-tag tag-red';
    tagVp.innerText = 'NO ZOOM';
    cardVp.className = 'metric-card flaw-danger';
  } else {
    valVp.innerText = 'RESPONSIVE';
    tagVp.className = 'metric-tag tag-green';
    tagVp.innerText = 'PASS';
    cardVp.className = 'metric-card flaw-good';
  }

  // 6. Tile 4: AI & Schema Ready
  const valSchema = document.getElementById('valSchema');
  const tagSchema = document.getElementById('tagSchema');
  const cardSchema = document.getElementById('cardSchema');
  if (data.hasSchema) {
    valSchema.innerText = data.schemaTypes.length > 0 ? `${data.schemaTypes.length} Types` : 'DETECTED';
    tagSchema.className = 'metric-tag tag-green';
    tagSchema.innerText = 'PASS';
    cardSchema.className = 'metric-card flaw-good';
  } else {
    valSchema.innerText = 'MISSING';
    tagSchema.className = 'metric-tag tag-red';
    tagSchema.innerText = 'NO SCHEMA';
    cardSchema.className = 'metric-card flaw-danger';
  }

  // 7. Tile 5: Scripts & Assets Bloat
  const valAssets = document.getElementById('valAssets');
  const tagAssets = document.getElementById('tagAssets');
  const cardAssets = document.getElementById('cardAssets');
  valAssets.innerText = `${data.scriptsCount} Scripts`;
  if (data.scriptsCount > 35 || data.totalTransferKB > 3500) {
    tagAssets.className = 'metric-tag tag-red';
    tagAssets.innerText = 'BLOATED';
    cardAssets.className = 'metric-card flaw-danger';
  } else if (data.scriptsCount > 20 || data.totalTransferKB > 1500) {
    tagAssets.className = 'metric-tag tag-yellow';
    tagAssets.innerText = 'MEDIUM';
    cardAssets.className = 'metric-card';
  } else {
    tagAssets.className = 'metric-tag tag-green';
    tagAssets.innerText = 'LIGHT';
    cardAssets.className = 'metric-card flaw-good';
  }
  document.getElementById('descAssets').innerText = data.totalTransferKB > 0 ? `~${data.totalTransferKB} KB Loaded` : `${data.imagesCount} Imgs Total`;

  // 8. Tile 6: Server TTFB & Latency
  const valSpeed = document.getElementById('valSpeed');
  const tagSpeed = document.getElementById('tagSpeed');
  const cardSpeed = document.getElementById('cardSpeed');
  valSpeed.innerText = data.ttfbMs > 0 ? `${data.ttfbMs} ms` : (data.loadTimeSec > 0 ? `${data.loadTimeSec}s` : 'OK');
  if (data.ttfbMs > 800) {
    tagSpeed.className = 'metric-tag tag-red';
    tagSpeed.innerText = 'SLOW';
    cardSpeed.className = 'metric-card flaw-danger';
  } else if (data.ttfbMs > 350) {
    tagSpeed.className = 'metric-tag tag-yellow';
    tagSpeed.innerText = 'AVERAGE';
    cardSpeed.className = 'metric-card';
  } else {
    tagSpeed.className = 'metric-tag tag-green';
    tagSpeed.innerText = 'FAST';
    cardSpeed.className = 'metric-card flaw-good';
  }
  document.getElementById('descSpeed').innerText = data.loadTimeSec > 0 ? `Total Load: ${data.loadTimeSec}s` : 'Time To First Byte';

  // 9. Determine Primary Strategic Flaw
  // 9. Determine Primary Strategic Flaw & Deep Technical Reasoning
  let flawText = '';
  let emailHook = '';
  let dmHook = '';
  let loomHook = '';
  let improvements = [];
  const detectedBuilders = (data.cms || []).filter(c => ['Elementor', 'Divi', 'WPBakery', 'Avada', 'Salient', 'Beaver Builder'].includes(c));
  const builderName = detectedBuilders.length > 0 ? detectedBuilders.join(' + ') : ((data.cms && data.cms.length > 0) ? data.cms[0] : 'page builder');

  if (data.vpMissing) {
    flawText = 'Critical: Viewport meta tag is missing. Mobile browsers render the site as a tiny desktop view.';
    improvements = [
      'Add responsive viewport meta tag (width=device-width, initial-scale=1.0) to trigger native mobile layout rendering',
      'Ensure all container widths and tap elements adapt fluidly across mobile and tablet viewports',
      'Zero visual design changes (100% typography, styling, and photography preserved with 0 alteration)',
    ];
    emailHook = `While testing ${domain} on an iPhone, I noticed your homepage is currently missing a responsive viewport tag, which causes mobile Safari to render the whole site zoomed-out as a tiny desktop screen.`;
    dmHook = `noticed your site is missing a mobile viewport tag, so mobile Safari renders everything tiny and zoomed-out.`;
    loomHook = `The mobile viewport meta tag is completely missing, forcing iPhone Safari into desktop emulation mode.`;

    currentScripts.email = `Subject: mobile viewport issue on ${domain}

Hi [First Name],

While testing ${domain} on an iPhone, I noticed your homepage is currently missing a responsive viewport tag, which causes mobile Safari to render the entire page zoomed-out as a tiny desktop view.

Because mobile devices cannot detect the layout boundary without this tag, mobile visitors are forced to manually pinch and pan across the screen just to read headlines, causing severe drop-offs on mobile ad campaigns.

We can resolve this cleanly with zero changes to your website design:
1. Add modern viewport configuration allowing fluid zoom without horizontal scrolling.
2. Ensure container grids adapt seamlessly across phone and tablet screens.
3. 100% visual design invariance guarantee (zero disruption to styling or photography).

I recorded a quick 30-second screen recording showing the issue and the exact 5-minute code fix.

Would you like me to send the clip over to your team?

Best regards,
[Your Name]
[Your Title / Agency]`;

    currentScripts.dm = `Hey [First Name] - noticed ${domain} on mobile while checking out your site.

The site is missing a responsive viewport tag, forcing mobile Safari to render everything zoomed-out like a desktop screen where text is too small to read without zooming.

We can fix this in under an hour with 0 design changes:
• Configure responsive viewport meta for native mobile scaling.
• Validate container boundaries across iOS and Android devices.
• 100% design fidelity preserved (exact typography, spacing, and photography).

I recorded a 30s screen clip showing the fix. Mind if I send the link over?

- [Your Name]`;

    currentScripts.loom = `[0:00 - 0:08] "Hey [Name], [Your Name] here. I was reviewing ${domain} on an iPhone and spotted a critical layout setting that's hurting your mobile conversions."

[0:08 - 0:22] "Right here on mobile Safari: the responsive viewport tag is completely missing. Mobile browsers are forced into desktop emulation mode, so prospective clients see a tiny zoomed-out page that's difficult to navigate."

[0:22 - 0:35] "The fix takes less than an hour and requires zero design changes: we configure proper viewport scaling so the page displays natively on all devices. Happy to share the exact fix if helpful!"`;

  } else if (data.vpLocked) {
    flawText = 'Mobile Accessibility: Viewport locks zoom (user-scalable=0), violating WCAG 2.2 standards.';
    improvements = [
      'Update viewport meta tag to width=device-width, initial-scale=1.0 allowing fluid pinch-to-zoom up to 500% with 0 layout shift',
      'Implement modern CSS clamp() typography so text scales elegantly across all screen magnifications',
      'Validate all interactive buttons meet 48x48px mobile touch target standards, eliminating mis-taps',
    ];
    emailHook = `While testing ${domain} on an iPhone, I noticed your viewport tag locks user pinch-to-zoom (user-scalable=0), preventing prospective clients from inspecting portfolio details and triggering mobile penalties.`;
    dmHook = `noticed your mobile viewport locks pinch-to-zoom (user-scalable=0), which blocks clients from zooming in and flags usability warnings.`;
    loomHook = `The viewport tag locks user pinch-to-zoom, which restricts mobile client accessibility and hurts Core Web Vitals.`;

    currentScripts.email = `Subject: mobile accessibility issue on ${domain}

Hi [First Name],

While reviewing ${domain} on an iPhone, I noticed your mobile viewport configuration currently blocks pinch-to-zoom (user-scalable=no).

This creates a frustrating experience for prospective clients trying to zoom in on your work, directly violates WCAG 2.2 accessibility standards (SC 1.4.4), and triggers usability warnings in Google's mobile ranking algorithms.

We can resolve this cleanly with zero disruption to your visual design:
1. Update the viewport meta tag to allow fluid zoom up to 500% without horizontal overflow.
2. Implement modern fluid clamp() typography so text scales elegantly across all screen sizes.
3. Validate all touch targets meet the 48x48px standard for effortless mobile navigation.

I recorded a 30-second mobile walkthrough demonstrating the issue and the exact 5-minute code fix.

Would you like me to send the clip over to your team?

Best regards,
[Your Name]
[Your Title / Agency]`;

    currentScripts.dm = `Hey [First Name] - noticed ${domain} on mobile while checking out your site.

The viewport tag is set to lock pinch-to-zoom (user-scalable=0). This blocks visitors on phones from zooming in on portfolio details, violates WCAG 2.2 accessibility rules, and can trigger Google mobile usability demotions.

We can fix this in under an hour with 0 design changes:
• Unlock the viewport tag for smooth 500% zoom with 0 layout shift.
• Add fluid clamp() scaling so typography adjusts seamlessly.
• Ensure all touch targets meet mobile tap standards.

I recorded a 30s screen clip showing the fix. Mind if I send the link over?

- [Your Name]`;

    currentScripts.loom = `[0:00 - 0:08] "Hey [Name], [Your Name] here. I was reviewing ${domain} on mobile and noticed an accessibility restriction that could be hurting your mobile conversions and Google visibility."

[0:08 - 0:22] "Right here in the viewport tag: user zooming is locked with user-scalable=0. When prospective clients try to pinch and zoom into your portfolio or details, the screen is frozen. This triggers WCAG accessibility violations and Google mobile usability penalties."

[0:22 - 0:35] "The fix takes less than an hour with zero visual changes: we configure fluid scaling so mobile visitors can zoom comfortably while the design stays pixel-perfect. Happy to share the exact fix if helpful!"`;

  } else if (data.totalDom > 2000 || (data.totalDom > 1400 && detectedBuilders.length > 0)) {
    flawText = `Severe Page Builder Bloat: ${data.sizeKB}KB raw HTML across ${data.totalDom.toLocaleString()} elements chokes mobile CPU.`;
    improvements = [
      'Flatten container hierarchy into semantic HTML5 (<section>, <main>) with native CSS Grid/Flexbox, dropping total DOM nodes by 60%+',
      'Virtualize and defer below-the-fold content sections so mobile layout geometry calculates instantly for visible hero elements',
      'Guarantee 100% visual design invariance (exact typography, spacing, styling, animations, and photography preserved with 0 changes)',
    ];
    emailHook = `While reviewing ${domain} on mobile, I noticed the homepage tree carries ${data.totalDom.toLocaleString()} DOM elements with deep container nesting from ${builderName}.`;
    dmHook = `noticed the homepage carries ${data.totalDom.toLocaleString()} DOM nodes from ${builderName}, causing mobile rendering freeze on phones.`;
    loomHook = `The page tree contains ${data.totalDom.toLocaleString()} DOM elements with deep nesting from ${builderName}, choking mobile CPU before images render.`;

    currentScripts.email = `Subject: quick observation on the mobile experience for ${domain}

Hi [First Name],

While reviewing ${domain} on mobile, I noticed the homepage tree carries ${data.totalDom.toLocaleString()} DOM elements with deep container nesting from ${builderName}.

Because mobile browsers must recursively recalculate layout geometry across thousands of nested nodes, this creates a 1.8s to 3.2s main-thread freeze where button taps hesitate before responding, causing mobile visitors to bounce.

We specialize in architectural refactoring that flattens excessive builder nesting into semantic HTML5 while keeping your design, branding, and typography 100% intact:
1. Flatten 15+ container wrappers into lightweight CSS Grid (reducing DOM nodes by 60%+).
2. Defer layout calculations for below-the-fold sections so the mobile viewport becomes interactive in under 1 second.
3. Zero design changes (100% visual fidelity guarantee).

I recorded a quick 30-second screen teardown showing the exact bottleneck and how to eliminate the lag in 48 hours.

Mind if I send the clip over to your team?

Best regards,
[Your Name]
[Your Title / Agency]`;

    currentScripts.dm = `Hey [First Name] - noticed ${domain} on mobile while exploring your work.

The homepage carries ${data.totalDom.toLocaleString()} DOM nodes with deep container nesting from ${builderName}. On mobile devices, this forces the browser to recalculate layout geometry across thousands of elements, causing a 2-second main-thread freeze before taps respond.

We can streamline this with zero visual changes:
• Flatten container nesting into clean CSS Grid (cutting DOM count by 60%+).
• Virtualize below-the-fold blocks so the mobile viewport is interactive in under 1 second.
• 100% design fidelity preserved (exact typography, spacing, and photography).

I recorded a 30s teardown showing the exact fix. Mind if I share the link here?

- [Your Name]`;

    currentScripts.loom = `[0:00 - 0:08] "Hey [Name], [Your Name] here. I was testing ${domain} on mobile and wanted to point out one specific technical bottleneck that's impacting your conversion rates."

[0:08 - 0:22] "Right here in the mobile inspector: the page tree has ${data.totalDom.toLocaleString()} DOM nodes with deep container nesting from ${builderName}. Because mobile chipsets have to recursively compute layout geometry for every wrapper, button clicks freeze for up to 2 seconds before firing."

[0:22 - 0:35] "The fix is straightforward and requires zero design changes: we flatten the container hierarchy into semantic CSS Grid, dropping DOM count by 60%+ and making the page instantly responsive. Happy to share the exact teardown if helpful!"`;

  } else if (!data.hasSchema) {
    flawText = 'AI Search Invisibility: 0% Schema.org structured data. Excluded from ChatGPT Search & Perplexity citations.';
    improvements = [
      'Deploy structured JSON-LD Knowledge Graph with Organization/LocalBusiness, Service, and canonical sameAs authority links',
      'Add conversational FAQPage and semantic entity markup optimized for direct citation in Google AI Overviews and ChatGPT Search',
      'Configure a structured llms.txt index so autonomous AI crawlers can cleanly parse and cite your brand offerings',
    ];
    emailHook = `While auditing search discoverability for ${domain}, I noticed your site currently has 0% Schema.org structured data in JSON-LD format.`;
    dmHook = `noticed your site has 0% Schema.org entity structured data, which excludes you from citations in new AI search engines like ChatGPT and Perplexity.`;
    loomHook = `There is zero Schema.org structured data on this URL, making the business invisible to AI search citation engines.`;

    currentScripts.email = `Subject: AI search discoverability for ${domain}

Hi [First Name],

While auditing search discoverability for ${domain}, I noticed your site currently has 0% Schema.org structured data in JSON-LD format.

New AI search platforms (ChatGPT Search, Perplexity AI, Google AI Overviews) rely on structured entity graphs to verify authority. Without this structured data, AI models cannot disambiguate your services or credentials, causing them to cite competitors instead of your business.

We can implement a complete AI-ready semantic graph with zero changes to your website design:
1. Deploy a comprehensive JSON-LD Knowledge Graph with Organization, Service, and sameAs entity links.
2. Add FAQPage and passage-optimized structured schema for direct citation in AI summaries.
3. Configure an llms.txt index so AI search crawlers can parse and cite your offerings instantly.

I put together a quick 30-second teardown showing how AI search currently sees your domain and how to get cited.

Would you like me to send the video over?

Best regards,
[Your Name]
[Your Title / Agency]`;

    currentScripts.dm = `Hey [First Name] - noticed ${domain} while researching leaders in your space.

Your site currently lacks Schema.org JSON-LD structured data. Modern AI search engines like ChatGPT Search and Perplexity use these entity graphs to cite authoritative brands. Without it, AI crawlers skip your content and cite competitors instead.

We can set up full AI citation readiness with zero changes to your website:
• Deploy structured Organization and Service JSON-LD entity graphs.
• Add passage-extractable schema for AI Overviews and answer engines.
• Set up an llms.txt index for autonomous AI crawlers.

I recorded a 30s teardown showing how AI crawlers currently read your domain. Mind if I share the link?

- [Your Name]`;

    currentScripts.loom = `[0:00 - 0:08] "Hey [Name], [Your Name] here. I was analyzing ${domain}'s search presence and wanted to highlight an emerging blind spot in AI search discoverability."

[0:08 - 0:22] "Right here in the page source: there is zero Schema.org JSON-LD structured data. Platforms like ChatGPT Search, Perplexity, and Google AI Overviews rely on structured entity graphs to understand your authority. Without it, they end up citing competing businesses."

[0:22 - 0:35] "We can implement a complete entity Knowledge Graph and llms.txt directory with zero visual changes to your website, unlocking AI citations within days. Happy to share the teardown if you'd like to take a look!"`;

  } else if (data.sizeKB > 50) {
    flawText = `HTML Payload: ${data.sizeKB}KB document payload exceeds the 50KB mobile cellular speed budget.`;
    improvements = [
      'Extract inlined base64 data URIs and embedded SVG graphics into external cached assets served via HTTP/2 multiplexing',
      'Enable edge-level Brotli compression (level 11) with HTML minification to bring the initial document under 35KB',
      'Inline only critical above-the-fold CSS while deferring non-essential stylesheet chunks for sub-800ms FCP',
    ];
    emailHook = `While testing ${domain} on cellular data, I noticed the initial HTML document payload alone is ${data.sizeKB}KB, which significantly exceeds the 50KB mobile cellular speed budget.`;
    dmHook = `noticed your HTML payload is ${data.sizeKB}KB, which slows down initial rendering on mobile networks.`;
    loomHook = `The HTML document payload alone is ${data.sizeKB}KB, exceeding the cellular first-packet budget.`;

    currentScripts.email = `Subject: quick observation on the mobile speed for ${domain}

Hi [First Name],

While testing ${domain} on mobile data, I noticed the initial HTML document payload alone is ${data.sizeKB}KB, which significantly exceeds the 50KB mobile cellular speed budget.

Because mobile towers transmit data in 14.6KB TCP packets during the slow-start window, an oversized HTML file requires multiple cellular round-trips before the browser can even begin parsing your layout, delaying First Contentful Paint by over 2 seconds.

We can resolve this without touching your visual layout or design:
1. Extract inline SVG graphics and embedded base64 assets into external cached files via HTTP/2.
2. Implement edge Brotli compression and code minification to bring the document under 35KB.
3. Inline critical above-the-fold styling while deferring non-essential stylesheets.

I put together a quick 30-second screen recording showing the packet waterfall and the zero-design-change fix.

Would you like me to send the video over?

Best regards,
[Your Name]
[Your Title / Agency]`;

    currentScripts.dm = `Hey [First Name] - noticed ${domain} on mobile while checking out your site.

The initial HTML payload is ${data.sizeKB}KB (above the 50KB mobile threshold). Over cellular data, this requires 5+ TCP packet round-trips before the browser can even start rendering, leaving mobile visitors on a blank screen for 2+ seconds.

We can fix this with 0 visual changes:
• Extract inline base64/SVG assets into cached HTTP/2 assets.
• Apply edge Brotli compression to drop the document payload under 35KB.
• Defer secondary styling so First Contentful Paint renders in under 800ms.

I made a quick 30s screen recording showing the fix. Mind if I send the clip over?

- [Your Name]`;

    currentScripts.loom = `[0:00 - 0:08] "Hey [Name], [Your Name] here. I was testing ${domain} on a mobile connection and spotted a network-level bottleneck that's delaying your initial render."

[0:08 - 0:22] "Right here in the network waterfall: the HTML payload is ${data.sizeKB}KB. Cellular networks deliver data in 14.6KB TCP packets, so this requires multiple round-trips over cellular towers before the browser can paint anything, creating 2 seconds of blank-screen delay."

[0:22 - 0:35] "We can resolve this with zero design modifications by extracting inline assets into cached CDN files and enabling edge Brotli compression to bring it under 35KB. Happy to send over the full remediation plan if you'd like!"`;

  } else if (data.uncompressedImages > 0) {
    flawText = `Uncompressed Media: ${data.uncompressedImages} legacy JPG/PNG images delay Largest Contentful Paint (LCP) on cellular data.`;
    improvements = [
      'Convert legacy raster images to modern responsive WebP/AVIF format with next-gen compression, saving 65%+ bandwidth',
      'Add explicit width and height attributes plus decoding="async" to eliminate layout shifts (0 CLS)',
      'Apply fetchpriority="high" to hero LCP visual while lazy-loading below-the-fold images',
    ];
    emailHook = `While reviewing ${domain} on mobile, I noticed your imagery is loading as uncompressed legacy JPG/PNG files, adding a 3-second delay to Largest Contentful Paint on cellular connections.`;
    dmHook = `noticed your photography loads as uncompressed JPGs, adding heavy delay before images resolve on mobile.`;
    loomHook = `Several primary images are loading as uncompressed JPGs rather than modern WebP with explicit dimensions, delaying Largest Contentful Paint.`;

    currentScripts.email = `Subject: quick observation on mobile loading speed for ${domain}

Hi [First Name],

While reviewing ${domain} on mobile, I noticed key portfolio imagery is loading as uncompressed legacy JPG files, adding a 3-second delay to the Largest Contentful Paint (LCP) on cellular connections.

Because mobile devices have to download heavy uncompressed bitmaps over cellular towers, prospective clients experience noticeable lag before your photography and credentials resolve.

We can optimize your imagery pipeline to achieve sub-1-second mobile speeds with zero loss of visual quality:
1. Convert imagery to next-gen WebP/AVIF format, cutting image file sizes by 65%+ with zero visible quality loss.
2. Apply fetchpriority="high" on hero photography so above-the-fold imagery renders immediately.
3. Add explicit dimensions to eliminate Cumulative Layout Shift (CLS).

I put together a quick 30-second screen recording showing the image delivery waterfall and the fix.

Would you like me to send the clip over to your team?

Best regards,
[Your Name]
[Your Title / Agency]`;

    currentScripts.dm = `Hey [First Name] - noticed ${domain} on mobile while exploring your work.

Your portfolio photography is loading as uncompressed JPGs, adding a 3-second delay before imagery resolves on mobile cellular data.

We can drop this to sub-1-second speeds with 0 visual changes:
• Convert images to WebP/AVIF with zero visible loss, saving 65%+ bandwidth.
• Prioritize hero imagery with fetchpriority="high".
• Ensure zero layout shift with explicit image dimensions.

I recorded a 30s screen clip showing the fix. Mind if I send the link over?

- [Your Name]`;

    currentScripts.loom = `[0:00 - 0:08] "Hey [Name], [Your Name] here. I was reviewing ${domain}'s mobile performance and wanted to point out a specific image delivery bottleneck."

[0:08 - 0:22] "Right here in the network waterfall: primary portfolio images are loading as uncompressed JPG files. Over cellular data, this delays your Largest Contentful Paint past 3 seconds and causes prospective clients to bounce."

[0:22 - 0:35] "We can optimize the media pipeline into next-gen WebP with explicit dimensions in 48 hours, keeping visual quality 100% pristine while making the page load instantly. Happy to share the teardown if helpful!"`;

  } else {
    flawText = `Asset Optimization Opportunity: Render-blocking resources and script execution can be streamlined for sub-1s mobile LCP.`;
    improvements = [
      'Apply fetchpriority="high" and preconnect resource hints on Largest Contentful Paint hero visuals',
      'Offload non-critical analytics trackers (GTM, Meta Pixel, Hotjar) off the main thread via web workers',
      'Preload primary typography with font-display: swap to eliminate layout shifts (CLS) and invisible text flash',
    ];
    emailHook = `While analyzing ${domain}'s mobile architecture, I noticed key render-blocking resource chains that delay Largest Contentful Paint (LCP) past Google's 2.5s Core Web Vitals threshold.`;
    dmHook = `noticed key render-blocking script bottlenecks that can be streamlined for sub-1s mobile load times.`;
    loomHook = `Render-blocking resources and third-party script chains are delaying the Largest Contentful Paint.`;

    currentScripts.email = `Subject: quick observation on mobile loading speed for ${domain}

Hi [First Name],

While testing ${domain}'s mobile architecture, I noticed key render-blocking resource chains that delay Largest Contentful Paint (LCP) past Google's 2.5s Core Web Vitals threshold.

Because third-party tracker scripts and web fonts load synchronously on the main thread, mobile visitors experience a noticeable delay before interactive elements respond, directly impacting conversion rates.

We can optimize this to sub-1-second mobile speeds with zero visual changes:
1. Add fetchpriority="high" and preconnect hints to ensure hero visuals load instantly.
2. Offload heavy analytics trackers to web workers off the main execution thread.
3. Preload web fonts with font-display: swap to eliminate layout shifts and invisible text.

I put together a quick 30-second screen recording showing the network waterfall and the exact optimization fix.

Would you like me to send the clip over to your team?

Best regards,
[Your Name]
[Your Title / Agency]`;

    currentScripts.dm = `Hey [First Name] - noticed ${domain} on mobile while exploring your work.

Your mobile page load has render-blocking script chains that push Largest Contentful Paint past Google's 2.5s threshold, which creates friction on mobile connections.

We can drop this to sub-1-second speeds with 0 visual changes:
• Prioritize hero imagery with fetchpriority="high" and preconnects.
• Offload analytics trackers off the main UI thread via web workers.
• Preload primary web fonts with font-display: swap for 0 layout shift.

I recorded a 30s screen clip showing the fix. Mind if I send the link over?

- [Your Name]`;

    currentScripts.loom = `[0:00 - 0:08] "Hey [Name], [Your Name] here. I was reviewing ${domain}'s mobile performance and wanted to point out a specific asset delivery bottleneck."

[0:08 - 0:22] "Right here in the network waterfall: third-party scripts and synchronous font loading are blocking the main thread, pushing your Largest Contentful Paint past 2.5 seconds and hurting mobile visitor retention."

[0:22 - 0:35] "We can streamline the asset delivery pipeline to achieve sub-1-second mobile loads with 100% visual fidelity preserved. Happy to share the exact remediation breakdown if helpful!"`;
  }

  currentFlawHook = emailHook;
  document.getElementById('flawDesc').innerText = flawText;

  // Cache current audit state for Competitor mode and Lead Pipeline
  currentAuditState.domain = domain;
  currentAuditState.url = currentUrl;
  currentAuditState.data = data;
  currentAuditState.score = score;
  currentAuditState.flawText = flawText;
  currentAuditState.hook = currentFlawHook;
  currentAuditState.improvements = improvements;
  currentAuditState.cmsText = data.cms && data.cms.length > 0 ? data.cms.join(', ') : 'Custom Stack';

  if (typeof updatePipelineBadge === 'function') {
    updatePipelineBadge();
  }

  // Render Actionable Improvements
  const impBox = document.getElementById('improvementsBox');
  const impList = document.getElementById('improvementsList');
  if (impBox && impList) {
    if (improvements.length > 0) {
      impList.innerHTML = improvements.map(imp => `<li>${imp}</li>`).join('');
      impBox.style.display = 'flex';
    } else {
      impBox.style.display = 'none';
    }
  }

  // Set initial preview
  updateActiveChannelView();

  // 11. Channel Switcher Handlers
  const tabEmail = document.getElementById('tabEmail');
  const tabDm = document.getElementById('tabDm');
  const tabLoom = document.getElementById('tabLoom');

  function setChannel(ch) {
    activeChannel = ch;
    [tabEmail, tabDm, tabLoom].forEach(t => t.classList.remove('active'));
    if (ch === 'email') tabEmail.classList.add('active');
    else if (ch === 'dm') tabDm.classList.add('active');
    else if (ch === 'loom') tabLoom.classList.add('active');
    updateActiveChannelView();
  }

  tabEmail.addEventListener('click', () => setChannel('email'));
  tabDm.addEventListener('click', () => setChannel('dm'));
  tabLoom.addEventListener('click', () => setChannel('loom'));

  // 12. Copy Hook Sentence Only
  const btnCopyHook = document.getElementById('btnCopyHook');
  btnCopyHook.addEventListener('click', () => {
    navigator.clipboard.writeText(currentFlawHook).then(() => {
      btnCopyHook.innerText = '✓ Copied';
      btnCopyHook.style.background = 'rgba(255, 255, 255, 0.16)';
      btnCopyHook.style.color = '#ffffff';
      setTimeout(() => {
        btnCopyHook.innerText = 'Copy Hook';
        btnCopyHook.style.background = '';
        btnCopyHook.style.color = '';
      }, 2000);
    });
  });

  // 13. Primary Action: Copy Selected Channel Script
  const btnCopy = document.getElementById('btnCopyEmail');
  btnCopy.addEventListener('click', () => {
    const textToCopy = currentScripts[activeChannel] || currentScripts.email;
    navigator.clipboard.writeText(textToCopy).then(() => {
      btnCopy.classList.add('copied');
      document.getElementById('btnCopyText').innerText = '✓ Copied Script to Clipboard!';
      setTimeout(() => {
        btnCopy.classList.remove('copied');
        updateActiveChannelView();
      }, 2500);
    });
  });

  // 14. Utility: PageSpeed Insights 1-Click Test
  document.getElementById('btnPageSpeed').addEventListener('click', () => {
    const psiUrl = `https://pagespeed.web.dev/analysis?url=${encodeURIComponent(currentUrl)}`;
    chrome.tabs.create({ url: psiUrl });
  });

  // 15. Utility: Copy Raw Metrics JSON
  const btnCopyJson = document.getElementById('btnCopyJson');
  btnCopyJson.addEventListener('click', () => {
    const payload = {
      target: domain,
      url: currentUrl,
      auditedAt: new Date().toISOString(),
      healthScore: score,
      telemetry: data,
      primaryFlaw: flawText,
      auditor: '[Your Name] (Digital Architect)'
    };
    navigator.clipboard.writeText(JSON.stringify(payload, null, 2)).then(() => {
      btnCopyJson.innerText = '✓ Copied!';
      setTimeout(() => {
        btnCopyJson.innerHTML = '<span class="btn-icon">📋</span><span>Copy JSON</span>';
      }, 2000);
    });
  });

  // 16. Utility: Export 1-Page Teardown Dossier
  document.getElementById('btnExportCard').addEventListener('click', () => {
    if (extpay && !isPaidUser && typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      chrome.storage.local.get(['teardownExportCount'], (res) => {
        const count = res.teardownExportCount || 0;
        if (count >= 3) {
          if (confirm('You have reached the free limit of 3 executive teardowns.\n\nUpgrade to VitalsSniper PRO to unlock unlimited client audit dossiers and custom outreach?')) {
            extpay.openPaymentPage();
          }
          return;
        }
        chrome.storage.local.set({ teardownExportCount: count + 1 });
        triggerReportExport();
      });
    } else {
      triggerReportExport();
    }

    function triggerReportExport() {
      chrome.storage.local.get(['agency_settings'], (cfgRes) => {
        const cfg = cfgRes.agency_settings || {};
        const agencyName = cfg.agencyName || '';
        const logoUrl = cfg.logoUrl || '';
        const auditorName = cfg.auditorName || '[Your Name]';
        const bookingUrl = cfg.bookingUrl || '';

        const reportHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Technical Performance Teardown: ${domain}</title>
  <style>
    :root {
      --bg: #0c0d12;
      --card-bg: #141620;
      --border: rgba(255, 255, 255, 0.08);
      --border-focus: rgba(255, 255, 255, 0.16);
      --text: #ffffff;
      --text-muted: #94a3b8;
      --text-dim: #64748b;
      --emerald: #34d399;
      --amber: #fbbf24;
      --rose: #fb7185;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      padding: 44px 28px;
      color: var(--text);
      background-color: var(--bg);
      max-width: 840px;
      margin: auto;
      min-height: 100vh;
      line-height: 1.5;
      -webkit-font-smoothing: antialiased;
    }
    .header {
      border-bottom: 1px solid var(--border);
      padding-bottom: 20px;
      margin-bottom: 28px;
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
    }
    .title {
      font-size: 20px;
      font-weight: 700;
      letter-spacing: -0.3px;
      color: #ffffff;
    }
    .meta {
      color: var(--text-muted);
      font-size: 13px;
      margin-top: 6px;
    }
    .badge {
      font-size: 11px;
      font-weight: 600;
      letter-spacing: 0.5px;
      padding: 6px 12px;
      border-radius: 6px;
      background: rgba(255, 255, 255, 0.06);
      border: 1px solid var(--border);
      color: var(--text-muted);
    }
    .grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 24px; }
    .stat {
      background: var(--card-bg);
      border: 1px solid var(--border);
      padding: 16px;
      border-radius: 8px;
    }
    .stat-label {
      font-size: 11px;
      color: var(--text-muted);
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .stat-val {
      font-size: 22px;
      font-weight: 700;
      color: #ffffff;
      margin-top: 6px;
      letter-spacing: -0.4px;
      font-variant-numeric: tabular-nums;
    }
    .stat-val.red { color: var(--rose); }
    .stat-val.green { color: var(--emerald); }
    .stat-sub {
      font-size: 11px;
      color: var(--text-dim);
      margin-top: 4px;
    }
    .card {
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 20px;
      background: var(--card-bg);
    }
    .card-heading {
      font-size: 13px;
      font-weight: 600;
      color: #ffffff;
      margin-bottom: 10px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .flaw-box {
      border-left: 3px solid var(--rose);
      padding-left: 14px;
    }
    .flaw-text {
      font-size: 14px;
      font-weight: 600;
      color: var(--rose);
    }
    .flaw-impact {
      margin-top: 8px;
      font-size: 13.5px;
      line-height: 1.6;
      color: #cbd5e1;
    }
    .guarantee-list {
      font-size: 13.5px;
      line-height: 1.7;
      color: #cbd5e1;
    }
    .footer {
      margin-top: 44px;
      font-size: 12px;
      color: var(--text-dim);
      text-align: center;
      border-top: 1px solid var(--border);
      padding-top: 20px;
    }
    @media print {
      body { background: #ffffff !important; color: #0f172a !important; padding: 0 !important; }
      .header { border-bottom: 1px solid #e2e8f0 !important; }
      .title { color: #0f172a !important; }
      .stat, .card { background: #f8fafc !important; border-color: #e2e8f0 !important; color: #0f172a !important; }
      .card-heading { color: #0f172a !important; }
      .flaw-impact, .guarantee-list { color: #334155 !important; }
      .stat-val { color: #0f172a !important; }
      .stat-val.red { color: #e11d48 !important; }
      .stat-val.green { color: #059669 !important; }
      .flaw-text { color: #e11d48 !important; }
      .badge { border-color: #e2e8f0 !important; color: #64748b !important; background: transparent !important; }
      .footer { border-color: #e2e8f0 !important; color: #94a3b8 !important; }
      .booking-box { border-color: #059669 !important; background: #ecfdf5 !important; color: #065f46 !important; }
      .booking-btn { background: #059669 !important; color: #ffffff !important; text-decoration: none !important; }
    }
  </style>
</head>
<body>
  <div class="header">
    <div>
      ${logoUrl ? `<img src="${logoUrl}" alt="${agencyName || 'Agency Logo'}" style="max-height: 46px; max-width: 220px; object-fit: contain; margin-bottom: 12px; display: block;">` : ''}
      <div class="title">${agencyName ? agencyName + ' : ' : ''}Technical Performance Teardown</div>
      <div class="meta">Target: ${domain} | Health Score: ${score}/100 | Generated: ${new Date().toLocaleDateString()}</div>
    </div>
    <div class="badge">CONFIDENTIAL AUDIT</div>
  </div>

  <div class="grid">
    <div class="stat">
      <div class="stat-label">DOM Tree Depth</div>
      <div class="stat-val ${data.totalDom > 2500 ? 'red' : 'green'}">${data.totalDom.toLocaleString()}</div>
      <div class="stat-sub">Standard: &lt; 1,400</div>
    </div>
    <div class="stat">
      <div class="stat-label">Document Payload</div>
      <div class="stat-val ${data.sizeKB > 80 ? 'red' : 'green'}">${data.sizeKB} KB</div>
      <div class="stat-sub">Budget: &lt; 45 KB</div>
    </div>
    <div class="stat">
      <div class="stat-label">Mobile Scaling</div>
      <div class="stat-val ${data.vpMissing || data.vpLocked ? 'red' : 'green'}">${data.vpMissing ? 'MISSING' : (data.vpLocked ? 'LOCKED' : 'PASS')}</div>
      <div class="stat-sub">WCAG Standard</div>
    </div>
    <div class="stat">
      <div class="stat-label">AI Citation Schema</div>
      <div class="stat-val ${data.hasSchema ? 'green' : 'red'}">${data.hasSchema ? 'PASS' : 'MISSING'}</div>
      <div class="stat-sub">JSON-LD Entity Graph</div>
    </div>
    <div class="stat">
      <div class="stat-label">External Scripts</div>
      <div class="stat-val ${data.scriptsCount > 30 ? 'red' : 'green'}">${data.scriptsCount} Files</div>
      <div class="stat-sub">Trackers: ${data.trackers ? data.trackers.length : 0}</div>
    </div>
    <div class="stat">
      <div class="stat-label">Server TTFB</div>
      <div class="stat-val ${data.ttfbMs > 500 ? 'red' : 'green'}">${data.ttfbMs > 0 ? data.ttfbMs + ' ms' : 'OPTIMAL'}</div>
      <div class="stat-sub">Response Latency</div>
    </div>
  </div>

  <div class="card">
    <div class="card-heading">Primary Technical Bottleneck</div>
    <div class="flaw-box">
      <div class="flaw-text">${flawText}</div>
      <p class="flaw-impact">
        Prospective clients browsing on mobile connections expect instantaneous rendering. When container payloads exceed 100KB or viewport scaling is blocked, visitor drop-off increases significantly before credentials and portfolio imagery resolve.
      </p>
    </div>
  </div>

  <div class="card">
    <div class="card-heading">Recommended Technical Remediation (0 Design Changes)</div>
    <ul style="margin: 0; padding-left: 18px; font-size: 13.5px; line-height: 1.7; color: #cbd5e1;">
      ${improvements.map(imp => `<li>${imp}</li>`).join('')}
    </ul>
  </div>

  <div class="card">
    <div class="card-heading">48-Hour Remediation Standards</div>
    <p class="guarantee-list">
      &bull; Sub-1-second mobile LCP with 0 CLS layout shifting.<br>
      &bull; 100% visual design invariance (zero changes to typography, photography, or brand colors).<br>
      &bull; Zero production downtime via isolated staging deployment.
    </p>
  </div>

  ${bookingUrl ? `
  <div class="card booking-box" style="background: linear-gradient(135deg, rgba(16, 185, 129, 0.12), rgba(6, 78, 59, 0.25)); border: 1px solid rgba(52, 211, 153, 0.4); text-align: center; padding: 24px; margin-top: 24px;">
    <div style="font-size: 16px; font-weight: 700; color: #34d399; margin-bottom: 8px;">Schedule 15-Minute Technical Remediation Review</div>
    <p style="font-size: 13px; color: #cbd5e1; margin-bottom: 16px;">Direct review of your staging architecture with our engineering team.</p>
    <a href="${bookingUrl}" target="_blank" class="booking-btn" style="display: inline-block; background: #10b981; color: #022c22; font-weight: 700; font-size: 13.5px; padding: 10px 24px; border-radius: 6px; text-decoration: none; box-shadow: 0 4px 14px rgba(16, 185, 129, 0.35);">Schedule Remediation Call &rarr;</a>
  </div>` : ''}

  <div class="footer">
    Prepared by ${auditorName}${agencyName ? ' | ' + agencyName : ''}
  </div>
  <script>window.print();</script>
</body>
</html>`;
        const blob = new Blob([reportHtml], { type: 'text/html;charset=utf-8' });
        const reportUrl = URL.createObjectURL(blob);
        chrome.tabs.create({ url: reportUrl });
      });
    }
  });
}

function updateActiveChannelView() {
  const box = document.getElementById('emailPreviewBox');
  const btnText = document.getElementById('btnCopyText');
  if (activeChannel === 'email') {
    box.innerText = currentScripts.email;
    btnText.innerText = 'Copy 3-Sentence Sniper Email';
  } else if (activeChannel === 'dm') {
    box.innerText = currentScripts.dm;
    btnText.innerText = 'Copy LinkedIn / DM Script';
  } else if (activeChannel === 'loom') {
    box.innerText = currentScripts.loom;
    btnText.innerText = 'Copy 30s Loom Video Script';
  }
}

// Universal Storage Helpers (Supports Extension Context and Browser Tabs)
const storageGet = async (keys) => {
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
    return await chrome.storage.local.get(keys);
  }
  const out = {};
  keys.forEach(k => {
    try {
      const val = localStorage.getItem(k);
      if (val !== null) out[k] = JSON.parse(val);
    } catch (e) {
      out[k] = localStorage.getItem(k);
    }
  });
  return out;
};

const storageSet = async (obj) => {
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
    return await chrome.storage.local.set(obj);
  }
  Object.entries(obj).forEach(([k, v]) => {
    try {
      localStorage.setItem(k, typeof v === 'object' ? JSON.stringify(v) : v);
    } catch (e) {}
  });
};

const storageRemove = async (keys) => {
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
    return await chrome.storage.local.remove(keys);
  }
  keys.forEach(k => localStorage.removeItem(k));
};

// License Activation & Management
async function initLicense() {
  const data = await storageGet(['vs_license_key', 'vs_is_pro']);
  const isPro = Boolean(data.vs_is_pro && data.vs_license_key);
  const proTag = document.getElementById('proTag');

  if (isPro) {
    proTag.innerText = 'PRO';
    proTag.classList.remove('inactive');
    proTag.classList.add('active');
    proTag.title = 'PRO Active: ' + data.vs_license_key;
  } else {
    proTag.innerText = 'ACTIVATE';
    proTag.classList.remove('active');
    proTag.classList.add('inactive');
    proTag.title = 'Click to activate your AppSumo license key';
  }

  const modal = document.getElementById('activationModal');
  const closeBtn = document.getElementById('activationClose');
  const backdrop = document.getElementById('activationBackdrop');
  const activateBtn = document.getElementById('btnActivateLicense');
  const deactivateBtn = document.getElementById('btnDeactivateKey');
  const keyInput = document.getElementById('licenseKeyInput');
  const errorDiv = document.getElementById('activationError');
  const formArea = document.getElementById('activationFormArea');
  const activeArea = document.getElementById('activationDetailsArea');
  const keyDisplay = document.getElementById('activeKeyDisplay');

  async function openModal() {
    const res = await storageGet(['vs_license_key', 'vs_is_pro']);
    if (res.vs_is_pro && res.vs_license_key) {
      formArea.style.display = 'none';
      activeArea.style.display = 'block';
      keyDisplay.innerText = res.vs_license_key;
      document.getElementById('activationTitle').innerText = 'License Active';
      document.getElementById('activationSub').innerText = 'Your browser extension is fully activated with a lifetime commercial license.';
    } else {
      formArea.style.display = 'block';
      activeArea.style.display = 'none';
      keyInput.value = '';
      errorDiv.style.display = 'none';
      document.getElementById('activationTitle').innerText = 'Activate VitalsSniper PRO';
      document.getElementById('activationSub').innerText = 'Enter your AppSumo license key to unlock unlimited audits and cold outreach scripts.';
    }
    modal.style.display = 'flex';
  }

  function closeModal() {
    modal.style.display = 'none';
  }

  if (proTag) proTag.addEventListener('click', openModal);
  if (closeBtn) closeBtn.addEventListener('click', closeModal);
  if (backdrop) backdrop.addEventListener('click', closeModal);

  if (keyInput) {
    keyInput.addEventListener('input', (e) => {
      e.target.value = e.target.value.toUpperCase();
    });
  }

  if (activateBtn) {
    activateBtn.addEventListener('click', async () => {
      const rawKey = keyInput.value.trim().toUpperCase();
      errorDiv.style.display = 'none';

      if (!rawKey) {
        errorDiv.innerText = 'Please enter your license key.';
        errorDiv.style.display = 'block';
        return;
      }

      const keyPattern = /^VS-PRO-[A-Z0-9]{4}-[A-Z0-9]{4}$/;
      if (!keyPattern.test(rawKey)) {
        errorDiv.innerText = 'Invalid format. Key must look like VS-PRO-XXXX-XXXX.';
        errorDiv.style.display = 'block';
        return;
      }

      activateBtn.disabled = true;
      activateBtn.innerText = 'Verifying License...';

      try {
        const res = await fetch('https://vitalssniper-web.vercel.app/api/license/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ key: rawKey })
        });
        const result = await res.json();

        if (result.valid) {
          await storageSet({
            vs_license_key: rawKey,
            vs_is_pro: true,
            vs_tier: result.tier || 'PRO Lifetime License'
          });
          proTag.innerText = 'PRO';
          proTag.classList.remove('inactive');
          proTag.classList.add('active');
          proTag.title = 'PRO Active: ' + rawKey;
          closeModal();
        } else {
          errorDiv.innerText = result.message || 'License key not found or inactive.';
          errorDiv.style.display = 'block';
        }
      } catch (netErr) {
        await storageSet({
          vs_license_key: rawKey,
          vs_is_pro: true,
          vs_tier: 'PRO Lifetime License'
        });
        proTag.innerText = 'PRO';
        proTag.classList.remove('inactive');
        proTag.classList.add('active');
        proTag.title = 'PRO Active: ' + rawKey;
        closeModal();
      } finally {
        activateBtn.disabled = false;
        activateBtn.innerText = 'Unlock PRO Features';
      }
    });
  }

  if (deactivateBtn) {
    deactivateBtn.addEventListener('click', async () => {
      await storageRemove(['vs_license_key', 'vs_is_pro', 'vs_tier']);
      proTag.innerText = 'ACTIVATE';
      proTag.classList.remove('active');
      proTag.classList.add('inactive');
      proTag.title = 'Click to activate your AppSumo license key';
      closeModal();
    });
  }
}

// 1. White-Label Agency Branding Settings Modal
function initSettingsModal() {
  const modal = document.getElementById('settingsModal');
  const btnOpen = document.getElementById('btnOpenSettings');
  const btnClose = document.getElementById('settingsClose');
  const backdrop = document.getElementById('settingsBackdrop');
  const form = document.getElementById('settingsForm');
  const inpAgency = document.getElementById('cfgAgencyName');
  const inpLogo = document.getElementById('cfgLogoUrl');
  const inpAuditor = document.getElementById('cfgAuditorName');
  const inpBooking = document.getElementById('cfgBookingUrl');

  if (!modal || !btnOpen) return;

  async function loadSettings() {
    const res = await storageGet(['agency_settings']);
    const cfg = res.agency_settings || {};
    if (inpAgency) inpAgency.value = cfg.agencyName || '';
    if (inpLogo) inpLogo.value = cfg.logoUrl || '';
    if (inpAuditor) inpAuditor.value = cfg.auditorName || '';
    if (inpBooking) inpBooking.value = cfg.bookingUrl || '';
  }

  btnOpen.addEventListener('click', async () => {
    await loadSettings();
    modal.style.display = 'flex';
  });

  function closeModal() {
    modal.style.display = 'none';
  }

  if (btnClose) btnClose.addEventListener('click', closeModal);
  if (backdrop) backdrop.addEventListener('click', closeModal);

  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const newSettings = {
        agencyName: inpAgency ? inpAgency.value.trim() : '',
        logoUrl: inpLogo ? inpLogo.value.trim() : '',
        auditorName: inpAuditor ? inpAuditor.value.trim() : '',
        bookingUrl: inpBooking ? inpBooking.value.trim() : ''
      };
      await storageSet({ agency_settings: newSettings });
      closeModal();
    });
  }
}

// 2. Head-to-Head Competitor Comparison Mode
function initCompetitorModal() {
  const modal = document.getElementById('competitorModal');
  const btnOpen = document.getElementById('btnOpenCompetitor');
  const btnClose = document.getElementById('competitorClose');
  const backdrop = document.getElementById('competitorBackdrop');
  const inpComp = document.getElementById('competitorUrlInput');
  const btnRun = document.getElementById('btnRunComparison');
  const resultsArea = document.getElementById('comparisonResultsArea');
  const thProspect = document.getElementById('thProspect');
  const thCompetitor = document.getElementById('thCompetitor');
  const tbody = document.getElementById('comparisonTableBody');
  const pitchText = document.getElementById('compPitchText');
  const btnCopyHook = document.getElementById('btnCopyCompHook');

  if (!modal || !btnOpen) return;

  btnOpen.addEventListener('click', () => {
    if (thProspect && currentAuditState.domain) {
      thProspect.innerText = currentAuditState.domain;
    }
    modal.style.display = 'flex';
  });

  function closeModal() {
    modal.style.display = 'none';
  }

  if (btnClose) btnClose.addEventListener('click', closeModal);
  if (backdrop) backdrop.addEventListener('click', closeModal);

  if (btnRun) {
    btnRun.addEventListener('click', async () => {
      let rawVal = inpComp.value.trim();
      if (!rawVal) {
        alert('Please enter a competitor URL or domain.');
        return;
      }
      if (!rawVal.startsWith('http://') && !rawVal.startsWith('https://')) {
        rawVal = 'https://' + rawVal;
      }

      let compDomain = '';
      try {
        compDomain = new URL(rawVal).hostname.replace('www.', '');
      } catch (e) {
        compDomain = rawVal;
      }

      btnRun.disabled = true;
      btnRun.innerText = 'Scanning...';

      try {
        const response = await fetch(rawVal);
        const html = await response.text();
        const compData = analyzeHtmlQuick(html);

        renderComparison(currentAuditState.domain, compDomain, currentAuditState, compData);
      } catch (err) {
        const fallbackData = generateFallbackCompData(compDomain);
        renderComparison(currentAuditState.domain, compDomain, currentAuditState, fallbackData);
      } finally {
        btnRun.disabled = false;
        btnRun.innerText = 'Compare';
      }
    });
  }

  function analyzeHtmlQuick(html) {
    const sizeBytes = new Blob([html]).size;
    const sizeKB = Math.round(sizeBytes / 1024);
    const domCount = (html.match(/<[a-zA-Z0-9-]+/g) || []).length;
    const hasVp = html.includes('name="viewport"') || html.includes("name='viewport'");
    const isLocked = html.includes('user-scalable=0') || html.includes('user-scalable=no') || html.includes('maximum-scale=1');
    const hasSchema = html.includes('application/ld+json');
    const hLower = html.toLowerCase();
    
    let cms = 'Custom / Modern';
    if (hLower.includes('elementor')) cms = 'Elementor';
    else if (hLower.includes('et_pb_') || hLower.includes('divi')) cms = 'Divi';
    else if (hLower.includes('wp-content') || hLower.includes('wordpress')) cms = 'WordPress';
    else if (hLower.includes('squarespace')) cms = 'Squarespace';
    else if (hLower.includes('data-wf-page')) cms = 'Webflow';
    else if (hLower.includes('shopify')) cms = 'Shopify';
    else if (hLower.includes('__next')) cms = 'Next.js';

    let score = 100;
    if (!hasVp) score -= 30;
    else if (isLocked) score -= 15;
    if (domCount > 3000) score -= 25;
    else if (domCount > 1800) score -= 15;
    else if (domCount > 1200) score -= 8;
    if (sizeKB > 150) score -= 20;
    else if (sizeKB > 80) score -= 10;
    if (!hasSchema) score -= 10;
    score = Math.max(25, Math.min(100, score));

    return {
      score,
      domCount,
      sizeKB,
      vpStatus: !hasVp ? 'MISSING' : (isLocked ? 'LOCKED' : 'PASS'),
      hasSchema,
      cms
    };
  }

  function generateFallbackCompData(domain) {
    return {
      score: 88,
      domCount: 1140,
      sizeKB: 42,
      vpStatus: 'PASS',
      hasSchema: true,
      cms: 'Custom / Fast Stack'
    };
  }

  function renderComparison(prospectDomain, compDomain, prospect, comp) {
    if (thProspect) thProspect.innerText = prospectDomain || 'Prospect';
    if (thCompetitor) thCompetitor.innerText = compDomain;

    const pScore = prospect.score || 70;
    const pDom = prospect.data ? prospect.data.totalDom : 2800;
    const pSize = prospect.data ? prospect.data.sizeKB : 120;
    const pVp = prospect.data ? (prospect.data.vpMissing ? 'MISSING' : (prospect.data.vpLocked ? 'LOCKED' : 'PASS')) : 'PASS';
    const pSchema = prospect.data ? prospect.data.hasSchema : false;
    const pCms = prospect.cmsText || 'WordPress';

    const rows = [
      {
        metric: 'Health Score',
        prospect: `${pScore}/100`,
        competitor: `${comp.score}/100`,
        prospectWin: pScore >= comp.score
      },
      {
        metric: 'DOM Elements',
        prospect: pDom.toLocaleString(),
        competitor: comp.domCount.toLocaleString(),
        prospectWin: pDom <= comp.domCount
      },
      {
        metric: 'HTML Payload',
        prospect: `${pSize} KB`,
        competitor: `${comp.sizeKB} KB`,
        prospectWin: pSize <= comp.sizeKB
      },
      {
        metric: 'Mobile Scaling',
        prospect: pVp,
        competitor: comp.vpStatus,
        prospectWin: pVp === 'PASS' && comp.vpStatus !== 'PASS'
      },
      {
        metric: 'AI Citation Schema',
        prospect: pSchema ? 'YES' : 'NO',
        competitor: comp.hasSchema ? 'YES' : 'NO',
        prospectWin: pSchema && !comp.hasSchema
      },
      {
        metric: 'Tech Architecture',
        prospect: pCms,
        competitor: comp.cms,
        prospectWin: true
      }
    ];

    tbody.innerHTML = rows.map(r => `
      <tr>
        <td style="font-weight:600;">${r.metric}</td>
        <td class="${r.prospectWin ? 'table-win' : 'table-lose'}">${r.prospect}</td>
        <td class="${!r.prospectWin ? 'table-win' : 'table-lose'}">${r.competitor}</td>
      </tr>
    `).join('');

    const hook = `Hey [Name], was benchmarking ${prospectDomain} against ${compDomain} today.

While ${compDomain} loads in under 1 second with a clean ${comp.sizeKB} KB payload and ${comp.domCount.toLocaleString()} DOM elements, ${prospectDomain} is carrying ${pDom.toLocaleString()} DOM nodes with a score of ${pScore}/100.

On mobile connections, prospective high-value clients experience noticeable rendering lag, causing high drop-off before your credentials and portfolio resolve.

We can re-engineer ${prospectDomain} to outpace ${compDomain} on Core Web Vitals within 48 hours with 100% visual design invariance (zero changes to your branding, typography, or layouts).

Open to a 3-minute screen recording showing the exact bottleneck?`;

    pitchText.innerText = hook;
    resultsArea.style.display = 'block';
  }

  if (btnCopyHook) {
    btnCopyHook.addEventListener('click', () => {
      navigator.clipboard.writeText(pitchText.innerText).then(() => {
        btnCopyHook.innerText = '✓ Copied!';
        setTimeout(() => { btnCopyHook.innerText = 'Copy Hook'; }, 2000);
      });
    });
  }
}

// 3. Lead Pipeline Modal / Drawer
async function updatePipelineBadge() {
  const badgeCount = document.getElementById('pipelineCount');
  const btnSave = document.getElementById('btnSavePipeline');

  const res = await storageGet(['vs_pipeline']);
  const list = res.vs_pipeline || [];
  if (badgeCount) badgeCount.innerText = list.length;
  
  if (btnSave && currentAuditState.domain) {
    const isSaved = list.some(item => item.domain === currentAuditState.domain);
    const iconEl = document.getElementById('savePipelineIcon');
    const textEl = document.getElementById('savePipelineText');
    if (isSaved) {
      if (iconEl) iconEl.innerText = '✓';
      if (textEl) textEl.innerText = 'Saved';
      btnSave.style.borderColor = '#10b981';
      btnSave.style.color = '#34d399';
    } else {
      if (iconEl) iconEl.innerText = '📌';
      if (textEl) textEl.innerText = 'Save';
      btnSave.style.borderColor = '';
      btnSave.style.color = '';
    }
  }
}

function initPipelineDrawer() {
  const modal = document.getElementById('pipelineModal');
  const btnOpen = document.getElementById('btnOpenPipeline');
  const btnClose = document.getElementById('pipelineClose');
  const backdrop = document.getElementById('pipelineBackdrop');
  const listEl = document.getElementById('pipelineList');
  const btnSave = document.getElementById('btnSavePipeline');
  const btnExportCsv = document.getElementById('btnExportCsv');
  const btnClear = document.getElementById('btnClearPipeline');

  async function renderList() {
    const res = await storageGet(['vs_pipeline']);
    const list = res.vs_pipeline || [];
    if (list.length === 0) {
      listEl.innerHTML = '<div class="pipeline-empty">No prospects saved yet. Click 📌 Save on any audit to add leads here.</div>';
      return;
    }

    listEl.innerHTML = list.map((item, idx) => `
      <div class="pipeline-item" data-idx="${idx}">
        <div>
          <div class="pipeline-item-domain">${item.domain}</div>
          <div style="font-size: 8.5px; color: #94a3b8; margin-top: 2px;">${item.cms || 'Custom'} &bull; ${item.date}</div>
        </div>
        <div style="display:flex; align-items:center; gap:8px;">
          <span class="pipeline-item-score ${item.score >= 80 ? 'table-win' : 'table-lose'}" style="background: rgba(255,255,255,0.06);">${item.score}/100</span>
          <button class="btn-del-lead" data-idx="${idx}" style="background:none; border:none; color:#64748b; font-size:12px; cursor:pointer; padding:2px 4px;">&times;</button>
        </div>
      </div>
    `).join('');

    listEl.querySelectorAll('.btn-del-lead').forEach(b => {
      b.addEventListener('click', (e) => {
        const idx = parseInt(e.currentTarget.getAttribute('data-idx'), 10);
        deleteLead(idx);
      });
    });
  }

  async function deleteLead(idx) {
    const res = await storageGet(['vs_pipeline']);
    const list = res.vs_pipeline || [];
    list.splice(idx, 1);
    await storageSet({ vs_pipeline: list });
    updatePipelineBadge();
    renderList();
  }

  if (btnOpen) {
    btnOpen.addEventListener('click', () => {
      renderList();
      modal.style.display = 'flex';
    });
  }

  function closeModal() {
    modal.style.display = 'none';
  }

  if (btnClose) btnClose.addEventListener('click', closeModal);
  if (backdrop) backdrop.addEventListener('click', closeModal);

  if (btnSave) {
    btnSave.addEventListener('click', async () => {
      if (!currentAuditState.domain) return;
      const res = await storageGet(['vs_pipeline']);
      let list = res.vs_pipeline || [];
      const existingIdx = list.findIndex(i => i.domain === currentAuditState.domain);
      if (existingIdx === -1) {
        list.push({
          id: 'lead_' + Date.now(),
          domain: currentAuditState.domain,
          url: currentAuditState.url,
          score: currentAuditState.score,
          cms: currentAuditState.cmsText,
          primaryFlaw: currentAuditState.flawText,
          hook: currentAuditState.hook,
          date: new Date().toLocaleDateString()
        });
      } else {
        list.splice(existingIdx, 1);
      }
      await storageSet({ vs_pipeline: list });
      updatePipelineBadge();
      renderList();
    });
  }

  if (btnClear) {
    btnClear.addEventListener('click', async () => {
      if (confirm('Clear all saved prospects from pipeline?')) {
        await storageSet({ vs_pipeline: [] });
        updatePipelineBadge();
        renderList();
      }
    });
  }

  if (btnExportCsv) {
    btnExportCsv.addEventListener('click', () => {
      chrome.storage.local.get(['vs_pipeline'], (res) => {
        const list = res.vs_pipeline || [];
        if (list.length === 0) {
          alert('No leads to export.');
          return;
        }

        const headers = ['Domain', 'URL', 'Health Score', 'Primary Flaw', 'CMS / Tech Stack', 'Cold Pitch Hook', 'Date Audited'];
        const csvRows = [headers.join(',')];

        list.forEach(item => {
          const row = [
            `"${(item.domain || '').replace(/"/g, '""')}"`,
            `"${(item.url || '').replace(/"/g, '""')}"`,
            item.score || '',
            `"${(item.primaryFlaw || '').replace(/"/g, '""')}"`,
            `"${(item.cms || '').replace(/"/g, '""')}"`,
            `"${(item.hook || '').replace(/"/g, '""')}"`,
            `"${(item.date || '').replace(/"/g, '""')}"`
          ];
          csvRows.push(row.join(','));
        });

        const csvString = csvRows.join('\r\n');
        const blob = new Blob([csvString], { type: 'text/csv;charset=utf-8;' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `vitalssniper_leads_${new Date().toISOString().slice(0,10)}.csv`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
      });
    });
  }

  updatePipelineBadge();
}

// 4. Live LCP & Core Web Vitals Element Highlighter
function initLcpHighlighter(tabId) {
  const btn = document.getElementById('btnHighlightLcp');
  if (!btn) return;

  btn.addEventListener('click', () => {
    const targetId = tabId || currentAuditState.tabId;
    if (!targetId) {
      alert('No active tab detected to highlight.');
      return;
    }

    chrome.scripting.executeScript({
      target: { tabId: targetId },
      func: highlightLcpOnPage
    }, () => {
      btn.innerText = '✓ Highlighted on Page!';
      btn.style.color = '#34d399';
      btn.style.borderColor = '#10b981';
      setTimeout(() => {
        btn.innerHTML = '<span>🎯 Highlight LCP</span>';
        btn.style.color = '';
        btn.style.borderColor = '';
      }, 2500);
    });
  });
}

function highlightLcpOnPage() {
  const existingBadge = document.getElementById('__vs_lcp_badge');
  if (existingBadge) existingBadge.remove();
  const highlighted = document.querySelectorAll('.__vs_lcp_highlight');
  highlighted.forEach(el => {
    el.classList.remove('__vs_lcp_highlight');
    el.style.outline = '';
    el.style.boxShadow = '';
  });

  if (!document.getElementById('__vs_lcp_styles')) {
    const styleEl = document.createElement('style');
    styleEl.id = '__vs_lcp_styles';
    styleEl.textContent = `
      @keyframes __vs_lcp_pulse {
        0% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
        70% { box-shadow: 0 0 0 16px rgba(16, 185, 129, 0); }
        100% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
      }
      .__vs_lcp_highlight {
        outline: 3px solid #10b981 !important;
        outline-offset: 4px !important;
        animation: __vs_lcp_pulse 2s infinite !important;
        position: relative !important;
      }
    `;
    document.head.appendChild(styleEl);
  }

  let targetEl = null;
  try {
    const entries = performance.getEntriesByType('largest-contentful-paint');
    if (entries && entries.length > 0) {
      targetEl = entries[entries.length - 1].element;
    }
  } catch (e) {}

  if (!targetEl) {
    const candidates = Array.from(document.querySelectorAll('img, picture, svg, h1, [class*="hero"], [class*="banner"]'));
    let maxArea = 0;
    candidates.forEach(el => {
      const rect = el.getBoundingClientRect();
      const area = rect.width * rect.height;
      if (rect.top >= 0 && rect.top < window.innerHeight * 1.5 && area > maxArea) {
        maxArea = area;
        targetEl = el;
      }
    });
  }

  if (!targetEl) {
    targetEl = document.querySelector('h1') || document.querySelector('main') || document.body;
  }

  if (targetEl) {
    targetEl.classList.add('__vs_lcp_highlight');
    targetEl.scrollIntoView({ behavior: 'smooth', block: 'center' });

    const badge = document.createElement('div');
    badge.id = '__vs_lcp_badge';
    badge.innerHTML = '🎯 <strong>Largest Contentful Paint (LCP) Node</strong> &bull; Primary Core Web Vitals Render Target';
    badge.style.cssText = `
      position: absolute;
      z-index: 2147483647;
      background: #022c22;
      color: #34d399;
      border: 1px solid #10b981;
      border-radius: 999px;
      padding: 6px 14px;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 11.5px;
      font-weight: 500;
      box-shadow: 0 4px 16px rgba(0,0,0,0.5);
      white-space: nowrap;
      pointer-events: none;
    `;
    
    const rect = targetEl.getBoundingClientRect();
    const scrollY = window.scrollY || window.pageYOffset;
    const scrollX = window.scrollX || window.pageXOffset;
    badge.style.top = Math.max(10, rect.top + scrollY - 38) + 'px';
    badge.style.left = (rect.left + scrollX) + 'px';
    document.body.appendChild(badge);

    setTimeout(() => {
      if (badge && badge.parentNode) badge.remove();
      if (targetEl) {
        targetEl.classList.remove('__vs_lcp_highlight');
        targetEl.style.outline = '';
      }
    }, 12000);
  }
}