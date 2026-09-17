// VitalsSniper PRO: Proof-of-Flaw Precision Web Inspector
// Author: Antigravity • NB Solutions

document.addEventListener('DOMContentLoaded', async () => {
  let tab;
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    tab = tabs[0];
  } catch (e) {}

  if (!tab || !tab.id || !tab.url) {
    document.getElementById('targetDomain').innerText = 'No active tab found';
    return;
  }

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

// AppSumo License Key & Monetization Engine
let isPaidUser = false;

function setProActive(reason) {
  isPaidUser = true;
  const proTag = document.getElementById('proTag');
  if (proTag) {
    proTag.innerText = 'PRO';
    proTag.classList.add('active-pro');
    proTag.title = `VitalsSniper PRO (${reason})`;
  }
}

function setFreeTier() {
  isPaidUser = false;
  const proTag = document.getElementById('proTag');
  if (proTag) {
    proTag.innerText = 'UPGRADE';
    proTag.classList.remove('active-pro');
    proTag.title = 'Click to activate your AppSumo license';
  }
}

function checkProStatus() {
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
    chrome.storage.local.get(['appsumoProKey'], (res) => {
      if (res.appsumoProKey) {
        setProActive('AppSumo Lifetime License');
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

document.addEventListener('DOMContentLoaded', () => {
  const proTag = document.getElementById('proTag');
  if (proTag) {
    proTag.addEventListener('click', () => {
      if (isPaidUser) {
        alert('Your VitalsSniper PRO license is active with unlimited audits and teardowns.');
      } else {
        const code = prompt('Enter your AppSumo Redemption Code to activate VitalsSniper PRO:');
        if (code && code.trim().length >= 8) {
          chrome.storage.local.set({ appsumoProKey: code.trim().toUpperCase() }, () => {
            setProActive('AppSumo Lifetime License');
            alert('✓ VitalsSniper PRO successfully activated with your AppSumo license!');
          });
        }
      }
    });
  }
});

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
  let flawText = '';
  let emailHook = '';
  let dmHook = '';
  let loomHook = '';

  if (data.vpMissing) {
    flawText = 'Critical: Viewport meta tag is missing. Mobile browsers render the site as a tiny desktop view.';
    emailHook = `While testing ${domain} on an iPhone, I noticed your homepage is currently missing a responsive viewport tag, which causes mobile Safari to render the whole site zoomed-out as a tiny desktop screen.`;
    dmHook = `noticed your site is missing a mobile viewport tag, so mobile Safari renders everything tiny and zoomed-out.`;
    loomHook = `The mobile viewport meta tag is completely missing, forcing iPhone Safari into desktop emulation mode.`;
  } else if (data.vpLocked) {
    flawText = 'Mobile Accessibility: Viewport locks zoom (user-scalable=0), failing Google mobile standards.';
    emailHook = `While testing ${domain} on an iPhone, I noticed your viewport tag locks user pinch-to-zoom (user-scalable=0), preventing prospective clients from inspecting portfolio details and triggering mobile penalties.`;
    dmHook = `noticed your mobile viewport locks pinch-to-zoom (user-scalable=0), which blocks clients from zooming in and flags usability warnings.`;
    loomHook = `The viewport tag locks user pinch-to-zoom, which restricts mobile client accessibility and hurts Core Web Vitals.`;
  } else if (data.sizeKB > 200 || data.totalDom > 4000) {
    flawText = `Severe Page Builder Bloat: ${data.sizeKB}KB raw HTML across ${data.totalDom.toLocaleString()} elements chokes mobile CPU.`;
    emailHook = `While reviewing ${domain} on mobile, I noticed the homepage payload carries over ${data.sizeKB}KB of uncompressed container code across ${data.totalDom.toLocaleString()} DOM elements, causing a multi-second freeze on cellular connections before imagery renders.`;
    dmHook = `noticed your homepage payload is ${data.sizeKB}KB across ${data.totalDom.toLocaleString()} elements, which causes noticeable mobile lag on cellular data.`;
    loomHook = `Here is the DOM tree payload: over ${data.sizeKB}KB of HTML code choke mobile rendering before photography even starts downloading.`;
  } else if (!data.hasSchema) {
    flawText = 'AI Search Invisibility: 0% Schema.org structured data. The site is excluded from ChatGPT Search & Perplexity citations.';
    emailHook = `While auditing search discoverability for ${domain}, I noticed your practice currently misses out on high-intent citations in new AI search tools like ChatGPT and Perplexity due to missing structured Schema.org entity data.`;
    dmHook = `noticed your site has 0% Schema.org entity structured data, which excludes you from citations in new AI search engines like ChatGPT and Perplexity.`;
    loomHook = `There is zero Schema.org structured data on this URL, making the business invisible to AI search citation engines.`;
  } else if (data.uncompressedImages > 0) {
    flawText = `Uncompressed Media: ${data.uncompressedImages} legacy JPG/PNG images delay Largest Contentful Paint (LCP) on cellular data.`;
    emailHook = `While reviewing ${domain} on mobile, I noticed your portfolio imagery is loading as uncompressed legacy JPG files, adding a 3-second delay to the Largest Contentful Paint (LCP) on cellular connections.`;
    dmHook = `noticed your portfolio photography loads as uncompressed JPGs, adding heavy delay before images resolve on mobile.`;
    loomHook = `Several primary portfolio images are loading as uncompressed JPGs rather than modern WebP with explicit dimensions, delaying Largest Contentful Paint.`;
  } else if (data.totalDom > 1400) {
    flawText = `DOM Element Bloat: ${data.totalDom.toLocaleString()} DOM elements exceed Google's recommended 1,400 ceiling.`;
    emailHook = `While reviewing ${domain} on mobile, I noticed the DOM tree contains ${data.totalDom.toLocaleString()} elements, which exceeds Google's recommended 1,400-node ceiling and degrades touch response on phones.`;
    dmHook = `noticed the page contains ${data.totalDom.toLocaleString()} DOM nodes (Google recommends under 1,400), causing mobile scroll stutter.`;
    loomHook = `The page tree contains ${data.totalDom.toLocaleString()} DOM elements, exceeding Google's recommended ceiling and inflating mobile memory usage.`;
  } else if (data.sizeKB > 50) {
    flawText = `HTML Payload: ${data.sizeKB}KB document payload exceeds the 50KB mobile cellular speed budget.`;
    emailHook = `While testing ${domain} on cellular data, I noticed the initial HTML payload is ${data.sizeKB}KB, delaying initial paint before stylesheets parse.`;
    dmHook = `noticed your HTML payload is ${data.sizeKB}KB, which slows down initial rendering on mobile networks.`;
    loomHook = `The HTML document payload alone is ${data.sizeKB}KB, exceeding the cellular first-packet budget.`;
  } else {
    flawText = `Asset Optimization Opportunity: Render-blocking resources and script execution can be streamlined for sub-1s mobile LCP.`;
    emailHook = `While analyzing ${domain}'s mobile architecture, I noticed key asset delivery bottlenecks that can be streamlined to achieve sub-1-second LCP.`;
    dmHook = `noticed key render-blocking script bottlenecks that can be streamlined for sub-1s mobile load times.`;
    loomHook = `Render-blocking resources and third-party script chains are delaying the Largest Contentful Paint.`;
  }

  currentFlawHook = emailHook;
  document.getElementById('flawDesc').innerText = flawText;

  // 10. Generate Multi-Channel Outreach Templates
  currentScripts.email = `Subject: quick observation on the mobile experience for ${domain}

Hi [First Name],

${emailHook}

We specialize in optimizing high-ticket digital architecture so visual fidelity stays pristine while dropping mobile load times to under 1 second.

I put together a quick 30-second screen recording showing the exact bottleneck and the zero-design-change fix.

Would you like me to send the clip over to your team?

Best regards,
Antigravity
Digital Architect • NB Solutions`;

  currentScripts.dm = `Hey [First Name] - noticed ${domain} on mobile while exploring your work. 

${dmHook}

I put together a quick 30s screen recording showing how to resolve the bottleneck with zero changes to your photography, typography, or styling.

Mind if I send the clip link over here?

- Antigravity (Digital Architect • NB Solutions)`;

  currentScripts.loom = `[0:00 - 0:08] "Hey [Name], Antigravity here. I was reviewing the mobile experience on ${domain} and wanted to point out one specific technical bottleneck your team might not have caught."

[0:08 - 0:18] "Right here on mobile: ${loomHook} Affluent clients on iPhone Safari wait several seconds before credentials and imagery render."

[0:18 - 0:30] "The good news is this can be streamlined in 48 hours with 100% visual invariance and zero downtime. Happy to share the exact remediation teardown if helpful!"`;

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
      auditor: 'Antigravity • NB Solutions (Digital Architect)'
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
    }
  </style>
</head>
<body>
  <div class="header">
    <div>
      <div class="title">Technical Performance Teardown</div>
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
    <div class="card-heading">48-Hour Remediation Standards</div>
    <p class="guarantee-list">
      &bull; Sub-1-second mobile LCP with 0 CLS layout shifting.<br>
      &bull; 100% visual design invariance (zero changes to typography, photography, or brand colors).<br>
      &bull; Zero production downtime via isolated staging deployment.
    </p>
  </div>

  <div class="footer">
    Prepared by Antigravity &bull; NB Solutions (Digital Architect)
  </div>
  <script>window.print();</script>
</body>
</html>`;
    const blob = new Blob([reportHtml], { type: 'text/html;charset=utf-8' });
    const reportUrl = URL.createObjectURL(blob);
    chrome.tabs.create({ url: reportUrl });
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