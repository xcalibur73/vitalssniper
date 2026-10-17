// Technology Stack Signature Detection Engine
// Reverse-engineered signatures for Ecommerce, CMS, Frameworks, Pixels, Analytics, and CDN
// Zero em-dash compliance: strictly hyphens or colons

import { TechnologyDetection } from '../types/audit';

export function detectTechnologies(doc: Document | null, windowObj: any, rawHtml: string): TechnologyDetection[] {
  const detections: TechnologyDetection[] = [];
  const htmlLower = (rawHtml || '').toLowerCase();
  const safeDoc = doc || (typeof document !== 'undefined' ? document : null);
  const safeWin = windowObj || (typeof window !== 'undefined' ? window : {});

  // 1. Ecommerce
  // Shopify
  const shopifyEvidence: string[] = [];
  if (htmlLower.includes('cdn.shopify.com')) shopifyEvidence.push('CDN resource: cdn.shopify.com');
  if (safeWin.Shopify !== undefined) shopifyEvidence.push('Global window.Shopify object detected');
  if (shopifyEvidence.length > 0) {
    detections.push({
      name: 'Shopify',
      category: 'Ecommerce',
      confidence: 'high',
      evidence: shopifyEvidence
    });
  }

  // WooCommerce
  const wooEvidence: string[] = [];
  if (htmlLower.includes('woocommerce')) wooEvidence.push('Markup signature: woocommerce');
  if (htmlLower.includes('wc-blocks')) wooEvidence.push('CSS/block signature: wc-blocks');
  if (wooEvidence.length > 0) {
    detections.push({
      name: 'WooCommerce',
      category: 'Ecommerce',
      confidence: 'high',
      evidence: wooEvidence
    });
  }

  // Magento
  const magentoEvidence: string[] = [];
  if (htmlLower.includes('mage/cookies.js')) magentoEvidence.push('Script path: mage/cookies.js');
  if (htmlLower.includes('text/x-magento-init')) magentoEvidence.push('Config block: text/x-magento-init');
  if (magentoEvidence.length > 0) {
    detections.push({
      name: 'Magento',
      category: 'Ecommerce',
      confidence: 'high',
      evidence: magentoEvidence
    });
  }

  // BigCommerce
  const bcEvidence: string[] = [];
  if (htmlLower.includes('stencil-config')) bcEvidence.push('Template signature: stencil-config');
  if (/cdn\d*\.bigcommerce\.com/.test(htmlLower) || htmlLower.includes('cdn.bigcommerce.com')) {
    bcEvidence.push('CDN resource: cdn*.bigcommerce.com');
  }
  if (bcEvidence.length > 0) {
    detections.push({
      name: 'BigCommerce',
      category: 'Ecommerce',
      confidence: 'high',
      evidence: bcEvidence
    });
  }

  // 2. CMS & Builders
  // WordPress
  const wpEvidence: string[] = [];
  if (htmlLower.includes('/wp-content/')) wpEvidence.push('Path: /wp-content/');
  if (htmlLower.includes('/wp-includes/')) wpEvidence.push('Path: /wp-includes/');
  if (safeDoc && safeDoc.querySelector && safeDoc.querySelector('meta[name="generator"][content*="WordPress"]')) {
    wpEvidence.push('Meta generator: WordPress');
  }
  if (wpEvidence.length > 0) {
    detections.push({
      name: 'WordPress',
      category: 'CMS',
      confidence: wpEvidence.length > 1 ? 'high' : 'medium',
      evidence: wpEvidence
    });
  }

  // Elementor
  const elementorEvidence: string[] = [];
  if (htmlLower.includes('elementor-widget')) elementorEvidence.push('DOM class: elementor-widget');
  if (safeWin.elementorFrontend !== undefined) elementorEvidence.push('Global window.elementorFrontend detected');
  if (elementorEvidence.length > 0) {
    detections.push({
      name: 'Elementor',
      category: 'Page Builder',
      confidence: 'high',
      evidence: elementorEvidence
    });
  }

  // Divi
  const diviEvidence: string[] = [];
  if (htmlLower.includes('et_pb_section') || htmlLower.includes('et_pb_')) diviEvidence.push('Class signature: et_pb_section');
  if (htmlLower.includes('themes/divi')) diviEvidence.push('Theme path: themes/Divi');
  if (diviEvidence.length > 0) {
    detections.push({
      name: 'Divi',
      category: 'Page Builder',
      confidence: 'high',
      evidence: diviEvidence
    });
  }

  // GeneratePress
  const gpEvidence: string[] = [];
  if (htmlLower.includes('generatepress')) gpEvidence.push('Theme token: generatepress');
  if (htmlLower.includes('generateblocks')) gpEvidence.push('Block token: generateblocks');
  if (gpEvidence.length > 0) {
    detections.push({
      name: 'GeneratePress',
      category: 'Page Builder',
      confidence: 'high',
      evidence: gpEvidence
    });
  }

  // Webflow
  const wfEvidence: string[] = [];
  if (htmlLower.includes('w-mod-js') || (safeDoc && safeDoc.documentElement && safeDoc.documentElement.classList && safeDoc.documentElement.classList.contains('w-mod-js'))) {
    wfEvidence.push('HTML class: w-mod-js');
  }
  if (htmlLower.includes('data-wf-page')) wfEvidence.push('Attribute: data-wf-page');
  if (wfEvidence.length > 0) {
    detections.push({
      name: 'Webflow',
      category: 'CMS',
      confidence: 'high',
      evidence: wfEvidence
    });
  }

  // Wix
  const wixEvidence: string[] = [];
  if (htmlLower.includes('parastorage') || htmlLower.includes('static.parastorage.com')) wixEvidence.push('CDN resource: parastorage');
  if (safeWin.wixBiSession !== undefined) wixEvidence.push('Global window.wixBiSession detected');
  if (wixEvidence.length > 0) {
    detections.push({
      name: 'Wix',
      category: 'CMS',
      confidence: 'high',
      evidence: wixEvidence
    });
  }

  // Squarespace
  const sqsEvidence: string[] = [];
  if (htmlLower.includes('sqs-block')) sqsEvidence.push('Markup signature: sqs-block');
  if (safeWin.Static && safeWin.Static.SQUARESPACE_CONTEXT) sqsEvidence.push('Global Static.SQUARESPACE_CONTEXT detected');
  if (sqsEvidence.length > 0) {
    detections.push({
      name: 'Squarespace',
      category: 'CMS',
      confidence: 'high',
      evidence: sqsEvidence
    });
  }

  // 3. Frameworks
  // Next.js
  const nextEvidence: string[] = [];
  if (htmlLower.includes('/_next/static/')) nextEvidence.push('Path: /_next/static/');
  if (htmlLower.includes('__next_data__') || safeWin.__NEXT_DATA__ !== undefined) nextEvidence.push('Hydration data: __NEXT_DATA__');
  if (safeDoc && safeDoc.getElementById && safeDoc.getElementById('__next') !== null) nextEvidence.push('Root node: #__next');
  if (nextEvidence.length > 0) {
    detections.push({
      name: 'Next.js',
      category: 'Framework',
      confidence: 'high',
      evidence: nextEvidence
    });
  }

  // React
  const reactEvidence: string[] = [];
  if (htmlLower.includes('data-reactroot') || (safeDoc && safeDoc.querySelector && safeDoc.querySelector('[data-reactroot]'))) {
    reactEvidence.push('DOM attribute: data-reactroot');
  }
  if (safeWin.__REACT_DEVTOOLS_GLOBAL_HOOK__ !== undefined) reactEvidence.push('Global __REACT_DEVTOOLS_GLOBAL_HOOK__ detected');
  if (reactEvidence.length > 0) {
    detections.push({
      name: 'React',
      category: 'Framework',
      confidence: 'high',
      evidence: reactEvidence
    });
  }

  // Vue.js
  const vueEvidence: string[] = [];
  if (htmlLower.includes('data-v-') || (safeDoc && safeDoc.querySelector && safeDoc.querySelector('[data-v-]'))) {
    vueEvidence.push('Scoped style attribute: data-v-');
  }
  if (safeWin.__VUE__ !== undefined) vueEvidence.push('Global window.__VUE__ detected');
  if (vueEvidence.length > 0) {
    detections.push({
      name: 'Vue.js',
      category: 'Framework',
      confidence: 'high',
      evidence: vueEvidence
    });
  }

  // Nuxt.js
  const nuxtEvidence: string[] = [];
  if (htmlLower.includes('/_nuxt/')) nuxtEvidence.push('Path: /_nuxt/');
  if (htmlLower.includes('__nuxt__') || safeWin.__NUXT__ !== undefined) nuxtEvidence.push('Global window.__NUXT__ detected');
  if (nuxtEvidence.length > 0) {
    detections.push({
      name: 'Nuxt.js',
      category: 'Framework',
      confidence: 'high',
      evidence: nuxtEvidence
    });
  }

  // Astro
  const astroEvidence: string[] = [];
  if (htmlLower.includes('<astro-island') || (safeDoc && safeDoc.querySelector && safeDoc.querySelector('astro-island'))) {
    astroEvidence.push('Custom element: <astro-island>');
  }
  if (astroEvidence.length > 0) {
    detections.push({
      name: 'Astro',
      category: 'Framework',
      confidence: 'high',
      evidence: astroEvidence
    });
  }

  // 4. Marketing Pixels
  // Meta Pixel
  const metaEvidence: string[] = [];
  if (htmlLower.includes('connect.facebook.net/fbevents.js') || htmlLower.includes('connect.facebook.net')) {
    metaEvidence.push('Script: connect.facebook.net/fbevents.js');
  }
  if (typeof safeWin.fbq === 'function') metaEvidence.push('Global window.fbq detected');
  if (metaEvidence.length > 0) {
    detections.push({
      name: 'Meta Pixel',
      category: 'Marketing Pixel',
      confidence: 'high',
      evidence: metaEvidence
    });
  }

  // Google Tag Manager
  const gtmEvidence: string[] = [];
  if (htmlLower.includes('googletagmanager.com/gtm.js')) gtmEvidence.push('Script: googletagmanager.com/gtm.js');
  if (safeWin.google_tag_manager !== undefined) gtmEvidence.push('Global window.google_tag_manager detected');
  if (gtmEvidence.length > 0) {
    detections.push({
      name: 'Google Tag Manager',
      category: 'Marketing Pixel',
      confidence: 'high',
      evidence: gtmEvidence
    });
  }

  // Google Analytics 4
  const gaEvidence: string[] = [];
  if (htmlLower.includes('googletagmanager.com/gtag/js') || htmlLower.includes('google-analytics.com/analytics.js')) {
    gaEvidence.push('Script: googletagmanager.com/gtag/js');
  }
  if (typeof safeWin.gtag === 'function') gaEvidence.push('Global window.gtag detected');
  if (gaEvidence.length > 0) {
    detections.push({
      name: 'Google Analytics 4',
      category: 'Marketing Pixel',
      confidence: 'high',
      evidence: gaEvidence
    });
  }

  // TikTok Pixel
  const ttEvidence: string[] = [];
  if (htmlLower.includes('analytics.tiktok.com/i18n/pixel/')) ttEvidence.push('Script: analytics.tiktok.com/i18n/pixel/');
  if (safeWin.ttq !== undefined) ttEvidence.push('Global window.ttq detected');
  if (ttEvidence.length > 0) {
    detections.push({
      name: 'TikTok Pixel',
      category: 'Marketing Pixel',
      confidence: 'high',
      evidence: ttEvidence
    });
  }

  // Klaviyo
  const klaviyoEvidence: string[] = [];
  if (htmlLower.includes('static.klaviyo.com/onsite/js/klaviyo.js') || htmlLower.includes('static.klaviyo.com')) {
    klaviyoEvidence.push('Script: static.klaviyo.com/onsite/js/klaviyo.js');
  }
  if (safeWin._learnq !== undefined) klaviyoEvidence.push('Global window._learnq detected');
  if (klaviyoEvidence.length > 0) {
    detections.push({
      name: 'Klaviyo',
      category: 'Marketing Pixel',
      confidence: 'high',
      evidence: klaviyoEvidence
    });
  }

  // Pinterest Pixel
  const pintrkEvidence: string[] = [];
  if (htmlLower.includes('assets.pinterest.com/js/pintrk.js')) pintrkEvidence.push('Script: assets.pinterest.com/js/pintrk.js');
  if (typeof safeWin.pintrk === 'function') pintrkEvidence.push('Global window.pintrk detected');
  if (pintrkEvidence.length > 0) {
    detections.push({
      name: 'Pinterest Pixel',
      category: 'Marketing Pixel',
      confidence: 'high',
      evidence: pintrkEvidence
    });
  }

  // Postscript
  const postscriptEvidence: string[] = [];
  if (htmlLower.includes('sdk.postscript.io')) postscriptEvidence.push('Script: sdk.postscript.io');
  if (safeWin.postscript !== undefined) postscriptEvidence.push('Global window.postscript detected');
  if (postscriptEvidence.length > 0) {
    detections.push({
      name: 'Postscript',
      category: 'Marketing Pixel',
      confidence: 'high',
      evidence: postscriptEvidence
    });
  }

  // Triple Whale
  const twEvidence: string[] = [];
  if (htmlLower.includes('triplewhale-pixel.triplewhale.com') || htmlLower.includes('triplewhale.com')) {
    twEvidence.push('Script: triplewhale-pixel.triplewhale.com');
  }
  if (twEvidence.length > 0) {
    detections.push({
      name: 'Triple Whale',
      category: 'Marketing Pixel',
      confidence: 'high',
      evidence: twEvidence
    });
  }

  // 5. Analytics
  // Hotjar
  const hotjarEvidence: string[] = [];
  if (htmlLower.includes('static.hotjar.com')) hotjarEvidence.push('Script: static.hotjar.com');
  if (typeof safeWin.hj === 'function') hotjarEvidence.push('Global window.hj detected');
  if (hotjarEvidence.length > 0) {
    detections.push({
      name: 'Hotjar',
      category: 'Analytics',
      confidence: 'high',
      evidence: hotjarEvidence
    });
  }

  // Microsoft Clarity
  const clarityEvidence: string[] = [];
  if (htmlLower.includes('clarity.ms')) clarityEvidence.push('Script: clarity.ms');
  if (typeof safeWin.clarity === 'function') clarityEvidence.push('Global window.clarity detected');
  if (clarityEvidence.length > 0) {
    detections.push({
      name: 'Microsoft Clarity',
      category: 'Analytics',
      confidence: 'high',
      evidence: clarityEvidence
    });
  }

  // 6. CDN
  // Cloudflare
  const cfEvidence: string[] = [];
  if (htmlLower.includes('cdnjs.cloudflare.com')) cfEvidence.push('Resource path: cdnjs.cloudflare.com');
  if (htmlLower.includes('rocket-loader')) cfEvidence.push('Cloudflare Rocket Loader signature');
  if (htmlLower.includes('/cdn-cgi/')) cfEvidence.push('Path: /cdn-cgi/');
  if (cfEvidence.length > 0) {
    detections.push({
      name: 'Cloudflare',
      category: 'CDN',
      confidence: 'high',
      evidence: cfEvidence
    });
  }

  return detections;
}
