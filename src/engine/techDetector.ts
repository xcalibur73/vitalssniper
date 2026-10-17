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
  if (safeWin.ShopifyBuy !== undefined ||
      (safeDoc && safeDoc.querySelector && safeDoc.querySelector('script[src*="buy-button.js"], script[src*="shopify-buy"], [data-shopify-buy]')) ||
      /(?:<script[^>]+src=["'][^"']*(?:buy-button\.js|shopify-buy)|data-shopify-buy)/i.test(rawHtml)) {
    shopifyEvidence.push('Shopify Buy Button integration');
  }
  if ((safeDoc && safeDoc.querySelector && safeDoc.querySelector('script[src*="cdn.shopify.com"], link[href*="cdn.shopify.com"], img[src*="cdn.shopify.com"]')) ||
      /(?:<script|<link|<img)[^>]+(?:src|href)=["'][^"']*cdn\.shopify\.com/i.test(rawHtml)) {
    shopifyEvidence.push('CDN resource: cdn.shopify.com');
  }
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
  const wooVersion = extractTechVersion('WooCommerce', safeDoc, safeWin, rawHtml);
  if ((safeDoc && safeDoc.querySelector && safeDoc.querySelector('body.woocommerce, .woocommerce, link[rel="stylesheet"][href*="woocommerce"], script[src*="woocommerce"]')) ||
      /<link[^>]+rel=["']stylesheet["'][^>]+href=["'][^"']*woocommerce/i.test(rawHtml) ||
      /<script[^>]+src=["'][^"']*woocommerce/i.test(rawHtml) ||
      /(?:\bclass=["'][^"']*\s|\bclass=["'])woocommerce(?=[\s"'])/i.test(rawHtml) ||
      /(?:<link[^>]+rel=["']stylesheet["'][^>]+href=["'][^"']*|<script[^>]+src=["'][^"']*)\/plugins\/woocommerce\//i.test(rawHtml)) {
    wooEvidence.push('Scoped DOM signature: WooCommerce class or script asset');
  }
  if ((safeDoc && safeDoc.querySelector && safeDoc.querySelector('meta[name="generator"][content*="WooCommerce"]')) ||
      /<meta[^>]+name=["']generator["'][^>]+content=["'][^"']*WooCommerce/i.test(rawHtml) ||
      /<meta[^>]+content=["'][^"']*WooCommerce[^"']*["'][^>]+name=["']generator["']/i.test(rawHtml)) {
    wooEvidence.push('Meta generator: WooCommerce');
  }
  if (safeWin.woocommerce_params !== undefined || safeWin.wc_add_to_cart_params !== undefined) {
    wooEvidence.push('Global window.woocommerce_params detected');
  }
  if (wooVersion && !wooEvidence.some(e => e.includes('WooCommerce'))) {
    wooEvidence.push(`Version detected: WooCommerce ${wooVersion}`);
  }
  if (wooEvidence.length > 0) {
    const wooDet: TechnologyDetection = {
      name: 'WooCommerce',
      category: 'Ecommerce',
      confidence: 'high',
      evidence: wooEvidence
    };
    if (wooVersion) wooDet.version = wooVersion;
    detections.push(wooDet);
  }

  // Magento
  const magentoEvidence: string[] = [];
  if ((safeDoc && safeDoc.querySelector && safeDoc.querySelector('script[src*="mage/cookies.js"], script[type="text/x-magento-init"]')) ||
      /<script[^>]+src=["'][^"']*mage\/cookies\.js/i.test(rawHtml) ||
      /type=["']text\/x-magento-init["']/i.test(rawHtml)) {
    magentoEvidence.push('Script path or config block: mage/cookies.js');
  }
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
  if (safeWin.stencil !== undefined ||
      (safeDoc && safeDoc.querySelector && safeDoc.querySelector('script[src*="bigcommerce.com"], link[href*="bigcommerce.com"], [data-stencil-config]')) ||
      /(?:<script|<link)[^>]+(?:src|href)=["'][^"']*cdn\d*\.bigcommerce\.com/i.test(rawHtml) ||
      /data-stencil-config/i.test(rawHtml)) {
    bcEvidence.push('CDN resource or template signature: bigcommerce.com');
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
  const wpVersion = extractTechVersion('WordPress', safeDoc, safeWin, rawHtml);
  if ((safeDoc && safeDoc.querySelector && safeDoc.querySelector('link[rel="stylesheet"][href*="/wp-content/"], script[src*="/wp-content/"]')) ||
      /(?:<link[^>]+rel=["']stylesheet["'][^>]+href=["'][^"']*|<script[^>]+src=["'][^"']*)\/wp-content\//i.test(rawHtml)) {
    wpEvidence.push('Path: /wp-content/');
  }
  if ((safeDoc && safeDoc.querySelector && safeDoc.querySelector('link[rel="stylesheet"][href*="/wp-includes/"], script[src*="/wp-includes/"]')) ||
      /(?:<link[^>]+rel=["']stylesheet["'][^>]+href=["'][^"']*|<script[^>]+src=["'][^"']*)\/wp-includes\//i.test(rawHtml)) {
    wpEvidence.push('Path: /wp-includes/');
  }
  if ((safeDoc && safeDoc.querySelector && safeDoc.querySelector('meta[name="generator"][content*="WordPress"]')) ||
      /<meta[^>]+name=["']generator["'][^>]+content=["'][^"']*WordPress/i.test(rawHtml) ||
      /<meta[^>]+content=["'][^"']*WordPress[^"']*["'][^>]+name=["']generator["']/i.test(rawHtml)) {
    wpEvidence.push('Meta generator: WordPress');
  }
  if (safeWin.wp !== undefined && typeof safeWin.wp === 'object') {
    wpEvidence.push('Global window.wp object detected');
  }
  if (wpVersion && !wpEvidence.length) {
    wpEvidence.push(`Version asset detected: WordPress ${wpVersion}`);
  }
  if (wpEvidence.length > 0) {
    const wpDet: TechnologyDetection = {
      name: 'WordPress',
      category: 'CMS',
      confidence: wpEvidence.length > 1 ? 'high' : 'medium',
      evidence: wpEvidence
    };
    if (wpVersion) wpDet.version = wpVersion;
    detections.push(wpDet);
  }

  // Elementor
  const elementorEvidence: string[] = [];
  const elementorVersion = extractTechVersion('Elementor', safeDoc, safeWin, rawHtml);
  if ((safeDoc && safeDoc.querySelector && safeDoc.querySelector('.elementor-widget, [data-elementor-type], link[rel="stylesheet"][href*="elementor"], script[src*="elementor"]')) ||
      /(?:\bclass=["'][^"']*\s|\bclass=["'])elementor-widget(?=[\s"'])/i.test(rawHtml) ||
      /data-elementor-type=/i.test(rawHtml) ||
      /(?:<link[^>]+rel=["']stylesheet["'][^>]+href=["'][^"']*|<script[^>]+src=["'][^"']*)\/plugins\/elementor\//i.test(rawHtml)) {
    elementorEvidence.push('DOM class: elementor-widget');
  }
  if (safeWin.elementorFrontend !== undefined) elementorEvidence.push('Global window.elementorFrontend detected');
  if (elementorVersion && !elementorEvidence.length) {
    elementorEvidence.push('Elementor asset signature detected');
  }
  if (elementorEvidence.length > 0) {
    const elemDet: TechnologyDetection = {
      name: 'Elementor',
      category: 'Page Builder',
      confidence: 'high',
      evidence: elementorEvidence
    };
    if (elementorVersion) elemDet.version = elementorVersion;
    detections.push(elemDet);
  }

  // Divi
  const diviEvidence: string[] = [];
  if ((safeDoc && safeDoc.querySelector && safeDoc.querySelector('.et_pb_section, [class*="et_pb_"]')) ||
      /(?:\bclass=["'][^"']*\s|\bclass=["'])et_pb_/i.test(rawHtml)) {
    diviEvidence.push('Class signature: et_pb_section');
  }
  if ((safeDoc && safeDoc.querySelector && safeDoc.querySelector('link[rel="stylesheet"][href*="/themes/Divi/"], link[rel="stylesheet"][href*="/themes/divi/"]')) ||
      /(?:<link[^>]+rel=["']stylesheet["'][^>]+href=["'][^"']*|<script[^>]+src=["'][^"']*)\/themes\/[Dd]ivi\//i.test(rawHtml)) {
    diviEvidence.push('Theme path: themes/Divi');
  }
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
  const gpVersion = extractTechVersion('GeneratePress', safeDoc, safeWin, rawHtml);
  if ((safeDoc && safeDoc.querySelector && safeDoc.querySelector('link[rel="stylesheet"][href*="generatepress"], script[src*="generatepress"], body.generatepress, body[class*="generatepress"]')) ||
      /<link[^>]+rel=["']stylesheet["'][^>]+href=["'][^"']*generatepress/i.test(rawHtml) ||
      /<script[^>]+src=["'][^"']*generatepress/i.test(rawHtml) ||
      /(?:\bclass=["'][^"']*\s|\bclass=["'])generatepress(?=[\s"'])/i.test(rawHtml) ||
      /(?:<link[^>]+rel=["']stylesheet["'][^>]+href=["'][^"']*|<script[^>]+src=["'][^"']*)\/themes\/generatepress\//i.test(rawHtml)) {
    gpEvidence.push('Theme token: generatepress');
  }
  if ((safeDoc && safeDoc.querySelector && safeDoc.querySelector('link[rel="stylesheet"][href*="generateblocks"], [class*="gb-container"], [class*="gb-grid"]')) ||
      /<link[^>]+rel=["']stylesheet["'][^>]+href=["'][^"']*generateblocks/i.test(rawHtml) ||
      /(?:\bclass=["'][^"']*\s|\bclass=["'])gb-(?:container|grid|button)(?=[\s"'])/i.test(rawHtml)) {
    gpEvidence.push('Block token: generateblocks');
  }
  if (safeWin.generatepress !== undefined) {
    gpEvidence.push('Global window.generatepress detected');
  }
  if (gpVersion && !gpEvidence.length) {
    gpEvidence.push('GeneratePress style asset detected');
  }
  if (gpEvidence.length > 0) {
    const gpDet: TechnologyDetection = {
      name: 'GeneratePress',
      category: 'Page Builder',
      confidence: 'high',
      evidence: gpEvidence
    };
    if (gpVersion) gpDet.version = gpVersion;
    detections.push(gpDet);
  }

  // Webflow
  const wfEvidence: string[] = [];
  if ((safeDoc && safeDoc.documentElement && safeDoc.documentElement.classList && safeDoc.documentElement.classList.contains('w-mod-js')) ||
      /<html[^>]+class=["'][^"']*\bw-mod-js\b/i.test(rawHtml)) {
    wfEvidence.push('HTML class: w-mod-js');
  }
  if ((safeDoc && safeDoc.querySelector && safeDoc.querySelector('[data-wf-page]')) ||
      /data-wf-page=/i.test(rawHtml)) {
    wfEvidence.push('Attribute: data-wf-page');
  }
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
  if ((safeDoc && safeDoc.querySelector && safeDoc.querySelector('script[src*="parastorage"], link[href*="parastorage"]')) ||
      /(?:<script|<link)[^>]+(?:src|href)=["'][^"']*static\.parastorage\.com/i.test(rawHtml)) {
    wixEvidence.push('CDN resource: parastorage');
  }
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
  if ((safeDoc && safeDoc.querySelector && safeDoc.querySelector('.sqs-block, [class*="sqs-block-"]')) ||
      /(?:\bclass=["'][^"']*\s|\bclass=["'])sqs-block/i.test(rawHtml)) {
    sqsEvidence.push('Markup signature: sqs-block');
  }
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
  const nextVersion = extractTechVersion('Next.js', safeDoc, safeWin, rawHtml);
  if (safeDoc && safeDoc.querySelector && safeDoc.querySelector('#__next, script[src*="/_next/static/"]')) {
    nextEvidence.push('DOM/Script signature: Next.js root node or /_next/static/ bundle');
  } else if (/id=["']__next["']/i.test(rawHtml) || /(?:<script|<link)[^>]+(?:src|href)=["'][^"']*\/_next\/static\//i.test(rawHtml)) {
    nextEvidence.push('DOM/Script signature: Next.js root node or /_next/static/ bundle');
  }
  if (safeWin.__NEXT_DATA__ !== undefined || (safeDoc && safeDoc.getElementById && safeDoc.getElementById('__NEXT_DATA__')) || /<script[^>]+id=["']__NEXT_DATA__["']/i.test(rawHtml)) {
    nextEvidence.push('Hydration data: Global window.__NEXT_DATA__ detected');
  }
  if (nextVersion && !nextEvidence.length) {
    nextEvidence.push('Next.js runtime detected');
  }
  if (nextEvidence.length > 0) {
    const nextDet: TechnologyDetection = {
      name: 'Next.js',
      category: 'Framework',
      confidence: 'high',
      evidence: nextEvidence
    };
    if (nextVersion) nextDet.version = nextVersion;
    detections.push(nextDet);
  }

  // React (False-positive devtools hook removed)
  const reactEvidence: string[] = [];
  const reactVersion = extractTechVersion('React', safeDoc, safeWin, rawHtml);
  if (safeDoc && safeDoc.querySelector && safeDoc.querySelector('[data-reactroot], #root[data-react-checksum], script[src*="react.production"], script[src*="react-dom"], script[src*="react@"]')) {
    reactEvidence.push('DOM/Script signature: React root node or bundle script');
  } else if (/data-reactroot/i.test(rawHtml) || /(?:<script|<link)[^>]+(?:src|href)=["'][^"']*(?:react-dom|react\.production|react@)/i.test(rawHtml)) {
    reactEvidence.push('DOM/Script signature: React root node or bundle script');
  }
  if (safeWin.React !== undefined) {
    reactEvidence.push('Global window.React detected');
  }
  if (reactVersion && !reactEvidence.length) {
    reactEvidence.push('React library detected');
  }
  if (reactEvidence.length > 0) {
    const reactDet: TechnologyDetection = {
      name: 'React',
      category: 'Framework',
      confidence: 'high',
      evidence: reactEvidence
    };
    if (reactVersion) reactDet.version = reactVersion;
    detections.push(reactDet);
  }

  // Vue.js
  const vueEvidence: string[] = [];
  const vueVersion = extractTechVersion('Vue.js', safeDoc, safeWin, rawHtml);
  if (safeDoc && safeDoc.querySelector && safeDoc.querySelector('[data-v-], [v-cloak], script[src*="vue.runtime"], script[src*="vue@"]')) {
    vueEvidence.push('DOM/Script signature: Vue scoped attribute or runtime script');
  } else if (/data-v-[a-zA-Z0-9]/i.test(rawHtml) || /\bv-cloak\b/i.test(rawHtml) || /(?:<script|<link)[^>]+(?:src|href)=["'][^"']*(?:vue\.runtime|vue@)/i.test(rawHtml)) {
    vueEvidence.push('DOM/Script signature: Vue scoped attribute or runtime script');
  }
  if (safeWin.__VUE__ !== undefined) {
    vueEvidence.push('Global window.__VUE__ detected');
  }
  if (safeWin.Vue !== undefined) {
    vueEvidence.push('Global window.Vue detected');
  }
  if (vueVersion && !vueEvidence.length) {
    vueEvidence.push('Vue.js runtime detected');
  }
  if (vueEvidence.length > 0) {
    const vueDet: TechnologyDetection = {
      name: 'Vue.js',
      category: 'Framework',
      confidence: 'high',
      evidence: vueEvidence
    };
    if (vueVersion) vueDet.version = vueVersion;
    detections.push(vueDet);
  }

  // Nuxt.js
  const nuxtEvidence: string[] = [];
  if ((safeDoc && safeDoc.querySelector && safeDoc.querySelector('script[src*="/_nuxt/"], link[href*="/_nuxt/"]')) ||
      /(?:<script|<link)[^>]+(?:src|href)=["'][^"']*\/_nuxt\//i.test(rawHtml)) {
    nuxtEvidence.push('Path: /_nuxt/');
  }
  if (safeWin.__NUXT__ !== undefined || (safeDoc && safeDoc.getElementById && safeDoc.getElementById('__nuxt')) || /id=["']__nuxt["']/i.test(rawHtml)) {
    nuxtEvidence.push('Global window.__NUXT__ detected');
  }
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
  if (safeDoc && safeDoc.querySelector && safeDoc.querySelector('astro-island, [data-astro-cid]')) {
    astroEvidence.push('DOM signature: astro-island element or data-astro-cid attribute');
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
  if ((safeDoc && safeDoc.querySelector && safeDoc.querySelector('script[src*="connect.facebook.net"]')) ||
      /<script[^>]+src=["'][^"']*connect\.facebook\.net/i.test(rawHtml)) {
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
  if ((safeDoc && safeDoc.querySelector && safeDoc.querySelector('script[src*="googletagmanager.com/gtm.js"]')) ||
      /<script[^>]+src=["'][^"']*googletagmanager\.com\/gtm\.js/i.test(rawHtml)) {
    gtmEvidence.push('Script: googletagmanager.com/gtm.js');
  }
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
  if ((safeDoc && safeDoc.querySelector && safeDoc.querySelector('script[src*="googletagmanager.com/gtag/js"], script[src*="google-analytics.com/analytics.js"]')) ||
      /<script[^>]+src=["'][^"']*(?:googletagmanager\.com\/gtag\/js|google-analytics\.com\/analytics\.js)/i.test(rawHtml)) {
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
  if ((safeDoc && safeDoc.querySelector && safeDoc.querySelector('script[src*="analytics.tiktok.com/i18n/pixel/"]')) ||
      /<script[^>]+src=["'][^"']*analytics\.tiktok\.com\/i18n\/pixel\//i.test(rawHtml)) {
    ttEvidence.push('Script: analytics.tiktok.com/i18n/pixel/');
  }
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
  if ((safeDoc && safeDoc.querySelector && safeDoc.querySelector('script[src*="static.klaviyo.com"]')) ||
      /<script[^>]+src=["'][^"']*static\.klaviyo\.com/i.test(rawHtml)) {
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
  if ((safeDoc && safeDoc.querySelector && safeDoc.querySelector('script[src*="assets.pinterest.com/js/pintrk.js"]')) ||
      /<script[^>]+src=["'][^"']*assets\.pinterest\.com\/js\/pintrk\.js/i.test(rawHtml)) {
    pintrkEvidence.push('Script: assets.pinterest.com/js/pintrk.js');
  }
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
  if ((safeDoc && safeDoc.querySelector && safeDoc.querySelector('script[src*="sdk.postscript.io"]')) ||
      /<script[^>]+src=["'][^"']*sdk\.postscript\.io/i.test(rawHtml)) {
    postscriptEvidence.push('Script: sdk.postscript.io');
  }
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
  if ((safeDoc && safeDoc.querySelector && safeDoc.querySelector('script[src*="triplewhale.com"]')) ||
      /<script[^>]+src=["'][^"']*triplewhale\.com/i.test(rawHtml)) {
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
  if ((safeDoc && safeDoc.querySelector && safeDoc.querySelector('script[src*="static.hotjar.com"]')) ||
      /<script[^>]+src=["'][^"']*static\.hotjar\.com/i.test(rawHtml)) {
    hotjarEvidence.push('Script: static.hotjar.com');
  }
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
  if ((safeDoc && safeDoc.querySelector && safeDoc.querySelector('script[src*="clarity.ms"]')) ||
      /<script[^>]+src=["'][^"']*clarity\.ms/i.test(rawHtml)) {
    clarityEvidence.push('Script: clarity.ms');
  }
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
  // Cloudflare (cdnjs false positive eliminated)
  const cfEvidence: string[] = [];
  if ((safeDoc && safeDoc.querySelector && safeDoc.querySelector('script[src*="rocket-loader"], script[data-cfasync], script[src*="/cdn-cgi/"]')) ||
      /(?:<script[^>]+src=["'][^"']*(?:rocket-loader|\/cdn-cgi\/)|<script[^>]+data-cfasync)/i.test(rawHtml)) {
    cfEvidence.push('Infrastructure signature: Cloudflare Rocket Loader or /cdn-cgi/ endpoint');
  }
  if (cfEvidence.length > 0) {
    detections.push({
      name: 'Cloudflare',
      category: 'CDN',
      confidence: 'high',
      evidence: cfEvidence
    });
  }

  // Pipeline: Raw detections -> resolveExcludes -> resolveImplies -> resolveExcludes
  const initialExcludes = resolveExcludes(detections);
  const resolvedImplies = resolveImplies(initialExcludes);
  return resolveExcludes(resolvedImplies);
}

export function resolveImplies(detections: TechnologyDetection[]): TechnologyDetection[] {
  const result: TechnologyDetection[] = [...detections];
  const hasTech = (name: string) => result.some(d => d.name === name);

  if (hasTech('WooCommerce') && !hasTech('WordPress')) {
    result.push({
      name: 'WordPress',
      category: 'CMS',
      confidence: 'high',
      evidence: ['Inferred by dependency: WooCommerce implies WordPress']
    });
  }

  if (hasTech('Elementor') && !hasTech('WordPress')) {
    result.push({
      name: 'WordPress',
      category: 'CMS',
      confidence: 'high',
      evidence: ['Inferred by dependency: Elementor implies WordPress']
    });
  }

  if (hasTech('Divi') && !hasTech('WordPress')) {
    result.push({
      name: 'WordPress',
      category: 'CMS',
      confidence: 'high',
      evidence: ['Inferred by dependency: Divi implies WordPress']
    });
  }

  if (hasTech('GeneratePress') && !hasTech('WordPress')) {
    result.push({
      name: 'WordPress',
      category: 'CMS',
      confidence: 'high',
      evidence: ['Inferred by dependency: GeneratePress implies WordPress']
    });
  }

  if (hasTech('Next.js') && !hasTech('React')) {
    result.push({
      name: 'React',
      category: 'Framework',
      confidence: 'high',
      evidence: ['Inferred by dependency: Next.js implies React']
    });
  }

  if (hasTech('Nuxt.js') && !hasTech('Vue.js')) {
    result.push({
      name: 'Vue.js',
      category: 'Framework',
      confidence: 'high',
      evidence: ['Inferred by dependency: Nuxt.js implies Vue.js']
    });
  }

  return result;
}

export function resolveExcludes(detections: TechnologyDetection[]): TechnologyDetection[] {
  const shopifyDet = detections.find(d => d.name === 'Shopify');
  const hasShopify = !!shopifyDet;
  const hasShopifyBuy = shopifyDet && shopifyDet.evidence.some(e => /shopify-buy|buy\s*button/i.test(e));
  const hasWix = detections.some(d => d.name === 'Wix');
  const hasSquarespace = detections.some(d => d.name === 'Squarespace');

  return detections.filter(d => {
    if (hasShopify && !hasShopifyBuy && (d.name === 'WooCommerce' || d.name === 'Magento')) {
      return false;
    }
    if (hasWix && d.name === 'WordPress') {
      return false;
    }
    if (hasSquarespace && d.name === 'WordPress') {
      return false;
    }
    return true;
  });
}

export function extractTechVersion(techName: string, doc: Document | null, windowObj: any, rawHtml: string): string | null {
  const safeDoc = doc || (typeof document !== 'undefined' ? document : null);
  const safeWin = windowObj || (typeof window !== 'undefined' ? window : {});
  const htmlStr = rawHtml || '';

  if (techName === 'WordPress') {
    if (safeDoc && safeDoc.querySelector) {
      const meta = safeDoc.querySelector('meta[name="generator"][content*="WordPress"]');
      if (meta) {
        const content = meta.getAttribute('content') || '';
        const m = content.match(/WordPress\s+([0-9.]+)/i);
        if (m && m[1]) return m[1];
      }
    }
    const metaMatch = htmlStr.match(/<meta[^>]+name=["']generator["'][^>]+content=["'][^"']*WordPress\s+([0-9.]+)[^"']*["']/i)
      || htmlStr.match(/<meta[^>]+content=["'][^"']*WordPress\s+([0-9.]+)[^"']*["'][^>]+name=["']generator["']/i);
    if (metaMatch && metaMatch[1]) return metaMatch[1];

    if (safeDoc && safeDoc.querySelectorAll) {
      const nodes = safeDoc.querySelectorAll('script[src*="wp-includes"], script[src*="wp-embed"], link[rel="stylesheet"][href*="wp-includes"], link[rel="stylesheet"][href*="wp-embed"]');
      for (let i = 0; i < nodes.length; i++) {
        const src = nodes[i].getAttribute('src') || nodes[i].getAttribute('href') || '';
        const m = src.match(/(?:wp-includes|wp-embed)[^"'>]*?[?&]ver=([0-9.]+)/i);
        if (m && m[1]) return m[1];
      }
    }
    const scriptMatch = htmlStr.match(/(?:<script|<link)[^>]+(?:src|href)=["'][^"']*(?:wp-includes|wp-embed)[^"'>]*?[?&]ver=([0-9.]+)/i);
    if (scriptMatch && scriptMatch[1]) return scriptMatch[1];

    if (!htmlStr.includes('<')) {
      const directMatch = htmlStr.match(/^WordPress\s+([0-9.]+)/i);
      if (directMatch && directMatch[1]) return directMatch[1];
    }
    return null;
  }

  if (techName === 'WooCommerce') {
    if (safeDoc && safeDoc.querySelector) {
      const meta = safeDoc.querySelector('meta[name="generator"][content*="WooCommerce"]');
      if (meta) {
        const content = meta.getAttribute('content') || '';
        const m = content.match(/WooCommerce\s+([0-9.]+)/i);
        if (m && m[1]) return m[1];
      }
    }
    const metaMatch = htmlStr.match(/<meta[^>]+name=["']generator["'][^>]+content=["'][^"']*WooCommerce\s+([0-9.]+)[^"']*["']/i)
      || htmlStr.match(/<meta[^>]+content=["'][^"']*WooCommerce\s+([0-9.]+)[^"']*["'][^>]+name=["']generator["']/i);
    if (metaMatch && metaMatch[1]) return metaMatch[1];

    if (safeDoc && safeDoc.querySelectorAll) {
      const nodes = safeDoc.querySelectorAll('script[src*="woocommerce"], link[rel="stylesheet"][href*="woocommerce"]');
      for (let i = 0; i < nodes.length; i++) {
        const src = nodes[i].getAttribute('src') || nodes[i].getAttribute('href') || '';
        const m = src.match(/woocommerce[^"'>]*?[?&]ver=([0-9.]+)/i);
        if (m && m[1]) return m[1];
      }
    }
    const scriptMatch = htmlStr.match(/(?:<script|<link)[^>]+(?:src|href)=["'][^"']*woocommerce[^"'>]*?[?&]ver=([0-9.]+)/i);
    if (scriptMatch && scriptMatch[1]) return scriptMatch[1];

    if (!htmlStr.includes('<')) {
      const directMatch = htmlStr.match(/^WooCommerce\s+([0-9.]+)/i);
      if (directMatch && directMatch[1]) return directMatch[1];
    }
    return null;
  }

  if (techName === 'Elementor') {
    if (safeWin.elementorFrontendConfig && safeWin.elementorFrontendConfig.version) {
      return String(safeWin.elementorFrontendConfig.version);
    }
    if (safeDoc && safeDoc.querySelector) {
      const meta = safeDoc.querySelector('meta[name="generator"][content*="Elementor"]');
      if (meta) {
        const content = meta.getAttribute('content') || '';
        const m = content.match(/Elementor\s+([0-9.]+)/i);
        if (m && m[1]) return m[1];
      }
    }
    const metaMatch = htmlStr.match(/<meta[^>]+name=["']generator["'][^>]+content=["'][^"']*Elementor\s+([0-9.]+)[^"']*["']/i)
      || htmlStr.match(/<meta[^>]+content=["'][^"']*Elementor\s+([0-9.]+)[^"']*["'][^>]+name=["']generator["']/i);
    if (metaMatch && metaMatch[1]) return metaMatch[1];

    if (safeDoc && safeDoc.querySelectorAll) {
      const nodes = safeDoc.querySelectorAll('script[src*="elementor"], link[rel="stylesheet"][href*="elementor"]');
      for (let i = 0; i < nodes.length; i++) {
        const src = nodes[i].getAttribute('src') || nodes[i].getAttribute('href') || '';
        const m = src.match(/elementor\/assets\/js\/[^"'>]*?[?&]ver=([0-9.]+)/i)
          || src.match(/elementor[^"'>]*?assets[^"'>]*?[?&]ver=([0-9.]+)/i);
        if (m && m[1]) return m[1];
      }
    }
    const scriptMatch = htmlStr.match(/(?:<script|<link)[^>]+(?:src|href)=["'][^"']*(?:elementor\/assets\/js\/|elementor[^"'>]*?assets)[^"'>]*?[?&]ver=([0-9.]+)/i);
    if (scriptMatch && scriptMatch[1]) return scriptMatch[1];

    if (!htmlStr.includes('<')) {
      const directMatch = htmlStr.match(/^Elementor\s+([0-9.]+)/i);
      if (directMatch && directMatch[1]) return directMatch[1];
    }
    return null;
  }

  if (techName === 'Next.js') {
    if (safeWin.next && safeWin.next.version) {
      return String(safeWin.next.version);
    }
    if (safeWin.__NEXT_DATA__ && safeWin.__NEXT_DATA__.buildId) {
      return String(safeWin.__NEXT_DATA__.buildId);
    }
    if (safeDoc && safeDoc.getElementById) {
      const el = safeDoc.getElementById('__NEXT_DATA__');
      if (el && el.textContent) {
        try {
          const parsed = JSON.parse(el.textContent);
          if (parsed && parsed.buildId) return String(parsed.buildId);
        } catch {
          // ignore
        }
      }
    }
    const m = htmlStr.match(/<script[^>]+id=["']__NEXT_DATA__["'][^>]*>([\s\S]*?)<\/script>/i);
    if (m && m[1]) {
      try {
        const parsed = JSON.parse(m[1]);
        if (parsed && parsed.buildId) return String(parsed.buildId);
      } catch {
        // ignore
      }
    }
    return null;
  }

  if (techName === 'React') {
    if (safeWin.React && safeWin.React.version) {
      return String(safeWin.React.version);
    }
    if (safeDoc && safeDoc.querySelectorAll) {
      const nodes = safeDoc.querySelectorAll('script[src*="react@"], script[src*="react."]');
      for (let i = 0; i < nodes.length; i++) {
        const src = nodes[i].getAttribute('src') || '';
        const m = src.match(/react@([0-9.]+)/i);
        if (m && m[1]) return m[1];
      }
    }
    const scriptMatch = htmlStr.match(/(?:<script|<link)[^>]+(?:src|href)=["'][^"']*react@([0-9.]+)/i);
    if (scriptMatch && scriptMatch[1]) return scriptMatch[1];

    if (!htmlStr.includes('<')) {
      const directMatch = htmlStr.match(/^(?:React\s+|react@)([0-9.]+)/i);
      if (directMatch && directMatch[1]) return directMatch[1];
    }
    return null;
  }

  if (techName === 'Vue.js') {
    if (safeWin.Vue && safeWin.Vue.version) {
      return String(safeWin.Vue.version);
    }
    if (safeWin.__VUE__ && typeof safeWin.__VUE__ === 'object' && safeWin.__VUE__.version) {
      return String(safeWin.__VUE__.version);
    }
    if (safeDoc && safeDoc.querySelectorAll) {
      const nodes = safeDoc.querySelectorAll('script[src*="vue@"], script[src*="vue."]');
      for (let i = 0; i < nodes.length; i++) {
        const src = nodes[i].getAttribute('src') || '';
        const m = src.match(/vue@([0-9.]+)/i);
        if (m && m[1]) return m[1];
      }
    }
    const scriptMatch = htmlStr.match(/(?:<script|<link)[^>]+(?:src|href)=["'][^"']*vue@([0-9.]+)/i);
    if (scriptMatch && scriptMatch[1]) return scriptMatch[1];

    if (!htmlStr.includes('<')) {
      const directMatch = htmlStr.match(/^(?:Vue(?:\.js)?\s+|vue@)([0-9.]+)/i);
      if (directMatch && directMatch[1]) return directMatch[1];
    }
    return null;
  }

  if (techName === 'GeneratePress') {
    if (safeDoc && safeDoc.querySelectorAll) {
      const nodes = safeDoc.querySelectorAll('link[rel="stylesheet"][href*="generatepress"], script[src*="generatepress"]');
      for (let i = 0; i < nodes.length; i++) {
        const href = nodes[i].getAttribute('href') || nodes[i].getAttribute('src') || '';
        const m = href.match(/generatepress\/style(?:\.min)?\.css\?ver=([0-9.]+)/i)
          || href.match(/generatepress[^"'>]*?[?&]ver=([0-9.]+)/i);
        if (m && m[1]) return m[1];
      }
    }
    const m = htmlStr.match(/(?:<link[^>]+rel=["']stylesheet["'][^>]+href=["'][^"']*|<script[^>]+src=["'][^"']*)generatepress\/style(?:\.min)?\.css\?ver=([0-9.]+)/i)
      || htmlStr.match(/(?:<link[^>]+rel=["']stylesheet["'][^>]+href=["'][^"']*|<script[^>]+src=["'][^"']*)generatepress[^"'>]*?[?&]ver=([0-9.]+)/i);
    if (m && m[1]) return m[1];

    if (!htmlStr.includes('<')) {
      const directMatch = htmlStr.match(/^GeneratePress\s+([0-9.]+)/i);
      if (directMatch && directMatch[1]) return directMatch[1];
    }
    return null;
  }

  return null;
}
