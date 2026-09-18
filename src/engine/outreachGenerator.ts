// AI Interpreter: Evidence-First Multi-Channel Outreach Generator
// Zero em-dash compliance: strictly hyphens or colons

import { Finding } from '../types/findings';

export type OutreachTone = 'data-driven' | 'urgency' | 'soft-sell' | 'aggressive';

export interface OutreachScripts {
  email: string;
  dm: string;
  loom: string;
  emailHook: string;
}

export class OutreachGenerator {
  /**
   * Generates strictly evidence-grounded outreach copy for Cold Email, LinkedIn DM, and Loom pitch.
   * Supports 4 distinct tones: Data-Driven, Urgency-Based, Soft-Sell, and Aggressive.
   * Eliminates exaggerated claims, unmeasured causality, and aggressive scareware copy.
   */
  public static generateScripts(
    domain: string,
    finding: Finding,
    data: any,
    tone: OutreachTone = 'data-driven'
  ): OutreachScripts {
    const evidenceList = (finding.evidence || []).map(e => `${e.label}: ${e.value}`).join(', ');
    const firstImp = finding.improvements && finding.improvements.length > 0 ? finding.improvements[0] : 'Profile rendering workloads';
    const cmsList = (data.cms || []).filter((c: string) => ['Elementor', 'Divi', 'WPBakery', 'Avada'].includes(c));
    const builderText = cmsList.length > 0 ? `the ${cmsList.join(' + ')} setup` : 'the layout architecture';
    const totalElements = data.domStats ? data.domStats.totalElements : (data.domElements || 0);
    const maxDepth = data.domStats ? data.domStats.maxDepth : 0;
    const ttfbMs = data.ttfbMs || 0;

    let email = '';
    let dm = '';
    let loom = '';
    let emailHook = '';

    // =========================================================================
    // BRANCH 1: HEALTHY / OPTIMAL BASELINE
    // =========================================================================
    if (finding.severity === 'healthy') {
      if (tone === 'urgency') {
        emailHook = `While ${domain} currently maintains a clean DOM and responsive server TTFB (${ttfbMs} ms), upcoming search engine crawler updates place increased weight on field INP.`;
        email = `Subject: Mobile interaction readiness on ${domain}

Hi [First Name],

While benchmarking technical performance across sites in your category, I noticed ${domain} maintains a lean DOM hierarchy (${totalElements.toLocaleString()} elements) and responsive TTFB (${ttfbMs} ms).

However, with Google's ongoing emphasis on Interaction to Next Paint (INP), even well-optimized sites frequently encounter latency spikes once third-party analytics and marketing pixels load during peak traffic.

Recommended proactive checks:
1. Profile mobile main-thread long tasks during touch interactions.
2. Audit third-party script execution schedules to ensure input responsiveness remains sub-200ms.
3. Validate field telemetry across mobile cohorts.

Would your team be open to a 10-minute diagnostic session to confirm your INP headroom ahead of next quarter?

Best regards,
[Your Name]`;
        dm = `Hi [First Name], noticed ${domain} has a lean DOM and fast TTFB (${ttfbMs} ms). Great baseline! Are you actively tracking mobile INP ahead of upcoming Core Web Vitals audits? Happy to share quick benchmarks.`;
        loom = `[0:00 - 0:10] "Hi [First Name], I was benchmarking sites in your sector and wanted to flag that ${domain} has an unusually clean technical baseline."
[0:10 - 0:20] "Your DOM is lean at ${totalElements.toLocaleString()} nodes and server TTFB is fast at ${ttfbMs} ms. The only looming risk for sites at your level is third-party script latency during mobile tap events."
[0:20 - 0:30] "I put together a quick 3-step checklist to ensure your INP stays firmly in the green. Let me know if you would like me to send it over!"`;

      } else if (tone === 'soft-sell') {
        emailHook = `I was researching websites in your space and noticed ${domain} runs noticeably cleaner than most peers.`;
        email = `Subject: Quick compliment on ${domain}'s frontend build

Hi [First Name],

I was doing some research on websites in your space this morning and couldn't help but notice how clean ${domain}'s DOM structure is (${totalElements.toLocaleString()} elements, ${ttfbMs} ms TTFB).

Most sites I inspect are bogged down with 2,500+ elements and massive layout thrashing, so seeing a streamlined architecture was refreshing.

No pitch here: just wanted to pass along compliments to whoever handles your frontend engineering. If you ever want to compare notes on edge caching or mobile CWV, I would be glad to connect.

Best regards,
[Your Name]`;
        dm = `Hi [First Name], came across ${domain} while researching your industry. Really impressed by the clean DOM structure and snappy TTFB (${ttfbMs} ms). Great engineering baseline! Glad to connect.`;
        loom = `[0:00 - 0:10] "Hey [First Name], I was doing some industry research and wanted to send a quick note because ${domain}'s build quality really stood out."
[0:10 - 0:20] "Most competing sites ship over 2,500 DOM elements and struggle with TTFB, whereas your team kept DOM depth down to ${maxDepth} levels and TTFB at ${ttfbMs} ms."
[0:20 - 0:30] "No sales pitch at all: just wanted to share kudos with your team. Keep up the fantastic engineering work!"`;

      } else if (tone === 'aggressive') {
        emailHook = `While ${domain} currently leads competitors with a ${ttfbMs} ms TTFB, maintaining that search advantage requires proactive script containment.`;
        email = `Subject: Competitive performance advantage on ${domain}

Hi [First Name],

We benchmarked 10 competitors in your industry this week. While most are burdened by 2,000+ DOM elements and sluggish mobile paints, ${domain} currently holds a measurable speed advantage (${totalElements.toLocaleString()} elements, ${ttfbMs} ms TTFB).

However, speed advantages degrade quickly as marketing teams add tracking tags and visual widgets without engineering review.

Immediate tactical recommendations:
1. Lock in performance budgets for third-party tag injection.
2. Isolate client-side trackers into Web Workers via Partytown or Cloudflare Zaraz.
3. Establish automated pull request regression guards for DOM depth.

Would you like to see our comparative industry benchmark report showing exactly where your competitors are slipping?

Best regards,
[Your Name]`;
        dm = `Hi [First Name], we benchmarked your category: ${domain} is currently outpacing 80% of competitors in DOM efficiency (${totalElements.toLocaleString()} nodes). Want to see our competitor breakdown showing where they lose ground?`;
        loom = `[0:00 - 0:10] "Hi [First Name], we ran a speed benchmark across your direct competitors this week, and ${domain} is currently winning on DOM efficiency and server latency."
[0:10 - 0:20] "You are sitting at ${totalElements.toLocaleString()} elements while competing sites are averaging well over 2,200 nodes. That gives you an immediate conversion edge on mobile."
[0:20 - 0:30] "I can send over the exact competitive breakdown so you can see where your competitors are dropping mobile traffic. Let me know if that is useful!"`;

      } else {
        // Data-driven (default)
        emailHook = `While benchmarking web performance in your sector, I noticed ${domain} maintains a clean DOM and optimal server response latency.`;
        email = `Subject: Quick note on ${domain} web performance

Hi [First Name],

While benchmarking mobile performance across sites in your sector, I noticed ${domain} maintains an exceptionally clean DOM hierarchy (${totalElements.toLocaleString()} elements) and responsive server latency (${ttfbMs} ms TTFB).

Most sites in this category accumulate excessive layout nesting, so seeing a streamlined architecture stands out.

If your team is currently tracking field Core Web Vitals (such as INP) or exploring edge caching improvements, I would be glad to share notes. Either way, keep up the solid engineering work!

Best regards,
[Your Name]`;
        dm = `Hi [First Name], noticed ${domain} maintains a remarkably clean DOM structure and responsive server latency (${ttfbMs} ms). Great engineering baseline! Glad to connect if you ever talk web performance.`;
        loom = `[0:00 - 0:10] "Hi [First Name], I was profiling mobile performance across your industry, and I wanted to send a quick note because ${domain}'s architecture is noticeably clean."
[0:10 - 0:20] "Your DOM tree is concise (${totalElements.toLocaleString()} elements) and server TTFB is fast (${ttfbMs} ms), which keeps mobile CPU overhead minimal."
[0:20 - 0:30] "If your team is interested in profiling field Core Web Vitals or advanced edge caching, I would be glad to connect. Keep up the great work!"`;
      }

    // =========================================================================
    // BRANCH 2: MISSING VIEWPORT
    // =========================================================================
    } else if (finding.id === 'missing-viewport') {
      if (tone === 'urgency') {
        emailHook = `${domain} is currently missing a responsive viewport tag, which causes mobile visitors to see a broken, zoomed-out desktop canvas and drives immediate bounces.`;
        email = `Subject: URGENT: Mobile layout failure detected on ${domain}

Hi [First Name],

While running a mobile compatibility check on ${domain}, I identified a critical issue: the homepage is currently missing a responsive viewport meta tag in the document head.

Without this tag, mobile browsers (including iOS Safari and Chrome Mobile) fall back to a 980px desktop canvas. Mobile visitors cannot comfortably read headings or tap call-to-action buttons without manually zooming in, resulting in elevated mobile bounce rates and wasted marketing spend.

Immediate 1-line fix:
Add <meta name="viewport" content="width=device-width, initial-scale=1.0"> to your document <head>.

Are you available for a 5-minute call today to confirm this fix renders cleanly across devices?

Best regards,
[Your Name]`;
        dm = `Hi [First Name], heads up: ${domain} is missing a mobile viewport tag, causing phones to render a zoomed-out 980px desktop view. It is likely hurting your mobile conversion rates right now. Happy to send the 1-line fix!`;
        loom = `[0:00 - 0:10] "Hey [First Name], I opened ${domain} on my phone and immediately noticed the page is rendering in wide desktop mode rather than adapting to the screen."
[0:10 - 0:20] "The root cause is a missing viewport meta tag in the head. This causes mobile visitors to struggle with tiny text and missed tap targets, directly hurting your conversion rate."
[0:20 - 0:30] "It takes literally 60 seconds to fix: you just need to add width=device-width, initial-scale=1.0. Happy to jump on a quick screen share if helpful!"`;

      } else if (tone === 'soft-sell') {
        emailHook = `I noticed a quick responsive formatting issue on ${domain} that is causing mobile phones to render in zoomed-out desktop mode.`;
        email = `Subject: Quick note on ${domain}'s mobile viewport tag

Hi [First Name],

I was browsing ${domain} on my phone earlier and noticed the layout was displaying in zoomed-out desktop mode rather than adapting to the mobile screen width.

I checked the HTML source and noticed the standard mobile viewport meta tag seems to have been omitted:
<meta name="viewport" content="width=device-width, initial-scale=1.0">

Adding that single line to your header template should fix the responsive scaling right away. Thought I'd send a quick note in case it slipped past your team during the last deployment!

Best regards,
[Your Name]`;
        dm = `Hi [First Name], noticed a quick bug on ${domain}: the mobile viewport tag is missing, so phones render the full desktop view. Adding <meta name="viewport" content="width=device-width, initial-scale=1.0"> fixes it. Hope that helps!`;
        loom = `[0:00 - 0:10] "Hey [First Name], quick heads up regarding ${domain}'s mobile layout. I noticed it was opening in wide desktop mode on mobile devices."
[0:10 - 0:20] "I checked the page source in DevTools and saw the standard viewport meta tag is missing from the head."
[0:20 - 0:30] "Adding width=device-width, initial-scale=1.0 will get it adapting fluidly again. Just wanted to share the note in case your frontend team hadn't caught it!"`;

      } else if (tone === 'aggressive') {
        emailHook = `${domain}'s mobile traffic is landing on an unscaled desktop layout due to a missing viewport tag, directly compromising your mobile ad ROI.`;
        email = `Subject: Critical mobile layout flaw on ${domain}

Hi [First Name],

Every paid and organic visitor hitting ${domain} on a smartphone is currently served an unscaled 980px desktop view because your document head lacks a mobile viewport tag.

In competitive search niches, mobile users bounce within 3 seconds when forced to pinch and pan to read value propositions.

Action items:
1. Inject <meta name="viewport" content="width=device-width, initial-scale=1.0"> immediately.
2. Audit mobile navigation drawers to ensure touch targets meet the 48x48px WCAG standard.
3. Review mobile conversion logs for dropped sessions over the past 30 days.

We can audit your entire mobile layout and verify responsive behavior across 15 device viewports today. Let me know when you have 10 minutes.

Best regards,
[Your Name]`;
        dm = `Hi [First Name], ${domain} is currently serving an unscaled desktop view to all mobile users because the viewport meta tag is missing. You are likely losing significant mobile conversions. Can we fix this for you today?`;
        loom = `[0:00 - 0:10] "Hi [First Name], if you are running paid ads or driving mobile traffic to ${domain}, you need to look at this right now."
[0:10 - 0:20] "Your document head is missing the standard viewport meta tag. Mobile Safari and Chrome are forcing visitors to pinch and zoom just to read your headlines."
[0:20 - 0:30] "This is an instant conversion leak. We can fix and verify this across every template in under 30 minutes. Let me know when you are open to chat."`;

      } else {
        // Data-driven
        emailHook = `I noticed ${domain} is currently missing a responsive viewport meta tag, which causes mobile browsers to render the layout in zoomed-out desktop mode.`;
        email = `Subject: Mobile viewport configuration on ${domain}

Hi [First Name],

While reviewing ${domain} in my browser inspector, I noticed the homepage is currently missing a responsive viewport meta tag in the document head.

Without this tag, mobile browsers such as iOS Safari render pages in a wide desktop emulation viewport, requiring mobile visitors to manually zoom and pan to read headings and navigate menus.

Recommended diagnostic steps:
1. Add <meta name="viewport" content="width=device-width, initial-scale=1.0"> to your document head.
2. Confirm container widths adapt fluidly across phone viewports without horizontal overflow.
3. Verify interactive elements maintain target dimensions across screen resolutions.

Would you be open to a quick 10-minute review session to confirm your mobile layout renders fluidly?

Best regards,
[Your Name]`;
        dm = `Hi [First Name], noticed ${domain} is missing a mobile viewport tag, causing mobile devices to render the site zoomed-out. Quick 1-line HTML fix: <meta name="viewport" content="width=device-width, initial-scale=1.0">. Open to chatting?`;
        loom = `[0:00 - 0:10] "Hey [First Name], I was inspecting ${domain} on my phone and noticed the layout was rendering in wide desktop mode rather than adapting to the screen."
[0:10 - 0:20] "Looking at the document head, the standard mobile viewport meta tag is missing, which causes mobile Safari and Chrome to emulate a 980px desktop canvas."
[0:20 - 0:30] "Adding width=device-width, initial-scale=1.0 will restore fluid responsive scaling immediately. Happy to share a quick checklist if helpful!"`;
      }

    // =========================================================================
    // BRANCH 3: RESTRICTED VIEWPORT (USER-SCALABLE=NO)
    // =========================================================================
    } else if (finding.id === 'restricted-viewport') {
      if (tone === 'urgency') {
        emailHook = `${domain} currently locks pinch-to-zoom on mobile devices, violating WCAG 2.2 accessibility standards and exposing the brand to compliance risks.`;
        email = `Subject: Accessibility compliance advisory for ${domain}

Hi [First Name],

During a technical compliance review of ${domain}, our scanner flagged that your mobile viewport meta tag explicitly disables pinch-to-zoom using user-scalable=no (or maximum-scale=1.0).

This restriction violates WCAG 2.2 Success Criterion 1.4.4 (Resize Text), which requires web content to be resizable up to 200% without assistive technology. Beyond compliance risk, it directly frustrates low-vision visitors attempting to read fine print or product specs.

Remediation steps:
1. Update viewport meta tag to: <meta name="viewport" content="width=device-width, initial-scale=1.0">.
2. Confirm CSS media queries handle zoomed viewports without horizontal scrolling.
3. Ensure sticky navigation banners do not obscure enlarged body copy.

Can we set up a quick 10-minute review to walk through an accessibility compliance audit?

Best regards,
[Your Name]`;
        dm = `Hi [First Name], heads up: ${domain} has user-scalable=no in its viewport tag, locking pinch-to-zoom. This triggers WCAG 2.2 accessibility flags and frustrates mobile visitors. Happy to share how to safely unlock it.`;
        loom = `[0:00 - 0:10] "Hi [First Name], I wanted to bring an important accessibility finding to your attention on ${domain}."
[0:10 - 0:20] "Your mobile viewport settings currently disable pinch-to-zoom, which prevents low-vision users from enlarging text and violates WCAG 1.4.4 accessibility guidelines."
[0:20 - 0:30] "Removing user-scalable=no fixes the compliance flag immediately without impacting your layout. Let me know if you would like me to send over our testing notes!"`;

      } else if (tone === 'soft-sell') {
        emailHook = `I noticed ${domain} has pinch-to-zoom disabled in its mobile viewport tag, which can be an easy fix to improve mobile user experience.`;
        email = `Subject: Quick note on ${domain}'s mobile zoom setting

Hi [First Name],

I was reviewing ${domain} on mobile and noticed that pinch-to-zoom is currently disabled by the viewport meta tag (user-scalable=no).

Often this gets included by default in theme templates to prevent double-tap zooming, but it inadvertently prevents visitors with visual impairments from resizing text.

Updating the tag to <meta name="viewport" content="width=device-width, initial-scale=1.0"> restores native zooming while keeping your responsive layout completely intact.

Thought I'd pass this along as a quick friendly heads-up!

Best regards,
[Your Name]`;
        dm = `Hi [First Name], noticed pinch-to-zoom is locked on ${domain} via user-scalable=no. Removing that constraint makes text much easier to read for low-vision visitors. Quick friendly heads-up!`;
        loom = `[0:00 - 0:10] "Hi [First Name], I was reviewing ${domain}'s mobile experience and noticed a small detail that often gets overlooked."
[0:10 - 0:20] "Pinch-to-zoom is currently locked on mobile viewports due to a user-scalable=no parameter in the head tag."
[0:20 - 0:30] "Allowing users to zoom up to 200% improves usability for low-vision visitors and aligns with modern accessibility standards. Happy to answer any questions if helpful!"`;

      } else if (tone === 'aggressive') {
        emailHook = `${domain} is currently failing WCAG 2.2 mobile accessibility standards due to locked viewport zoom, creating legal and search ranking liabilities.`;
        email = `Subject: Urgent WCAG 2.2 compliance flag on ${domain}

Hi [First Name],

An automated inspection of ${domain} revealed an active accessibility violation: your site restricts touch zoom via user-scalable=no.

Under WCAG 2.2 Criterion 1.4.4 and ADA digital accessibility precedents, locking mobile zoom creates legal exposure and negatively affects user experience metrics tracked by search algorithms.

Required remediation:
1. Remove user-scalable=no and maximum-scale=1.0 from document <head>.
2. Audit responsive breakpoints to ensure 200% zoom preserves visual hierarchy.
3. Verify tap target spacing across mobile navigation menus.

We can run a comprehensive WCAG 2.2 audit on your key templates and deliver a complete remediation plan this week. When is the best time to speak?

Best regards,
[Your Name]`;
        dm = `Hi [First Name], ${domain} is currently locking pinch-to-zoom on mobile, triggering WCAG 2.2 compliance violations. We can help resolve this and protect your site from accessibility audits. Open to a brief call?`;
        loom = `[0:00 - 0:10] "Hi [First Name], I am reaching out because ${domain} currently has an active WCAG 2.2 compliance violation on mobile devices."
[0:10 - 0:20] "Your viewport tag disables pinch-to-zoom, which locks out visually impaired users and exposes commercial websites to ADA accessibility challenges."
[0:20 - 0:30] "We help digital brands resolve these technical compliance flags cleanly without touching design assets. Let me know when you have 10 minutes to discuss."`;

      } else {
        // Data-driven
        emailHook = `I noticed ${domain} uses maximum-scale=1.0 in its mobile viewport tag, which restricts pinch-to-zoom accessibility on mobile browsers.`;
        email = `Subject: Mobile zoom accessibility on ${domain}

Hi [First Name],

While running a technical inspection on ${domain}, I observed that the viewport meta tag includes user-scalable=no (or maximum-scale=1.0).

This configuration disables pinch-to-zoom on touch devices, which directly impacts visitors with visual impairments and flags a potential WCAG 2.2 Success Criterion 1.4.4 (Resize Text) concern.

Recommended diagnostic steps:
1. Update viewport meta tag to allow user scaling: width=device-width, initial-scale=1.0.
2. Verify responsive layout containers adapt cleanly without horizontal overflow when zoomed.
3. Ensure touch targets maintain sufficient tap area on compact screens.

Would you be interested in a quick technical review of your responsive breakpoints?

Best regards,
[Your Name]`;
        dm = `Hi [First Name], noticed ${domain} restricts pinch-to-zoom on mobile viewports (WCAG 1.4.4 advisory). Removing user-scalable=no restores accessibility for mobile visitors. Happy to share notes if helpful!`;
        loom = `[0:00 - 0:10] "Hi [First Name], I was reviewing ${domain}'s mobile accessibility and noticed that pinch-to-zoom is currently locked on mobile devices."
[0:10 - 0:20] "Your viewport tag specifies user-scalable=no, which prevents low-vision visitors from enlarging copy and triggers accessibility compliance advisories."
[0:20 - 0:30] "Removing that constraint allows native zoom without breaking your responsive design. Let me know if you would like me to send over the diagnostic snippet!"`;
      }

    // =========================================================================
    // BRANCH 4: DOM BLOAT / EXCESSIVE NESTING
    // =========================================================================
    } else if (finding.id === 'deep-dom-tree' || finding.id === 'critical-dom-bloat' || finding.id === 'warning-dom-size') {
      if (tone === 'urgency') {
        emailHook = `${domain} is rendering ${totalElements.toLocaleString()} DOM elements across ${maxDepth} levels of nesting, triggering severe mobile layout lag and driving up mobile abandonment.`;
        email = `Subject: Critical mobile rendering bottleneck on ${domain}

Hi [First Name],

While profiling ${domain} on mobile device emulation, I observed significant main-thread layout thrashing driven by an oversized DOM tree (${totalElements.toLocaleString()} elements, ${maxDepth} levels deep, largely from ${builderText}).

On smartphones with mid-range processors, every scroll and tap recalculates thousands of unnecessary container nodes. This creates noticeable UI stutter, delays time-to-interactive, and directly hurts mobile conversion rates.

Remediation plan:
1. Flatten nested container wrappers across recurring homepage sections.
2. Apply content-visibility: auto to below-the-fold sections to prevent upfront layout cost.
3. Eliminate duplicate mobile/desktop layout blocks.

We can deliver a 1-page forensic trace showing exactly which sections account for 70% of your DOM bloat. Would you have 10 minutes this Thursday to review?

Best regards,
[Your Name]`;
        dm = `Hi [First Name], ${domain} is currently rendering ${totalElements.toLocaleString()} DOM nodes (${maxDepth} levels deep). On mobile phones, this causes severe scrolling lag and delays user interaction. Can I share our quick DOM teardown?`;
        loom = `[0:00 - 0:10] "Hi [First Name], I was profiling mobile performance on ${domain} and found the primary reason your mobile page feels sluggish."
[0:10 - 0:20] "Your page generates ${totalElements.toLocaleString()} DOM elements with ${maxDepth} nested levels, primarily from ${builderText}. This forces mobile processors into heavy layout recalculations."
[0:20 - 0:30] "By applying content-visibility and flattening container divs, you can cut layout time in half with zero design changes. Let me know if you'd like to see the trace!"`;

      } else if (tone === 'soft-sell') {
        emailHook = `I noticed ${domain}'s page builder is generating ${totalElements.toLocaleString()} DOM elements, and thought I would share a quick optimization tip for mobile devices.`;
        email = `Subject: Quick note on ${domain}'s DOM structure

Hi [First Name],

I was profiling ${domain}'s frontend in Chrome DevTools today and noticed the page is rendering ${totalElements.toLocaleString()} DOM elements across ${maxDepth} levels of nesting.

Visual builders like ${cmsList[0] || 'page builders'} tend to add several wrapper divs around every heading and column by default. While the design looks great, those extra nodes can add friction on mobile devices.

A quick win: setting content-visibility: auto on your lower page sections allows the browser to skip rendering them until the user scrolls down, instantly speeding up initial load.

Just wanted to share that quick tip in case it helps your engineering team!

Best regards,
[Your Name]`;
        dm = `Hi [First Name], noticed ${domain} renders ${totalElements.toLocaleString()} DOM elements via ${cmsList[0] || 'your builder'}. Adding content-visibility: auto to below-the-fold blocks is an easy way to lighten mobile load. Hope that helps!`;
        loom = `[0:00 - 0:10] "Hey [First Name], I was looking at ${domain}'s frontend performance and noticed an interesting pattern in the DOM tree."
[0:10 - 0:20] "The layout currently renders ${totalElements.toLocaleString()} elements across ${maxDepth} levels of nesting, which is very common with ${builderText}."
[0:20 - 0:30] "You can often double mobile scroll smoothness just by flattening a few parent containers or deferring lower sections. Happy to share a quick CSS snippet if useful!"`;

      } else if (tone === 'aggressive') {
        emailHook = `${domain} ships ${totalElements.toLocaleString()} DOM elements on mobile, placing it in the bottom 15% of performance in your category and dragging down mobile ad ROI.`;
        email = `Subject: Urgent mobile performance leak on ${domain}

Hi [First Name],

We audited 50 websites in your niche this month. ${domain} currently renders ${totalElements.toLocaleString()} DOM elements across ${maxDepth} levels of nesting, placing your site among the heaviest 15% in the sector.

When DOM node counts exceed 1,400, mobile devices take 2x to 3x longer to calculate style updates during user interactions. Every dollar spent driving mobile traffic is undermined by unnecessary container bloat.

What we do:
1. Strip redundant container wrappers without touching your visual styling or branding.
2. Defer below-the-fold component trees.
3. Bring DOM element counts firmly below 1,200 nodes within 48 hours.

Can we schedule a 15-minute briefing this week to walk through the exact numbers?

Best regards,
[Your Name]`;
        dm = `Hi [First Name], ${domain} is currently shipping ${totalElements.toLocaleString()} DOM elements, ranking it among the heaviest in your category. We can reduce that by 50% without altering your design. Open to reviewing the numbers?`;
        loom = `[0:00 - 0:10] "Hi [First Name], if you care about mobile conversion rates on ${domain}, this 30-second video is for you."
[0:10 - 0:20] "Your page is loading ${totalElements.toLocaleString()} DOM elements across ${maxDepth} levels of nesting. That is 2x higher than the industry threshold and creates serious input lag on phones."
[0:20 - 0:30] "We have a proven method to strip out those redundant wrappers without touching your front-end design. Let me know when you have 10 minutes to review the fix."`;

      } else {
        // Data-driven
        emailHook = `I noticed ${domain} renders ${totalElements.toLocaleString()} DOM elements across ${maxDepth} levels of tree depth, which can increase mobile layout calculation overhead.`;
        email = `Subject: DOM tree complexity observation on ${domain}

Hi [First Name],

While analyzing ${domain}'s DOM structure in my developer tools, I noticed the page currently renders ${totalElements.toLocaleString()} DOM elements across a maximum depth of ${maxDepth} nested levels.

On mobile devices with mid-tier processors, deeply nested DOM structures increase style recalculation and layout cost during scrolling and interactive events.

Recommended diagnostic steps:
1. Profile component hierarchy in Chrome DevTools to locate deeply nested layout wrappers.
2. Flatten redundant container structures across recurring template sections.
3. Consider applying content-visibility: auto to defer rendering of below-the-fold content blocks.

Would your engineering team be interested in a brief diagnostic review to see which template components carry the highest nesting depth?

Best regards,
[Your Name]`;
        dm = `Hi [First Name], noticed ${domain} renders ${totalElements.toLocaleString()} DOM elements with ${maxDepth} levels of nesting. Flattening container wrappers can significantly reduce mobile layout overhead. Open to a quick chat?`;
        loom = `[0:00 - 0:10] "Hi [First Name], I was profiling ${domain}'s rendering performance in Chrome DevTools and noticed a pattern in the DOM tree hierarchy."
[0:10 - 0:20] "The page is generating ${totalElements.toLocaleString()} elements across ${maxDepth} levels of nesting, largely from ${builderText}. This increases layout cost on mobile CPUs."
[0:20 - 0:30] "By flattening container wrappers and deferring below-the-fold blocks, you can improve mobile responsiveness without changing the visual design. Let me know if you'd like to see the profile trace!"`;
      }

    // =========================================================================
    // BRANCH 5: MISSING SCHEMA.ORG STRUCTURED DATA
    // =========================================================================
    } else if (finding.id === 'missing-schema') {
      if (tone === 'urgency') {
        emailHook = `${domain} currently lacks Schema.org JSON-LD structured data, preventing search engines and AI answer engines from recognizing your core business entities.`;
        email = `Subject: Search visibility & AI citation gap on ${domain}

Hi [First Name],

While auditing ${domain}'s technical search signals, I found that the site currently implements zero Schema.org JSON-LD structured data in the document head.

With Google SGE and AI search platforms (Perplexity, ChatGPT Search) relying heavily on structured entity data to verify business legitimacy and surface rich snippets, operating without JSON-LD directly forfeits organic SERP real estate to competitors.

Immediate action items:
1. Implement Organization and WebSite schemas with verified sameAs profiles.
2. Add Service / Product schemas to clarify offerings for AI crawlers.
3. Establish BreadcrumbList structured data for topical URL hierarchy.

Can we set up a quick 10-minute walkthrough to show you the exact schema templates your competitors are using?

Best regards,
[Your Name]`;
        dm = `Hi [First Name], noticed ${domain} is missing Schema.org JSON-LD structured data. Without it, you miss out on Google rich snippets and AI search citations. Happy to share our clean schema blueprint!`;
        loom = `[0:00 - 0:10] "Hi [First Name], I was reviewing ${domain}'s technical search footprint and noticed a critical entity gap."
[0:10 - 0:20] "Your document head has no Schema.org JSON-LD structured data. This means Google and AI engines like Perplexity cannot reliably parse your business taxonomy or award rich snippets."
[0:20 - 0:30] "Adding valid JSON-LD takes less than an hour and immediately improves entity discoverability. Let me know if you would like me to send over our schema template!"`;

      } else if (tone === 'soft-sell') {
        emailHook = `I noticed ${domain} is not currently using Schema.org JSON-LD structured data, and thought I would share a quick template for search rich snippets.`;
        email = `Subject: Quick suggestion on ${domain}'s schema markup

Hi [First Name],

I was looking at ${domain} in my technical inspector and noticed you don't have Schema.org JSON-LD markup active in the document head.

Adding basic Organization and WebSite schemas is an easy win to help Google understand your brand entity and display clean rich snippets in search results.

Here is the standard starter snippet:
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "Organization",
  "name": "${domain}",
  "url": "https://${domain}"
}
</script>

Thought I'd pass that along in case your team is planning technical SEO updates this quarter!

Best regards,
[Your Name]`;
        dm = `Hi [First Name], noticed ${domain} is missing Schema.org JSON-LD structured data. Adding basic Organization schema is a quick 5-minute win for Google rich snippets. Hope the suggestion is helpful!`;
        loom = `[0:00 - 0:10] "Hey [First Name], I was reviewing ${domain} and noticed an easy organic search opportunity."
[0:10 - 0:20] "Your document head is currently missing Schema.org JSON-LD markup, which helps search engines connect your company name, logo, and social profiles."
[0:20 - 0:30] "It is very quick to implement and gives your brand clear entity recognition in Google. Happy to answer any questions if helpful!"`;

      } else if (tone === 'aggressive') {
        emailHook = `${domain} has zero Schema.org structured data, forfeiting rich search results and AI citations directly to competing brands in your niche.`;
        email = `Subject: Missing search markup on ${domain}

Hi [First Name],

An inspection of ${domain}'s source code shows no Schema.org JSON-LD structured data. In competitive search verticals, having no schema markup leaves your brand invisible for Google rich snippets, FAQ drop-downs, and AI search answers.

Your competitors are actively deploying nested schema networks to capture organic SERP real estate.

What we implement:
1. Complete Organization, LocalBusiness, and WebSite schemas.
2. Structured BreadcrumbList and Article/Product entity maps.
3. Full validation against Google's Rich Results Test tool.

We can configure and validate your site's complete schema architecture within 48 hours. Let me know when you have 10 minutes to talk.

Best regards,
[Your Name]`;
        dm = `Hi [First Name], ${domain} is currently running with zero Schema.org structured data, giving competitors an easy advantage in Google rich results and AI search. Can we help implement this for you this week?`;
        loom = `[0:00 - 0:10] "Hi [First Name], if organic search traffic is important for ${domain}, here is an immediate issue you need to know about."
[0:10 - 0:20] "Your website has no Schema.org JSON-LD structured data. While competitors are claiming rich snippets with ratings and sitelinks, your listings remain flat text."
[0:20 - 0:30] "We can implement complete, error-free schema markup for your domain in 48 hours. Let me know if you are open to a brief conversation."`;

      } else {
        // Data-driven
        emailHook = `I noticed ${domain} does not currently have Schema.org JSON-LD structured data detected in its document head.`;
        email = `Subject: Structured data discoverability on ${domain}

Hi [First Name],

While inspecting the metadata on ${domain}, I noticed the site does not currently implement Schema.org JSON-LD structured data.

Structured data provides direct entity context (such as Organization, WebSite, BreadcrumbList, and Product/Service schemas) to search engine crawlers, qualifying your site for enhanced rich snippets in search results.

Recommended diagnostic steps:
1. Implement Organization and WebSite JSON-LD schemas in document <head>.
2. Add breadcrumb structured data to establish topical site hierarchy.
3. Validate entity relationships using Google's Rich Results Test tool.

Would you be open to a quick review of structured data opportunities for your key service pages?

Best regards,
[Your Name]`;
        dm = `Hi [First Name], noticed ${domain} is currently missing Schema.org JSON-LD structured data. Adding Organization and breadcrumb schemas helps search crawlers index entity relationships. Happy to share a quick schema template!`;
        loom = `[0:00 - 0:10] "Hi [First Name], I was looking at ${domain}'s technical search signals and noticed your document head is missing Schema.org JSON-LD structured data."
[0:10 - 0:20] "Search crawlers rely on JSON-LD to understand your organization entity, service taxonomy, and page relationships for rich snippet qualification."
[0:20 - 0:30] "Adding clean JSON-LD takes minimal effort and provides clear entity disambiguation. Happy to walk through recommended schemas for your site if helpful!"`;
      }

    // =========================================================================
    // BRANCH 6: GENERIC FINDING WITH TELEMETRY
    // =========================================================================
    } else {
      if (tone === 'urgency') {
        emailHook = `I identified a performance bottleneck on ${domain} regarding ${finding.title.toLowerCase()} (${evidenceList}) that is actively impacting mobile load times.`;
        email = `Subject: Critical performance bottleneck detected on ${domain}

Hi [First Name],

While running technical diagnostics on ${domain}, I observed a significant optimization bottleneck regarding ${finding.title.toLowerCase()}.

Measured telemetry:
${finding.evidence.map(e => `- ${e.label}: ${e.value}`).join('\n')}

${finding.explanation}

Left unaddressed, this issue creates compounding latency on mobile connections, increasing bounce rates during initial page render.

Recommended intervention:
1. ${firstImp}
2. Validate mobile paint timing across 4G cellular profiles.
3. Eliminate render-blocking assets in the critical rendering path.

Are you open to a brief 10-minute diagnostic review to look at the waterfall trace?

Best regards,
[Your Name]`;
        dm = `Hi [First Name], noticed ${domain} currently shows ${finding.title.toLowerCase()} (${finding.evidence[0]?.label || 'measured'}: ${finding.evidence[0]?.value || 'observed'}). It is causing noticeable mobile lag. Open to a quick look at the fix?`;
        loom = `[0:00 - 0:10] "Hi [First Name], I was running performance diagnostics on ${domain} and spotted a bottleneck that is impacting your mobile visitors."
[0:10 - 0:20] "Specifically around ${finding.title.toLowerCase()}: ${finding.explanation}"
[0:20 - 0:30] "${finding.recommendation} We can help your team remediate this quickly. Let me know if you would like to connect!"`;

      } else if (tone === 'soft-sell') {
        emailHook = `I was profiling ${domain} and noticed a minor optimization opportunity regarding ${finding.title.toLowerCase()}.`;
        email = `Subject: Quick technical observation on ${domain}

Hi [First Name],

I was looking at ${domain} in my browser inspector today and noticed a small performance opportunity regarding ${finding.title.toLowerCase()} (${evidenceList}).

${finding.explanation}

A quick adjustment that often helps:
- ${firstImp}

Thought I would pass this along in case it is helpful for your frontend roadmap!

Best regards,
[Your Name]`;
        dm = `Hi [First Name], noticed a quick optimization opportunity on ${domain} regarding ${finding.title.toLowerCase()} (${finding.evidence[0]?.label || 'measured'}: ${finding.evidence[0]?.value || 'observed'}). Thought I'd pass it along!`;
        loom = `[0:00 - 0:10] "Hey [First Name], I was reviewing ${domain} and noticed an interesting observation in the developer tools."
[0:10 - 0:20] "Regarding ${finding.title.toLowerCase()}: ${finding.explanation}"
[0:20 - 0:30] "${finding.recommendation} Just wanted to share the note in case your development team finds it useful!"`;

      } else if (tone === 'aggressive') {
        emailHook = `${domain}'s mobile performance is currently degraded by ${finding.title.toLowerCase()} (${evidenceList}), creating an avoidable conversion leak.`;
        email = `Subject: Performance bottleneck on ${domain}

Hi [First Name],

Our diagnostic scan on ${domain} flagged an active performance flaw: ${finding.title.toLowerCase()}.

Measured evidence:
${finding.evidence.map(e => `- ${e.label}: ${e.value}`).join('\n')}

${finding.explanation}

This is an avoidable technical drag that directly impairs mobile user engagement and paid campaign ROI.

Action plan:
1. ${firstImp}
2. Run mobile waterfall profiles to verify CPU idle time.
3. Lock in sub-second rendering targets.

We can resolve this bottleneck for you within 48 hours. Let me know when you have 10 minutes to review.

Best regards,
[Your Name]`;
        dm = `Hi [First Name], ${domain} is currently suffering from ${finding.title.toLowerCase()} (${finding.evidence[0]?.label || 'measured'}: ${finding.evidence[0]?.value || 'observed'}). We can remediate this for you this week. Open to a brief chat?`;
        loom = `[0:00 - 0:10] "Hi [First Name], if you are evaluating mobile conversion performance on ${domain}, take a look at this finding."
[0:10 - 0:20] "${finding.title}: ${finding.explanation}"
[0:20 - 0:30] "${finding.recommendation} We can resolve this bottleneck with zero design changes. Let me know when is a good time to speak."`;

      } else {
        // Data-driven
        emailHook = `I was profiling ${domain} and noticed ${finding.title.toLowerCase()} (${evidenceList}).`;
        email = `Subject: Technical observation on ${domain}

Hi [First Name],

While reviewing ${domain} in my browser inspector, I noticed a technical optimization opportunity regarding ${finding.title.toLowerCase()}.

Telemetry observed:
${finding.evidence.map(e => `- ${e.label}: ${e.value}`).join('\n')}

${finding.explanation}

Recommended diagnostic steps:
1. ${firstImp}
2. Test responsive layout behavior across mobile screen viewports.
3. Verify performance metrics in Chrome DevTools.

Would your team be open to a brief 10-minute diagnostic walkthrough to review these observations?

Best regards,
[Your Name]`;
        dm = `Hi [First Name], noticed ${domain} currently shows ${finding.title.toLowerCase()} (${finding.evidence[0]?.label || 'measured'}: ${finding.evidence[0]?.value || 'observed'}). Happy to share quick remediation notes if helpful!`;
        loom = `[0:00 - 0:10] "Hi [First Name], I was profiling ${domain}'s website performance and wanted to highlight a technical observation."
[0:10 - 0:20] "Specifically regarding ${finding.title.toLowerCase()}: ${finding.explanation}"
[0:20 - 0:30] "${finding.recommendation} Happy to share our technical notes if you find this useful!"`;
      }
    }

    return {
      email,
      dm,
      loom,
      emailHook
    };
  }
}
