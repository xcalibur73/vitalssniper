// HTTP Header and Redirect Chain Forensics Engine
// Edge cache, canonical match, and search indexing directives inspector
// Zero em-dash compliance: strictly hyphens or colons

import { HttpHeaderForensics } from '../types/audit';

export function parseHttpHeaderForensics(
  headers: Record<string, string>,
  redirectCount: number = 0
): HttpHeaderForensics {
  const norm: Record<string, string> = {};
  if (headers && typeof headers === 'object') {
    Object.keys(headers).forEach(k => {
      norm[k.toLowerCase()] = headers[k];
    });
  }

  const xRobots = norm['x-robots-tag'] || undefined;
  const isNoindex = Boolean(xRobots && /noindex/i.test(xRobots));
  const isNofollow = Boolean(xRobots && /nofollow/i.test(xRobots));

  let canonicalHeaderUrl: string | undefined = undefined;
  const linkHeader = norm['link'];
  if (linkHeader) {
    const match = linkHeader.match(/<([^>]+)>;\s*rel=["']?canonical["']?/i);
    if (match) {
      canonicalHeaderUrl = match[1];
    }
  }

  const cfCache = norm['cf-cache-status'];
  const xCache = norm['x-cache'] || norm['x-cache-lookup'];
  const cacheStatus = (cfCache || xCache || norm['cache-control'] || 'UNCACHED').toUpperCase();
  const isCachedEdge = /HIT/i.test(cacheStatus);

  const serverBanner = norm['server'] || undefined;
  const hasRedirectChain = redirectCount > 1;
  const hstsHeader = norm['strict-transport-security']?.trim() || undefined;
  const hstsMatch = hstsHeader ? hstsHeader.match(/max-age\s*=\s*(\d+)/i) : null;
  const hasHsts = Boolean(hstsHeader && (!hstsMatch || Number(hstsMatch[1]) > 0));

  return {
    xRobotsTag: xRobots,
    isNoindex,
    isNofollow,
    canonicalHeaderUrl,
    cacheStatus,
    isCachedEdge,
    serverBanner,
    redirectCount,
    hasRedirectChain,
    hasHsts,
    hstsHeader
  };
}
