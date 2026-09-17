// Security and Input Sanitization Utilities
// Zero em-dash compliance: strictly hyphens or colons

export function escapeHtml(str: any): string {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

export function isSafeUrl(urlString: string | null | undefined): boolean {
  if (!urlString || typeof urlString !== 'string') return false;
  try {
    const parsed = new URL(urlString);
    return parsed.protocol === 'https:' || parsed.protocol === 'http:';
  } catch (e) {
    return false;
  }
}

/**
 * Mitigates CSV formula injection (CSV Injection / Formula Injection).
 * Spreadsheet programs (Excel, Google Sheets, Calc) evaluate cells starting with
 * '=', '+', '-', '@', tab, or carriage return as executable formulas. Prepending an
 * apostrophe forces plain-text string evaluation without mutating legitimate data.
 */
export function escapeCsvField(val: any): string {
  if (val === null || val === undefined) return '""';
  let str = String(val);

  // If starts with formula trigger characters (including leading spaces/tabs before triggers)
  if (/^\s*[=+\-@\t\r]/.test(str)) {
    str = "'" + str;
  }

  // RFC 4180 quoting: escape quotes and wrap in double quotes if containing comma, quote, or newline
  if (/[",\n\r]/.test(str)) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return `"${str}"`;
}
