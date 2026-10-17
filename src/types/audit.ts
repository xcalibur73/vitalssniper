// Audit Engine Data Models and Interfaces
// Zero em-dash compliance: strictly hyphens or colons

export interface AuditMetadata {
  url: string;
  domain: string;
  tabId: number | null;
  protocol: 'https:' | 'http:' | string;
  auditedAt: string;
  viewportWidth: number;
  viewportHeight: number;
  scanDurationMs: number;
  cacheState?: 'likely cached' | 'service-worker mediated' | 'network-delivered' | 'unavailable/uncertain' | 'redirect' | string;
  measurementSource?: string;
}

export type LcpMeasurementSource =
  | 'navigation-observed'
  | 'buffered-active-tab'
  | 'heuristic'
  | 'unavailable';

export interface LcpSubpartAttribution {
  elementSelector: string | null;
  timeToFirstByteMs: number | null;
  resourceLoadDelayMs: number | null;
  resourceLoadDurationMs: number | null;
  elementRenderDelayMs: number | null;
  url?: string | null;
}

export interface InpSubpartAttribution {
  interactionTarget: string | null;
  interactionType: string | null;
  processingDelayMs: number | null;
  inputDelayMs: number | null;
  presentationDelayMs: number | null;
  culpritScriptUrl?: string | null;
  culpritFunctionName?: string | null;
  culpritExecutionMs?: number | null;
  culpritForcedStyleMs?: number | null;
  groupedEventCount?: number;
  groupedEvents?: string[];
}

export interface LayoutShiftBoundingBox {
  x: number;
  y: number;
  width: number;
  height: number;
  top: number;
  right: number;
  bottom: number;
  left: number;
}

export interface LayoutShiftDetail {
  score: number;
  startTimeMs: number;
  hadRecentInput: boolean;
  elementSelector: string | null;
  elementTag: string | null;
  previousRect: LayoutShiftBoundingBox | null;
  currentRect: LayoutShiftBoundingBox | null;
  deltaX: number;
  deltaY: number;
  distancePx: number;
  direction: 'down' | 'up' | 'left' | 'right' | 'diagonal' | 'none';
  impactAreaPx: number;
}

export interface ClsSubpartAttribution {
  sessionWindowScore: number;
  largestShiftTarget: string | null;
  largestShiftValue: number;
  shiftDetails?: LayoutShiftDetail[];
  totalShiftsCount?: number;
  largestShiftBoundingBox?: LayoutShiftBoundingBox | null;
}

export interface PerformanceMetrics {
  lcpMs: number | null;
  lcpSource: LcpMeasurementSource;
  lcpDisplay: string;
  lcpElementSelector: string | null;
  lcpElementType: string | null;
  lcpTtfbMs?: number | null;
  lcpLoadDelayMs?: number | null;
  lcpLoadDurationMs?: number | null;
  lcpRenderDelayMs?: number | null;
  lcpAttribution?: LcpSubpartAttribution | null;
  fcpMs: number | null;
  fcpDisplay: string;
  inpMs: number | null;
  inpObserved: boolean;
  inpDisplay: string;
  inpTarget?: string | null;
  inpProcessingDelayMs?: number | null;
  inpInputDelayMs?: number | null;
  inpPresentationDelayMs?: number | null;
  inpAttribution?: InpSubpartAttribution | null;
  cls: number | null;
  clsDisplay: string;
  clsSessionScore?: number | null;
  clsAttribution?: ClsSubpartAttribution | null;
  ttfbMs: number | null;
  ttfbDisplay: string;
  domLoadMs: number | null;
}

export interface LoafScriptCulprit {
  invoker: string | null;
  invokerType: string | null;
  sourceUrl: string | null;
  sourceFunctionName: string | null;
  sourceCharPosition?: number | null;
  executionDurationMs: number;
  forcedStyleAndLayoutMs: number;
  pauseDurationMs: number;
  compileDurationMs: number;
  totalDurationMs: number;
}

export interface LoafFrameForensics {
  startTimeMs: number;
  durationMs: number;
  blockingDurationMs: number;
  preRenderDurationMs: number;
  styleAndLayoutDurationMs: number;
  renderDelayMs: number;
  scripts: LoafScriptCulprit[];
  primaryCulprit: LoafScriptCulprit | null;
}

export interface MainThreadMetrics {
  longTaskCount: number;
  longestTaskMs: number | null;
  totalBlockingTimeMs: number;
  loafCount?: number;
  longestLoafMs?: number | null;
  totalLoafBlockingMs?: number;
  primaryLoafCulprit?: LoafScriptCulprit | null;
  loafFrames?: LoafFrameForensics[];
}

export interface DomMetrics {
  totalElements: number;
  maxDepth: number;
  averageDepth: number;
  deepBranchCount: number; // elements at depth > 15
}

export interface HtmlSizeMetrics {
  documentSerializedKB: number;
  encodedBodyKB: number | null;
  decodedBodyKB: number | null;
  transferKB: number | null;
}

export interface ImageAuditItem {
  src: string;
  currentSrc: string;
  format: string;
  naturalWidth: number;
  naturalHeight: number;
  renderedWidth: number;
  renderedHeight: number;
  isOversized: boolean;
  missingDimensions: boolean;
  hasPictureParent: boolean;
  hasSrcset: boolean;
  resourceKB: number | null;
  loading: 'lazy' | 'eager' | 'auto';
  fetchPriority: 'high' | 'low' | 'auto';
  decoding: 'async' | 'sync' | 'auto';
}

export interface HeadingNode {
  tag: 'h1' | 'h2' | 'h3' | 'h4' | 'h5' | 'h6';
  level: number;
  text: string;
}

export interface HeadingSkippedLevel {
  fromTag: string;
  toTag: string;
  headingText: string;
}

export interface HeadingHierarchy {
  tree: HeadingNode[];
  totalCount: number;
  h1Count: number;
  h2Count: number;
  h3Count: number;
  h4Count: number;
  h5Count: number;
  h6Count: number;
  missingH1: boolean;
  duplicateH1: boolean;
  skippedLevels: HeadingSkippedLevel[];
}

export interface LinkItem {
  url: string;
  anchorText: string;
  isInternal: boolean;
  isExternal: boolean;
  rel?: string;
  isNofollow: boolean;
  isSponsored: boolean;
  isUgc: boolean;
}

export interface LinkGraphSummary {
  total: number;
  internalCount: number;
  externalCount: number;
  nofollowCount: number;
  sponsoredCount: number;
  ugcCount: number;
  emptyAnchorCount: number;
}

export interface HreflangTag {
  hreflang: string;
  href: string;
}

export interface SeoStructuredDataAudit {
  jsonLdDetected: boolean;
  jsonLdValid: boolean;
  schemaTypes: string[];
  graphTypes: string[];
  duplicateSchemas: boolean;
  parsingErrors: string[];
  title: string | null;
  metaDescription: string | null;
  canonical: string | null;
  robots: string | null;
  h1Count: number;
  h1Text: string | null;
  openGraph: Record<string, string>;
  twitter: Record<string, string>;
  lang: string | null;
  hreflangCount: number;
  headings?: HeadingHierarchy;
  links?: LinkGraphSummary;
  wordCount?: number;
  hreflangs?: HreflangTag[];
  canonicalMatchesUrl?: boolean | null;
  isNoindex?: boolean;
  isNofollow?: boolean;
}

export interface AccessibilityMetrics {
  viewportPresent: boolean;
  zoomRestricted: boolean;
  viewportContent: string;
  horizontalOverflow: boolean;
  missingAltCount: number;
  emptyInteractiveCount: number;
  unlabeledControlCount: number;
  undersizedTargets24px: number;
  undersizedTargets44px: number;
  smallestTargetDimensions: string | null;
}

export interface ResourceMetrics {
  totalScripts: number;
  inlineScripts: number;
  externalScripts: number;
  thirdPartyScripts: number;
  stylesheets: number;
  fonts: number;
  imagesCount: number;
  totalTransferKB: number;
  detectedTelemetry: string[];
}

export interface TechnologyDetection {
  name: string;
  category: 'CMS' | 'Page Builder' | 'Framework' | 'Analytics' | 'Marketing Pixel' | 'Ecommerce' | 'CDN';
  confidence: 'high' | 'medium';
  evidence: string[];
  version?: string | null;
}

export interface RevenueLossAnalysis {
  isOptimal: boolean;
  modelType: string;
  totalExcessSeconds: number;
  conversionDropPct: number;
  lostMonthly: number;
  lostAnnual: number;
  roiHeadline: string;
}

export interface HttpHeaderForensics {
  xRobotsTag?: string;
  isNoindex: boolean;
  isNofollow: boolean;
  canonicalHeaderUrl?: string;
  cacheStatus: string;
  isCachedEdge: boolean;
  serverBanner?: string;
  redirectCount: number;
  hasRedirectChain: boolean;
}

export interface LabMetrics {
  lighthouseScore: number;
  seoScore: number;
  accessibilityScore: number;
  bestPracticesScore: number;
  lcpMs: number | null;
  lcpDisplay: string;
  clsScore: number | null;
  clsDisplay: string;
  tbtMs: number | null;
  tbtDisplay: string;
  fcpMs: number | null;
  fcpDisplay: string;
  speedIndexMs: number | null;
}

export interface FieldMetrics {
  available: boolean;
  lcpMs: number | null;
  lcpDisplay: string;
  clsScore: number | null;
  clsDisplay: string;
  inpMs: number | null;
  inpDisplay: string;
  fcpMs: number | null;
  fcpDisplay: string;
}

export interface ExternalMetrics {
  lighthouseScore: number;
  seoScore: number;
  accessibilityScore: number;
  bestPracticesScore: number;
  lcpMs: number | null;
  lcpDisplay: string;
  clsScore: number | null;
  clsDisplay: string;
  inpMs: number | null;
  inpDisplay: string;
  fcpMs: number | null;
  fcpDisplay: string;
  auditedAt: string;
  lab?: LabMetrics;
  field?: FieldMetrics;
}

export interface RawObservations {
  metadata: AuditMetadata;
  performance: PerformanceMetrics;
  mainThread: MainThreadMetrics;
  dom: DomMetrics;
  htmlSize: HtmlSizeMetrics;
  images: ImageAuditItem[];
  seo: SeoStructuredDataAudit;
  accessibility: AccessibilityMetrics;
  resources: ResourceMetrics;
  technologies: TechnologyDetection[];
  revenueLoss?: RevenueLossAnalysis;
  httpHeaders?: HttpHeaderForensics;
}

export interface AuditData {
  metadata?: AuditMetadata;
  performance?: PerformanceMetrics;
  mainThread?: MainThreadMetrics;
  dom?: DomMetrics;
  htmlSize?: HtmlSizeMetrics;
  images?: ImageAuditItem[];
  seo?: SeoStructuredDataAudit;
  accessibility?: AccessibilityMetrics;
  resources?: ResourceMetrics;
  technologies?: TechnologyDetection[];
  revenueLoss?: RevenueLossAnalysis;
  httpHeaders?: HttpHeaderForensics;
  [key: string]: any;
}
