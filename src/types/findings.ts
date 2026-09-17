// Findings Engine Types and Interfaces

export type FindingCategory = 'performance' | 'accessibility' | 'seo' | 'architecture' | 'security';

export type SeverityLevel = 'critical' | 'warning' | 'opportunity' | 'healthy';

export interface EvidenceItem {
  label: string;
  value: string | number;
  context?: string;
}

export interface Finding {
  id: string;
  category: FindingCategory;
  severity: SeverityLevel;
  badge: string;
  title: string;
  evidence: EvidenceItem[];
  confidence: 'high' | 'medium' | 'low';
  explanation: string;
  recommendation: string;
  improvements: string[];
}

export interface AuditScorecard {
  overallScore: number;
  scoreMethodology: string;
  categoryScores: {
    performance: number;
    accessibility: number;
    seo: number;
    architecture: number;
  };
  primaryFinding: Finding;
  allFindings: Finding[];
}
