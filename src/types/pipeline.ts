// Pipeline & Agency Settings Types and Interfaces
import { SeverityLevel } from './findings';

export type LeadStatus = 'New' | 'Contacted' | 'Replied' | 'Qualified' | 'Proposal' | 'Won' | 'Lost';

export interface SavedLead {
  id: string;
  url: string;
  domain: string;
  timestamp: string;
  score: number;
  primaryFinding: string;
  severity: SeverityLevel;
  evidenceSummary: string;
  lcpDisplay: string;
  inpDisplay: string;
  clsDisplay: string;
  ttfbDisplay: string;
  domElements: number;
  techStack: string;
  status: LeadStatus;
  notes: string;
  companyName?: string;
  pitchSubject?: string;
  pitchBody?: string;
}

export interface AgencySettings {
  agencyName: string;
  logoUrl: string;
  auditorName: string;
  bookingUrl: string;
  psiApiKey: string;
}
