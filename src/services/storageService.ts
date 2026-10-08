// Storage Service: Type-Safe Wrapper & Backward-Compatible Migration
// Zero em-dash compliance: strictly hyphens or colons

import { SavedLead, AgencySettings, LeadStatus } from '../types/pipeline';
import { escapeCsvField } from '../utils/security';

export interface StoredSubscriptionTimeframe {
  status: 'active' | 'trial' | 'annual' | 'monthly' | 'free' | 'expired' | 'lifetime';
  tier: string;
  planName: string;
  interval: 'monthly' | 'annual' | 'trial' | 'free' | 'lifetime' | 'none';
  totalDays: number;
  daysRemaining: number;
  daysElapsed: number;
  percentRemaining: number;
  periodStart: string;
  periodEnd: string | null;
  isMaster: boolean;
  formattedStatus: string;
  formattedRenewal: string;
}

export class StorageService {
  private static migrationDone = false;

  public static async get<T = Record<string, any>>(keys: string[]): Promise<Record<string, any>> {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      return await chrome.storage.local.get(keys);
    }
    const out: Record<string, any> = {};
    keys.forEach(k => {
      try {
        const val = localStorage.getItem(k);
        if (val !== null) out[k] = JSON.parse(val);
      } catch (e) {
        out[k] = localStorage.getItem(k);
      }
    });
    return out;
  }

  public static async set(obj: Record<string, any>): Promise<boolean> {
    try {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        await chrome.storage.local.set(obj);
        return true;
      }
      Object.entries(obj).forEach(([k, v]) => {
        try {
          localStorage.setItem(k, typeof v === 'object' ? JSON.stringify(v) : String(v));
        } catch (e) {}
      });
      return true;
    } catch (err: any) {
      console.error('StorageService.set failed (possible quota error):', err);
      return false;
    }
  }

  public static async remove(keys: string[]): Promise<void> {
    try {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        await chrome.storage.local.remove(keys);
        return;
      }
      keys.forEach(k => localStorage.removeItem(k));
    } catch (err) {
      console.warn('StorageService.remove error:', err);
    }
  }

  /**
   * Idempotent migration from legacy storage keys (vitalssniper_leads, vitalssniper_settings).
   * Non-destructive migration under tested conditions: preserves existing pipeline data and prevents startup crashes on invalid data.
   */
  public static async initialize(): Promise<void> {
    if (this.migrationDone) return;
    this.migrationDone = true;

    try {
      const res = await this.get([
        'vs_pipeline',
        'vitalssniper_leads',
        'agency_settings',
        'vitalssniper_settings',
        'vs_license_key',
        'vs_is_pro',
        'vs_tier',
        'vs_entitlement'
      ]);

      // 1. Migrate legacy leads
      if ((!res.vs_pipeline || (Array.isArray(res.vs_pipeline) && res.vs_pipeline.length === 0)) && res.vitalssniper_leads) {
        const legacyLeads = Array.isArray(res.vitalssniper_leads) ? res.vitalssniper_leads : [];
        if (legacyLeads.length > 0) {
          const migratedLeads: SavedLead[] = legacyLeads.map((item: any, idx: number) => ({
            id: item.id || `lead-legacy-${Date.now()}-${idx}`,
            url: item.url || '',
            domain: item.domain || (item.url ? new URL(item.url, 'https://example.com').hostname.replace(/^www\./, '') : 'prospect'),
            timestamp: item.timestamp || new Date().toISOString(),
            score: typeof item.score === 'number' ? item.score : 100,
            primaryFinding: item.primaryFinding || item.flaw || 'Observation',
            severity: item.severity || 'warning',
            evidenceSummary: item.evidenceSummary || '',
            lcpDisplay: item.lcpDisplay || 'N/A',
            inpDisplay: item.inpDisplay || 'N/A',
            clsDisplay: item.clsDisplay || 'N/A',
            ttfbDisplay: item.ttfbDisplay || 'N/A',
            domElements: typeof item.domElements === 'number' ? item.domElements : (item.domNodes || 0),
            techStack: item.techStack || '',
            status: item.status || 'New',
            notes: item.notes || ''
          }));
          await this.set({ vs_pipeline: migratedLeads });
          await this.remove(['vitalssniper_leads']);
        }
      }

      // 2. Migrate legacy settings
      if (!res.agency_settings && res.vitalssniper_settings && typeof res.vitalssniper_settings === 'object') {
        const legacySettings = res.vitalssniper_settings;
        const migratedSettings: AgencySettings = {
          agencyName: legacySettings.agencyName || legacySettings.brandName || '',
          logoUrl: legacySettings.logoUrl || '',
          auditorName: legacySettings.auditorName || '',
          bookingUrl: legacySettings.bookingUrl || legacySettings.calendlyUrl || '',
          psiApiKey: legacySettings.psiApiKey || ''
        };
        await this.set({ agency_settings: migratedSettings });
        await this.remove(['vitalssniper_settings']);
      }
    } catch (migrationErr) {
      console.warn('StorageService.initialize migration non-fatal error:', migrationErr);
    }
  }

  // --- Lead Pipeline CRM Operations ---

  public static async getPipelineLeads(): Promise<SavedLead[]> {
    await this.initialize();
    const res = await this.get(['vs_pipeline', 'vitalssniper_leads']);
    let list = res.vs_pipeline;
    if (!Array.isArray(list) || list.length === 0) {
      if (Array.isArray(res.vitalssniper_leads)) {
        list = res.vitalssniper_leads;
      }
    }
    if (!Array.isArray(list)) return [];
    
    // Normalization: ensure every lead has proper structure
    return list.map((item: any) => ({
      id: item.id || `lead-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
      url: item.url || '',
      domain: item.domain || '',
      timestamp: item.timestamp || new Date().toISOString(),
      score: typeof item.score === 'number' ? item.score : 100,
      primaryFinding: item.primaryFinding || item.flaw || 'Observation',
      severity: item.severity || 'warning',
      evidenceSummary: item.evidenceSummary || '',
      lcpDisplay: item.lcpDisplay || 'N/A',
      inpDisplay: item.inpDisplay || 'N/A',
      clsDisplay: item.clsDisplay || 'N/A',
      ttfbDisplay: item.ttfbDisplay || 'N/A',
      domElements: typeof item.domElements === 'number' ? item.domElements : (item.domNodes || 0),
      techStack: item.techStack || '',
      status: item.status || 'New',
      notes: item.notes || ''
    }));
  }

  public static async savePipelineLead(lead: SavedLead): Promise<SavedLead[]> {
    const leads = await this.getPipelineLeads();
    const existingIndex = leads.findIndex(l => l.domain.toLowerCase() === lead.domain.toLowerCase());

    if (existingIndex >= 0) {
      leads[existingIndex] = { ...leads[existingIndex], ...lead };
    } else {
      leads.unshift(lead);
    }

    await this.set({ vs_pipeline: leads });
    return leads;
  }

  public static async removePipelineLead(leadId: string): Promise<SavedLead[]> {
    const leads = await this.getPipelineLeads();
    const filtered = leads.filter(l => l.id !== leadId);
    await this.set({ vs_pipeline: filtered });
    return filtered;
  }

  public static async updateLeadStatus(leadId: string, status: LeadStatus): Promise<SavedLead[]> {
    const leads = await this.getPipelineLeads();
    const index = leads.findIndex(l => l.id === leadId);
    if (index >= 0) {
      leads[index].status = status;
      await this.set({ vs_pipeline: leads });
    }
    return leads;
  }

  public static async clearPipeline(): Promise<void> {
    await this.set({ vs_pipeline: [] });
  }

  public static async generatePipelineCsv(leads: SavedLead[]): Promise<string> {
    const headers = [
      'Company Name',
      'Domain',
      'Target URL',
      'Audited At',
      'Pitch Subject',
      'Pitch Body',
      'VitalsSniper Score',
      'Severity',
      'Primary Finding',
      'Evidence Summary',
      'LCP',
      'Observed Interaction Latency',
      'CLS',
      'TTFB',
      'DOM Elements',
      'Tech Stack',
      'Lead Status',
      'Notes'
    ];

    const rows = leads.map(lead => [
      escapeCsvField(lead.companyName || lead.domain),
      escapeCsvField(lead.domain),
      escapeCsvField(lead.url),
      escapeCsvField(lead.timestamp),
      escapeCsvField(lead.pitchSubject || ''),
      escapeCsvField(lead.pitchBody || ''),
      escapeCsvField(lead.score),
      escapeCsvField(lead.severity),
      escapeCsvField(lead.primaryFinding),
      escapeCsvField(lead.evidenceSummary),
      escapeCsvField(lead.lcpDisplay),
      escapeCsvField(lead.inpDisplay),
      escapeCsvField(lead.clsDisplay),
      escapeCsvField(lead.ttfbDisplay),
      escapeCsvField(lead.domElements),
      escapeCsvField(lead.techStack),
      escapeCsvField(lead.status),
      escapeCsvField(lead.notes)
    ]);

    return [
      headers.map(escapeCsvField).join(','),
      ...rows.map(row => row.join(','))
    ].join('\r\n');
  }

  // --- Agency White-Label Settings ---

  public static async getAgencySettings(): Promise<AgencySettings> {
    await this.initialize();
    const res = await this.get(['agency_settings', 'vitalssniper_settings']);
    const raw = res.agency_settings || res.vitalssniper_settings || {};
    return {
      agencyName: raw.agencyName || raw.brandName || '',
      logoUrl: raw.logoUrl || '',
      auditorName: raw.auditorName || '',
      bookingUrl: raw.bookingUrl || raw.calendlyUrl || '',
      psiApiKey: raw.psiApiKey || ''
    };
  }

  public static async saveAgencySettings(settings: AgencySettings): Promise<void> {
    await this.set({ agency_settings: settings });
  }

  // --- WebAudits.pro SSO & 30-Day Vault Sync Settings ---

  public static async getWebAuditsSyncConfig(): Promise<{ apiKey: string; email: string; tier: string }> {
    const res = await this.get(['vs_webaudits_api_key', 'vs_webaudits_email', 'vs_webaudits_tier', 'vs_license_key']);
    let apiKey = res.vs_webaudits_api_key || '';
    if (!apiKey && res.vs_license_key && res.vs_license_key.startsWith('wba_live_')) {
      apiKey = res.vs_license_key;
    }
    return {
      apiKey: apiKey.trim(),
      email: res.vs_webaudits_email || '',
      tier: res.vs_webaudits_tier || '',
    };
  }

  public static async saveWebAuditsApiKey(apiKey: string): Promise<void> {
    await this.set({ vs_webaudits_api_key: apiKey.trim() });
  }

  // --- PDF Export Tracking ---
  // Free tier has a 3-export limit. Ultra/Enterprise tiers have unlimited exports.

  public static async getPdfExportCount(): Promise<number> {
    const res = await this.get(['vs_pdf_exports', 'vs_lifetime_pdf_exports']);
    if (typeof res.vs_pdf_exports === 'number') return res.vs_pdf_exports;
    return typeof res.vs_lifetime_pdf_exports === 'number' ? res.vs_lifetime_pdf_exports : 0;
  }

  public static async incrementPdfExportCount(): Promise<number> {
    const current = await this.getPdfExportCount();
    const next = current + 1;
    await this.set({ vs_pdf_exports: next, vs_lifetime_pdf_exports: next });
    return next;
  }

  // --- Subscription Timeframe Persistence ---

  public static async getSubscriptionTimeframe(): Promise<StoredSubscriptionTimeframe | null> {
    const res = await this.get(['vs_subscription']);
    return (res.vs_subscription as StoredSubscriptionTimeframe) || null;
  }

  public static async saveSubscriptionTimeframe(sub: StoredSubscriptionTimeframe): Promise<void> {
    if (!sub) return;
    await this.set({ vs_subscription: sub });
  }
}


