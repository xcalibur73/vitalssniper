// Cloud Sync Service: WebAudits.pro 30-Day Vault Ingestion
// Zero em-dash compliance: strictly hyphens or colons

import { StorageService } from './storageService';

export interface CloudSyncResult {
  attempted: boolean;
  success: boolean;
  saved: boolean;
  message: string;
  auditId?: string;
}

export class CloudSyncService {
  private static PRIMARY_ENDPOINT = 'https://webaudits.pro/api/extension/sync';
  private static FALLBACK_ENDPOINT = 'https://vitalssniper-web.vercel.app/api/extension/sync';

  /**
   * Synchronizes an extension audit directly to the user's WebAudits.pro 30-day vault.
   * Silently executes in the background without interrupting or blocking the user experience.
   */
  public static async syncAudit(auditState: {
    url: string;
    domain: string;
    score: number;
    flawTitle?: string;
    flawEvidence?: string;
    flawBadge?: string;
    flawSeverity?: string;
    improvements?: string[];
    cmsText?: string;
    data?: any;
    scorecard?: any;
  }): Promise<CloudSyncResult> {
    try {
      if (!auditState || !auditState.url) {
        return { attempted: false, success: false, saved: false, message: 'No active URL to sync.' };
      }

      // 1. Retrieve configured WebAudits API key
      const config = await StorageService.getWebAuditsSyncConfig();
      if (!config.apiKey) {
        return {
          attempted: false,
          success: false,
          saved: false,
          message: 'No WebAudits.pro API key configured.'
        };
      }

      const apiKey = config.apiKey.trim();

      // 2. Prepare standardized payload
      const payload = {
        url: auditState.url,
        domain: auditState.domain,
        score: auditState.score,
        metrics: {
          tool: 'vitalssniper-extension',
          origin: 'chrome-extension',
          detectedCms: auditState.cmsText || 'Custom Stack',
          domElements: auditState.data?.dom?.totalElements || null,
          docKb: auditState.data?.payload?.documentSizeKb || null,
          primaryFlaw: auditState.flawTitle || 'Diagnostic scan completed',
          evidence: auditState.flawEvidence || '',
          scorecardGrade: auditState.scorecard?.grade || (auditState.score >= 80 ? 'A' : auditState.score >= 50 ? 'C' : 'F'),
          rawMetrics: {
            dom: auditState.data?.dom || null,
            performance: auditState.data?.performance || null,
            security: auditState.data?.security || null,
          }
        }
      };

      // 3. Dispatch to WebAudits.pro endpoint
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 6000);

      let resp: Response | null = null;
      try {
        resp = await fetch(this.PRIMARY_ENDPOINT, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'x-api-key': apiKey
          },
          body: JSON.stringify(payload),
          signal: controller.signal
        });
      } catch (primaryErr) {
        // Try fallback endpoint
        try {
          resp = await fetch(this.FALLBACK_ENDPOINT, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Accept': 'application/json',
              'x-api-key': apiKey
            },
            body: JSON.stringify(payload),
            signal: controller.signal
          });
        } catch {
          clearTimeout(timeoutId);
          return {
            attempted: true,
            success: false,
            saved: false,
            message: 'Network unreachable for cloud vault sync.'
          };
        }
      }
      clearTimeout(timeoutId);

      if (!resp || !resp.ok) {
        return {
          attempted: true,
          success: false,
          saved: false,
          message: `Vault sync rejected (HTTP ${resp ? resp.status : 'ERR'}).`
        };
      }

      const resData = await resp.json().catch(() => ({}));
      if (resData.subscription) {
        await StorageService.saveSubscriptionTimeframe(resData.subscription);
      }
      return {
        attempted: true,
        success: Boolean(resData.success),
        saved: Boolean(resData.saved),
        message: resData.message || 'Audit synced to WebAudits vault.',
        auditId: resData.audit_id
      };
    } catch (err: any) {
      return {
        attempted: true,
        success: false,
        saved: false,
        message: err.message || 'Unknown vault sync error.'
      };
    }
  }
}
