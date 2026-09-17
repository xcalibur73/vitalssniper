// License & Entitlement Types and Interfaces
// Zero em-dash compliance: strictly hyphens or colons

export type LicenseTier = 'free' | 'pro' | 'agency';

export type LicenseSource = 'appsumo' | 'payment' | 'license' | 'demo';

export interface SignedEntitlementPayload {
  sub: string;
  tier: LicenseTier;
  iat: number;
  exp: number | null;
  iss: string;
  aud: string;
  jti: string;
}

export interface EntitlementState {
  isPro: boolean;
  tier: LicenseTier;
  valid: boolean;
  expiresAt: string | null;
  source: LicenseSource;
  keyPrefix: string | null;
  token: string | null;
  payload?: SignedEntitlementPayload;
  signature?: string;
}

export interface VerifyResult {
  valid: boolean;
  tier?: LicenseTier;
  message?: string;
  expiresAt?: string;
  token?: string;
  payload?: SignedEntitlementPayload;
  signature?: string;
}

export interface FeatureAuthorizationResult {
  authorized: boolean;
  feature: string;
  reason?: string;
  executionScope: 'local' | 'cloud-api';
}

