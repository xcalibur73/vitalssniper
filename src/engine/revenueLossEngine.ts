// Lost Revenue and Financial ROI Engine
// Reverse-engineered MyWebAudit and Google/Deloitte conversion decay curve
// Thresholds: LCP > 2.5s, INP > 200ms, CLS > 0.10
// Decoupled latency conversion decay and visual friction penalties
// Zero em-dash compliance: strictly hyphens or colons

import { RevenueLossAnalysis } from '../types/audit';

export function calculateLostRevenue(
  lcpSec: number,
  inpMs: number,
  cls: number,
  isEcommerce: boolean,
  monthlyVisitors?: number,
  aovOrLeadValue?: number,
  hasLeadGenForm: boolean = false
): RevenueLossAnalysis {
  // CLS Math Distortion Fix: Latency excess is calculated strictly from LCP and INP
  const excessLcpMs = Math.max(0, Math.round((lcpSec - 2.5) * 1000));
  const excessInpMs = Math.max(0, Math.round(inpMs - 200));
  const excessLatencyMs = Math.min(3000, excessLcpMs + excessInpMs);
  const totalExcessSeconds = parseFloat((excessLatencyMs / 1000).toFixed(2));

  // Latency conversion drop: 1.11% drop per 100ms excess latency (capped at 35%)
  const latencyDrop = Math.min(35, (excessLatencyMs / 100) * 1.11);

  // Visual friction drop: unitless CLS evaluated via stepped penalty (capped at 20%)
  const visualFrictionDrop = cls > 0.10 ? Math.min(20, Math.round(((cls - 0.10) / 0.05) * 2.5 * 10) / 10) : 0;

  // Total conversion drop capped at 50%
  const conversionDropPct = Math.min(50, Math.round((latencyDrop + visualFrictionDrop) * 100) / 100);

  // Non-Commercial / Editorial Guard
  const modelType: 'ecommerce' | 'leadgen' | 'editorial' = isEcommerce
    ? 'ecommerce'
    : (hasLeadGenForm ? 'leadgen' : 'editorial');

  if (conversionDropPct <= 0) {
    return {
      isOptimal: true,
      modelType,
      totalExcessSeconds: 0,
      conversionDropPct: 0,
      lostMonthly: 0,
      lostAnnual: 0,
      roiHeadline: modelType === 'editorial'
        ? 'Core Web Vitals are within optimal thresholds with 0 audience engagement drag.'
        : 'Core Web Vitals are within optimal thresholds with 0 estimated latency revenue leakage.'
    };
  }

  // Editorial sites do not output phantom order losses
  if (modelType === 'editorial') {
    return {
      isOptimal: false,
      modelType,
      totalExcessSeconds,
      conversionDropPct,
      lostMonthly: 0,
      lostAnnual: 0,
      roiHeadline: `Core Web Vitals friction causes an estimated ${conversionDropPct}% audience engagement drag and bounce inflation across editorial readership.`
    };
  }

  let visitors = monthlyVisitors && monthlyVisitors > 0 ? monthlyVisitors : 0;
  let unitValue = aovOrLeadValue && aovOrLeadValue > 0 ? aovOrLeadValue : 0;
  let baselineConversionRate = 0.02;

  if (isEcommerce) {
    if (!visitors) visitors = 15000;
    if (!unitValue) unitValue = 85;
    baselineConversionRate = 0.02;
  } else {
    if (!visitors) visitors = 5000;
    if (!unitValue) unitValue = 250;
    baselineConversionRate = 0.03;
  }

  const baselineMonthlyConversions = visitors * baselineConversionRate;
  const baselineMonthlyRevenue = baselineMonthlyConversions * unitValue;
  const lostMonthly = Math.round(baselineMonthlyRevenue * (conversionDropPct / 100));
  const lostAnnual = Math.round(lostMonthly * 12);

  const conversionTerm = isEcommerce ? 'orders' : 'conversions';
  const roiHeadline = `Resolving ${excessLatencyMs}ms latency and layout instability recovers an estimated $${lostMonthly.toLocaleString()}/mo in lost ${conversionTerm}.`;

  return {
    isOptimal: false,
    modelType,
    totalExcessSeconds,
    conversionDropPct,
    lostMonthly,
    lostAnnual,
    roiHeadline
  };
}
