// Lost Revenue and Financial ROI Engine
// Reverse-engineered MyWebAudit and Google/Deloitte conversion decay curve
// Thresholds: LCP > 2.5s, INP > 200ms, CLS > 0.10
// Latency conversion decay rate: 1.11% drop per 100ms excess latency
// Zero em-dash compliance: strictly hyphens or colons

import { RevenueLossAnalysis } from '../types/audit';

export function calculateLostRevenue(
  lcpSec: number,
  inpMs: number,
  cls: number,
  isEcommerce: boolean,
  monthlyVisitors?: number,
  aovOrLeadValue?: number
): RevenueLossAnalysis {
  const excessLcpMs = Math.max(0, Math.round((lcpSec - 2.5) * 1000));
  const excessInpMs = Math.max(0, Math.round(inpMs - 200));
  const excessClsPenaltyMs = Math.max(0, Math.round((cls - 0.10) * 1000));

  const totalExcessMs = excessLcpMs + excessInpMs + excessClsPenaltyMs;
  const totalExcessSeconds = parseFloat((totalExcessMs / 1000).toFixed(2));

  if (totalExcessMs <= 0) {
    return {
      isOptimal: true,
      modelType: isEcommerce ? 'ecommerce' : 'leadgen',
      totalExcessSeconds: 0,
      conversionDropPct: 0,
      lostMonthly: 0,
      lostAnnual: 0,
      roiHeadline: 'Core Web Vitals are within optimal thresholds with 0 estimated latency revenue leakage.'
    };
  }

  // Conversion decay rate: 1.11% drop per 100ms of excess latency, capped at 50%
  const calculatedDrop = (totalExcessMs / 100) * 1.11;
  const conversionDropPct = parseFloat(Math.min(50, calculatedDrop).toFixed(2));

  let visitors = monthlyVisitors && monthlyVisitors > 0 ? monthlyVisitors : 0;
  let unitValue = aovOrLeadValue && aovOrLeadValue > 0 ? aovOrLeadValue : 0;
  let baselineConversionRate = 0.02;
  const modelType = isEcommerce ? 'ecommerce' : 'leadgen';

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
  const roiHeadline = `Resolving ${totalExcessMs}ms latency penalty recovers an estimated $${lostMonthly.toLocaleString()}/mo in lost ${conversionTerm}.`;

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
