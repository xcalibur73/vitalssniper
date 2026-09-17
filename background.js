// VitalsSniper PRO: Background Service Worker (Manifest V3)
// Handles ExtensionPay subscription management & Stripe checkout tabs
importScripts('ExtPay.js');
const extpay = ExtPay('vitalssniper');
extpay.startBackground();
