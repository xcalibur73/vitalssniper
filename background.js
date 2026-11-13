// VitalsSniper: Background Service Worker (Manifest V3)
// Bot Emulation via declarativeNetRequest Session Rules

const BOT_USER_AGENTS = {
  'googlebot-smartphone': 'Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.115 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
  'googlebot-desktop': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
  'bingbot': 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
  'gptbot': 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)'
};

const BOT_RULE_ID = 1001;

const ALL_RESOURCE_TYPES = [
  'main_frame',
  'sub_frame',
  'stylesheet',
  'script',
  'image',
  'font',
  'object',
  'xmlhttprequest',
  'ping',
  'csp_report',
  'media',
  'websocket',
  'other'
];

chrome.runtime.onInstalled.addListener((details) => {
  // Service worker initialization: clear any lingering session rules
  if (typeof chrome !== 'undefined' && chrome.declarativeNetRequest && chrome.declarativeNetRequest.updateSessionRules) {
    chrome.declarativeNetRequest.updateSessionRules({
      removeRuleIds: [BOT_RULE_ID]
    }).catch((err) => console.warn('[VitalsSniper] Background warning:', err));
  }

  // Open onboarding tab strictly on fresh installation
  if (details && details.reason === 'install') {
    if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.create) {
      chrome.tabs.create({
        url: 'https://webaudits.pro/products/vitalssniper-pro?utm_source=cws_install&utm_medium=extension'
      }).catch((err) => console.warn('[VitalsSniper] Background warning:', err));
    }
  }
});

function getStorageSession() {
  if (typeof chrome === 'undefined' || !chrome.storage) {
    return null;
  }
  return chrome.storage.session || chrome.storage.local;
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message !== 'object') {
    return false;
  }

  if (message.action === 'setUserAgent') {
    const userAgent = message.userAgent || 'default';
    const activeTabId = typeof message.tabId === 'number'
      ? message.tabId
      : (sender && sender.tab && typeof sender.tab.id === 'number' ? sender.tab.id : undefined);

    if (userAgent === 'default' || !BOT_USER_AGENTS[userAgent]) {
      const storage = getStorageSession();
      const updateStorage = () => {
        if (storage && storage.set) {
          storage.set({ emulated: 'default', emulatedUserAgent: 'default' }, () => {
            sendResponse({ success: true, emulated: 'default', emulatedUserAgent: 'default' });
          });
        } else {
          sendResponse({ success: true, emulated: 'default', emulatedUserAgent: 'default' });
        }
      };

      if (typeof chrome !== 'undefined' && chrome.declarativeNetRequest && chrome.declarativeNetRequest.updateSessionRules) {
        chrome.declarativeNetRequest.updateSessionRules({
          removeRuleIds: [BOT_RULE_ID]
        }).then(() => {
          updateStorage();
        }).catch((err) => {
          console.error('Failed to reset DNR session rules:', err);
          updateStorage();
        });
        return true;
      } else {
        updateStorage();
        return true;
      }
    } else {
      const targetUa = BOT_USER_AGENTS[userAgent];
      const botRule = {
        id: BOT_RULE_ID,
        priority: 1,
        action: {
          type: 'modifyHeaders',
          requestHeaders: [
            {
              header: 'User-Agent',
              operation: 'set',
              value: targetUa
            }
          ]
        },
        condition: {
          urlFilter: '*',
          resourceTypes: ALL_RESOURCE_TYPES,
          ...(typeof activeTabId === 'number' ? { tabIds: [activeTabId] } : {})
        }
      };

      const storage = getStorageSession();
      const updateStorage = () => {
        if (storage && storage.set) {
          storage.set({ emulated: userAgent, emulatedUserAgent: userAgent }, () => {
            sendResponse({ success: true, emulated: userAgent, emulatedUserAgent: userAgent, targetUa });
          });
        } else {
          sendResponse({ success: true, emulated: userAgent, emulatedUserAgent: userAgent, targetUa });
        }
      };

      if (typeof chrome !== 'undefined' && chrome.declarativeNetRequest && chrome.declarativeNetRequest.updateSessionRules) {
        chrome.declarativeNetRequest.updateSessionRules({
          removeRuleIds: [BOT_RULE_ID],
          addRules: [botRule]
        }).then(() => {
          updateStorage();
        }).catch((err) => {
          console.error('Failed to update DNR session rules:', err);
          updateStorage();
        });
        return true;
      } else {
        updateStorage();
        return true;
      }
    }
  }

  if (message.action === 'getUserAgent') {
    const storage = getStorageSession();
    if (storage && storage.get) {
      storage.get(['emulated', 'emulatedUserAgent'], (result) => {
        const active = (result && (result.emulatedUserAgent || result.emulated)) || 'default';
        sendResponse({ emulatedUserAgent: active, emulated: active, userAgent: active });
      });
      return true;
    } else {
      sendResponse({ emulatedUserAgent: 'default', emulated: 'default', userAgent: 'default' });
      return false;
    }
  }

  return false;
});
