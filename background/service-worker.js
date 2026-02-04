// Track blocked requests
let blockedCount = 0;

// Basic ad blocking rules (simplified)
const adPatterns = [
  '*://*.doubleclick.net/*',
  '*://*.googlesyndication.com/*',
  '*://*.googleadservices.com/*',
  '*://*.facebook.com/tr/*',
  '*://*.amazon-adsystem.com/*'
];

// Listen for messages from popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'TOGGLE_AD_BLOCK') {
    if (message.enabled) {
      enableAdBlocking();
    } else {
      disableAdBlocking();
    }
  }
  
  if (message.type === 'GET_BLOCKED_COUNT') {
    sendResponse({ count: blockedCount });
  }
  
  return true;
});

// Enable ad blocking using declarativeNetRequest
async function enableAdBlocking() {
  const rules = adPatterns.map((pattern, index) => ({
    id: index + 1,
    priority: 1,
    action: { type: 'block' },
    condition: {
      urlFilter: pattern.replace('*://*.', '||').replace('/*', ''),
      resourceTypes: ['script', 'image', 'xmlhttprequest', 'sub_frame']
    }
  }));

  try {
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: rules.map(r => r.id),
      addRules: rules
    });
    console.log('Ad blocking enabled');
  } catch (error) {
    console.error('Error enabling ad blocking:', error);
  }
}

// Disable ad blocking
async function disableAdBlocking() {
  try {
    const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: existingRules.map(r => r.id)
    });
    console.log('Ad blocking disabled');
  } catch (error) {
    console.error('Error disabling ad blocking:', error);
  }
}

// Initialize - check saved state
chrome.runtime.onInstalled.addListener(async () => {
  const { adBlockEnabled } = await chrome.storage.local.get('adBlockEnabled');
  if (adBlockEnabled) {
    enableAdBlocking();
  }
});