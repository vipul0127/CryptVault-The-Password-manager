chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'autofill') {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (tabs.length === 0) {
                console.error('No active tab found');
                sendResponse({ error: 'No active tab' });
                return;
            }
            chrome.scripting.executeScript({
                target: { tabId: tabs[0].id },
                files: ['content.js']
            }, () => {
                chrome.tabs.sendMessage(tabs[0].id, message, (response) => {
                    if (chrome.runtime.lastError) {
                        console.error('Autofill message error:', chrome.runtime.lastError);
                        sendResponse({ error: chrome.runtime.lastError.message });
                    } else {
                        sendResponse({ status: 'Autofill sent', response: response });
                    }
                });
            });
        });
    }
    return true;
});