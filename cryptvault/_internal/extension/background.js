chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'autofill') {
    chrome.scripting.executeScript({
      target: { tabId: sender.tab.id },
      func: (username, password) => {
        const usernameFields = document.querySelectorAll('input[type="text"], input[type="email"]');
        const passwordFields = document.querySelectorAll('input[type="password"]');
        
        if (usernameFields.length) {
          usernameFields[0].value = username;
          usernameFields[0].dispatchEvent(new Event('input', { bubbles: true }));
        }
        if (passwordFields.length) {
          passwordFields[0].value = password;
          passwordFields[0].dispatchEvent(new Event('input', { bubbles: true }));
        }
      },
      args: [request.username, request.password]
    });
  }
});