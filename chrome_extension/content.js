chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'autofill') {
        try {
            const usernameFields = document.querySelectorAll('input[type="text"], input[type="email"], input[name*="username"], input[name*="email"], input[id*="username"], input[id*="email"]');
            const passwordFields = document.querySelectorAll('input[type="password"], input[name*="password"], input[id*="password"]');

            if (usernameFields.length > 0 && message.username) {
                usernameFields.forEach(field => {
                    field.value = message.username;
                    field.dispatchEvent(new Event('input', { bubbles: true }));
                    field.dispatchEvent(new Event('change', { bubbles: true }));
                });
            }

            if (passwordFields.length > 0 && message.password) {
                passwordFields.forEach(field => {
                    field.value = message.password;
                    field.dispatchEvent(new Event('input', { bubbles: true }));
                    field.dispatchEvent(new Event('change', { bubbles: true }));
                });
            }

            sendResponse({ status: 'Autofill completed' });
        } catch (err) {
            console.error('Autofill error:', err);
            sendResponse({ status: 'Autofill failed', error: err.message });
        }
    }
    return true;
});