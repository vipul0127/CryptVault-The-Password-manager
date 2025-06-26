// popup.js
document.addEventListener('DOMContentLoaded', () => {
    // Clear current_url to force a fresh URL fetch
    chrome.storage.local.remove('current_url', () => {
        checkAppStatus()
            .then(() => {
                chrome.storage.local.get(['username', 'token'], (data) => {
                    // Clear session storage to force re-authentication
                    chrome.storage.session.clear();
                    
                    // If no token or token is invalid, show login UI
                    if (!data.token) {
                        const usernameInput = document.getElementById('username');
                        if (data.username && usernameInput) {
                            usernameInput.value = data.username;
                        }
                        document.getElementById('loginButton').addEventListener('click', authenticate);
                        return;
                    }

                    // Validate token with backend
                    fetch('http://127.0.0.1:8000/api/validate_token/', {
                        method: 'GET',
                        headers: { 'Authorization': `Token ${data.token}` }
                    })
                    .then(response => {
                        if (!response.ok) {
                            throw new Error('Invalid token');
                        }
                        return response.json();
                    })
                    .then(() => {
                        // Token is valid, load search UI
                        loadSearchUI();
                    })
                    .catch(() => {
                        // Token is invalid, clear storage and show login UI
                        chrome.storage.local.remove(['token', 'username']);
                        document.getElementById('loginButton').addEventListener('click', authenticate);
                    });
                });
            })
            .catch(() => {
                showAppNotRunning();
            });
    });
});

function checkAppStatus() {
    return new Promise((resolve, reject) => {
        fetch('http://127.0.0.1:8000/api/health/', {
            method: 'GET',
            timeout: 2000 // 2 seconds timeout
        })
        .then(response => {
            if (response.ok) {
                resolve();
            } else {
                reject();
            }
        })
        .catch(() => {
            reject();
        });
    });
}

function showAppNotRunning() {
    const contentDiv = document.getElementById('content');
    const loginForm = document.querySelector('.glass-card');
    
    if (loginForm) {
        loginForm.style.display = 'none';
    }
    
    contentDiv.innerHTML = `
        <div class="glass-card" style="text-align: center;">
            <svg width="48" height="48" fill="none" stroke="#fca5a5" viewBox="0 0 24 24" style="margin-bottom: 16px;">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
            </svg>
            <h3 style="color: #fca5a5; margin-bottom: 8px;">CryptVault App Not Detected</h3>
            <p style="color: rgba(255, 255, 255, 0.8); margin-bottom: 16px;">
                Please make sure the CryptVault desktop application is running on your computer.
            </p>
            <p style="color: rgba(255, 255, 255, 0.6); font-size: 14px;">
                The extension requires the desktop app to be installed and running to function properly.
            </p>
        </div>
    `;
}
function authenticate() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('master_password').value;
    const errorDiv = document.getElementById('error');
    const loginButton = document.getElementById('loginButton');
    const btnText = loginButton.querySelector('.btn-text');
    const spinner = loginButton.querySelector('.loading-spinner');

    // Clear previous errors
    errorDiv.textContent = '';
    errorDiv.classList.remove('show');

    if (!username || !password) {
        errorDiv.textContent = 'Username and password are required';
        errorDiv.classList.add('show');
        return;
    }

    // Show loading state
    btnText.textContent = 'Authenticating...';
    spinner.style.display = 'block';
    loginButton.disabled = true;

    fetch('http://127.0.0.1:8000/api/login/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            // Include CSRF token if required (e.g., for Django)
            // 'X-CSRFToken': getCsrfToken(), // Uncomment and implement if needed
        },
        credentials: 'include', // Include cookies if CSRF or session-based auth is used
        body: JSON.stringify({ username, master_password: password })
    })
    .then(response => {
        if (!response.ok) {
            // Try to parse JSON error response
            return response.json().then(errData => {
                // Extract specific error message from server
                let errorMessage = errData.error || errData.detail || 'Authentication failed';
                if (response.status === 403) {
                    errorMessage = errData.error || 'Invalid username or password';
                }
                throw new Error(errorMessage);
            }).catch(() => {
                // Fallback if response isn't JSON
                throw new Error(response.status === 403 ? 'Invalid username or password' : `HTTP ${response.status}: ${response.statusText}`);
            });
        }
        return response.json();
    })
    .then(data => {
        if (data.token) {
            chrome.storage.local.set({ token: data.token, username }, () => {
                chrome.storage.session.set({ master_password: password }, () => {
                    loadSearchUI();
                });
            });
        } else {
            throw new Error(data.error || 'Authentication failed');
        }
    })
    .catch(err => {
        errorDiv.textContent = err.message || 'An error occurred during authentication';
        errorDiv.classList.add('show');
        console.error('Authentication error:', err);
    })
    .finally(() => {
        // Reset button state
        btnText.textContent = 'Sign In Securely';
        spinner.style.display = 'none';
        loginButton.disabled = false;
    });
}
// popup.js
function loadSearchUI() {
    const contentDiv = document.getElementById('content');
    const loginForm = document.querySelector('.glass-card');
    
    if (loginForm) {
        loginForm.style.display = 'none';
    }
    
  fetch(chrome.runtime.getURL('search.html'))
    .then(response => response.text())
    .then(html => {
        contentDiv.innerHTML = html;
        const script = document.createElement('script');
        script.src = chrome.runtime.getURL('search.js');
        script.onload = () => {
            // Ensure search button listener is attached after script loads
            const searchButton = document.getElementById('searchButton');
            if (searchButton) {
                searchButton.addEventListener('click', search);
            }
        };
        document.body.appendChild(script);
            
            document.getElementById('error').textContent = '';
            chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
                if (tabs.length > 0) {
                    const newUrl = tabs[0].url;
                    chrome.storage.local.set({ current_url: newUrl }, () => {
                        const urlInput = document.getElementById('url');
                        if (urlInput) {
                            urlInput.value = newUrl;
                            search(); // Trigger search with new URL
                        }
                    });
                }
            });
        })
        .catch(err => {
            document.getElementById('error').textContent = 'Failed to load search: ' + err.message;
            console.error(err);
        });
}