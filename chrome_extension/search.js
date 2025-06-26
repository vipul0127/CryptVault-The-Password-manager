// search.js
function search() {
    const urlInput = document.getElementById('url');
    const url = urlInput ? urlInput.value : '';
    const errorDiv = document.getElementById('error');
    const resultsBody = document.querySelector('#results tbody');
    errorDiv.textContent = '';
    resultsBody.innerHTML = '';

    if (!url) {
        errorDiv.textContent = 'Please enter a website URL';
        return;
    }

    // Update current_url in storage to reflect manual input
    chrome.storage.local.set({ current_url: url }, () => {
        chrome.storage.local.get(['token', 'username'], (localData) => {
            if (!localData.token) {
                errorDiv.textContent = 'Please log in first';
                return;
            }

            chrome.storage.session.get(['master_password'], (sessionData) => {
                let masterPassword = sessionData.master_password;
                if (!masterPassword) {
                    errorDiv.textContent = 'Session expired. Please log in again.';
                    return;
                }

                let hostname;
                try {
                    hostname = new URL(url.startsWith('http') ? url : 'http://' + url).hostname.replace('www.', '');
                } catch (e) {
                    errorDiv.textContent = 'Invalid URL';
                    return;
                }

                fetch('http://127.0.0.1:8000/api/password_search/', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Token ${localData.token}`
                    },
                    body: JSON.stringify({
                        q: hostname,
                        master_password: masterPassword
                    })
                })
                .then(response => {
                    if (!response.ok) {
                        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                    }
                    return response.json();
                })
                .then(data => {
                    if (data.error) {
                        errorDiv.textContent = data.error;
                        return;
                    }
                    if (!data.results || data.results.length === 0) {
                        errorDiv.textContent = 'No matching entries found. Add a password entry in CryptVault.';
                        return;
                    }
                    data.results.forEach(entry => {
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td class="service-cell">
                                <div class="service-icon">${entry.service.charAt(0).toUpperCase()}</div>
                                <div class="service-name">${entry.service}</div>
                            </td>
                            <td class="username-cell">${entry.username}</td>
                            <td>
                                <div class="action-buttons">
                                    <button id="autofill-${entry.id}" class="action-btn autofill-btn">
                                        <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4"></path>
                                        </svg>
                                        Autofill
                                    </button>
                                    <button id="show-${entry.id}" class="action-btn show-btn">
                                        <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path>
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path>
                                        </svg>
                                        Show
                                    </button>
                                </div>
                                <div id="creds-${entry.id}" class="credentials">
                                    <div class="credential-item">
                                        <span class="credential-label">Username:</span>
                                        <span id="username-${entry.id}" class="credential-value"></span>
                                        <button class="copy-btn" onclick="copyText('username-${entry.id}')">Copy</button>
                                    </div>
                                    <div class="credential-item">
                                        <span class="credential-label">Password:</span>
                                        <span id="password-${entry.id}" class="credential-value"></span>
                                        <button class="copy-btn" onclick="copyText('password-${entry.id}')">Copy</button>
                                    </div>
                                </div>
                            </td>
                        `;
                        resultsBody.appendChild(row);
                        document.getElementById(`autofill-${entry.id}`).addEventListener('click', () => autofill(entry.id));
                        document.getElementById(`show-${entry.id}`).addEventListener('click', () => showCredentials(entry.id));
                    });
                })
                .catch(err => {
                    errorDiv.textContent = 'Error searching passwords: ' + err.message;
                    console.error('Search error:', err);
                });
            });
        });
    });
}
function autofill(entryId) {
    chrome.storage.local.get(['token'], (localData) => {
        if (!localData.token) {
            alert('Please log in first');
            return;
        }
        chrome.storage.session.get(['master_password'], (sessionData) => {
            let masterPassword = sessionData.master_password;
            if (!masterPassword) {
                alert('Session expired. Please log in again.');
                return;
            }
            fetch(`http://127.0.0.1:8000/api/get_password/${entryId}/?master_password=${encodeURIComponent(masterPassword)}`, {
                method: 'GET',
                headers: { 'Authorization': `Token ${localData.token}` }
            })
            .then(response => {
                console.log('Autofill fetch status:', response.status, response.statusText);
                console.log('Autofill fetch headers:', [...response.headers.entries()]);
                return response.text().then(text => {
                    console.log('Autofill fetch response body:', text.substring(0, 200));
                    if (!response.ok) {
                        throw new Error(`HTTP ${response.status}: ${text.substring(0, 50)}...`);
                    }
                    try {
                        return JSON.parse(text);
                    } catch (e) {
                        throw new Error('Invalid JSON response: ' + text.substring(0, 50) + '...');
                    }
                });
            })
            .then(data => {
                if (data.error) {
                    alert(data.error);
                    return;
                }
                chrome.runtime.sendMessage({
                    action: 'autofill',
                    username: data.username,
                    password: data.password
                }, (response) => {
                    if (chrome.runtime.lastError) {
                        alert('Autofill failed: ' + chrome.runtime.lastError.message);
                    } else if (response && response.error) {
                        alert('Autofill failed: ' + response.error);
                    }
                });
            })
            .catch(err => {
                alert('Error fetching password: ' + err.message);
                console.error('Autofill fetch error:', err);
            });
        });
    });
}

function showCredentials(entryId) {
    const credsDiv = document.getElementById(`creds-${entryId}`);
    const usernameSpan = document.getElementById(`username-${entryId}`);
    const passwordSpan = document.getElementById(`password-${entryId}`);
    if (credsDiv.style.display === 'block') {
        credsDiv.style.display = 'none';
        return;
    }

    chrome.storage.local.get(['token'], (localData) => {
        if (!localData.token) {
            alert('Please log in first');
            return;
        }
        chrome.storage.session.get(['master_password'], (sessionData) => {
            let masterPassword = sessionData.master_password;
            if (!masterPassword) {
                alert('Session expired. Please log in again.');
                return;
            }
            fetch(`http://127.0.0.1:8000/api/get_password/${entryId}/?master_password=${encodeURIComponent(masterPassword)}`, {
                method: 'GET',
                headers: { 'Authorization': `Token ${localData.token}` }
            })
            .then(response => {
                console.log('Show fetch status:', response.status, response.statusText);
                console.log('Show fetch headers:', [...response.headers.entries()]);
                return response.text().then(text => {
                    console.log('Show fetch response body:', text.substring(0, 200));
                    if (!response.ok) {
                        throw new Error(`HTTP ${response.status}: ${text.substring(0, 50)}...`);
                    }
                    try {
                        return JSON.parse(text);
                    } catch (e) {
                        throw new Error('Invalid JSON response: ' + text.substring(0, 50) + '...');
                    }
                });
            })
            .then(data => {
                if (data.error) {
                    alert(data.error);
                    return;
                }
                usernameSpan.textContent = data.username;
                passwordSpan.textContent = data.password;
                credsDiv.style.display = 'block';
            })
            .catch(err => {
                alert('Error fetching credentials: ' + err.message);
                console.error('Fetch error:', err);
            });
        });
    });
}
function copyText(elementId) {
    const text = document.getElementById(elementId).textContent;
    navigator.clipboard.writeText(text)
        .then(() => alert('Copied to clipboard'))
        .catch(err => {
            alert('Failed to copy: ' + err.message);
            console.error('Copy error:', err);
        });
}
// search.js
document.addEventListener('DOMContentLoaded', () => {
    const searchButton = document.getElementById('searchButton');
    if (searchButton) {
        searchButton.addEventListener('click', search);
    }
    chrome.storage.local.get(['current_url'], (data) => {
        const urlInput = document.getElementById('url');
        if (urlInput && data.current_url) {
            urlInput.value = data.current_url;
            search();
        }
    });
});