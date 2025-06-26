const API_BASE_URL = 'http://localhost:8000';

document.addEventListener('DOMContentLoaded', () => {
  const usernameInput = document.getElementById('username');
  const passwordInput = document.getElementById('master-password');
  const loginBtn = document.getElementById('login-btn');
  const authError = document.getElementById('auth-error');
  const authSection = document.getElementById('auth-section');
  const searchSection = document.getElementById('search-section');
  const serviceUrlInput = document.getElementById('service-url');
  const searchBtn = document.getElementById('search-btn');
  const resultsDiv = document.getElementById('results');
  const logoutBtn = document.getElementById('logout-btn');

  // Register extension ID on first load
  chrome.runtime.getManifest((manifest) => {
    const extensionId = chrome.runtime.id;
    chrome.storage.local.get(['authToken'], async (result) => {
      if (result.authToken) {
        try {
          await fetch(`${API_BASE_URL}/api/update-extension-id/`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Token ${result.authToken}`
            },
            body: JSON.stringify({ extension_id: extensionId })
          });
        } catch (error) {
          console.error('Failed to register extension ID:', error);
        }
      }
    });
  });

  // Check if token exists in storage
  chrome.storage.local.get(['authToken'], (result) => {
    if (result.authToken) {
      authSection.classList.add('d-none');
      searchSection.classList.remove('d-none');
    }
  });

  // Login handler
  loginBtn.addEventListener('click', async () => {
    const username = usernameInput.value.trim();
    const masterPassword = passwordInput.value.trim();
    if (!username || !masterPassword) {
      authError.textContent = 'Please enter both username and password.';
      authError.classList.remove('d-none');
      return;
    }

    try {
      const response = await fetch(`${API_BASE_URL}/api/login/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, master_password: masterPassword })
      });
      const data = await response.json();
      if (data.error) {
        authError.textContent = data.error;
        authError.classList.remove('d-none');
      } else {
        chrome.storage.local.set({ authToken: data.token, masterPassword }, () => {
          authSection.classList.add('d-none');
          searchSection.classList.remove('d-none');
          authError.classList.add('d-none');
          // Register extension ID after login
          const extensionId = chrome.runtime.id;
          fetch(`${API_BASE_URL}/api/update-extension-id/`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Token ${data.token}`
            },
            body: JSON.stringify({ extension_id: extensionId })
          }).catch(error => console.error('Failed to register extension ID:', error));
        });
      }
    } catch (error) {
      authError.textContent = 'Failed to connect to server.';
      authError.classList.remove('d-none');
    }
  });

  // Search handler
  searchBtn.addEventListener('click', async () => {
    const serviceUrl = serviceUrlInput.value.trim();
    if (!serviceUrl) {
      resultsDiv.innerHTML = '<div class="alert alert-warning">Please enter a service URL.</div>';
      return;
    }

    chrome.storage.local.get(['authToken', 'masterPassword'], async (result) => {
      const token = result.authToken;
      const masterPassword = result.masterPassword;
      try {
        const response = await fetch(`${API_BASE_URL}/api/password-search/`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Token ${token}`
          },
          body: JSON.stringify({ q: serviceUrl, master_password: masterPassword })
        });
        const data = await response.json();
        if (data.error) {
          resultsDiv.innerHTML = `<div class="alert alert-danger">${data.error}</div>`;
        } else {
          resultsDiv.innerHTML = data.results.length
            ? data.results.map(entry => `
                <div class="card mb-2" style="background-color: #2d3748; color: #fff;">
                  <div class="card-body">
                    <h6>${entry.service}</h6>
                    <p>Username: ${entry.username}</p>
                    <button class="btn btn-primary btn-sm autofill-btn" 
                            data-username="${entry.username}" 
                            data-password="${entry.password}">Autofill</button>
                  </div>
                </div>
              `).join('')
            : '<div class="alert alert-info">No credentials found.</div>';

          // Add event listeners for autofill buttons
          document.querySelectorAll('.autofill-btn').forEach(btn => {
            btn.addEventListener('click', () => {
              const username = btn.dataset.username;
              const password = btn.dataset.password;
              chrome.runtime.sendMessage({
                action: 'autofill',
                username,
                password
              });
            });
          });
        }
      } catch (error) {
        resultsDiv.innerHTML = '<div class="alert alert-danger">Failed to fetch credentials.</div>';
      }
    });
  });

  // Logout handler
  logoutBtn.addEventListener('click', () => {
    chrome.storage.local.remove(['authToken', 'masterPassword'], () => {
      authSection.classList.remove('d-none');
      searchSection.classList.add('d-none');
      resultsDiv.innerHTML = '';
      usernameInput.value = '';
      passwordInput.value = '';
    });
  });
});