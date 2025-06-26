CryptVault — A Smart Step for Data Privacy in Today’s Digital World
Home Page
🏠 Home Page

After logging in with the master password, users are redirected to the Home Page.
The Home Page provides access to credential management, including viewing, adding, and editing saved credentials.


🔐 User Login

Users log in using a unique master password to access CryptVault.


📝 Registration

New users can set up CryptVault by creating a master password during initial setup.


➕ Add Credential Page

Users can add new credentials (website, username, password) securely on the Add Credential Page.


Extension Section
🌐 CryptVault Extension Overview

The CryptVault Extension is a browser add-on designed to enhance security and convenience by auto-filling saved credentials on login pages. It communicates exclusively with the local CryptVault application via localhost (e.g., http://127.0.0.1:8000), ensuring no data is transmitted over the internet. This offline-first approach minimizes exposure to external threats, making it a robust solution for privacy-conscious users.

🔑 Extension Login Page

Upon installation, the extension prompts users to log in with their master password to authenticate with the local CryptVault app.
Details: This page ensures secure initialization by validating the master password against the locally stored encrypted database. Only after successful authentication can the extension access and manage credentials.

📋 Credential Auto-Fill Page

When a user visits a login page (e.g., a website), the extension detects the URL and offers to auto-fill the username and password fields with saved credentials.
Details: The auto-fill feature leverages the Chrome Extension API to match the current webpage URL with stored entries. It fetches encrypted data from the local server, decrypts it in real-time using the master password, and populates the fields securely. Users can select from multiple saved credentials if available for the site.

⚙️ Extension Settings Page

The settings page allows users to configure auto-fill preferences, manage connected sites, and update the extension’s sync with the CryptVault app.
Details: This page provides options to enable/disable auto-fill, clear cached data, or re-authenticate with the local app. It ensures users retain control over how and when credentials are accessed, enhancing usability and security.


Features

Offline Operation: Runs locally, eliminating cloud vulnerabilities.
AES-256 Encryption: Secures all credentials with strong encryption.
Credential Management: Add, edit, or delete website credentials.
Auto-Fill Extension: Browser extension for seamless login experiences.
Portable: Single .exe file for easy installation via PyInstaller.

Requirements

Python 3.x
Django 3.x or later
PyQt5 for desktop UI
PyInstaller for packaging
Chrome Extension API support

Installation and Setup
Step 1: Clone the Repository
Clone the repository to your local machine:
git clone https://github.com/vipul0127/CryptVault.git
cd CryptVault

Step 2: Install Dependencies
Create a virtual environment and install required packages:
python3 -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
pip install -r requirements.txt

Step 3: Build the Executable
Package the application into a single .exe file:
pyinstaller --onefile cryptvault.py

Step 4: Install the Extension

Load the extension folder into your browser as an unpacked extension.

Step 5: Run the Application

Launch the generated .exe file to start CryptVault.

Usage

Log in with your master password.
Manage credentials via the desktop UI.
Use the extension for auto-filling on supported websites.

Tech Stack

Backend: Django
UI: PyQt5
Encryption: AES-256
Packaging: PyInstaller
Extension: Chrome Extension API
Local Communication: Localhost

Contributing
Fork the repository, submit issues, or create pull requests. Contributions are appreciated!
Future Improvements

Support for additional browsers.
Enhanced UI with dark mode.
Backup and restore functionality.

License
MIT License
Contact

GitHub: @Vipul0127
LinkedIn: @Vipul-iiitd
Website: Portfolio.Vipul-iiitd.in


Note: Replace placeholder image paths with actual screenshot files in the designated sections.
