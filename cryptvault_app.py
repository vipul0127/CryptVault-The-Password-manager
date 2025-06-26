import os
import sys
import threading
import signal
import django
from django.core.wsgi import get_wsgi_application
from django.core.management import call_command
from django.contrib.auth import logout
from django.http import HttpResponseRedirect
from waitress import serve
from PyQt5.QtWidgets import QApplication, QMainWindow
from PyQt5.QtWebEngineWidgets import QWebEngineView
from PyQt5.QtCore import QUrl
from PyQt5.QtGui import QIcon
# Set the Django settings module explicitly
os.environ['DJANGO_SETTINGS_MODULE'] = 'cryptvault.settings'
# Initialize Django
django.setup()
# Get the WSGI application
application = get_wsgi_application()
# Function to start the Django server
def start_server():
    serve(application, host='127.0.0.1', port=8000)
# Function to initialize the database (with delayed imports)
def initialize_database():
    from django.contrib.auth.models import User
    from django.contrib.auth.hashers import make_password
    from django.db import connection
    try:
        # Apply migrations
        call_command('migrate', interactive=False)
        # Check if a user exists; create a default user if not
        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM auth_user")
            if cursor.fetchone()[0] == 0:
                User.objects.create_user(
                    username='defaultuser',
                    password=make_password('defaultpass'),
                    email='default@example.com'
                )
                print("Default user created. Username: defaultuser, Password: defaultpass")
    except Exception as e:
        print(f"Database initialization failed: {e}")
# Define the CryptVaultWindow class
class CryptVaultWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('CryptVault Password Manager')
        self.setGeometry(100, 100, 1200, 800)
        self.browser = QWebEngineView()
        self.browser.setUrl(QUrl('http://localhost:8000/login/'))  # Default to login page
        self.setCentralWidget(self.browser)
    def closeEvent(self, event):
        event.accept()  # Let the aboutToQuit signal handle the shutdown
if __name__ == '__main__':
    # Initialize database in the main thread before starting the server
    initialize_database()
    # Start the server in a separate thread
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()
    # Create and run the PyQt5 application
    app = QApplication(sys.argv)
    # Set icon with path resolution for PyInstaller
    if hasattr(sys, '_MEIPASS'):
        icon_path = os.path.join(sys._MEIPASS, 'static', 'admin_icon.ico')
    else:
        icon_path = os.path.join('static', 'admin_icon.ico')
    app.setWindowIcon(QIcon(icon_path))
    window = CryptVaultWindow()
    window.show()
    # Handle application exit gracefully and invalidate session
    def shutdown():
        from django.contrib.auth import get_user
        from django.http import HttpRequest
        try:
            # Create a mock request to access the current user
            request = HttpRequest()
            request.session = {}
            user = get_user(request)
            if user.is_authenticated:
                logout(request)  # Invalidate the session
                print("Session invalidated on close")
        except Exception as e:
            print(f"Error during logout: {e}")
        server_thread.join(timeout=2)
        if server_thread.is_alive():
            os.kill(os.getpid(), signal.SIGTERM)
        sys.exit(0)
    app.aboutToQuit.connect(shutdown)
    sys.exit(app.exec_())