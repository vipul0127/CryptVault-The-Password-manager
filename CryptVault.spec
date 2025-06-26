# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['cryptvault_app.py'],
    pathex=[],
    binaries=[('C:\\Users\\dayan\\Downloads\\password_manager\\password_manager\\cryptvault_env\\Lib\\site-packages\\PyQt5\\Qt5\\plugins', 'PyQt5\\Qt5\\plugins')],
    datas=[('C:\\Users\\dayan\\Downloads\\password_manager\\password_manager\\cryptvault\\static', 'static'), ('C:\\Users\\dayan\\Downloads\\password_manager\\password_manager\\cryptvault\\staticfiles', 'staticfiles'), ('C:\\Users\\dayan\\Downloads\\password_manager\\password_manager\\cryptvault\\vault\\templates', 'templates'), ('C:\\Users\\dayan\\Downloads\\password_manager\\password_manager\\cryptvault\\db.sqlite3', '.'), ('C:\\Users\\dayan\\Downloads\\password_manager\\password_manager\\cryptvault_env\\Lib\\site-packages\\PyQt5\\Qt5\\bin', 'PyQt5\\Qt5\\bin')],
    hiddenimports=['rest_framework.permissions', 'rest_framework', 'rest_framework_simplejwt', 'PyQt5', 'PyQt5.QtWebEngineWidgets', 'PyQt5.QtWebEngineCore', 'PyQt5.QtCore', 'PyQt5.QtWidgets', 'PyQt5.QtGui', 'pycryptodomex', 'waitress'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='CryptVault',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['static\\admin_icon.ico'],
)
