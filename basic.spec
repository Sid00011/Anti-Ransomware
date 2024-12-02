# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['basic.py'],
    pathex=[],
    binaries=[],
    datas=[('classifier/svm_classifier.pkl', 'classifier'), ('classifier/svm_features.pkl', 'classifier'), ('database/file_list.txt', 'database'), ('hashes.txt', '.')],
    hiddenimports=['pygame', 'sklearn', 'joblib', 'numpy', 'psutil', 'pefile', 'prettytable', 'tkinter', 'shutil', 'ctypes', 'subprocess', 'hashlib', 're'],
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
    name='basic',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
