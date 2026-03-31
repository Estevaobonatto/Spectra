# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec para Spectra Security Suite.
Gera um executável single-file standalone (sem Python necessário).

Uso:
    pip install pyinstaller
    pyinstaller spectra.spec

Saída:
    dist/spectra          (Linux/macOS)
    dist/spectra.exe      (Windows)
"""

import sys
from pathlib import Path

block_cipher = None

# ── Dados a empacotar ─────────────────────────────────────────────────────────
# Inclui payloads e wordlists pequenas (<5 MB); exclui rockyou.txt (50+ MB)
datas = []

payloads_dir = Path("spectra/data/payloads")
if payloads_dir.exists():
    datas.append((str(payloads_dir), "spectra/data/payloads"))

wordlists_dir = Path("spectra/data/wordlists")
if wordlists_dir.exists():
    for wl in wordlists_dir.iterdir():
        if wl.is_file() and wl.stat().st_size < 5 * 1024 * 1024:  # < 5 MB
            datas.append((str(wl), "spectra/data/wordlists"))

rainbow_dir = Path("spectra/data/rainbow_tables")
if rainbow_dir.exists():
    for rt in rainbow_dir.iterdir():
        if rt.is_file() and rt.stat().st_size < 10 * 1024 * 1024:  # < 10 MB
            datas.append((str(rt), "spectra/data/rainbow_tables"))

# ── Análise ───────────────────────────────────────────────────────────────────
a = Analysis(
    ["main.py"],
    pathex=["."],
    binaries=[],
    datas=datas,
    hiddenimports=[
        # Módulos Spectra (carregados dinamicamente)
        "spectra.modules.port_scanner",
        "spectra.modules.banner_grabber",
        "spectra.modules.directory_scanner",
        "spectra.modules.dns_analyzer",
        "spectra.modules.subdomain_scanner",
        "spectra.modules.whois_analyzer",
        "spectra.modules.ssl_analyzer",
        "spectra.modules.headers_analyzer",
        "spectra.modules.technology_detector",
        "spectra.modules.waf_detector",
        "spectra.modules.sql_injection_scanner",
        "spectra.modules.xss_scanner",
        "spectra.modules.lfi_scanner",
        "spectra.modules.ssrf_scanner",
        "spectra.modules.xxe_scanner",
        "spectra.modules.command_injection_scanner",
        "spectra.modules.idor_scanner",
        "spectra.modules.cve_integrator",
        "spectra.modules.hash_cracker",
        "spectra.modules.metadata_extractor",
        "spectra.modules.network_monitor",
        "spectra.modules.vulnerability_scanner",
        "spectra.modules.basic_vulnerability_scanner",
        "spectra.modules.advanced_subdomain_scanner",
        "spectra.utils.oast",
        "spectra.utils.rate_limiter",
        # DNS
        "dns.resolver",
        "dns.rdatatype",
        "dns.rdataclass",
        "dns.rdtypes",
        "dns.dnssec",
        "dns.name",
        "dns.query",
        "dns.zone",
        # Crypto
        "cryptography.hazmat.backends.openssl",
        "cryptography.hazmat.primitives.hashes",
        "cryptography.hazmat.primitives.serialization",
        "cryptography.x509",
        "cryptography.x509.oid",
        "OpenSSL",
        "OpenSSL.SSL",
        "OpenSSL.crypto",
        # Pillow
        "PIL._imaging",
        "PIL.Image",
        "PIL.ExifTags",
        "PIL.TiffImagePlugin",
        # lxml / bs4
        "lxml._elementpath",
        "lxml.etree",
        "bs4",
        "bs4.builder._lxml",
        # Rich
        "rich.console",
        "rich.table",
        "rich.panel",
        "rich.live",
        "rich.layout",
        "rich.columns",
        "rich.text",
        "rich.rule",
        "rich.padding",
        "rich.box",
        "rich.progress",
        # Stdlib extras
        "sqlite3",
        "json",
        "csv",
        "xml.etree.ElementTree",
        # Terceiros
        "tqdm",
        "psutil",
        "whois",
        "requests",
        "aiohttp",
        "aiodns",
        "urllib3",
        "certifi",
        "charset_normalizer",
        "idna",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # GUI / notebook — não usados no CLI
        "tkinter",
        "matplotlib",
        "notebook",
        "jupyterlab",
        "IPython",
        # GPU — opcional, não incluído no binário padrão
        "pyopencl",
        "pycuda",
        # Browser automation — opcional
        "selenium",
        # Dev tools
        "pytest",
        "flake8",
        "bandit",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="spectra",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,            # comprime o binário (~30% menor)
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,        # CLI — mantém console
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
