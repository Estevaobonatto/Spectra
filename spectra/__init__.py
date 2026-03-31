# -*- coding: utf-8 -*-
"""
Spectra - Web Security Suite
Uma ferramenta de hacking ético para análise de segurança web.

Version: 2.0.1
Author: Spectra Team
"""

__version__ = "2.0.1"
__author__ = "Spectra Team"
__description__ = "Uma ferramenta de hacking ético para análise de segurança web"

# Imports principais para facilitar o uso
from .core.console import console
from .core.config import Config
from .core.banner import display_banner

# Importa os módulos principais
from .modules import (
    port_scanner,
    banner_grabber,
    directory_scanner,
    dns_analyzer,
    subdomain_scanner,
    metadata_extractor,
    whois_analyzer
    # Módulos ainda não migrados:
    # vulnerability_scanner,
    # bruteforce_scanner,
    # http_analyzer,
    # ssl_analyzer,
    # technology_detector,
    # waf_detector
)

__all__ = [
    '__version__',
    '__author__',
    '__description__',
    'console',
    'Config',
    'display_banner',
    'port_scanner',
    'directory_scanner',
    'dns_analyzer',
    'subdomain_scanner',
    'metadata_extractor',
    'banner_grabber',
    'whois_analyzer'
    # Módulos ainda não migrados:
    # 'vulnerability_scanner',
    # 'bruteforce_scanner',
    # 'http_analyzer',
    # 'ssl_analyzer',
    # 'technology_detector',
    # 'waf_detector'
]
