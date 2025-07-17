# -*- coding: utf-8 -*-
"""
Spectra Security Modules
"""

# Import dos módulos principais
from . import port_scanner
from . import banner_grabber
from . import directory_scanner
from . import metadata_extractor
from . import subdomain_scanner
from . import dns_analyzer
from . import whois_analyzer
from . import cve_integrator
from . import idor_scanner
from . import basic_vulnerability_scanner

# Funções principais para facilitar o uso
from .port_scanner import scan_ports, AdvancedPortScanner
from .banner_grabber import BannerGrabber
from .directory_scanner import AdvancedDirectoryScanner, advanced_directory_scan
from .metadata_extractor import MetadataExtractor, extract_metadata
from .subdomain_scanner import SubdomainScanner, discover_subdomains
from .dns_analyzer import DNSAnalyzer, query_dns
from .whois_analyzer import WhoisAnalyzer, get_whois_info
from .idor_scanner import AdvancedIDORScanner, idor_scan
from .basic_vulnerability_scanner import BasicVulnerabilityScanner, scan_basic_vulnerabilities

__all__ = [
    'port_scanner', 'banner_grabber', 'directory_scanner', 'metadata_extractor', 
    'subdomain_scanner', 'dns_analyzer', 'whois_analyzer', 'idor_scanner', 'basic_vulnerability_scanner',
    'scan_ports', 'AdvancedPortScanner', 'BannerGrabber', 'AdvancedDirectoryScanner', 
    'advanced_directory_scan', 'MetadataExtractor', 'extract_metadata', 
    'SubdomainScanner', 'discover_subdomains', 'DNSAnalyzer', 'query_dns',
    'WhoisAnalyzer', 'get_whois_info', 'AdvancedIDORScanner', 'idor_scan',
    'BasicVulnerabilityScanner', 'scan_basic_vulnerabilities'
]
