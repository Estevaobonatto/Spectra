# -*- coding: utf-8 -*-
"""
Utility functions and helpers for Spectra
"""

from .network import (
    is_valid_ip, is_valid_domain, resolve_hostname, normalize_url,
    extract_domain, extract_scheme, extract_port, ping_host, test_port_open,
    get_local_ip, is_private_ip, expand_cidr, validate_port_range, create_session
)

from .parsers import (
    parse_ports, get_common_ports, get_top_ports, 
    get_service_ports, categorize_ports
)

from .validators import (
    validate_url, validate_domain, validate_ip, validate_port,
    validate_email, validate_file_path, validate_wordlist,
    validate_timeout, validate_workers, sanitize_filename,
    sanitize_input, validate_range
)

__all__ = [
    # Network utils
    'is_valid_ip', 'is_valid_domain', 'resolve_hostname', 'normalize_url',
    'extract_domain', 'extract_scheme', 'extract_port', 'ping_host', 
    'test_port_open', 'get_local_ip', 'is_private_ip', 'expand_cidr', 
    'validate_port_range', 'create_session',
    
    # Parsers
    'parse_ports', 'get_common_ports', 'get_top_ports', 
    'get_service_ports', 'categorize_ports',
    
    # Validators
    'validate_url', 'validate_domain', 'validate_ip', 'validate_port',
    'validate_email', 'validate_file_path', 'validate_wordlist',
    'validate_timeout', 'validate_workers', 'sanitize_filename',
    'sanitize_input', 'validate_range'
]
