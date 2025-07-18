# -*- coding: utf-8 -*-
"""
Help System for Spectra - Standardized documentation and help generation
"""

from .help_manager import HelpManager, get_help_manager
from .module_registry import ModuleRegistry, get_registry, register_module
from .help_formatter import HelpFormatter, OutputFormat
from .module_discovery import ModuleDiscovery, get_module_discovery, auto_discover_modules, initialize_help_system

# Keep backward compatibility with existing CLI integration if it exists
try:
    from .cli_integration import HelpCLIHandler, integrate_help_with_cli, handle_cli_help
    _has_old_cli = True
except ImportError:
    _has_old_cli = False

__all__ = [
    'HelpManager', 'get_help_manager',
    'ModuleRegistry', 'get_registry', 'register_module', 
    'HelpFormatter', 'OutputFormat',
    'ModuleDiscovery', 'get_module_discovery', 'auto_discover_modules', 'initialize_help_system'
]

if _has_old_cli:
    __all__.extend(['HelpCLIHandler', 'integrate_help_with_cli', 'handle_cli_help'])