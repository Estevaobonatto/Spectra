# -*- coding: utf-8 -*-
"""
Help System for Spectra - Standardized documentation and help generation
"""

from .help_manager import HelpManager, get_help_manager
from .module_registry import ModuleRegistry, get_registry, register_module
from .help_formatter import HelpFormatter, OutputFormat
from .cli_integration import HelpCLIHandler, integrate_help_with_cli, handle_cli_help

__all__ = [
    'HelpManager', 'get_help_manager',
    'ModuleRegistry', 'get_registry', 'register_module', 
    'HelpFormatter', 'OutputFormat',
    'HelpCLIHandler', 'integrate_help_with_cli', 'handle_cli_help'
]