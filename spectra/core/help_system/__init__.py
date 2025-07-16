# -*- coding: utf-8 -*-
"""
Help System for Spectra - Standardized documentation and help generation
"""

from .help_manager import HelpManager
from .module_registry import ModuleRegistry
from .help_formatter import HelpFormatter
from .example_generator import ExampleGenerator

__all__ = [
    'HelpManager',
    'ModuleRegistry', 
    'HelpFormatter',
    'ExampleGenerator'
]