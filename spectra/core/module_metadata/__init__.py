# -*- coding: utf-8 -*-
"""
Module Metadata System - Structured metadata for Spectra modules
"""

from .base_metadata import (
    ModuleMetadata,
    Parameter,
    Example,
    UseCase,
    ModuleCategory,
    OutputFormat,
    ParameterType
)
from .validators import MetadataValidator, ValidationResult, ValidationReport

__all__ = [
    'ModuleMetadata',
    'Parameter',
    'Example', 
    'UseCase',
    'ModuleCategory',
    'OutputFormat',
    'ParameterType',
    'MetadataValidator',
    'ValidationResult',
    'ValidationReport'
]