# -*- coding: utf-8 -*-
"""
Module Metadata System for Spectra - Structured module information
"""

from .base_metadata import (
    ModuleMetadata, Parameter, Example, UseCase, ModuleCategory,
    ExampleLevel, ParameterType
)
from .validators import MetadataValidator, ValidationResult, ValidationReport

__all__ = [
    'ModuleMetadata', 'Parameter', 'Example', 'UseCase', 'ModuleCategory',
    'ExampleLevel', 'ParameterType',
    'MetadataValidator', 'ValidationResult', 'ValidationReport'
]