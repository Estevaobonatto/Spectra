# -*- coding: utf-8 -*-
"""
Validation system for module metadata
"""

import re
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from .base_metadata import ModuleMetadata, Parameter, Example, ParameterType


@dataclass
class ValidationResult:
    """Result of validating a single module's metadata"""
    module_name: str
    is_valid: bool
    errors: List[str]
    warnings: List[str]
    
    def __post_init__(self):
        if self.errors is None:
            self.errors = []
        if self.warnings is None:
            self.warnings = []


@dataclass
class ValidationReport:
    """Complete validation report for all modules"""
    total_modules: int
    valid_modules: int
    invalid_modules: int
    results: List[ValidationResult]
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate as percentage"""
        if self.total_modules == 0:
            return 0.0
        return (self.valid_modules / self.total_modules) * 100
    
    def get_all_errors(self) -> List[str]:
        """Get all errors from all modules"""
        all_errors = []
        for result in self.results:
            for error in result.errors:
                all_errors.append(f"{result.module_name}: {error}")
        return all_errors
    
    def get_all_warnings(self) -> List[str]:
        """Get all warnings from all modules"""
        all_warnings = []
        for result in self.results:
            for warning in result.warnings:
                all_warnings.append(f"{result.module_name}: {warning}")
        return all_warnings


class MetadataValidator:
    """Validates module metadata for consistency and completeness"""
    
    def __init__(self):
        self.naming_patterns = {
            'module_name': re.compile(r'^[a-z][a-z0-9_]*[a-z0-9]$'),
            'parameter_name': re.compile(r'^[a-z][a-z0-9-]*[a-z0-9]$'),
            'short_name': re.compile(r'^[a-z][a-z0-9]*$')
        }
        
        self.required_fields = [
            'name', 'display_name', 'category', 'description', 
            'detailed_description', 'parameters', 'examples'
        ]
        
        self.min_examples_by_level = {
            'basic': 1,
            'intermediate': 1,
            'advanced': 1
        }
    
    def validate_module(self, metadata: ModuleMetadata) -> ValidationResult:
        """Validate a single module's metadata"""
        errors = []
        warnings = []
        
        # Basic field validation
        errors.extend(self._validate_basic_fields(metadata))
        
        # Naming convention validation
        errors.extend(self._validate_naming_conventions(metadata))
        
        # Parameter validation
        param_errors, param_warnings = self._validate_parameters(metadata)
        errors.extend(param_errors)
        warnings.extend(param_warnings)
        
        # Example validation
        example_errors, example_warnings = self._validate_examples(metadata)
        errors.extend(example_errors)
        warnings.extend(example_warnings)
        
        # Content quality validation
        warnings.extend(self._validate_content_quality(metadata))
        
        # Dependency validation
        errors.extend(metadata.validate_parameter_dependencies())
        
        return ValidationResult(
            module_name=metadata.name,
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings
        )
    
    def validate_modules(self, modules: List[ModuleMetadata]) -> ValidationReport:
        """Validate multiple modules and generate report"""
        results = []
        
        for module in modules:
            result = self.validate_module(module)
            results.append(result)
        
        valid_count = sum(1 for r in results if r.is_valid)
        
        return ValidationReport(
            total_modules=len(modules),
            valid_modules=valid_count,
            invalid_modules=len(modules) - valid_count,
            results=results
        )
    
    def _validate_basic_fields(self, metadata: ModuleMetadata) -> List[str]:
        """Validate required fields are present and non-empty"""
        errors = []
        
        if not metadata.name or not metadata.name.strip():
            errors.append("Module name is required and cannot be empty")
        
        if not metadata.display_name or not metadata.display_name.strip():
            errors.append("Display name is required and cannot be empty")
        
        if not metadata.description or not metadata.description.strip():
            errors.append("Description is required and cannot be empty")
        
        if not metadata.detailed_description or not metadata.detailed_description.strip():
            errors.append("Detailed description is required and cannot be empty")
        
        if not metadata.parameters:
            errors.append("At least one parameter must be defined")
        
        if not metadata.examples:
            errors.append("At least one example must be provided")
        
        return errors
    
    def _validate_naming_conventions(self, metadata: ModuleMetadata) -> List[str]:
        """Validate naming conventions"""
        errors = []
        
        # Module name validation
        if not self.naming_patterns['module_name'].match(metadata.name):
            errors.append(f"Module name '{metadata.name}' doesn't follow naming convention (lowercase, underscores only)")
        
        return errors
    
    def _validate_parameters(self, metadata: ModuleMetadata) -> tuple[List[str], List[str]]:
        """Validate parameters"""
        errors = []
        warnings = []
        
        param_names = set()
        short_names = set()
        
        for param in metadata.parameters:
            # Check for duplicate names
            if param.name in param_names:
                errors.append(f"Duplicate parameter name: {param.name}")
            param_names.add(param.name)
            
            if param.short_name:
                if param.short_name in short_names:
                    errors.append(f"Duplicate short parameter name: {param.short_name}")
                short_names.add(param.short_name)
            
            # Validate parameter naming
            if not self.naming_patterns['parameter_name'].match(param.name):
                errors.append(f"Parameter name '{param.name}' doesn't follow naming convention")
            
            if param.short_name and not self.naming_patterns['short_name'].match(param.short_name):
                errors.append(f"Short parameter name '{param.short_name}' doesn't follow naming convention")
            
            # Validate parameter description
            if not param.description or not param.description.strip():
                errors.append(f"Parameter '{param.name}' missing description")
            
            # Validate choices for choice type
            if param.param_type == ParameterType.CHOICE and not param.choices:
                errors.append(f"Parameter '{param.name}' is choice type but has no choices defined")
            
            # Validate default value
            if param.default_value is not None and param.param_type == ParameterType.CHOICE:
                if param.choices and param.default_value not in param.choices:
                    errors.append(f"Parameter '{param.name}' default value not in choices")
            
            # Validate numeric ranges
            if param.param_type in [ParameterType.INTEGER, ParameterType.FLOAT]:
                if param.min_value is not None and param.max_value is not None:
                    if param.min_value >= param.max_value:
                        errors.append(f"Parameter '{param.name}' min_value must be less than max_value")
            
            # Warning for missing examples
            if not param.examples:
                warnings.append(f"Parameter '{param.name}' has no usage examples")
        
        return errors, warnings
    
    def _validate_examples(self, metadata: ModuleMetadata) -> tuple[List[str], List[str]]:
        """Validate examples"""
        errors = []
        warnings = []
        
        if not metadata.examples:
            errors.append("Module must have at least one example")
            return errors, warnings
        
        # Check for examples at different levels
        levels = {ex.level for ex in metadata.examples}
        
        if 'basic' not in levels:
            warnings.append("Module should have at least one basic example")
        
        if len(metadata.examples) >= 3 and 'advanced' not in levels:
            warnings.append("Module with multiple examples should include advanced examples")
        
        # Validate individual examples
        for i, example in enumerate(metadata.examples):
            if not example.title or not example.title.strip():
                errors.append(f"Example {i+1} missing title")
            
            if not example.description or not example.description.strip():
                errors.append(f"Example {i+1} missing description")
            
            if not example.command or not example.command.strip():
                errors.append(f"Example {i+1} missing command")
            
            if example.level not in ['basic', 'intermediate', 'advanced']:
                errors.append(f"Example {i+1} has invalid level: {example.level}")
            
            # Basic command validation
            if example.command and not example.command.startswith('spectra'):
                warnings.append(f"Example {i+1} command should start with 'spectra'")
        
        return errors, warnings
    
    def _validate_content_quality(self, metadata: ModuleMetadata) -> List[str]:
        """Validate content quality (warnings only)"""
        warnings = []
        
        # Description length checks
        if len(metadata.description) < 20:
            warnings.append("Description is quite short, consider adding more detail")
        
        if len(metadata.detailed_description) < 50:
            warnings.append("Detailed description is quite short, consider expanding")
        
        # Check for common typos or issues
        if 'TODO' in metadata.description or 'TODO' in metadata.detailed_description:
            warnings.append("Description contains TODO - should be completed")
        
        # Parameter description quality
        for param in metadata.parameters:
            if param.description and len(param.description) < 10:
                warnings.append(f"Parameter '{param.name}' description is very short")
        
        return warnings
    
    def validate_cross_module_consistency(self, modules: List[ModuleMetadata]) -> List[str]:
        """Validate consistency across modules"""
        warnings = []
        
        # Check for consistent parameter naming across modules
        all_params = {}
        for module in modules:
            for param in module.parameters:
                if param.name not in all_params:
                    all_params[param.name] = []
                all_params[param.name].append({
                    'module': module.name,
                    'description': param.description,
                    'type': param.param_type
                })
        
        # Find parameters with same name but different descriptions/types
        for param_name, usages in all_params.items():
            if len(usages) > 1:
                descriptions = {usage['description'] for usage in usages}
                types = {usage['type'] for usage in usages}
                
                if len(descriptions) > 1:
                    modules_list = [usage['module'] for usage in usages]
                    warnings.append(f"Parameter '{param_name}' has different descriptions across modules: {', '.join(modules_list)}")
                
                if len(types) > 1:
                    modules_list = [usage['module'] for usage in usages]
                    warnings.append(f"Parameter '{param_name}' has different types across modules: {', '.join(modules_list)}")
        
        return warnings