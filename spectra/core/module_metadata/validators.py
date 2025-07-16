# -*- coding: utf-8 -*-
"""
Validation system for module metadata
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from .base_metadata import ModuleMetadata, Parameter, Example, UseCase, ParameterType, ExampleLevel


@dataclass
class ValidationResult:
    """Result of metadata validation for a single module"""
    module_name: str
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    
    def add_error(self, message: str):
        """Add an error message"""
        self.errors.append(message)
        self.is_valid = False
    
    def add_warning(self, message: str):
        """Add a warning message"""
        self.warnings.append(message)
    
    def has_issues(self) -> bool:
        """Check if there are any errors or warnings"""
        return len(self.errors) > 0 or len(self.warnings) > 0


@dataclass
class ValidationReport:
    """Complete validation report for all modules"""
    total_modules: int
    valid_modules: int
    invalid_modules: int
    results: List[ValidationResult] = field(default_factory=list)
    
    def add_result(self, result: ValidationResult):
        """Add a validation result"""
        self.results.append(result)
        if result.is_valid:
            self.valid_modules += 1
        else:
            self.invalid_modules += 1
    
    def get_summary(self) -> str:
        """Get validation summary"""
        return f"Validation Summary: {self.valid_modules}/{self.total_modules} modules valid"
    
    def get_failed_modules(self) -> List[ValidationResult]:
        """Get modules that failed validation"""
        return [r for r in self.results if not r.is_valid]
    
    def get_modules_with_warnings(self) -> List[ValidationResult]:
        """Get modules with warnings"""
        return [r for r in self.results if len(r.warnings) > 0]


class MetadataValidator:
    """Validator for module metadata consistency and quality"""
    
    def __init__(self):
        self.naming_patterns = {
            'module_name': re.compile(r'^[a-z][a-z0-9_]*[a-z0-9]$'),
            'parameter_name': re.compile(r'^[a-z][a-z0-9-]*[a-z0-9]$'),
            'short_name': re.compile(r'^[a-z]{1,3}$'),
            'cli_command': re.compile(r'^-[a-z]{1,4}$')
        }
        
        self.required_examples_per_level = {
            ExampleLevel.BASIC: 1,
            ExampleLevel.INTERMEDIATE: 1,
            ExampleLevel.ADVANCED: 1
        }
        
        self.min_description_length = 10
        self.max_description_length = 200
        self.min_detailed_description_length = 50
    
    def validate_metadata(self, metadata: ModuleMetadata) -> ValidationResult:
        """Validate complete module metadata"""
        result = ValidationResult(module_name=metadata.name, is_valid=True)
        
        # Validate basic fields
        self._validate_basic_fields(metadata, result)
        
        # Validate naming conventions
        self._validate_naming_conventions(metadata, result)
        
        # Validate parameters
        self._validate_parameters(metadata, result)
        
        # Validate examples
        self._validate_examples(metadata, result)
        
        # Validate use cases
        self._validate_use_cases(metadata, result)
        
        # Validate relationships
        self._validate_relationships(metadata, result)
        
        # Quality checks
        self._validate_quality(metadata, result)
        
        return result
    
    def _validate_basic_fields(self, metadata: ModuleMetadata, result: ValidationResult):
        """Validate basic required fields"""
        if not metadata.name:
            result.add_error("Module name is required")
        
        if not metadata.display_name:
            result.add_error("Display name is required")
        
        if not metadata.description:
            result.add_error("Description is required")
        elif len(metadata.description) < self.min_description_length:
            result.add_error(f"Description too short (minimum {self.min_description_length} characters)")
        elif len(metadata.description) > self.max_description_length:
            result.add_warning(f"Description very long (over {self.max_description_length} characters)")
        
        if metadata.detailed_description and len(metadata.detailed_description) < self.min_detailed_description_length:
            result.add_warning(f"Detailed description too short (minimum {self.min_detailed_description_length} characters)")
        
        if not metadata.version:
            result.add_warning("Version not specified")
        elif not re.match(r'^\d+\.\d+\.\d+$', metadata.version):
            result.add_warning("Version should follow semantic versioning (x.y.z)")
    
    def _validate_naming_conventions(self, metadata: ModuleMetadata, result: ValidationResult):
        """Validate naming conventions"""
        # Module name
        if not self.naming_patterns['module_name'].match(metadata.name):
            result.add_error("Module name must be lowercase with underscores (snake_case)")
        
        # CLI command
        if metadata.cli_command and not self.naming_patterns['cli_command'].match(metadata.cli_command):
            result.add_error("CLI command must start with dash and be lowercase (-ps, -ds, etc.)")
        
        # Display name should be title case
        if metadata.display_name and not metadata.display_name.replace(' ', '').replace('-', '').isalnum():
            result.add_warning("Display name should contain only alphanumeric characters, spaces, and hyphens")
    
    def _validate_parameters(self, metadata: ModuleMetadata, result: ValidationResult):
        """Validate parameters"""
        if not metadata.parameters:
            result.add_warning("Module has no parameters defined")
            return
        
        parameter_names = set()
        short_names = set()
        
        for param in metadata.parameters:
            # Check for duplicate names
            if param.name in parameter_names:
                result.add_error(f"Duplicate parameter name: {param.name}")
            parameter_names.add(param.name)
            
            if param.short_name:
                if param.short_name in short_names:
                    result.add_error(f"Duplicate short name: {param.short_name}")
                short_names.add(param.short_name)
                
                # Validate short name format
                if not self.naming_patterns['short_name'].match(param.short_name):
                    result.add_error(f"Invalid short name format: {param.short_name}")
            
            # Validate parameter name format
            if not self.naming_patterns['parameter_name'].match(param.name):
                result.add_error(f"Invalid parameter name format: {param.name}")
            
            # Validate description
            if not param.description:
                result.add_error(f"Parameter {param.name} missing description")
            elif len(param.description) < 5:
                result.add_warning(f"Parameter {param.name} description too short")
            
            # Validate choices for choice parameters
            if param.param_type == ParameterType.CHOICE and not param.choices:
                result.add_error(f"Parameter {param.name} is choice type but has no choices defined")
            
            # Validate numeric ranges
            if param.param_type in [ParameterType.INTEGER, ParameterType.FLOAT]:
                if param.min_value is not None and param.max_value is not None:
                    if param.min_value >= param.max_value:
                        result.add_error(f"Parameter {param.name} min_value must be less than max_value")
            
            # Validate examples
            if not param.examples:
                result.add_warning(f"Parameter {param.name} has no usage examples")
    
    def _validate_examples(self, metadata: ModuleMetadata, result: ValidationResult):
        """Validate examples"""
        if not metadata.examples:
            result.add_error("Module must have at least one usage example")
            return
        
        # Check for examples at different levels
        levels_present = set(ex.level for ex in metadata.examples)
        
        if ExampleLevel.BASIC not in levels_present:
            result.add_error("Module must have at least one basic example")
        
        if len(metadata.examples) >= 3 and ExampleLevel.ADVANCED not in levels_present:
            result.add_warning("Module with multiple examples should include advanced examples")
        
        example_titles = set()
        for example in metadata.examples:
            # Check for duplicate titles
            if example.title in example_titles:
                result.add_error(f"Duplicate example title: {example.title}")
            example_titles.add(example.title)
            
            # Validate command format
            if not example.command.startswith('spectra '):
                result.add_error(f"Example '{example.title}' command should start with 'spectra '")
            
            # Check for placeholder values
            if '<' in example.command and '>' in example.command:
                result.add_warning(f"Example '{example.title}' contains placeholder values")
            
            # Validate description length
            if len(example.description) < 10:
                result.add_warning(f"Example '{example.title}' description too short")
    
    def _validate_use_cases(self, metadata: ModuleMetadata, result: ValidationResult):
        """Validate use cases"""
        if not metadata.use_cases:
            result.add_warning("Module has no use cases defined")
            return
        
        use_case_titles = set()
        for use_case in metadata.use_cases:
            # Check for duplicate titles
            if use_case.title in use_case_titles:
                result.add_error(f"Duplicate use case title: {use_case.title}")
            use_case_titles.add(use_case.title)
            
            # Validate content
            if len(use_case.description) < 20:
                result.add_warning(f"Use case '{use_case.title}' description too short")
            
            if not use_case.steps:
                result.add_warning(f"Use case '{use_case.title}' has no steps defined")
    
    def _validate_relationships(self, metadata: ModuleMetadata, result: ValidationResult):
        """Validate module relationships"""
        # Check for self-references
        if metadata.name in metadata.related_modules:
            result.add_error("Module cannot reference itself in related_modules")
        
        # Validate related module names
        for related in metadata.related_modules:
            if not self.naming_patterns['module_name'].match(related):
                result.add_warning(f"Related module name '{related}' doesn't follow naming convention")
    
    def _validate_quality(self, metadata: ModuleMetadata, result: ValidationResult):
        """Validate overall quality and completeness"""
        # Check for comprehensive documentation
        if not metadata.detailed_description:
            result.add_warning("Module missing detailed description")
        
        if not metadata.tags:
            result.add_warning("Module has no search tags")
        
        if not metadata.documentation_url:
            result.add_warning("Module has no documentation URL")
        
        # Check parameter coverage
        required_params = [p for p in metadata.parameters if p.required]
        if not required_params and len(metadata.parameters) > 0:
            result.add_warning("Module has parameters but none are marked as required")
        
        # Check example coverage
        if len(metadata.examples) < 3:
            result.add_warning("Module should have at least 3 examples (basic, intermediate, advanced)")
        
        # Check for common typos in descriptions
        common_typos = ['teh', 'recieve', 'seperate', 'occured']
        all_text = f"{metadata.description} {metadata.detailed_description}".lower()
        for typo in common_typos:
            if typo in all_text:
                result.add_warning(f"Possible typo detected: '{typo}'")
    
    def validate_multiple_modules(self, modules: List[ModuleMetadata]) -> ValidationReport:
        """Validate multiple modules and generate report"""
        report = ValidationReport(
            total_modules=len(modules),
            valid_modules=0,
            invalid_modules=0
        )
        
        # Validate each module
        for module in modules:
            result = self.validate_metadata(module)
            report.add_result(result)
        
        # Cross-module validation
        self._validate_cross_module_references(modules, report)
        
        return report
    
    def _validate_cross_module_references(self, modules: List[ModuleMetadata], report: ValidationReport):
        """Validate references between modules"""
        module_names = {m.name for m in modules}
        
        for module in modules:
            result = next((r for r in report.results if r.module_name == module.name), None)
            if not result:
                continue
            
            # Check if related modules exist
            for related in module.related_modules:
                if related not in module_names:
                    result.add_warning(f"Related module '{related}' not found in module registry")
            
            # Check for circular dependencies
            for related_name in module.related_modules:
                related_module = next((m for m in modules if m.name == related_name), None)
                if related_module and module.name in related_module.related_modules:
                    # This is okay - bidirectional relationship
                    pass