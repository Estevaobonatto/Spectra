# -*- coding: utf-8 -*-
"""
Base metadata classes for Spectra modules
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Union
from enum import Enum


class ModuleCategory(Enum):
    """Categories for organizing modules functionally"""
    RECONNAISSANCE = "reconnaissance"
    SECURITY_ANALYSIS = "security_analysis"
    VULNERABILITY_DETECTION = "vulnerability_detection"
    CRYPTOGRAPHY = "cryptography"
    MONITORING = "monitoring"
    INTEGRATION = "integration"


class OutputFormat(Enum):
    """Supported output formats for help system"""
    TEXT = "text"
    JSON = "json"
    HTML = "html"
    MARKDOWN = "markdown"
    XML = "xml"


class ParameterType(Enum):
    """Parameter data types"""
    STRING = "str"
    INTEGER = "int"
    FLOAT = "float"
    BOOLEAN = "bool"
    LIST = "list"
    CHOICE = "choice"
    FILE_PATH = "file_path"
    URL = "url"
    IP_ADDRESS = "ip_address"
    PORT = "port"
    RANGE = "range"


@dataclass
class Parameter:
    """Represents a command-line parameter for a module"""
    name: str                           # Full parameter name (--port-scan)
    short_name: Optional[str] = None    # Short name (-ps)
    description: str = ""               # Parameter description
    param_type: ParameterType = ParameterType.STRING
    required: bool = False              # Whether parameter is required
    default_value: Any = None           # Default value if not provided
    choices: Optional[List[str]] = None # Valid choices for choice type
    depends_on: Optional[List[str]] = None  # Parameters this depends on
    conflicts_with: Optional[List[str]] = None  # Mutually exclusive parameters
    examples: Optional[List[str]] = None    # Example values
    min_value: Optional[Union[int, float]] = None  # Minimum value for numeric types
    max_value: Optional[Union[int, float]] = None  # Maximum value for numeric types
    help_group: Optional[str] = None    # Group for organizing help display
    
    def __post_init__(self):
        """Initialize default values after creation"""
        if self.examples is None:
            self.examples = []
        if self.depends_on is None:
            self.depends_on = []
        if self.conflicts_with is None:
            self.conflicts_with = []


@dataclass
class Example:
    """Represents a usage example for a module"""
    title: str                          # Example title
    description: str                    # What this example demonstrates
    command: str                        # Full command to execute
    level: str = "basic"               # basic, intermediate, advanced
    category: Optional[str] = None      # Category of example
    expected_output: Optional[str] = None   # Expected output description
    prerequisites: Optional[List[str]] = None  # What's needed to run this
    notes: Optional[str] = None         # Additional notes
    
    def __post_init__(self):
        """Initialize default values after creation"""
        if self.prerequisites is None:
            self.prerequisites = []


@dataclass
class UseCase:
    """Represents a practical use case for a module"""
    title: str                          # Use case title
    description: str                    # Detailed description
    scenario: str                       # When to use this
    steps: List[str]                    # Step-by-step instructions
    related_modules: Optional[List[str]] = None  # Other modules often used with this
    
    def __post_init__(self):
        """Initialize default values after creation"""
        if self.related_modules is None:
            self.related_modules = []


@dataclass
class ModuleMetadata:
    """Complete metadata for a Spectra module"""
    # Basic Information
    name: str                           # Module name (e.g., "port_scanner")
    display_name: str                   # Display name (e.g., "Port Scanner")
    category: ModuleCategory            # Functional category
    description: str                    # Brief description
    detailed_description: str           # Detailed description
    
    # Parameters and Usage
    parameters: List[Parameter] = field(default_factory=list)
    examples: List[Example] = field(default_factory=list)
    use_cases: List[UseCase] = field(default_factory=list)
    
    # Relationships and Metadata
    related_modules: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    
    # Version and Authorship
    version: str = "1.0.0"
    author: str = "Spectra Team"
    last_updated: Optional[str] = None
    
    # Technical Details
    cli_flags: List[str] = field(default_factory=list)  # Main CLI flags for this module
    output_formats: List[OutputFormat] = field(default_factory=list)
    
    # Documentation
    documentation_url: Optional[str] = None
    source_file: Optional[str] = None
    
    def get_parameter(self, name: str) -> Optional[Parameter]:
        """Get parameter by name"""
        for param in self.parameters:
            if param.name == name or param.short_name == name:
                return param
        return None
    
    def get_examples_by_level(self, level: str) -> List[Example]:
        """Get examples filtered by level"""
        return [ex for ex in self.examples if ex.level == level]
    
    def get_examples_by_category(self, category: str) -> List[Example]:
        """Get examples filtered by category"""
        return [ex for ex in self.examples if ex.category == category]
    
    def get_required_parameters(self) -> List[Parameter]:
        """Get all required parameters"""
        return [param for param in self.parameters if param.required]
    
    def get_optional_parameters(self) -> List[Parameter]:
        """Get all optional parameters"""
        return [param for param in self.parameters if not param.required]
    
    def get_parameters_by_group(self, group: str) -> List[Parameter]:
        """Get parameters by help group"""
        return [param for param in self.parameters if param.help_group == group]
    
    def validate_parameter_dependencies(self) -> List[str]:
        """Validate parameter dependencies and return any issues"""
        issues = []
        param_names = {param.name for param in self.parameters}
        
        for param in self.parameters:
            # Check dependencies exist
            for dep in param.depends_on:
                if dep not in param_names:
                    issues.append(f"Parameter '{param.name}' depends on non-existent parameter '{dep}'")
            
            # Check conflicts exist
            for conflict in param.conflicts_with:
                if conflict not in param_names:
                    issues.append(f"Parameter '{param.name}' conflicts with non-existent parameter '{conflict}'")
        
        return issues
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to dictionary for serialization"""
        return {
            'name': self.name,
            'display_name': self.display_name,
            'category': self.category.value,
            'description': self.description,
            'detailed_description': self.detailed_description,
            'parameters': [
                {
                    'name': p.name,
                    'short_name': p.short_name,
                    'description': p.description,
                    'type': p.param_type.value,
                    'required': p.required,
                    'default_value': p.default_value,
                    'choices': p.choices,
                    'examples': p.examples,
                    'help_group': p.help_group
                }
                for p in self.parameters
            ],
            'examples': [
                {
                    'title': ex.title,
                    'description': ex.description,
                    'command': ex.command,
                    'level': ex.level,
                    'category': ex.category
                }
                for ex in self.examples
            ],
            'use_cases': [
                {
                    'title': uc.title,
                    'description': uc.description,
                    'scenario': uc.scenario,
                    'steps': uc.steps
                }
                for uc in self.use_cases
            ],
            'related_modules': self.related_modules,
            'tags': self.tags,
            'version': self.version,
            'author': self.author,
            'cli_flags': self.cli_flags
        }