# -*- coding: utf-8 -*-
"""
Base metadata classes for Spectra modules
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum


class ModuleCategory(Enum):
    """Categories for organizing modules"""
    RECONNAISSANCE = "reconnaissance"
    SECURITY_ANALYSIS = "security_analysis"
    VULNERABILITY_DETECTION = "vulnerability_detection"
    CRYPTOGRAPHY = "cryptography"
    MONITORING = "monitoring"
    INTEGRATION = "integration"


class ParameterType(Enum):
    """Parameter types for validation"""
    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    LIST = "list"
    FILE_PATH = "file_path"
    URL = "url"
    IP_ADDRESS = "ip_address"
    PORT = "port"
    CHOICE = "choice"


class ExampleLevel(Enum):
    """Example complexity levels"""
    BASIC = "basic"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"


@dataclass
class Parameter:
    """Represents a module parameter with all its properties"""
    name: str                           # Full parameter name (--port-scan)
    short_name: Optional[str] = None    # Short name (-ps)
    description: str = ""               # Parameter description
    param_type: ParameterType = ParameterType.STRING
    required: bool = False              # Is parameter required
    default_value: Any = None           # Default value
    choices: List[str] = field(default_factory=list)  # Valid choices
    depends_on: List[str] = field(default_factory=list)  # Parameter dependencies
    examples: List[str] = field(default_factory=list)   # Example values
    min_value: Optional[float] = None   # Minimum value (for numeric types)
    max_value: Optional[float] = None   # Maximum value (for numeric types)
    help_text: str = ""                 # Extended help text
    
    def __post_init__(self):
        """Validate parameter after initialization"""
        if not self.name:
            raise ValueError("Parameter name cannot be empty")
        if not self.description:
            raise ValueError(f"Parameter '{self.name}' must have a description")


@dataclass
class Example:
    """Represents a usage example for a module"""
    title: str                          # Example title
    description: str                    # What the example does
    command: str                        # Full command to execute
    level: ExampleLevel = ExampleLevel.BASIC
    category: str = ""                  # Example category
    expected_output: str = ""           # Expected output description
    notes: List[str] = field(default_factory=list)  # Additional notes
    prerequisites: List[str] = field(default_factory=list)  # Required setup
    
    def __post_init__(self):
        """Validate example after initialization"""
        if not self.title:
            raise ValueError("Example title cannot be empty")
        if not self.description:
            raise ValueError("Example description cannot be empty")
        if not self.command:
            raise ValueError("Example command cannot be empty")


@dataclass
class UseCase:
    """Represents a practical use case for a module"""
    title: str                          # Use case title
    description: str                    # Detailed description
    scenario: str                       # When to use this
    steps: List[str] = field(default_factory=list)  # Step-by-step guide
    related_examples: List[str] = field(default_factory=list)  # Related example titles
    
    def __post_init__(self):
        """Validate use case after initialization"""
        if not self.title:
            raise ValueError("Use case title cannot be empty")
        if not self.description:
            raise ValueError("Use case description cannot be empty")


@dataclass
class ModuleMetadata:
    """Complete metadata for a Spectra module"""
    name: str                           # Module name (port_scanner)
    display_name: str                   # Display name (Port Scanner)
    category: ModuleCategory            # Module category
    description: str                    # Brief description
    detailed_description: str = ""      # Detailed description
    version: str = "1.0.0"             # Module version
    author: str = "Spectra Team"        # Author/Maintainer
    
    # Parameters and usage
    parameters: List[Parameter] = field(default_factory=list)
    examples: List[Example] = field(default_factory=list)
    use_cases: List[UseCase] = field(default_factory=list)
    
    # Relationships
    related_modules: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    
    # CLI integration
    cli_command: str = ""               # Primary CLI command (-ps)
    cli_aliases: List[str] = field(default_factory=list)  # Alternative commands
    
    # Documentation
    documentation_url: str = ""         # Link to detailed docs
    tags: List[str] = field(default_factory=list)  # Search tags
    
    def __post_init__(self):
        """Validate metadata after initialization"""
        if not self.name:
            raise ValueError("Module name cannot be empty")
        if not self.display_name:
            raise ValueError("Module display name cannot be empty")
        if not self.description:
            raise ValueError("Module description cannot be empty")
        if not isinstance(self.category, ModuleCategory):
            raise ValueError("Module category must be a ModuleCategory enum")
    
    def get_parameter(self, name: str) -> Optional[Parameter]:
        """Get parameter by name"""
        for param in self.parameters:
            if param.name == name or param.short_name == name:
                return param
        return None
    
    def get_examples_by_level(self, level: ExampleLevel) -> List[Example]:
        """Get examples filtered by complexity level"""
        return [ex for ex in self.examples if ex.level == level]
    
    def get_required_parameters(self) -> List[Parameter]:
        """Get all required parameters"""
        return [param for param in self.parameters if param.required]
    
    def get_optional_parameters(self) -> List[Parameter]:
        """Get all optional parameters"""
        return [param for param in self.parameters if not param.required]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to dictionary for JSON serialization"""
        return {
            'name': self.name,
            'display_name': self.display_name,
            'category': self.category.value,
            'description': self.description,
            'detailed_description': self.detailed_description,
            'version': self.version,
            'author': self.author,
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
                    'help_text': p.help_text
                }
                for p in self.parameters
            ],
            'examples': [
                {
                    'title': ex.title,
                    'description': ex.description,
                    'command': ex.command,
                    'level': ex.level.value,
                    'category': ex.category,
                    'expected_output': ex.expected_output,
                    'notes': ex.notes
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
            'cli_command': self.cli_command,
            'tags': self.tags
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ModuleMetadata':
        """Create metadata from dictionary"""
        # Convert parameters
        parameters = []
        for p_data in data.get('parameters', []):
            param = Parameter(
                name=p_data['name'],
                short_name=p_data.get('short_name'),
                description=p_data['description'],
                param_type=ParameterType(p_data.get('type', 'string')),
                required=p_data.get('required', False),
                default_value=p_data.get('default_value'),
                choices=p_data.get('choices', []),
                examples=p_data.get('examples', []),
                help_text=p_data.get('help_text', '')
            )
            parameters.append(param)
        
        # Convert examples
        examples = []
        for ex_data in data.get('examples', []):
            example = Example(
                title=ex_data['title'],
                description=ex_data['description'],
                command=ex_data['command'],
                level=ExampleLevel(ex_data.get('level', 'basic')),
                category=ex_data.get('category', ''),
                expected_output=ex_data.get('expected_output', ''),
                notes=ex_data.get('notes', [])
            )
            examples.append(example)
        
        # Convert use cases
        use_cases = []
        for uc_data in data.get('use_cases', []):
            use_case = UseCase(
                title=uc_data['title'],
                description=uc_data['description'],
                scenario=uc_data['scenario'],
                steps=uc_data.get('steps', [])
            )
            use_cases.append(use_case)
        
        return cls(
            name=data['name'],
            display_name=data['display_name'],
            category=ModuleCategory(data['category']),
            description=data['description'],
            detailed_description=data.get('detailed_description', ''),
            version=data.get('version', '1.0.0'),
            author=data.get('author', 'Spectra Team'),
            parameters=parameters,
            examples=examples,
            use_cases=use_cases,
            related_modules=data.get('related_modules', []),
            cli_command=data.get('cli_command', ''),
            tags=data.get('tags', [])
        )