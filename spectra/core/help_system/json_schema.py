# -*- coding: utf-8 -*-
"""
JSON Schema definitions for Spectra help system
"""

import json
from typing import Dict, Any

# JSON Schema for module metadata
MODULE_METADATA_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "Spectra Module Metadata",
    "type": "object",
    "required": ["name", "display_name", "category", "description"],
    "properties": {
        "name": {
            "type": "string",
            "pattern": "^[a-z][a-z0-9_]*[a-z0-9]$",
            "description": "Module name in snake_case"
        },
        "display_name": {
            "type": "string",
            "minLength": 1,
            "description": "Human-readable module name"
        },
        "category": {
            "type": "string",
            "enum": [
                "reconnaissance",
                "security_analysis", 
                "vulnerability_detection",
                "cryptography",
                "monitoring",
                "integration"
            ],
            "description": "Module category"
        },
        "description": {
            "type": "string",
            "minLength": 10,
            "maxLength": 200,
            "description": "Brief module description"
        },
        "detailed_description": {
            "type": "string",
            "minLength": 50,
            "description": "Detailed module description"
        },
        "version": {
            "type": "string",
            "pattern": "^\\d+\\.\\d+\\.\\d+$",
            "description": "Semantic version"
        },
        "author": {
            "type": "string",
            "description": "Module author"
        },
        "cli_command": {
            "type": "string",
            "pattern": "^-[a-z]{1,4}$",
            "description": "CLI command"
        },
        "cli_aliases": {
            "type": "array",
            "items": {
                "type": "string",
                "pattern": "^-[a-z]{1,4}$"
            },
            "description": "Alternative CLI commands"
        },
        "parameters": {
            "type": "array",
            "items": {
                "$ref": "#/definitions/parameter"
            },
            "description": "Module parameters"
        },
        "examples": {
            "type": "array",
            "items": {
                "$ref": "#/definitions/example"
            },
            "minItems": 1,
            "description": "Usage examples"
        },
        "use_cases": {
            "type": "array",
            "items": {
                "$ref": "#/definitions/use_case"
            },
            "description": "Practical use cases"
        },
        "related_modules": {
            "type": "array",
            "items": {
                "type": "string"
            },
            "description": "Related module names"
        },
        "dependencies": {
            "type": "array",
            "items": {
                "type": "string"
            },
            "description": "Module dependencies"
        },
        "tags": {
            "type": "array",
            "items": {
                "type": "string"
            },
            "description": "Search tags"
        },
        "documentation_url": {
            "type": "string",
            "format": "uri",
            "description": "Documentation URL"
        }
    },
    "definitions": {
        "parameter": {
            "type": "object",
            "required": ["name", "description"],
            "properties": {
                "name": {
                    "type": "string",
                    "pattern": "^[a-z][a-z0-9-]*[a-z0-9]$",
                    "description": "Parameter name"
                },
                "short_name": {
                    "type": "string",
                    "pattern": "^[a-z]{1,3}$",
                    "description": "Short parameter name"
                },
                "description": {
                    "type": "string",
                    "minLength": 5,
                    "description": "Parameter description"
                },
                "type": {
                    "type": "string",
                    "enum": [
                        "string", "integer", "float", "boolean", "list",
                        "file_path", "url", "ip_address", "port", "choice"
                    ],
                    "description": "Parameter type"
                },
                "required": {
                    "type": "boolean",
                    "description": "Whether parameter is required"
                },
                "default_value": {
                    "description": "Default parameter value"
                },
                "choices": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    },
                    "description": "Valid choices for choice type"
                },
                "examples": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    },
                    "description": "Example values"
                },
                "min_value": {
                    "type": "number",
                    "description": "Minimum value for numeric types"
                },
                "max_value": {
                    "type": "number",
                    "description": "Maximum value for numeric types"
                },
                "help_text": {
                    "type": "string",
                    "description": "Extended help text"
                }
            }
        },
        "example": {
            "type": "object",
            "required": ["title", "description", "command"],
            "properties": {
                "title": {
                    "type": "string",
                    "minLength": 1,
                    "description": "Example title"
                },
                "description": {
                    "type": "string",
                    "minLength": 10,
                    "description": "Example description"
                },
                "command": {
                    "type": "string",
                    "pattern": "^spectra ",
                    "description": "Command to execute"
                },
                "level": {
                    "type": "string",
                    "enum": ["basic", "intermediate", "advanced"],
                    "description": "Example complexity level"
                },
                "category": {
                    "type": "string",
                    "description": "Example category"
                },
                "expected_output": {
                    "type": "string",
                    "description": "Expected output description"
                },
                "notes": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    },
                    "description": "Additional notes"
                },
                "prerequisites": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    },
                    "description": "Required setup"
                }
            }
        },
        "use_case": {
            "type": "object",
            "required": ["title", "description", "scenario"],
            "properties": {
                "title": {
                    "type": "string",
                    "minLength": 1,
                    "description": "Use case title"
                },
                "description": {
                    "type": "string",
                    "minLength": 20,
                    "description": "Use case description"
                },
                "scenario": {
                    "type": "string",
                    "description": "When to use this"
                },
                "steps": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    },
                    "description": "Step-by-step guide"
                },
                "related_examples": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    },
                    "description": "Related example titles"
                }
            }
        }
    }
}

# JSON Schema for help search results
SEARCH_RESULTS_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "Spectra Help Search Results",
    "type": "object",
    "required": ["query", "result_count", "results"],
    "properties": {
        "query": {
            "type": "string",
            "description": "Search query"
        },
        "result_count": {
            "type": "integer",
            "minimum": 0,
            "description": "Number of results"
        },
        "results": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["name", "display_name", "category", "description"],
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Module name"
                    },
                    "display_name": {
                        "type": "string",
                        "description": "Display name"
                    },
                    "category": {
                        "type": "string",
                        "description": "Module category"
                    },
                    "description": {
                        "type": "string",
                        "description": "Module description"
                    },
                    "cli_command": {
                        "type": "string",
                        "description": "CLI command"
                    },
                    "tags": {
                        "type": "array",
                        "items": {
                            "type": "string"
                        },
                        "description": "Search tags"
                    },
                    "match_score": {
                        "type": "number",
                        "minimum": 0,
                        "maximum": 100,
                        "description": "Search match score"
                    }
                }
            },
            "description": "Search results"
        },
        "suggestions": {
            "type": "array",
            "items": {
                "type": "string"
            },
            "description": "Search suggestions"
        }
    }
}

# JSON Schema for general help
GENERAL_HELP_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "Spectra General Help",
    "type": "object",
    "required": ["spectra_help"],
    "properties": {
        "spectra_help": {
            "type": "object",
            "required": ["version", "description", "categories"],
            "properties": {
                "version": {
                    "type": "string",
                    "description": "Spectra version"
                },
                "description": {
                    "type": "string",
                    "description": "Tool description"
                },
                "categories": {
                    "type": "object",
                    "patternProperties": {
                        "^[a-z_]+$": {
                            "type": "object",
                            "required": ["name", "modules"],
                            "properties": {
                                "name": {
                                    "type": "string",
                                    "description": "Category display name"
                                },
                                "description": {
                                    "type": "string",
                                    "description": "Category description"
                                },
                                "modules": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "required": ["name", "display_name", "description"],
                                        "properties": {
                                            "name": {
                                                "type": "string",
                                                "description": "Module name"
                                            },
                                            "display_name": {
                                                "type": "string",
                                                "description": "Module display name"
                                            },
                                            "description": {
                                                "type": "string",
                                                "description": "Module description"
                                            },
                                            "cli_command": {
                                                "type": "string",
                                                "description": "CLI command"
                                            },
                                            "version": {
                                                "type": "string",
                                                "description": "Module version"
                                            }
                                        }
                                    },
                                    "description": "Modules in category"
                                }
                            }
                        }
                    },
                    "description": "Modules organized by category"
                },
                "statistics": {
                    "type": "object",
                    "properties": {
                        "total_modules": {
                            "type": "integer",
                            "minimum": 0
                        },
                        "total_categories": {
                            "type": "integer",
                            "minimum": 0
                        },
                        "total_commands": {
                            "type": "integer",
                            "minimum": 0
                        }
                    },
                    "description": "Help system statistics"
                }
            }
        }
    }
}


class JSONSchemaValidator:
    """Validator for JSON schema compliance"""
    
    def __init__(self):
        self.schemas = {
            'module_metadata': MODULE_METADATA_SCHEMA,
            'search_results': SEARCH_RESULTS_SCHEMA,
            'general_help': GENERAL_HELP_SCHEMA
        }
    
    def validate_module_metadata(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate module metadata against schema
        
        Args:
            data: Module metadata dictionary
            
        Returns:
            Validation result
        """
        return self._validate_against_schema(data, 'module_metadata')
    
    def validate_search_results(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate search results against schema
        
        Args:
            data: Search results dictionary
            
        Returns:
            Validation result
        """
        return self._validate_against_schema(data, 'search_results')
    
    def validate_general_help(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate general help against schema
        
        Args:
            data: General help dictionary
            
        Returns:
            Validation result
        """
        return self._validate_against_schema(data, 'general_help')
    
    def _validate_against_schema(self, data: Dict[str, Any], schema_name: str) -> Dict[str, Any]:
        """
        Validate data against specified schema
        
        Args:
            data: Data to validate
            schema_name: Name of schema to use
            
        Returns:
            Validation result dictionary
        """
        try:
            # Try to import jsonschema for proper validation
            try:
                import jsonschema
                schema = self.schemas[schema_name]
                jsonschema.validate(data, schema)
                return {
                    'valid': True,
                    'errors': [],
                    'schema': schema_name
                }
            except ImportError:
                # Fallback to basic validation if jsonschema not available
                return self._basic_validation(data, schema_name)
                
        except Exception as e:
            return {
                'valid': False,
                'errors': [str(e)],
                'schema': schema_name
            }
    
    def _basic_validation(self, data: Dict[str, Any], schema_name: str) -> Dict[str, Any]:
        """
        Basic validation without jsonschema library
        
        Args:
            data: Data to validate
            schema_name: Schema name
            
        Returns:
            Basic validation result
        """
        errors = []
        
        if schema_name == 'module_metadata':
            required_fields = ['name', 'display_name', 'category', 'description']
            for field in required_fields:
                if field not in data:
                    errors.append(f"Missing required field: {field}")
        
        elif schema_name == 'search_results':
            required_fields = ['query', 'result_count', 'results']
            for field in required_fields:
                if field not in data:
                    errors.append(f"Missing required field: {field}")
        
        elif schema_name == 'general_help':
            if 'spectra_help' not in data:
                errors.append("Missing required field: spectra_help")
        
        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'schema': schema_name,
            'validation_type': 'basic'
        }
    
    def get_schema(self, schema_name: str) -> Dict[str, Any]:
        """
        Get schema by name
        
        Args:
            schema_name: Name of schema
            
        Returns:
            Schema dictionary
        """
        return self.schemas.get(schema_name, {})
    
    def get_available_schemas(self) -> List[str]:
        """
        Get list of available schema names
        
        Returns:
            List of schema names
        """
        return list(self.schemas.keys())


def export_schemas_to_file(file_path: str) -> bool:
    """
    Export all schemas to a JSON file
    
    Args:
        file_path: Path to output file
        
    Returns:
        True if successful
    """
    try:
        schemas_export = {
            'title': 'Spectra Help System JSON Schemas',
            'version': '1.0.0',
            'schemas': {
                'module_metadata': MODULE_METADATA_SCHEMA,
                'search_results': SEARCH_RESULTS_SCHEMA,
                'general_help': GENERAL_HELP_SCHEMA
            }
        }
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(schemas_export, f, indent=2)
        
        return True
        
    except Exception as e:
        print(f"Failed to export schemas: {e}")
        return False