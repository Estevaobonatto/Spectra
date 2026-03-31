# -*- coding: utf-8 -*-
"""
Help Formatter for Spectra - Formats help output in various formats
"""

import json
from typing import Dict, List, Optional, Any
from enum import Enum

from ..module_metadata import ModuleMetadata, Parameter, Example, UseCase, ModuleCategory, ExampleLevel
from ..console import console
from .json_schema import JSONSchemaValidator


class OutputFormat(Enum):
    """Supported output formats"""
    TEXT = "text"
    JSON = "json"
    HTML = "html"
    MARKDOWN = "markdown"
    XML = "xml"


class HelpFormatter:
    """Formats help information in various output formats"""
    
    def __init__(self, width: int = 80, indent: int = 2):
        self.width = width
        self.console_width = width
        self.indent = indent
        self.indent_size = indent
        self.indent_str = " " * indent
        self.validator = JSONSchemaValidator()
        self.validate_json = True
        
    def format_general_help(self, modules_by_category: Dict[ModuleCategory, List[ModuleMetadata]], 
                          format_type: OutputFormat = OutputFormat.TEXT) -> str:
        """
        Format general help showing all modules organized by category
        
        Args:
            modules_by_category: Dictionary mapping categories to module lists
            format_type: Output format
            
        Returns:
            Formatted help string
        """
        if format_type == OutputFormat.TEXT:
            return self._format_general_help_text(modules_by_category)
        elif format_type == OutputFormat.JSON:
            return self._format_general_help_json(modules_by_category)
        elif format_type == OutputFormat.MARKDOWN:
            return self._format_general_help_markdown(modules_by_category)
        elif format_type == OutputFormat.HTML:
            return self._format_general_help_html(modules_by_category)
        else:
            return self._format_general_help_text(modules_by_category)
    
    def format_module_help(self, metadata: ModuleMetadata,
                          format_type: OutputFormat = OutputFormat.TEXT,
                          include_examples: bool = True,
                          include_parameters: bool = True) -> str:
        """
        Format detailed help for a specific module

        Args:
            metadata: Module metadata
            format_type: Output format
            include_examples: Whether to include examples section
            include_parameters: Whether to include parameters section

        Returns:
            Formatted help string
        """
        if not isinstance(format_type, OutputFormat):
            raise ValueError(f"Unsupported format: {format_type!r}")
        if format_type == OutputFormat.TEXT:
            return self._format_module_help_text(metadata,
                                                  include_examples=include_examples,
                                                  include_parameters=include_parameters)
        elif format_type == OutputFormat.JSON:
            return self._format_module_help_json(metadata)
        elif format_type == OutputFormat.MARKDOWN:
            return self._format_module_help_markdown(metadata)
        elif format_type == OutputFormat.HTML:
            return self._format_module_help_html(metadata)
        else:
            return self._format_module_help_text(metadata,
                                                  include_examples=include_examples,
                                                  include_parameters=include_parameters)

    def format_parameters(self, parameters: List[Parameter],
                          format_type: OutputFormat = OutputFormat.TEXT,
                          group_by: str = None) -> str:
        """
        Format a list of parameters.

        Args:
            parameters: List of Parameter objects
            format_type: Output format
            group_by: Optional grouping ('required' or 'help_group')

        Returns:
            Formatted parameters string
        """
        if not isinstance(format_type, OutputFormat):
            raise ValueError(f"Unsupported format: {format_type!r}")

        if not parameters:
            return "No parameters available"

        if format_type == OutputFormat.JSON:
            return json.dumps({"parameters": [self._param_to_dict(p) for p in parameters]}, indent=2)

        lines = []
        if group_by == "required":
            required = [p for p in parameters if p.required]
            optional = [p for p in parameters if not p.required]
            if required:
                lines.append("Required:")
                for p in required:
                    lines.append(self._format_single_param(p))
            if optional:
                lines.append("Optional:")
                for p in optional:
                    lines.append(self._format_single_param(p))
        elif group_by == "help_group":
            groups: Dict[str, List[Parameter]] = {}
            for p in parameters:
                group = getattr(p, "help_group", "") or "General"
                groups.setdefault(group, []).append(p)
            # Named groups first, then General
            ordered = {k: v for k, v in groups.items() if k != "General"}
            if "General" in groups:
                ordered["General"] = groups["General"]
            for group_name, params in ordered.items():
                lines.append(f"{group_name}:")
                for p in params:
                    lines.append(self._format_single_param(p))
        else:
            for p in parameters:
                lines.append(self._format_single_param(p))

        return "\n".join(lines)

    def _param_to_dict(self, p: Parameter) -> dict:
        """Convert a Parameter to a dict for JSON serialisation."""
        _TYPE_MAP = {
            "string": "str",
            "integer": "int",
            "boolean": "bool",
            "float": "float",
            "port": "port",
            "url": "url",
            "path": "path",
            "ip": "ip",
        }
        raw = p.param_type.value if hasattr(p.param_type, "value") else str(p.param_type)
        type_str = _TYPE_MAP.get(raw, raw)
        return {
            "name": p.name,
            "description": p.description,
            "type": type_str,
            "required": p.required,
            "default": p.default_value,
            "examples": p.examples,
        }

    def _format_single_param(self, p: Parameter) -> str:
        """Format a single parameter for text output."""
        flag = f"--{p.name}"
        if hasattr(p, "short_name") and p.short_name:
            flag = f"--{p.name}, -{p.short_name}"
        required_str = "  [Required]" if p.required else ""
        type_str = p.param_type.value if hasattr(p.param_type, "value") else str(p.param_type)
        lines = [f"  {flag}{required_str}"]
        lines.append(f"    {p.description}")
        lines.append(f"    Type: {type_str}")
        if not p.required and p.default_value is not None:
            lines.append(f"    Default: {p.default_value}")
        if p.examples:
            lines.append(f"    Examples: {', '.join(str(e) for e in p.examples)}")
        return "\n".join(lines)
    
    def format_examples(self, examples: list,
                        format_type: OutputFormat = OutputFormat.TEXT,
                        level_filter: str = None) -> str:
        """
        Format a list of examples.

        Args:
            examples: List of Example objects
            format_type: Output format
            level_filter: Optional level to filter by (e.g. 'basic')

        Returns:
            Formatted examples string
        """
        if not isinstance(format_type, OutputFormat):
            raise ValueError(f"Unsupported format: {format_type!r}")

        if level_filter:
            examples = [
                ex for ex in examples
                if (ex.level.value if hasattr(ex.level, 'value') else ex.level) == level_filter.lower()
            ]

        if not examples:
            return "No examples available"

        if format_type == OutputFormat.JSON:
            return json.dumps({"examples": [
                {
                    "title": ex.title,
                    "level": ex.level.value if hasattr(ex.level, 'value') else ex.level,
                    "command": ex.command,
                    "description": ex.description,
                }
                for ex in examples
            ]}, indent=2)

        # TEXT format — group by level
        lines = []
        _LEVELS = [ExampleLevel.BASIC, ExampleLevel.INTERMEDIATE, ExampleLevel.ADVANCED]
        levels_present = {(ex.level.value if hasattr(ex.level, 'value') else ex.level) for ex in examples}

        for lvl in _LEVELS:
            if lvl.value not in levels_present:
                continue
            lines.append(f"{lvl.value.title()} Examples:")
            for ex in examples:
                ex_level = ex.level.value if hasattr(ex.level, 'value') else ex.level
                if ex_level != lvl.value:
                    continue
                lines.append(f"  {ex.title}:")
                if ex.description:
                    lines.append(f"    {ex.description}")
                lines.append(f"    $ {ex.command}")
                if ex.prerequisites:
                    prereq_str = ", ".join(ex.prerequisites) if isinstance(ex.prerequisites, list) else ex.prerequisites
                    lines.append(f"    Prerequisites: {prereq_str}")
                if ex.notes:
                    if isinstance(ex.notes, list):
                        note_str = ", ".join(ex.notes)
                    else:
                        note_str = ex.notes
                    lines.append(f"    Note: {note_str}")
            lines.append("")

        return "\n".join(lines)

    def format_category_help(self, category: ModuleCategory, modules: List[ModuleMetadata],
                           format_type: OutputFormat = OutputFormat.TEXT) -> str:
        """
        Format help for a specific category
        
        Args:
            category: Module category
            modules: List of modules in category
            format_type: Output format
            
        Returns:
            Formatted help string
        """
        if format_type == OutputFormat.TEXT:
            return self._format_category_help_text(category, modules)
        elif format_type == OutputFormat.JSON:
            return self._format_category_help_json(category, modules)
        else:
            return self._format_category_help_text(category, modules)
    
    def format_search_results(self, query: str, results: List[ModuleMetadata],
                            format_type: OutputFormat = OutputFormat.TEXT) -> str:
        """
        Format search results
        
        Args:
            query: Search query
            results: List of matching modules
            format_type: Output format
            
        Returns:
            Formatted search results
        """
        if format_type == OutputFormat.TEXT:
            return self._format_search_results_text(query, results)
        elif format_type == OutputFormat.JSON:
            return self._format_search_results_json(query, results)
        else:
            return self._format_search_results_text(query, results)
    
    # TEXT FORMAT IMPLEMENTATIONS
    
    def _format_general_help_text(self, modules_by_category: Dict[ModuleCategory, List[ModuleMetadata]]) -> str:
        """Format general help in text format"""
        w = self.width
        lines = []

        # Header
        lines.append("=" * w)
        lines.append("Spectra - Web Security Suite")
        lines.append("Comprehensive security testing and analysis toolkit")
        lines.append("=" * w)
        lines.append("")

        # Usage
        lines.append("Usage:")
        lines.append("  spectra <module> [options]")
        lines.append("  spectra --help <module>")
        lines.append("  spectra --search <query>")
        lines.append("")

        # Categories and modules
        for category in ModuleCategory:
            modules = modules_by_category.get(category, [])
            if not modules:
                continue

            cat_name = self._format_category_name(category)
            lines.append(f"[{cat_name}]")
            for module in sorted(modules, key=lambda m: m.name):
                flags = getattr(module, "cli_flags", [])
                if flags:
                    flag_str = ", ".join(flags)
                elif module.cli_command:
                    flag_str = module.cli_command
                else:
                    flag_str = f"--{module.name.replace('_', '-')}"
                lines.append(f"  {flag_str:<25} {module.description}")
            lines.append("")

        return "\n".join(lines)
    
    def _format_module_help_text(self, metadata: ModuleMetadata,
                                 include_examples: bool = True,
                                 include_parameters: bool = True) -> str:
        """Format module help in text format"""
        lines = []
        w = self.width

        # Header
        lines.append(metadata.display_name)
        lines.append("=" * w)
        lines.append("")

        # Basic info block
        lines.append(f"Module: {metadata.name}")
        lines.append(f"Category: {self._get_category_display_name(metadata.category)}")
        if metadata.tags:
            lines.append(f"Tags: {', '.join(metadata.tags)}")
        if metadata.cli_flags:
            lines.append(f"CLI: {', '.join(metadata.cli_flags)}")
        lines.append("")

        # Description
        if metadata.detailed_description or metadata.description:
            lines.append("Description:")
            desc = metadata.detailed_description or metadata.description
            lines.extend(self._wrap_text(desc, indent=2))
            lines.append("")

        # Usage
        primary_flag = None
        aliases = []
        if hasattr(metadata, "cli_flags") and metadata.cli_flags:
            for f in metadata.cli_flags:
                if f.startswith("--"):
                    if primary_flag is None:
                        primary_flag = f
                    else:
                        aliases.append(f)
                else:
                    aliases.append(f)
        if primary_flag is None and metadata.cli_command:
            primary_flag = metadata.cli_command

        if primary_flag:
            lines.append("Usage:")
            lines.append(f"  spectra {primary_flag} [options]")
            if aliases:
                lines.append(f"  Aliases: {', '.join(aliases)}")
            lines.append("")

        # Parameters
        if include_parameters:
            if metadata.parameters:
                lines.append("Parameters:")
                lines.append("")
                required_params = metadata.get_required_parameters()
                optional_params = metadata.get_optional_parameters()
                if required_params:
                    for param in required_params:
                        lines.extend(self._format_parameter_text(param, indent=2))
                if optional_params:
                    for param in optional_params:
                        lines.extend(self._format_parameter_text(param, indent=2))
                lines.append("")
            else:
                lines.append("No parameters available")
                lines.append("")

        # Examples
        if include_examples:
            if metadata.examples:
                lines.append("Examples:")
                lines.append("")
                for level in [ExampleLevel.BASIC, ExampleLevel.INTERMEDIATE, ExampleLevel.ADVANCED]:
                    level_examples = [
                        ex for ex in metadata.examples
                        if (ex.level.value if hasattr(ex.level, 'value') else ex.level) == level.value
                    ]
                    if level_examples:
                        lines.append(f"  {level.value.title()} Examples:")
                        for example in level_examples:
                            lines.extend(self._format_example_text(example, indent=4))
                        lines.append("")
            else:
                lines.append("No examples available")
                lines.append("")

        # Use cases
        if metadata.use_cases:
            lines.append("Common Use Cases:")
            lines.append("")
            for use_case in metadata.use_cases:
                lines.extend(self._format_use_case_text(use_case, indent=2))
            lines.append("")

        # Related modules
        if metadata.related_modules:
            lines.append("Related Modules:")
            related_list = ", ".join(metadata.related_modules)
            lines.extend(self._wrap_text(related_list, indent=2))
            lines.append("")

        return "\n".join(lines)
    
    def _format_category_help_text(self, category: ModuleCategory, modules: List[ModuleMetadata]) -> str:
        """Format category help in text format"""
        w = self.width
        cat_name = self._format_category_name(category)
        _CATEGORY_DESCRIPTIONS = {
            ModuleCategory.RECONNAISSANCE: "Modules for information gathering and reconnaissance against targets.",
            ModuleCategory.VULNERABILITY_DETECTION: "Modules for detecting vulnerabilities and security weaknesses.",
            ModuleCategory.SECURITY_ANALYSIS: "Modules for security analysis and assessment.",
            ModuleCategory.CRYPTOGRAPHY: "Modules for cryptographic operations and analysis.",
            ModuleCategory.MONITORING: "Modules for monitoring and observability.",
            ModuleCategory.INTEGRATION: "Modules for integration with external services.",
        }
        lines = []
        lines.append(f"{cat_name} Modules")
        lines.append("=" * w)
        lines.append("")
        lines.append(f"Category: {cat_name}")
        lines.append(f"Modules: {len(modules)}")
        lines.append("")
        lines.append("Description:")
        desc = _CATEGORY_DESCRIPTIONS.get(category, f"{cat_name} modules.")
        lines.extend(self._wrap_text(desc, indent=2))
        lines.append("")
        lines.append("Available Modules:")
        for module in sorted(modules, key=lambda m: m.name):
            flags = getattr(module, "cli_flags", [])
            if flags:
                flag_str = ", ".join(flags)
            elif module.cli_command:
                flag_str = module.cli_command
            else:
                flag_str = f"--{module.name.replace('_', '-')}"
            lines.append(f"  {flag_str:<25} {module.description}")
        lines.append("")
        return "\n".join(lines)
    
    def _format_search_results_text(self, query: str, results: List[ModuleMetadata]) -> str:
        """Format search results in text format"""
        lines = []
        
        lines.append(f"Search Results for: '{query}'")
        lines.append("=" * self.console_width)
        lines.append("")
        
        if not results:
            lines.append("No modules found matching your query.")
            lines.append("")
            lines.append("Try:")
            lines.append("  - Using different keywords")
            lines.append("  - Checking spelling")
            lines.append("  - Using broader search terms")
            return "\n".join(lines)
        
        lines.append(f"Found {len(results)} matching module(s):")
        lines.append("")
        
        for i, module in enumerate(results, 1):
            lines.append(f"{i}. {module.display_name}")
            lines.append(f"   Command: {module.cli_command or 'N/A'}")
            lines.append(f"   Category: {self._get_category_display_name(module.category)}")
            lines.append(f"   Description: {module.description}")
            if module.tags:
                lines.append(f"   Tags: {', '.join(module.tags)}")
            lines.append("")
        
        return "\n".join(lines)
    
    def _format_parameter_text(self, param: Parameter, indent: int = 0) -> List[str]:
        """Format a parameter in text format"""
        lines = []
        prefix = " " * indent

        # Parameter name: --name or --name, -s
        flag = f"--{param.name}"
        if param.short_name:
            flag += f", -{param.short_name}"

        required_str = "  [Required]" if param.required else ""
        lines.append(f"{prefix}{flag}{required_str}")

        # Description
        if param.description:
            lines.extend(self._wrap_text(param.description, indent=indent + 2))

        # Type
        type_str = param.param_type.value if hasattr(param.param_type, "value") else str(param.param_type)
        lines.append(f"{prefix}  Type: {type_str}")

        # Default value
        if param.default_value is not None:
            lines.append(f"{prefix}  Default: {param.default_value}")

        # Choices
        if param.choices:
            lines.append(f"{prefix}  Choices: {', '.join(param.choices)}")

        # Examples
        if param.examples:
            lines.append(f"{prefix}  Examples: {', '.join(str(e) for e in param.examples)}")

        lines.append("")
        return lines
    
    def _format_example_text(self, example: Example, indent: int = 0) -> List[str]:
        """Format an example in text format"""
        lines = []
        prefix = " " * indent
        
        lines.append(f"{prefix}{example.title}:")
        lines.extend(self._wrap_text(example.description, indent=indent + 2))
        lines.append(f"{prefix}  $ {example.command}")
        
        if example.expected_output:
            lines.append(f"{prefix}  Expected: {example.expected_output}")
        
        if example.notes:
            lines.append(f"{prefix}  Notes:")
            for note in example.notes:
                lines.append(f"{prefix}    - {note}")
        
        lines.append("")
        return lines
    
    def _format_use_case_text(self, use_case: UseCase, indent: int = 0) -> List[str]:
        """Format a use case in text format"""
        lines = []
        prefix = " " * indent
        
        lines.append(f"{prefix}{use_case.title}:")
        lines.extend(self._wrap_text(use_case.description, indent=indent + 2))
        
        if use_case.scenario:
            lines.append(f"{prefix}  When to use: {use_case.scenario}")
        
        if use_case.steps:
            lines.append(f"{prefix}  Steps:")
            for i, step in enumerate(use_case.steps, 1):
                lines.append(f"{prefix}    {i}. {step}")
        
        lines.append("")
        return lines
    
    # JSON FORMAT IMPLEMENTATIONS
    
    def _format_general_help_json(self, modules_by_category: Dict[ModuleCategory, List[ModuleMetadata]]) -> str:
        """Format general help in JSON format"""
        data = {
            "title": "Spectra - Web Security Suite",
            "categories": {}
        }

        for category, modules in modules_by_category.items():
            if modules:
                data["categories"][category.value] = {
                    "name": self._format_category_name(category),
                    "modules": [
                        {
                            "name": module.name,
                            "display_name": module.display_name,
                            "description": module.description,
                            "cli_flags": getattr(module, "cli_flags", []),
                        }
                        for module in modules
                    ]
                }

        return json.dumps(data, indent=2)
    
    def _format_module_help_json(self, metadata: ModuleMetadata) -> str:
        """Format module help in JSON format"""
        return json.dumps(metadata.to_dict(), indent=2)
    
    def _format_category_help_json(self, category: ModuleCategory, modules: List[ModuleMetadata]) -> str:
        """Format category help in JSON format"""
        data = {
            "category": {
                "name": category.value,
                "display_name": self._format_category_name(category),
                "module_count": len(modules),
                "modules": [module.to_dict() for module in modules],
            }
        }
        return json.dumps(data, indent=2)
    
    def _format_search_results_json(self, query: str, results: List[ModuleMetadata]) -> str:
        """Format search results in JSON format"""
        data = {
            "query": query,
            "result_count": len(results),
            "results": [
                {
                    "name": module.name,
                    "display_name": module.display_name,
                    "category": module.category.value,
                    "description": module.description,
                    "cli_command": module.cli_command,
                    "tags": module.tags
                }
                for module in results
            ]
        }
        
        # Validate JSON if enabled
        if self.validate_json:
            validation_result = self.validator.validate_search_results(data)
            if not validation_result['valid']:
                # Log validation errors but still return the JSON
                from ..logger import get_logger
                logger = get_logger(__name__)
                logger.warning(f"Search results JSON validation failed: {validation_result['errors']}")
        
        return json.dumps(data, indent=2)
    
    # MARKDOWN FORMAT IMPLEMENTATIONS
    
    def _format_general_help_markdown(self, modules_by_category: Dict[ModuleCategory, List[ModuleMetadata]]) -> str:
        """Format general help in Markdown format"""
        lines = []
        
        lines.append("# Spectra - Web Security Suite")
        lines.append("")
        lines.append("Comprehensive security testing and analysis toolkit")
        lines.append("")
        lines.append("## Usage")
        lines.append("")
        lines.append("```bash")
        lines.append("spectra [OPTIONS] <command> [ARGS...]")
        lines.append("spectra --help <module>     # Get help for specific module")
        lines.append("spectra --search <query>    # Search modules")
        lines.append("```")
        lines.append("")
        
        # Table of contents
        lines.append("## Modules by Category")
        lines.append("")
        
        for category in ModuleCategory:
            modules = modules_by_category.get(category, [])
            if not modules:
                continue
                
            category_name = self._get_category_display_name(category)
            lines.append(f"### {category_name}")
            lines.append("")
            
            lines.append("| Command | Module | Description |")
            lines.append("|---------|--------|-------------|")
            
            for module in sorted(modules, key=lambda m: m.name):
                cli_cmd = module.cli_command or f"`--{module.name.replace('_', '-')}`"
                lines.append(f"| `{cli_cmd}` | {module.display_name} | {module.description} |")
            
            lines.append("")
        
        return "\n".join(lines)
    
    def _format_module_help_markdown(self, metadata: ModuleMetadata) -> str:
        """Format module help in Markdown format"""
        lines = []
        
        lines.append(f"# {metadata.display_name}")
        lines.append("")
        lines.append(metadata.description)
        lines.append("")
        
        # Module info table
        lines.append("## Module Information")
        lines.append("")
        lines.append("| Property | Value |")
        lines.append("|----------|-------|")
        lines.append(f"| Name | `{metadata.name}` |")
        lines.append(f"| Category | {self._get_category_display_name(metadata.category)} |")
        lines.append(f"| Version | {metadata.version} |")
        if metadata.cli_command:
            lines.append(f"| CLI Command | `{metadata.cli_command}` |")
        lines.append("")
        
        # Detailed description
        if metadata.detailed_description:
            lines.append("## Description")
            lines.append("")
            lines.append(metadata.detailed_description)
            lines.append("")
        
        # Parameters
        if metadata.parameters:
            lines.append("## Parameters")
            lines.append("")
            
            required_params = metadata.get_required_parameters()
            if required_params:
                lines.append("### Required Parameters")
                lines.append("")
                for param in required_params:
                    lines.extend(self._format_parameter_markdown(param))
            
            optional_params = metadata.get_optional_parameters()
            if optional_params:
                lines.append("### Optional Parameters")
                lines.append("")
                for param in optional_params:
                    lines.extend(self._format_parameter_markdown(param))
        
        # Examples
        if metadata.examples:
            lines.append("## Examples")
            lines.append("")
            
            for level in [ExampleLevel.BASIC, ExampleLevel.INTERMEDIATE, ExampleLevel.ADVANCED]:
                level_examples = metadata.get_examples_by_level(level)
                if level_examples:
                    lines.append(f"### {level.value.title()} Usage")
                    lines.append("")
                    for example in level_examples:
                        lines.extend(self._format_example_markdown(example))
        
        return "\n".join(lines)
    
    def _format_parameter_markdown(self, param: Parameter) -> List[str]:
        """Format parameter in Markdown"""
        lines = []
        
        # Parameter header
        param_name = f"`{param.name}`"
        if param.short_name:
            param_name += f" / `-{param.short_name}`"
        
        if param.required:
            param_name += " **[REQUIRED]**"
        
        lines.append(f"#### {param_name}")
        lines.append("")
        lines.append(param.description)
        lines.append("")
        
        # Details
        details = []
        if param.param_type.value != "string":
            details.append(f"**Type:** {param.param_type.value}")
        if param.default_value is not None:
            details.append(f"**Default:** `{param.default_value}`")
        if param.choices:
            choices_str = ", ".join(f"`{c}`" for c in param.choices)
            details.append(f"**Choices:** {choices_str}")
        if param.examples:
            examples_str = ", ".join(f"`{e}`" for e in param.examples)
            details.append(f"**Examples:** {examples_str}")
        
        if details:
            lines.extend(details)
            lines.append("")
        
        return lines
    
    def _format_example_markdown(self, example: Example) -> List[str]:
        """Format example in Markdown"""
        lines = []
        
        lines.append(f"#### {example.title}")
        lines.append("")
        lines.append(example.description)
        lines.append("")
        lines.append("```bash")
        lines.append(example.command)
        lines.append("```")
        lines.append("")
        
        if example.expected_output:
            lines.append(f"**Expected output:** {example.expected_output}")
            lines.append("")
        
        if example.notes:
            lines.append("**Notes:**")
            for note in example.notes:
                lines.append(f"- {note}")
            lines.append("")
        
        return lines
    
    # HTML FORMAT IMPLEMENTATIONS
    
    def _format_general_help_html(self, modules_by_category: Dict[ModuleCategory, List[ModuleMetadata]]) -> str:
        """Format general help in HTML format"""
        html = []
        
        html.append("<!DOCTYPE html>")
        html.append("<html>")
        html.append("<head>")
        html.append("    <title>Spectra - Web Security Suite</title>")
        html.append("    <style>")
        html.append("        body { font-family: Arial, sans-serif; margin: 40px; }")
        html.append("        h1 { color: #2c3e50; }")
        html.append("        h2 { color: #34495e; border-bottom: 2px solid #ecf0f1; }")
        html.append("        .module { margin: 10px 0; }")
        html.append("        .command { font-family: monospace; background: #f8f9fa; padding: 2px 4px; }")
        html.append("        table { border-collapse: collapse; width: 100%; }")
        html.append("        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }")
        html.append("        th { background-color: #f2f2f2; }")
        html.append("    </style>")
        html.append("</head>")
        html.append("<body>")
        
        html.append("    <h1>Spectra - Web Security Suite</h1>")
        html.append("    <p>Comprehensive security testing and analysis toolkit</p>")
        
        for category in ModuleCategory:
            modules = modules_by_category.get(category, [])
            if not modules:
                continue
                
            category_name = self._get_category_display_name(category)
            html.append(f"    <h2>{category_name}</h2>")
            html.append("    <table>")
            html.append("        <tr><th>Command</th><th>Module</th><th>Description</th></tr>")
            
            for module in sorted(modules, key=lambda m: m.name):
                cli_cmd = module.cli_command or f"--{module.name.replace('_', '-')}"
                html.append("        <tr>")
                html.append(f"            <td><span class='command'>{cli_cmd}</span></td>")
                html.append(f"            <td>{module.display_name}</td>")
                html.append(f"            <td>{module.description}</td>")
                html.append("        </tr>")
            
            html.append("    </table>")
        
        html.append("</body>")
        html.append("</html>")
        
        return "\n".join(html)
    
    def _format_module_help_html(self, metadata: ModuleMetadata) -> str:
        """Format module help in HTML format"""
        # Simplified HTML implementation
        return f"<h1>{metadata.display_name}</h1><p>{metadata.description}</p>"
    
    # UTILITY METHODS
    
    def _format_category_name(self, category: ModuleCategory) -> str:
        """Return human-readable category name."""
        return category.value.replace('_', ' ').title()

    def _format_parameter_name(self, param: Parameter) -> str:
        """Return formatted CLI flag string for a parameter."""
        if getattr(param, 'short_name', None):
            return f"--{param.name}, -{param.short_name}"
        return f"--{param.name}"

    def _get_category_display_name(self, category: ModuleCategory) -> str:
        """Get display name for category (legacy helper)."""
        return self._format_category_name(category)
    
    def _wrap_text(self, text: str, width: int = None, indent: int = 0) -> List[str]:
        """Wrap text to specified width with indentation"""
        if width is None:
            width = self.console_width - indent
        
        words = text.split()
        lines = []
        current_line = ""
        prefix = " " * indent
        
        for word in words:
            if len(current_line + word) + 1 <= width:
                if current_line:
                    current_line += " " + word
                else:
                    current_line = word
            else:
                if current_line:
                    lines.append(prefix + current_line)
                current_line = word
        
        if current_line:
            lines.append(prefix + current_line)
        
        return lines