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
    
    def __init__(self):
        self.console_width = 80
        self.indent_size = 2
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
                          format_type: OutputFormat = OutputFormat.TEXT) -> str:
        """
        Format detailed help for a specific module
        
        Args:
            metadata: Module metadata
            format_type: Output format
            
        Returns:
            Formatted help string
        """
        if format_type == OutputFormat.TEXT:
            return self._format_module_help_text(metadata)
        elif format_type == OutputFormat.JSON:
            return self._format_module_help_json(metadata)
        elif format_type == OutputFormat.MARKDOWN:
            return self._format_module_help_markdown(metadata)
        elif format_type == OutputFormat.HTML:
            return self._format_module_help_html(metadata)
        else:
            return self._format_module_help_text(metadata)
    
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
        lines = []
        
        # Header
        lines.append("=" * self.console_width)
        lines.append("SPECTRA - Web Security Suite")
        lines.append("Comprehensive security testing and analysis toolkit")
        lines.append("=" * self.console_width)
        lines.append("")
        
        # Usage
        lines.append("USAGE:")
        lines.append("  spectra [OPTIONS] <command> [ARGS...]")
        lines.append("  spectra --help <module>     # Get help for specific module")
        lines.append("  spectra --search <query>    # Search modules")
        lines.append("")
        
        # Categories
        for category in ModuleCategory:
            modules = modules_by_category.get(category, [])
            if not modules:
                continue
                
            lines.append(f"{self._get_category_display_name(category).upper()}:")
            lines.append("")
            
            for module in sorted(modules, key=lambda m: m.name):
                cli_cmd = module.cli_command or f"--{module.name.replace('_', '-')}"
                lines.append(f"  {cli_cmd:<15} {module.description}")
            
            lines.append("")
        
        # Footer
        lines.append("EXAMPLES:")
        lines.append("  spectra -ps example.com                    # Port scan")
        lines.append("  spectra -ds https://example.com -w dirs.txt # Directory scan")
        lines.append("  spectra -hc 5d41402abc4b2a76b9719d911017c592 # Hash crack")
        lines.append("  spectra --help port_scanner                # Module help")
        lines.append("")
        lines.append("For detailed help on any module, use: spectra --help <module_name>")
        lines.append("For more information, visit: https://github.com/spectra-team/spectra")
        
        return "\n".join(lines)
    
    def _format_module_help_text(self, metadata: ModuleMetadata) -> str:
        """Format module help in text format"""
        lines = []
        
        # Header
        lines.append("=" * self.console_width)
        lines.append(f"{metadata.display_name.upper()} - {metadata.description}")
        lines.append("=" * self.console_width)
        lines.append("")
        
        # Basic info
        lines.append("MODULE INFORMATION:")
        lines.append(f"  Name:        {metadata.name}")
        lines.append(f"  Category:    {self._get_category_display_name(metadata.category)}")
        lines.append(f"  Version:     {metadata.version}")
        if metadata.cli_command:
            lines.append(f"  CLI Command: {metadata.cli_command}")
        lines.append("")
        
        # Detailed description
        if metadata.detailed_description:
            lines.append("DESCRIPTION:")
            lines.extend(self._wrap_text(metadata.detailed_description, indent=2))
            lines.append("")
        
        # Parameters
        if metadata.parameters:
            lines.append("PARAMETERS:")
            lines.append("")
            
            # Required parameters first
            required_params = metadata.get_required_parameters()
            if required_params:
                lines.append("  Required:")
                for param in required_params:
                    lines.extend(self._format_parameter_text(param, indent=4))
                lines.append("")
            
            # Optional parameters
            optional_params = metadata.get_optional_parameters()
            if optional_params:
                lines.append("  Optional:")
                for param in optional_params:
                    lines.extend(self._format_parameter_text(param, indent=4))
                lines.append("")
        
        # Examples
        if metadata.examples:
            lines.append("EXAMPLES:")
            lines.append("")
            
            # Group by level
            for level in [ExampleLevel.BASIC, ExampleLevel.INTERMEDIATE, ExampleLevel.ADVANCED]:
                level_examples = metadata.get_examples_by_level(level)
                if level_examples:
                    lines.append(f"  {level.value.title()} Usage:")
                    for example in level_examples:
                        lines.extend(self._format_example_text(example, indent=4))
                    lines.append("")
        
        # Use cases
        if metadata.use_cases:
            lines.append("USE CASES:")
            lines.append("")
            for use_case in metadata.use_cases:
                lines.extend(self._format_use_case_text(use_case, indent=2))
            lines.append("")
        
        # Related modules
        if metadata.related_modules:
            lines.append("RELATED MODULES:")
            related_list = ", ".join(metadata.related_modules)
            lines.extend(self._wrap_text(related_list, indent=2))
            lines.append("")
        
        return "\n".join(lines)
    
    def _format_category_help_text(self, category: ModuleCategory, modules: List[ModuleMetadata]) -> str:
        """Format category help in text format"""
        lines = []
        
        category_name = self._get_category_display_name(category)
        lines.append("=" * self.console_width)
        lines.append(f"{category_name.upper()} MODULES")
        lines.append("=" * self.console_width)
        lines.append("")
        
        lines.append(f"Category: {category_name}")
        lines.append(f"Modules:  {len(modules)}")
        lines.append("")
        
        for module in sorted(modules, key=lambda m: m.name):
            lines.append(f"{module.display_name}:")
            lines.append(f"  Command:     {module.cli_command or 'N/A'}")
            lines.append(f"  Description: {module.description}")
            if module.tags:
                lines.append(f"  Tags:        {', '.join(module.tags)}")
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
        
        # Parameter name and type
        param_line = f"{prefix}{param.name}"
        if param.short_name:
            param_line += f", -{param.short_name}"
        
        if param.param_type.value != "string":
            param_line += f" ({param.param_type.value})"
        
        if param.required:
            param_line += " [REQUIRED]"
        
        lines.append(param_line)
        
        # Description
        if param.description:
            lines.extend(self._wrap_text(param.description, indent=indent + 2))
        
        # Default value
        if param.default_value is not None:
            lines.append(f"{prefix}  Default: {param.default_value}")
        
        # Choices
        if param.choices:
            choices_str = ", ".join(param.choices)
            lines.append(f"{prefix}  Choices: {choices_str}")
        
        # Examples
        if param.examples:
            examples_str = ", ".join(param.examples)
            lines.append(f"{prefix}  Examples: {examples_str}")
        
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
            "spectra_help": {
                "version": "3.3.0",
                "description": "Spectra Web Security Suite",
                "categories": {}
            }
        }
        
        for category, modules in modules_by_category.items():
            if modules:
                data["spectra_help"]["categories"][category.value] = {
                    "name": self._get_category_display_name(category),
                    "modules": [
                        {
                            "name": module.name,
                            "display_name": module.display_name,
                            "description": module.description,
                            "cli_command": module.cli_command,
                            "version": module.version
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
            "category": category.value,
            "display_name": self._get_category_display_name(category),
            "module_count": len(modules),
            "modules": [module.to_dict() for module in modules]
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
    
    def _get_category_display_name(self, category: ModuleCategory) -> str:
        """Get display name for category"""
        display_names = {
            ModuleCategory.RECONNAISSANCE: "Reconnaissance & Enumeration",
            ModuleCategory.SECURITY_ANALYSIS: "Security Analysis",
            ModuleCategory.VULNERABILITY_DETECTION: "Vulnerability Detection",
            ModuleCategory.CRYPTOGRAPHY: "Cryptography & Password Cracking",
            ModuleCategory.MONITORING: "Monitoring & Analysis",
            ModuleCategory.INTEGRATION: "Integration & Reporting"
        }
        return display_names.get(category, category.value.replace('_', ' ').title())
    
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