# -*- coding: utf-8 -*-
"""
Help Formatter - Formats help output in various formats
"""

import json
import textwrap
from typing import List, Dict, Any, Optional
from ..module_metadata import ModuleMetadata, Parameter, Example, ModuleCategory, OutputFormat


class HelpFormatter:
    """Formats help content in various output formats"""
    
    def __init__(self, width: int = 80, indent: int = 2):
        """
        Initialize formatter
        
        Args:
            width: Maximum line width for text formatting
            indent: Number of spaces for indentation
        """
        self.width = width
        self.indent = indent
        self.indent_str = " " * indent
    
    def format_general_help(self, modules: Dict[ModuleCategory, List[ModuleMetadata]], 
                          format: OutputFormat = OutputFormat.TEXT) -> str:
        """
        Format general help showing all modules organized by category
        
        Args:
            modules: Dictionary of categories to module lists
            format: Output format
            
        Returns:
            Formatted help string
        """
        if format == OutputFormat.TEXT:
            return self._format_general_help_text(modules)
        elif format == OutputFormat.JSON:
            return self._format_general_help_json(modules)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def format_module_help(self, metadata: ModuleMetadata, 
                          format: OutputFormat = OutputFormat.TEXT,
                          include_examples: bool = True,
                          include_parameters: bool = True) -> str:
        """
        Format help for a specific module
        
        Args:
            metadata: Module metadata
            format: Output format
            include_examples: Whether to include examples
            include_parameters: Whether to include parameters
            
        Returns:
            Formatted help string
        """
        if format == OutputFormat.TEXT:
            return self._format_module_help_text(metadata, include_examples, include_parameters)
        elif format == OutputFormat.JSON:
            return self._format_module_help_json(metadata)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def format_examples(self, examples: List[Example], 
                       format: OutputFormat = OutputFormat.TEXT,
                       level_filter: Optional[str] = None) -> str:
        """
        Format examples
        
        Args:
            examples: List of examples
            format: Output format
            level_filter: Filter by level (basic, intermediate, advanced)
            
        Returns:
            Formatted examples string
        """
        if level_filter:
            examples = [ex for ex in examples if ex.level == level_filter]
        
        if format == OutputFormat.TEXT:
            return self._format_examples_text(examples)
        elif format == OutputFormat.JSON:
            return self._format_examples_json(examples)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def format_parameters(self, parameters: List[Parameter], 
                         format: OutputFormat = OutputFormat.TEXT,
                         group_by: Optional[str] = None) -> str:
        """
        Format parameters
        
        Args:
            parameters: List of parameters
            format: Output format
            group_by: Group parameters by field (help_group, required, etc.)
            
        Returns:
            Formatted parameters string
        """
        if format == OutputFormat.TEXT:
            return self._format_parameters_text(parameters, group_by)
        elif format == OutputFormat.JSON:
            return self._format_parameters_json(parameters)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def format_category_help(self, category: ModuleCategory, 
                           modules: List[ModuleMetadata],
                           format: OutputFormat = OutputFormat.TEXT) -> str:
        """
        Format help for a specific category
        
        Args:
            category: Module category
            modules: List of modules in category
            format: Output format
            
        Returns:
            Formatted category help string
        """
        if format == OutputFormat.TEXT:
            return self._format_category_help_text(category, modules)
        elif format == OutputFormat.JSON:
            return self._format_category_help_json(category, modules)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _format_general_help_text(self, modules: Dict[ModuleCategory, List[ModuleMetadata]]) -> str:
        """Format general help in text format"""
        lines = []
        lines.append("Spectra - Web Security Suite")
        lines.append("=" * 50)
        lines.append("")
        lines.append("Available modules organized by category:")
        lines.append("")
        
        for category, module_list in modules.items():
            if not module_list:
                continue
                
            # Category header
            category_name = self._format_category_name(category)
            lines.append(f"[{category_name}]")
            lines.append("-" * (len(category_name) + 2))
            
            # Module list
            for module in sorted(module_list, key=lambda m: m.name):
                # Format CLI flags
                flags = ", ".join(module.cli_flags) if module.cli_flags else f"--{module.name.replace('_', '-')}"
                
                # Format description with proper wrapping
                desc_lines = textwrap.wrap(module.description, 
                                         width=self.width - 20, 
                                         initial_indent="",
                                         subsequent_indent=" " * 20)
                
                lines.append(f"  {flags:<18} {desc_lines[0] if desc_lines else ''}")
                for desc_line in desc_lines[1:]:
                    lines.append(f"  {'':<18} {desc_line}")
            
            lines.append("")
        
        # Footer with usage info
        lines.append("Usage:")
        lines.append("  spectra <module> [options]")
        lines.append("  spectra --help <module>     Show help for specific module")
        lines.append("  spectra --help <category>   Show help for module category")
        lines.append("")
        lines.append("For detailed help on any module, use: spectra --help <module-name>")
        
        return "\n".join(lines)
    
    def _format_module_help_text(self, metadata: ModuleMetadata, 
                               include_examples: bool = True,
                               include_parameters: bool = True) -> str:
        """Format module help in text format"""
        lines = []
        
        # Header
        lines.append(f"{metadata.display_name}")
        lines.append("=" * len(metadata.display_name))
        lines.append("")
        
        # Basic info
        lines.append(f"Module: {metadata.name}")
        lines.append(f"Category: {self._format_category_name(metadata.category)}")
        if metadata.tags:
            lines.append(f"Tags: {', '.join(metadata.tags)}")
        lines.append("")
        
        # Description
        lines.append("Description:")
        desc_lines = textwrap.wrap(metadata.detailed_description, 
                                 width=self.width - self.indent)
        for line in desc_lines:
            lines.append(f"{self.indent_str}{line}")
        lines.append("")
        
        # CLI Usage
        if metadata.cli_flags:
            lines.append("Usage:")
            primary_flag = metadata.cli_flags[0]
            lines.append(f"{self.indent_str}spectra {primary_flag} [options]")
            if len(metadata.cli_flags) > 1:
                other_flags = ", ".join(metadata.cli_flags[1:])
                lines.append(f"{self.indent_str}Aliases: {other_flags}")
            lines.append("")
        
        # Parameters
        if include_parameters:
            if metadata.parameters:
                lines.append("Parameters:")
                lines.append(self._format_parameters_text(metadata.parameters))
                lines.append("")
            else:
                lines.append("Parameters:")
                lines.append(f"{self.indent_str}No parameters available.")
                lines.append("")
        
        # Examples
        if include_examples:
            if metadata.examples:
                lines.append("Examples:")
                lines.append(self._format_examples_text(metadata.examples))
                lines.append("")
            else:
                lines.append("Examples:")
                lines.append(f"{self.indent_str}No examples available.")
                lines.append("")
        
        # Use cases
        if metadata.use_cases:
            lines.append("Common Use Cases:")
            for i, use_case in enumerate(metadata.use_cases, 1):
                lines.append(f"{self.indent_str}{i}. {use_case.title}")
                lines.append(f"{self.indent_str}   {use_case.description}")
                if use_case.scenario:
                    lines.append(f"{self.indent_str}   When: {use_case.scenario}")
                lines.append("")
        
        # Related modules
        if metadata.related_modules:
            lines.append("Related Modules:")
            lines.append(f"{self.indent_str}{', '.join(metadata.related_modules)}")
            lines.append("")
        
        return "\n".join(lines)
    
    def _format_parameters_text(self, parameters: List[Parameter], 
                              group_by: Optional[str] = None) -> str:
        """Format parameters in text format"""
        if not parameters:
            return f"{self.indent_str}No parameters available."
        
        lines = []
        
        if group_by == "required":
            # Group by required/optional
            required = [p for p in parameters if p.required]
            optional = [p for p in parameters if not p.required]
            
            if required:
                lines.append(f"{self.indent_str}Required:")
                lines.extend(self._format_parameter_list(required, self.indent * 2))
                lines.append("")
            
            if optional:
                lines.append(f"{self.indent_str}Optional:")
                lines.extend(self._format_parameter_list(optional, self.indent * 2))
        
        elif group_by == "help_group":
            # Group by help group
            groups = {}
            ungrouped = []
            
            for param in parameters:
                if param.help_group:
                    if param.help_group not in groups:
                        groups[param.help_group] = []
                    groups[param.help_group].append(param)
                else:
                    ungrouped.append(param)
            
            # Show grouped parameters
            for group_name, group_params in groups.items():
                lines.append(f"{self.indent_str}{group_name}:")
                lines.extend(self._format_parameter_list(group_params, self.indent * 2))
                lines.append("")
            
            # Show ungrouped parameters
            if ungrouped:
                lines.append(f"{self.indent_str}General:")
                lines.extend(self._format_parameter_list(ungrouped, self.indent * 2))
        
        else:
            # No grouping
            lines.extend(self._format_parameter_list(parameters, self.indent))
        
        return "\n".join(lines)
    
    def _format_parameter_list(self, parameters: List[Parameter], indent_level: int) -> List[str]:
        """Format a list of parameters with consistent alignment"""
        lines = []
        indent_str = " " * indent_level
        
        # Calculate max width for parameter names for alignment
        max_name_width = max(len(self._format_parameter_name(p)) for p in parameters)
        max_name_width = min(max_name_width, 25)  # Cap at reasonable width
        
        for param in parameters:
            param_name = self._format_parameter_name(param)
            
            # Format parameter line
            param_line = f"{indent_str}{param_name:<{max_name_width}} {param.description}"
            
            # Wrap long lines
            if len(param_line) > self.width:
                # Split and wrap description
                desc_width = self.width - indent_level - max_name_width - 1
                desc_lines = textwrap.wrap(param.description, width=desc_width)
                
                lines.append(f"{indent_str}{param_name:<{max_name_width}} {desc_lines[0] if desc_lines else ''}")
                for desc_line in desc_lines[1:]:
                    lines.append(f"{indent_str}{'':<{max_name_width}} {desc_line}")
            else:
                lines.append(param_line)
            
            # Add additional parameter info
            info_parts = []
            
            if param.param_type.value != "str":
                info_parts.append(f"Type: {param.param_type.value}")
            
            if param.required:
                info_parts.append("Required")
            elif param.default_value is not None:
                info_parts.append(f"Default: {param.default_value}")
            
            if param.choices:
                choices_str = ", ".join(str(c) for c in param.choices[:5])
                if len(param.choices) > 5:
                    choices_str += "..."
                info_parts.append(f"Choices: {choices_str}")
            
            if param.examples:
                examples_str = ", ".join(str(e) for e in param.examples[:3])
                if len(param.examples) > 3:
                    examples_str += "..."
                info_parts.append(f"Examples: {examples_str}")
            
            if info_parts:
                info_line = f"{indent_str}{'':<{max_name_width}} ({'; '.join(info_parts)})"
                lines.append(info_line)
            
            lines.append("")  # Empty line between parameters
        
        return lines
    
    def _format_parameter_name(self, param: Parameter) -> str:
        """Format parameter name with short name if available"""
        if param.short_name:
            return f"--{param.name}, -{param.short_name}"
        else:
            return f"--{param.name}"
    
    def _format_examples_text(self, examples: List[Example]) -> str:
        """Format examples in text format"""
        if not examples:
            return f"{self.indent_str}No examples available."
        
        lines = []
        
        # Group examples by level
        levels = ["basic", "intermediate", "advanced"]
        for level in levels:
            level_examples = [ex for ex in examples if ex.level == level]
            if not level_examples:
                continue
            
            lines.append(f"{self.indent_str}{level.title()} Examples:")
            
            for i, example in enumerate(level_examples, 1):
                lines.append(f"{self.indent_str * 2}{i}. {example.title}")
                
                # Description
                desc_lines = textwrap.wrap(example.description, 
                                         width=self.width - self.indent * 3)
                for desc_line in desc_lines:
                    lines.append(f"{self.indent_str * 3}{desc_line}")
                
                # Command
                lines.append(f"{self.indent_str * 3}$ {example.command}")
                
                # Prerequisites
                if example.prerequisites:
                    lines.append(f"{self.indent_str * 3}Prerequisites: {', '.join(example.prerequisites)}")
                
                # Notes
                if example.notes:
                    note_lines = textwrap.wrap(example.notes, 
                                             width=self.width - self.indent * 3)
                    lines.append(f"{self.indent_str * 3}Note: {note_lines[0]}")
                    for note_line in note_lines[1:]:
                        lines.append(f"{self.indent_str * 3}      {note_line}")
                
                lines.append("")  # Empty line between examples
            
            lines.append("")  # Empty line between levels
        
        return "\n".join(lines)
    
    def _format_category_help_text(self, category: ModuleCategory, 
                                 modules: List[ModuleMetadata]) -> str:
        """Format category help in text format"""
        lines = []
        
        category_name = self._format_category_name(category)
        lines.append(f"{category_name} Modules")
        lines.append("=" * (len(category_name) + 8))
        lines.append("")
        
        lines.append(f"Category: {category_name}")
        lines.append(f"Modules: {len(modules)}")
        lines.append("")
        
        # Category description
        category_descriptions = {
            ModuleCategory.RECONNAISSANCE: "Modules for information gathering and enumeration",
            ModuleCategory.SECURITY_ANALYSIS: "Modules for security assessment and analysis",
            ModuleCategory.VULNERABILITY_DETECTION: "Modules for detecting security vulnerabilities",
            ModuleCategory.CRYPTOGRAPHY: "Modules for cryptographic operations and password cracking",
            ModuleCategory.MONITORING: "Modules for monitoring and network analysis",
            ModuleCategory.INTEGRATION: "Modules for integration and reporting"
        }
        
        if category in category_descriptions:
            lines.append("Description:")
            desc_lines = textwrap.wrap(category_descriptions[category], 
                                     width=self.width - self.indent)
            for line in desc_lines:
                lines.append(f"{self.indent_str}{line}")
            lines.append("")
        
        # Module list
        lines.append("Available Modules:")
        for module in sorted(modules, key=lambda m: m.name):
            flags = ", ".join(module.cli_flags) if module.cli_flags else f"--{module.name.replace('_', '-')}"
            lines.append(f"{self.indent_str}{flags}")
            
            # Description with proper indentation
            desc_lines = textwrap.wrap(module.description, 
                                     width=self.width - self.indent * 2)
            for desc_line in desc_lines:
                lines.append(f"{self.indent_str * 2}{desc_line}")
            
            lines.append("")
        
        lines.append("For detailed help on any module, use: spectra --help <module-name>")
        
        return "\n".join(lines)
    
    def _format_category_name(self, category: ModuleCategory) -> str:
        """Format category name for display"""
        return category.value.replace("_", " ").title()
    
    # JSON formatting methods
    def _format_general_help_json(self, modules: Dict[ModuleCategory, List[ModuleMetadata]]) -> str:
        """Format general help in JSON format"""
        data = {
            "title": "Spectra - Web Security Suite",
            "categories": {}
        }
        
        for category, module_list in modules.items():
            data["categories"][category.value] = {
                "name": self._format_category_name(category),
                "modules": [
                    {
                        "name": module.name,
                        "display_name": module.display_name,
                        "description": module.description,
                        "cli_flags": module.cli_flags,
                        "tags": module.tags
                    }
                    for module in module_list
                ]
            }
        
        return json.dumps(data, indent=2)
    
    def _format_module_help_json(self, metadata: ModuleMetadata) -> str:
        """Format module help in JSON format"""
        return json.dumps(metadata.to_dict(), indent=2)
    
    def _format_examples_json(self, examples: List[Example]) -> str:
        """Format examples in JSON format"""
        data = {
            "examples": [
                {
                    "title": ex.title,
                    "description": ex.description,
                    "command": ex.command,
                    "level": ex.level,
                    "category": ex.category,
                    "prerequisites": ex.prerequisites,
                    "notes": ex.notes
                }
                for ex in examples
            ]
        }
        return json.dumps(data, indent=2)
    
    def _format_parameters_json(self, parameters: List[Parameter]) -> str:
        """Format parameters in JSON format"""
        data = {
            "parameters": [
                {
                    "name": param.name,
                    "short_name": param.short_name,
                    "description": param.description,
                    "type": param.param_type.value,
                    "required": param.required,
                    "default_value": param.default_value,
                    "choices": param.choices,
                    "examples": param.examples,
                    "help_group": param.help_group
                }
                for param in parameters
            ]
        }
        return json.dumps(data, indent=2)
    
    def _format_category_help_json(self, category: ModuleCategory, 
                                 modules: List[ModuleMetadata]) -> str:
        """Format category help in JSON format"""
        data = {
            "category": {
                "name": category.value,
                "display_name": self._format_category_name(category),
                "module_count": len(modules),
                "modules": [
                    {
                        "name": module.name,
                        "display_name": module.display_name,
                        "description": module.description,
                        "cli_flags": module.cli_flags
                    }
                    for module in modules
                ]
            }
        }
        return json.dumps(data, indent=2)