# -*- coding: utf-8 -*-
"""
Help Manager - Central coordinator for the help system
"""

from typing import List, Dict, Optional, Union
from collections import defaultdict

from .module_registry import ModuleRegistry, ModuleNotFoundError
from .help_formatter import HelpFormatter
from ..module_metadata import ModuleMetadata, ModuleCategory, OutputFormat


class HelpSystemError(Exception):
    """Base exception for help system errors"""
    pass


class HelpManager:
    """Central coordinator for the help system"""
    
    def __init__(self, registry: Optional[ModuleRegistry] = None, 
                 formatter: Optional[HelpFormatter] = None):
        """
        Initialize HelpManager
        
        Args:
            registry: Module registry instance (creates new if None)
            formatter: Help formatter instance (creates new if None)
        """
        self.registry = registry or ModuleRegistry()
        self.formatter = formatter or HelpFormatter()
        
        # Auto-discover modules on initialization
        self._auto_discover_modules()
    
    def get_general_help(self, format: Union[str, OutputFormat] = OutputFormat.TEXT) -> str:
        """
        Get general help showing all modules organized by category
        
        Args:
            format: Output format (text, json, etc.)
            
        Returns:
            Formatted general help string
        """
        if isinstance(format, str):
            format = OutputFormat(format.lower())
        
        # Organize modules by category
        modules_by_category = defaultdict(list)
        for module in self.registry.get_all_modules():
            modules_by_category[module.category].append(module)
        
        return self.formatter.format_general_help(dict(modules_by_category), format)
    
    def get_module_help(self, module_name: str, 
                       format: Union[str, OutputFormat] = OutputFormat.TEXT,
                       include_examples: bool = True,
                       include_parameters: bool = True) -> str:
        """
        Get help for a specific module
        
        Args:
            module_name: Name of the module
            format: Output format
            include_examples: Whether to include examples
            include_parameters: Whether to include parameters
            
        Returns:
            Formatted module help string
            
        Raises:
            ModuleNotFoundError: If module not found
        """
        if isinstance(format, str):
            format = OutputFormat(format.lower())
        
        try:
            metadata = self.registry.get_module(module_name)
            return self.formatter.format_module_help(
                metadata, format, include_examples, include_parameters
            )
        except ModuleNotFoundError:
            # Try to find by CLI flag
            metadata = self.registry.get_module_by_cli_flag(module_name)
            if metadata:
                return self.formatter.format_module_help(
                    metadata, format, include_examples, include_parameters
                )
            raise
    
    def get_category_help(self, category_name: str,
                         format: Union[str, OutputFormat] = OutputFormat.TEXT) -> str:
        """
        Get help for a specific category
        
        Args:
            category_name: Name of the category
            format: Output format
            
        Returns:
            Formatted category help string
            
        Raises:
            ValueError: If category not found
        """
        if isinstance(format, str):
            format = OutputFormat(format.lower())
        
        # Try to find category by name
        category = None
        for cat in ModuleCategory:
            if (cat.value == category_name.lower() or 
                cat.value.replace("_", " ") == category_name.lower() or
                cat.value.replace("_", "-") == category_name.lower()):
                category = cat
                break
        
        if not category:
            available_categories = [cat.value for cat in ModuleCategory]
            raise ValueError(f"Category '{category_name}' not found. Available: {', '.join(available_categories)}")
        
        modules = self.registry.get_modules_by_category(category)
        return self.formatter.format_category_help(category, modules, format)
    
    def search_modules(self, query: str, limit: int = 10) -> List[ModuleMetadata]:
        """
        Search modules by query string
        
        Args:
            query: Search query
            limit: Maximum number of results
            
        Returns:
            List of matching modules
        """
        return self.registry.search_modules(query, limit)
    
    def search_parameters(self, query: str, limit: int = 20) -> List[tuple]:
        """
        Search parameters across all modules
        
        Args:
            query: Search query
            limit: Maximum number of results
            
        Returns:
            List of tuples (module_metadata, parameter)
        """
        return self.registry.search_parameters(query, limit)
    
    def get_module_suggestions(self, partial_name: str, limit: int = 5) -> List[str]:
        """
        Get module name suggestions for partial input
        
        Args:
            partial_name: Partial module name
            limit: Maximum number of suggestions
            
        Returns:
            List of suggested module names
        """
        all_names = self.registry.get_module_names()
        
        # Exact matches first
        exact_matches = [name for name in all_names if partial_name.lower() in name.lower()]
        
        # Fuzzy matches
        import difflib
        fuzzy_matches = difflib.get_close_matches(partial_name, all_names, n=limit, cutoff=0.3)
        
        # Combine and deduplicate
        suggestions = []
        for name in exact_matches + fuzzy_matches:
            if name not in suggestions:
                suggestions.append(name)
        
        return suggestions[:limit]
    
    def get_related_modules(self, module_name: str) -> List[ModuleMetadata]:
        """
        Get modules related to the specified module
        
        Args:
            module_name: Name of the module
            
        Returns:
            List of related modules
        """
        return self.registry.get_related_modules(module_name)
    
    def register_module(self, metadata: ModuleMetadata, allow_override: bool = False) -> None:
        """
        Register a new module
        
        Args:
            metadata: Module metadata
            allow_override: Whether to allow overriding existing modules
        """
        self.registry.register_module(metadata, allow_override)
    
    def unregister_module(self, module_name: str) -> bool:
        """
        Unregister a module
        
        Args:
            module_name: Name of module to unregister
            
        Returns:
            True if module was unregistered, False if not found
        """
        return self.registry.unregister_module(module_name)
    
    def get_statistics(self) -> Dict[str, any]:
        """Get help system statistics"""
        registry_stats = self.registry.get_statistics()
        
        return {
            **registry_stats,
            'help_system_version': '1.0.0',
            'supported_formats': [fmt.value for fmt in OutputFormat],
            'auto_discovery_enabled': self.registry._auto_discovery_enabled
        }
    
    def validate_all_modules(self):
        """Validate all registered modules"""
        return self.registry.validate_all_modules()
    
    def export_help_data(self, format: Union[str, OutputFormat] = OutputFormat.JSON) -> str:
        """
        Export all help data in specified format
        
        Args:
            format: Export format
            
        Returns:
            Exported data string
        """
        if isinstance(format, str):
            format = OutputFormat(format.lower())
        
        if format == OutputFormat.JSON:
            return self.registry.export_registry('json')
        else:
            raise ValueError(f"Export format {format} not supported")
    
    def get_help_for_cli_flag(self, flag: str, 
                             format: Union[str, OutputFormat] = OutputFormat.TEXT) -> Optional[str]:
        """
        Get help for a CLI flag
        
        Args:
            flag: CLI flag (e.g., '-ps', '--port-scan')
            format: Output format
            
        Returns:
            Formatted help string or None if flag not found
        """
        metadata = self.registry.get_module_by_cli_flag(flag)
        if metadata:
            if isinstance(format, str):
                format = OutputFormat(format.lower())
            return self.formatter.format_module_help(metadata, format)
        return None
    
    def get_examples_for_module(self, module_name: str, 
                               level: Optional[str] = None,
                               format: Union[str, OutputFormat] = OutputFormat.TEXT) -> str:
        """
        Get examples for a specific module
        
        Args:
            module_name: Name of the module
            level: Filter by level (basic, intermediate, advanced)
            format: Output format
            
        Returns:
            Formatted examples string
        """
        if isinstance(format, str):
            format = OutputFormat(format.lower())
        
        metadata = self.registry.get_module(module_name)
        return self.formatter.format_examples(metadata.examples, format, level)
    
    def get_parameters_for_module(self, module_name: str,
                                 group_by: Optional[str] = None,
                                 format: Union[str, OutputFormat] = OutputFormat.TEXT) -> str:
        """
        Get parameters for a specific module
        
        Args:
            module_name: Name of the module
            group_by: Group parameters by field (required, help_group)
            format: Output format
            
        Returns:
            Formatted parameters string
        """
        if isinstance(format, str):
            format = OutputFormat(format.lower())
        
        metadata = self.registry.get_module(module_name)
        return self.formatter.format_parameters(metadata.parameters, format, group_by)
    
    def _auto_discover_modules(self) -> None:
        """Auto-discover modules if enabled"""
        try:
            discovered_count = self.registry.auto_discover_modules()
            if discovered_count > 0:
                print(f"Auto-discovered {discovered_count} modules")
        except Exception as e:
            # Log warning but don't fail initialization
            print(f"Warning: Auto-discovery failed: {e}")
    
    def reload_modules(self) -> int:
        """
        Reload all modules from discovery paths
        
        Returns:
            Number of modules reloaded
        """
        # Clear existing modules
        self.registry.clear()
        
        # Re-discover
        return self.registry.auto_discover_modules()
    
    def get_module_count(self) -> int:
        """Get total number of registered modules"""
        return len(self.registry)
    
    def get_category_count(self) -> int:
        """Get number of categories with modules"""
        return len(self.registry.get_all_categories())
    
    def is_module_registered(self, module_name: str) -> bool:
        """Check if a module is registered"""
        return module_name in self.registry
    
    def get_all_module_names(self) -> List[str]:
        """Get list of all registered module names"""
        return self.registry.get_module_names()
    
    def get_all_categories(self) -> List[str]:
        """Get list of all category names"""
        return self.registry.get_category_names()
    
    def __repr__(self) -> str:
        """String representation"""
        return f"HelpManager({self.get_module_count()} modules, {self.get_category_count()} categories)"