# -*- coding: utf-8 -*-
"""
Help Manager for Spectra - Central coordinator for help system
"""

from typing import Dict, List, Optional, Tuple
from collections import defaultdict

from .module_registry import ModuleRegistry, get_registry
from .help_formatter import HelpFormatter, OutputFormat
from ..module_metadata import ModuleMetadata, ModuleCategory, ValidationResult
from ..logger import get_logger

logger = get_logger(__name__)


class HelpSearchResult:
    """Represents a help search result"""
    
    def __init__(self, module: ModuleMetadata, score: float, match_type: str):
        self.module = module
        self.score = score
        self.match_type = match_type  # 'name', 'description', 'tag', etc.


class HelpManager:
    """Central manager for the help system"""
    
    def __init__(self, registry: Optional[ModuleRegistry] = None):
        self.registry = registry or get_registry()
        self.formatter = HelpFormatter()
        self._cache = {}
        self._cache_enabled = True
        
    def get_general_help(self, format_type: OutputFormat = OutputFormat.TEXT) -> str:
        """
        Get general help showing all modules organized by category
        
        Args:
            format_type: Output format
            
        Returns:
            Formatted help string
        """
        cache_key = f"general_help_{format_type.value}"
        
        if self._cache_enabled and cache_key in self._cache:
            return self._cache[cache_key]
        
        try:
            # Ensure registry is initialized
            if not self.registry.is_initialized():
                self.registry.auto_discover_modules()
            
            # Get modules organized by category
            modules_by_category = {}
            for category in ModuleCategory:
                modules = self.registry.get_modules_by_category(category)
                if modules:
                    modules_by_category[category] = modules
            
            # Format the help
            help_text = self.formatter.format_general_help(modules_by_category, format_type)
            
            # Cache the result
            if self._cache_enabled:
                self._cache[cache_key] = help_text
            
            return help_text
            
        except Exception as e:
            logger.error(f"Failed to generate general help: {e}")
            return f"Error generating help: {e}"
    
    def get_module_help(self, module_name: str, format_type: OutputFormat = OutputFormat.TEXT) -> str:
        """
        Get detailed help for a specific module
        
        Args:
            module_name: Name of the module or CLI command
            format_type: Output format
            
        Returns:
            Formatted help string or error message
        """
        cache_key = f"module_help_{module_name}_{format_type.value}"
        
        if self._cache_enabled and cache_key in self._cache:
            return self._cache[cache_key]
        
        try:
            # Get module metadata
            metadata = self.registry.get_module(module_name)
            
            if not metadata:
                # Try to find suggestions
                suggestions = self.registry.get_module_suggestions(module_name)
                error_msg = f"Module '{module_name}' not found."
                
                if suggestions:
                    error_msg += f"\n\nDid you mean one of these?\n"
                    for suggestion in suggestions:
                        error_msg += f"  - {suggestion}\n"
                    error_msg += f"\nUse 'spectra --help {suggestions[0]}' for help on that module."
                else:
                    error_msg += f"\n\nUse 'spectra --help' to see all available modules."
                
                return error_msg
            
            # Format the help
            help_text = self.formatter.format_module_help(metadata, format_type)
            
            # Cache the result
            if self._cache_enabled:
                self._cache[cache_key] = help_text
            
            return help_text
            
        except Exception as e:
            logger.error(f"Failed to generate module help for '{module_name}': {e}")
            return f"Error generating help for module '{module_name}': {e}"
    
    def get_category_help(self, category_name: str, format_type: OutputFormat = OutputFormat.TEXT) -> str:
        """
        Get help for a specific category
        
        Args:
            category_name: Name of the category
            format_type: Output format
            
        Returns:
            Formatted help string or error message
        """
        try:
            # Find matching category
            category = None
            category_name_lower = category_name.lower()
            
            for cat in ModuleCategory:
                if (cat.value.lower() == category_name_lower or 
                    cat.value.replace('_', ' ').lower() == category_name_lower or
                    cat.value.replace('_', '-').lower() == category_name_lower):
                    category = cat
                    break
            
            if not category:
                available_categories = [cat.value.replace('_', ' ') for cat in ModuleCategory]
                return f"Category '{category_name}' not found.\n\nAvailable categories:\n" + \
                       "\n".join(f"  - {cat}" for cat in available_categories)
            
            # Get modules in category
            modules = self.registry.get_modules_by_category(category)
            
            if not modules:
                return f"No modules found in category '{category.value.replace('_', ' ')}'."
            
            # Format the help
            return self.formatter.format_category_help(category, modules, format_type)
            
        except Exception as e:
            logger.error(f"Failed to generate category help for '{category_name}': {e}")
            return f"Error generating help for category '{category_name}': {e}"
    
    def search_help(self, query: str, format_type: OutputFormat = OutputFormat.TEXT, 
                   max_results: int = 10) -> str:
        """
        Search for modules matching the query
        
        Args:
            query: Search query
            format_type: Output format
            max_results: Maximum number of results to return
            
        Returns:
            Formatted search results
        """
        try:
            if not query.strip():
                return "Please provide a search query."
            
            # Search modules
            results = self.registry.search_modules_fuzzy(query, fuzzy=True)
            
            # Limit results
            if len(results) > max_results:
                results = results[:max_results]
            
            # Format results
            return self.formatter.format_search_results(query, results, format_type)
            
        except Exception as e:
            logger.error(f"Failed to search help for '{query}': {e}")
            return f"Error searching for '{query}': {e}"
    
    def get_module_by_cli_command(self, cli_command: str) -> Optional[ModuleMetadata]:
        """
        Get module metadata by CLI command
        
        Args:
            cli_command: CLI command (e.g., '-ps', '--port-scan')
            
        Returns:
            ModuleMetadata or None if not found
        """
        return self.registry.get_module(cli_command)
    
    def get_available_modules(self) -> List[str]:
        """
        Get list of all available module names
        
        Returns:
            List of module names
        """
        return list(self.registry.modules.keys())
    
    def get_available_categories(self) -> List[str]:
        """
        Get list of all available categories
        
        Returns:
            List of category names
        """
        return [cat.value.replace('_', ' ') for cat in ModuleCategory]
    
    def get_cli_commands(self) -> Dict[str, str]:
        """
        Get mapping of CLI commands to module names
        
        Returns:
            Dictionary mapping CLI commands to module names
        """
        return self.registry.get_cli_command_mapping()
    
    def validate_all_modules(self) -> Dict[str, any]:
        """
        Validate all registered modules
        
        Returns:
            Validation report
        """
        try:
            from ..module_metadata.validators import MetadataValidator
            
            validator = MetadataValidator()
            modules = self.registry.get_all_modules()
            
            if not modules:
                return {
                    'status': 'warning',
                    'message': 'No modules registered for validation',
                    'total_modules': 0,
                    'valid_modules': 0,
                    'invalid_modules': 0,
                    'issues': []
                }
            
            report = validator.validate_multiple_modules(modules)
            
            return {
                'status': 'success' if report.invalid_modules == 0 else 'error',
                'message': report.get_summary(),
                'total_modules': report.total_modules,
                'valid_modules': report.valid_modules,
                'invalid_modules': report.invalid_modules,
                'issues': [
                    {
                        'module': result.module_name,
                        'valid': result.is_valid,
                        'errors': result.errors,
                        'warnings': result.warnings
                    }
                    for result in report.results if result.has_issues()
                ]
            }
            
        except Exception as e:
            logger.error(f"Failed to validate modules: {e}")
            return {
                'status': 'error',
                'message': f'Validation failed: {e}',
                'total_modules': 0,
                'valid_modules': 0,
                'invalid_modules': 0,
                'issues': []
            }
    
    def get_statistics(self) -> Dict[str, any]:
        """
        Get help system statistics
        
        Returns:
            Dictionary with statistics
        """
        try:
            registry_stats = self.registry.get_statistics()
            
            # Add help system specific stats
            stats = {
                'registry': registry_stats,
                'cache': {
                    'enabled': self._cache_enabled,
                    'entries': len(self._cache)
                },
                'formatter': {
                    'supported_formats': [fmt.value for fmt in OutputFormat]
                }
            }
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            return {'error': str(e)}
    
    def clear_cache(self):
        """Clear the help cache"""
        self._cache.clear()
        logger.debug("Help cache cleared")
    
    def enable_cache(self, enabled: bool = True):
        """Enable or disable caching"""
        self._cache_enabled = enabled
        if not enabled:
            self.clear_cache()
        logger.debug(f"Help cache {'enabled' if enabled else 'disabled'}")
    
    def refresh_modules(self) -> int:
        """
        Refresh module registry by re-discovering modules
        
        Returns:
            Number of modules discovered
        """
        try:
            # Clear cache since modules might have changed
            self.clear_cache()
            
            # Clear and re-initialize registry
            self.registry.clear()
            discovered = self.registry.auto_discover_modules()
            
            logger.info(f"Refreshed help system with {discovered} modules")
            return discovered
            
        except Exception as e:
            logger.error(f"Failed to refresh modules: {e}")
            return 0
    
    def get_module_examples(self, module_name: str, level: str = None) -> List[Dict[str, str]]:
        """
        Get examples for a specific module
        
        Args:
            module_name: Name of the module
            level: Filter by example level (basic, intermediate, advanced)
            
        Returns:
            List of example dictionaries
        """
        try:
            metadata = self.registry.get_module(module_name)
            if not metadata:
                return []
            
            examples = metadata.examples
            
            # Filter by level if specified
            if level:
                from ..module_metadata import ExampleLevel
                try:
                    level_enum = ExampleLevel(level.lower())
                    examples = [ex for ex in examples if ex.level == level_enum]
                except ValueError:
                    logger.warning(f"Invalid example level: {level}")
            
            return [
                {
                    'title': ex.title,
                    'description': ex.description,
                    'command': ex.command,
                    'level': ex.level.value,
                    'expected_output': ex.expected_output,
                    'notes': ex.notes
                }
                for ex in examples
            ]
            
        except Exception as e:
            logger.error(f"Failed to get examples for '{module_name}': {e}")
            return []
    
    def get_quick_help(self, module_name: str) -> str:
        """
        Get quick help summary for a module
        
        Args:
            module_name: Name of the module
            
        Returns:
            Quick help string
        """
        try:
            metadata = self.registry.get_module(module_name)
            if not metadata:
                return f"Module '{module_name}' not found."
            
            lines = []
            lines.append(f"{metadata.display_name}: {metadata.description}")
            
            if metadata.cli_command:
                lines.append(f"Command: {metadata.cli_command}")
            
            # Show one basic example if available
            basic_examples = metadata.get_examples_by_level(
                getattr(__import__('spectra.core.module_metadata', fromlist=['ExampleLevel']), 'ExampleLevel').BASIC
            )
            if basic_examples:
                lines.append(f"Example: {basic_examples[0].command}")
            
            return "\n".join(lines)
            
        except Exception as e:
            logger.error(f"Failed to get quick help for '{module_name}': {e}")
            return f"Error getting help for '{module_name}': {e}"
    
    def suggest_related_modules(self, module_name: str) -> List[str]:
        """
        Suggest related modules based on current module
        
        Args:
            module_name: Name of the current module
            
        Returns:
            List of related module names
        """
        try:
            metadata = self.registry.get_module(module_name)
            if not metadata:
                return []
            
            suggestions = []
            
            # Add explicitly related modules
            suggestions.extend(metadata.related_modules)
            
            # Add modules from same category
            category_modules = self.registry.get_modules_by_category(metadata.category)
            for mod in category_modules:
                if mod.name != module_name and mod.name not in suggestions:
                    suggestions.append(mod.name)
            
            # Limit suggestions
            return suggestions[:5]
            
        except Exception as e:
            logger.error(f"Failed to get related modules for '{module_name}': {e}")
            return []


# Global help manager instance
_global_help_manager = None


def get_help_manager() -> HelpManager:
    """
    Get the global help manager instance
    
    Returns:
        HelpManager instance
    """
    global _global_help_manager
    if _global_help_manager is None:
        _global_help_manager = HelpManager()
    return _global_help_manager