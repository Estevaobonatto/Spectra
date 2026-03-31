# -*- coding: utf-8 -*-
"""
Help Manager for Spectra - Central coordinator for help system
"""

from typing import Dict, List, Optional, Tuple
from collections import defaultdict

from .module_registry import ModuleRegistry, ModuleNotFoundError, get_registry
from .help_formatter import HelpFormatter, OutputFormat
from ..module_metadata import ModuleMetadata, ModuleCategory, ValidationResult, Parameter
from ..logger import get_logger

logger = get_logger(__name__)


class HelpSystemError(Exception):
    """Base exception for the help system"""
    pass


class HelpSearchResult:
    """Represents a help search result"""
    
    def __init__(self, module: ModuleMetadata, score: float, match_type: str):
        self.module = module
        self.score = score
        self.match_type = match_type  # 'name', 'description', 'tag', etc.


class HelpManager:
    """Central manager for the help system"""

    def __init__(self, registry: Optional[ModuleRegistry] = None,
                 formatter: Optional[HelpFormatter] = None):
        # Use the provided registry; create a fresh one if not given so each
        # HelpManager instance is isolated. Use get_help_manager() for the
        # global singleton that includes auto-discovered modules.
        self.registry = registry if registry is not None else ModuleRegistry()
        self.formatter = formatter if formatter is not None else HelpFormatter()
        self._cache = {}
        self._cache_enabled = True

    # ── Delegation helpers ───────────────────────────────────────────────────

    def register_module(self, metadata: ModuleMetadata) -> bool:
        """Register a module in the registry."""
        result = self.registry.register_module(metadata)
        self.clear_cache()
        return result

    def unregister_module(self, module_name: str) -> bool:
        """Unregister a module from the registry."""
        result = self.registry.unregister_module(module_name)
        self.clear_cache()
        return result

    def is_module_registered(self, module_name: str) -> bool:
        """Check whether a module is registered."""
        return module_name in self.registry.modules

    def get_module_count(self) -> int:
        """Return the number of registered modules."""
        return len(self.registry.modules)

    def get_all_module_names(self) -> List[str]:
        """Return a list of all registered module names."""
        return list(self.registry.modules.keys())

    def search_modules(self, query: str, limit: int = 10) -> List[ModuleMetadata]:
        """Search modules by name, description, or tags."""
        return self.registry.search_modules(query, limit=limit)

    def search_parameters(self, query: str) -> List[Tuple[ModuleMetadata, Parameter]]:
        """Search for parameters whose name or description matches *query*."""
        query_lower = query.lower()
        name_matches = []
        desc_matches = []
        for module in self.registry.get_all_modules():
            for param in module.parameters:
                if query_lower in param.name.lower():
                    name_matches.append((module, param))
                elif query_lower in param.description.lower():
                    desc_matches.append((module, param))
        return name_matches + desc_matches

    def get_module_suggestions(self, query: str, limit: int = 5) -> List[str]:
        """Return similar module name suggestions for a query."""
        return self.registry.get_module_suggestions(query, limit=limit)

    def get_related_modules(self, module_name: str) -> List[ModuleMetadata]:
        """Return modules related to the given module."""
        return self.registry.get_related_modules(module_name)

    def get_help_for_cli_flag(self, flag: str) -> Optional[str]:
        """Return formatted help for a CLI flag, or None if not found."""
        metadata = self.registry.get_module(flag)
        if metadata is None:
            # Search cli_flags list on all modules
            for mod in self.registry.get_all_modules():
                if hasattr(mod, "cli_flags") and flag in mod.cli_flags:
                    metadata = mod
                    break
        if metadata is None:
            return None
        return self.formatter.format_module_help(metadata)

    def get_examples_for_module(self, module_name: str,
                                 level: str = None) -> str:
        """Return formatted examples text for a module."""
        metadata = self.registry.get_module(module_name)
        if not metadata:
            raise ModuleNotFoundError(f"Module '{module_name}' not found.")
        examples = metadata.examples
        if level:
            try:
                from ..module_metadata import ExampleLevel
                level_enum = ExampleLevel(level.lower())
                examples = [ex for ex in examples if ex.level == level_enum]
            except ValueError:
                pass
        if not examples:
            return ""
        lines = []
        # Group by level
        from ..module_metadata import ExampleLevel
        levels_present = {ex.level for ex in examples}
        for lvl in [ExampleLevel.BASIC, ExampleLevel.INTERMEDIATE, ExampleLevel.ADVANCED]:
            if lvl not in levels_present:
                continue
            lines.append(f"  {lvl.value.title()} Examples:")
            for ex in examples:
                if ex.level == lvl:
                    lines.append(f"    {ex.title}:")
                    lines.append(f"      {ex.description}")
                    lines.append(f"      $ {ex.command}")
            lines.append("")
        return "\n".join(lines)

    def get_parameters_for_module(self, module_name: str,
                                   group_by: str = None) -> str:
        """Return formatted parameters text for a module."""
        metadata = self.registry.get_module(module_name)
        if not metadata:
            raise ModuleNotFoundError(f"Module '{module_name}' not found.")
        return self.formatter.format_parameters(metadata.parameters, group_by=group_by)
        
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
    
    def get_module_help(self, module_name: str,
                        format_type: OutputFormat = None,
                        format: Optional[str] = None) -> str:
        """
        Get detailed help for a specific module

        Args:
            module_name: Name of the module or CLI command
            format_type: Output format (OutputFormat enum)
            format: Output format as string or OutputFormat (alternative to format_type)

        Returns:
            Formatted help string

        Raises:
            ModuleNotFoundError: If module is not found
        """
        # Resolve format kwarg (string or OutputFormat) into format_type
        if format is not None and format_type is None:
            if isinstance(format, OutputFormat):
                format_type = format
            else:
                format_type = OutputFormat(str(format))
        if format_type is None:
            format_type = OutputFormat.TEXT

        cache_key = f"module_help_{module_name}_{format_type.value}"

        if self._cache_enabled and cache_key in self._cache:
            return self._cache[cache_key]

        try:
            # Get module metadata
            metadata = self.registry.get_module(module_name)

            if not metadata:
                raise ModuleNotFoundError(f"Module '{module_name}' not found.")

            # Format the help
            help_text = self.formatter.format_module_help(metadata, format_type)

            # Cache the result
            if self._cache_enabled:
                self._cache[cache_key] = help_text

            return help_text

        except ModuleNotFoundError:
            raise
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
                raise ValueError(
                    f"Category '{category_name}' not found. "
                    f"Available: {', '.join(available_categories)}"
                )
            
            # Get modules in category
            modules = self.registry.get_modules_by_category(category)
            
            if not modules:
                return f"No modules found in category '{category.value.replace('_', ' ')}'."
            
            # Format the help
            return self.formatter.format_category_help(category, modules, format_type)

        except ValueError:
            raise
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
    
    def validate_all_modules(self):
        """
        Validate all registered modules

        Returns:
            ValidationReport object
        """
        from ..module_metadata.validators import MetadataValidator, ValidationReport

        modules = self.registry.get_all_modules()
        if not modules:
            # Return an empty report
            report = ValidationReport(total_modules=0, valid_modules=0, invalid_modules=0)
            return report

        validator = MetadataValidator()
        return validator.validate_multiple_modules(modules)
    
    def get_statistics(self) -> Dict[str, any]:
        """
        Get help system statistics

        Returns:
            Dictionary with statistics
        """
        from spectra import __version__
        try:
            version = __version__
        except Exception:
            version = "2.0.1"
        return {
            'total_modules': len(self.registry.modules),
            'help_system_version': version,
            'supported_formats': [fmt.value for fmt in OutputFormat],
        }

    def export_help_data(self, format_type: OutputFormat) -> str:
        """
        Export all help data in the given format.

        Args:
            format_type: OutputFormat.TEXT or OutputFormat.JSON

        Returns:
            Formatted help data string

        Raises:
            ValueError: If format_type is not supported for export
        """
        if format_type not in (OutputFormat.TEXT, OutputFormat.JSON):
            raise ValueError(
                f"Export format '{format_type.value}' not supported. Use TEXT or JSON."
            )
        return self.get_general_help(format_type)

    def get_category_count(self) -> int:
        """
        Return the number of categories that have at least one registered module.
        """
        count = 0
        for category in ModuleCategory:
            if self.registry.get_modules_by_category(category):
                count += 1
        return count

    def get_all_categories(self) -> List[str]:
        """
        Return the values of all categories that have at least one module.
        """
        return [
            category.value
            for category in ModuleCategory
            if self.registry.get_modules_by_category(category)
        ]

    def __repr__(self) -> str:
        return (
            f"HelpManager(modules={len(self.registry.modules)}, "
            f"categories={self.get_category_count()})"
        )
    
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