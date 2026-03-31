# -*- coding: utf-8 -*-
"""
Module Registry for Spectra - Central registry for all module metadata
"""

import os
import json
from typing import Dict, List, Optional, Set
from collections import defaultdict
import difflib

from ..module_metadata import ModuleMetadata, ModuleCategory
from ..logger import get_logger

logger = get_logger(__name__)


class ModuleNotFoundError(Exception):
    """Raised when a requested module is not found in the registry"""
    pass


class ModuleRegistry:
    """Central registry for managing module metadata"""
    
    def __init__(self):
        self.modules: Dict[str, ModuleMetadata] = {}
        self.categories: Dict[ModuleCategory, List[str]] = defaultdict(list)
        self.cli_commands: Dict[str, str] = {}  # CLI command -> module name mapping
        self.cli_flags_index: Dict[str, str] = {}  # any cli_flag -> module name
        self.tags_index: Dict[str, Set[str]] = defaultdict(set)  # tag -> module names
        self._initialized = False
    
    def register_module(self, metadata: ModuleMetadata) -> bool:
        """
        Register a module in the registry
        
        Args:
            metadata: Module metadata to register
            
        Returns:
            bool: True if registration successful, False otherwise
        """
        try:
            # Validate metadata before registration
            if not metadata.name:
                logger.error(f"Cannot register module with empty name")
                return False
            
            # Check for duplicate module names
            if metadata.name in self.modules:
                logger.warning(f"Module '{metadata.name}' already registered, updating...")
            
            # Check for duplicate CLI commands
            if metadata.cli_command:
                existing_module = self.cli_commands.get(metadata.cli_command)
                if existing_module and existing_module != metadata.name:
                    logger.error(f"CLI command '{metadata.cli_command}' already used by module '{existing_module}'")
                    return False
                self.cli_commands[metadata.cli_command] = metadata.name
            
            # Register the module
            self.modules[metadata.name] = metadata

            # Update category index
            if metadata.name not in self.categories[metadata.category]:
                self.categories[metadata.category].append(metadata.name)

            # Update tags index
            for tag in metadata.tags:
                self.tags_index[tag.lower()].add(metadata.name)

            # Index cli_flags list
            for flag in getattr(metadata, "cli_flags", []):
                self.cli_flags_index[flag] = metadata.name
            
            logger.info(f"Successfully registered module: {metadata.name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to register module '{metadata.name}': {e}")
            return False
    
    def unregister_module(self, module_name: str) -> bool:
        """
        Unregister a module from the registry
        
        Args:
            module_name: Name of module to unregister
            
        Returns:
            bool: True if unregistration successful, False otherwise
        """
        if module_name not in self.modules:
            logger.warning(f"Module '{module_name}' not found in registry")
            return False
        
        try:
            metadata = self.modules[module_name]
            
            # Remove from modules
            del self.modules[module_name]
            
            # Remove from category index
            if module_name in self.categories[metadata.category]:
                self.categories[metadata.category].remove(module_name)
            
            # Remove from CLI commands
            if metadata.cli_command in self.cli_commands:
                del self.cli_commands[metadata.cli_command]

            # Remove from cli_flags index
            for flag in getattr(metadata, "cli_flags", []):
                self.cli_flags_index.pop(flag, None)

            # Remove from tags index
            for tag in metadata.tags:
                self.tags_index[tag.lower()].discard(module_name)
            
            logger.info(f"Successfully unregistered module: {module_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to unregister module '{module_name}': {e}")
            return False
    
    def get_module(self, name: str) -> Optional[ModuleMetadata]:
        """
        Get module metadata by name
        
        Args:
            name: Module name or CLI command
            
        Returns:
            ModuleMetadata or None if not found
        """
        # Try direct module name lookup
        if name in self.modules:
            return self.modules[name]

        # Try CLI command lookup
        if name in self.cli_commands:
            module_name = self.cli_commands[name]
            return self.modules.get(module_name)

        # Try cli_flags index
        if name in self.cli_flags_index:
            module_name = self.cli_flags_index[name]
            return self.modules.get(module_name)

        return None
    
    def get_modules_by_category(self, category: ModuleCategory) -> List[ModuleMetadata]:
        """
        Get all modules in a specific category
        
        Args:
            category: Module category
            
        Returns:
            List of module metadata
        """
        module_names = self.categories.get(category, [])
        return [self.modules[name] for name in module_names if name in self.modules]
    
    def get_all_categories(self) -> Dict[ModuleCategory, List[str]]:
        """
        Get all categories and their modules
        
        Returns:
            Dictionary mapping categories to module names
        """
        return dict(self.categories)
    
    def get_all_modules(self) -> List[ModuleMetadata]:
        """
        Get all registered modules
        
        Returns:
            List of all module metadata
        """
        return list(self.modules.values())
    
    def search_modules(self, query: str, limit: int = 10) -> List[ModuleMetadata]:
        """
        Search modules by name, description, or tags
        
        Args:
            query: Search query
            limit: Maximum number of results
            
        Returns:
            List of matching modules, sorted by relevance
        """
        if not query:
            return []
        
        query_lower = query.lower()
        results = []
        
        for module in self.modules.values():
            score = 0
            
            # Exact name match gets highest score
            if query_lower == module.name.lower():
                score += 100
            elif query_lower in module.name.lower():
                score += 50
            
            # Display name match
            if query_lower in module.display_name.lower():
                score += 30
            
            # Description match
            if query_lower in module.description.lower():
                score += 20
            
            # Detailed description match
            if module.detailed_description and query_lower in module.detailed_description.lower():
                score += 10
            
            # Tag match
            for tag in module.tags:
                if query_lower in tag.lower():
                    score += 25
            
            # CLI command match
            if module.cli_command and query_lower in module.cli_command.lower():
                score += 40
            
            # Category match
            if query_lower in module.category.value.lower():
                score += 15
            
            if score > 0:
                results.append((score, module))
        
        # Sort by score (descending) and return modules
        results.sort(key=lambda x: x[0], reverse=True)
        return [module for score, module in results[:limit]]
    
    def suggest_similar_modules(self, query: str, limit: int = 5) -> List[str]:
        """
        Suggest similar module names using fuzzy matching
        """
        all_names = list(self.modules.keys()) + list(self.cli_commands.keys())
        # Try substring match first (lower threshold)
        substring_matches = [n for n in all_names if query.lower() in n.lower()]
        fuzzy_matches = difflib.get_close_matches(query, all_names, n=limit, cutoff=0.4)
        # Combine and deduplicate maintaining order
        seen = set()
        result = []
        for name in substring_matches + fuzzy_matches:
            if name not in seen:
                seen.add(name)
                result.append(name)
            if len(result) >= limit:
                break
        return result
    
    def get_modules_by_tag(self, tag: str) -> List[ModuleMetadata]:
        """
        Get modules that have a specific tag
        
        Args:
            tag: Tag to search for
            
        Returns:
            List of modules with the tag
        """
        module_names = self.tags_index.get(tag.lower(), set())
        return [self.modules[name] for name in module_names if name in self.modules]
    
    def get_related_modules(self, module_name: str) -> List[ModuleMetadata]:
        """
        Get modules related to a specific module
        
        Args:
            module_name: Name of the module
            
        Returns:
            List of related modules
        """
        if module_name not in self.modules:
            return []
        
        module = self.modules[module_name]
        related = []
        
        # Get explicitly related modules
        for related_name in module.related_modules:
            if related_name in self.modules:
                related.append(self.modules[related_name])
        
        # Get modules in same category (if not too many)
        category_modules = self.get_modules_by_category(module.category)
        if len(category_modules) <= 10:  # Only if category isn't too large
            for cat_module in category_modules:
                if cat_module.name != module_name and cat_module not in related:
                    related.append(cat_module)
        
        return related
    
    def validate_registry(self) -> Dict[str, List[str]]:
        """
        Validate the entire registry for consistency
        
        Returns:
            Dictionary with validation issues
        """
        issues = {
            'errors': [],
            'warnings': [],
            'missing_references': []
        }
        
        # Check for missing related modules
        for module in self.modules.values():
            for related_name in module.related_modules:
                if related_name not in self.modules:
                    issues['missing_references'].append(
                        f"Module '{module.name}' references non-existent module '{related_name}'"
                    )
        
        # Check for duplicate CLI commands
        cli_usage = defaultdict(list)
        for module in self.modules.values():
            if module.cli_command:
                cli_usage[module.cli_command].append(module.name)
        
        for cli_cmd, modules in cli_usage.items():
            if len(modules) > 1:
                issues['errors'].append(
                    f"CLI command '{cli_cmd}' used by multiple modules: {', '.join(modules)}"
                )
        
        # Check category distribution
        for category, modules in self.categories.items():
            if len(modules) == 0:
                issues['warnings'].append(f"Category '{category.value}' has no modules")
            elif len(modules) > 15:
                issues['warnings'].append(f"Category '{category.value}' has many modules ({len(modules)})")
        
        return issues
    
    def export_registry(self, file_path: str) -> bool:
        """
        Export registry to JSON file
        
        Args:
            file_path: Path to export file
            
        Returns:
            bool: True if export successful
        """
        try:
            export_data = {
                'modules': {name: module.to_dict() for name, module in self.modules.items()},
                'metadata': {
                    'total_modules': len(self.modules),
                    'categories': {cat.value: len(modules) for cat, modules in self.categories.items()},
                    'export_timestamp': __import__('datetime').datetime.now().isoformat()
                }
            }
            
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Registry exported to {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export registry: {e}")
            return False
    
    def import_registry(self, file_path: str) -> bool:
        """
        Import registry from JSON file
        
        Args:
            file_path: Path to import file
            
        Returns:
            bool: True if import successful
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                import_data = json.load(f)
            
            # Clear current registry
            self.modules.clear()
            self.categories.clear()
            self.cli_commands.clear()
            self.tags_index.clear()
            
            # Import modules
            modules_data = import_data.get('modules', {})
            for module_name, module_data in modules_data.items():
                try:
                    metadata = ModuleMetadata.from_dict(module_data)
                    self.register_module(metadata)
                except Exception as e:
                    logger.error(f"Failed to import module '{module_name}': {e}")
            
            logger.info(f"Registry imported from {file_path} ({len(self.modules)} modules)")
            return True
            
        except Exception as e:
            logger.error(f"Failed to import registry: {e}")
            return False
    
    def get_statistics(self) -> Dict[str, any]:
        """
        Get registry statistics
        
        Returns:
            Dictionary with statistics
        """
        stats = {
            'total_modules': len(self.modules),
            'categories': {},
            'cli_commands': len(self.cli_commands),
            'total_parameters': 0,
            'total_examples': 0,
            'modules_with_use_cases': 0,
            'modules_with_tags': 0
        }
        
        # Category statistics
        for category, modules in self.categories.items():
            stats['categories'][category.value] = len(modules)
        
        # Module content statistics
        for module in self.modules.values():
            stats['total_parameters'] += len(module.parameters)
            stats['total_examples'] += len(module.examples)
            
            if module.use_cases:
                stats['modules_with_use_cases'] += 1
            
            if module.tags:
                stats['modules_with_tags'] += 1
        
        return stats
    
    def __len__(self) -> int:
        """Return number of registered modules"""
        return len(self.modules)
    
    def __contains__(self, module_name: str) -> bool:
        """Check if module is registered"""
        return module_name in self.modules
    
    def __iter__(self):
        """Iterate over module names"""
        return iter(self.modules.keys())
    
    def is_initialized(self) -> bool:
        """Check if registry has been initialized with modules"""
        return len(self.modules) > 0
    
    def clear(self):
        """Clear all registered modules"""
        self.modules.clear()
        self.categories.clear()
        self.cli_commands.clear()
        self.tags_index.clear()
        self._initialized = False
        logger.info("Module registry cleared")
    
    def get_cli_command_mapping(self) -> Dict[str, str]:
        """Get mapping of CLI commands to module names"""
        return dict(self.cli_commands)
    
    def get_module_suggestions(self, query: str, limit: int = 5) -> List[str]:
        """Get module name suggestions for a query"""
        return self.suggest_similar_modules(query, limit)
    
    def search_modules_fuzzy(self, query: str, fuzzy: bool = True, limit: int = 10) -> List[ModuleMetadata]:
        """Search modules with optional fuzzy matching"""
        if fuzzy:
            # Use existing search_modules method
            return self.search_modules(query, limit)
        else:
            # Exact matching only
            results = []
            query_lower = query.lower()
            
            for module in self.modules.values():
                if (query_lower in module.name.lower() or 
                    query_lower in module.display_name.lower() or
                    query_lower in module.description.lower()):
                    results.append(module)
                    if len(results) >= limit:
                        break
            
            return results
    
    def auto_discover_modules(self) -> int:
        """Auto-discover modules using the discovery system"""
        try:
            from .module_discovery import get_module_discovery
            discovery = get_module_discovery()
            return discovery.discover_all_modules()
        except ImportError:
            logger.warning("Module discovery not available")
            return 0


# Global registry instance
_global_registry = None


def get_registry() -> ModuleRegistry:
    """Get the global module registry instance"""
    global _global_registry
    if _global_registry is None:
        _global_registry = ModuleRegistry()
    return _global_registry


def register_module(metadata: ModuleMetadata) -> bool:
    """
    Convenience function to register a module in the global registry
    
    Args:
        metadata: Module metadata to register
        
    Returns:
        bool: True if registration successful
    """
    return get_registry().register_module(metadata)