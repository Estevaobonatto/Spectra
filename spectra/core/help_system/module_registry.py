# -*- coding: utf-8 -*-
"""
Module Registry for Spectra - Centralized module management and discovery
"""

import os
import importlib
import inspect
from typing import Dict, List, Optional, Set
from collections import defaultdict

from ..module_metadata import ModuleMetadata, ModuleCategory
from ..logger import get_logger

logger = get_logger(__name__)


class ModuleRegistry:
    """Central registry for all Spectra modules and their metadata"""
    
    def __init__(self):
        self.modules: Dict[str, ModuleMetadata] = {}
        self.categories: Dict[ModuleCategory, List[str]] = defaultdict(list)
        self.cli_commands: Dict[str, str] = {}  # CLI command -> module name mapping
        self.tags: Dict[str, Set[str]] = defaultdict(set)  # tag -> set of module names
        self._initialized = False
        
    def register_module(self, metadata: ModuleMetadata) -> bool:
        """
        Register a module with its metadata
        
        Args:
            metadata: ModuleMetadata instance
            
        Returns:
            bool: True if registration successful, False otherwise
        """
        try:
            # Validate metadata before registration
            if not metadata.name:
                logger.error(f"Cannot register module with empty name")
                return False
            
            if metadata.name in self.modules:
                logger.warning(f"Module '{metadata.name}' already registered, updating...")
            
            # Register the module
            self.modules[metadata.name] = metadata
            
            # Update category mapping
            if metadata.name not in self.categories[metadata.category]:
                self.categories[metadata.category].append(metadata.name)
            
            # Update CLI command mapping
            if metadata.cli_command:
                if metadata.cli_command in self.cli_commands:
                    existing_module = self.cli_commands[metadata.cli_command]
                    logger.warning(f"CLI command '{metadata.cli_command}' already mapped to '{existing_module}', overriding with '{metadata.name}'")
                self.cli_commands[metadata.cli_command] = metadata.name
            
            # Update CLI aliases
            for alias in metadata.cli_aliases:
                if alias in self.cli_commands:
                    existing_module = self.cli_commands[alias]
                    logger.warning(f"CLI alias '{alias}' already mapped to '{existing_module}', overriding with '{metadata.name}'")
                self.cli_commands[alias] = metadata.name
            
            # Update tag mapping
            for tag in metadata.tags:
                self.tags[tag.lower()].add(metadata.name)
            
            logger.debug(f"Successfully registered module: {metadata.name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to register module '{metadata.name}': {e}")
            return False
    
    def unregister_module(self, module_name: str) -> bool:
        """
        Unregister a module
        
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
            
            # Remove from category mapping
            if module_name in self.categories[metadata.category]:
                self.categories[metadata.category].remove(module_name)
            
            # Remove from CLI command mapping
            cli_commands_to_remove = []
            for cmd, mod_name in self.cli_commands.items():
                if mod_name == module_name:
                    cli_commands_to_remove.append(cmd)
            
            for cmd in cli_commands_to_remove:
                del self.cli_commands[cmd]
            
            # Remove from tag mapping
            for tag, module_set in self.tags.items():
                module_set.discard(module_name)
            
            logger.debug(f"Successfully unregistered module: {module_name}")
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
        
        return None
    
    def get_modules_by_category(self, category: ModuleCategory) -> List[ModuleMetadata]:
        """
        Get all modules in a specific category
        
        Args:
            category: ModuleCategory enum value
            
        Returns:
            List of ModuleMetadata objects
        """
        module_names = self.categories.get(category, [])
        return [self.modules[name] for name in module_names if name in self.modules]
    
    def get_all_categories(self) -> Dict[ModuleCategory, List[str]]:
        """
        Get all categories with their module names
        
        Returns:
            Dictionary mapping categories to module name lists
        """
        return dict(self.categories)
    
    def get_all_modules(self) -> List[ModuleMetadata]:
        """
        Get all registered modules
        
        Returns:
            List of all ModuleMetadata objects
        """
        return list(self.modules.values())
    
    def search_modules(self, query: str, fuzzy: bool = True) -> List[ModuleMetadata]:
        """
        Search modules by name, description, or tags
        
        Args:
            query: Search query string
            fuzzy: Enable fuzzy matching
            
        Returns:
            List of matching ModuleMetadata objects
        """
        query_lower = query.lower()
        matches = []
        
        for metadata in self.modules.values():
            score = 0
            
            # Exact name match (highest priority)
            if query_lower == metadata.name.lower():
                score += 100
            elif query_lower in metadata.name.lower():
                score += 50
            
            # Display name match
            if query_lower in metadata.display_name.lower():
                score += 40
            
            # Description match
            if query_lower in metadata.description.lower():
                score += 20
            
            # Detailed description match
            if metadata.detailed_description and query_lower in metadata.detailed_description.lower():
                score += 10
            
            # Tag match
            for tag in metadata.tags:
                if query_lower in tag.lower():
                    score += 30
                    break
            
            # CLI command match
            if metadata.cli_command and query_lower in metadata.cli_command.lower():
                score += 35
            
            # Fuzzy matching for typos
            if fuzzy and score == 0:
                if self._fuzzy_match(query_lower, metadata.name.lower()):
                    score += 15
                elif self._fuzzy_match(query_lower, metadata.display_name.lower()):
                    score += 10
            
            if score > 0:
                matches.append((score, metadata))
        
        # Sort by score (descending) and return metadata objects
        matches.sort(key=lambda x: x[0], reverse=True)
        return [metadata for score, metadata in matches]
    
    def search_by_tag(self, tag: str) -> List[ModuleMetadata]:
        """
        Search modules by tag
        
        Args:
            tag: Tag to search for
            
        Returns:
            List of ModuleMetadata objects with the tag
        """
        tag_lower = tag.lower()
        if tag_lower in self.tags:
            module_names = self.tags[tag_lower]
            return [self.modules[name] for name in module_names if name in self.modules]
        return []
    
    def get_module_suggestions(self, invalid_name: str, max_suggestions: int = 5) -> List[str]:
        """
        Get suggestions for invalid module names
        
        Args:
            invalid_name: The invalid module name
            max_suggestions: Maximum number of suggestions
            
        Returns:
            List of suggested module names
        """
        suggestions = []
        invalid_lower = invalid_name.lower()
        
        # Calculate similarity scores
        for module_name in self.modules.keys():
            similarity = self._calculate_similarity(invalid_lower, module_name.lower())
            if similarity > 0.3:  # Threshold for suggestions
                suggestions.append((similarity, module_name))
        
        # Sort by similarity and return top suggestions
        suggestions.sort(key=lambda x: x[0], reverse=True)
        return [name for score, name in suggestions[:max_suggestions]]
    
    def get_cli_command_mapping(self) -> Dict[str, str]:
        """
        Get mapping of CLI commands to module names
        
        Returns:
            Dictionary mapping CLI commands to module names
        """
        return self.cli_commands.copy()
    
    def get_statistics(self) -> Dict[str, int]:
        """
        Get registry statistics
        
        Returns:
            Dictionary with registry statistics
        """
        stats = {
            'total_modules': len(self.modules),
            'total_categories': len([cat for cat in self.categories if self.categories[cat]]),
            'total_cli_commands': len(self.cli_commands),
            'total_tags': len([tag for tag in self.tags if self.tags[tag]])
        }
        
        # Add per-category counts
        for category in ModuleCategory:
            count = len(self.categories.get(category, []))
            stats[f'{category.value}_modules'] = count
        
        return stats
    
    def validate_registry(self) -> Dict[str, List[str]]:
        """
        Validate registry for consistency issues
        
        Returns:
            Dictionary with validation issues
        """
        issues = {
            'errors': [],
            'warnings': []
        }
        
        # Check for orphaned CLI commands
        for cli_cmd, module_name in self.cli_commands.items():
            if module_name not in self.modules:
                issues['errors'].append(f"CLI command '{cli_cmd}' points to non-existent module '{module_name}'")
        
        # Check for modules without CLI commands
        modules_without_cli = []
        for module_name, metadata in self.modules.items():
            if not metadata.cli_command:
                modules_without_cli.append(module_name)
        
        if modules_without_cli:
            issues['warnings'].append(f"Modules without CLI commands: {', '.join(modules_without_cli)}")
        
        # Check for empty categories
        empty_categories = []
        for category in ModuleCategory:
            if not self.categories.get(category):
                empty_categories.append(category.value)
        
        if empty_categories:
            issues['warnings'].append(f"Empty categories: {', '.join(empty_categories)}")
        
        return issues
    
    def auto_discover_modules(self, modules_path: str = None) -> int:
        """
        Automatically discover and register modules from the modules directory
        
        Args:
            modules_path: Path to modules directory (defaults to spectra/modules)
            
        Returns:
            Number of modules discovered and registered
        """
        if modules_path is None:
            # Default to spectra/modules relative to this file
            current_dir = os.path.dirname(os.path.abspath(__file__))
            modules_path = os.path.join(current_dir, '..', '..', 'modules')
        
        if not os.path.exists(modules_path):
            logger.error(f"Modules path does not exist: {modules_path}")
            return 0
        
        discovered_count = 0
        
        # Scan for Python files in modules directory
        for filename in os.listdir(modules_path):
            if filename.endswith('.py') and not filename.startswith('__'):
                module_name = filename[:-3]  # Remove .py extension
                
                try:
                    # Try to import the module
                    module_path = f"spectra.modules.{module_name}"
                    module = importlib.import_module(module_path)
                    
                    # Look for METADATA attribute
                    if hasattr(module, 'METADATA'):
                        metadata = module.METADATA
                        if isinstance(metadata, ModuleMetadata):
                            if self.register_module(metadata):
                                discovered_count += 1
                                logger.debug(f"Auto-discovered module: {module_name}")
                        else:
                            logger.warning(f"Module {module_name} has invalid METADATA attribute")
                    else:
                        logger.debug(f"Module {module_name} has no METADATA attribute")
                        
                except ImportError as e:
                    logger.debug(f"Could not import module {module_name}: {e}")
                except Exception as e:
                    logger.error(f"Error processing module {module_name}: {e}")
        
        logger.info(f"Auto-discovered {discovered_count} modules")
        return discovered_count
    
    def _fuzzy_match(self, query: str, target: str, threshold: float = 0.6) -> bool:
        """
        Simple fuzzy matching using character overlap
        
        Args:
            query: Query string
            target: Target string
            threshold: Minimum similarity threshold
            
        Returns:
            True if strings are similar enough
        """
        if len(query) == 0 or len(target) == 0:
            return False
        
        # Simple character-based similarity
        query_chars = set(query)
        target_chars = set(target)
        
        intersection = len(query_chars.intersection(target_chars))
        union = len(query_chars.union(target_chars))
        
        similarity = intersection / union if union > 0 else 0
        return similarity >= threshold
    
    def _calculate_similarity(self, str1: str, str2: str) -> float:
        """
        Calculate similarity between two strings using Levenshtein-like algorithm
        
        Args:
            str1: First string
            str2: Second string
            
        Returns:
            Similarity score between 0 and 1
        """
        if str1 == str2:
            return 1.0
        
        if len(str1) == 0 or len(str2) == 0:
            return 0.0
        
        # Simple character overlap similarity
        chars1 = set(str1)
        chars2 = set(str2)
        
        intersection = len(chars1.intersection(chars2))
        union = len(chars1.union(chars2))
        
        char_similarity = intersection / union if union > 0 else 0
        
        # Length similarity
        max_len = max(len(str1), len(str2))
        min_len = min(len(str1), len(str2))
        length_similarity = min_len / max_len if max_len > 0 else 0
        
        # Combined similarity
        return (char_similarity + length_similarity) / 2
    
    def initialize(self) -> bool:
        """
        Initialize the registry by auto-discovering modules
        
        Returns:
            True if initialization successful
        """
        if self._initialized:
            logger.debug("Registry already initialized")
            return True
        
        try:
            discovered = self.auto_discover_modules()
            self._initialized = True
            logger.info(f"Registry initialized with {discovered} modules")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize registry: {e}")
            return False
    
    def is_initialized(self) -> bool:
        """Check if registry is initialized"""
        return self._initialized
    
    def clear(self):
        """Clear all registered modules"""
        self.modules.clear()
        self.categories.clear()
        self.cli_commands.clear()
        self.tags.clear()
        self._initialized = False
        logger.debug("Registry cleared")


# Global registry instance
_global_registry = None


def get_registry() -> ModuleRegistry:
    """
    Get the global module registry instance
    
    Returns:
        ModuleRegistry instance
    """
    global _global_registry
    if _global_registry is None:
        _global_registry = ModuleRegistry()
        _global_registry.initialize()
    return _global_registry


def register_module(metadata: ModuleMetadata) -> bool:
    """
    Convenience function to register a module with the global registry
    
    Args:
        metadata: ModuleMetadata instance
        
    Returns:
        True if registration successful
    """
    return get_registry().register_module(metadata)