# -*- coding: utf-8 -*-
"""
Module Registry - Central registry for all Spectra modules and their metadata
"""

import os
import importlib
import inspect
from typing import Dict, List, Optional, Set, Callable
from collections import defaultdict
import difflib

from ..module_metadata import ModuleMetadata, ModuleCategory


class ModuleRegistryError(Exception):
    """Base exception for module registry errors"""
    pass


class ModuleNotFoundError(ModuleRegistryError):
    """Raised when a requested module is not found"""
    pass


class DuplicateModuleError(ModuleRegistryError):
    """Raised when attempting to register a module that already exists"""
    pass


class ModuleRegistry:
    """Central registry for managing module metadata"""
    
    def __init__(self):
        self._modules: Dict[str, ModuleMetadata] = {}
        self._categories: Dict[ModuleCategory, List[str]] = defaultdict(list)
        self._tags: Dict[str, List[str]] = defaultdict(list)
        self._cli_flags: Dict[str, str] = {}  # flag -> module_name mapping
        self._search_index: Dict[str, Set[str]] = defaultdict(set)  # term -> module_names
        
        # Auto-discovery settings
        self._auto_discovery_enabled = True
        self._discovery_paths = ['spectra.modules']
        
    def register_module(self, metadata: ModuleMetadata, allow_override: bool = False) -> None:
        """
        Register a module's metadata
        
        Args:
            metadata: Module metadata to register
            allow_override: Whether to allow overriding existing modules
            
        Raises:
            DuplicateModuleError: If module already exists and override not allowed
        """
        if metadata.name in self._modules and not allow_override:
            raise DuplicateModuleError(f"Module '{metadata.name}' is already registered")
        
        # Validate metadata before registration
        from ..module_metadata import MetadataValidator
        validator = MetadataValidator()
        result = validator.validate_module(metadata)
        
        if not result.is_valid:
            raise ModuleRegistryError(f"Invalid metadata for module '{metadata.name}': {', '.join(result.errors)}")
        
        # Register the module
        self._modules[metadata.name] = metadata
        
        # Update category index
        if metadata.category not in self._categories:
            self._categories[metadata.category] = []
        if metadata.name not in self._categories[metadata.category]:
            self._categories[metadata.category].append(metadata.name)
        
        # Update tag index
        for tag in metadata.tags:
            if metadata.name not in self._tags[tag]:
                self._tags[tag].append(metadata.name)
        
        # Update CLI flags index
        for flag in metadata.cli_flags:
            self._cli_flags[flag] = metadata.name
        
        # Update search index
        self._update_search_index(metadata)
    
    def unregister_module(self, module_name: str) -> bool:
        """
        Unregister a module
        
        Args:
            module_name: Name of module to unregister
            
        Returns:
            True if module was unregistered, False if not found
        """
        if module_name not in self._modules:
            return False
        
        metadata = self._modules[module_name]
        
        # Remove from main registry
        del self._modules[module_name]
        
        # Remove from category index
        if metadata.category in self._categories:
            if module_name in self._categories[metadata.category]:
                self._categories[metadata.category].remove(module_name)
            if not self._categories[metadata.category]:
                del self._categories[metadata.category]
        
        # Remove from tag index
        for tag in metadata.tags:
            if tag in self._tags and module_name in self._tags[tag]:
                self._tags[tag].remove(module_name)
                if not self._tags[tag]:
                    del self._tags[tag]
        
        # Remove from CLI flags index
        flags_to_remove = [flag for flag, mod_name in self._cli_flags.items() if mod_name == module_name]
        for flag in flags_to_remove:
            del self._cli_flags[flag]
        
        # Remove from search index
        self._remove_from_search_index(metadata)
        
        return True
    
    def get_module(self, name: str) -> ModuleMetadata:
        """
        Get module metadata by name
        
        Args:
            name: Module name
            
        Returns:
            Module metadata
            
        Raises:
            ModuleNotFoundError: If module not found
        """
        if name not in self._modules:
            # Try to suggest similar modules
            suggestions = self._get_similar_module_names(name)
            suggestion_text = f" Did you mean: {', '.join(suggestions[:3])}?" if suggestions else ""
            raise ModuleNotFoundError(f"Module '{name}' not found.{suggestion_text}")
        
        return self._modules[name]
    
    def get_module_by_cli_flag(self, flag: str) -> Optional[ModuleMetadata]:
        """
        Get module metadata by CLI flag
        
        Args:
            flag: CLI flag (e.g., '-ps', '--port-scan')
            
        Returns:
            Module metadata or None if not found
        """
        module_name = self._cli_flags.get(flag)
        if module_name:
            return self._modules.get(module_name)
        return None
    
    def get_modules_by_category(self, category: ModuleCategory) -> List[ModuleMetadata]:
        """
        Get all modules in a category
        
        Args:
            category: Module category
            
        Returns:
            List of module metadata
        """
        module_names = self._categories.get(category, [])
        return [self._modules[name] for name in module_names]
    
    def get_modules_by_tag(self, tag: str) -> List[ModuleMetadata]:
        """
        Get all modules with a specific tag
        
        Args:
            tag: Tag to search for
            
        Returns:
            List of module metadata
        """
        module_names = self._tags.get(tag, [])
        return [self._modules[name] for name in module_names]
    
    def get_all_modules(self) -> List[ModuleMetadata]:
        """Get all registered modules"""
        return list(self._modules.values())
    
    def get_all_categories(self) -> Dict[ModuleCategory, List[str]]:
        """Get all categories and their modules"""
        return dict(self._categories)
    
    def get_module_names(self) -> List[str]:
        """Get list of all module names"""
        return list(self._modules.keys())
    
    def get_category_names(self) -> List[str]:
        """Get list of all category names"""
        return [cat.value for cat in self._categories.keys()]
    
    def search_modules(self, query: str, limit: int = 10) -> List[ModuleMetadata]:
        """
        Search modules by query string
        
        Args:
            query: Search query
            limit: Maximum number of results
            
        Returns:
            List of matching modules, sorted by relevance
        """
        query_lower = query.lower()
        matches = []
        
        # Direct name matches (highest priority)
        for name, metadata in self._modules.items():
            if query_lower in name.lower():
                matches.append((metadata, 100))
        
        # Display name matches
        for metadata in self._modules.values():
            if query_lower in metadata.display_name.lower() and metadata not in [m[0] for m in matches]:
                matches.append((metadata, 90))
        
        # Description matches
        for metadata in self._modules.values():
            if (query_lower in metadata.description.lower() or 
                query_lower in metadata.detailed_description.lower()) and metadata not in [m[0] for m in matches]:
                matches.append((metadata, 80))
        
        # Tag matches
        for metadata in self._modules.values():
            if any(query_lower in tag.lower() for tag in metadata.tags) and metadata not in [m[0] for m in matches]:
                matches.append((metadata, 70))
        
        # Parameter name matches
        for metadata in self._modules.values():
            if any(query_lower in param.name.lower() for param in metadata.parameters) and metadata not in [m[0] for m in matches]:
                matches.append((metadata, 60))
        
        # Parameter description matches
        for metadata in self._modules.values():
            if any(query_lower in param.description.lower() for param in metadata.parameters) and metadata not in [m[0] for m in matches]:
                matches.append((metadata, 50))
        
        # Sort by relevance score and return
        matches.sort(key=lambda x: x[1], reverse=True)
        return [match[0] for match in matches[:limit]]
    
    def search_parameters(self, query: str, limit: int = 20) -> List[tuple]:
        """
        Search parameters across all modules
        
        Args:
            query: Search query
            limit: Maximum number of results
            
        Returns:
            List of tuples (module_metadata, parameter)
        """
        query_lower = query.lower()
        matches = []
        
        for metadata in self._modules.values():
            for param in metadata.parameters:
                score = 0
                
                # Parameter name match
                if query_lower in param.name.lower():
                    score += 100
                
                # Parameter description match
                if query_lower in param.description.lower():
                    score += 80
                
                # Short name match
                if param.short_name and query_lower in param.short_name.lower():
                    score += 90
                
                if score > 0:
                    matches.append((metadata, param, score))
        
        # Sort by relevance and return
        matches.sort(key=lambda x: x[2], reverse=True)
        return [(match[0], match[1]) for match in matches[:limit]]
    
    def get_related_modules(self, module_name: str) -> List[ModuleMetadata]:
        """
        Get modules related to the specified module
        
        Args:
            module_name: Name of the module
            
        Returns:
            List of related modules
        """
        if module_name not in self._modules:
            return []
        
        metadata = self._modules[module_name]
        related = []
        
        # Get explicitly related modules
        for related_name in metadata.related_modules:
            if related_name in self._modules:
                related.append(self._modules[related_name])
        
        # Get modules in same category
        category_modules = self.get_modules_by_category(metadata.category)
        for mod in category_modules:
            if mod.name != module_name and mod not in related:
                related.append(mod)
        
        # Get modules with common tags
        for tag in metadata.tags:
            tag_modules = self.get_modules_by_tag(tag)
            for mod in tag_modules:
                if mod.name != module_name and mod not in related:
                    related.append(mod)
        
        return related
    
    def auto_discover_modules(self, paths: Optional[List[str]] = None) -> int:
        """
        Automatically discover and register modules
        
        Args:
            paths: List of module paths to search (uses default if None)
            
        Returns:
            Number of modules discovered and registered
        """
        if not self._auto_discovery_enabled:
            return 0
        
        search_paths = paths or self._discovery_paths
        discovered_count = 0
        
        for path in search_paths:
            try:
                discovered_count += self._discover_modules_in_path(path)
            except ImportError as e:
                # Log warning but continue
                print(f"Warning: Could not import from {path}: {e}")
        
        return discovered_count
    
    def _discover_modules_in_path(self, module_path: str) -> int:
        """Discover modules in a specific path"""
        discovered_count = 0
        
        try:
            # Import the package
            package = importlib.import_module(module_path)
            package_dir = os.path.dirname(package.__file__)
            
            # Scan for Python files
            for filename in os.listdir(package_dir):
                if filename.endswith('.py') and not filename.startswith('__'):
                    module_name = filename[:-3]  # Remove .py extension
                    
                    try:
                        # Import the module
                        full_module_path = f"{module_path}.{module_name}"
                        module = importlib.import_module(full_module_path)
                        
                        # Look for metadata
                        metadata = self._extract_metadata_from_module(module, module_name)
                        if metadata:
                            self.register_module(metadata, allow_override=True)
                            discovered_count += 1
                            
                    except Exception as e:
                        # Log warning but continue
                        print(f"Warning: Could not process module {module_name}: {e}")
        
        except Exception as e:
            print(f"Warning: Could not discover modules in {module_path}: {e}")
        
        return discovered_count
    
    def _extract_metadata_from_module(self, module, module_name: str) -> Optional[ModuleMetadata]:
        """Extract metadata from a module if available"""
        # Look for METADATA constant
        if hasattr(module, 'METADATA') and isinstance(module.METADATA, ModuleMetadata):
            return module.METADATA
        
        # Look for get_metadata function
        if hasattr(module, 'get_metadata') and callable(module.get_metadata):
            try:
                return module.get_metadata()
            except Exception:
                pass
        
        # Look for metadata in module docstring or other conventions
        # This could be extended to parse docstrings, comments, etc.
        
        return None
    
    def _update_search_index(self, metadata: ModuleMetadata) -> None:
        """Update search index with module metadata"""
        module_name = metadata.name
        
        # Index module name
        self._search_index[metadata.name.lower()].add(module_name)
        
        # Index display name words
        for word in metadata.display_name.lower().split():
            self._search_index[word].add(module_name)
        
        # Index description words
        for word in metadata.description.lower().split():
            self._search_index[word].add(module_name)
        
        # Index tags
        for tag in metadata.tags:
            self._search_index[tag.lower()].add(module_name)
        
        # Index parameter names
        for param in metadata.parameters:
            self._search_index[param.name.lower()].add(module_name)
            if param.short_name:
                self._search_index[param.short_name.lower()].add(module_name)
    
    def _remove_from_search_index(self, metadata: ModuleMetadata) -> None:
        """Remove module from search index"""
        module_name = metadata.name
        
        # Remove from all index entries
        for term_set in self._search_index.values():
            term_set.discard(module_name)
        
        # Clean up empty entries
        empty_terms = [term for term, modules in self._search_index.items() if not modules]
        for term in empty_terms:
            del self._search_index[term]
    
    def _get_similar_module_names(self, name: str, limit: int = 5) -> List[str]:
        """Get similar module names using fuzzy matching"""
        all_names = list(self._modules.keys())
        matches = difflib.get_close_matches(name, all_names, n=limit, cutoff=0.3)
        return matches
    
    def get_statistics(self) -> Dict[str, any]:
        """Get registry statistics"""
        return {
            'total_modules': len(self._modules),
            'categories': {cat.value: len(modules) for cat, modules in self._categories.items()},
            'total_parameters': sum(len(mod.parameters) for mod in self._modules.values()),
            'total_examples': sum(len(mod.examples) for mod in self._modules.values()),
            'modules_with_tags': len([mod for mod in self._modules.values() if mod.tags]),
            'cli_flags': len(self._cli_flags),
            'search_terms': len(self._search_index)
        }
    
    def validate_all_modules(self) -> 'ValidationReport':
        """Validate all registered modules"""
        from ..module_metadata import MetadataValidator
        validator = MetadataValidator()
        return validator.validate_modules(list(self._modules.values()))
    
    def export_registry(self, format: str = 'json') -> str:
        """Export registry data in specified format"""
        data = {
            'modules': {name: metadata.to_dict() for name, metadata in self._modules.items()},
            'statistics': self.get_statistics()
        }
        
        if format.lower() == 'json':
            import json
            return json.dumps(data, indent=2, default=str)
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def clear(self) -> None:
        """Clear all registered modules"""
        self._modules.clear()
        self._categories.clear()
        self._tags.clear()
        self._cli_flags.clear()
        self._search_index.clear()
    
    def __len__(self) -> int:
        """Return number of registered modules"""
        return len(self._modules)
    
    def __contains__(self, module_name: str) -> bool:
        """Check if module is registered"""
        return module_name in self._modules
    
    def __iter__(self):
        """Iterate over module names"""
        return iter(self._modules.keys())
    
    def __repr__(self) -> str:
        """String representation"""
        return f"ModuleRegistry({len(self._modules)} modules, {len(self._categories)} categories)"