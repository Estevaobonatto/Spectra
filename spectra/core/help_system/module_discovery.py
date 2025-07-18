# -*- coding: utf-8 -*-
"""
Module Discovery for Spectra Help System - Auto-discovers and registers module metadata
"""

import os
import importlib
import inspect
from typing import List, Dict, Optional, Tuple
from pathlib import Path

from ..module_metadata import ModuleMetadata
from ..logger import get_logger
from .module_registry import get_registry

logger = get_logger(__name__)


class ModuleDiscovery:
    """Discovers and registers module metadata automatically"""
    
    def __init__(self):
        self.registry = get_registry()
        self.discovered_modules = {}
        self.discovery_errors = []
        
    def discover_all_modules(self) -> int:
        """
        Discover all modules with metadata and register them
        
        Returns:
            Number of modules discovered and registered
        """
        logger.info("Starting module discovery...")
        
        # Clear previous discoveries
        self.discovered_modules.clear()
        self.discovery_errors.clear()
        
        # Get the modules directory path
        modules_dir = self._get_modules_directory()
        if not modules_dir.exists():
            logger.error(f"Modules directory not found: {modules_dir}")
            return 0
        
        # Discover metadata files
        metadata_files = self._find_metadata_files(modules_dir)
        logger.info(f"Found {len(metadata_files)} metadata files")
        
        # Load metadata from each file
        registered_count = 0
        for metadata_file in metadata_files:
            try:
                metadata = self._load_metadata_from_file(metadata_file)
                if metadata:
                    success = self.registry.register_module(metadata)
                    if success:
                        self.discovered_modules[metadata.name] = metadata
                        registered_count += 1
                        logger.debug(f"Registered module: {metadata.name}")
                    else:
                        logger.warning(f"Failed to register module: {metadata.name}")
            except Exception as e:
                error_msg = f"Error loading metadata from {metadata_file}: {e}"
                self.discovery_errors.append(error_msg)
                logger.error(error_msg)
        
        logger.info(f"Module discovery completed. Registered {registered_count} modules")
        
        if self.discovery_errors:
            logger.warning(f"Discovery completed with {len(self.discovery_errors)} errors")
        
        return registered_count
    
    def _get_modules_directory(self) -> Path:
        """Get the path to the modules directory"""
        # Get the directory containing this file
        current_dir = Path(__file__).parent
        # Navigate to the modules directory
        modules_dir = current_dir.parent.parent / "modules"
        return modules_dir
    
    def _find_metadata_files(self, modules_dir: Path) -> List[Path]:
        """Find all metadata files in the modules directory"""
        metadata_files = []
        
        # Look for files ending with _metadata.py
        for file_path in modules_dir.glob("*_metadata.py"):
            if file_path.is_file():
                metadata_files.append(file_path)
        
        return sorted(metadata_files)
    
    def _load_metadata_from_file(self, file_path: Path) -> Optional[ModuleMetadata]:
        """Load metadata from a specific file"""
        try:
            # Convert file path to module name
            module_name = self._file_path_to_module_name(file_path)
            
            # Import the module
            module = importlib.import_module(module_name)
            
            # Look for METADATA attribute
            if hasattr(module, 'METADATA'):
                metadata = module.METADATA
                if isinstance(metadata, ModuleMetadata):
                    return metadata
                else:
                    logger.warning(f"METADATA in {file_path} is not a ModuleMetadata instance")
            else:
                logger.warning(f"No METADATA attribute found in {file_path}")
                
        except Exception as e:
            logger.error(f"Failed to load metadata from {file_path}: {e}")
        
        return None
    
    def _file_path_to_module_name(self, file_path: Path) -> str:
        """Convert file path to Python module name"""
        # Get relative path from project root
        try:
            # Find the spectra directory in the path
            parts = file_path.parts
            spectra_index = None
            for i, part in enumerate(parts):
                if part == 'spectra':
                    spectra_index = i
                    break
            
            if spectra_index is None:
                raise ValueError("Could not find 'spectra' in path")
            
            # Build module name from spectra onwards
            module_parts = parts[spectra_index:]
            # Remove .py extension
            if module_parts[-1].endswith('.py'):
                module_parts = module_parts[:-1] + (module_parts[-1][:-3],)
            
            return '.'.join(module_parts)
            
        except Exception as e:
            logger.error(f"Failed to convert path to module name: {file_path} - {e}")
            raise
    
    def get_discovery_report(self) -> Dict[str, any]:
        """Get a report of the discovery process"""
        return {
            'discovered_modules': len(self.discovered_modules),
            'modules': list(self.discovered_modules.keys()),
            'errors': len(self.discovery_errors),
            'error_details': self.discovery_errors
        }
    
    def validate_discovered_modules(self) -> Dict[str, any]:
        """Validate all discovered modules"""
        from ..module_metadata.validators import MetadataValidator
        
        validator = MetadataValidator()
        modules = list(self.discovered_modules.values())
        
        if not modules:
            return {
                'status': 'warning',
                'message': 'No modules to validate',
                'valid_modules': 0,
                'invalid_modules': 0
            }
        
        report = validator.validate_multiple_modules(modules)
        
        return {
            'status': 'success' if report.invalid_modules == 0 else 'error',
            'message': report.get_summary(),
            'total_modules': report.total_modules,
            'valid_modules': report.valid_modules,
            'invalid_modules': report.invalid_modules,
            'validation_details': [
                {
                    'module': result.module_name,
                    'valid': result.is_valid,
                    'errors': result.errors,
                    'warnings': result.warnings
                }
                for result in report.results
            ]
        }
    
    def rediscover_modules(self) -> int:
        """Rediscover modules (clear registry and discover again)"""
        logger.info("Rediscovering modules...")
        
        # Clear the registry
        self.registry.clear()
        
        # Discover again
        return self.discover_all_modules()


# Global discovery instance
_global_discovery = None


def get_module_discovery() -> ModuleDiscovery:
    """Get the global module discovery instance"""
    global _global_discovery
    if _global_discovery is None:
        _global_discovery = ModuleDiscovery()
    return _global_discovery


def auto_discover_modules() -> int:
    """
    Convenience function to auto-discover all modules
    
    Returns:
        Number of modules discovered
    """
    discovery = get_module_discovery()
    return discovery.discover_all_modules()


def initialize_help_system() -> Dict[str, any]:
    """
    Initialize the complete help system
    
    Returns:
        Initialization report
    """
    logger.info("Initializing Spectra help system...")
    
    try:
        # Discover modules
        discovery = get_module_discovery()
        discovered_count = discovery.discover_all_modules()
        
        # Validate modules
        validation_report = discovery.validate_discovered_modules()
        
        # Get registry statistics
        registry = get_registry()
        registry_stats = registry.get_statistics()
        
        report = {
            'status': 'success',
            'message': f'Help system initialized with {discovered_count} modules',
            'discovered_modules': discovered_count,
            'registry_stats': registry_stats,
            'validation': validation_report,
            'errors': discovery.discovery_errors
        }
        
        if discovery.discovery_errors:
            report['status'] = 'warning'
            report['message'] += f' ({len(discovery.discovery_errors)} errors)'
        
        logger.info(f"Help system initialization completed: {report['message']}")
        return report
        
    except Exception as e:
        error_msg = f"Failed to initialize help system: {e}"
        logger.error(error_msg)
        return {
            'status': 'error',
            'message': error_msg,
            'discovered_modules': 0,
            'errors': [error_msg]
        }