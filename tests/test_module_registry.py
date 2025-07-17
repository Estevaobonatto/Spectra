# -*- coding: utf-8 -*-
"""
Tests for ModuleRegistry
"""

import pytest
import tempfile
import os
from spectra.core.help_system.module_registry import ModuleRegistry, get_registry, register_module
from spectra.core.module_metadata import (
    ModuleMetadata, Parameter, Example, ModuleCategory, ExampleLevel
)


class TestModuleRegistry:
    """Test ModuleRegistry class"""
    
    def setup_method(self):
        """Setup for each test"""
        self.registry = ModuleRegistry()
        
        # Create sample metadata
        self.sample_metadata = ModuleMetadata(
            name="port_scanner",
            display_name="Port Scanner",
            category=ModuleCategory.RECONNAISSANCE,
            description="Advanced port scanning tool",
            cli_command="-ps",
            tags=["network", "scanning", "ports"],
            parameters=[
                Parameter(name="target", description="Target host", required=True),
                Parameter(name="ports", description="Ports to scan")
            ],
            examples=[
                Example(
                    title="Basic Scan",
                    description="Basic port scan",
                    command="spectra -ps example.com",
                    level=ExampleLevel.BASIC
                )
            ]
        )
    
    def test_register_module(self):
        """Test module registration"""
        result = self.registry.register_module(self.sample_metadata)
        assert result is True
        assert "port_scanner" in self.registry.modules
        assert len(self.registry) == 1
    
    def test_register_duplicate_module(self):
        """Test registering duplicate module"""
        # Register first time
        result1 = self.registry.register_module(self.sample_metadata)
        assert result1 is True
        
        # Register again (should update)
        result2 = self.registry.register_module(self.sample_metadata)
        assert result2 is True
        assert len(self.registry) == 1
    
    def test_register_duplicate_cli_command(self):
        """Test registering modules with duplicate CLI commands"""
        # Register first module
        result1 = self.registry.register_module(self.sample_metadata)
        assert result1 is True
        
        # Create second module with same CLI command
        duplicate_metadata = ModuleMetadata(
            name="another_scanner",
            display_name="Another Scanner",
            category=ModuleCategory.RECONNAISSANCE,
            description="Another scanner",
            cli_command="-ps"  # Same CLI command
        )
        
        result2 = self.registry.register_module(duplicate_metadata)
        assert result2 is False  # Should fail
    
    def test_get_module(self):
        """Test module retrieval"""
        self.registry.register_module(self.sample_metadata)
        
        # Get by module name
        module = self.registry.get_module("port_scanner")
        assert module is not None
        assert module.name == "port_scanner"
        
        # Get by CLI command
        module = self.registry.get_module("-ps")
        assert module is not None
        assert module.name == "port_scanner"
        
        # Get non-existent module
        module = self.registry.get_module("nonexistent")
        assert module is None
    
    def test_unregister_module(self):
        """Test module unregistration"""
        self.registry.register_module(self.sample_metadata)
        assert len(self.registry) == 1
        
        result = self.registry.unregister_module("port_scanner")
        assert result is True
        assert len(self.registry) == 0
        assert "port_scanner" not in self.registry
    
    def test_get_modules_by_category(self):
        """Test getting modules by category"""
        # Register modules in different categories
        recon_module = ModuleMetadata(
            name="recon_tool",
            display_name="Recon Tool",
            category=ModuleCategory.RECONNAISSANCE,
            description="Reconnaissance tool"
        )
        
        vuln_module = ModuleMetadata(
            name="vuln_scanner",
            display_name="Vulnerability Scanner",
            category=ModuleCategory.VULNERABILITY_DETECTION,
            description="Vulnerability scanner"
        )
        
        self.registry.register_module(recon_module)
        self.registry.register_module(vuln_module)
        
        # Get reconnaissance modules
        recon_modules = self.registry.get_modules_by_category(ModuleCategory.RECONNAISSANCE)
        assert len(recon_modules) == 1
        assert recon_modules[0].name == "recon_tool"
        
        # Get vulnerability modules
        vuln_modules = self.registry.get_modules_by_category(ModuleCategory.VULNERABILITY_DETECTION)
        assert len(vuln_modules) == 1
        assert vuln_modules[0].name == "vuln_scanner"
    
    def test_search_modules(self):
        """Test module search functionality"""
        self.registry.register_module(self.sample_metadata)
        
        # Search by name
        results = self.registry.search_modules("port")
        assert len(results) == 1
        assert results[0].name == "port_scanner"
        
        # Search by description
        results = self.registry.search_modules("scanning")
        assert len(results) == 1
        
        # Search by tag
        results = self.registry.search_modules("network")
        assert len(results) == 1
        
        # Search with no results
        results = self.registry.search_modules("nonexistent")
        assert len(results) == 0
    
    def test_suggest_similar_modules(self):
        """Test similar module suggestions"""
        self.registry.register_module(self.sample_metadata)
        
        # Test similar name suggestion
        suggestions = self.registry.suggest_similar_modules("port_scan")
        assert "port_scanner" in suggestions
        
        # Test CLI command suggestion
        suggestions = self.registry.suggest_similar_modules("-p")
        assert "-ps" in suggestions
    
    def test_get_modules_by_tag(self):
        """Test getting modules by tag"""
        self.registry.register_module(self.sample_metadata)
        
        # Get modules with 'network' tag
        modules = self.registry.get_modules_by_tag("network")
        assert len(modules) == 1
        assert modules[0].name == "port_scanner"
        
        # Get modules with non-existent tag
        modules = self.registry.get_modules_by_tag("nonexistent")
        assert len(modules) == 0
    
    def test_get_related_modules(self):
        """Test getting related modules"""
        # Create related modules
        related_metadata = ModuleMetadata(
            name="banner_grabber",
            display_name="Banner Grabber",
            category=ModuleCategory.RECONNAISSANCE,
            description="Banner grabbing tool"
        )
        
        # Set up relationship
        self.sample_metadata.related_modules = ["banner_grabber"]
        
        self.registry.register_module(self.sample_metadata)
        self.registry.register_module(related_metadata)
        
        # Get related modules
        related = self.registry.get_related_modules("port_scanner")
        assert len(related) >= 1
        assert any(m.name == "banner_grabber" for m in related)
    
    def test_validate_registry(self):
        """Test registry validation"""
        # Create module with missing related module reference
        invalid_metadata = ModuleMetadata(
            name="test_module",
            display_name="Test Module",
            category=ModuleCategory.RECONNAISSANCE,
            description="Test module",
            related_modules=["nonexistent_module"]
        )
        
        self.registry.register_module(invalid_metadata)
        
        issues = self.registry.validate_registry()
        assert len(issues['missing_references']) > 0
        assert "nonexistent_module" in issues['missing_references'][0]
    
    def test_export_import_registry(self):
        """Test registry export and import"""
        self.registry.register_module(self.sample_metadata)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_file = f.name
        
        try:
            # Export registry
            result = self.registry.export_registry(temp_file)
            assert result is True
            assert os.path.exists(temp_file)
            
            # Create new registry and import
            new_registry = ModuleRegistry()
            result = new_registry.import_registry(temp_file)
            assert result is True
            assert len(new_registry) == 1
            assert "port_scanner" in new_registry
            
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)
    
    def test_get_statistics(self):
        """Test registry statistics"""
        self.registry.register_module(self.sample_metadata)
        
        stats = self.registry.get_statistics()
        assert stats['total_modules'] == 1
        assert stats['total_parameters'] == 2  # target and ports
        assert stats['total_examples'] == 1
        assert stats['cli_commands'] == 1
        assert 'reconnaissance' in stats['categories']
    
    def test_registry_magic_methods(self):
        """Test registry magic methods"""
        self.registry.register_module(self.sample_metadata)
        
        # Test __len__
        assert len(self.registry) == 1
        
        # Test __contains__
        assert "port_scanner" in self.registry
        assert "nonexistent" not in self.registry
        
        # Test __iter__
        module_names = list(self.registry)
        assert "port_scanner" in module_names


class TestGlobalRegistry:
    """Test global registry functions"""
    
    def test_get_registry(self):
        """Test getting global registry"""
        registry1 = get_registry()
        registry2 = get_registry()
        
        # Should return same instance
        assert registry1 is registry2
    
    def test_register_module_function(self):
        """Test global register_module function"""
        metadata = ModuleMetadata(
            name="test_global",
            display_name="Test Global",
            category=ModuleCategory.RECONNAISSANCE,
            description="Test global registration"
        )
        
        result = register_module(metadata)
        assert result is True
        
        # Should be in global registry
        global_registry = get_registry()
        assert "test_global" in global_registry


if __name__ == "__main__":
    pytest.main([__file__])