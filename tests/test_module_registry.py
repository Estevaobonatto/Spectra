# -*- coding: utf-8 -*-
"""
Unit tests for ModuleRegistry
"""

import pytest
from spectra.core.help_system.module_registry import (
    ModuleRegistry, ModuleRegistryError, ModuleNotFoundError, DuplicateModuleError
)
from spectra.core.module_metadata import (
    ModuleMetadata, Parameter, Example, ModuleCategory, ParameterType
)


class TestModuleRegistry:
    """Test ModuleRegistry class"""
    
    def create_sample_metadata(self, name: str = "test_module") -> ModuleMetadata:
        """Create sample metadata for testing"""
        return ModuleMetadata(
            name=name,
            display_name=f"Test {name.title()}",
            category=ModuleCategory.RECONNAISSANCE,
            description=f"A test {name} module",
            detailed_description=f"This is a detailed description of the test {name} module",
            parameters=[
                Parameter(
                    name="target",
                    description="Target to scan",
                    param_type=ParameterType.STRING,
                    required=True,
                    examples=["example.com"]
                ),
                Parameter(
                    name="port",
                    short_name="p",
                    description="Port to scan",
                    param_type=ParameterType.PORT,
                    default_value=80,
                    examples=["80", "443"]
                )
            ],
            examples=[
                Example(
                    title="Basic Scan",
                    description="Basic scanning example",
                    command=f"spectra --{name.replace('_', '-')} example.com",
                    level="basic"
                )
            ],
            cli_flags=[f"--{name.replace('_', '-')}", f"-{name[0]}"],
            tags=["scanning", "network"]
        )
    
    def test_registry_creation(self):
        """Test registry creation"""
        registry = ModuleRegistry()
        
        assert len(registry) == 0
        assert registry.get_module_names() == []
        assert registry.get_all_categories() == {}
    
    def test_register_module(self):
        """Test module registration"""
        registry = ModuleRegistry()
        metadata = self.create_sample_metadata("port_scanner")
        
        registry.register_module(metadata)
        
        assert len(registry) == 1
        assert "port_scanner" in registry
        assert registry.get_module("port_scanner") == metadata
    
    def test_register_duplicate_module(self):
        """Test registering duplicate module"""
        registry = ModuleRegistry()
        metadata = self.create_sample_metadata("port_scanner")
        
        registry.register_module(metadata)
        
        # Should raise error for duplicate
        with pytest.raises(DuplicateModuleError):
            registry.register_module(metadata)
        
        # Should work with allow_override
        registry.register_module(metadata, allow_override=True)
        assert len(registry) == 1
    
    def test_unregister_module(self):
        """Test module unregistration"""
        registry = ModuleRegistry()
        metadata = self.create_sample_metadata("port_scanner")
        
        registry.register_module(metadata)
        assert len(registry) == 1
        
        # Unregister existing module
        result = registry.unregister_module("port_scanner")
        assert result is True
        assert len(registry) == 0
        assert "port_scanner" not in registry
        
        # Unregister non-existent module
        result = registry.unregister_module("nonexistent")
        assert result is False
    
    def test_get_module_not_found(self):
        """Test getting non-existent module"""
        registry = ModuleRegistry()
        
        with pytest.raises(ModuleNotFoundError) as exc_info:
            registry.get_module("nonexistent")
        
        assert "not found" in str(exc_info.value)
    
    def test_get_module_with_suggestions(self):
        """Test getting module with similar name suggestions"""
        registry = ModuleRegistry()
        registry.register_module(self.create_sample_metadata("port_scanner"))
        registry.register_module(self.create_sample_metadata("port_analyzer"))
        
        with pytest.raises(ModuleNotFoundError) as exc_info:
            registry.get_module("port_scan")  # Similar to port_scanner
        
        error_msg = str(exc_info.value)
        assert "Did you mean" in error_msg
        assert "port_scanner" in error_msg
    
    def test_get_modules_by_category(self):
        """Test getting modules by category"""
        registry = ModuleRegistry()
        
        # Add modules in different categories
        recon_module = self.create_sample_metadata("port_scanner")
        recon_module.category = ModuleCategory.RECONNAISSANCE
        
        vuln_module = self.create_sample_metadata("sql_scanner")
        vuln_module.category = ModuleCategory.VULNERABILITY_DETECTION
        
        registry.register_module(recon_module)
        registry.register_module(vuln_module)
        
        # Test category filtering
        recon_modules = registry.get_modules_by_category(ModuleCategory.RECONNAISSANCE)
        vuln_modules = registry.get_modules_by_category(ModuleCategory.VULNERABILITY_DETECTION)
        
        assert len(recon_modules) == 1
        assert len(vuln_modules) == 1
        assert recon_modules[0].name == "port_scanner"
        assert vuln_modules[0].name == "sql_scanner"
    
    def test_get_modules_by_tag(self):
        """Test getting modules by tag"""
        registry = ModuleRegistry()
        
        # Create modules with different tags
        module1 = self.create_sample_metadata("scanner1")
        module1.tags = ["network", "tcp"]
        
        module2 = self.create_sample_metadata("scanner2")
        module2.tags = ["network", "udp"]
        
        module3 = self.create_sample_metadata("scanner3")
        module3.tags = ["web", "http"]
        
        registry.register_module(module1)
        registry.register_module(module2)
        registry.register_module(module3)
        
        # Test tag filtering
        network_modules = registry.get_modules_by_tag("network")
        web_modules = registry.get_modules_by_tag("web")
        
        assert len(network_modules) == 2
        assert len(web_modules) == 1
        assert {mod.name for mod in network_modules} == {"scanner1", "scanner2"}
        assert web_modules[0].name == "scanner3"
    
    def test_get_module_by_cli_flag(self):
        """Test getting module by CLI flag"""
        registry = ModuleRegistry()
        metadata = self.create_sample_metadata("port_scanner")
        metadata.cli_flags = ["--port-scan", "-ps"]
        
        registry.register_module(metadata)
        
        # Test both flags
        module1 = registry.get_module_by_cli_flag("--port-scan")
        module2 = registry.get_module_by_cli_flag("-ps")
        
        assert module1 == metadata
        assert module2 == metadata
        
        # Test non-existent flag
        module3 = registry.get_module_by_cli_flag("--nonexistent")
        assert module3 is None
    
    def test_search_modules(self):
        """Test module search functionality"""
        registry = ModuleRegistry()
        
        # Create modules with different searchable content
        port_module = self.create_sample_metadata("port_scanner")
        port_module.description = "Scan network ports"
        port_module.tags = ["network", "ports"]
        
        web_module = self.create_sample_metadata("web_scanner")
        web_module.description = "Scan web applications"
        web_module.tags = ["web", "http"]
        
        registry.register_module(port_module)
        registry.register_module(web_module)
        
        # Test name search
        results = registry.search_modules("port_scanner")
        assert len(results) == 1
        assert results[0].name == "port_scanner"
        
        # Test description search
        results = registry.search_modules("network")
        assert len(results) == 1
        assert results[0].name == "port_scanner"
        
        # Test tag search
        results = registry.search_modules("web")
        assert len(results) == 1
        assert results[0].name == "web_scanner"
        
        # Test general search
        results = registry.search_modules("scan")
        assert len(results) == 2  # Both modules contain "scan"
    
    def test_search_parameters(self):
        """Test parameter search functionality"""
        registry = ModuleRegistry()
        
        # Create module with searchable parameters
        metadata = self.create_sample_metadata("test_scanner")
        metadata.parameters.append(
            Parameter(
                name="timeout",
                description="Connection timeout in seconds",
                param_type=ParameterType.INTEGER,
                examples=["10", "30"]
            )
        )
        
        registry.register_module(metadata)
        
        # Test parameter name search
        results = registry.search_parameters("timeout")
        assert len(results) == 1
        assert results[0][1].name == "timeout"
        
        # Test parameter description search
        results = registry.search_parameters("connection")
        assert len(results) == 1
        assert results[0][1].name == "timeout"
    
    def test_get_related_modules(self):
        """Test getting related modules"""
        registry = ModuleRegistry()
        
        # Create related modules
        port_module = self.create_sample_metadata("port_scanner")
        port_module.category = ModuleCategory.RECONNAISSANCE
        port_module.tags = ["network"]
        port_module.related_modules = ["banner_grabber"]
        
        banner_module = self.create_sample_metadata("banner_grabber")
        banner_module.category = ModuleCategory.RECONNAISSANCE
        banner_module.tags = ["network"]
        
        web_module = self.create_sample_metadata("web_scanner")
        web_module.category = ModuleCategory.VULNERABILITY_DETECTION
        web_module.tags = ["web"]
        
        registry.register_module(port_module)
        registry.register_module(banner_module)
        registry.register_module(web_module)
        
        # Test related modules
        related = registry.get_related_modules("port_scanner")
        related_names = {mod.name for mod in related}
        
        # Should include explicitly related module and same category
        assert "banner_grabber" in related_names
        # Should not include different category module
        assert "web_scanner" not in related_names
    
    def test_get_statistics(self):
        """Test registry statistics"""
        registry = ModuleRegistry()
        
        # Add some modules
        module1 = self.create_sample_metadata("scanner1")
        module1.category = ModuleCategory.RECONNAISSANCE
        module1.tags = ["network"]
        
        module2 = self.create_sample_metadata("scanner2")
        module2.category = ModuleCategory.VULNERABILITY_DETECTION
        module2.tags = ["web", "security"]
        
        registry.register_module(module1)
        registry.register_module(module2)
        
        stats = registry.get_statistics()
        
        assert stats['total_modules'] == 2
        assert stats['categories']['reconnaissance'] == 1
        assert stats['categories']['vulnerability_detection'] == 1
        assert stats['total_parameters'] == 4  # 2 params per module
        assert stats['total_examples'] == 2  # 1 example per module
    
    def test_export_registry(self):
        """Test registry export"""
        registry = ModuleRegistry()
        metadata = self.create_sample_metadata("test_module")
        registry.register_module(metadata)
        
        # Test JSON export
        json_data = registry.export_registry('json')
        assert isinstance(json_data, str)
        assert 'test_module' in json_data
        assert 'modules' in json_data
        assert 'statistics' in json_data
        
        # Test invalid format
        with pytest.raises(ValueError):
            registry.export_registry('invalid')
    
    def test_clear_registry(self):
        """Test clearing registry"""
        registry = ModuleRegistry()
        registry.register_module(self.create_sample_metadata("test1"))
        registry.register_module(self.create_sample_metadata("test2"))
        
        assert len(registry) == 2
        
        registry.clear()
        
        assert len(registry) == 0
        assert registry.get_module_names() == []
        assert registry.get_all_categories() == {}
    
    def test_registry_iteration(self):
        """Test registry iteration"""
        registry = ModuleRegistry()
        registry.register_module(self.create_sample_metadata("module1"))
        registry.register_module(self.create_sample_metadata("module2"))
        
        # Test iteration
        module_names = list(registry)
        assert len(module_names) == 2
        assert "module1" in module_names
        assert "module2" in module_names
    
    def test_registry_repr(self):
        """Test registry string representation"""
        registry = ModuleRegistry()
        registry.register_module(self.create_sample_metadata("test_module"))
        
        repr_str = repr(registry)
        assert "ModuleRegistry" in repr_str
        assert "1 modules" in repr_str
        assert "1 categories" in repr_str


if __name__ == "__main__":
    pytest.main([__file__])