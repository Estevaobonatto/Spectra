# -*- coding: utf-8 -*-
"""
Unit tests for HelpManager
"""

import pytest
from spectra.core.help_system.help_manager import HelpManager, HelpSystemError
from spectra.core.help_system.module_registry import ModuleRegistry, ModuleNotFoundError
from spectra.core.help_system.help_formatter import HelpFormatter
from spectra.core.module_metadata import (
    ModuleMetadata, Parameter, Example, ModuleCategory, 
    ParameterType, OutputFormat
)


class TestHelpManager:
    """Test HelpManager class"""
    
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
                ),
                Example(
                    title="Advanced Scan",
                    description="Advanced scanning example",
                    command=f"spectra --{name.replace('_', '-')} example.com -p 443",
                    level="advanced"
                )
            ],
            cli_flags=[f"--{name.replace('_', '-')}", f"-{name[0]}"],
            tags=["scanning", "network"]
        )
    
    def test_help_manager_creation(self):
        """Test HelpManager creation"""
        # Test with default components
        manager = HelpManager()
        
        assert isinstance(manager.registry, ModuleRegistry)
        assert isinstance(manager.formatter, HelpFormatter)
        assert manager.get_module_count() >= 0  # May have auto-discovered modules
    
    def test_help_manager_with_custom_components(self):
        """Test HelpManager with custom registry and formatter"""
        registry = ModuleRegistry()
        formatter = HelpFormatter(width=100)
        
        manager = HelpManager(registry=registry, formatter=formatter)
        
        assert manager.registry is registry
        assert manager.formatter is formatter
        assert manager.formatter.width == 100
    
    def test_register_and_get_module(self):
        """Test module registration and retrieval"""
        manager = HelpManager()
        metadata = self.create_sample_metadata("port_scanner")
        
        # Register module
        manager.register_module(metadata)
        
        # Test retrieval
        assert manager.is_module_registered("port_scanner")
        assert "port_scanner" in manager.get_all_module_names()
        
        # Test help generation
        help_text = manager.get_module_help("port_scanner")
        assert "Test Port_Scanner" in help_text
        assert "port_scanner" in help_text
    
    def test_get_module_help_by_cli_flag(self):
        """Test getting module help by CLI flag"""
        manager = HelpManager()
        metadata = self.create_sample_metadata("port_scanner")
        metadata.cli_flags = ["--port-scan", "-ps"]
        
        manager.register_module(metadata)
        
        # Test by full flag
        help_text = manager.get_module_help("--port-scan")
        assert "Test Port_Scanner" in help_text
        
        # Test by short flag
        help_text = manager.get_module_help("-ps")
        assert "Test Port_Scanner" in help_text
    
    def test_get_module_help_not_found(self):
        """Test getting help for non-existent module"""
        manager = HelpManager()
        
        with pytest.raises(ModuleNotFoundError):
            manager.get_module_help("nonexistent_module")
    
    def test_get_general_help(self):
        """Test getting general help"""
        manager = HelpManager()
        
        # Add some test modules
        recon_module = self.create_sample_metadata("port_scanner")
        recon_module.category = ModuleCategory.RECONNAISSANCE
        
        vuln_module = self.create_sample_metadata("sql_scanner")
        vuln_module.category = ModuleCategory.VULNERABILITY_DETECTION
        
        manager.register_module(recon_module)
        manager.register_module(vuln_module)
        
        # Test text format
        help_text = manager.get_general_help(OutputFormat.TEXT)
        assert "Spectra - Web Security Suite" in help_text
        assert "Reconnaissance" in help_text
        assert "Vulnerability Detection" in help_text
        
        # Test JSON format
        help_json = manager.get_general_help(OutputFormat.JSON)
        assert '"title": "Spectra - Web Security Suite"' in help_json
        assert '"reconnaissance"' in help_json
    
    def test_get_category_help(self):
        """Test getting category help"""
        manager = HelpManager()
        metadata = self.create_sample_metadata("port_scanner")
        metadata.category = ModuleCategory.RECONNAISSANCE
        
        manager.register_module(metadata)
        
        # Test by category value
        help_text = manager.get_category_help("reconnaissance")
        assert "Reconnaissance Modules" in help_text
        assert "port_scanner" in help_text
        
        # Test by formatted name
        help_text = manager.get_category_help("Reconnaissance")
        assert "Reconnaissance Modules" in help_text
        
        # Test invalid category
        with pytest.raises(ValueError, match="Category .* not found"):
            manager.get_category_help("invalid_category")
    
    def test_search_modules(self):
        """Test module search functionality"""
        manager = HelpManager()
        
        # Add test modules
        port_module = self.create_sample_metadata("port_scanner")
        port_module.description = "Scan network ports"
        port_module.tags = ["network", "ports"]
        
        web_module = self.create_sample_metadata("web_scanner")
        web_module.description = "Scan web applications"
        web_module.tags = ["web", "http"]
        
        manager.register_module(port_module)
        manager.register_module(web_module)
        
        # Test search by name
        results = manager.search_modules("port")
        assert len(results) >= 1
        assert any(mod.name == "port_scanner" for mod in results)
        
        # Test search by description
        results = manager.search_modules("network")
        assert len(results) >= 1
        assert any(mod.name == "port_scanner" for mod in results)
        
        # Test search by tag
        results = manager.search_modules("web")
        assert len(results) >= 1
        assert any(mod.name == "web_scanner" for mod in results)
    
    def test_search_parameters(self):
        """Test parameter search functionality"""
        manager = HelpManager()
        metadata = self.create_sample_metadata("test_scanner")
        
        # Add parameter with searchable content
        metadata.parameters.append(
            Parameter(
                name="timeout",
                description="Connection timeout in seconds",
                param_type=ParameterType.INTEGER
            )
        )
        
        manager.register_module(metadata)
        
        # Test parameter name search
        results = manager.search_parameters("timeout")
        assert len(results) >= 1
        assert results[0][1].name == "timeout"
        
        # Test parameter description search
        results = manager.search_parameters("connection")
        assert len(results) >= 1
        assert results[0][1].name == "timeout"
    
    def test_get_module_suggestions(self):
        """Test module name suggestions"""
        manager = HelpManager()
        
        # Add test modules
        manager.register_module(self.create_sample_metadata("port_scanner"))
        manager.register_module(self.create_sample_metadata("port_analyzer"))
        manager.register_module(self.create_sample_metadata("web_scanner"))
        
        # Test partial match
        suggestions = manager.get_module_suggestions("port")
        assert len(suggestions) >= 2
        assert "port_scanner" in suggestions
        assert "port_analyzer" in suggestions
        
        # Test fuzzy match
        suggestions = manager.get_module_suggestions("port_scan")
        assert "port_scanner" in suggestions
    
    def test_get_related_modules(self):
        """Test getting related modules"""
        manager = HelpManager()
        
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
        
        manager.register_module(port_module)
        manager.register_module(banner_module)
        manager.register_module(web_module)
        
        # Test related modules
        related = manager.get_related_modules("port_scanner")
        related_names = {mod.name for mod in related}
        
        # Should include explicitly related and same category
        assert "banner_grabber" in related_names
        # Should not include different category
        assert "web_scanner" not in related_names
    
    def test_get_help_for_cli_flag(self):
        """Test getting help for CLI flag"""
        manager = HelpManager()
        metadata = self.create_sample_metadata("port_scanner")
        metadata.cli_flags = ["--port-scan", "-ps"]
        
        manager.register_module(metadata)
        
        # Test existing flag
        help_text = manager.get_help_for_cli_flag("--port-scan")
        assert help_text is not None
        assert "Test Port_Scanner" in help_text
        
        # Test non-existent flag
        help_text = manager.get_help_for_cli_flag("--nonexistent")
        assert help_text is None
    
    def test_get_examples_for_module(self):
        """Test getting examples for a module"""
        manager = HelpManager()
        metadata = self.create_sample_metadata("test_scanner")
        manager.register_module(metadata)
        
        # Test all examples
        examples_text = manager.get_examples_for_module("test_scanner")
        assert "Basic Examples:" in examples_text
        assert "Advanced Examples:" in examples_text
        
        # Test filtered by level
        basic_examples = manager.get_examples_for_module("test_scanner", level="basic")
        assert "Basic Scan" in basic_examples
        assert "Advanced Scan" not in basic_examples
    
    def test_get_parameters_for_module(self):
        """Test getting parameters for a module"""
        manager = HelpManager()
        metadata = self.create_sample_metadata("test_scanner")
        manager.register_module(metadata)
        
        # Test all parameters
        params_text = manager.get_parameters_for_module("test_scanner")
        assert "--target" in params_text
        assert "--port" in params_text
        
        # Test grouped by required
        grouped_params = manager.get_parameters_for_module("test_scanner", group_by="required")
        assert "Required:" in grouped_params
        assert "Optional:" in grouped_params
    
    def test_unregister_module(self):
        """Test module unregistration"""
        manager = HelpManager()
        metadata = self.create_sample_metadata("test_module")
        
        # Register and verify
        manager.register_module(metadata)
        assert manager.is_module_registered("test_module")
        
        # Unregister and verify
        result = manager.unregister_module("test_module")
        assert result is True
        assert not manager.is_module_registered("test_module")
        
        # Try to unregister non-existent module
        result = manager.unregister_module("nonexistent")
        assert result is False
    
    def test_get_statistics(self):
        """Test getting help system statistics"""
        manager = HelpManager()
        
        # Add some modules
        manager.register_module(self.create_sample_metadata("module1"))
        manager.register_module(self.create_sample_metadata("module2"))
        
        stats = manager.get_statistics()
        
        assert 'total_modules' in stats
        assert 'help_system_version' in stats
        assert 'supported_formats' in stats
        assert stats['total_modules'] >= 2
        assert 'text' in stats['supported_formats']
        assert 'json' in stats['supported_formats']
    
    def test_validate_all_modules(self):
        """Test module validation"""
        manager = HelpManager()
        
        # Add valid module
        valid_metadata = self.create_sample_metadata("valid_module")
        manager.register_module(valid_metadata)
        
        # Validate
        report = manager.validate_all_modules()
        
        assert report.total_modules >= 1
        assert hasattr(report, 'valid_modules')
        assert hasattr(report, 'invalid_modules')
    
    def test_export_help_data(self):
        """Test exporting help data"""
        manager = HelpManager()
        metadata = self.create_sample_metadata("test_module")
        manager.register_module(metadata)
        
        # Test JSON export
        json_data = manager.export_help_data(OutputFormat.JSON)
        assert isinstance(json_data, str)
        assert 'test_module' in json_data
        
        # Test invalid format
        with pytest.raises(ValueError, match="Export format .* not supported"):
            manager.export_help_data(OutputFormat.HTML)
    
    def test_module_count_and_categories(self):
        """Test module and category counting"""
        manager = HelpManager()
        
        initial_count = manager.get_module_count()
        initial_categories = manager.get_category_count()
        
        # Add modules in different categories
        recon_module = self.create_sample_metadata("recon_module")
        recon_module.category = ModuleCategory.RECONNAISSANCE
        
        vuln_module = self.create_sample_metadata("vuln_module")
        vuln_module.category = ModuleCategory.VULNERABILITY_DETECTION
        
        manager.register_module(recon_module)
        manager.register_module(vuln_module)
        
        # Check counts
        assert manager.get_module_count() == initial_count + 2
        assert manager.get_category_count() >= initial_categories + 2
    
    def test_get_all_names_and_categories(self):
        """Test getting all names and categories"""
        manager = HelpManager()
        
        # Add test module
        metadata = self.create_sample_metadata("test_module")
        metadata.category = ModuleCategory.RECONNAISSANCE
        manager.register_module(metadata)
        
        # Test module names
        all_names = manager.get_all_module_names()
        assert "test_module" in all_names
        
        # Test categories
        all_categories = manager.get_all_categories()
        assert "reconnaissance" in all_categories
    
    def test_format_parameter_handling(self):
        """Test format parameter handling (string vs enum)"""
        manager = HelpManager()
        metadata = self.create_sample_metadata("test_module")
        manager.register_module(metadata)
        
        # Test string format
        help_text1 = manager.get_module_help("test_module", format="text")
        help_text2 = manager.get_module_help("test_module", format=OutputFormat.TEXT)
        
        # Should produce same result
        assert help_text1 == help_text2
        
        # Test JSON format
        help_json1 = manager.get_module_help("test_module", format="json")
        help_json2 = manager.get_module_help("test_module", format=OutputFormat.JSON)
        
        assert help_json1 == help_json2
        assert '"name": "test_module"' in help_json1
    
    def test_help_manager_repr(self):
        """Test HelpManager string representation"""
        manager = HelpManager()
        manager.register_module(self.create_sample_metadata("test_module"))
        
        repr_str = repr(manager)
        assert "HelpManager" in repr_str
        assert "modules" in repr_str
        assert "categories" in repr_str


if __name__ == "__main__":
    pytest.main([__file__])