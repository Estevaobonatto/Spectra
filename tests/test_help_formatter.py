# -*- coding: utf-8 -*-
"""
Unit tests for HelpFormatter
"""

import pytest
import json
from spectra.core.help_system.help_formatter import HelpFormatter, OutputFormat
from spectra.core.module_metadata import (
    ModuleMetadata, Parameter, Example, UseCase,
    ModuleCategory, ParameterType
)


class TestHelpFormatter:
    """Test HelpFormatter class"""
    
    def create_sample_metadata(self) -> ModuleMetadata:
        """Create sample metadata for testing"""
        return ModuleMetadata(
            name="test_scanner",
            display_name="Test Scanner",
            category=ModuleCategory.RECONNAISSANCE,
            description="A test scanner module",
            detailed_description="This is a detailed description of the test scanner module that provides comprehensive scanning capabilities",
            parameters=[
                Parameter(
                    name="target",
                    description="Target hostname or IP address to scan",
                    param_type=ParameterType.STRING,
                    required=True,
                    examples=["example.com", "192.168.1.1"]
                ),
                Parameter(
                    name="port",
                    short_name="p",
                    description="Port number to scan",
                    param_type=ParameterType.PORT,
                    default_value=80,
                    examples=["80", "443", "22"],
                    help_group="Network"
                ),
                Parameter(
                    name="timeout",
                    description="Connection timeout in seconds",
                    param_type=ParameterType.INTEGER,
                    default_value=10,
                    examples=["5", "10", "30"]
                )
            ],
            examples=[
                Example(
                    title="Basic Scan",
                    description="Perform a basic scan on a target",
                    command="spectra --test-scanner example.com",
                    level="basic"
                ),
                Example(
                    title="Port-Specific Scan",
                    description="Scan a specific port on a target",
                    command="spectra --test-scanner example.com -p 443",
                    level="intermediate",
                    prerequisites=["Target must be accessible"]
                ),
                Example(
                    title="Advanced Scan with Timeout",
                    description="Advanced scan with custom timeout",
                    command="spectra --test-scanner example.com -p 443 --timeout 30",
                    level="advanced",
                    notes="Use higher timeout for slow networks"
                )
            ],
            use_cases=[
                UseCase(
                    title="Network Discovery",
                    description="Discover active hosts on a network",
                    scenario="When you need to map network topology",
                    steps=["Identify target range", "Run basic scan", "Analyze results"]
                )
            ],
            cli_flags=["--test-scanner", "-ts"],
            tags=["scanning", "network"],
            related_modules=["port_scanner", "banner_grabber"]
        )
    
    def test_formatter_creation(self):
        """Test formatter creation with default settings"""
        formatter = HelpFormatter()
        
        assert formatter.width == 80
        assert formatter.indent == 2
        assert formatter.indent_str == "  "
    
    def test_formatter_custom_settings(self):
        """Test formatter creation with custom settings"""
        formatter = HelpFormatter(width=100, indent=4)
        
        assert formatter.width == 100
        assert formatter.indent == 4
        assert formatter.indent_str == "    "
    
    def test_format_module_help_text(self):
        """Test formatting module help in text format"""
        formatter = HelpFormatter()
        metadata = self.create_sample_metadata()
        
        result = formatter.format_module_help(metadata, OutputFormat.TEXT)
        
        # Check basic structure
        assert "Test Scanner" in result
        assert "=" in result  # Header underline
        assert "Module: test_scanner" in result
        assert "Category: Reconnaissance" in result
        assert "Tags: scanning, network" in result
        
        # Check description
        assert "Description:" in result
        # Check that key parts of the description are present (may be wrapped)
        assert "detailed description" in result
        assert "comprehensive scanning capabilities" in result
        
        # Check usage
        assert "Usage:" in result
        assert "spectra --test-scanner [options]" in result
        assert "Aliases: -ts" in result
        
        # Check parameters
        assert "Parameters:" in result
        assert "--target" in result
        assert "--port, -p" in result
        assert "Required" in result
        
        # Check examples
        assert "Examples:" in result
        assert "Basic Examples:" in result
        assert "Intermediate Examples:" in result
        assert "Advanced Examples:" in result
        
        # Check use cases
        assert "Common Use Cases:" in result
        assert "Network Discovery" in result
        
        # Check related modules
        assert "Related Modules:" in result
        assert "port_scanner, banner_grabber" in result
    
    def test_format_module_help_json(self):
        """Test formatting module help in JSON format"""
        formatter = HelpFormatter()
        metadata = self.create_sample_metadata()
        
        result = formatter.format_module_help(metadata, OutputFormat.JSON)
        
        # Parse JSON to verify structure
        data = json.loads(result)
        
        assert data["name"] == "test_scanner"
        assert data["display_name"] == "Test Scanner"
        assert data["category"] == "reconnaissance"
        assert len(data["parameters"]) == 3
        assert len(data["examples"]) == 3
        assert data["tags"] == ["scanning", "network"]
    
    def test_format_module_help_without_examples(self):
        """Test formatting module help without examples"""
        formatter = HelpFormatter()
        metadata = self.create_sample_metadata()
        
        result = formatter.format_module_help(metadata, include_examples=False)
        
        assert "Examples:\n" not in result  # Section header
        assert "Basic Examples:" not in result
    
    def test_format_module_help_without_parameters(self):
        """Test formatting module help without parameters"""
        formatter = HelpFormatter()
        metadata = self.create_sample_metadata()
        
        result = formatter.format_module_help(metadata, include_parameters=False)
        
        assert "Parameters:" not in result
        assert "--target" not in result
    
    def test_format_parameters_text(self):
        """Test formatting parameters in text format"""
        formatter = HelpFormatter()
        metadata = self.create_sample_metadata()
        
        result = formatter.format_parameters(metadata.parameters, OutputFormat.TEXT)
        
        # Check parameter formatting
        assert "--target" in result
        assert "--port, -p" in result
        assert "--timeout" in result
        
        # Check parameter details
        assert "Required" in result
        assert "Default: 80" in result
        assert "Type: port" in result
        assert "Examples: example.com, 192.168.1.1" in result
    
    def test_format_parameters_grouped_by_required(self):
        """Test formatting parameters grouped by required status"""
        formatter = HelpFormatter()
        metadata = self.create_sample_metadata()
        
        result = formatter.format_parameters(metadata.parameters, group_by="required")
        
        assert "Required:" in result
        assert "Optional:" in result
        
        # Target should be in required section
        required_section = result.split("Optional:")[0]
        assert "--target" in required_section
        
        # Port and timeout should be in optional section
        optional_section = result.split("Optional:")[1]
        assert "--port" in optional_section
        assert "--timeout" in optional_section
    
    def test_format_parameters_grouped_by_help_group(self):
        """Test formatting parameters grouped by help group"""
        formatter = HelpFormatter()
        metadata = self.create_sample_metadata()
        
        result = formatter.format_parameters(metadata.parameters, group_by="help_group")
        
        assert "Network:" in result
        assert "General:" in result
        
        # Port should be in Network group
        network_section = result.split("General:")[0]
        assert "--port" in network_section
    
    def test_format_parameters_json(self):
        """Test formatting parameters in JSON format"""
        formatter = HelpFormatter()
        metadata = self.create_sample_metadata()
        
        result = formatter.format_parameters(metadata.parameters, OutputFormat.JSON)
        
        data = json.loads(result)
        assert "parameters" in data
        assert len(data["parameters"]) == 3
        
        # Check first parameter
        param = data["parameters"][0]
        assert param["name"] == "target"
        assert param["required"] is True
        assert param["type"] == "str"
    
    def test_format_examples_text(self):
        """Test formatting examples in text format"""
        formatter = HelpFormatter()
        metadata = self.create_sample_metadata()
        
        result = formatter.format_examples(metadata.examples, OutputFormat.TEXT)
        
        # Check level grouping
        assert "Basic Examples:" in result
        assert "Intermediate Examples:" in result
        assert "Advanced Examples:" in result
        
        # Check example content
        assert "Basic Scan" in result
        assert "Port-Specific Scan" in result
        assert "Advanced Scan with Timeout" in result
        
        # Check commands
        assert "$ spectra --test-scanner example.com" in result
        assert "$ spectra --test-scanner example.com -p 443" in result
        
        # Check prerequisites and notes
        assert "Prerequisites: Target must be accessible" in result
        assert "Note: Use higher timeout for slow networks" in result
    
    def test_format_examples_with_level_filter(self):
        """Test formatting examples with level filter"""
        formatter = HelpFormatter()
        metadata = self.create_sample_metadata()
        
        result = formatter.format_examples(metadata.examples, level_filter="basic")
        
        assert "Basic Scan" in result
        assert "Port-Specific Scan" not in result
        assert "Advanced Scan" not in result
    
    def test_format_examples_json(self):
        """Test formatting examples in JSON format"""
        formatter = HelpFormatter()
        metadata = self.create_sample_metadata()
        
        result = formatter.format_examples(metadata.examples, OutputFormat.JSON)
        
        data = json.loads(result)
        assert "examples" in data
        assert len(data["examples"]) == 3
        
        # Check first example
        example = data["examples"][0]
        assert example["title"] == "Basic Scan"
        assert example["level"] == "basic"
        assert example["command"] == "spectra --test-scanner example.com"
    
    def test_format_general_help_text(self):
        """Test formatting general help in text format"""
        formatter = HelpFormatter()
        
        # Create modules for different categories
        recon_module = self.create_sample_metadata()
        recon_module.name = "port_scanner"
        recon_module.display_name = "Port Scanner"
        recon_module.cli_flags = ["--port-scan", "-ps"]
        
        vuln_module = self.create_sample_metadata()
        vuln_module.name = "sql_scanner"
        vuln_module.display_name = "SQL Scanner"
        vuln_module.category = ModuleCategory.VULNERABILITY_DETECTION
        vuln_module.cli_flags = ["--sql-scan", "-sql"]
        
        modules = {
            ModuleCategory.RECONNAISSANCE: [recon_module],
            ModuleCategory.VULNERABILITY_DETECTION: [vuln_module]
        }
        
        result = formatter.format_general_help(modules, OutputFormat.TEXT)
        
        # Check header
        assert "Spectra - Web Security Suite" in result
        assert "=" in result
        
        # Check categories
        assert "[Reconnaissance]" in result
        assert "[Vulnerability Detection]" in result
        
        # Check modules
        assert "--port-scan, -ps" in result
        assert "--sql-scan, -sql" in result
        
        # Check usage info
        assert "Usage:" in result
        assert "spectra <module> [options]" in result
        assert "spectra --help <module>" in result
    
    def test_format_general_help_json(self):
        """Test formatting general help in JSON format"""
        formatter = HelpFormatter()
        
        recon_module = self.create_sample_metadata()
        modules = {ModuleCategory.RECONNAISSANCE: [recon_module]}
        
        result = formatter.format_general_help(modules, OutputFormat.JSON)
        
        data = json.loads(result)
        assert data["title"] == "Spectra - Web Security Suite"
        assert "categories" in data
        assert "reconnaissance" in data["categories"]
        
        recon_data = data["categories"]["reconnaissance"]
        assert recon_data["name"] == "Reconnaissance"
        assert len(recon_data["modules"]) == 1
        assert recon_data["modules"][0]["name"] == "test_scanner"
    
    def test_format_category_help_text(self):
        """Test formatting category help in text format"""
        formatter = HelpFormatter()
        metadata = self.create_sample_metadata()
        
        result = formatter.format_category_help(
            ModuleCategory.RECONNAISSANCE, 
            [metadata], 
            OutputFormat.TEXT
        )
        
        # Check header
        assert "Reconnaissance Modules" in result
        assert "=" in result
        
        # Check category info
        assert "Category: Reconnaissance" in result
        assert "Modules: 1" in result
        
        # Check description
        assert "Description:" in result
        assert "information gathering" in result
        
        # Check module list
        assert "Available Modules:" in result
        assert "--test-scanner, -ts" in result
        assert metadata.description in result
    
    def test_format_category_help_json(self):
        """Test formatting category help in JSON format"""
        formatter = HelpFormatter()
        metadata = self.create_sample_metadata()
        
        result = formatter.format_category_help(
            ModuleCategory.RECONNAISSANCE,
            [metadata],
            OutputFormat.JSON
        )
        
        data = json.loads(result)
        assert "category" in data
        
        category_data = data["category"]
        assert category_data["name"] == "reconnaissance"
        assert category_data["display_name"] == "Reconnaissance"
        assert category_data["module_count"] == 1
        assert len(category_data["modules"]) == 1
        assert category_data["modules"][0]["name"] == "test_scanner"
    
    def test_format_parameter_name(self):
        """Test parameter name formatting"""
        formatter = HelpFormatter()
        
        # Parameter with short name
        param_with_short = Parameter(name="verbose", short_name="v", description="Verbose output")
        result = formatter._format_parameter_name(param_with_short)
        assert result == "--verbose, -v"
        
        # Parameter without short name
        param_without_short = Parameter(name="timeout", description="Timeout value")
        result = formatter._format_parameter_name(param_without_short)
        assert result == "--timeout"
    
    def test_format_category_name(self):
        """Test category name formatting"""
        formatter = HelpFormatter()
        
        result = formatter._format_category_name(ModuleCategory.RECONNAISSANCE)
        assert result == "Reconnaissance"
        
        result = formatter._format_category_name(ModuleCategory.VULNERABILITY_DETECTION)
        assert result == "Vulnerability Detection"
        
        result = formatter._format_category_name(ModuleCategory.SECURITY_ANALYSIS)
        assert result == "Security Analysis"
    
    def test_unsupported_format_error(self):
        """Test error handling for unsupported formats"""
        formatter = HelpFormatter()
        metadata = self.create_sample_metadata()
        
        with pytest.raises(ValueError, match="Unsupported format"):
            formatter.format_module_help(metadata, "invalid_format")
        
        with pytest.raises(ValueError, match="Unsupported format"):
            formatter.format_parameters(metadata.parameters, "invalid_format")
        
        with pytest.raises(ValueError, match="Unsupported format"):
            formatter.format_examples(metadata.examples, "invalid_format")
    
    def test_empty_data_handling(self):
        """Test handling of empty data"""
        formatter = HelpFormatter()
        
        # Empty parameters
        result = formatter.format_parameters([], OutputFormat.TEXT)
        assert "No parameters available" in result
        
        # Empty examples
        result = formatter.format_examples([], OutputFormat.TEXT)
        assert "No examples available" in result
        
        # Module without parameters or examples
        minimal_metadata = ModuleMetadata(
            name="minimal",
            display_name="Minimal Module",
            category=ModuleCategory.RECONNAISSANCE,
            description="A minimal module",
            detailed_description="This is a minimal module for testing"
        )
        
        result = formatter.format_module_help(minimal_metadata)
        assert "Minimal Module" in result
        assert "No parameters available" in result
        assert "No examples available" in result


if __name__ == "__main__":
    pytest.main([__file__])