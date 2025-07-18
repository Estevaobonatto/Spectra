# -*- coding: utf-8 -*-
"""
Tests for module metadata system
"""

import pytest
from spectra.core.module_metadata import (
    ModuleMetadata, Parameter, Example, UseCase, ModuleCategory,
    ParameterType, ExampleLevel, MetadataValidator, ValidationResult
)


class TestParameter:
    """Test Parameter class"""
    
    def test_parameter_creation(self):
        """Test basic parameter creation"""
        param = Parameter(
            name="port-scan",
            short_name="ps",
            description="Execute port scan on target",
            param_type=ParameterType.STRING,
            required=True
        )
        
        assert param.name == "port-scan"
        assert param.short_name == "ps"
        assert param.description == "Execute port scan on target"
        assert param.param_type == ParameterType.STRING
        assert param.required is True
    
    def test_parameter_validation(self):
        """Test parameter validation"""
        # Empty name should raise error
        with pytest.raises(ValueError, match="Parameter name cannot be empty"):
            Parameter(name="", description="Test")
        
        # Empty description should raise error
        with pytest.raises(ValueError, match="must have a description"):
            Parameter(name="test", description="")
    
    def test_parameter_with_choices(self):
        """Test parameter with choices"""
        param = Parameter(
            name="scan-type",
            description="Type of scan",
            param_type=ParameterType.CHOICE,
            choices=["tcp", "udp", "syn"],
            default_value="tcp"
        )
        
        assert param.choices == ["tcp", "udp", "syn"]
        assert param.default_value == "tcp"


class TestExample:
    """Test Example class"""
    
    def test_example_creation(self):
        """Test basic example creation"""
        example = Example(
            title="Basic Port Scan",
            description="Scan common ports on target",
            command="spectra -ps example.com",
            level=ExampleLevel.BASIC
        )
        
        assert example.title == "Basic Port Scan"
        assert example.description == "Scan common ports on target"
        assert example.command == "spectra -ps example.com"
        assert example.level == ExampleLevel.BASIC
    
    def test_example_validation(self):
        """Test example validation"""
        # Empty title should raise error
        with pytest.raises(ValueError, match="Example title cannot be empty"):
            Example(title="", description="Test", command="test")
        
        # Empty description should raise error
        with pytest.raises(ValueError, match="Example description cannot be empty"):
            Example(title="Test", description="", command="test")
        
        # Empty command should raise error
        with pytest.raises(ValueError, match="Example command cannot be empty"):
            Example(title="Test", description="Test", command="")


class TestUseCase:
    """Test UseCase class"""
    
    def test_use_case_creation(self):
        """Test basic use case creation"""
        use_case = UseCase(
            title="Network Reconnaissance",
            description="Discover open ports and services",
            scenario="When you need to assess network security",
            steps=["Run port scan", "Analyze results", "Generate report"]
        )
        
        assert use_case.title == "Network Reconnaissance"
        assert use_case.description == "Discover open ports and services"
        assert use_case.scenario == "When you need to assess network security"
        assert len(use_case.steps) == 3
    
    def test_use_case_validation(self):
        """Test use case validation"""
        # Empty title should raise error
        with pytest.raises(ValueError, match="Use case title cannot be empty"):
            UseCase(title="", description="Test", scenario="Test")
        
        # Empty description should raise error
        with pytest.raises(ValueError, match="Use case description cannot be empty"):
            UseCase(title="Test", description="", scenario="Test")


class TestModuleMetadata:
    """Test ModuleMetadata class"""
    
    def test_module_metadata_creation(self):
        """Test basic module metadata creation"""
        metadata = ModuleMetadata(
            name="port_scanner",
            display_name="Port Scanner",
            category=ModuleCategory.RECONNAISSANCE,
            description="Advanced port scanning capabilities"
        )
        
        assert metadata.name == "port_scanner"
        assert metadata.display_name == "Port Scanner"
        assert metadata.category == ModuleCategory.RECONNAISSANCE
        assert metadata.description == "Advanced port scanning capabilities"
    
    def test_module_metadata_validation(self):
        """Test module metadata validation"""
        # Empty name should raise error
        with pytest.raises(ValueError, match="Module name cannot be empty"):
            ModuleMetadata(
                name="",
                display_name="Test",
                category=ModuleCategory.RECONNAISSANCE,
                description="Test"
            )
        
        # Invalid category should raise error
        with pytest.raises(ValueError, match="Module category must be a ModuleCategory enum"):
            ModuleMetadata(
                name="test",
                display_name="Test",
                category="invalid",  # type: ignore
                description="Test"
            )
    
    def test_get_parameter(self):
        """Test parameter retrieval"""
        param1 = Parameter(name="port-scan", short_name="ps", description="Port scan")
        param2 = Parameter(name="verbose", short_name="v", description="Verbose output")
        
        metadata = ModuleMetadata(
            name="test_module",
            display_name="Test Module",
            category=ModuleCategory.RECONNAISSANCE,
            description="Test module",
            parameters=[param1, param2]
        )
        
        # Test retrieval by full name
        found_param = metadata.get_parameter("port-scan")
        assert found_param is not None
        assert found_param.name == "port-scan"
        
        # Test retrieval by short name
        found_param = metadata.get_parameter("v")
        assert found_param is not None
        assert found_param.name == "verbose"
        
        # Test non-existent parameter
        found_param = metadata.get_parameter("nonexistent")
        assert found_param is None
    
    def test_get_examples_by_level(self):
        """Test example filtering by level"""
        basic_example = Example(
            title="Basic", description="Basic usage", command="test", level=ExampleLevel.BASIC
        )
        advanced_example = Example(
            title="Advanced", description="Advanced usage", command="test", level=ExampleLevel.ADVANCED
        )
        
        metadata = ModuleMetadata(
            name="test_module",
            display_name="Test Module",
            category=ModuleCategory.RECONNAISSANCE,
            description="Test module",
            examples=[basic_example, advanced_example]
        )
        
        basic_examples = metadata.get_examples_by_level(ExampleLevel.BASIC)
        assert len(basic_examples) == 1
        assert basic_examples[0].title == "Basic"
        
        advanced_examples = metadata.get_examples_by_level(ExampleLevel.ADVANCED)
        assert len(advanced_examples) == 1
        assert advanced_examples[0].title == "Advanced"
    
    def test_required_optional_parameters(self):
        """Test required and optional parameter filtering"""
        required_param = Parameter(name="target", description="Target host", required=True)
        optional_param = Parameter(name="verbose", description="Verbose output", required=False)
        
        metadata = ModuleMetadata(
            name="test_module",
            display_name="Test Module",
            category=ModuleCategory.RECONNAISSANCE,
            description="Test module",
            parameters=[required_param, optional_param]
        )
        
        required_params = metadata.get_required_parameters()
        assert len(required_params) == 1
        assert required_params[0].name == "target"
        
        optional_params = metadata.get_optional_parameters()
        assert len(optional_params) == 1
        assert optional_params[0].name == "verbose"
    
    def test_to_dict_conversion(self):
        """Test conversion to dictionary"""
        param = Parameter(name="test-param", description="Test parameter")
        example = Example(title="Test", description="Test example", command="test command")
        
        metadata = ModuleMetadata(
            name="test_module",
            display_name="Test Module",
            category=ModuleCategory.RECONNAISSANCE,
            description="Test module",
            parameters=[param],
            examples=[example]
        )
        
        data = metadata.to_dict()
        
        assert data['name'] == "test_module"
        assert data['display_name'] == "Test Module"
        assert data['category'] == "reconnaissance"
        assert len(data['parameters']) == 1
        assert len(data['examples']) == 1
        assert data['parameters'][0]['name'] == "test-param"
        assert data['examples'][0]['title'] == "Test"
    
    def test_from_dict_conversion(self):
        """Test creation from dictionary"""
        data = {
            'name': 'test_module',
            'display_name': 'Test Module',
            'category': 'reconnaissance',
            'description': 'Test module',
            'parameters': [
                {
                    'name': 'test-param',
                    'description': 'Test parameter',
                    'type': 'string',
                    'required': False
                }
            ],
            'examples': [
                {
                    'title': 'Test Example',
                    'description': 'Test description',
                    'command': 'test command',
                    'level': 'basic'
                }
            ],
            'use_cases': []
        }
        
        metadata = ModuleMetadata.from_dict(data)
        
        assert metadata.name == "test_module"
        assert metadata.display_name == "Test Module"
        assert metadata.category == ModuleCategory.RECONNAISSANCE
        assert len(metadata.parameters) == 1
        assert len(metadata.examples) == 1
        assert metadata.parameters[0].name == "test-param"
        assert metadata.examples[0].title == "Test Example"


class TestMetadataValidator:
    """Test MetadataValidator class"""
    
    def test_valid_metadata(self):
        """Test validation of valid metadata"""
        validator = MetadataValidator()
        
        metadata = ModuleMetadata(
            name="port_scanner",
            display_name="Port Scanner",
            category=ModuleCategory.RECONNAISSANCE,
            description="Advanced port scanning tool for network reconnaissance",
            detailed_description="This module provides comprehensive port scanning capabilities with multiple scan types and advanced features.",
            version="1.0.0",
            cli_command="-ps",
            parameters=[
                Parameter(
                    name="target",
                    short_name="t",
                    description="Target host or IP address to scan",
                    required=True,
                    examples=["example.com", "192.168.1.1"]
                )
            ],
            examples=[
                Example(
                    title="Basic Port Scan",
                    description="Perform a basic port scan on target host",
                    command="spectra -ps example.com",
                    level=ExampleLevel.BASIC
                )
            ]
        )
        
        result = validator.validate_metadata(metadata)
        assert result.is_valid
        assert len(result.errors) == 0
    
    def test_invalid_module_name(self):
        """Test validation of invalid module name"""
        validator = MetadataValidator()
        
        metadata = ModuleMetadata(
            name="Port-Scanner",  # Invalid: should be snake_case
            display_name="Port Scanner",
            category=ModuleCategory.RECONNAISSANCE,
            description="Port scanning tool"
        )
        
        result = validator.validate_metadata(metadata)
        assert not result.is_valid
        assert any("snake_case" in error for error in result.errors)
    
    def test_missing_required_fields(self):
        """Test validation with missing required fields"""
        validator = MetadataValidator()
        
        metadata = ModuleMetadata(
            name="test_module",
            display_name="Test Module",
            category=ModuleCategory.RECONNAISSANCE,
            description=""  # Empty description
        )
        
        result = validator.validate_metadata(metadata)
        assert not result.is_valid
        assert any("Description is required" in error for error in result.errors)
    
    def test_parameter_validation(self):
        """Test parameter validation"""
        validator = MetadataValidator()
        
        # Duplicate parameter names
        metadata = ModuleMetadata(
            name="test_module",
            display_name="Test Module",
            category=ModuleCategory.RECONNAISSANCE,
            description="Test module with duplicate parameters",
            parameters=[
                Parameter(name="target", description="Target host"),
                Parameter(name="target", description="Another target")  # Duplicate
            ]
        )
        
        result = validator.validate_metadata(metadata)
        assert not result.is_valid
        assert any("Duplicate parameter name" in error for error in result.errors)
    
    def test_example_validation(self):
        """Test example validation"""
        validator = MetadataValidator()
        
        # No examples
        metadata = ModuleMetadata(
            name="test_module",
            display_name="Test Module",
            category=ModuleCategory.RECONNAISSANCE,
            description="Test module without examples",
            examples=[]
        )
        
        result = validator.validate_metadata(metadata)
        assert not result.is_valid
        assert any("at least one usage example" in error for error in result.errors)
    
    def test_validation_warnings(self):
        """Test validation warnings"""
        validator = MetadataValidator()
        
        metadata = ModuleMetadata(
            name="test_module",
            display_name="Test Module",
            category=ModuleCategory.RECONNAISSANCE,
            description="Test module",
            examples=[
                Example(
                    title="Test",
                    description="Test example",
                    command="spectra -test example.com",  # Valid command
                    level=ExampleLevel.BASIC
                )
            ]
        )
        
        result = validator.validate_metadata(metadata)
        assert result.is_valid  # Should be valid but have warnings
        assert len(result.warnings) > 0  # Should have warnings about missing fields


if __name__ == "__main__":
    pytest.main([__file__])