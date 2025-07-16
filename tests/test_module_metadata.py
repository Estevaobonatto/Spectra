# -*- coding: utf-8 -*-
"""
Unit tests for module metadata system
"""

import pytest
from spectra.core.module_metadata import (
    ModuleMetadata, Parameter, Example, UseCase,
    ModuleCategory, ParameterType, MetadataValidator,
    ValidationResult, ValidationReport
)


class TestParameter:
    """Test Parameter class"""
    
    def test_parameter_creation(self):
        """Test basic parameter creation"""
        param = Parameter(
            name="test-param",
            description="Test parameter",
            param_type=ParameterType.STRING,
            required=True
        )
        
        assert param.name == "test-param"
        assert param.description == "Test parameter"
        assert param.param_type == ParameterType.STRING
        assert param.required is True
        assert param.examples == []
        assert param.depends_on == []
    
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
    
    def test_parameter_with_dependencies(self):
        """Test parameter with dependencies"""
        param = Parameter(
            name="advanced-scan",
            description="Advanced scanning options",
            depends_on=["scan-type"],
            conflicts_with=["quick-scan"]
        )
        
        assert "scan-type" in param.depends_on
        assert "quick-scan" in param.conflicts_with


class TestExample:
    """Test Example class"""
    
    def test_example_creation(self):
        """Test basic example creation"""
        example = Example(
            title="Basic Port Scan",
            description="Scan common ports on a target",
            command="spectra -ps example.com",
            level="basic"
        )
        
        assert example.title == "Basic Port Scan"
        assert example.level == "basic"
        assert example.prerequisites == []
    
    def test_example_with_prerequisites(self):
        """Test example with prerequisites"""
        example = Example(
            title="Advanced Scan",
            description="Advanced scanning with wordlist",
            command="spectra -ds https://example.com -w wordlist.txt",
            level="advanced",
            prerequisites=["wordlist.txt file", "target accessible"]
        )
        
        assert len(example.prerequisites) == 2
        assert "wordlist.txt file" in example.prerequisites


class TestModuleMetadata:
    """Test ModuleMetadata class"""
    
    def create_sample_metadata(self):
        """Create sample metadata for testing"""
        return ModuleMetadata(
            name="test_scanner",
            display_name="Test Scanner",
            category=ModuleCategory.RECONNAISSANCE,
            description="A test scanner module",
            detailed_description="This is a detailed description of the test scanner module",
            parameters=[
                Parameter(
                    name="target",
                    description="Target to scan",
                    param_type=ParameterType.STRING,
                    required=True
                ),
                Parameter(
                    name="port",
                    short_name="p",
                    description="Port to scan",
                    param_type=ParameterType.PORT,
                    default_value=80
                )
            ],
            examples=[
                Example(
                    title="Basic Scan",
                    description="Basic scanning example",
                    command="spectra --test-scanner example.com",
                    level="basic"
                )
            ]
        )
    
    def test_metadata_creation(self):
        """Test basic metadata creation"""
        metadata = self.create_sample_metadata()
        
        assert metadata.name == "test_scanner"
        assert metadata.category == ModuleCategory.RECONNAISSANCE
        assert len(metadata.parameters) == 2
        assert len(metadata.examples) == 1
    
    def test_get_parameter(self):
        """Test parameter retrieval"""
        metadata = self.create_sample_metadata()
        
        # Test by full name
        param = metadata.get_parameter("target")
        assert param is not None
        assert param.name == "target"
        
        # Test by short name
        param = metadata.get_parameter("p")
        assert param is not None
        assert param.name == "port"
        
        # Test non-existent parameter
        param = metadata.get_parameter("nonexistent")
        assert param is None
    
    def test_get_required_parameters(self):
        """Test required parameter filtering"""
        metadata = self.create_sample_metadata()
        required = metadata.get_required_parameters()
        
        assert len(required) == 1
        assert required[0].name == "target"
    
    def test_get_optional_parameters(self):
        """Test optional parameter filtering"""
        metadata = self.create_sample_metadata()
        optional = metadata.get_optional_parameters()
        
        assert len(optional) == 1
        assert optional[0].name == "port"
    
    def test_get_examples_by_level(self):
        """Test example filtering by level"""
        metadata = self.create_sample_metadata()
        
        # Add more examples
        metadata.examples.append(
            Example(
                title="Advanced Scan",
                description="Advanced example",
                command="spectra --test-scanner example.com --advanced",
                level="advanced"
            )
        )
        
        basic_examples = metadata.get_examples_by_level("basic")
        advanced_examples = metadata.get_examples_by_level("advanced")
        
        assert len(basic_examples) == 1
        assert len(advanced_examples) == 1
        assert basic_examples[0].title == "Basic Scan"
    
    def test_validate_parameter_dependencies(self):
        """Test parameter dependency validation"""
        metadata = self.create_sample_metadata()
        
        # Add parameter with invalid dependency
        metadata.parameters.append(
            Parameter(
                name="advanced-option",
                description="Advanced option",
                depends_on=["nonexistent-param"]
            )
        )
        
        issues = metadata.validate_parameter_dependencies()
        assert len(issues) == 1
        assert "nonexistent-param" in issues[0]
    
    def test_to_dict(self):
        """Test dictionary conversion"""
        metadata = self.create_sample_metadata()
        data = metadata.to_dict()
        
        assert data['name'] == "test_scanner"
        assert data['category'] == "reconnaissance"
        assert len(data['parameters']) == 2
        assert len(data['examples']) == 1
        
        # Check parameter structure
        param_data = data['parameters'][0]
        assert 'name' in param_data
        assert 'description' in param_data
        assert 'type' in param_data


class TestMetadataValidator:
    """Test MetadataValidator class"""
    
    def create_valid_metadata(self):
        """Create valid metadata for testing"""
        return ModuleMetadata(
            name="valid_scanner",
            display_name="Valid Scanner",
            category=ModuleCategory.RECONNAISSANCE,
            description="A valid scanner module for testing",
            detailed_description="This is a detailed description of the valid scanner module that provides comprehensive information about its functionality",
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
                    examples=["80", "443", "22"]
                )
            ],
            examples=[
                Example(
                    title="Basic Scan",
                    description="Perform a basic scan on a target",
                    command="spectra --valid-scanner example.com",
                    level="basic"
                ),
                Example(
                    title="Port-Specific Scan",
                    description="Scan a specific port on a target",
                    command="spectra --valid-scanner example.com -p 443",
                    level="intermediate"
                )
            ]
        )
    
    def test_validate_valid_metadata(self):
        """Test validation of valid metadata"""
        validator = MetadataValidator()
        metadata = self.create_valid_metadata()
        
        result = validator.validate_module(metadata)
        
        assert result.is_valid is True
        assert len(result.errors) == 0
        assert result.module_name == "valid_scanner"
    
    def test_validate_missing_required_fields(self):
        """Test validation with missing required fields"""
        validator = MetadataValidator()
        
        # Create metadata with missing fields
        metadata = ModuleMetadata(
            name="",  # Empty name
            display_name="Test",
            category=ModuleCategory.RECONNAISSANCE,
            description="",  # Empty description
            detailed_description="Test",
            parameters=[],  # No parameters
            examples=[]  # No examples
        )
        
        result = validator.validate_module(metadata)
        
        assert result.is_valid is False
        assert len(result.errors) >= 4  # name, description, parameters, examples
    
    def test_validate_naming_conventions(self):
        """Test naming convention validation"""
        validator = MetadataValidator()
        metadata = self.create_valid_metadata()
        
        # Invalid module name
        metadata.name = "Invalid-Name"
        
        result = validator.validate_module(metadata)
        
        assert result.is_valid is False
        assert any("naming convention" in error for error in result.errors)
    
    def test_validate_parameter_duplicates(self):
        """Test duplicate parameter validation"""
        validator = MetadataValidator()
        metadata = self.create_valid_metadata()
        
        # Add duplicate parameter
        metadata.parameters.append(
            Parameter(
                name="target",  # Duplicate name
                description="Another target parameter"
            )
        )
        
        result = validator.validate_module(metadata)
        
        assert result.is_valid is False
        assert any("Duplicate parameter name" in error for error in result.errors)
    
    def test_validate_choice_parameter(self):
        """Test choice parameter validation"""
        validator = MetadataValidator()
        metadata = self.create_valid_metadata()
        
        # Add choice parameter without choices
        metadata.parameters.append(
            Parameter(
                name="scan-type",
                description="Type of scan",
                param_type=ParameterType.CHOICE
                # Missing choices
            )
        )
        
        result = validator.validate_module(metadata)
        
        assert result.is_valid is False
        assert any("choice type but has no choices" in error for error in result.errors)
    
    def test_validate_examples(self):
        """Test example validation"""
        validator = MetadataValidator()
        metadata = self.create_valid_metadata()
        
        # Add invalid example
        metadata.examples.append(
            Example(
                title="",  # Empty title
                description="",  # Empty description
                command="",  # Empty command
                level="invalid"  # Invalid level
            )
        )
        
        result = validator.validate_module(metadata)
        
        assert result.is_valid is False
        assert len([e for e in result.errors if "Example" in e]) >= 3
    
    def test_validate_multiple_modules(self):
        """Test validation of multiple modules"""
        validator = MetadataValidator()
        
        valid_metadata = self.create_valid_metadata()
        invalid_metadata = ModuleMetadata(
            name="invalid",
            display_name="Invalid",
            category=ModuleCategory.RECONNAISSANCE,
            description="",  # Invalid
            detailed_description="Test",
            parameters=[],  # Invalid
            examples=[]  # Invalid
        )
        
        report = validator.validate_modules([valid_metadata, invalid_metadata])
        
        assert report.total_modules == 2
        assert report.valid_modules == 1
        assert report.invalid_modules == 1
        assert report.success_rate == 50.0
    
    def test_cross_module_consistency(self):
        """Test cross-module consistency validation"""
        validator = MetadataValidator()
        
        # Create two modules with same parameter name but different descriptions
        metadata1 = self.create_valid_metadata()
        metadata2 = self.create_valid_metadata()
        metadata2.name = "another_scanner"
        metadata2.parameters[0].description = "Different description for target"
        
        warnings = validator.validate_cross_module_consistency([metadata1, metadata2])
        
        assert len(warnings) > 0
        assert any("different descriptions" in warning for warning in warnings)


if __name__ == "__main__":
    pytest.main([__file__])