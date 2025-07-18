# -*- coding: utf-8 -*-
"""
Metadata Extractor Module Metadata for Spectra Help System
"""

from ..core.module_metadata import (
    ModuleMetadata, Parameter, Example, UseCase, 
    ModuleCategory, ParameterType, ExampleLevel
)

# Metadata Extractor Module Metadata
METADATA = ModuleMetadata(
    name="metadata_extractor",
    display_name="Metadata Extractor",
    category=ModuleCategory.RECONNAISSANCE,
    description="Advanced metadata extraction from files and documents for intelligence gathering",
    detailed_description="""
    The Metadata Extractor module extracts comprehensive metadata from various
    file types including documents, images, and media files. Features include
    EXIF data extraction, document properties analysis, hidden information
    discovery, and privacy assessment of file metadata.
    """,
    version="1.7.0",
    author="Spectra Team",
    cli_command="-meta",
    cli_aliases=["--metadata-extraction"],
    
    parameters=[
        Parameter(
            name="target",
            description="Target file, URL, or directory to extract metadata from",
            param_type=ParameterType.STRING,
            required=True,
            examples=["document.pdf", "https://site.com/image.jpg", "/path/to/files/"],
            help_text="File path, URL, or directory containing files to analyze"
        ),
        Parameter(
            name="file-types",
            description="File types to analyze",
            param_type=ParameterType.LIST,
            default_value=["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "png", "gif"],
            examples=["pdf,doc,docx", "jpg,png,gif", "all"],
            help_text="Comma-separated file extensions or 'all' for all supported types"
        ),
        Parameter(
            name="recursive",
            short_name="r",
            description="Recursively scan subdirectories",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Scan all subdirectories for files to analyze"
        ),
        Parameter(
            name="extract-text",
            description="Extract text content from documents",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Include document text content in analysis"
        ),
        Parameter(
            name="privacy-analysis",
            description="Perform privacy risk analysis",
            param_type=ParameterType.BOOLEAN,
            default_value=True,
            help_text="Identify potentially sensitive metadata"
        ),
        Parameter(
            name="geolocation",
            description="Extract and analyze GPS/location data",
            param_type=ParameterType.BOOLEAN,
            default_value=True,
            help_text="Extract GPS coordinates from image EXIF data"
        ),
        Parameter(
            name="user-info",
            description="Extract user and system information",
            param_type=ParameterType.BOOLEAN,
            default_value=True,
            help_text="Extract author, creator, and system details"
        ),
        Parameter(
            name="timestamps",
            description="Extract and analyze timestamp information",
            param_type=ParameterType.BOOLEAN,
            default_value=True,
            help_text="Extract creation, modification, and access times"
        ),
        Parameter(
            name="output-format",
            description="Output format for results",
            param_type=ParameterType.CHOICE,
            choices=["table", "json", "xml", "csv", "html"],
            default_value="table",
            help_text="Format for metadata extraction results"
        ),
        Parameter(
            name="save-extracted",
            description="Save extracted metadata to file",
            param_type=ParameterType.STRING,
            examples=["metadata-report.json", "extracted-data.csv"],
            help_text="Filename to save extracted metadata"
        ),
        Parameter(
            name="verbose",
            short_name="v",
            description="Enable verbose output with detailed information",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Shows detailed metadata extraction and analysis"
        )
    ],
    
    examples=[
        Example(
            title="Basic Metadata Extraction",
            description="Extract metadata from a single document",
            command="spectra -meta document.pdf",
            level=ExampleLevel.BASIC,
            category="Basic Usage",
            expected_output="Document metadata including author, creation date, and software used",
            notes=[
                "Extracts standard document properties",
                "Includes privacy risk analysis"
            ]
        ),
        Example(
            title="Image EXIF Analysis",
            description="Extract EXIF data from images including GPS information",
            command="spectra -meta photo.jpg --geolocation --verbose",
            level=ExampleLevel.BASIC,
            category="Image Analysis",
            expected_output="Image EXIF data with GPS coordinates and camera information",
            notes=[
                "Extracts GPS coordinates if available",
                "Shows camera settings and device information"
            ]
        ),
        Example(
            title="Directory Metadata Scan",
            description="Recursively scan directory for file metadata",
            command="spectra -meta /documents/ --recursive --file-types pdf,doc,docx --privacy-analysis",
            level=ExampleLevel.INTERMEDIATE,
            category="Bulk Analysis",
            expected_output="Metadata analysis for all documents in directory tree",
            notes=[
                "Scans all subdirectories recursively",
                "Focuses on document file types",
                "Includes privacy risk assessment"
            ]
        ),
        Example(
            title="Comprehensive Metadata Analysis",
            description="Complete metadata extraction with text content and reporting",
            command="spectra -meta /media/ --extract-text --user-info --timestamps --output-format html --save-extracted metadata-report.html",
            level=ExampleLevel.ADVANCED,
            category="Comprehensive Analysis",
            expected_output="Complete metadata analysis report in HTML format",
            notes=[
                "Extracts text content from documents",
                "Comprehensive user and timestamp analysis",
                "Generates HTML report for presentation"
            ]
        )
    ],
    
    use_cases=[
        UseCase(
            title="Digital Forensics",
            description="Extract metadata for forensic analysis and evidence gathering",
            scenario="During digital forensic investigations",
            steps=[
                "Extract metadata from suspect files",
                "Analyze timestamps and user information",
                "Identify file creation and modification patterns",
                "Generate forensic reports with findings"
            ],
            related_examples=["Basic Metadata Extraction", "Comprehensive Metadata Analysis"]
        ),
        UseCase(
            title="Privacy Assessment",
            description="Assess privacy risks in document metadata",
            scenario="Before publishing documents or sharing files",
            steps=[
                "Scan documents for sensitive metadata",
                "Identify personal information in file properties",
                "Check for GPS coordinates in images",
                "Generate privacy risk reports"
            ],
            related_examples=["Image EXIF Analysis", "Directory Metadata Scan"]
        ),
        UseCase(
            title="Intelligence Gathering",
            description="Gather intelligence from publicly available files",
            scenario="During OSINT investigations or reconnaissance",
            steps=[
                "Download and analyze target organization files",
                "Extract user names and system information",
                "Map organizational structure from metadata",
                "Identify software and technology usage"
            ],
            related_examples=["Directory Metadata Scan", "Comprehensive Metadata Analysis"]
        )
    ],
    
    related_modules=[
        "technology_detector",
        "whois_analyzer",
        "dns_analyzer"
    ],
    
    tags=[
        "metadata extraction",
        "exif data",
        "document analysis",
        "privacy assessment",
        "digital forensics",
        "intelligence gathering"
    ]
)