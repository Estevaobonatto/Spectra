# -*- coding: utf-8 -*-
"""
IDOR Scanner Module Metadata for Spectra Help System
"""

from ..core.module_metadata import (
    ModuleMetadata, Parameter, Example, UseCase, 
    ModuleCategory, ParameterType, ExampleLevel
)

# IDOR Scanner Module Metadata
METADATA = ModuleMetadata(
    name="idor_scanner",
    display_name="IDOR Vulnerability Scanner",
    category=ModuleCategory.VULNERABILITY_DETECTION,
    description="Advanced Insecure Direct Object Reference (IDOR) vulnerability scanner",
    detailed_description="""
    The IDOR Scanner module detects Insecure Direct Object Reference vulnerabilities
    by automatically identifying and testing object reference parameters. Features
    include intelligent parameter detection, multiple ID types support, response
    analysis for access control bypass, and comprehensive reporting.
    """,
    version="1.2.0",
    author="Spectra Team",
    cli_command="-idor",
    cli_aliases=["--idor-scan"],
    
    parameters=[
        Parameter(
            name="url",
            description="Target URL to scan for IDOR vulnerabilities",
            param_type=ParameterType.URL,
            required=True,
            examples=["https://api.example.com/user/123", "http://webapp.com/profile?id=456"],
            help_text="URL containing object reference parameters"
        ),
        Parameter(
            name="parameter",
            short_name="p",
            description="Specific parameter to test for IDOR",
            param_type=ParameterType.STRING,
            examples=["id", "user_id", "doc_id", "file_id"],
            help_text="If not specified, scanner will auto-detect parameters"
        ),
        Parameter(
            name="id-range",
            description="Range of IDs to test (start-end)",
            param_type=ParameterType.STRING,
            default_value="1-100",
            examples=["1-50", "100-200", "1000-1100"],
            help_text="Range of numeric IDs to test for access"
        ),
        Parameter(
            name="id-type",
            description="Type of ID format to test",
            param_type=ParameterType.CHOICE,
            choices=["numeric", "uuid", "hash", "mixed"],
            default_value="numeric",
            help_text="Format of object identifiers to generate"
        ),
        Parameter(
            name="method",
            description="HTTP method to use for requests",
            param_type=ParameterType.CHOICE,
            choices=["GET", "POST", "PUT", "DELETE"],
            default_value="GET",
            help_text="HTTP method for testing object access"
        ),
        Parameter(
            name="threads",
            description="Number of concurrent threads",
            param_type=ParameterType.INTEGER,
            default_value=10,
            min_value=1,
            max_value=50,
            examples=["5", "15", "25"],
            help_text="Controls scan speed and server load"
        ),
        Parameter(
            name="delay",
            description="Delay between requests in milliseconds",
            param_type=ParameterType.INTEGER,
            default_value=100,
            min_value=0,
            max_value=5000,
            examples=["50", "200", "500"],
            help_text="Helps avoid rate limiting and reduces server load"
        ),
        Parameter(
            name="verbose",
            short_name="v",
            description="Enable verbose output with detailed information",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Shows scan progress and detailed vulnerability analysis"
        ),
        Parameter(
            name="output-format",
            description="Output format for results",
            param_type=ParameterType.CHOICE,
            choices=["table", "json", "csv"],
            default_value="table",
            help_text="Format for vulnerability report"
        )
    ],
    
    examples=[
        Example(
            title="Basic IDOR Scan",
            description="Scan URL for IDOR vulnerabilities with auto-detection",
            command="spectra -idor https://api.example.com/user/123",
            level=ExampleLevel.BASIC,
            category="Basic Usage",
            expected_output="IDOR vulnerability scan results with accessible objects",
            notes=[
                "Automatically detects ID parameters",
                "Tests numeric ID range 1-100"
            ]
        ),
        Example(
            title="Specific Parameter Test",
            description="Test specific parameter for IDOR vulnerability",
            command="spectra -idor https://webapp.com/profile -p user_id --id-range 1-50",
            level=ExampleLevel.INTERMEDIATE,
            category="Targeted Testing",
            expected_output="IDOR test results for user_id parameter",
            notes=[
                "Focuses on specific parameter",
                "Custom ID range for targeted testing"
            ]
        ),
        Example(
            title="UUID IDOR Testing",
            description="Test IDOR with UUID-based object references",
            command="spectra -idor https://api.company.com/document/uuid-here --id-type uuid --threads 5",
            level=ExampleLevel.ADVANCED,
            category="Advanced ID Types",
            expected_output="IDOR vulnerability results for UUID-based objects",
            notes=[
                "Tests UUID format object references",
                "Reduced threads for careful testing"
            ]
        ),
        Example(
            title="Stealth IDOR Scan",
            description="Perform slow, stealthy IDOR testing",
            command="spectra -idor https://sensitive-app.com/data?id=100 --delay 1000 --threads 2 --verbose",
            level=ExampleLevel.ADVANCED,
            category="Stealth Testing",
            expected_output="Detailed IDOR scan with minimal detection risk",
            notes=[
                "1 second delay between requests",
                "Limited concurrent connections",
                "Verbose output for detailed analysis"
            ]
        )
    ],
    
    use_cases=[
        UseCase(
            title="Web Application Security Assessment",
            description="Test web applications for IDOR vulnerabilities",
            scenario="During security audits of applications with user-specific data",
            steps=[
                "Identify URLs with object reference parameters",
                "Test parameter manipulation for unauthorized access",
                "Analyze response differences for access control bypass",
                "Document vulnerable endpoints and impact"
            ],
            related_examples=["Basic IDOR Scan", "Specific Parameter Test"]
        ),
        UseCase(
            title="API Security Testing",
            description="Assess REST APIs for IDOR vulnerabilities",
            scenario="When testing APIs that expose object references",
            steps=[
                "Map API endpoints with object identifiers",
                "Test different ID formats and ranges",
                "Verify access control implementation",
                "Generate security recommendations"
            ],
            related_examples=["UUID IDOR Testing", "Stealth IDOR Scan"]
        )
    ],
    
    related_modules=[
        "sql_injection_scanner",
        "xss_scanner",
        "vulnerability_scanner"
    ],
    
    tags=[
        "idor",
        "insecure direct object reference",
        "access control",
        "authorization bypass",
        "object reference",
        "vulnerability scanning"
    ]
)