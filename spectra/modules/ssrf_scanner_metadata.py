# -*- coding: utf-8 -*-
"""
SSRF Scanner Module Metadata for Spectra Help System
"""

from ..core.module_metadata import (
    ModuleMetadata, Parameter, Example, UseCase, 
    ModuleCategory, ParameterType, ExampleLevel
)

# SSRF Scanner Module Metadata
METADATA = ModuleMetadata(
    name="ssrf_scanner",
    display_name="SSRF Vulnerability Scanner",
    category=ModuleCategory.VULNERABILITY_DETECTION,
    description="Advanced Server-Side Request Forgery vulnerability scanner",
    detailed_description="""
    The SSRF Scanner module detects Server-Side Request Forgery vulnerabilities
    through comprehensive testing of URL parameters and request handling. Features
    include internal network probing, cloud metadata access testing, protocol
    smuggling detection, and blind SSRF identification with OAST integration.
    """,
    version="1.3.0",
    author="Spectra Team",
    cli_command="-ssrf",
    cli_aliases=["--ssrf-scan"],
    
    parameters=[
        Parameter(
            name="url",
            description="Target URL to scan for SSRF vulnerabilities",
            param_type=ParameterType.URL,
            required=True,
            examples=["https://api.example.com/fetch?url=", "http://webapp.com/proxy.php?target="],
            help_text="URL with parameters that accept URLs or hostnames"
        ),
        Parameter(
            name="parameter",
            short_name="p",
            description="Specific parameter to test for SSRF",
            param_type=ParameterType.STRING,
            examples=["url", "target", "fetch", "proxy", "callback"],
            help_text="Parameter name to test, auto-detected if not specified"
        ),
        Parameter(
            name="collaborator-url",
            description="OAST collaborator URL for blind SSRF detection",
            param_type=ParameterType.URL,
            examples=["http://your-server.com", "https://burp-collaborator.net"],
            help_text="External server to detect blind SSRF interactions"
        ),
        Parameter(
            name="internal-targets",
            description="Test access to internal network targets",
            param_type=ParameterType.BOOLEAN,
            default_value=True,
            help_text="Test common internal IP ranges and services"
        ),
        Parameter(
            name="cloud-metadata",
            description="Test access to cloud metadata services",
            param_type=ParameterType.BOOLEAN,
            default_value=True,
            help_text="Test AWS, GCP, Azure metadata endpoints"
        ),
        Parameter(
            name="protocol-smuggling",
            description="Test protocol smuggling techniques",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Test file://, gopher://, and other protocol handlers"
        ),
        Parameter(
            name="bypass-filters",
            description="Test common SSRF filter bypass techniques",
            param_type=ParameterType.BOOLEAN,
            default_value=True,
            help_text="Use encoding, redirects, and other bypass methods"
        ),
        Parameter(
            name="timeout",
            description="Request timeout in seconds",
            param_type=ParameterType.INTEGER,
            default_value=15,
            min_value=5,
            max_value=60,
            examples=["10", "20", "30"],
            help_text="Maximum time to wait for SSRF responses"
        ),
        Parameter(
            name="threads",
            description="Number of concurrent testing threads",
            param_type=ParameterType.INTEGER,
            default_value=5,
            min_value=1,
            max_value=20,
            examples=["3", "10", "15"],
            help_text="Controls testing speed and server load"
        ),
        Parameter(
            name="output-format",
            description="Output format for results",
            param_type=ParameterType.CHOICE,
            choices=["table", "json", "xml"],
            default_value="table",
            help_text="Format for SSRF scan results"
        ),
        Parameter(
            name="verbose",
            short_name="v",
            description="Enable verbose output with detailed information",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Shows detailed SSRF testing and response analysis"
        )
    ],
    
    examples=[
        Example(
            title="Basic SSRF Scan",
            description="Scan URL for Server-Side Request Forgery vulnerabilities",
            command="spectra -ssrf https://api.example.com/fetch?url=http://example.com",
            level=ExampleLevel.BASIC,
            category="Basic Usage",
            expected_output="SSRF vulnerability scan results with accessible targets",
            notes=[
                "Tests internal network access",
                "Includes cloud metadata testing"
            ]
        ),
        Example(
            title="Blind SSRF Detection",
            description="Detect blind SSRF using OAST collaborator",
            command="spectra -ssrf https://webapp.com/proxy.php --collaborator-url http://your-server.com",
            level=ExampleLevel.INTERMEDIATE,
            category="Blind SSRF",
            expected_output="Blind SSRF detection results with OAST interactions",
            notes=[
                "Requires external server for interaction detection",
                "Can detect SSRF without visible responses"
            ]
        ),
        Example(
            title="Advanced SSRF Testing",
            description="Comprehensive SSRF testing with protocol smuggling",
            command="spectra -ssrf https://app.com/fetch -p target --protocol-smuggling --bypass-filters --verbose",
            level=ExampleLevel.ADVANCED,
            category="Advanced Techniques",
            expected_output="Comprehensive SSRF analysis with advanced attack vectors",
            notes=[
                "Tests protocol smuggling attacks",
                "Includes filter bypass techniques",
                "Verbose output shows detailed analysis"
            ]
        ),
        Example(
            title="Cloud Environment SSRF",
            description="Test SSRF in cloud environments with metadata access",
            command="spectra -ssrf https://cloud-app.com/api/fetch?url= --cloud-metadata --internal-targets",
            level=ExampleLevel.ADVANCED,
            category="Cloud Security",
            expected_output="SSRF scan results focusing on cloud metadata access",
            notes=[
                "Tests AWS, GCP, Azure metadata endpoints",
                "Comprehensive internal network probing"
            ]
        )
    ],
    
    use_cases=[
        UseCase(
            title="Web Application Security Testing",
            description="Test web applications for SSRF vulnerabilities",
            scenario="During security assessments of applications with URL handling",
            steps=[
                "Identify URL parameters and request handlers",
                "Test internal network access capabilities",
                "Check cloud metadata accessibility",
                "Document SSRF impact and exploitation paths"
            ],
            related_examples=["Basic SSRF Scan", "Cloud Environment SSRF"]
        ),
        UseCase(
            title="API Security Assessment",
            description="Assess APIs for SSRF vulnerabilities",
            scenario="When testing APIs that fetch external resources",
            steps=[
                "Map API endpoints that accept URLs",
                "Test blind SSRF with OAST techniques",
                "Verify internal service access",
                "Generate security recommendations"
            ],
            related_examples=["Blind SSRF Detection", "Advanced SSRF Testing"]
        )
    ],
    
    related_modules=[
        "sql_injection_scanner",
        "xss_scanner",
        "vulnerability_scanner"
    ],
    
    tags=[
        "ssrf",
        "server-side request forgery",
        "internal network access",
        "cloud metadata",
        "protocol smuggling",
        "blind ssrf"
    ]
)