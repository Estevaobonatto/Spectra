# -*- coding: utf-8 -*-
"""
XXE Scanner Module Metadata for Spectra Help System
"""

from ..core.module_metadata import (
    ModuleMetadata, Parameter, Example, UseCase, 
    ModuleCategory, ParameterType, ExampleLevel
)

# XXE Scanner Module Metadata
METADATA = ModuleMetadata(
    name="xxe_scanner",
    display_name="XXE Vulnerability Scanner",
    category=ModuleCategory.VULNERABILITY_DETECTION,
    description="Advanced XML External Entity (XXE) vulnerability scanner with multiple attack vectors",
    detailed_description="""
    The XXE Scanner module detects XML External Entity vulnerabilities through comprehensive
    testing of XML endpoints. Features include file disclosure detection, SSRF via XXE,
    blind XXE testing with OAST integration, DoS attack detection, and WAF bypass techniques.
    Supports custom payloads and multiple output formats.
    """,
    version="1.5.0",
    author="Spectra Team",
    cli_command="-xxe",
    cli_aliases=["--xxe-scan"],
    
    parameters=[
        Parameter(
            name="url",
            description="Target URL to scan for XXE vulnerabilities",
            param_type=ParameterType.URL,
            required=True,
            examples=["https://api.example.com", "http://webapp.com/xml"],
            help_text="URL that accepts XML input or has XML endpoints"
        ),
        Parameter(
            name="collaborator-url",
            description="OAST collaborator URL for blind XXE detection",
            param_type=ParameterType.URL,
            examples=["http://your-server.com", "https://burp-collaborator.net"],
            help_text="External server to detect blind XXE interactions"
        ),
        Parameter(
            name="max-workers",
            description="Maximum number of concurrent workers",
            param_type=ParameterType.INTEGER,
            default_value=10,
            min_value=1,
            max_value=50,
            examples=["5", "15", "25"],
            help_text="Controls scan speed and resource usage"
        ),
        Parameter(
            name="timeout",
            description="Request timeout in seconds",
            param_type=ParameterType.INTEGER,
            default_value=15,
            min_value=5,
            max_value=60,
            examples=["10", "20", "30"],
            help_text="Maximum time to wait for each request"
        ),
        Parameter(
            name="custom-payloads",
            description="File containing custom XXE payloads",
            param_type=ParameterType.FILE_PATH,
            examples=["payloads.txt", "custom_xxe.xml"],
            help_text="One payload per line, supports XML format"
        ),
        Parameter(
            name="verbose",
            short_name="v",
            description="Enable verbose output with detailed information",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Shows scan progress and detailed vulnerability information"
        ),
        Parameter(
            name="output-format",
            description="Output format for results",
            param_type=ParameterType.CHOICE,
            choices=["json", "xml", "csv"],
            default_value="json",
            help_text="Format for exporting scan results"
        )
    ],
    
    examples=[
        Example(
            title="Basic XXE Scan",
            description="Scan for XXE vulnerabilities in XML endpoints",
            command="spectra -xxe https://api.example.com/xml",
            level=ExampleLevel.BASIC,
            category="Basic Usage",
            expected_output="XXE vulnerability scan results with detected issues",
            notes=[
                "Automatically discovers XML endpoints",
                "Tests for file disclosure and SSRF"
            ]
        ),
        Example(
            title="Blind XXE Detection",
            description="Detect blind XXE using OAST collaborator",
            command="spectra -xxe https://webapp.com --collaborator-url http://your-server.com",
            level=ExampleLevel.INTERMEDIATE,
            category="Blind XXE",
            expected_output="Blind XXE detection results with OAST interactions",
            notes=[
                "Requires external server for interaction detection",
                "Can detect XXE even without visible output"
            ]
        ),
        Example(
            title="Custom Payloads Scan",
            description="Use custom XXE payloads for targeted testing",
            command="spectra -xxe https://api.target.com --custom-payloads custom_xxe_payloads.txt --verbose",
            level=ExampleLevel.ADVANCED,
            category="Custom Testing",
            expected_output="Scan results using custom payload set",
            notes=[
                "Allows testing with application-specific payloads",
                "Verbose mode shows payload execution details"
            ]
        ),
        Example(
            title="High-Performance Scan",
            description="Fast XXE scan with optimized settings",
            command="spectra -xxe https://api.company.com --max-workers 25 --timeout 10",
            level=ExampleLevel.ADVANCED,
            category="Performance",
            expected_output="Rapid XXE vulnerability assessment",
            notes=[
                "Increased concurrency for faster scanning",
                "Reduced timeout for quick assessment"
            ]
        )
    ],
    
    use_cases=[
        UseCase(
            title="Web Application Security Testing",
            description="Test web applications for XXE vulnerabilities",
            scenario="During security assessments of applications that process XML",
            steps=[
                "Identify XML processing endpoints",
                "Test for file disclosure vulnerabilities",
                "Check for SSRF via XXE",
                "Verify blind XXE with OAST",
                "Document findings and impact"
            ],
            related_examples=["Basic XXE Scan", "Blind XXE Detection"]
        ),
        UseCase(
            title="API Security Assessment",
            description="Assess REST/SOAP APIs for XXE vulnerabilities",
            scenario="When testing APIs that accept XML input",
            steps=[
                "Map XML-accepting API endpoints",
                "Test various XXE attack vectors",
                "Verify parser security configurations",
                "Generate security recommendations"
            ],
            related_examples=["Custom Payloads Scan", "High-Performance Scan"]
        )
    ],
    
    related_modules=[
        "sql_injection_scanner",
        "xss_scanner",
        "vulnerability_scanner"
    ],
    
    tags=[
        "xxe",
        "xml external entity",
        "file disclosure",
        "ssrf",
        "blind xxe",
        "xml security",
        "vulnerability scanning"
    ]
)