# -*- coding: utf-8 -*-
"""
Headers Analyzer Module Metadata for Spectra Help System
"""

from ..core.module_metadata import (
    ModuleMetadata, Parameter, Example, UseCase, 
    ModuleCategory, ParameterType, ExampleLevel
)

# Headers Analyzer Module Metadata
METADATA = ModuleMetadata(
    name="headers_analyzer",
    display_name="HTTP Headers Analyzer",
    category=ModuleCategory.SECURITY_ANALYSIS,
    description="Advanced HTTP security headers analysis with comprehensive security checks",
    detailed_description="""
    The Headers Analyzer module performs comprehensive analysis of HTTP security headers,
    identifying missing security controls, misconfigurations, and potential vulnerabilities.
    Features include CSP analysis, cookie security assessment, CORS configuration review,
    and detection of information disclosure through headers.
    """,
    version="2.1.0",
    author="Spectra Team",
    cli_command="-ha",
    cli_aliases=["--headers-analysis"],
    
    parameters=[
        Parameter(
            name="url",
            description="Target URL to analyze headers",
            param_type=ParameterType.URL,
            required=True,
            examples=["https://example.com", "http://api.example.com/v1"],
            help_text="Full URL including protocol (http/https)"
        ),
        Parameter(
            name="timeout",
            description="Request timeout in seconds",
            param_type=ParameterType.INTEGER,
            default_value=10,
            min_value=1,
            max_value=60,
            examples=["5", "15", "30"],
            help_text="Maximum time to wait for server response"
        ),
        Parameter(
            name="follow-redirects",
            description="Follow HTTP redirects during analysis",
            param_type=ParameterType.BOOLEAN,
            default_value=True,
            help_text="Analyze final destination after redirects"
        ),
        Parameter(
            name="verbose",
            short_name="v",
            description="Enable verbose output with detailed analysis",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Shows detailed header analysis and recommendations"
        ),
        Parameter(
            name="output-format",
            description="Output format for results",
            param_type=ParameterType.CHOICE,
            choices=["table", "json", "xml"],
            default_value="table",
            help_text="Choose format for analysis results"
        ),
        Parameter(
            name="include-advanced",
            description="Include advanced security analysis",
            param_type=ParameterType.BOOLEAN,
            default_value=True,
            help_text="Performs deep analysis of CSP, CORS, and cookie security"
        )
    ],
    
    examples=[
        Example(
            title="Basic Headers Analysis",
            description="Analyze security headers for a website",
            command="spectra -ha https://example.com",
            level=ExampleLevel.BASIC,
            category="Basic Usage",
            expected_output="Security headers analysis with recommendations",
            notes=[
                "Checks for common security headers",
                "Provides security recommendations"
            ]
        ),
        Example(
            title="Verbose Analysis",
            description="Detailed analysis with comprehensive output",
            command="spectra -ha https://api.example.com --verbose",
            level=ExampleLevel.INTERMEDIATE,
            category="Detailed Analysis",
            expected_output="Comprehensive security analysis with detailed explanations",
            notes=[
                "Shows all headers and their security implications",
                "Includes CSP and CORS analysis"
            ]
        ),
        Example(
            title="JSON Output for Automation",
            description="Generate machine-readable security analysis",
            command="spectra -ha https://webapp.com --output-format json",
            level=ExampleLevel.INTERMEDIATE,
            category="Automation",
            expected_output="JSON formatted security analysis results",
            notes=[
                "Suitable for automated security pipelines",
                "Can be integrated with other security tools"
            ]
        ),
        Example(
            title="API Security Assessment",
            description="Analyze API endpoint security headers",
            command="spectra -ha https://api.company.com/v2/users --timeout 30 --include-advanced",
            level=ExampleLevel.ADVANCED,
            category="API Security",
            expected_output="Comprehensive API security headers analysis",
            notes=[
                "Extended timeout for slow APIs",
                "Advanced analysis for API-specific security concerns"
            ]
        )
    ],
    
    use_cases=[
        UseCase(
            title="Web Application Security Assessment",
            description="Evaluate web application security posture through headers analysis",
            scenario="During security audits or penetration testing of web applications",
            steps=[
                "Analyze main application URLs and API endpoints",
                "Review security headers implementation",
                "Identify missing or misconfigured security controls",
                "Generate recommendations for security improvements"
            ],
            related_examples=["Basic Headers Analysis", "Verbose Analysis"]
        ),
        UseCase(
            title="Compliance Verification",
            description="Verify security headers compliance with standards",
            scenario="When ensuring compliance with security frameworks (OWASP, PCI-DSS)",
            steps=[
                "Check for required security headers",
                "Validate CSP and HSTS implementation",
                "Review cookie security settings",
                "Document compliance status"
            ],
            related_examples=["API Security Assessment", "JSON Output for Automation"]
        )
    ],
    
    related_modules=[
        "ssl_analyzer",
        "vulnerability_scanner",
        "technology_detector"
    ],
    
    tags=[
        "http headers",
        "security analysis",
        "web security",
        "csp analysis",
        "cors analysis",
        "cookie security",
        "security headers"
    ]
)