# -*- coding: utf-8 -*-
"""
Technology Detector Module Metadata for Spectra Help System
"""

from ..core.module_metadata import (
    ModuleMetadata, Parameter, Example, UseCase, 
    ModuleCategory, ParameterType, ExampleLevel
)

# Technology Detector Module Metadata
METADATA = ModuleMetadata(
    name="technology_detector",
    display_name="Technology Detector",
    category=ModuleCategory.RECONNAISSANCE,
    description="Advanced web technology detection with 500+ technology signatures",
    detailed_description="""
    The Technology Detector module identifies web technologies, frameworks, CMS,
    libraries, and services used by target websites. Features include file
    fingerprinting, passive scanning, WAF detection, API fingerprinting,
    and comprehensive reporting with confidence scoring.
    """,
    version="3.0.0",
    author="Spectra Team",
    cli_command="-tech",
    cli_aliases=["--technology-detection"],
    
    parameters=[
        Parameter(
            name="url",
            description="Target URL to analyze for technologies",
            param_type=ParameterType.URL,
            required=True,
            examples=["https://example.com", "http://webapp.company.com"],
            help_text="Full URL of the target website or application"
        ),
        Parameter(
            name="threads",
            description="Number of concurrent scanning threads",
            param_type=ParameterType.INTEGER,
            default_value=10,
            min_value=1,
            max_value=20,
            examples=["5", "15", "20"],
            help_text="Controls scan speed and resource usage"
        ),
        Parameter(
            name="timeout",
            description="Request timeout in seconds",
            param_type=ParameterType.INTEGER,
            default_value=10,
            min_value=5,
            max_value=60,
            examples=["15", "30", "45"],
            help_text="Maximum time to wait for each request"
        ),
        Parameter(
            name="user-agent",
            description="Custom User-Agent string for requests",
            param_type=ParameterType.STRING,
            examples=["Mozilla/5.0...", "Custom-Scanner/1.0"],
            help_text="Custom User-Agent to avoid detection"
        ),
        Parameter(
            name="passive-only",
            description="Use only passive detection techniques",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Avoid active probing, analyze only main page"
        ),
        Parameter(
            name="include-waf",
            description="Include WAF detection in analysis",
            param_type=ParameterType.BOOLEAN,
            default_value=True,
            help_text="Detect Web Application Firewalls"
        ),
        Parameter(
            name="deep-scan",
            description="Perform deep technology analysis",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Analyze additional files and endpoints"
        ),
        Parameter(
            name="confidence-threshold",
            description="Minimum confidence score for results",
            param_type=ParameterType.INTEGER,
            default_value=50,
            min_value=1,
            max_value=100,
            examples=["25", "75", "90"],
            help_text="Filter results by confidence percentage"
        ),
        Parameter(
            name="output-format",
            description="Output format for results",
            param_type=ParameterType.CHOICE,
            choices=["table", "json", "xml", "csv", "html"],
            default_value="table",
            help_text="Format for technology detection results"
        ),
        Parameter(
            name="verbose",
            short_name="v",
            description="Enable verbose output with detailed information",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Shows detection details and confidence scores"
        )
    ],
    
    examples=[
        Example(
            title="Basic Technology Detection",
            description="Detect technologies used by a website",
            command="spectra -tech https://example.com",
            level=ExampleLevel.BASIC,
            category="Basic Usage",
            expected_output="List of detected technologies with confidence scores",
            notes=[
                "Detects common web technologies and frameworks",
                "Includes CMS, JavaScript libraries, and server technologies"
            ]
        ),
        Example(
            title="Deep Technology Analysis",
            description="Comprehensive technology detection with deep scanning",
            command="spectra -tech https://webapp.com --deep-scan --verbose",
            level=ExampleLevel.INTERMEDIATE,
            category="Comprehensive Analysis",
            expected_output="Detailed technology analysis with additional findings",
            notes=[
                "Analyzes additional files and endpoints",
                "Verbose output shows detection methodology"
            ]
        ),
        Example(
            title="High-Confidence Detection",
            description="Filter results by high confidence threshold",
            command="spectra -tech https://company.com --confidence-threshold 80 --include-waf",
            level=ExampleLevel.INTERMEDIATE,
            category="Filtered Results",
            expected_output="High-confidence technology detections with WAF analysis",
            notes=[
                "Only shows results with 80%+ confidence",
                "Includes WAF detection for security assessment"
            ]
        ),
        Example(
            title="Stealth Technology Scan",
            description="Passive technology detection to avoid detection",
            command="spectra -tech https://target.com --passive-only --user-agent \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\"",
            level=ExampleLevel.ADVANCED,
            category="Stealth Scanning",
            expected_output="Technology detection using only passive techniques",
            notes=[
                "No active probing to avoid detection",
                "Custom User-Agent for better stealth"
            ]
        ),
        Example(
            title="Automated Technology Assessment",
            description="Generate machine-readable technology report",
            command="spectra -tech https://api.company.com --output-format json --threads 15 --timeout 30",
            level=ExampleLevel.ADVANCED,
            category="Automation",
            expected_output="JSON formatted technology detection results",
            notes=[
                "Suitable for automated security pipelines",
                "Optimized settings for API endpoints"
            ]
        )
    ],
    
    use_cases=[
        UseCase(
            title="Security Assessment Preparation",
            description="Identify technologies for targeted security testing",
            scenario="Before conducting penetration tests or security audits",
            steps=[
                "Detect web technologies and frameworks",
                "Identify potential attack vectors based on technologies",
                "Research known vulnerabilities for detected versions",
                "Plan targeted security tests"
            ],
            related_examples=["Basic Technology Detection", "Deep Technology Analysis"]
        ),
        UseCase(
            title="Competitive Intelligence",
            description="Analyze competitor technology stacks",
            scenario="For business intelligence and technology research",
            steps=[
                "Identify technologies used by competitors",
                "Analyze technology trends and adoption",
                "Compare technology choices",
                "Generate technology landscape reports"
            ],
            related_examples=["High-Confidence Detection", "Automated Technology Assessment"]
        ),
        UseCase(
            title="Asset Inventory",
            description="Catalog technologies used across organization",
            scenario="For IT asset management and compliance",
            steps=[
                "Scan all organizational web assets",
                "Catalog detected technologies and versions",
                "Identify outdated or vulnerable components",
                "Generate compliance and inventory reports"
            ],
            related_examples=["Stealth Technology Scan", "Automated Technology Assessment"]
        )
    ],
    
    related_modules=[
        "headers_analyzer",
        "ssl_analyzer",
        "vulnerability_scanner",
        "waf_detector"
    ],
    
    tags=[
        "technology detection",
        "web fingerprinting",
        "cms detection",
        "framework identification",
        "javascript libraries",
        "server technologies",
        "waf detection"
    ]
)