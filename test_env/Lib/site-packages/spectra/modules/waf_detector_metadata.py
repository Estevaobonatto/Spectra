# -*- coding: utf-8 -*-
"""
WAF Detector Module Metadata for Spectra Help System
"""

from ..core.module_metadata import (
    ModuleMetadata, Parameter, Example, UseCase, 
    ModuleCategory, ParameterType, ExampleLevel
)

# WAF Detector Module Metadata
METADATA = ModuleMetadata(
    name="waf_detector",
    display_name="WAF Detector",
    category=ModuleCategory.SECURITY_ANALYSIS,
    description="Advanced Web Application Firewall detection and analysis",
    detailed_description="""
    The WAF Detector module identifies Web Application Firewalls and security
    solutions protecting web applications. Features include signature-based
    detection, behavioral analysis, bypass technique testing, and comprehensive
    WAF fingerprinting with evasion strategy recommendations.
    """,
    version="1.6.0",
    author="Spectra Team",
    cli_command="-waf",
    cli_aliases=["--waf-detection"],
    
    parameters=[
        Parameter(
            name="url",
            description="Target URL to test for WAF presence",
            param_type=ParameterType.URL,
            required=True,
            examples=["https://example.com", "http://webapp.company.com/app"],
            help_text="Full URL of the target web application"
        ),
        Parameter(
            name="payloads",
            description="Test payloads to trigger WAF responses",
            param_type=ParameterType.CHOICE,
            choices=["basic", "comprehensive", "custom"],
            default_value="comprehensive",
            help_text="Set of payloads to use for WAF detection"
        ),
        Parameter(
            name="custom-payload-file",
            description="File containing custom test payloads",
            param_type=ParameterType.FILE_PATH,
            examples=["waf-payloads.txt", "custom-tests.txt"],
            help_text="One payload per line for custom WAF testing"
        ),
        Parameter(
            name="detection-level",
            description="WAF detection sensitivity level",
            param_type=ParameterType.CHOICE,
            choices=["passive", "active", "aggressive"],
            default_value="active",
            help_text="Level of testing aggressiveness"
        ),
        Parameter(
            name="bypass-testing",
            description="Test common WAF bypass techniques",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Attempt to identify potential bypass methods"
        ),
        Parameter(
            name="user-agent",
            description="Custom User-Agent string for requests",
            param_type=ParameterType.STRING,
            examples=["Mozilla/5.0...", "Custom-Scanner/1.0"],
            help_text="Custom User-Agent to avoid detection"
        ),
        Parameter(
            name="timeout",
            description="Request timeout in seconds",
            param_type=ParameterType.INTEGER,
            default_value=10,
            min_value=5,
            max_value=60,
            examples=["15", "30", "45"],
            help_text="Maximum time to wait for responses"
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
            help_text="Format for WAF detection results"
        ),
        Parameter(
            name="verbose",
            short_name="v",
            description="Enable verbose output with detailed information",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Shows detailed WAF analysis and detection methods"
        )
    ],
    
    examples=[
        Example(
            title="Basic WAF Detection",
            description="Detect WAF presence using standard techniques",
            command="spectra -waf https://example.com",
            level=ExampleLevel.BASIC,
            category="Basic Usage",
            expected_output="WAF detection results with identified security solutions",
            notes=[
                "Uses comprehensive payload set",
                "Identifies common WAF solutions"
            ]
        ),
        Example(
            title="Passive WAF Analysis",
            description="Detect WAF using only passive techniques",
            command="spectra -waf https://webapp.com --detection-level passive --verbose",
            level=ExampleLevel.INTERMEDIATE,
            category="Passive Detection",
            expected_output="WAF detection using passive analysis methods",
            notes=[
                "No aggressive payloads sent",
                "Analyzes headers and response patterns"
            ]
        ),
        Example(
            title="WAF Bypass Testing",
            description="Test for potential WAF bypass techniques",
            command="spectra -waf https://api.company.com --bypass-testing --payloads comprehensive",
            level=ExampleLevel.ADVANCED,
            category="Bypass Testing",
            expected_output="WAF detection with bypass technique analysis",
            notes=[
                "Tests common bypass methods",
                "Comprehensive payload testing"
            ]
        ),
        Example(
            title="Custom Payload Testing",
            description="Use custom payloads for specific WAF testing",
            command="spectra -waf https://target.com --custom-payload-file custom-waf-tests.txt --detection-level aggressive",
            level=ExampleLevel.ADVANCED,
            category="Custom Testing",
            expected_output="WAF detection using custom test payloads",
            notes=[
                "Uses application-specific payloads",
                "Aggressive detection mode"
            ]
        )
    ],
    
    use_cases=[
        UseCase(
            title="Security Assessment Preparation",
            description="Identify WAF solutions before security testing",
            scenario="Before conducting web application penetration tests",
            steps=[
                "Detect presence of WAF or security solutions",
                "Identify specific WAF vendor and version",
                "Test for potential bypass techniques",
                "Plan evasion strategies for security testing"
            ],
            related_examples=["Basic WAF Detection", "WAF Bypass Testing"]
        ),
        UseCase(
            title="WAF Configuration Validation",
            description="Verify WAF deployment and configuration",
            scenario="For organizations validating their WAF implementation",
            steps=[
                "Confirm WAF is properly deployed",
                "Test WAF detection capabilities",
                "Identify potential configuration weaknesses",
                "Recommend configuration improvements"
            ],
            related_examples=["Passive WAF Analysis", "Custom Payload Testing"]
        )
    ],
    
    related_modules=[
        "sql_injection_scanner",
        "xss_scanner",
        "headers_analyzer"
    ],
    
    tags=[
        "waf detection",
        "web application firewall",
        "security solutions",
        "bypass testing",
        "evasion techniques"
    ]
)