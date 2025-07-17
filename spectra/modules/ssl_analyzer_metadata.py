# -*- coding: utf-8 -*-
"""
SSL Analyzer Module Metadata for Spectra Help System
"""

from ..core.module_metadata import (
    ModuleMetadata, Parameter, Example, UseCase, 
    ModuleCategory, ParameterType, ExampleLevel
)

# SSL Analyzer Module Metadata
METADATA = ModuleMetadata(
    name="ssl_analyzer",
    display_name="SSL/TLS Analyzer",
    category=ModuleCategory.SECURITY_ANALYSIS,
    description="Comprehensive SSL/TLS security analysis and certificate validation",
    detailed_description="""
    The SSL Analyzer module performs comprehensive SSL/TLS security analysis including
    certificate validation, cipher suite analysis, protocol version testing,
    vulnerability detection (Heartbleed, POODLE, etc.), and compliance checking
    against security standards.
    """,
    version="2.2.0",
    author="Spectra Team",
    cli_command="-ssl",
    cli_aliases=["--ssl-analysis"],
    
    parameters=[
        Parameter(
            name="host",
            description="Target hostname or IP address",
            param_type=ParameterType.STRING,
            required=True,
            examples=["example.com", "192.168.1.1", "mail.company.com"],
            help_text="Hostname or IP address of the SSL/TLS service"
        ),
        Parameter(
            name="port",
            short_name="p",
            description="Target port number",
            param_type=ParameterType.PORT,
            default_value=443,
            examples=["443", "8443", "993", "995"],
            help_text="Port number of the SSL/TLS service"
        ),
        Parameter(
            name="timeout",
            description="Connection timeout in seconds",
            param_type=ParameterType.INTEGER,
            default_value=10,
            min_value=1,
            max_value=60,
            examples=["5", "15", "30"],
            help_text="Maximum time to wait for SSL connection"
        ),
        Parameter(
            name="protocols",
            description="SSL/TLS protocols to test",
            param_type=ParameterType.LIST,
            default_value=["TLSv1.2", "TLSv1.3"],
            examples=["TLSv1.2,TLSv1.3", "SSLv3,TLSv1.0,TLSv1.1,TLSv1.2"],
            help_text="Comma-separated list of protocols to analyze"
        ),
        Parameter(
            name="check-vulnerabilities",
            description="Check for known SSL/TLS vulnerabilities",
            param_type=ParameterType.BOOLEAN,
            default_value=True,
            help_text="Test for Heartbleed, POODLE, BEAST, and other vulnerabilities"
        ),
        Parameter(
            name="cipher-analysis",
            description="Perform detailed cipher suite analysis",
            param_type=ParameterType.BOOLEAN,
            default_value=True,
            help_text="Analyze supported cipher suites and their security"
        ),
        Parameter(
            name="certificate-details",
            description="Include detailed certificate information",
            param_type=ParameterType.BOOLEAN,
            default_value=True,
            help_text="Show certificate chain, validity, and extensions"
        ),
        Parameter(
            name="compliance-check",
            description="Check compliance with security standards",
            param_type=ParameterType.CHOICE,
            choices=["pci-dss", "nist", "mozilla", "all"],
            help_text="Validate against specific compliance standards"
        ),
        Parameter(
            name="output-format",
            description="Output format for results",
            param_type=ParameterType.CHOICE,
            choices=["table", "json", "xml", "html"],
            default_value="table",
            help_text="Format for SSL analysis results"
        ),
        Parameter(
            name="verbose",
            short_name="v",
            description="Enable verbose output with detailed information",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Shows detailed SSL/TLS analysis and recommendations"
        )
    ],
    
    examples=[
        Example(
            title="Basic SSL Analysis",
            description="Analyze SSL configuration for a website",
            command="spectra -ssl example.com",
            level=ExampleLevel.BASIC,
            category="Basic Usage",
            expected_output="SSL/TLS security analysis with certificate details",
            notes=[
                "Analyzes certificate validity and chain",
                "Checks for common SSL vulnerabilities"
            ]
        ),
        Example(
            title="Custom Port Analysis",
            description="Analyze SSL service on non-standard port",
            command="spectra -ssl mail.company.com -p 993 --verbose",
            level=ExampleLevel.INTERMEDIATE,
            category="Custom Ports",
            expected_output="Detailed SSL analysis for IMAPS service",
            notes=[
                "Analyzes SSL on port 993 (IMAPS)",
                "Verbose output shows detailed findings"
            ]
        ),
        Example(
            title="Vulnerability Assessment",
            description="Comprehensive SSL vulnerability testing",
            command="spectra -ssl target.com --check-vulnerabilities --protocols SSLv3,TLSv1.0,TLSv1.1,TLSv1.2,TLSv1.3",
            level=ExampleLevel.ADVANCED,
            category="Vulnerability Testing",
            expected_output="Complete SSL vulnerability assessment",
            notes=[
                "Tests all SSL/TLS protocol versions",
                "Comprehensive vulnerability scanning"
            ]
        ),
        Example(
            title="Compliance Validation",
            description="Check SSL configuration against PCI-DSS standards",
            command="spectra -ssl payment.company.com --compliance-check pci-dss --output-format json",
            level=ExampleLevel.ADVANCED,
            category="Compliance",
            expected_output="PCI-DSS compliance report in JSON format",
            notes=[
                "Validates against PCI-DSS requirements",
                "JSON output for compliance reporting"
            ]
        )
    ],
    
    use_cases=[
        UseCase(
            title="SSL Security Assessment",
            description="Evaluate SSL/TLS security posture",
            scenario="During security audits or compliance assessments",
            steps=[
                "Analyze certificate validity and configuration",
                "Test for known SSL/TLS vulnerabilities",
                "Review cipher suite security",
                "Generate security recommendations"
            ],
            related_examples=["Basic SSL Analysis", "Vulnerability Assessment"]
        ),
        UseCase(
            title="Compliance Verification",
            description="Verify SSL configuration meets compliance standards",
            scenario="For PCI-DSS, NIST, or other regulatory compliance",
            steps=[
                "Test SSL configuration against standards",
                "Validate certificate requirements",
                "Check protocol and cipher compliance",
                "Generate compliance reports"
            ],
            related_examples=["Compliance Validation", "Custom Port Analysis"]
        )
    ],
    
    related_modules=[
        "headers_analyzer",
        "vulnerability_scanner",
        "port_scanner"
    ],
    
    tags=[
        "ssl analysis",
        "tls security",
        "certificate validation",
        "cipher analysis",
        "ssl vulnerabilities",
        "compliance checking"
    ]
)