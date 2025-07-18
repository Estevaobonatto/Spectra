# -*- coding: utf-8 -*-
"""
Banner Grabber Module Metadata for Spectra Help System
"""

from ..core.module_metadata import (
    ModuleMetadata, Parameter, Example, UseCase, 
    ModuleCategory, ParameterType, ExampleLevel
)

# Banner Grabber Module Metadata
METADATA = ModuleMetadata(
    name="banner_grabber",
    display_name="Banner Grabber",
    category=ModuleCategory.RECONNAISSANCE,
    description="Advanced service banner grabbing and service identification",
    detailed_description="""
    The Banner Grabber module performs comprehensive service banner grabbing
    to identify running services, versions, and configurations. Features include
    protocol-specific banner grabbing, service fingerprinting, version detection,
    and vulnerability correlation based on discovered service versions.
    """,
    version="2.0.0",
    author="Spectra Team",
    cli_command="-bg",
    cli_aliases=["--banner-grab"],
    
    parameters=[
        Parameter(
            name="target",
            description="Target host or IP address",
            param_type=ParameterType.STRING,
            required=True,
            examples=["example.com", "192.168.1.1", "mail.company.com"],
            help_text="Hostname or IP address to grab banners from"
        ),
        Parameter(
            name="ports",
            short_name="p",
            description="Ports to grab banners from",
            param_type=ParameterType.STRING,
            default_value="21,22,23,25,53,80,110,143,443,993,995,3306,5432",
            examples=["80,443,22", "1-1000", "21,22,23,25,80,443"],
            help_text="Comma-separated ports or ranges"
        ),
        Parameter(
            name="timeout",
            description="Connection timeout in seconds",
            param_type=ParameterType.FLOAT,
            default_value=5.0,
            min_value=1.0,
            max_value=30.0,
            examples=["3.0", "10.0", "15.0"],
            help_text="Maximum time to wait for banner response"
        ),
        Parameter(
            name="protocol",
            description="Specific protocol to use for banner grabbing",
            param_type=ParameterType.CHOICE,
            choices=["tcp", "udp", "auto"],
            default_value="auto",
            help_text="Protocol to use, auto-detects based on port"
        ),
        Parameter(
            name="service-detection",
            description="Enable advanced service detection",
            param_type=ParameterType.BOOLEAN,
            default_value=True,
            help_text="Perform service fingerprinting and version detection"
        ),
        Parameter(
            name="grab-ssl",
            description="Grab banners from SSL/TLS services",
            param_type=ParameterType.BOOLEAN,
            default_value=True,
            help_text="Connect to SSL/TLS services for banner grabbing"
        ),
        Parameter(
            name="custom-payloads",
            description="Use custom payloads for specific services",
            param_type=ParameterType.BOOLEAN,
            default_value=True,
            help_text="Send service-specific payloads to elicit responses"
        ),
        Parameter(
            name="threads",
            description="Number of concurrent threads",
            param_type=ParameterType.INTEGER,
            default_value=10,
            min_value=1,
            max_value=50,
            examples=["5", "20", "30"],
            help_text="Controls scanning speed and resource usage"
        ),
        Parameter(
            name="output-format",
            description="Output format for results",
            param_type=ParameterType.CHOICE,
            choices=["table", "json", "xml", "txt"],
            default_value="table",
            help_text="Format for banner grabbing results"
        ),
        Parameter(
            name="verbose",
            short_name="v",
            description="Enable verbose output with detailed information",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Shows detailed banner information and analysis"
        )
    ],
    
    examples=[
        Example(
            title="Basic Banner Grabbing",
            description="Grab banners from common service ports",
            command="spectra -bg example.com",
            level=ExampleLevel.BASIC,
            category="Basic Usage",
            expected_output="Service banners with version information",
            notes=[
                "Grabs banners from common service ports",
                "Includes service identification and versions"
            ]
        ),
        Example(
            title="Custom Port Range",
            description="Grab banners from specific port range",
            command="spectra -bg 192.168.1.1 -p 1-1000 --threads 20",
            level=ExampleLevel.INTERMEDIATE,
            category="Custom Ports",
            expected_output="Banners from ports 1-1000",
            notes=[
                "Scans first 1000 ports for banners",
                "Increased threads for faster scanning"
            ]
        ),
        Example(
            title="SSL Service Analysis",
            description="Focus on SSL/TLS service banner grabbing",
            command="spectra -bg secure.company.com -p 443,993,995,8443 --grab-ssl --verbose",
            level=ExampleLevel.INTERMEDIATE,
            category="SSL Services",
            expected_output="SSL service banners with detailed analysis",
            notes=[
                "Focuses on SSL/TLS enabled services",
                "Verbose output shows SSL handshake details"
            ]
        ),
        Example(
            title="Comprehensive Service Fingerprinting",
            description="Advanced service detection with custom payloads",
            command="spectra -bg target.com --service-detection --custom-payloads --output-format json",
            level=ExampleLevel.ADVANCED,
            category="Service Detection",
            expected_output="Comprehensive service fingerprinting in JSON",
            notes=[
                "Advanced service detection techniques",
                "Custom payloads for better identification",
                "JSON output for automated processing"
            ]
        )
    ],
    
    use_cases=[
        UseCase(
            title="Service Enumeration",
            description="Identify running services and their versions",
            scenario="During reconnaissance phase of security assessments",
            steps=[
                "Grab banners from discovered open ports",
                "Identify service types and versions",
                "Correlate with known vulnerabilities",
                "Document service inventory"
            ],
            related_examples=["Basic Banner Grabbing", "Comprehensive Service Fingerprinting"]
        ),
        UseCase(
            title="Vulnerability Assessment Preparation",
            description="Gather service information for targeted vulnerability testing",
            scenario="Before conducting vulnerability scans or penetration tests",
            steps=[
                "Identify all running services",
                "Determine exact service versions",
                "Research version-specific vulnerabilities",
                "Plan targeted security tests"
            ],
            related_examples=["Custom Port Range", "SSL Service Analysis"]
        )
    ],
    
    related_modules=[
        "port_scanner",
        "ssl_analyzer",
        "vulnerability_scanner"
    ],
    
    tags=[
        "banner grabbing",
        "service identification",
        "version detection",
        "service fingerprinting",
        "reconnaissance"
    ]
)