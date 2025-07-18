# -*- coding: utf-8 -*-
"""
WHOIS Analyzer Module Metadata for Spectra Help System
"""

from ..core.module_metadata import (
    ModuleMetadata, Parameter, Example, UseCase, 
    ModuleCategory, ParameterType, ExampleLevel
)

# WHOIS Analyzer Module Metadata
METADATA = ModuleMetadata(
    name="whois_analyzer",
    display_name="WHOIS Analyzer",
    category=ModuleCategory.RECONNAISSANCE,
    description="Comprehensive WHOIS information analysis and domain intelligence gathering",
    detailed_description="""
    The WHOIS Analyzer module performs comprehensive WHOIS lookups and analysis
    for domains and IP addresses. Features include registrar information extraction,
    contact details analysis, domain history tracking, and privacy protection
    detection with intelligent parsing of various WHOIS formats.
    """,
    version="1.8.0",
    author="Spectra Team",
    cli_command="-whois",
    cli_aliases=["--whois-analysis"],
    
    parameters=[
        Parameter(
            name="target",
            description="Target domain or IP address for WHOIS lookup",
            param_type=ParameterType.STRING,
            required=True,
            examples=["example.com", "192.168.1.1", "company.org"],
            help_text="Domain name or IP address to analyze"
        ),
        Parameter(
            name="server",
            description="Custom WHOIS server to query",
            param_type=ParameterType.STRING,
            examples=["whois.verisign-grs.com", "whois.arin.net"],
            help_text="Specific WHOIS server to use for queries"
        ),
        Parameter(
            name="timeout",
            description="WHOIS query timeout in seconds",
            param_type=ParameterType.INTEGER,
            default_value=10,
            min_value=5,
            max_value=60,
            examples=["15", "30", "45"],
            help_text="Maximum time to wait for WHOIS response"
        ),
        Parameter(
            name="follow-referrals",
            description="Follow WHOIS referrals to authoritative servers",
            param_type=ParameterType.BOOLEAN,
            default_value=True,
            help_text="Query referred WHOIS servers for complete information"
        ),
        Parameter(
            name="privacy-analysis",
            description="Analyze privacy protection and contact information",
            param_type=ParameterType.BOOLEAN,
            default_value=True,
            help_text="Detect privacy services and analyze contact details"
        ),
        Parameter(
            name="historical-data",
            description="Include historical WHOIS data analysis",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Analyze domain registration history and changes"
        ),
        Parameter(
            name="dns-correlation",
            description="Correlate WHOIS data with DNS information",
            param_type=ParameterType.BOOLEAN,
            default_value=True,
            help_text="Cross-reference WHOIS data with DNS records"
        ),
        Parameter(
            name="output-format",
            description="Output format for results",
            param_type=ParameterType.CHOICE,
            choices=["table", "json", "xml", "raw"],
            default_value="table",
            help_text="Format for WHOIS analysis results"
        ),
        Parameter(
            name="verbose",
            short_name="v",
            description="Enable verbose output with detailed information",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Shows detailed WHOIS analysis and parsing information"
        )
    ],
    
    examples=[
        Example(
            title="Basic WHOIS Lookup",
            description="Perform WHOIS lookup for a domain",
            command="spectra -whois example.com",
            level=ExampleLevel.BASIC,
            category="Basic Usage",
            expected_output="WHOIS information with registrar and contact details",
            notes=[
                "Shows domain registration information",
                "Includes registrar and nameserver details"
            ]
        ),
        Example(
            title="IP Address WHOIS",
            description="Analyze WHOIS information for an IP address",
            command="spectra -whois 8.8.8.8 --verbose",
            level=ExampleLevel.BASIC,
            category="IP Analysis",
            expected_output="IP WHOIS information with network details",
            notes=[
                "Shows network allocation information",
                "Includes ISP and geographic details"
            ]
        ),
        Example(
            title="Privacy Analysis",
            description="Analyze domain privacy protection and contact information",
            command="spectra -whois company.com --privacy-analysis --dns-correlation",
            level=ExampleLevel.INTERMEDIATE,
            category="Privacy Analysis",
            expected_output="WHOIS analysis with privacy protection assessment",
            notes=[
                "Detects privacy protection services",
                "Correlates with DNS information"
            ]
        ),
        Example(
            title="Historical Domain Analysis",
            description="Comprehensive domain analysis with historical data",
            command="spectra -whois target.org --historical-data --output-format json --verbose",
            level=ExampleLevel.ADVANCED,
            category="Historical Analysis",
            expected_output="Complete domain intelligence in JSON format",
            notes=[
                "Includes historical registration data",
                "JSON output for automated processing"
            ]
        )
    ],
    
    use_cases=[
        UseCase(
            title="Domain Intelligence Gathering",
            description="Collect comprehensive information about target domains",
            scenario="During reconnaissance phase of security assessments",
            steps=[
                "Perform WHOIS lookup for target domain",
                "Analyze registrar and contact information",
                "Check for privacy protection services",
                "Correlate with DNS and other intelligence"
            ],
            related_examples=["Basic WHOIS Lookup", "Privacy Analysis"]
        ),
        UseCase(
            title="Infrastructure Mapping",
            description="Map network infrastructure through IP WHOIS analysis",
            scenario="For understanding target network ownership and allocation",
            steps=[
                "Perform WHOIS lookups on discovered IP addresses",
                "Identify network blocks and ISPs",
                "Map organizational infrastructure",
                "Document network ownership patterns"
            ],
            related_examples=["IP Address WHOIS", "Historical Domain Analysis"]
        )
    ],
    
    related_modules=[
        "dns_analyzer",
        "subdomain_scanner",
        "port_scanner"
    ],
    
    tags=[
        "whois lookup",
        "domain intelligence",
        "registrar information",
        "contact analysis",
        "privacy protection",
        "network analysis"
    ]
)