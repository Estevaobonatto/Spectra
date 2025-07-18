# -*- coding: utf-8 -*-
"""
Subdomain Scanner Module Metadata for Spectra Help System
"""

from ..core.module_metadata import (
    ModuleMetadata, Parameter, Example, UseCase, 
    ModuleCategory, ParameterType, ExampleLevel
)

# Subdomain Scanner Module Metadata
METADATA = ModuleMetadata(
    name="subdomain_scanner",
    display_name="Subdomain Scanner",
    category=ModuleCategory.RECONNAISSANCE,
    description="Advanced subdomain discovery with multiple enumeration techniques",
    detailed_description="""
    The Subdomain Scanner module performs comprehensive subdomain enumeration using
    multiple techniques including DNS brute force, certificate transparency logs,
    search engine queries, and passive DNS sources. Features intelligent wordlist
    management, DNS resolution verification, and comprehensive reporting.
    """,
    version="2.4.0",
    author="Spectra Team",
    cli_command="-sub",
    cli_aliases=["--subdomain-scan"],
    
    parameters=[
        Parameter(
            name="domain",
            description="Target domain for subdomain discovery",
            param_type=ParameterType.STRING,
            required=True,
            examples=["example.com", "company.org", "target-domain.net"],
            help_text="Root domain to enumerate subdomains for"
        ),
        Parameter(
            name="wordlist",
            short_name="w",
            description="Wordlist file for subdomain brute force",
            param_type=ParameterType.FILE_PATH,
            examples=["subdomains.txt", "common-subdomains.txt"],
            help_text="File containing subdomain names to test"
        ),
        Parameter(
            name="threads",
            description="Number of concurrent DNS resolution threads",
            param_type=ParameterType.INTEGER,
            default_value=50,
            min_value=1,
            max_value=200,
            examples=["25", "100", "150"],
            help_text="Higher values increase speed but may cause DNS issues"
        ),
        Parameter(
            name="timeout",
            description="DNS resolution timeout in seconds",
            param_type=ParameterType.FLOAT,
            default_value=2.0,
            min_value=0.5,
            max_value=10.0,
            examples=["1.0", "3.0", "5.0"],
            help_text="Maximum time to wait for DNS responses"
        ),
        Parameter(
            name="recursive",
            description="Perform recursive subdomain discovery",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Find subdomains of discovered subdomains"
        ),
        Parameter(
            name="passive-only",
            description="Use only passive enumeration techniques",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Avoid active DNS queries, use only passive sources"
        ),
        Parameter(
            name="include-wildcard",
            description="Include wildcard subdomain detection",
            param_type=ParameterType.BOOLEAN,
            default_value=True,
            help_text="Detect and handle wildcard DNS responses"
        ),
        Parameter(
            name="verify-ssl",
            description="Verify SSL certificates for discovered subdomains",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Check SSL certificate validity and details"
        ),
        Parameter(
            name="output-format",
            description="Output format for results",
            param_type=ParameterType.CHOICE,
            choices=["table", "json", "csv", "txt"],
            default_value="table",
            help_text="Format for subdomain enumeration results"
        ),
        Parameter(
            name="verbose",
            short_name="v",
            description="Enable verbose output with detailed information",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Shows enumeration progress and detailed results"
        )
    ],
    
    examples=[
        Example(
            title="Basic Subdomain Discovery",
            description="Discover subdomains using default techniques",
            command="spectra -sub example.com",
            level=ExampleLevel.BASIC,
            category="Basic Usage",
            expected_output="List of discovered subdomains with IP addresses",
            notes=[
                "Uses built-in wordlist for common subdomains",
                "Combines passive and active enumeration"
            ]
        ),
        Example(
            title="Custom Wordlist Scan",
            description="Use custom wordlist for subdomain brute force",
            command="spectra -sub company.com -w custom-subdomains.txt --threads 100",
            level=ExampleLevel.INTERMEDIATE,
            category="Custom Wordlists",
            expected_output="Subdomains discovered using custom wordlist",
            notes=[
                "Uses provided wordlist for targeted discovery",
                "Increased threads for faster enumeration"
            ]
        ),
        Example(
            title="Passive Enumeration Only",
            description="Discover subdomains using only passive techniques",
            command="spectra -sub target.org --passive-only --verify-ssl",
            level=ExampleLevel.INTERMEDIATE,
            category="Passive Discovery",
            expected_output="Passively discovered subdomains with SSL information",
            notes=[
                "No active DNS queries to avoid detection",
                "SSL verification for additional information"
            ]
        ),
        Example(
            title="Comprehensive Discovery",
            description="Full subdomain enumeration with all techniques",
            command="spectra -sub enterprise.com --recursive --threads 150 --verbose --output-format json",
            level=ExampleLevel.ADVANCED,
            category="Comprehensive Enumeration",
            expected_output="Complete subdomain enumeration in JSON format",
            notes=[
                "Recursive discovery finds sub-subdomains",
                "High thread count for maximum speed",
                "JSON output for automated processing"
            ]
        )
    ],
    
    use_cases=[
        UseCase(
            title="Attack Surface Mapping",
            description="Map complete attack surface through subdomain discovery",
            scenario="During reconnaissance phase of security assessments",
            steps=[
                "Enumerate all subdomains for target domain",
                "Verify subdomain resolution and accessibility",
                "Identify interesting subdomains (admin, dev, staging)",
                "Document findings for further testing"
            ],
            related_examples=["Basic Subdomain Discovery", "Comprehensive Discovery"]
        ),
        UseCase(
            title="Asset Discovery",
            description="Discover unknown assets and services",
            scenario="For organizations wanting to inventory their external assets",
            steps=[
                "Use passive enumeration to avoid detection",
                "Verify SSL certificates for asset validation",
                "Cross-reference with known asset inventory",
                "Report unknown or forgotten assets"
            ],
            related_examples=["Passive Enumeration Only", "Custom Wordlist Scan"]
        )
    ],
    
    related_modules=[
        "dns_analyzer",
        "port_scanner",
        "ssl_analyzer",
        "technology_detector"
    ],
    
    tags=[
        "subdomain enumeration",
        "dns reconnaissance",
        "asset discovery",
        "passive enumeration",
        "certificate transparency",
        "attack surface mapping"
    ]
)