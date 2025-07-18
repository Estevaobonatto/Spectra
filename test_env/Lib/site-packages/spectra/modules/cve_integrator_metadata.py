# -*- coding: utf-8 -*-
"""
CVE Integrator Module Metadata for Spectra Help System
"""

from ..core.module_metadata import (
    ModuleMetadata, Parameter, Example, UseCase, 
    ModuleCategory, ParameterType, ExampleLevel
)

# CVE Integrator Module Metadata
METADATA = ModuleMetadata(
    name="cve_integrator",
    display_name="CVE Database Integrator",
    category=ModuleCategory.INTEGRATION,
    description="CVE database integration for vulnerability correlation and threat intelligence",
    detailed_description="""
    The CVE Integrator module provides comprehensive integration with CVE databases
    for vulnerability correlation and threat intelligence. Features include CVE
    lookup, CVSS scoring, exploit availability checking, vulnerability trending
    analysis, and automated threat intelligence gathering.
    """,
    version="2.0.0",
    author="Spectra Team",
    cli_command="-cve",
    cli_aliases=["--cve-lookup"],
    
    parameters=[
        Parameter(
            name="cve-id",
            description="Specific CVE ID to lookup",
            param_type=ParameterType.STRING,
            examples=["CVE-2021-44228", "CVE-2023-23397", "CVE-2022-30190"],
            help_text="CVE identifier in format CVE-YYYY-NNNN"
        ),
        Parameter(
            name="product",
            description="Product name to search for vulnerabilities",
            param_type=ParameterType.STRING,
            examples=["apache", "nginx", "wordpress", "windows"],
            help_text="Software product name for vulnerability search"
        ),
        Parameter(
            name="version",
            description="Specific product version",
            param_type=ParameterType.STRING,
            examples=["2.4.41", "1.18.0", "5.8.1"],
            help_text="Product version to check for vulnerabilities"
        ),
        Parameter(
            name="severity",
            description="Minimum CVSS severity level",
            param_type=ParameterType.CHOICE,
            choices=["low", "medium", "high", "critical"],
            default_value="medium",
            help_text="Filter results by CVSS severity score"
        ),
        Parameter(
            name="year",
            description="CVE publication year",
            param_type=ParameterType.INTEGER,
            examples=["2023", "2022", "2021"],
            help_text="Filter CVEs by publication year"
        ),
        Parameter(
            name="exploit-check",
            description="Check for available exploits",
            param_type=ParameterType.BOOLEAN,
            default_value=True,
            help_text="Verify if exploits are publicly available"
        ),
        Parameter(
            name="trending",
            description="Show trending vulnerabilities",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Display currently trending CVEs"
        ),
        Parameter(
            name="update-db",
            description="Update local CVE database",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Download latest CVE data before search"
        ),
        Parameter(
            name="limit",
            description="Maximum number of results to return",
            param_type=ParameterType.INTEGER,
            default_value=50,
            min_value=1,
            max_value=500,
            examples=["10", "100", "200"],
            help_text="Limit number of CVE results"
        ),
        Parameter(
            name="output-format",
            description="Output format for results",
            param_type=ParameterType.CHOICE,
            choices=["table", "json", "xml", "csv"],
            default_value="table",
            help_text="Format for CVE lookup results"
        ),
        Parameter(
            name="verbose",
            short_name="v",
            description="Enable verbose output with detailed information",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Shows detailed CVE information and analysis"
        )
    ],
    
    examples=[
        Example(
            title="CVE Lookup",
            description="Look up specific CVE information",
            command="spectra -cve --cve-id CVE-2021-44228",
            level=ExampleLevel.BASIC,
            category="Basic Usage",
            expected_output="Detailed information about Log4j vulnerability",
            notes=[
                "Shows CVSS score and description",
                "Includes exploit availability information"
            ]
        ),
        Example(
            title="Product Vulnerability Search",
            description="Search for vulnerabilities in specific product",
            command="spectra -cve --product apache --version 2.4.41 --severity high",
            level=ExampleLevel.INTERMEDIATE,
            category="Product Search",
            expected_output="High severity vulnerabilities in Apache 2.4.41",
            notes=[
                "Filters by product version and severity",
                "Shows relevant CVEs for specific configuration"
            ]
        ),
        Example(
            title="Trending Vulnerabilities",
            description="Display currently trending CVEs",
            command="spectra -cve --trending --year 2023 --exploit-check --verbose",
            level=ExampleLevel.INTERMEDIATE,
            category="Threat Intelligence",
            expected_output="Trending 2023 CVEs with exploit information",
            notes=[
                "Shows currently active threats",
                "Includes exploit availability status"
            ]
        ),
        Example(
            title="Comprehensive CVE Analysis",
            description="Complete CVE database analysis with updates",
            command="spectra -cve --product windows --severity critical --update-db --output-format json --limit 100",
            level=ExampleLevel.ADVANCED,
            category="Comprehensive Analysis",
            expected_output="Critical Windows vulnerabilities in JSON format",
            notes=[
                "Updates CVE database before search",
                "JSON output for automated processing",
                "Focuses on critical severity vulnerabilities"
            ]
        )
    ],
    
    use_cases=[
        UseCase(
            title="Vulnerability Management",
            description="Track and manage organizational vulnerabilities",
            scenario="For security teams managing vulnerability remediation",
            steps=[
                "Search for vulnerabilities in deployed software",
                "Prioritize by CVSS severity and exploit availability",
                "Track trending threats and emerging vulnerabilities",
                "Generate vulnerability management reports"
            ],
            related_examples=["Product Vulnerability Search", "Comprehensive CVE Analysis"]
        ),
        UseCase(
            title="Threat Intelligence",
            description="Gather threat intelligence from CVE data",
            scenario="For security analysts monitoring threat landscape",
            steps=[
                "Monitor trending vulnerabilities",
                "Analyze exploit availability and weaponization",
                "Correlate CVEs with organizational assets",
                "Generate threat intelligence reports"
            ],
            related_examples=["Trending Vulnerabilities", "CVE Lookup"]
        ),
        UseCase(
            title="Security Research",
            description="Research vulnerabilities for security analysis",
            scenario="For security researchers and penetration testers",
            steps=[
                "Research specific CVEs for testing",
                "Identify vulnerable software versions",
                "Check exploit availability and techniques",
                "Document vulnerability research findings"
            ],
            related_examples=["CVE Lookup", "Product Vulnerability Search"]
        )
    ],
    
    related_modules=[
        "vulnerability_scanner",
        "port_scanner",
        "banner_grabber"
    ],
    
    tags=[
        "cve database",
        "vulnerability intelligence",
        "cvss scoring",
        "exploit availability",
        "threat intelligence",
        "vulnerability management"
    ]
)