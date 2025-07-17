# -*- coding: utf-8 -*-
"""
DNS Analyzer Module Metadata for Spectra Help System
"""

from ..core.module_metadata import (
    ModuleMetadata, Parameter, Example, UseCase, 
    ModuleCategory, ParameterType, ExampleLevel
)

# DNS Analyzer Module Metadata
METADATA = ModuleMetadata(
    name="dns_analyzer",
    display_name="DNS Analyzer",
    category=ModuleCategory.RECONNAISSANCE,
    description="Comprehensive DNS analysis and security assessment tool",
    detailed_description="""
    The DNS Analyzer module performs comprehensive DNS analysis including record
    enumeration, zone transfer testing, DNS security assessment, cache poisoning
    detection, and DNS over HTTPS/TLS support analysis. Features advanced query
    techniques and security-focused DNS testing.
    """,
    version="2.1.0",
    author="Spectra Team",
    cli_command="-dns",
    cli_aliases=["--dns-analysis"],
    
    parameters=[
        Parameter(
            name="domain",
            description="Target domain for DNS analysis",
            param_type=ParameterType.STRING,
            required=True,
            examples=["example.com", "company.org", "target-domain.net"],
            help_text="Domain name to analyze DNS records and configuration"
        ),
        Parameter(
            name="record-types",
            description="DNS record types to query",
            param_type=ParameterType.LIST,
            default_value=["A", "AAAA", "MX", "NS", "TXT", "CNAME"],
            examples=["A,MX,NS", "ALL", "A,AAAA,TXT,SPF"],
            help_text="Comma-separated list of DNS record types or 'ALL'"
        ),
        Parameter(
            name="nameserver",
            description="Custom DNS server to use for queries",
            param_type=ParameterType.IP_ADDRESS,
            examples=["8.8.8.8", "1.1.1.1", "208.67.222.222"],
            help_text="IP address of DNS server to query"
        ),
        Parameter(
            name="timeout",
            description="DNS query timeout in seconds",
            param_type=ParameterType.FLOAT,
            default_value=5.0,
            min_value=1.0,
            max_value=30.0,
            examples=["3.0", "10.0", "15.0"],
            help_text="Maximum time to wait for DNS responses"
        ),
        Parameter(
            name="zone-transfer",
            description="Attempt DNS zone transfer (AXFR)",
            param_type=ParameterType.BOOLEAN,
            default_value=True,
            help_text="Test for misconfigured zone transfers"
        ),
        Parameter(
            name="reverse-dns",
            description="Perform reverse DNS lookups",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Perform PTR record lookups for discovered IPs"
        ),
        Parameter(
            name="dnssec-check",
            description="Check DNSSEC configuration",
            param_type=ParameterType.BOOLEAN,
            default_value=True,
            help_text="Validate DNSSEC signatures and configuration"
        ),
        Parameter(
            name="security-analysis",
            description="Perform DNS security analysis",
            param_type=ParameterType.BOOLEAN,
            default_value=True,
            help_text="Check for DNS security issues and misconfigurations"
        ),
        Parameter(
            name="subdomain-enum",
            description="Include basic subdomain enumeration",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Perform basic subdomain discovery during analysis"
        ),
        Parameter(
            name="output-format",
            description="Output format for results",
            param_type=ParameterType.CHOICE,
            choices=["table", "json", "xml", "txt"],
            default_value="table",
            help_text="Format for DNS analysis results"
        ),
        Parameter(
            name="verbose",
            short_name="v",
            description="Enable verbose output with detailed information",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Shows detailed DNS analysis and query information"
        )
    ],
    
    examples=[
        Example(
            title="Basic DNS Analysis",
            description="Analyze DNS records for a domain",
            command="spectra -dns example.com",
            level=ExampleLevel.BASIC,
            category="Basic Usage",
            expected_output="DNS records and basic security analysis",
            notes=[
                "Queries common DNS record types",
                "Includes zone transfer testing"
            ]
        ),
        Example(
            title="Comprehensive DNS Security Audit",
            description="Full DNS security assessment with DNSSEC validation",
            command="spectra -dns company.com --security-analysis --dnssec-check --verbose",
            level=ExampleLevel.INTERMEDIATE,
            category="Security Analysis",
            expected_output="Comprehensive DNS security assessment",
            notes=[
                "Includes DNSSEC validation",
                "Detailed security analysis and recommendations"
            ]
        ),
        Example(
            title="Custom DNS Server Query",
            description="Query specific DNS server for domain records",
            command="spectra -dns target.org --nameserver 8.8.8.8 --record-types A,MX,TXT,SPF",
            level=ExampleLevel.INTERMEDIATE,
            category="Custom Queries",
            expected_output="DNS records from specified nameserver",
            notes=[
                "Uses Google DNS (8.8.8.8) for queries",
                "Focuses on specific record types"
            ]
        ),
        Example(
            title="DNS Reconnaissance",
            description="Comprehensive DNS reconnaissance with subdomain enumeration",
            command="spectra -dns enterprise.com --subdomain-enum --reverse-dns --output-format json",
            level=ExampleLevel.ADVANCED,
            category="Reconnaissance",
            expected_output="Complete DNS reconnaissance in JSON format",
            notes=[
                "Includes subdomain enumeration",
                "Reverse DNS lookups for discovered IPs",
                "JSON output for automated processing"
            ]
        )
    ],
    
    use_cases=[
        UseCase(
            title="DNS Security Assessment",
            description="Evaluate DNS security configuration and identify vulnerabilities",
            scenario="During security audits or penetration testing",
            steps=[
                "Analyze DNS record configuration",
                "Test for zone transfer vulnerabilities",
                "Validate DNSSEC implementation",
                "Check for DNS security misconfigurations"
            ],
            related_examples=["Basic DNS Analysis", "Comprehensive DNS Security Audit"]
        ),
        UseCase(
            title="Domain Intelligence Gathering",
            description="Collect intelligence about target domain infrastructure",
            scenario="For reconnaissance during security assessments",
            steps=[
                "Enumerate all DNS records",
                "Discover subdomains and related infrastructure",
                "Map IP addresses and hosting providers",
                "Identify mail servers and other services"
            ],
            related_examples=["DNS Reconnaissance", "Custom DNS Server Query"]
        )
    ],
    
    related_modules=[
        "subdomain_scanner",
        "whois_analyzer",
        "port_scanner"
    ],
    
    tags=[
        "dns analysis",
        "dns security",
        "zone transfer",
        "dnssec",
        "dns reconnaissance",
        "domain analysis"
    ]
)