# -*- coding: utf-8 -*-
"""
Port Scanner Module Metadata for Spectra Help System
"""

from ..core.module_metadata import (
    ModuleMetadata, Parameter, Example, UseCase, 
    ModuleCategory, ParameterType, ExampleLevel
)

# Port Scanner Module Metadata
METADATA = ModuleMetadata(
    name="port_scanner",
    display_name="Port Scanner",
    category=ModuleCategory.RECONNAISSANCE,
    description="Advanced port scanning with multiple scan types and service detection",
    detailed_description="""
    The Port Scanner module provides comprehensive port scanning capabilities with support for 
    TCP, UDP, and SYN scan types. Features include banner grabbing, service detection, 
    performance optimization, and detailed reporting. Supports both single targets and ranges, 
    with intelligent threading and connection pooling for optimal performance.
    """,
    version="3.3.0",
    author="Spectra Team",
    cli_command="-ps",
    cli_aliases=["--port-scan"],
    
    parameters=[
        Parameter(
            name="target",
            description="Target host, IP address, or hostname to scan",
            param_type=ParameterType.STRING,
            required=True,
            examples=["example.com", "192.168.1.1", "10.0.0.0/24"],
            help_text="Supports single hosts, IP addresses, and CIDR notation for ranges"
        ),
        Parameter(
            name="ports",
            short_name="p",
            description="Ports to scan (comma-separated or range)",
            param_type=ParameterType.STRING,
            default_value="80,443,22,21,25,53,110,143,993,995,3306,3389,5432",
            examples=["80,443,22", "1-1000", "80,443,8000-8080"],
            help_text="Supports individual ports, ranges, and combinations"
        ),
        Parameter(
            name="top-ports",
            description="Scan the N most common ports",
            param_type=ParameterType.INTEGER,
            examples=["100", "1000", "5000"],
            help_text="Alternative to specifying individual ports"
        ),
        Parameter(
            name="scan-type",
            description="Type of port scan to perform",
            param_type=ParameterType.CHOICE,
            choices=["tcp", "syn", "udp"],
            default_value="tcp",
            help_text="TCP connect scan is most compatible, SYN scan requires root privileges"
        ),
        Parameter(
            name="timeout",
            description="Connection timeout in seconds",
            param_type=ParameterType.FLOAT,
            default_value=1.0,
            min_value=0.1,
            max_value=30.0,
            examples=["0.5", "2.0", "5.0"],
            help_text="Lower values are faster but may miss slow services"
        ),
        Parameter(
            name="workers",
            description="Number of concurrent scanning threads",
            param_type=ParameterType.INTEGER,
            default_value=50,
            min_value=1,
            max_value=500,
            examples=["10", "100", "200"],
            help_text="Higher values scan faster but use more resources"
        ),
        Parameter(
            name="delay",
            description="Delay between requests in milliseconds",
            param_type=ParameterType.INTEGER,
            default_value=0,
            min_value=0,
            max_value=5000,
            examples=["100", "500", "1000"],
            help_text="Useful for stealth scanning or avoiding rate limits"
        ),
        Parameter(
            name="verbose",
            short_name="v",
            description="Enable verbose output with detailed information",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Shows scan progress, DNS resolution, and detailed results"
        ),
        Parameter(
            name="output-format",
            description="Output format for results",
            param_type=ParameterType.CHOICE,
            choices=["table", "json", "xml"],
            default_value="table",
            help_text="Choose format based on intended use (human-readable vs machine-parseable)"
        ),
        Parameter(
            name="host-discovery",
            description="Perform host discovery before port scanning",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Uses ping and common port checks to verify host is alive"
        ),
        Parameter(
            name="banner-grab",
            description="Attempt to grab service banners from open ports",
            param_type=ParameterType.BOOLEAN,
            default_value=True,
            help_text="Provides service version information but increases scan time"
        )
    ],
    
    examples=[
        Example(
            title="Basic Port Scan",
            description="Scan common ports on a target host",
            command="spectra -ps example.com",
            level=ExampleLevel.BASIC,
            category="Basic Usage",
            expected_output="List of open ports with detected services",
            notes=[
                "Uses default port list (web, SSH, FTP, email, database ports)",
                "Includes banner grabbing for service identification"
            ]
        ),
        Example(
            title="Custom Port Range",
            description="Scan a specific range of ports",
            command="spectra -ps 192.168.1.1 -p 1-1000",
            level=ExampleLevel.BASIC,
            category="Port Selection",
            expected_output="Results for ports 1-1000 showing open services",
            notes=[
                "Scans first 1000 ports",
                "Good for comprehensive local network scanning"
            ]
        ),
        Example(
            title="Top Ports Scan",
            description="Scan the 100 most common ports",
            command="spectra -ps target.com --top-ports 100",
            level=ExampleLevel.BASIC,
            category="Port Selection",
            expected_output="Results for 100 most commonly used ports",
            notes=[
                "Faster than full range scans",
                "Covers majority of common services"
            ]
        ),
        Example(
            title="UDP Service Discovery",
            description="Scan for UDP services with specific payloads",
            command="spectra -ps 10.0.0.1 --scan-type udp -p 53,123,161,514",
            level=ExampleLevel.INTERMEDIATE,
            category="Protocol Scanning",
            expected_output="UDP services with protocol-specific responses",
            notes=[
                "Targets common UDP services (DNS, NTP, SNMP, Syslog)",
                "Uses service-specific payloads for accurate detection"
            ]
        ),
        Example(
            title="Stealth Scanning",
            description="Perform slow, stealthy scan to avoid detection",
            command="spectra -ps target.com -p 80,443,22,21 --delay 1000 --workers 5",
            level=ExampleLevel.INTERMEDIATE,
            category="Stealth Techniques",
            expected_output="Scan results with minimal network footprint",
            notes=[
                "1 second delay between requests",
                "Limited concurrent connections",
                "Reduces chance of triggering IDS/IPS"
            ]
        ),
        Example(
            title="High-Performance Scan",
            description="Fast scan with optimized settings for large networks",
            command="spectra -ps 192.168.1.0/24 --top-ports 1000 --workers 200 --timeout 0.5",
            level=ExampleLevel.ADVANCED,
            category="Performance Optimization",
            expected_output="Rapid scan results for entire subnet",
            notes=[
                "Scans entire /24 subnet (254 hosts)",
                "200 concurrent threads for maximum speed",
                "Reduced timeout for faster completion"
            ]
        ),
        Example(
            title="Comprehensive Service Analysis",
            description="Detailed scan with service detection and host discovery",
            command="spectra -ps enterprise.com -p 1-65535 --host-discovery --verbose --output-format json",
            level=ExampleLevel.ADVANCED,
            category="Comprehensive Analysis",
            expected_output="Complete port scan results in JSON format",
            notes=[
                "Full port range scan (all 65535 ports)",
                "Host discovery ensures target is reachable",
                "JSON output suitable for automated processing",
                "Verbose mode shows scan progress and details"
            ]
        ),
        Example(
            title="Multi-Target Scanning",
            description="Scan multiple targets with different port sets",
            command="spectra -ps \"web1.com,web2.com,db.internal\" -p 80,443,3306,5432 --workers 100",
            level=ExampleLevel.ADVANCED,
            category="Multi-Target",
            expected_output="Consolidated results for all targets",
            notes=[
                "Comma-separated target list",
                "Focuses on web and database ports",
                "Efficient parallel scanning"
            ]
        )
    ],
    
    use_cases=[
        UseCase(
            title="Network Discovery",
            description="Discover active hosts and services in a network segment",
            scenario="When you need to map out network infrastructure and identify running services",
            steps=[
                "Start with host discovery to identify live hosts",
                "Perform top ports scan to find common services",
                "Use banner grabbing to identify service versions",
                "Document findings for network inventory"
            ],
            related_examples=["Basic Port Scan", "Top Ports Scan"]
        ),
        UseCase(
            title="Security Assessment",
            description="Identify potentially vulnerable services and unnecessary open ports",
            scenario="During security audits or penetration testing",
            steps=[
                "Scan all ports to identify complete attack surface",
                "Focus on non-standard ports that might be overlooked",
                "Correlate open ports with known vulnerabilities",
                "Generate reports for security team review"
            ],
            related_examples=["Comprehensive Service Analysis", "High-Performance Scan"]
        ),
        UseCase(
            title="Service Monitoring",
            description="Monitor critical services for availability and changes",
            scenario="For ongoing monitoring of production services",
            steps=[
                "Define list of critical ports/services to monitor",
                "Set up regular scanning schedule",
                "Compare results against baseline",
                "Alert on unexpected changes or service outages"
            ],
            related_examples=["Custom Port Range", "Multi-Target Scanning"]
        ),
        UseCase(
            title="Firewall Testing",
            description="Verify firewall rules and network segmentation",
            scenario="When testing network security controls and access policies",
            steps=[
                "Scan from different network segments",
                "Test both allowed and blocked ports",
                "Verify that only intended services are accessible",
                "Document any unexpected access paths"
            ],
            related_examples=["Stealth Scanning", "UDP Service Discovery"]
        )
    ],
    
    related_modules=[
        "banner_grabber",
        "service_detector", 
        "vulnerability_scanner",
        "network_monitor"
    ],
    
    dependencies=[
        "socket",
        "threading",
        "concurrent.futures"
    ],
    
    tags=[
        "port scanning",
        "network reconnaissance", 
        "service discovery",
        "tcp scan",
        "udp scan",
        "banner grabbing",
        "network mapping",
        "security assessment"
    ],
    
    documentation_url="https://github.com/spectra-team/spectra/wiki/Port-Scanner"
)