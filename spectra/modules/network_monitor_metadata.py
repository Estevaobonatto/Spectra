# -*- coding: utf-8 -*-
"""
Network Monitor Module Metadata for Spectra Help System
"""

from ..core.module_metadata import (
    ModuleMetadata, Parameter, Example, UseCase, 
    ModuleCategory, ParameterType, ExampleLevel
)

# Network Monitor Module Metadata
METADATA = ModuleMetadata(
    name="network_monitor",
    display_name="Network Monitor",
    category=ModuleCategory.MONITORING,
    description="Real-time network monitoring and traffic analysis tool",
    detailed_description="""
    The Network Monitor module provides comprehensive network monitoring capabilities
    including real-time traffic analysis, bandwidth monitoring, connection tracking,
    anomaly detection, and network performance metrics. Features advanced filtering
    and alerting for network security monitoring.
    """,
    version="1.9.0",
    author="Spectra Team",
    cli_command="-netmon",
    cli_aliases=["--network-monitor"],
    
    parameters=[
        Parameter(
            name="interface",
            short_name="i",
            description="Network interface to monitor",
            param_type=ParameterType.STRING,
            examples=["eth0", "wlan0", "en0", "any"],
            help_text="Network interface name or 'any' for all interfaces"
        ),
        Parameter(
            name="duration",
            description="Monitoring duration in seconds",
            param_type=ParameterType.INTEGER,
            default_value=60,
            min_value=10,
            max_value=3600,
            examples=["30", "300", "1800"],
            help_text="How long to monitor network traffic"
        ),
        Parameter(
            name="filter",
            description="Traffic filter expression (BPF syntax)",
            param_type=ParameterType.STRING,
            examples=["tcp port 80", "host 192.168.1.1", "icmp"],
            help_text="Berkeley Packet Filter expression for traffic filtering"
        ),
        Parameter(
            name="protocols",
            description="Protocols to monitor",
            param_type=ParameterType.LIST,
            default_value=["tcp", "udp", "icmp"],
            examples=["tcp,udp", "http,https,dns", "all"],
            help_text="Comma-separated protocol list or 'all'"
        ),
        Parameter(
            name="bandwidth-threshold",
            description="Bandwidth threshold for alerts (MB/s)",
            param_type=ParameterType.FLOAT,
            examples=["10.0", "50.0", "100.0"],
            help_text="Alert when bandwidth exceeds threshold"
        ),
        Parameter(
            name="connection-limit",
            description="Maximum connections threshold for alerts",
            param_type=ParameterType.INTEGER,
            examples=["100", "500", "1000"],
            help_text="Alert when connection count exceeds limit"
        ),
        Parameter(
            name="anomaly-detection",
            description="Enable network anomaly detection",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Detect unusual network patterns and behaviors"
        ),
        Parameter(
            name="save-pcap",
            description="Save captured packets to PCAP file",
            param_type=ParameterType.STRING,
            examples=["capture.pcap", "network-traffic.pcap"],
            help_text="Filename to save packet capture"
        ),
        Parameter(
            name="real-time",
            description="Enable real-time monitoring display",
            param_type=ParameterType.BOOLEAN,
            default_value=True,
            help_text="Show live network statistics and updates"
        ),
        Parameter(
            name="output-format",
            description="Output format for results",
            param_type=ParameterType.CHOICE,
            choices=["table", "json", "csv"],
            default_value="table",
            help_text="Format for network monitoring results"
        ),
        Parameter(
            name="verbose",
            short_name="v",
            description="Enable verbose output with detailed information",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Shows detailed network analysis and packet information"
        )
    ],
    
    examples=[
        Example(
            title="Basic Network Monitoring",
            description="Monitor network traffic on default interface",
            command="spectra -netmon --duration 300",
            level=ExampleLevel.BASIC,
            category="Basic Usage",
            expected_output="Real-time network traffic statistics and connection information",
            notes=[
                "Monitors for 5 minutes",
                "Shows bandwidth and connection statistics"
            ]
        ),
        Example(
            title="Protocol-Specific Monitoring",
            description="Monitor specific protocols with filtering",
            command="spectra -netmon -i eth0 --protocols tcp,udp --filter \"port 80 or port 443\"",
            level=ExampleLevel.INTERMEDIATE,
            category="Protocol Filtering",
            expected_output="HTTP/HTTPS traffic monitoring on eth0 interface",
            notes=[
                "Focuses on web traffic (ports 80 and 443)",
                "Monitors TCP and UDP protocols only"
            ]
        ),
        Example(
            title="Bandwidth Monitoring with Alerts",
            description="Monitor bandwidth usage with threshold alerts",
            command="spectra -netmon --bandwidth-threshold 50.0 --connection-limit 500 --real-time",
            level=ExampleLevel.INTERMEDIATE,
            category="Threshold Monitoring",
            expected_output="Real-time bandwidth monitoring with alert notifications",
            notes=[
                "Alerts when bandwidth exceeds 50 MB/s",
                "Alerts when connections exceed 500",
                "Real-time display updates"
            ]
        ),
        Example(
            title="Advanced Network Analysis",
            description="Comprehensive network monitoring with anomaly detection",
            command="spectra -netmon --anomaly-detection --save-pcap network-analysis.pcap --duration 1800 --verbose",
            level=ExampleLevel.ADVANCED,
            category="Advanced Analysis",
            expected_output="Comprehensive network analysis with anomaly detection and packet capture",
            notes=[
                "30-minute monitoring session",
                "Saves packet capture for later analysis",
                "Includes anomaly detection algorithms",
                "Verbose output with detailed packet information"
            ]
        )
    ],
    
    use_cases=[
        UseCase(
            title="Network Security Monitoring",
            description="Monitor network for security threats and anomalies",
            scenario="For security teams monitoring network infrastructure",
            steps=[
                "Set up continuous network monitoring",
                "Configure bandwidth and connection thresholds",
                "Enable anomaly detection for unusual patterns",
                "Generate security alerts and reports"
            ],
            related_examples=["Bandwidth Monitoring with Alerts", "Advanced Network Analysis"]
        ),
        UseCase(
            title="Performance Monitoring",
            description="Monitor network performance and capacity",
            scenario="For network administrators managing infrastructure",
            steps=[
                "Monitor bandwidth utilization patterns",
                "Track connection counts and protocols",
                "Identify performance bottlenecks",
                "Generate capacity planning reports"
            ],
            related_examples=["Basic Network Monitoring", "Protocol-Specific Monitoring"]
        ),
        UseCase(
            title="Incident Response",
            description="Capture and analyze network traffic during incidents",
            scenario="During security incidents or network troubleshooting",
            steps=[
                "Capture network traffic to PCAP files",
                "Monitor specific protocols or hosts",
                "Analyze traffic patterns and anomalies",
                "Document network evidence for investigation"
            ],
            related_examples=["Advanced Network Analysis", "Protocol-Specific Monitoring"]
        )
    ],
    
    related_modules=[
        "port_scanner",
        "vulnerability_scanner",
        "dns_analyzer"
    ],
    
    tags=[
        "network monitoring",
        "traffic analysis",
        "bandwidth monitoring",
        "anomaly detection",
        "packet capture",
        "network security"
    ]
)