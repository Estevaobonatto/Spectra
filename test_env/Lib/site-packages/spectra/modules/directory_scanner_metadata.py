# -*- coding: utf-8 -*-
"""
Directory Scanner Module Metadata for Spectra Help System
"""

from ..core.module_metadata import (
    ModuleMetadata, Parameter, Example, UseCase, 
    ModuleCategory, ParameterType, ExampleLevel
)

# Directory Scanner Module Metadata
METADATA = ModuleMetadata(
    name="directory_scanner",
    display_name="Directory Scanner",
    category=ModuleCategory.RECONNAISSANCE,
    description="Advanced web directory and file discovery with intelligent filtering and performance optimization",
    detailed_description="""
    The Directory Scanner module provides comprehensive web directory and file discovery capabilities 
    that rival tools like Dirsearch, Feroxbuster, and Gobuster. Features include multiple HTTP methods, 
    advanced filtering, recursive scanning, WAF detection and evasion, false positive filtering, 
    content-based discovery, and performance optimization with auto-scaling workers and connection pooling.
    """,
    version="3.3.0",
    author="Spectra Team",
    cli_command="-ds",
    cli_aliases=["--directory-scan"],
    
    parameters=[
        Parameter(
            name="url",
            description="Target URL to scan for directories and files",
            param_type=ParameterType.URL,
            required=True,
            examples=["https://example.com", "http://target.com/app", "https://api.company.com"],
            help_text="Base URL where directory scanning will start"
        ),
        Parameter(
            name="wordlist",
            short_name="w",
            description="Wordlist file containing directory and file names to test",
            param_type=ParameterType.FILE_PATH,
            required=True,
            examples=["common.txt", "directories.txt", "/usr/share/wordlists/dirb/common.txt"],
            help_text="Text file with one word per line for directory/file discovery"
        ),
        Parameter(
            name="workers",
            description="Number of concurrent scanning threads",
            param_type=ParameterType.INTEGER,
            default_value=30,
            min_value=1,
            max_value=500,
            examples=["50", "100", "200"],
            help_text="Auto-adjusted based on CPU count if not specified"
        ),
        Parameter(
            name="timeout",
            description="HTTP request timeout in seconds",
            param_type=ParameterType.FLOAT,
            default_value=10.0,
            min_value=1.0,
            max_value=60.0,
            examples=["5.0", "15.0", "30.0"],
            help_text="Balance between speed and reliability"
        ),
        Parameter(
            name="recursive",
            description="Enable recursive scanning of discovered directories",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Explores subdirectories found during scanning"
        ),
        Parameter(
            name="max-depth",
            description="Maximum recursion depth for recursive scanning",
            param_type=ParameterType.INTEGER,
            default_value=3,
            min_value=1,
            max_value=10,
            examples=["2", "5", "8"],
            help_text="Prevents infinite recursion and controls scan scope"
        ),
        Parameter(
            name="stealth",
            description="Enable stealth mode with extra delays",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Slower but less detectable scanning"
        ),
        Parameter(
            name="http-methods",
            description="HTTP methods to test (comma-separated)",
            param_type=ParameterType.STRING,
            default_value="GET",
            examples=["GET,POST", "GET,POST,PUT,HEAD", "GET,POST,PUT,DELETE,OPTIONS"],
            help_text="Different methods may reveal different resources"
        ),
        Parameter(
            name="status-codes",
            description="Include only these HTTP status codes",
            param_type=ParameterType.STRING,
            examples=["200,403,500", "200,301,302", "200,403,401,500"],
            help_text="Positive filtering - only show specified status codes"
        ),
        Parameter(
            name="exclude-status",
            description="Exclude these HTTP status codes from results",
            param_type=ParameterType.STRING,
            default_value="404",
            examples=["404,500,502", "404,403", "404,500,502,503"],
            help_text="Negative filtering - hide specified status codes"
        ),
        Parameter(
            name="content-length-min",
            description="Minimum response content length in bytes",
            param_type=ParameterType.INTEGER,
            min_value=0,
            examples=["100", "500", "1000"],
            help_text="Filter out very small responses (often error pages)"
        ),
        Parameter(
            name="content-length-max",
            description="Maximum response content length in bytes",
            param_type=ParameterType.INTEGER,
            examples=["10000", "50000", "100000"],
            help_text="Filter out very large responses"
        ),
        Parameter(
            name="response-time-min",
            description="Minimum response time in seconds",
            param_type=ParameterType.FLOAT,
            min_value=0.0,
            examples=["0.5", "1.0", "2.0"],
            help_text="Filter responses that are too fast (may indicate caching)"
        ),
        Parameter(
            name="response-time-max",
            description="Maximum response time in seconds",
            param_type=ParameterType.FLOAT,
            examples=["2.0", "5.0", "10.0"],
            help_text="Filter responses that are too slow"
        ),
        Parameter(
            name="no-backup-discovery",
            description="Disable automatic backup file discovery",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Skips testing for .bak, .old, ~, _backup variants"
        ),
        Parameter(
            name="no-content-discovery",
            description="Disable content-based path discovery",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Skips extracting paths from HTML/JS/CSS content"
        ),
        Parameter(
            name="adaptive-delay",
            description="Enable intelligent rate limiting",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Automatically adjusts speed based on server responses (429/503)"
        ),
        Parameter(
            name="performance-mode",
            description="Performance optimization mode",
            param_type=ParameterType.CHOICE,
            choices=["balanced", "fast", "aggressive"],
            default_value="balanced",
            help_text="balanced: default, fast: 8x CPUs, aggressive: 10x CPUs"
        ),
        Parameter(
            name="connection-pool-size",
            description="HTTP connection pool size",
            param_type=ParameterType.INTEGER,
            examples=["50", "100", "200"],
            help_text="Defaults to workers * 2 for optimal performance"
        ),
        Parameter(
            name="show-performance-stats",
            description="Display detailed performance statistics",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Shows requests/sec, efficiency score, and optimization suggestions"
        ),
        Parameter(
            name="verbose",
            short_name="v",
            description="Enable verbose output with detailed progress",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Shows scan progress, WAF detection, and detailed findings"
        )
    ],
    
    examples=[
        Example(
            title="Basic Directory Scan",
            description="Simple directory discovery using common wordlist",
            command="spectra -ds https://example.com -w common.txt",
            level=ExampleLevel.BASIC,
            category="Basic Usage",
            expected_output="List of discovered directories and files with status codes",
            notes=[
                "Uses default settings with GET method only",
                "Includes automatic backup file discovery",
                "Shows progress bar during scanning"
            ]
        ),
        Example(
            title="Recursive Directory Discovery",
            description="Deep directory scanning with recursive exploration",
            command="spectra -ds https://target.com -w dirs.txt --recursive --max-depth 2",
            level=ExampleLevel.BASIC,
            category="Recursive Scanning",
            expected_output="Hierarchical directory structure with nested discoveries",
            notes=[
                "Explores found directories up to 2 levels deep",
                "Automatically discovers directory listings",
                "May take longer but finds more hidden content"
            ]
        ),
        Example(
            title="Multi-Method HTTP Testing",
            description="Test multiple HTTP methods for comprehensive discovery",
            command="spectra -ds https://api.com -w api.txt --http-methods GET,POST,PUT,DELETE,OPTIONS",
            level=ExampleLevel.INTERMEDIATE,
            category="HTTP Methods",
            expected_output="Results showing different resources accessible via different methods",
            notes=[
                "Useful for API endpoint discovery",
                "May reveal admin functions via PUT/DELETE",
                "OPTIONS method shows allowed methods"
            ]
        ),
        Example(
            title="Advanced Filtering",
            description="Use multiple filters to reduce false positives",
            command="spectra -ds https://webapp.com -w wordlist.txt --exclude-status 404,500 --content-length-min 100 --response-time-max 2.0",
            level=ExampleLevel.INTERMEDIATE,
            category="Filtering",
            expected_output="Clean results with noise filtered out",
            notes=[
                "Excludes error pages and empty responses",
                "Filters out responses that are too fast or slow",
                "Reduces manual review time"
            ]
        ),
        Example(
            title="High-Performance Scanning",
            description="Maximum speed scanning with performance optimization",
            command="spectra -ds https://fast.com -w big.txt --performance-mode aggressive --workers 200 --show-performance-stats",
            level=ExampleLevel.ADVANCED,
            category="Performance",
            expected_output="Rapid scan results with performance metrics",
            notes=[
                "Uses 200 concurrent threads for maximum speed",
                "Shows requests/second and efficiency metrics",
                "Optimized connection pooling and retry logic"
            ]
        ),
        Example(
            title="Stealth Evasion Scanning",
            description="Slow, stealthy scan to avoid WAF detection",
            command="spectra -ds https://secure.com -w dirs.txt --stealth --adaptive-delay --workers 5",
            level=ExampleLevel.ADVANCED,
            category="Stealth",
            expected_output="Scan results with minimal detection footprint",
            notes=[
                "Automatically detects and evades WAF",
                "Adapts speed based on rate limiting responses",
                "Uses minimal concurrent connections"
            ]
        ),
        Example(
            title="Comprehensive Content Discovery",
            description="Full-featured scan with all discovery methods enabled",
            command="spectra -ds https://enterprise.com -w comprehensive.txt --recursive --http-methods GET,POST,HEAD --verbose",
            level=ExampleLevel.ADVANCED,
            category="Comprehensive",
            expected_output="Complete directory and file inventory with detailed information",
            notes=[
                "Combines recursive scanning with multiple methods",
                "Includes backup file and content-based discovery",
                "Verbose output shows technology detection"
            ]
        ),
        Example(
            title="API Endpoint Discovery",
            description="Specialized scanning for REST API endpoints",
            command="spectra -ds https://api.company.com/v1 -w api-endpoints.txt --http-methods GET,POST,PUT,DELETE --status-codes 200,401,403",
            level=ExampleLevel.INTERMEDIATE,
            category="API Testing",
            expected_output="API endpoints with authentication and authorization status",
            notes=[
                "Focuses on API-relevant HTTP methods",
                "Filters for meaningful API response codes",
                "Useful for API security assessment"
            ]
        )
    ],
    
    use_cases=[
        UseCase(
            title="Web Application Security Assessment",
            description="Discover hidden directories, files, and admin interfaces during security testing",
            scenario="During penetration testing or security audits of web applications",
            steps=[
                "Start with basic directory scan using common wordlist",
                "Enable recursive scanning for deeper discovery",
                "Use multiple HTTP methods to find admin functions",
                "Apply filtering to focus on interesting findings",
                "Document discovered attack surface"
            ],
            related_examples=["Basic Directory Scan", "Multi-Method HTTP Testing", "Comprehensive Content Discovery"]
        ),
        UseCase(
            title="Content Management System Analysis",
            description="Map out CMS structure and identify potential vulnerabilities",
            scenario="When analyzing WordPress, Drupal, or other CMS installations",
            steps=[
                "Use CMS-specific wordlists for targeted discovery",
                "Enable backup file discovery for configuration files",
                "Scan for admin panels and sensitive directories",
                "Check for default installation files and directories",
                "Correlate findings with known CMS vulnerabilities"
            ],
            related_examples=["Recursive Directory Discovery", "Advanced Filtering"]
        ),
        UseCase(
            title="API Security Testing",
            description="Discover and enumerate REST API endpoints and resources",
            scenario="When testing API security and looking for undocumented endpoints",
            steps=[
                "Use API-focused wordlists with common endpoint names",
                "Test multiple HTTP methods (GET, POST, PUT, DELETE, PATCH)",
                "Look for version-specific endpoints (/v1, /v2, /api)",
                "Check for admin and debug endpoints",
                "Test for CORS and authentication bypass"
            ],
            related_examples=["API Endpoint Discovery", "Multi-Method HTTP Testing"]
        ),
        UseCase(
            title="Large-Scale Infrastructure Mapping",
            description="Efficiently scan multiple web applications across an organization",
            scenario="During infrastructure assessments or bug bounty programs",
            steps=[
                "Use high-performance mode for speed",
                "Implement stealth techniques for sensitive targets",
                "Apply consistent filtering across all targets",
                "Generate machine-readable output for analysis",
                "Correlate findings across multiple applications"
            ],
            related_examples=["High-Performance Scanning", "Stealth Evasion Scanning"]
        )
    ],
    
    related_modules=[
        "port_scanner",
        "subdomain_scanner",
        "technology_detector",
        "waf_detector",
        "vulnerability_scanner"
    ],
    
    dependencies=[
        "requests",
        "urllib3",
        "concurrent.futures",
        "threading"
    ],
    
    tags=[
        "directory scanning",
        "web reconnaissance",
        "file discovery",
        "web application testing",
        "content discovery",
        "recursive scanning",
        "http methods",
        "waf evasion",
        "performance optimization"
    ],
    
    documentation_url="https://github.com/spectra-team/spectra/wiki/Directory-Scanner"
)