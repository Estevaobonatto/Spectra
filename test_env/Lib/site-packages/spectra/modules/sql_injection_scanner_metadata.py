# -*- coding: utf-8 -*-
"""
SQL Injection Scanner Module Metadata for Spectra Help System
"""

from ..core.module_metadata import (
    ModuleMetadata, Parameter, Example, UseCase, 
    ModuleCategory, ParameterType, ExampleLevel
)

# SQL Injection Scanner Module Metadata
METADATA = ModuleMetadata(
    name="sql_injection_scanner",
    display_name="SQL Injection Scanner",
    category=ModuleCategory.VULNERABILITY_DETECTION,
    description="Advanced SQL injection detection with multiple techniques and DBMS-specific payloads",
    detailed_description="""
    The SQL Injection Scanner module provides comprehensive SQL injection vulnerability detection 
    using multiple techniques including error-based, boolean-based, time-based, and union-based 
    injection. Supports various database management systems (MySQL, PostgreSQL, MSSQL, Oracle, SQLite) 
    with DBMS-specific payloads and detection methods. Features intelligent payload generation, 
    WAF evasion techniques, and out-of-band detection capabilities.
    """,
    version="3.3.0",
    author="Spectra Team",
    cli_command="-sqli",
    cli_aliases=["--sql-injection"],
    
    parameters=[
        Parameter(
            name="url",
            description="Target URL to test for SQL injection vulnerabilities",
            param_type=ParameterType.URL,
            required=True,
            examples=[
                "http://example.com/page?id=1",
                "https://shop.com/product.php?pid=123",
                "http://api.com/user/profile?user_id=456"
            ],
            help_text="URL with parameters that will be tested for SQL injection"
        ),
        Parameter(
            name="sqli-level",
            description="Aggressiveness level of SQL injection testing",
            param_type=ParameterType.CHOICE,
            choices=["1", "2", "3"],
            default_value="1",
            help_text="Level 1: Basic tests, Level 2: Moderate tests, Level 3: Aggressive tests"
        ),
        Parameter(
            name="sqli-dbms",
            description="Target database management system",
            param_type=ParameterType.CHOICE,
            choices=["mysql", "postgresql", "mssql", "oracle", "sqlite", "auto"],
            default_value="auto",
            help_text="Specify DBMS for targeted payloads or use auto-detection"
        ),
        Parameter(
            name="sqli-collaborator",
            description="OAST (Out-of-Band) collaborator server URL",
            param_type=ParameterType.URL,
            examples=[
                "http://your-server.com/callback",
                "https://collaborator.example.com",
                "http://burp-collaborator.net"
            ],
            help_text="Server to receive out-of-band callbacks for blind SQL injection detection"
        ),
        Parameter(
            name="method",
            description="HTTP method to use for requests",
            param_type=ParameterType.CHOICE,
            choices=["GET", "POST", "PUT", "DELETE", "PATCH"],
            default_value="GET",
            help_text="HTTP method for sending injection payloads"
        ),
        Parameter(
            name="data",
            description="POST data for testing (when using POST method)",
            param_type=ParameterType.STRING,
            examples=[
                "username=admin&password=test",
                "id=1&action=view",
                "{\"user_id\": 123, \"action\": \"get_profile\"}"
            ],
            help_text="Form data or JSON payload for POST requests"
        ),
        Parameter(
            name="headers",
            description="Custom HTTP headers to include",
            param_type=ParameterType.STRING,
            examples=[
                "Authorization: Bearer token123",
                "X-API-Key: abc123, Content-Type: application/json",
                "User-Agent: CustomBot/1.0"
            ],
            help_text="Comma-separated list of custom headers"
        ),
        Parameter(
            name="cookies",
            description="HTTP cookies to include in requests",
            param_type=ParameterType.STRING,
            examples=[
                "session=abc123; user=admin",
                "PHPSESSID=xyz789",
                "auth_token=token123; preferences=dark_mode"
            ],
            help_text="Cookie string to maintain session state"
        ),
        Parameter(
            name="timeout",
            description="Request timeout in seconds",
            param_type=ParameterType.FLOAT,
            default_value=10.0,
            min_value=1.0,
            max_value=60.0,
            examples=["5.0", "15.0", "30.0"],
            help_text="Timeout for HTTP requests and time-based injection detection"
        ),
        Parameter(
            name="delay",
            description="Delay between requests in seconds",
            param_type=ParameterType.FLOAT,
            default_value=0.0,
            min_value=0.0,
            max_value=10.0,
            examples=["0.5", "1.0", "2.0"],
            help_text="Delay to avoid overwhelming the target server"
        ),
        Parameter(
            name="threads",
            description="Number of concurrent testing threads",
            param_type=ParameterType.INTEGER,
            default_value=10,
            min_value=1,
            max_value=50,
            examples=["5", "15", "25"],
            help_text="Concurrent threads for faster testing (be careful with rate limiting)"
        ),
        Parameter(
            name="payloads-file",
            description="Custom payloads file for injection testing",
            param_type=ParameterType.FILE_PATH,
            examples=[
                "custom_sqli_payloads.txt",
                "mysql_specific.txt",
                "/path/to/advanced_payloads.txt"
            ],
            help_text="Text file with custom SQL injection payloads (one per line)"
        ),
        Parameter(
            name="techniques",
            description="SQL injection techniques to use",
            param_type=ParameterType.STRING,
            default_value="error,boolean,time,union",
            examples=[
                "error,boolean",
                "time,union",
                "error,boolean,time,union,blind"
            ],
            help_text="Comma-separated list: error, boolean, time, union, blind"
        ),
        Parameter(
            name="waf-bypass",
            description="Enable WAF bypass techniques",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Use encoding, comments, and other techniques to bypass WAF"
        ),
        Parameter(
            name="risk-level",
            description="Risk level for testing (affects payload selection)",
            param_type=ParameterType.CHOICE,
            choices=["low", "medium", "high"],
            default_value="medium",
            help_text="Higher risk levels use more intrusive payloads"
        ),
        Parameter(
            name="verbose",
            short_name="v",
            description="Enable verbose output with detailed testing information",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Shows all payloads tested, responses, and detection logic"
        ),
        Parameter(
            name="output-format",
            description="Output format for results",
            param_type=ParameterType.CHOICE,
            choices=["table", "json", "xml", "html"],
            default_value="table",
            help_text="Format for vulnerability report output"
        ),
        Parameter(
            name="save-traffic",
            description="Save all HTTP traffic to file",
            param_type=ParameterType.FILE_PATH,
            examples=["sqli_traffic.txt", "requests_responses.log"],
            help_text="File to save all HTTP requests and responses for analysis"
        )
    ],
    
    examples=[
        Example(
            title="Basic SQL Injection Test",
            description="Test a simple GET parameter for SQL injection",
            command="spectra -sqli http://example.com/page?id=1",
            level=ExampleLevel.BASIC,
            category="Basic Testing",
            expected_output="SQL injection vulnerability detected with payload details",
            notes=[
                "Tests the 'id' parameter with basic payloads",
                "Uses error-based and boolean-based detection",
                "Good starting point for SQL injection testing"
            ]
        ),
        Example(
            title="POST Data Testing",
            description="Test POST form data for SQL injection vulnerabilities",
            command="spectra -sqli http://example.com/login --method POST --data \"username=admin&password=test\"",
            level=ExampleLevel.BASIC,
            category="POST Testing",
            expected_output="Results showing which form fields are vulnerable",
            notes=[
                "Tests both username and password fields",
                "Uses POST method with form data",
                "Common for login form testing"
            ]
        ),
        Example(
            title="Database-Specific Testing",
            description="Target specific DBMS with optimized payloads",
            command="spectra -sqli http://mysql-app.com/user?id=123 --sqli-dbms mysql --sqli-level 2",
            level=ExampleLevel.INTERMEDIATE,
            category="DBMS Targeting",
            expected_output="MySQL-specific vulnerabilities and exploitation techniques",
            notes=[
                "Uses MySQL-specific payloads and functions",
                "Level 2 testing includes more advanced techniques",
                "More accurate results when DBMS is known"
            ]
        ),
        Example(
            title="Time-Based Blind Injection",
            description="Detect blind SQL injection using time delays",
            command="spectra -sqli http://secure.com/api?user_id=456 --techniques time --timeout 15",
            level=ExampleLevel.INTERMEDIATE,
            category="Blind Injection",
            expected_output="Time-based injection vulnerabilities with delay confirmation",
            notes=[
                "Uses only time-based detection techniques",
                "Increased timeout to detect delays reliably",
                "Effective when error messages are suppressed"
            ]
        ),
        Example(
            title="WAF Bypass Testing",
            description="Test with WAF evasion techniques enabled",
            command="spectra -sqli http://protected.com/search?q=test --waf-bypass --sqli-level 3",
            level=ExampleLevel.ADVANCED,
            category="WAF Evasion",
            expected_output="Successful injection despite WAF protection",
            notes=[
                "Uses encoding, comments, and case variations",
                "Level 3 includes most aggressive payloads",
                "Specifically designed to bypass common WAFs"
            ]
        ),
        Example(
            title="Out-of-Band Detection",
            description="Use OAST server for blind injection detection",
            command="spectra -sqli http://api.com/data?filter=name --sqli-collaborator http://your-server.com/callback",
            level=ExampleLevel.ADVANCED,
            category="OAST Detection",
            expected_output="Out-of-band callbacks confirming blind SQL injection",
            notes=[
                "Requires external collaborator server",
                "Detects blind injections that don't cause delays",
                "Most reliable method for complex blind injections"
            ]
        ),
        Example(
            title="Comprehensive Assessment",
            description="Full SQL injection assessment with all techniques",
            command="spectra -sqli http://webapp.com/profile?user=123 --sqli-level 3 --techniques error,boolean,time,union --verbose --output-format json",
            level=ExampleLevel.ADVANCED,
            category="Comprehensive",
            expected_output="Complete vulnerability assessment in JSON format",
            notes=[
                "Uses all available detection techniques",
                "Maximum aggressiveness level",
                "Detailed verbose output for analysis",
                "JSON output suitable for integration"
            ]
        ),
        Example(
            title="API Testing with Authentication",
            description="Test authenticated API endpoints for SQL injection",
            command="spectra -sqli http://api.com/v1/users?id=123 --headers \"Authorization: Bearer token123, Content-Type: application/json\" --method GET",
            level=ExampleLevel.INTERMEDIATE,
            category="API Testing",
            expected_output="API-specific SQL injection vulnerabilities",
            notes=[
                "Includes authentication headers",
                "Tests API endpoints with proper content type",
                "Common for modern web application testing"
            ]
        )
    ],
    
    use_cases=[
        UseCase(
            title="Web Application Security Testing",
            description="Identify SQL injection vulnerabilities during security assessments",
            scenario="During penetration testing or security audits of web applications",
            steps=[
                "Map all input parameters and endpoints",
                "Start with basic level testing on all parameters",
                "Increase aggressiveness for suspicious parameters",
                "Test different HTTP methods and data formats",
                "Document all findings with proof-of-concept payloads"
            ],
            related_examples=["Basic SQL Injection Test", "POST Data Testing", "Comprehensive Assessment"]
        ),
        UseCase(
            title="API Security Assessment",
            description="Test REST APIs and web services for SQL injection vulnerabilities",
            scenario="When assessing API security for modern web applications",
            steps=[
                "Identify all API endpoints and parameters",
                "Test with proper authentication headers",
                "Use JSON and XML payloads for API-specific testing",
                "Test both query parameters and request body data",
                "Verify findings don't cause data corruption"
            ],
            related_examples=["API Testing with Authentication", "Database-Specific Testing"]
        ),
        UseCase(
            title="Blind Injection Detection",
            description="Detect SQL injection in applications with minimal error feedback",
            scenario="When testing applications that suppress error messages",
            steps=[
                "Use time-based techniques for initial detection",
                "Set up OAST collaborator for out-of-band detection",
                "Test boolean-based blind injection techniques",
                "Increase timeout values for reliable detection",
                "Combine multiple techniques for confirmation"
            ],
            related_examples=["Time-Based Blind Injection", "Out-of-Band Detection"]
        ),
        UseCase(
            title="WAF-Protected Application Testing",
            description="Test applications protected by Web Application Firewalls",
            scenario="When target applications have WAF or similar protection",
            steps=[
                "Start with basic payloads to identify WAF presence",
                "Enable WAF bypass techniques and evasion methods",
                "Use encoding and obfuscation techniques",
                "Test with different payload variations",
                "Document successful bypass techniques"
            ],
            related_examples=["WAF Bypass Testing", "Comprehensive Assessment"]
        )
    ],
    
    related_modules=[
        "xss_scanner",
        "command_injection_scanner",
        "lfi_scanner",
        "waf_detector",
        "vulnerability_scanner"
    ],
    
    dependencies=[
        "requests",
        "urllib3",
        "concurrent.futures",
        "re"
    ],
    
    tags=[
        "sql injection",
        "database security",
        "web application testing",
        "vulnerability scanning",
        "blind injection",
        "time-based injection",
        "error-based injection",
        "union-based injection",
        "waf bypass",
        "oast detection"
    ],
    
    documentation_url="https://github.com/spectra-team/spectra/wiki/SQL-Injection-Scanner"
)