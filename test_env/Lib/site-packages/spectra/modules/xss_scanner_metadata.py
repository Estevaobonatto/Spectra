# -*- coding: utf-8 -*-
"""
XSS Scanner Module Metadata for Spectra Help System
"""

from ..core.module_metadata import (
    ModuleMetadata, Parameter, Example, UseCase, 
    ModuleCategory, ParameterType, ExampleLevel
)

# XSS Scanner Module Metadata
METADATA = ModuleMetadata(
    name="xss_scanner",
    display_name="XSS Scanner",
    category=ModuleCategory.VULNERABILITY_DETECTION,
    description="Advanced Cross-Site Scripting (XSS) vulnerability detection with multiple payload types",
    detailed_description="""
    The XSS Scanner module provides comprehensive Cross-Site Scripting vulnerability detection 
    using multiple techniques including reflected XSS, stored XSS, and DOM-based XSS. Features 
    intelligent payload generation, context-aware testing, WAF evasion techniques, and support 
    for modern web applications with AJAX and single-page architectures. Includes custom payload 
    support and detailed vulnerability reporting.
    """,
    version="3.3.0",
    author="Spectra Team",
    cli_command="-xss",
    cli_aliases=["--xss-scan"],
    
    parameters=[
        Parameter(
            name="url",
            description="Target URL to test for XSS vulnerabilities",
            param_type=ParameterType.URL,
            required=True,
            examples=[
                "http://example.com/search?q=test",
                "https://webapp.com/comment.php?id=123",
                "http://forum.com/post?message=hello"
            ],
            help_text="URL with parameters that will be tested for XSS injection"
        ),
        Parameter(
            name="xss-payloads",
            description="Custom payloads file for XSS testing",
            param_type=ParameterType.FILE_PATH,
            examples=[
                "xss-payloads.txt",
                "custom_xss.txt",
                "/path/to/advanced_xss_payloads.txt"
            ],
            help_text="Text file with custom XSS payloads (one per line)"
        ),
        Parameter(
            name="xss-stored",
            description="Enable stored XSS detection",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Test for persistent XSS that gets stored in the application"
        ),
        Parameter(
            name="xss-dom",
            description="Enable DOM-based XSS detection",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Test for client-side DOM manipulation vulnerabilities"
        ),
        Parameter(
            name="method",
            description="HTTP method to use for requests",
            param_type=ParameterType.CHOICE,
            choices=["GET", "POST", "PUT", "DELETE", "PATCH"],
            default_value="GET",
            help_text="HTTP method for sending XSS payloads"
        ),
        Parameter(
            name="data",
            description="POST data for testing (when using POST method)",
            param_type=ParameterType.STRING,
            examples=[
                "comment=test&name=user",
                "message=hello&email=test@example.com",
                "{\"content\": \"test message\", \"author\": \"user\"}"
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
            help_text="Timeout for HTTP requests"
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
            help_text="Concurrent threads for faster testing"
        ),
        Parameter(
            name="contexts",
            description="XSS contexts to test",
            param_type=ParameterType.STRING,
            default_value="html,attribute,script,style",
            examples=[
                "html,attribute",
                "script,style,html",
                "html,attribute,script,style,url"
            ],
            help_text="Comma-separated list: html, attribute, script, style, url"
        ),
        Parameter(
            name="encoding",
            description="Payload encoding techniques",
            param_type=ParameterType.STRING,
            examples=[
                "url,html",
                "unicode,hex",
                "url,html,unicode,hex,base64"
            ],
            help_text="Comma-separated list: url, html, unicode, hex, base64"
        ),
        Parameter(
            name="waf-bypass",
            description="Enable WAF bypass techniques",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Use encoding, fragmentation, and other techniques to bypass WAF"
        ),
        Parameter(
            name="browser-simulation",
            description="Simulate browser behavior for DOM XSS testing",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Use headless browser for JavaScript execution and DOM testing"
        ),
        Parameter(
            name="payload-level",
            description="Payload complexity level",
            param_type=ParameterType.CHOICE,
            choices=["basic", "intermediate", "advanced"],
            default_value="intermediate",
            help_text="Basic: simple payloads, Intermediate: common bypasses, Advanced: complex evasions"
        ),
        Parameter(
            name="check-reflection",
            description="Verify payload reflection in response",
            param_type=ParameterType.BOOLEAN,
            default_value=True,
            help_text="Check if payload is reflected in the response before marking as vulnerable"
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
            examples=["xss_traffic.txt", "requests_responses.log"],
            help_text="File to save all HTTP requests and responses for analysis"
        ),
        Parameter(
            name="screenshot",
            description="Take screenshots of successful XSS execution",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Capture screenshots when XSS payloads execute successfully"
        )
    ],
    
    examples=[
        Example(
            title="Basic XSS Test",
            description="Test a simple GET parameter for reflected XSS",
            command="spectra -xss http://example.com/search?q=test",
            level=ExampleLevel.BASIC,
            category="Reflected XSS",
            expected_output="XSS vulnerability detected with payload details",
            notes=[
                "Tests the 'q' parameter with basic XSS payloads",
                "Checks for payload reflection in response",
                "Good starting point for XSS testing"
            ]
        ),
        Example(
            title="POST Form Testing",
            description="Test POST form data for XSS vulnerabilities",
            command="spectra -xss http://example.com/comment --method POST --data \"comment=test&name=user\"",
            level=ExampleLevel.BASIC,
            category="Form Testing",
            expected_output="Results showing which form fields are vulnerable to XSS",
            notes=[
                "Tests both comment and name fields",
                "Uses POST method with form data",
                "Common for comment and contact forms"
            ]
        ),
        Example(
            title="Stored XSS Detection",
            description="Test for persistent XSS that gets stored in the application",
            command="spectra -xss http://forum.com/post?message=hello --xss-stored",
            level=ExampleLevel.INTERMEDIATE,
            category="Stored XSS",
            expected_output="Stored XSS vulnerabilities with persistence confirmation",
            notes=[
                "Tests if XSS payloads persist after submission",
                "Checks multiple pages for payload execution",
                "More dangerous than reflected XSS"
            ]
        ),
        Example(
            title="DOM-Based XSS Testing",
            description="Test for client-side DOM manipulation vulnerabilities",
            command="spectra -xss http://spa.com/app?fragment=test --xss-dom --browser-simulation",
            level=ExampleLevel.INTERMEDIATE,
            category="DOM XSS",
            expected_output="DOM-based XSS vulnerabilities with JavaScript execution proof",
            notes=[
                "Uses headless browser for JavaScript execution",
                "Tests client-side DOM manipulation",
                "Common in single-page applications"
            ]
        ),
        Example(
            title="WAF Bypass Testing",
            description="Test with WAF evasion techniques enabled",
            command="spectra -xss http://protected.com/search?q=test --waf-bypass --encoding url,html,unicode",
            level=ExampleLevel.ADVANCED,
            category="WAF Evasion",
            expected_output="Successful XSS despite WAF protection",
            notes=[
                "Uses multiple encoding techniques",
                "Fragments payloads to avoid detection",
                "Tests various bypass methods"
            ]
        ),
        Example(
            title="Custom Payload Testing",
            description="Use custom payloads for targeted XSS testing",
            command="spectra -xss http://webapp.com/input?data=test --xss-payloads custom_xss.txt --payload-level advanced",
            level=ExampleLevel.ADVANCED,
            category="Custom Payloads",
            expected_output="XSS results using custom payload set",
            notes=[
                "Uses custom payload file",
                "Advanced payload complexity level",
                "Tailored for specific application testing"
            ]
        ),
        Example(
            title="Comprehensive XSS Assessment",
            description="Full XSS testing with all detection methods",
            command="spectra -xss http://target.com/app?input=test --xss-stored --xss-dom --contexts html,attribute,script --verbose",
            level=ExampleLevel.ADVANCED,
            category="Comprehensive",
            expected_output="Complete XSS vulnerability assessment",
            notes=[
                "Tests reflected, stored, and DOM-based XSS",
                "Multiple injection contexts",
                "Detailed verbose output for analysis"
            ]
        ),
        Example(
            title="API XSS Testing",
            description="Test API endpoints for XSS in JSON responses",
            command="spectra -xss http://api.com/v1/search?query=test --headers \"Content-Type: application/json\" --method POST --data '{\"search\": \"test\"}'",
            level=ExampleLevel.INTERMEDIATE,
            category="API Testing",
            expected_output="API-specific XSS vulnerabilities in JSON responses",
            notes=[
                "Tests JSON API endpoints",
                "Includes proper content-type headers",
                "Common in modern web applications"
            ]
        )
    ],
    
    use_cases=[
        UseCase(
            title="Web Application Security Testing",
            description="Identify XSS vulnerabilities during security assessments",
            scenario="During penetration testing or security audits of web applications",
            steps=[
                "Map all input fields and parameters",
                "Test reflected XSS on all GET/POST parameters",
                "Check for stored XSS in user-generated content areas",
                "Test DOM-based XSS in client-side applications",
                "Document findings with proof-of-concept payloads"
            ],
            related_examples=["Basic XSS Test", "POST Form Testing", "Comprehensive XSS Assessment"]
        ),
        UseCase(
            title="Single Page Application Testing",
            description="Test modern SPAs and AJAX applications for DOM-based XSS",
            scenario="When testing modern web applications with heavy JavaScript usage",
            steps=[
                "Enable browser simulation for JavaScript execution",
                "Focus on DOM-based XSS detection methods",
                "Test URL fragments and hash parameters",
                "Check client-side routing and state management",
                "Verify XSS execution in dynamic content"
            ],
            related_examples=["DOM-Based XSS Testing", "Browser Simulation"]
        ),
        UseCase(
            title="Content Management System Testing",
            description="Test CMS platforms for stored XSS vulnerabilities",
            scenario="When assessing CMS security for persistent XSS threats",
            steps=[
                "Enable stored XSS detection",
                "Test all content input areas (posts, comments, profiles)",
                "Check administrative interfaces and rich text editors",
                "Verify XSS persistence across user sessions",
                "Test different user privilege levels"
            ],
            related_examples=["Stored XSS Detection", "Custom Payload Testing"]
        ),
        UseCase(
            title="WAF-Protected Application Testing",
            description="Test applications protected by Web Application Firewalls",
            scenario="When target applications have WAF or XSS protection",
            steps=[
                "Start with basic payloads to identify protection",
                "Enable WAF bypass techniques",
                "Use multiple encoding methods",
                "Test payload fragmentation and obfuscation",
                "Document successful bypass techniques"
            ],
            related_examples=["WAF Bypass Testing", "Advanced Encoding"]
        )
    ],
    
    related_modules=[
        "sql_injection_scanner",
        "command_injection_scanner",
        "waf_detector",
        "vulnerability_scanner"
    ],
    
    dependencies=[
        "requests",
        "beautifulsoup4",
        "urllib3",
        "concurrent.futures"
    ],
    
    tags=[
        "xss",
        "cross-site scripting",
        "web application testing",
        "vulnerability scanning",
        "reflected xss",
        "stored xss",
        "dom xss",
        "waf bypass",
        "payload encoding",
        "browser simulation"
    ],
    
    documentation_url="https://github.com/spectra-team/spectra/wiki/XSS-Scanner"
)