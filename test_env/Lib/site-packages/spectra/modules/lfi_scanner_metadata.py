# -*- coding: utf-8 -*-
"""
LFI Scanner Module Metadata for Spectra Help System
"""

from ..core.module_metadata import (
    ModuleMetadata, Parameter, Example, UseCase, 
    ModuleCategory, ParameterType, ExampleLevel
)

# LFI Scanner Module Metadata
METADATA = ModuleMetadata(
    name="lfi_scanner",
    display_name="Local File Inclusion Scanner",
    category=ModuleCategory.VULNERABILITY_DETECTION,
    description="Advanced Local File Inclusion vulnerability scanner with multiple attack vectors",
    detailed_description="""
    The LFI Scanner module detects Local File Inclusion vulnerabilities through
    comprehensive testing of file inclusion parameters. Features include path
    traversal detection, null byte injection, filter bypass techniques,
    and log poisoning attack vector identification.
    """,
    version="1.4.0",
    author="Spectra Team",
    cli_command="-lfi",
    cli_aliases=["--lfi-scan"],
    
    parameters=[
        Parameter(
            name="url",
            description="Target URL to scan for LFI vulnerabilities",
            param_type=ParameterType.URL,
            required=True,
            examples=["https://webapp.com/page.php?file=", "http://site.com/include.php?page=home"],
            help_text="URL with file inclusion parameters"
        ),
        Parameter(
            name="parameter",
            short_name="p",
            description="Specific parameter to test for LFI",
            param_type=ParameterType.STRING,
            examples=["file", "page", "include", "template"],
            help_text="Parameter name to test, auto-detected if not specified"
        ),
        Parameter(
            name="payloads",
            description="LFI payload set to use",
            param_type=ParameterType.CHOICE,
            choices=["basic", "comprehensive", "custom"],
            default_value="comprehensive",
            help_text="Predefined payload sets or custom payloads"
        ),
        Parameter(
            name="custom-payloads",
            description="File containing custom LFI payloads",
            param_type=ParameterType.FILE_PATH,
            examples=["lfi-payloads.txt", "custom-lfi.txt"],
            help_text="One payload per line for custom testing"
        ),
        Parameter(
            name="depth",
            description="Maximum directory traversal depth",
            param_type=ParameterType.INTEGER,
            default_value=5,
            min_value=1,
            max_value=15,
            examples=["3", "7", "10"],
            help_text="Number of ../ sequences to try"
        ),
        Parameter(
            name="null-byte",
            description="Test null byte injection techniques",
            param_type=ParameterType.BOOLEAN,
            default_value=True,
            help_text="Include null byte (%00) in payloads"
        ),
        Parameter(
            name="encoding",
            description="Test URL encoding bypass techniques",
            param_type=ParameterType.BOOLEAN,
            default_value=True,
            help_text="Test various encoding methods to bypass filters"
        ),
        Parameter(
            name="log-poisoning",
            description="Test for log poisoning attack vectors",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Check if log files are accessible for poisoning attacks"
        ),
        Parameter(
            name="threads",
            description="Number of concurrent testing threads",
            param_type=ParameterType.INTEGER,
            default_value=10,
            min_value=1,
            max_value=30,
            examples=["5", "15", "25"],
            help_text="Controls testing speed and server load"
        ),
        Parameter(
            name="timeout",
            description="Request timeout in seconds",
            param_type=ParameterType.INTEGER,
            default_value=10,
            min_value=5,
            max_value=60,
            examples=["15", "30", "45"],
            help_text="Maximum time to wait for responses"
        ),
        Parameter(
            name="output-format",
            description="Output format for results",
            param_type=ParameterType.CHOICE,
            choices=["table", "json", "xml"],
            default_value="table",
            help_text="Format for LFI scan results"
        ),
        Parameter(
            name="verbose",
            short_name="v",
            description="Enable verbose output with detailed information",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Shows detailed LFI testing and payload information"
        )
    ],
    
    examples=[
        Example(
            title="Basic LFI Scan",
            description="Scan URL for Local File Inclusion vulnerabilities",
            command="spectra -lfi https://webapp.com/page.php?file=home",
            level=ExampleLevel.BASIC,
            category="Basic Usage",
            expected_output="LFI vulnerability scan results with successful payloads",
            notes=[
                "Tests comprehensive payload set",
                "Includes path traversal and null byte techniques"
            ]
        ),
        Example(
            title="Specific Parameter Testing",
            description="Test specific parameter for LFI vulnerability",
            command="spectra -lfi https://site.com/include.php -p page --depth 7",
            level=ExampleLevel.INTERMEDIATE,
            category="Targeted Testing",
            expected_output="LFI test results for specific parameter",
            notes=[
                "Focuses on 'page' parameter",
                "Increased traversal depth for deeper testing"
            ]
        ),
        Example(
            title="Advanced LFI Testing",
            description="Comprehensive LFI testing with encoding and log poisoning",
            command="spectra -lfi https://app.com/view.php?template=main --encoding --log-poisoning --verbose",
            level=ExampleLevel.ADVANCED,
            category="Advanced Techniques",
            expected_output="Comprehensive LFI analysis with advanced attack vectors",
            notes=[
                "Tests encoding bypass techniques",
                "Checks for log poisoning opportunities",
                "Verbose output shows detailed analysis"
            ]
        ),
        Example(
            title="Custom Payload Testing",
            description="Use custom payloads for application-specific LFI testing",
            command="spectra -lfi https://target.com/file.php?doc=readme --custom-payloads custom-lfi.txt --threads 5",
            level=ExampleLevel.ADVANCED,
            category="Custom Testing",
            expected_output="LFI scan results using custom payload set",
            notes=[
                "Uses application-specific payloads",
                "Reduced threads for careful testing"
            ]
        )
    ],
    
    use_cases=[
        UseCase(
            title="Web Application Security Testing",
            description="Test web applications for Local File Inclusion vulnerabilities",
            scenario="During security assessments of web applications",
            steps=[
                "Identify file inclusion parameters",
                "Test various LFI attack vectors",
                "Verify file access and content disclosure",
                "Document vulnerable parameters and impact"
            ],
            related_examples=["Basic LFI Scan", "Specific Parameter Testing"]
        ),
        UseCase(
            title="Advanced LFI Exploitation",
            description="Identify advanced LFI attack opportunities",
            scenario="For comprehensive penetration testing",
            steps=[
                "Test encoding bypass techniques",
                "Check for log poisoning vectors",
                "Identify sensitive file access",
                "Develop exploitation strategies"
            ],
            related_examples=["Advanced LFI Testing", "Custom Payload Testing"]
        )
    ],
    
    related_modules=[
        "sql_injection_scanner",
        "xss_scanner",
        "vulnerability_scanner"
    ],
    
    tags=[
        "lfi",
        "local file inclusion",
        "path traversal",
        "file inclusion",
        "directory traversal",
        "log poisoning"
    ]
)