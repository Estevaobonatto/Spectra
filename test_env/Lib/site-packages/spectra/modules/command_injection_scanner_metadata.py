# -*- coding: utf-8 -*-
"""
Command Injection Scanner Module Metadata for Spectra Help System
"""

from ..core.module_metadata import (
    ModuleMetadata, Parameter, Example, UseCase, 
    ModuleCategory, ParameterType, ExampleLevel
)

# Command Injection Scanner Module Metadata
METADATA = ModuleMetadata(
    name="command_injection_scanner",
    display_name="Command Injection Scanner",
    category=ModuleCategory.VULNERABILITY_DETECTION,
    description="Advanced command injection vulnerability scanner with multiple detection techniques",
    detailed_description="""
    The Command Injection Scanner module detects command injection vulnerabilities
    through comprehensive testing of input parameters. Features include time-based
    detection, output-based detection, blind command injection testing with OAST,
    and platform-specific payload testing for Windows, Linux, and Unix systems.
    """,
    version="1.2.0",
    author="Spectra Team",
    cli_command="-cmd",
    cli_aliases=["--command-injection"],
    
    parameters=[
        Parameter(
            name="url",
            description="Target URL to scan for command injection vulnerabilities",
            param_type=ParameterType.URL,
            required=True,
            examples=["https://webapp.com/exec.php?cmd=", "http://api.com/system?command="],
            help_text="URL with parameters that might execute system commands"
        ),
        Parameter(
            name="parameter",
            short_name="p",
            description="Specific parameter to test for command injection",
            param_type=ParameterType.STRING,
            examples=["cmd", "command", "exec", "system", "run"],
            help_text="Parameter name to test, auto-detected if not specified"
        ),
        Parameter(
            name="detection-method",
            description="Command injection detection method",
            param_type=ParameterType.CHOICE,
            choices=["time-based", "output-based", "blind", "all"],
            default_value="all",
            help_text="Method used to detect command injection"
        ),
        Parameter(
            name="platform",
            description="Target platform for command payloads",
            param_type=ParameterType.CHOICE,
            choices=["windows", "linux", "unix", "auto"],
            default_value="auto",
            help_text="Operating system to target with specific payloads"
        ),
        Parameter(
            name="collaborator-url",
            description="OAST collaborator URL for blind detection",
            param_type=ParameterType.URL,
            examples=["http://your-server.com", "https://burp-collaborator.net"],
            help_text="External server to detect blind command injection"
        ),
        Parameter(
            name="time-delay",
            description="Time delay for time-based detection (seconds)",
            param_type=ParameterType.INTEGER,
            default_value=5,
            min_value=1,
            max_value=30,
            examples=["3", "10", "15"],
            help_text="Delay time to confirm time-based injection"
        ),
        Parameter(
            name="custom-payloads",
            description="File containing custom command injection payloads",
            param_type=ParameterType.FILE_PATH,
            examples=["cmd-payloads.txt", "custom-commands.txt"],
            help_text="One payload per line for custom testing"
        ),
        Parameter(
            name="encoding",
            description="Test URL encoding bypass techniques",
            param_type=ParameterType.BOOLEAN,
            default_value=True,
            help_text="Use various encoding methods to bypass filters"
        ),
        Parameter(
            name="timeout",
            description="Request timeout in seconds",
            param_type=ParameterType.INTEGER,
            default_value=30,
            min_value=10,
            max_value=120,
            examples=["20", "45", "60"],
            help_text="Maximum time to wait for responses (important for time-based)"
        ),
        Parameter(
            name="threads",
            description="Number of concurrent testing threads",
            param_type=ParameterType.INTEGER,
            default_value=5,
            min_value=1,
            max_value=15,
            examples=["3", "8", "12"],
            help_text="Controls testing speed and server load"
        ),
        Parameter(
            name="output-format",
            description="Output format for results",
            param_type=ParameterType.CHOICE,
            choices=["table", "json", "xml"],
            default_value="table",
            help_text="Format for command injection scan results"
        ),
        Parameter(
            name="verbose",
            short_name="v",
            description="Enable verbose output with detailed information",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Shows detailed command injection testing and payload information"
        )
    ],
    
    examples=[
        Example(
            title="Basic Command Injection Scan",
            description="Scan URL for command injection vulnerabilities",
            command="spectra -cmd https://webapp.com/exec.php?cmd=ls",
            level=ExampleLevel.BASIC,
            category="Basic Usage",
            expected_output="Command injection vulnerability scan results",
            notes=[
                "Tests all detection methods",
                "Auto-detects target platform"
            ]
        ),
        Example(
            title="Time-Based Detection",
            description="Use time-based detection for command injection",
            command="spectra -cmd https://api.com/system?command=ping --detection-method time-based --time-delay 10",
            level=ExampleLevel.INTERMEDIATE,
            category="Time-Based Detection",
            expected_output="Time-based command injection test results",
            notes=[
                "Uses 10-second delay for confirmation",
                "Effective for blind command injection"
            ]
        ),
        Example(
            title="Platform-Specific Testing",
            description="Test command injection with Windows-specific payloads",
            command="spectra -cmd https://winapp.com/run.asp?exe=calc --platform windows --encoding",
            level=ExampleLevel.INTERMEDIATE,
            category="Platform-Specific",
            expected_output="Windows command injection test results",
            notes=[
                "Uses Windows-specific command payloads",
                "Includes encoding bypass techniques"
            ]
        ),
        Example(
            title="Blind Command Injection",
            description="Detect blind command injection using OAST",
            command="spectra -cmd https://app.com/exec -p command --detection-method blind --collaborator-url http://your-server.com --verbose",
            level=ExampleLevel.ADVANCED,
            category="Blind Detection",
            expected_output="Blind command injection detection with OAST interactions",
            notes=[
                "Requires external server for interaction detection",
                "Can detect injection without visible output",
                "Verbose mode shows detailed analysis"
            ]
        )
    ],
    
    use_cases=[
        UseCase(
            title="Web Application Security Testing",
            description="Test web applications for command injection vulnerabilities",
            scenario="During security assessments of applications with system interaction",
            steps=[
                "Identify parameters that might execute commands",
                "Test various command injection techniques",
                "Verify command execution and system access",
                "Document vulnerable parameters and impact"
            ],
            related_examples=["Basic Command Injection Scan", "Platform-Specific Testing"]
        ),
        UseCase(
            title="API Security Assessment",
            description="Assess APIs for command injection vulnerabilities",
            scenario="When testing APIs that interact with system commands",
            steps=[
                "Map API endpoints that accept command-like parameters",
                "Test blind command injection with OAST",
                "Verify system command execution",
                "Generate security recommendations"
            ],
            related_examples=["Time-Based Detection", "Blind Command Injection"]
        )
    ],
    
    related_modules=[
        "sql_injection_scanner",
        "xss_scanner",
        "vulnerability_scanner"
    ],
    
    tags=[
        "command injection",
        "system command execution",
        "blind command injection",
        "time-based detection",
        "os command injection"
    ]
)