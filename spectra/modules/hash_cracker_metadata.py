# -*- coding: utf-8 -*-
"""
Hash Cracker Module Metadata for Spectra Help System
"""

from ..core.module_metadata import (
    ModuleMetadata, Parameter, Example, UseCase, 
    ModuleCategory, ParameterType, ExampleLevel
)

# Hash Cracker Module Metadata
METADATA = ModuleMetadata(
    name="hash_cracker",
    display_name="Hash Cracker",
    category=ModuleCategory.CRYPTOGRAPHY,
    description="Advanced hash cracking with 27+ algorithms, 11 attack modes, and GPU acceleration",
    detailed_description="""
    The Hash Cracker module provides comprehensive hash cracking capabilities inspired by HashCat 
    and John the Ripper. Supports 27+ hash algorithms including MD5, SHA family, NTLM, bcrypt, 
    Argon2, and more. Features 11 attack modes including dictionary, brute force, mask attacks, 
    rainbow tables, and hybrid approaches. Includes GPU acceleration support for NVIDIA CUDA 
    and OpenCL, intelligent performance optimization, and real-time statistics.
    """,
    version="3.3.0",
    author="Spectra Team",
    cli_command="-hc",
    cli_aliases=["--hash-crack"],
    
    parameters=[
        Parameter(
            name="hash",
            description="Hash value to crack",
            param_type=ParameterType.STRING,
            required=True,
            examples=[
                "5d41402abc4b2a76b9719d911017c592",  # MD5
                "356a192b7913b04c54574d18c28d46e6395428ab",  # SHA1
                "F054A2BB"  # CRC32
            ],
            help_text="Supports hex-encoded hash values for all supported algorithms"
        ),
        Parameter(
            name="hash-type",
            description="Hash algorithm type",
            param_type=ParameterType.CHOICE,
            choices=[
                "md5", "sha1", "sha224", "sha256", "sha384", "sha512", "md4", "ntlm", "lm",
                "blake2b", "blake2s", "sha3_224", "sha3_256", "sha3_384", "sha3_512",
                "ripemd160", "whirlpool", "adler32", "crc32", "xxhash32", "xxhash64",
                "bcrypt", "argon2", "scrypt", "pbkdf2", "md5crypt", "sha256crypt", "sha512crypt", "auto"
            ],
            default_value="auto",
            help_text="Auto-detection analyzes hash length and format patterns"
        ),
        Parameter(
            name="attack-mode",
            description="Hash cracking attack mode",
            param_type=ParameterType.CHOICE,
            choices=[
                "dictionary", "brute_force", "mask", "rainbow", "hybrid", "combinator",
                "toggle_case", "increment", "prince", "online", "all"
            ],
            default_value="dictionary",
            help_text="Different modes optimize for speed vs coverage trade-offs"
        ),
        Parameter(
            name="hash-wordlist",
            description="Wordlist file for dictionary attacks",
            param_type=ParameterType.FILE_PATH,
            examples=["rockyou.txt", "common-passwords.txt", "/usr/share/wordlists/rockyou.txt"],
            help_text="Uses built-in wordlist if not specified"
        ),
        Parameter(
            name="hash-rules",
            description="Password transformation rules",
            param_type=ParameterType.STRING,
            examples=["uppercase,digits,leet", "years,reverse", "uppercase,digits,special"],
            help_text="Comma-separated list: uppercase, digits, leet, years, reverse, special"
        ),
        Parameter(
            name="min-length",
            description="Minimum password length for brute force",
            param_type=ParameterType.INTEGER,
            default_value=1,
            min_value=1,
            max_value=20,
            examples=["4", "6", "8"],
            help_text="Lower values are faster but may miss longer passwords"
        ),
        Parameter(
            name="max-length",
            description="Maximum password length for brute force",
            param_type=ParameterType.INTEGER,
            default_value=6,
            min_value=1,
            max_value=20,
            examples=["8", "10", "12"],
            help_text="Higher values are more thorough but exponentially slower"
        ),
        Parameter(
            name="charset",
            description="Character set for brute force attacks",
            param_type=ParameterType.STRING,
            default_value="abcdefghijklmnopqrstuvwxyz0123456789",
            examples=[
                "abcdefghijklmnopqrstuvwxyz",  # lowercase
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",  # upper + digits
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"  # full
            ],
            help_text="Customize character set based on password policy knowledge"
        ),
        Parameter(
            name="mask-pattern",
            description="Mask pattern for mask attacks (HashCat style)",
            param_type=ParameterType.STRING,
            examples=[
                "?l?l?l?l",  # 4 lowercase letters
                "?u?l?l?l?d?d",  # Upper + 3 lower + 2 digits
                "?l?l?l?l?d?d?d?d"  # 4 letters + 4 digits
            ],
            help_text="?l=lower, ?u=upper, ?d=digits, ?s=special, ?a=all"
        ),
        Parameter(
            name="hash-performance",
            description="Performance optimization mode",
            param_type=ParameterType.CHOICE,
            choices=["balanced", "fast", "extreme"],
            default_value="balanced",
            help_text="balanced: default, fast: optimized threading, extreme: maximum resources"
        ),
        Parameter(
            name="workers",
            description="Number of cracking threads",
            param_type=ParameterType.INTEGER,
            default_value=0,  # Auto-detect
            min_value=1,
            max_value=500,
            examples=["50", "100", "200"],
            help_text="0 = auto-detect based on CPU cores and performance mode"
        ),
        Parameter(
            name="use-gpu",
            description="Enable GPU acceleration",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Requires NVIDIA CUDA or OpenCL support for 50-1000x speedup"
        ),
        Parameter(
            name="no-gpu",
            description="Force CPU-only processing",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Disable GPU even if available"
        ),
        Parameter(
            name="gpu-info",
            description="Display GPU information and capabilities",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Shows available GPUs, memory, and compute capability"
        ),
        Parameter(
            name="show-hash-stats",
            description="Display detailed cracking statistics",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Shows attempts/sec, progress, ETA, and performance metrics"
        ),
        Parameter(
            name="show-performance-estimate",
            description="Show performance estimates before starting",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Estimates completion time based on keyspace and hardware"
        ),
        Parameter(
            name="rainbow-table",
            description="Rainbow table file for instant lookups",
            param_type=ParameterType.FILE_PATH,
            examples=["md5_1_6_36chars.rt", "sha1_common.rt"],
            help_text="Pre-computed tables for O(1) hash lookups"
        ),
        Parameter(
            name="rainbow-generate",
            description="Generate new rainbow table",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Creates rainbow table for future use"
        ),
        Parameter(
            name="rainbow-charset",
            description="Character set for rainbow table generation",
            param_type=ParameterType.STRING,
            examples=["abc123", "abcdefghijklmnopqrstuvwxyz0123456789"],
            help_text="Defines keyspace for rainbow table coverage"
        ),
        Parameter(
            name="rainbow-max-length",
            description="Maximum password length for rainbow tables",
            param_type=ParameterType.INTEGER,
            default_value=8,
            min_value=1,
            max_value=12,
            examples=["6", "8", "10"],
            help_text="Longer lengths create larger tables but better coverage"
        ),
        Parameter(
            name="verbose",
            short_name="v",
            description="Enable verbose output with detailed progress",
            param_type=ParameterType.BOOLEAN,
            default_value=False,
            help_text="Shows algorithm detection, performance stats, and progress details"
        )
    ],
    
    examples=[
        Example(
            title="Basic Hash Cracking",
            description="Crack a simple MD5 hash using dictionary attack",
            command="spectra -hc 5d41402abc4b2a76b9719d911017c592",
            level=ExampleLevel.BASIC,
            category="Dictionary Attack",
            expected_output="Password found: hello",
            notes=[
                "Auto-detects MD5 hash type",
                "Uses built-in common password dictionary",
                "Fast for common passwords"
            ]
        ),
        Example(
            title="Specific Hash Type",
            description="Crack SHA1 hash with explicit type specification",
            command="spectra -hc 356a192b7913b04c54574d18c28d46e6395428ab --hash-type sha1",
            level=ExampleLevel.BASIC,
            category="Hash Types",
            expected_output="Password found: a",
            notes=[
                "Explicitly specifies SHA1 algorithm",
                "Useful when auto-detection is uncertain",
                "Slightly faster than auto-detection"
            ]
        ),
        Example(
            title="Custom Wordlist Attack",
            description="Use custom wordlist for targeted dictionary attack",
            command="spectra -hc 098f6bcd4621d373cade4e832627b4f6 --hash-wordlist rockyou.txt",
            level=ExampleLevel.BASIC,
            category="Dictionary Attack",
            expected_output="Password found from custom wordlist",
            notes=[
                "Uses popular rockyou.txt wordlist",
                "Better coverage than built-in dictionary",
                "Recommended for serious cracking attempts"
            ]
        ),
        Example(
            title="Brute Force Attack",
            description="Brute force short passwords with custom charset",
            command="spectra -hc F054A2BB --hash-type crc32 --attack-mode brute_force --max-length 4 --charset abc123",
            level=ExampleLevel.INTERMEDIATE,
            category="Brute Force",
            expected_output="Password found through brute force",
            notes=[
                "Limited charset reduces search space",
                "CRC32 is very fast to compute",
                "Good for short, simple passwords"
            ]
        ),
        Example(
            title="Mask Attack",
            description="Use mask pattern for structured password cracking",
            command="spectra -hc 098f6bcd4621d373cade4e832627b4f6 --attack-mode mask --mask-pattern \"?l?l?l?l?d?d\"",
            level=ExampleLevel.INTERMEDIATE,
            category="Mask Attack",
            expected_output="Password matching pattern found",
            notes=[
                "Pattern: 4 lowercase letters + 2 digits",
                "More efficient than full brute force",
                "Good when password format is known"
            ]
        ),
        Example(
            title="GPU Accelerated Cracking",
            description="Use GPU acceleration for maximum performance",
            command="spectra -hc 5d41402abc4b2a76b9719d911017c592 --use-gpu --attack-mode dictionary --hash-wordlist huge.txt",
            level=ExampleLevel.ADVANCED,
            category="GPU Acceleration",
            expected_output="GPU-accelerated cracking with performance stats",
            notes=[
                "Requires NVIDIA GPU with CUDA support",
                "50-1000x faster than CPU-only",
                "Ideal for large wordlists and complex hashes"
            ]
        ),
        Example(
            title="Rainbow Table Lookup",
            description="Instant hash lookup using pre-computed rainbow tables",
            command="spectra -hc 5d41402abc4b2a76b9719d911017c592 --attack-mode rainbow --rainbow-table md5_1_6_36chars.rt",
            level=ExampleLevel.ADVANCED,
            category="Rainbow Tables",
            expected_output="Instant password lookup: hello",
            notes=[
                "O(1) lookup time for covered passwords",
                "Requires pre-computed rainbow tables",
                "Trade storage space for computation time"
            ]
        ),
        Example(
            title="Comprehensive Attack",
            description="Try all attack modes for maximum success rate",
            command="spectra -hc ad0234829205b9033196ba818f7a872b --attack-mode all --hash-performance extreme --show-hash-stats",
            level=ExampleLevel.ADVANCED,
            category="Comprehensive",
            expected_output="Password found using optimal attack method",
            notes=[
                "Tries dictionary, brute force, mask, and other attacks",
                "Uses maximum performance settings",
                "Shows detailed statistics and progress"
            ]
        ),
        Example(
            title="Advanced Hash Types",
            description="Crack modern secure hash with GPU acceleration",
            command="spectra -hc \"$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj3QJgLVg2Lu\" --hash-type bcrypt --use-gpu --hash-wordlist passwords.txt",
            level=ExampleLevel.ADVANCED,
            category="Secure Hashes",
            expected_output="bcrypt password cracked with GPU assistance",
            notes=[
                "bcrypt is intentionally slow and secure",
                "GPU acceleration provides significant speedup",
                "May still take considerable time for strong passwords"
            ]
        )
    ],
    
    use_cases=[
        UseCase(
            title="Password Recovery",
            description="Recover forgotten passwords from hash values",
            scenario="When you have hash values but need the original passwords",
            steps=[
                "Identify the hash algorithm using auto-detection",
                "Start with dictionary attack using common passwords",
                "Try rule-based transformations on dictionary words",
                "Use mask attacks if password format is known",
                "Resort to brute force for short, simple passwords"
            ],
            related_examples=["Basic Hash Cracking", "Custom Wordlist Attack", "Mask Attack"]
        ),
        UseCase(
            title="Security Assessment",
            description="Test password strength and policy compliance",
            scenario="During security audits to assess password quality",
            steps=[
                "Collect password hashes from target systems",
                "Use comprehensive wordlists and rule sets",
                "Analyze cracking success rates and patterns",
                "Identify weak passwords and common patterns",
                "Generate recommendations for password policies"
            ],
            related_examples=["Comprehensive Attack", "GPU Accelerated Cracking"]
        ),
        UseCase(
            title="Forensic Investigation",
            description="Recover passwords for digital forensics",
            scenario="During incident response or legal investigations",
            steps=[
                "Extract hashes from seized systems or memory dumps",
                "Use targeted wordlists based on user information",
                "Apply social engineering insights to attack strategies",
                "Document all attempts and results for legal purposes",
                "Maintain chain of custody for evidence"
            ],
            related_examples=["Advanced Hash Types", "Custom Wordlist Attack"]
        ),
        UseCase(
            title="Penetration Testing",
            description="Crack captured hashes during penetration tests",
            scenario="After obtaining password hashes through various attack vectors",
            steps=[
                "Prioritize high-value accounts (admin, service accounts)",
                "Use GPU acceleration for time-limited engagements",
                "Combine multiple attack modes for best coverage",
                "Focus on business-relevant password patterns",
                "Document findings for client reporting"
            ],
            related_examples=["GPU Accelerated Cracking", "Comprehensive Attack"]
        )
    ],
    
    related_modules=[
        "gpu_manager",
        "network_monitor",
        "vulnerability_scanner"
    ],
    
    dependencies=[
        "hashlib",
        "multiprocessing",
        "concurrent.futures",
        "psutil"
    ],
    
    tags=[
        "hash cracking",
        "password recovery",
        "cryptography",
        "gpu acceleration",
        "dictionary attack",
        "brute force",
        "mask attack",
        "rainbow tables",
        "security assessment",
        "forensics"
    ],
    
    documentation_url="https://github.com/spectra-team/spectra/wiki/Hash-Cracker"
)