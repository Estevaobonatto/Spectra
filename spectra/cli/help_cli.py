# -*- coding: utf-8 -*-
"""
CLI Integration for Spectra Help System
"""

import sys
import argparse
from typing import List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.columns import Columns
from rich.text import Text
from rich.rule import Rule
from rich.padding import Padding
from rich import box

from ..core.help_system import get_help_manager, initialize_help_system
from ..core.help_system.help_formatter import OutputFormat
from ..core.logger import get_logger

logger = get_logger(__name__)


class HelpCLI:
    """CLI interface for the help system"""
    
    def __init__(self):
        self.help_manager = get_help_manager()
        self.initialized = False
    
    def ensure_initialized(self):
        """Ensure help system is initialized"""
        if not self.initialized:
            try:
                init_report = initialize_help_system()
                if init_report['status'] == 'error':
                    logger.error(f"Help system initialization failed: {init_report['message']}")
                    print(f"Warning: {init_report['message']}")
                else:
                    logger.info(f"Help system initialized: {init_report['message']}")
                self.initialized = True
            except Exception as e:
                logger.error(f"Failed to initialize help system: {e}")
                print(f"Warning: Help system initialization failed: {e}")
    
    def handle_help_command(self, args: List[str]) -> int:
        """
        Handle help command from CLI
        
        Args:
            args: Command line arguments
            
        Returns:
            Exit code (0 for success, 1 for error)
        """
        try:
            self.ensure_initialized()
            
            # Parse help arguments
            parser = self._create_help_parser()
            
            try:
                parsed_args = parser.parse_args(args)
            except SystemExit as e:
                return e.code if e.code is not None else 1
            
            # Handle different help commands
            if parsed_args.command == 'general':
                return self._show_general_help(parsed_args)
            elif parsed_args.command == 'module':
                return self._show_module_help(parsed_args)
            elif parsed_args.command == 'search':
                return self._show_search_results(parsed_args)
            elif parsed_args.command == 'category':
                return self._show_category_help(parsed_args)
            elif parsed_args.command == 'validate':
                return self._validate_modules(parsed_args)
            elif parsed_args.command == 'stats':
                return self._show_statistics(parsed_args)
            else:
                return self._show_general_help(parsed_args)
                
        except Exception as e:
            logger.error(f"Help command failed: {e}")
            print(f"Error: {e}")
            return 1
    
    def _create_help_parser(self) -> argparse.ArgumentParser:
        """Create argument parser for help commands"""
        parser = argparse.ArgumentParser(
            prog='spectra --help',
            description='Spectra Help System',
            add_help=False
        )
        
        subparsers = parser.add_subparsers(dest='command', help='Help commands')
        
        # General help
        general_parser = subparsers.add_parser('general', help='Show general help')
        general_parser.add_argument('--format', choices=['text', 'json', 'html', 'markdown'], 
                                  default='text', help='Output format')
        
        # Module help
        module_parser = subparsers.add_parser('module', help='Show module help')
        module_parser.add_argument('module_name', help='Module name or CLI command')
        module_parser.add_argument('--format', choices=['text', 'json', 'html', 'markdown'], 
                                 default='text', help='Output format')
        module_parser.add_argument('--examples-only', action='store_true', 
                                 help='Show only examples')
        module_parser.add_argument('--level', choices=['basic', 'intermediate', 'advanced'],
                                 help='Filter examples by level')
        
        # Search
        search_parser = subparsers.add_parser('search', help='Search modules')
        search_parser.add_argument('query', help='Search query')
        search_parser.add_argument('--format', choices=['text', 'json'], 
                                 default='text', help='Output format')
        search_parser.add_argument('--limit', type=int, default=10, 
                                 help='Maximum results')
        
        # Category help
        category_parser = subparsers.add_parser('category', help='Show category help')
        category_parser.add_argument('category_name', help='Category name')
        category_parser.add_argument('--format', choices=['text', 'json'], 
                                   default='text', help='Output format')
        
        # Validation
        validate_parser = subparsers.add_parser('validate', help='Validate modules')
        validate_parser.add_argument('--format', choices=['text', 'json'], 
                                   default='text', help='Output format')
        
        # Statistics
        stats_parser = subparsers.add_parser('stats', help='Show help system statistics')
        stats_parser.add_argument('--format', choices=['text', 'json'], 
                                default='text', help='Output format')
        
        return parser
    
    def _show_general_help(self, args) -> int:
        """Show general help"""
        try:
            format_type = OutputFormat(args.format)
            help_text = self.help_manager.get_general_help(format_type)
            print(help_text)
            return 0
        except Exception as e:
            print(f"Error generating general help: {e}")
            return 1
    
    def _show_module_help(self, args) -> int:
        """Show module-specific help"""
        try:
            if args.examples_only:
                examples = self.help_manager.get_module_examples(
                    args.module_name, args.level
                )
                if not examples:
                    print(f"No examples found for module '{args.module_name}'")
                    return 1
                
                print(f"Examples for {args.module_name}:")
                print("=" * 50)
                for example in examples:
                    print(f"\n{example['title']} ({example['level']}):")
                    print(f"  {example['description']}")
                    print(f"  Command: {example['command']}")
                    if example['notes']:
                        print(f"  Notes: {', '.join(example['notes'])}")
            else:
                format_type = OutputFormat(args.format)
                help_text = self.help_manager.get_module_help(args.module_name, format_type)
                print(help_text)
            
            return 0
        except Exception as e:
            print(f"Error generating module help: {e}")
            return 1
    
    def _show_search_results(self, args) -> int:
        """Show search results"""
        try:
            format_type = OutputFormat(args.format)
            results = self.help_manager.search_help(args.query, format_type, args.limit)
            print(results)
            return 0
        except Exception as e:
            print(f"Error searching modules: {e}")
            return 1
    
    def _show_category_help(self, args) -> int:
        """Show category help"""
        try:
            format_type = OutputFormat(args.format)
            help_text = self.help_manager.get_category_help(args.category_name, format_type)
            print(help_text)
            return 0
        except Exception as e:
            print(f"Error generating category help: {e}")
            return 1
    
    def _validate_modules(self, args) -> int:
        """Validate all modules"""
        try:
            report = self.help_manager.validate_all_modules()
            
            if args.format == 'json':
                import json
                print(json.dumps(report, indent=2))
            else:
                print("Module Validation Report")
                print("=" * 50)
                print(f"Status: {report['status']}")
                print(f"Total modules: {report['total_modules']}")
                print(f"Valid modules: {report['valid_modules']}")
                print(f"Invalid modules: {report['invalid_modules']}")
                
                if report['issues']:
                    print("\nIssues found:")
                    for issue in report['issues']:
                        print(f"\nModule: {issue['module']}")
                        print(f"  Valid: {issue['valid']}")
                        if issue['errors']:
                            print(f"  Errors: {', '.join(issue['errors'])}")
                        if issue['warnings']:
                            print(f"  Warnings: {', '.join(issue['warnings'])}")
            
            return 0 if report['status'] == 'success' else 1
        except Exception as e:
            print(f"Error validating modules: {e}")
            return 1
    
    def _show_statistics(self, args) -> int:
        """Show help system statistics"""
        try:
            stats = self.help_manager.get_statistics()
            
            if args.format == 'json':
                import json
                print(json.dumps(stats, indent=2))
            else:
                print("Help System Statistics")
                print("=" * 50)
                
                if 'registry' in stats:
                    reg_stats = stats['registry']
                    print(f"Total modules: {reg_stats.get('total_modules', 0)}")
                    print(f"CLI commands: {reg_stats.get('cli_commands', 0)}")
                    print(f"Total parameters: {reg_stats.get('total_parameters', 0)}")
                    print(f"Total examples: {reg_stats.get('total_examples', 0)}")
                    
                    if 'categories' in reg_stats:
                        print("\nModules by category:")
                        for category, count in reg_stats['categories'].items():
                            print(f"  {category.replace('_', ' ').title()}: {count}")
                
                if 'cache' in stats:
                    cache_stats = stats['cache']
                    print(f"\nCache enabled: {cache_stats.get('enabled', False)}")
                    print(f"Cache entries: {cache_stats.get('entries', 0)}")
            
            return 0
        except Exception as e:
            print(f"Error getting statistics: {e}")
            return 1
    
    def handle_quick_help(self, module_name: str) -> int:
        """
        Handle quick help for a module
        
        Args:
            module_name: Module name or CLI command
            
        Returns:
            Exit code
        """
        try:
            self.ensure_initialized()
            help_text = self.help_manager.get_quick_help(module_name)
            print(help_text)
            return 0
        except Exception as e:
            print(f"Error getting quick help: {e}")
            return 1
    
    def suggest_modules(self, partial_name: str) -> List[str]:
        """
        Suggest module names based on partial input
        
        Args:
            partial_name: Partial module name
            
        Returns:
            List of suggestions
        """
        try:
            self.ensure_initialized()
            return self.help_manager.registry.get_module_suggestions(partial_name)
        except Exception as e:
            logger.error(f"Error getting suggestions: {e}")
            return []


def show_rich_help() -> None:
    """Displays a modern Rich-formatted help screen organized by category."""
    _con = Console()

    # ── Header ──────────────────────────────────────────────────────────────
    header = Text(justify="center")
    header.append("SPECTRA", style="bold white")
    header.append("  v3.4.0", style="bold cyan")
    header.append("\n")
    header.append("Web Security Suite · Ethical Hacking Toolkit", style="dim white")
    header.append("\n")
    header.append("Usage: ", style="dim")
    header.append("spectra", style="bold cyan")
    header.append(" <command> [options]", style="white")
    _con.print(Panel(header, border_style="cyan", padding=(0, 4)))

    # ── Helper to build command tables ──────────────────────────────────────
    def _table(title: str, color: str, rows: list[tuple[str, str, str]]) -> Table:
        t = Table(
            title=title,
            title_style=f"bold {color}",
            box=box.SIMPLE_HEAD,
            border_style="dim",
            show_header=True,
            header_style="bold dim",
            padding=(0, 1),
            expand=True,
        )
        t.add_column("Command", style=color, no_wrap=True, min_width=22)
        t.add_column("Description", style="white")
        t.add_column("Key option", style="dim cyan", no_wrap=True)
        for cmd, desc, opt in rows:
            t.add_row(cmd, desc, opt)
        return t

    # ── Recon ────────────────────────────────────────────────────────────────
    recon = _table("RECON & ENUMERATION", "green", [
        ("-ps  <target>",     "Port scan + OS fingerprinting",           "--top-ports / --scan-type"),
        ("-ds  <url>",        "Directory bruteforce (Dirsearch-level)",   "--recursive --stealth"),
        ("-ss  <domain>",     "Subdomain enum (passive + active)",        "--advanced --passive-only"),
        ("-dns <domain>",     "DNS analysis — DNSSEC / DMARC / AXFR",    "--record-type"),
        ("-whois <domain>",   "WHOIS + threat-intel",                     "--threat-intel"),
        ("-bg  <host> <port>","Banner grabbing (29 protocol probes)",     "--banner-ports"),
        ("-nm",               "Network monitor (Wireshark-like TUI)",     "--network-interface"),
    ])

    # ── Web Vulns ────────────────────────────────────────────────────────────
    vulns = _table("WEB VULNERABILITIES", "red", [
        ("-sqli <url>",  "SQL Injection — UNION / Blind / OOB",     "--sqli-level --sqli-oast"),
        ("-xss  <url>",  "XSS — reflected / stored / DOM / mXSS",   "--xss-dom --xss-oast"),
        ("-cmdi <url>",  "Command Injection — timing / OOB DNS",     "--cmdi-level --cmdi-oast"),
        ("-lfi  <url>",  "LFI + PHP filter chain + log poison",      "--lfi-depth"),
        ("-xxe  <url>",  "XXE + Blind OOB via collaborator",         "--xxe-collaborator"),
        ("-idor <url>",  "IDOR + JWT sub/id manipulation",           "--idor-range --test-uuid"),
        ("-bvs  <url>",  "Basic Vulnerability Scanner",              "--bvs-workers"),
    ])

    # ── Analysis ─────────────────────────────────────────────────────────────
    analysis = _table("SECURITY ANALYSIS", "yellow", [
        ("-waf     <url>",  "WAF detection + bypass strategies",    "--test-bypasses"),
        ("-ssl     <host>", "TLS / OCSP / Certificate Transparency",""),
        ("-headers <url>",  "HTTP headers — CSP / CORS / HSTS",     ""),
        ("-tech    <url>",  "Technology detection (500+ techs)",     "--tech-deep --tech-quick"),
        ("-md      <url>",  "Metadata extraction (EXIF/XMP)",        ""),
        ("-hc      <hash>", "Hash cracker — 27 algos / 11 modes",   "--attack-mode --use-gpu"),
    ])

    # ── CVE ──────────────────────────────────────────────────────────────────
    cve = _table("CVE & INTELLIGENCE", "magenta", [
        ("--cve-search  <kw>", "Search NVD CVE database",         ""),
        ("--cve-details <id>", "Full CVE details + CVSS vectors",  ""),
        ("--cve-epss    <id>", "EPSS exploitability probability",  ""),
        ("--cve-kev     <id>", "CISA Known Exploited Vulns check", ""),
        ("--trending-cves N",  "Recent high-severity CVEs",        ""),
    ])

    # ── Render two-column grid ────────────────────────────────────────────────
    _con.print(Columns([recon, vulns], equal=True, expand=True))
    _con.print(Columns([analysis, cve], equal=True, expand=True))

    # ── Global flags ─────────────────────────────────────────────────────────
    flags_t = Table(box=box.SIMPLE_HEAD, show_header=True, padding=(0, 2), expand=True,
                    header_style="bold dim")
    flags_t.add_column("Flag", style="cyan", no_wrap=True, min_width=28)
    flags_t.add_column("Description", style="white")
    flags_t.add_row("--timeout <s>",          "Request timeout in seconds (default: 1.0)")
    flags_t.add_row("--workers <n>",           "Thread count (default: auto-tuned by scanner)")
    flags_t.add_row("--verbose / -v",          "Verbose output with debug details")
    flags_t.add_row("--no-banner",             "Skip banner and legal warning display")
    flags_t.add_row("--generate-report <fmt>", "Export report: json | xml | html | all")
    flags_t.add_row("--output-format <fmt>",   "Display format: table | json | xml")
    flags_t.add_row("--help-module <name>",    "Show detailed help for a specific module")
    _con.print(Panel(flags_t, title="[dim]GLOBAL FLAGS[/dim]", border_style="dim", padding=(0, 1)))

    # ── Quick examples ────────────────────────────────────────────────────────
    ex = Text()
    ex.append("  spectra ", style="bold cyan"); ex.append("-ps example.com ", style="white"); ex.append("-p 1-65535 --top-ports 1000\n", style="dim")
    ex.append("  spectra ", style="bold cyan"); ex.append("-ds https://site.com ", style="white"); ex.append("-w common.txt --recursive --stealth --workers 50\n", style="dim")
    ex.append("  spectra ", style="bold cyan"); ex.append("-sqli http://site.com/page?id=1 ", style="white"); ex.append("--sqli-level 2 --sqli-oast http://oast.pro\n", style="dim")
    ex.append("  spectra ", style="bold cyan"); ex.append("-xss http://app.com/search ", style="white"); ex.append("--xss-dom --xss-oast http://oast.pro\n", style="dim")
    ex.append("  spectra ", style="bold cyan"); ex.append("-ssl example.com ", style="white"); ex.append("--verbose\n", style="dim")
    ex.append("  spectra ", style="bold cyan"); ex.append("--cve-kev ", style="white"); ex.append("CVE-2021-44228 ", style="dim"); ex.append("· "); ex.append("spectra ", style="bold cyan"); ex.append("--cve-epss CVE-2024-3094", style="dim")
    _con.print(Panel(ex, title="[dim]QUICK EXAMPLES[/dim]", border_style="dim", padding=(0, 0)))

    _con.print(
        "[dim]  Full docs:[/dim] [cyan]spectra --help-module <name>[/cyan]"
        "  [dim]·  Report issues:[/dim] [cyan]github.com/spectra[/cyan]\n"
    )


# Global CLI instance
_global_help_cli = None


def get_help_cli() -> HelpCLI:
    """Get the global help CLI instance"""
    global _global_help_cli
    if _global_help_cli is None:
        _global_help_cli = HelpCLI()
    return _global_help_cli


def handle_help_request(args: List[str]) -> int:
    """
    Handle help request from main CLI
    
    Args:
        args: Command line arguments
        
    Returns:
        Exit code
    """
    cli = get_help_cli()
    return cli.handle_help_command(args)


def show_quick_help(module_name: str) -> int:
    """
    Show quick help for a module
    
    Args:
        module_name: Module name or CLI command
        
    Returns:
        Exit code
    """
    cli = get_help_cli()
    return cli.handle_quick_help(module_name)


def get_module_suggestions(partial_name: str) -> List[str]:
    """
    Get module name suggestions
    
    Args:
        partial_name: Partial module name
        
    Returns:
        List of suggestions
    """
    cli = get_help_cli()
    return cli.suggest_modules(partial_name)