# -*- coding: utf-8 -*-
"""
CLI Integration for Spectra Help System
"""

import sys
import argparse
from typing import List, Optional

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