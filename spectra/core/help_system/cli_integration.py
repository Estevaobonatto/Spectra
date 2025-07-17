# -*- coding: utf-8 -*-
"""
CLI Integration for Spectra Help System
"""

import sys
from typing import List, Optional

from .help_manager import get_help_manager, HelpManager
from .help_formatter import OutputFormat
from ..logger import get_logger

logger = get_logger(__name__)


class HelpCLIHandler:
    """Handles CLI integration for the help system"""
    
    def __init__(self):
        self.help_manager = get_help_manager()
        
    def handle_help_request(self, args: List[str]) -> bool:
        """
        Handle help requests from CLI
        
        Args:
            args: Command line arguments
            
        Returns:
            True if help was handled, False otherwise
        """
        try:
            # Check for general help
            if not args or args[0] in ['--help', '-h', 'help']:
                if len(args) <= 1:
                    # General help
                    help_text = self.help_manager.get_general_help()
                    print(help_text)
                    return True
                else:
                    # Module-specific help
                    module_name = args[1]
                    help_text = self.help_manager.get_module_help(module_name)
                    print(help_text)
                    return True
            
            # Check for search
            elif args[0] in ['--search', 'search']:
                if len(args) > 1:
                    query = ' '.join(args[1:])
                    help_text = self.help_manager.search_help(query)
                    print(help_text)
                    return True
                else:
                    print("Please provide a search query.")
                    return True
            
            # Check for category help
            elif args[0] in ['--category', 'category']:
                if len(args) > 1:
                    category = args[1]
                    help_text = self.help_manager.get_category_help(category)
                    print(help_text)
                    return True
                else:
                    categories = self.help_manager.get_available_categories()
                    print("Available categories:")
                    for cat in categories:
                        print(f"  - {cat}")
                    return True
            
            # Check for module list
            elif args[0] in ['--list-modules', 'list-modules']:
                modules = self.help_manager.get_available_modules()
                print("Available modules:")
                for module in sorted(modules):
                    print(f"  - {module}")
                return True
            
            # Check for JSON output
            elif args[0] in ['--help-json']:
                if len(args) > 1:
                    module_name = args[1]
                    help_text = self.help_manager.get_module_help(module_name, OutputFormat.JSON)
                    print(help_text)
                else:
                    help_text = self.help_manager.get_general_help(OutputFormat.JSON)
                    print(help_text)
                return True
            
            # Check for validation
            elif args[0] in ['--validate-help']:
                validation_result = self.help_manager.validate_all_modules()
                self._print_validation_result(validation_result)
                return True
            
            # Check for statistics
            elif args[0] in ['--help-stats']:
                stats = self.help_manager.get_statistics()
                self._print_statistics(stats)
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error handling help request: {e}")
            print(f"Error displaying help: {e}")
            return True
    
    def get_module_by_cli_command(self, cli_command: str) -> Optional[str]:
        """
        Get module name by CLI command
        
        Args:
            cli_command: CLI command (e.g., '-ps', '--port-scan')
            
        Returns:
            Module name or None if not found
        """
        try:
            metadata = self.help_manager.get_module_by_cli_command(cli_command)
            return metadata.name if metadata else None
        except Exception as e:
            logger.error(f"Error getting module by CLI command '{cli_command}': {e}")
            return None
    
    def get_quick_help(self, module_name: str) -> str:
        """
        Get quick help for a module
        
        Args:
            module_name: Name of the module
            
        Returns:
            Quick help string
        """
        try:
            return self.help_manager.get_quick_help(module_name)
        except Exception as e:
            logger.error(f"Error getting quick help for '{module_name}': {e}")
            return f"Error getting help for '{module_name}': {e}"
    
    def suggest_similar_commands(self, invalid_command: str) -> List[str]:
        """
        Suggest similar commands for invalid input
        
        Args:
            invalid_command: The invalid command
            
        Returns:
            List of suggested commands
        """
        try:
            # Try to find module suggestions
            registry = self.help_manager.registry
            suggestions = registry.get_module_suggestions(invalid_command)
            
            # Also check CLI commands
            cli_commands = registry.get_cli_command_mapping()
            cli_suggestions = []
            
            for cli_cmd in cli_commands.keys():
                if invalid_command.lower() in cli_cmd.lower():
                    cli_suggestions.append(cli_cmd)
            
            # Combine and limit suggestions
            all_suggestions = suggestions + cli_suggestions
            return list(set(all_suggestions))[:5]
            
        except Exception as e:
            logger.error(f"Error getting suggestions for '{invalid_command}': {e}")
            return []
    
    def _print_validation_result(self, validation_result: dict):
        """Print validation results in a readable format"""
        print("Help System Validation Results")
        print("=" * 40)
        print(f"Status: {validation_result['status']}")
        print(f"Total Modules: {validation_result['total_modules']}")
        print(f"Valid Modules: {validation_result['valid_modules']}")
        print(f"Invalid Modules: {validation_result['invalid_modules']}")
        
        if validation_result['issues']:
            print("\nIssues Found:")
            for issue in validation_result['issues']:
                print(f"\nModule: {issue['module']}")
                print(f"Valid: {issue['valid']}")
                
                if issue['errors']:
                    print("Errors:")
                    for error in issue['errors']:
                        print(f"  - {error}")
                
                if issue['warnings']:
                    print("Warnings:")
                    for warning in issue['warnings']:
                        print(f"  - {warning}")
    
    def _print_statistics(self, stats: dict):
        """Print help system statistics"""
        print("Help System Statistics")
        print("=" * 30)
        
        if 'registry' in stats:
            registry_stats = stats['registry']
            print(f"Total Modules: {registry_stats.get('total_modules', 0)}")
            print(f"Total Categories: {registry_stats.get('total_categories', 0)}")
            print(f"Total CLI Commands: {registry_stats.get('total_cli_commands', 0)}")
            print(f"Total Tags: {registry_stats.get('total_tags', 0)}")
            
            # Per-category counts
            categories = [
                'reconnaissance_modules',
                'security_analysis_modules', 
                'vulnerability_detection_modules',
                'cryptography_modules',
                'monitoring_modules',
                'integration_modules'
            ]
            
            print("\nModules by Category:")
            for cat in categories:
                if cat in registry_stats:
                    cat_name = cat.replace('_modules', '').replace('_', ' ').title()
                    print(f"  {cat_name}: {registry_stats[cat]}")
        
        if 'cache' in stats:
            cache_stats = stats['cache']
            print(f"\nCache Enabled: {cache_stats.get('enabled', False)}")
            print(f"Cache Entries: {cache_stats.get('entries', 0)}")


def integrate_help_with_cli():
    """
    Main function to integrate help system with CLI
    This should be called from the main CLI module
    """
    try:
        # Initialize help system
        help_manager = get_help_manager()
        
        # Ensure registry is initialized
        if not help_manager.registry.is_initialized():
            help_manager.registry.initialize()
        
        logger.info("Help system integrated with CLI")
        return True
        
    except Exception as e:
        logger.error(f"Failed to integrate help system with CLI: {e}")
        return False


def handle_cli_help(args: List[str]) -> bool:
    """
    Convenience function to handle CLI help requests
    
    Args:
        args: Command line arguments
        
    Returns:
        True if help was handled, False otherwise
    """
    handler = HelpCLIHandler()
    return handler.handle_help_request(args)


def get_module_help_for_cli(module_name: str, format_type: str = "text") -> str:
    """
    Get module help for CLI display
    
    Args:
        module_name: Name of the module
        format_type: Output format (text, json)
        
    Returns:
        Formatted help string
    """
    try:
        help_manager = get_help_manager()
        output_format = OutputFormat.JSON if format_type.lower() == "json" else OutputFormat.TEXT
        return help_manager.get_module_help(module_name, output_format)
    except Exception as e:
        logger.error(f"Error getting module help for CLI: {e}")
        return f"Error getting help for '{module_name}': {e}"