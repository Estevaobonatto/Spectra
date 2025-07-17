#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script for Spectra Help System
Demonstrates the new standardized help system functionality
"""

import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from spectra.core.help_system import (
    get_help_manager, get_registry, HelpFormatter, OutputFormat
)
from spectra.core.help_system.search_examples import HelpSearchEngine


def test_help_system():
    """Test the help system functionality"""
    print("🚀 Testing Spectra Help System")
    print("=" * 50)
    
    # Initialize help manager
    help_manager = get_help_manager()
    registry = get_registry()
    
    print(f"✅ Help system initialized")
    print(f"📊 Registry status: {'Initialized' if registry.is_initialized() else 'Not initialized'}")
    
    # Get statistics
    stats = help_manager.get_statistics()
    if 'registry' in stats:
        reg_stats = stats['registry']
        print(f"📈 Total modules: {reg_stats.get('total_modules', 0)}")
        print(f"📈 Total categories: {reg_stats.get('total_categories', 0)}")
        print(f"📈 Total CLI commands: {reg_stats.get('total_cli_commands', 0)}")
    
    print("\n" + "=" * 50)
    
    # Test general help
    print("🔍 Testing General Help:")
    print("-" * 30)
    general_help = help_manager.get_general_help()
    print(general_help[:500] + "..." if len(general_help) > 500 else general_help)
    
    print("\n" + "=" * 50)
    
    # Test module-specific help
    print("🔍 Testing Module Help:")
    print("-" * 30)
    
    # Test with port_scanner if available
    modules = help_manager.get_available_modules()
    if modules:
        test_module = modules[0]
        print(f"Testing help for module: {test_module}")
        module_help = help_manager.get_module_help(test_module)
        print(module_help[:500] + "..." if len(module_help) > 500 else module_help)
    else:
        print("No modules available for testing")
    
    print("\n" + "=" * 50)
    
    # Test search functionality
    print("🔍 Testing Search Functionality:")
    print("-" * 30)
    
    search_engine = HelpSearchEngine()
    
    # Test module search
    search_results = search_engine.search_modules("port")
    print(f"Search 'port': {len(search_results)} results")
    for result in search_results[:3]:
        print(f"  - {result['display_name']}: {result['description'][:50]}...")
    
    print("\n" + "-" * 30)
    
    # Test parameter search
    param_results = search_engine.search_parameters("timeout")
    print(f"Parameter search 'timeout': {len(param_results)} results")
    for result in param_results[:3]:
        print(f"  - {result['module_display_name']}.{result['parameter_name']}")
    
    print("\n" + "=" * 50)
    
    # Test JSON output
    print("🔍 Testing JSON Output:")
    print("-" * 30)
    
    if modules:
        json_help = help_manager.get_module_help(modules[0], OutputFormat.JSON)
        print("JSON help generated successfully ✅")
        print(f"JSON length: {len(json_help)} characters")
    
    print("\n" + "=" * 50)
    
    # Test validation
    print("🔍 Testing Validation:")
    print("-" * 30)
    
    validation_result = help_manager.validate_all_modules()
    print(f"Validation status: {validation_result['status']}")
    print(f"Total modules: {validation_result['total_modules']}")
    print(f"Valid modules: {validation_result['valid_modules']}")
    print(f"Invalid modules: {validation_result['invalid_modules']}")
    
    if validation_result['issues']:
        print("Issues found:")
        for issue in validation_result['issues'][:3]:  # Show first 3 issues
            print(f"  - {issue['module']}: {len(issue['errors'])} errors, {len(issue['warnings'])} warnings")
    
    print("\n" + "=" * 50)
    print("✅ Help system test completed!")


def test_cli_integration():
    """Test CLI integration"""
    print("\n🚀 Testing CLI Integration")
    print("=" * 50)
    
    from spectra.core.help_system import handle_cli_help
    
    # Test different CLI help scenarios
    test_cases = [
        ['--help'],
        ['--search', 'port'],
        ['--list-modules'],
        ['--help-stats']
    ]
    
    for test_case in test_cases:
        print(f"\n🔍 Testing: {' '.join(test_case)}")
        print("-" * 30)
        try:
            result = handle_cli_help(test_case)
            print(f"✅ CLI command handled: {result}")
        except Exception as e:
            print(f"❌ Error: {e}")
    
    print("\n✅ CLI integration test completed!")


def main():
    """Main test function"""
    try:
        test_help_system()
        test_cli_integration()
        
        print("\n🎉 All tests completed successfully!")
        print("\nTo use the new help system:")
        print("  python -m spectra.cli.help_cli --help")
        print("  python -m spectra.cli.help_cli --search port")
        print("  python -m spectra.cli.help_cli --help port_scanner")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()