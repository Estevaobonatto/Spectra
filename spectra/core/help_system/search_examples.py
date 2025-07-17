# -*- coding: utf-8 -*-
"""
Search functionality examples and utilities for Spectra Help System
"""

from typing import List, Dict, Any
from .help_manager import get_help_manager
from .help_formatter import OutputFormat


class HelpSearchEngine:
    """Advanced search engine for help system"""
    
    def __init__(self):
        self.help_manager = get_help_manager()
    
    def search_modules(self, query: str, filters: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """
        Advanced module search with filtering
        
        Args:
            query: Search query
            filters: Optional filters (category, tags, etc.)
            
        Returns:
            List of search results with metadata
        """
        results = self.help_manager.registry.search_modules(query, fuzzy=True)
        
        # Apply filters if provided
        if filters:
            results = self._apply_filters(results, filters)
        
        # Convert to detailed result format
        detailed_results = []
        for module in results:
            result = {
                'name': module.name,
                'display_name': module.display_name,
                'category': module.category.value,
                'description': module.description,
                'cli_command': module.cli_command,
                'tags': module.tags,
                'match_score': self._calculate_match_score(query, module)
            }
            detailed_results.append(result)
        
        # Sort by match score
        detailed_results.sort(key=lambda x: x['match_score'], reverse=True)
        
        return detailed_results
    
    def search_parameters(self, query: str, module_name: str = None) -> List[Dict[str, Any]]:
        """
        Search for parameters across modules
        
        Args:
            query: Parameter search query
            module_name: Optional module name to limit search
            
        Returns:
            List of matching parameters with module info
        """
        results = []
        query_lower = query.lower()
        
        modules = [self.help_manager.registry.get_module(module_name)] if module_name else self.help_manager.registry.get_all_modules()
        
        for module in modules:
            if not module:
                continue
                
            for param in module.parameters:
                score = 0
                
                # Check parameter name
                if query_lower in param.name.lower():
                    score += 50
                
                # Check description
                if query_lower in param.description.lower():
                    score += 30
                
                # Check examples
                for example in param.examples:
                    if query_lower in example.lower():
                        score += 20
                        break
                
                if score > 0:
                    results.append({
                        'module_name': module.name,
                        'module_display_name': module.display_name,
                        'parameter_name': param.name,
                        'parameter_description': param.description,
                        'parameter_type': param.param_type.value,
                        'required': param.required,
                        'examples': param.examples,
                        'match_score': score
                    })
        
        # Sort by score
        results.sort(key=lambda x: x['match_score'], reverse=True)
        return results
    
    def search_examples(self, query: str, level: str = None) -> List[Dict[str, Any]]:
        """
        Search for examples across modules
        
        Args:
            query: Example search query
            level: Optional level filter (basic, intermediate, advanced)
            
        Returns:
            List of matching examples with module info
        """
        results = []
        query_lower = query.lower()
        
        for module in self.help_manager.registry.get_all_modules():
            for example in module.examples:
                # Apply level filter
                if level and example.level.value != level.lower():
                    continue
                
                score = 0
                
                # Check title
                if query_lower in example.title.lower():
                    score += 50
                
                # Check description
                if query_lower in example.description.lower():
                    score += 40
                
                # Check command
                if query_lower in example.command.lower():
                    score += 30
                
                # Check category
                if query_lower in example.category.lower():
                    score += 20
                
                if score > 0:
                    results.append({
                        'module_name': module.name,
                        'module_display_name': module.display_name,
                        'example_title': example.title,
                        'example_description': example.description,
                        'example_command': example.command,
                        'example_level': example.level.value,
                        'example_category': example.category,
                        'match_score': score
                    })
        
        # Sort by score
        results.sort(key=lambda x: x['match_score'], reverse=True)
        return results
    
    def get_search_suggestions(self, query: str) -> List[str]:
        """
        Get search suggestions based on query
        
        Args:
            query: Partial search query
            
        Returns:
            List of suggested search terms
        """
        suggestions = set()
        query_lower = query.lower()
        
        # Get module names and display names
        for module in self.help_manager.registry.get_all_modules():
            if query_lower in module.name.lower():
                suggestions.add(module.name)
            if query_lower in module.display_name.lower():
                suggestions.add(module.display_name)
            
            # Add tags
            for tag in module.tags:
                if query_lower in tag.lower():
                    suggestions.add(tag)
        
        # Common search terms
        common_terms = [
            'port scanning', 'directory scanning', 'hash cracking',
            'sql injection', 'xss', 'vulnerability', 'reconnaissance',
            'security analysis', 'cryptography', 'monitoring'
        ]
        
        for term in common_terms:
            if query_lower in term.lower():
                suggestions.add(term)
        
        return sorted(list(suggestions))[:10]
    
    def _apply_filters(self, modules, filters):
        """Apply filters to module results"""
        filtered = modules
        
        if 'category' in filters:
            category_filter = filters['category'].lower()
            filtered = [m for m in filtered if m.category.value == category_filter]
        
        if 'tags' in filters:
            tag_filters = [t.lower() for t in filters['tags']]
            filtered = [m for m in filtered if any(tag.lower() in tag_filters for tag in m.tags)]
        
        if 'cli_command' in filters:
            cmd_filter = filters['cli_command']
            filtered = [m for m in filtered if m.cli_command == cmd_filter]
        
        return filtered
    
    def _calculate_match_score(self, query: str, module) -> float:
        """Calculate match score for search ranking"""
        score = 0.0
        query_lower = query.lower()
        
        # Exact name match (highest score)
        if query_lower == module.name.lower():
            score += 100
        elif query_lower in module.name.lower():
            score += 50
        
        # Display name match
        if query_lower in module.display_name.lower():
            score += 40
        
        # Description match
        if query_lower in module.description.lower():
            score += 20
        
        # Tag matches
        for tag in module.tags:
            if query_lower in tag.lower():
                score += 30
                break
        
        # CLI command match
        if module.cli_command and query_lower in module.cli_command.lower():
            score += 35
        
        return score


def demo_search_functionality():
    """Demonstrate search functionality"""
    search_engine = HelpSearchEngine()
    
    print("=== Spectra Help System Search Demo ===\n")
    
    # Module search
    print("1. Module Search Examples:")
    print("-" * 30)
    
    queries = ["port", "sql", "hash", "directory"]
    for query in queries:
        results = search_engine.search_modules(query)
        print(f"Search '{query}': {len(results)} results")
        for result in results[:2]:  # Show top 2
            print(f"  - {result['display_name']}: {result['description']}")
        print()
    
    # Parameter search
    print("2. Parameter Search Examples:")
    print("-" * 30)
    
    param_queries = ["timeout", "workers", "verbose"]
    for query in param_queries:
        results = search_engine.search_parameters(query)
        print(f"Parameter '{query}': {len(results)} results")
        for result in results[:2]:  # Show top 2
            print(f"  - {result['module_display_name']}.{result['parameter_name']}: {result['parameter_description']}")
        print()
    
    # Example search
    print("3. Example Search:")
    print("-" * 20)
    
    example_results = search_engine.search_examples("basic", level="basic")
    print(f"Basic examples: {len(example_results)} results")
    for result in example_results[:3]:  # Show top 3
        print(f"  - {result['module_display_name']}: {result['example_title']}")
    print()
    
    # Search suggestions
    print("4. Search Suggestions:")
    print("-" * 25)
    
    suggestion_queries = ["po", "sq", "ha"]
    for query in suggestion_queries:
        suggestions = search_engine.get_search_suggestions(query)
        print(f"'{query}' -> {', '.join(suggestions[:5])}")


if __name__ == '__main__':
    demo_search_functionality()