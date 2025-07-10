#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Teste simples do Headers Analyzer
"""

import sys
import os

# Adiciona o diretório pai ao path para importar o módulo
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from spectra.modules.headers_analyzer import AdvancedHeadersAnalyzer
from spectra.core.console import console

def test_simple():
    """Teste simples para validar se o Headers Analyzer está funcionando."""
    
    console.print("[bold green]🧪 TESTE SIMPLES DO HEADERS ANALYZER[/bold green]")
    console.print("=" * 50)
    
    # Teste com um site simples
    test_url = "https://httpbin.org/headers"
    
    try:
        console.print(f"[cyan]Testando: {test_url}[/cyan]")
        
        # Cria o analisador
        analyzer = AdvancedHeadersAnalyzer(test_url)
        
        # Executa análise
        results = analyzer.analyze_headers(verbose=True, include_advanced=True)
        
        if results:
            console.print("[bold green]✅ Análise executada com sucesso![/bold green]")
            
            # Apresenta resultados
            analyzer.present_results()
            
            # Mostra resumo
            security_analysis = results.get('security_analysis', {})
            score = security_analysis.get('security_score', 0)
            total_findings = security_analysis.get('total_findings', 0)
            
            console.print(f"\n[bold yellow]📊 RESUMO:[/bold yellow]")
            console.print(f"Pontuação: {score}/100")
            console.print(f"Problemas: {total_findings}")
            
        else:
            console.print("[bold red]❌ Falha na análise[/bold red]")
        
    except Exception as e:
        console.print(f"[bold red]❌ Erro: {e}[/bold red]")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_simple()
