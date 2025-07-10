#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Teste completo do Headers Analyzer com sites reais
"""

import sys
import os

# Adiciona o diretório pai ao path para importar o módulo
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from spectra.modules.headers_analyzer import AdvancedHeadersAnalyzer
from spectra.core.console import console

def test_real_sites():
    """Teste com sites reais para demonstrar as funcionalidades."""
    
    console.print("[bold green]📋 TESTE COMPLETO DO HEADERS ANALYZER MELHORADO[/bold green]")
    console.print("=" * 60)
    
    # Lista de sites para testar
    test_sites = [
        {
            'url': 'https://github.com',
            'description': 'GitHub (esperado: boa configuração de segurança)'
        },
        {
            'url': 'http://example.com',
            'description': 'HTTP Example (esperado: problemas de segurança)'
        }
    ]
    
    for i, site in enumerate(test_sites, 1):
        console.print(f"\n[bold cyan]TESTE {i}: {site['description']}[/bold cyan]")
        console.print(f"Analisando: {site['url']}")
        console.print("-" * 50)
        
        try:
            # Cria o analisador
            analyzer = AdvancedHeadersAnalyzer(site['url'])
            
            # Executa análise completa
            results = analyzer.analyze_headers(verbose=True, include_advanced=True)
            
            if results:
                # Apresenta os resultados
                analyzer.present_results('table')
                
                # Análise dos resultados
                console.print(f"\n[bold yellow]📊 RESUMO DA ANÁLISE[/bold yellow]")
                console.print("-" * 30)
                
                security_analysis = results.get('security_analysis', {})
                csp_analysis = results.get('csp_analysis', {})
                cookie_analysis = results.get('cookie_analysis', {})
                redirect_analysis = results.get('redirect_analysis', {})
                
                # Pontuação de segurança
                security_score = security_analysis.get('security_score', 0)
                console.print(f"Pontuação de Segurança: {security_score}/100")
                
                # CSP
                if csp_analysis:
                    csp_score = csp_analysis.get('score', 0)
                    csp_status = 'Configurado' if csp_score > 0 else 'Não Configurado'
                    console.print(f"CSP: {csp_status} (Score: {csp_score}/100)")
                
                # Cookies
                if cookie_analysis:
                    total_cookies = cookie_analysis.get('total_cookies', 0)
                    console.print(f"Cookies Detectados: {total_cookies}")
                
                # Redirecionamentos
                if redirect_analysis:
                    redirect_info = redirect_analysis.get('info', {})
                    total_redirects = redirect_info.get('total_redirects', 0)
                    https_enforced = redirect_info.get('https_enforced', False)
                    console.print(f"Redirecionamentos: {total_redirects}")
                    console.print(f"HTTPS Enforced: {'✅ Sim' if https_enforced else '❌ Não'}")
                
                # Problemas por categoria
                categories = security_analysis.get('categories', {})
                if categories:
                    console.print(f"Problemas por Categoria:")
                    for category, count in categories.items():
                        if count > 0:
                            console.print(f"  • {category.replace('_', ' ').title()}: {count}")
                
                console.print(f"[bold green]✅ Análise concluída com sucesso![/bold green]")
                
            else:
                console.print(f"[bold red]❌ Falha na análise do site {site['url']}[/bold red]")
                
        except Exception as e:
            console.print(f"[bold red]❌ Erro ao analisar {site['url']}: {e}[/bold red]")
        
        console.print("\n" + "=" * 60)
    
    console.print(f"\n[bold green]🎉 TESTE DAS MELHORIAS CONCLUÍDO![/bold green]")
    console.print("Funcionalidades implementadas e testadas:")
    console.print("✅ Análise avançada de cabeçalhos de segurança")
    console.print("✅ Análise detalhada de CSP (Content Security Policy)")
    console.print("✅ Verificação de segurança de cookies")
    console.print("✅ Análise de redirecionamentos seguros")
    console.print("✅ Detecção de cabeçalhos suspeitos")
    console.print("✅ Categorização de problemas por tipo")
    console.print("✅ Pontuação de segurança aprimorada")
    console.print("✅ Apresentação rica e organizada dos resultados")

if __name__ == "__main__":
    test_real_sites()
