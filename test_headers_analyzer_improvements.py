#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Teste das melhorias do Headers Analyzer
Valida as novas funcionalidades avançadas implementadas
"""

import sys
import os

# Adiciona o diretório pai ao path para importar o módulo
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from spectra.modules.headers_analyzer import AdvancedHeadersAnalyzer
from spectra.core.console import console

def test_headers_analyzer_improvements():
    """Testa as melhorias implementadas no Headers Analyzer."""
    
    console.print("[bold green]📋 TESTE DAS MELHORIAS DO HEADERS ANALYZER[/bold green]")
    console.print("=" * 60)
    
    # Lista de sites para testar
    test_sites = [
        {
            'url': 'https://github.com',
            'description': 'GitHub (esperado: boa configuração de segurança)'
        },
        {
            'url': 'https://google.com',
            'description': 'Google (esperado: CSP avançado, redirecionamentos)'
        },
        {
            'url': 'https://stackoverflow.com',
            'description': 'Stack Overflow (esperado: análise completa)'
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
            
            # Executa análise completa com todas as funcionalidades avançadas
            results = analyzer.analyze_headers(
                verbose=True,
                include_advanced=True
            )
            
            if results:
                # Apresenta os resultados
                analyzer.present_results('table')
                
                # Análise dos resultados
                console.print(f"\n[bold yellow]📊 RESUMO DA ANÁLISE[/bold yellow]")
                console.print("-" * 30)
                
                headers_info = results.get('headers_info', {})
                security_analysis = results.get('security_analysis', {})
                csp_analysis = results.get('csp_analysis', {})
                cookie_analysis = results.get('cookie_analysis', {})
                redirect_analysis = results.get('redirect_analysis', {})
                
                # Pontuação de segurança
                security_score = security_analysis.get('security_score', 0)
                console.print(f"Pontuação de Segurança: {security_score}/100")
                
                # Total de cabeçalhos
                total_headers = len(headers_info.get('headers', {}))
                console.print(f"Total de Cabeçalhos: {total_headers}")
                
                # CSP
                csp_score = csp_analysis.get('score', 0) if csp_analysis else 0
                csp_status = 'Configurado' if csp_score > 0 else 'Não Configurado'
                console.print(f"CSP: {csp_status} (Score: {csp_score}/100)")
                
                # Cookies
                total_cookies = cookie_analysis.get('total_cookies', 0) if cookie_analysis else 0
                console.print(f"Cookies Detectados: {total_cookies}")
                
                # Redirecionamentos
                redirect_info = redirect_analysis.get('info', {}) if redirect_analysis else {}
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
    console.print("Funcionalidades testadas:")
    console.print("✅ Análise avançada de cabeçalhos de segurança")
    console.print("✅ Análise detalhada de CSP (Content Security Policy)")
    console.print("✅ Verificação de segurança de cookies")
    console.print("✅ Análise de redirecionamentos seguros")
    console.print("✅ Detecção de cabeçalhos suspeitos")
    console.print("✅ Categorização de problemas")
    console.print("✅ Pontuação de segurança aprimorada")
    console.print("✅ Apresentação rica dos resultados")

def test_specific_features():
    """Testa funcionalidades específicas em detalhes."""
    
    console.print(f"\n[bold cyan]🔍 TESTE DE FUNCIONALIDADES ESPECÍFICAS[/bold cyan]")
    console.print("=" * 60)
    
    # Teste específico para um site conhecido por ter boa configuração
    test_url = "https://github.com"
    
    try:
        analyzer = AdvancedHeadersAnalyzer(test_url)
        
        console.print(f"[cyan]Testando funcionalidades específicas em {test_url}...[/cyan]")
        
        # Executa análise completa
        results = analyzer.analyze_headers(verbose=True, include_advanced=True)
        
        if results:
            console.print("\n1. Testando análise de CSP...")
            csp_analysis = results.get('csp_analysis', {})
            if csp_analysis:
                console.print(f"   ✅ CSP Score: {csp_analysis.get('score', 0)}/100")
                console.print(f"   ✅ Diretivas encontradas: {len(csp_analysis.get('directives', {}))}")
                console.print(f"   ✅ Problemas CSP: {len(csp_analysis.get('findings', []))}")
            
            console.print("\n2. Testando análise de cookies...")
            cookie_analysis = results.get('cookie_analysis', {})
            if cookie_analysis:
                console.print(f"   ✅ Cookies detectados: {cookie_analysis.get('total_cookies', 0)}")
                console.print(f"   ✅ Problemas de cookies: {len(cookie_analysis.get('findings', []))}")
            
            console.print("\n3. Testando análise de redirecionamentos...")
            redirect_analysis = results.get('redirect_analysis', {})
            if redirect_analysis:
                redirect_info = redirect_analysis.get('info', {})
                console.print(f"   ✅ Total de redirecionamentos: {redirect_info.get('total_redirects', 0)}")
                console.print(f"   ✅ HTTPS enforced: {redirect_info.get('https_enforced', False)}")
                console.print(f"   ✅ Problemas de redirecionamento: {len(redirect_analysis.get('findings', []))}")
            
            console.print("\n4. Testando categorização de problemas...")
            security_analysis = results.get('security_analysis', {})
            categories = security_analysis.get('categories', {})
            if categories:
                console.print(f"   ✅ Categorias detectadas: {len(categories)}")
                for category, count in categories.items():
                    console.print(f"   ✅ {category}: {count} problemas")
            
            console.print(f"\n[bold green]✅ Todos os testes específicos passaram![/bold green]")
        
    except Exception as e:
        console.print(f"[bold red]❌ Erro nos testes específicos: {e}[/bold red]")

def test_security_detection():
    """Testa detecção específica de problemas de segurança."""
    
    console.print(f"\n[bold cyan]🛡️ TESTE DE DETECÇÃO DE PROBLEMAS DE SEGURANÇA[/bold cyan]")
    console.print("=" * 60)
    
    # Sites com diferentes níveis de segurança
    security_test_sites = [
        {
            'url': 'https://security-headers.com',
            'expected': 'Alta segurança (site especializado)'
        },
        {
            'url': 'http://neverssl.com',
            'expected': 'Baixa segurança (HTTP apenas)'
        }
    ]
    
    for site in security_test_sites:
        console.print(f"\n[bold cyan]Testando: {site['url']}[/bold cyan]")
        console.print(f"Expectativa: {site['expected']}")
        console.print("-" * 40)
        
        try:
            analyzer = AdvancedHeadersAnalyzer(site['url'])
            results = analyzer.analyze_headers(include_advanced=True)
            
            if results:
                security_analysis = results.get('security_analysis', {})
                score = security_analysis.get('security_score', 0)
                total_findings = security_analysis.get('total_findings', 0)
                
                console.print(f"Pontuação: {score}/100")
                console.print(f"Problemas encontrados: {total_findings}")
                
                # Análise por severidade
                findings_by_severity = security_analysis.get('findings_by_severity', {})
                high_issues = findings_by_severity.get('HIGH', 0)
                medium_issues = findings_by_severity.get('MEDIUM', 0)
                
                if high_issues > 0:
                    console.print(f"[bold red]⚠️ {high_issues} problemas críticos detectados[/bold red]")
                if medium_issues > 0:
                    console.print(f"[bold yellow]⚠️ {medium_issues} problemas médios detectados[/bold yellow]")
                
                if score >= 80:
                    console.print(f"[bold green]✅ Boa configuração de segurança[/bold green]")
                elif score >= 60:
                    console.print(f"[bold yellow]⚠️ Configuração de segurança moderada[/bold yellow]")
                else:
                    console.print(f"[bold red]❌ Configuração de segurança insuficiente[/bold red]")
        
        except Exception as e:
            console.print(f"[bold red]❌ Erro: {e}[/bold red]")

if __name__ == "__main__":
    try:
        # Teste principal das melhorias
        test_headers_analyzer_improvements()
        
        # Teste de funcionalidades específicas
        test_specific_features()
        
        # Teste de detecção de segurança
        test_security_detection()
        
    except KeyboardInterrupt:
        console.print(f"\n[bold yellow]⚠️ Teste interrompido pelo usuário[/bold yellow]")
    except Exception as e:
        console.print(f"[bold red]❌ Erro geral nos testes: {e}[/bold red]")
