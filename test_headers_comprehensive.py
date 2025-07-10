#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Teste Abrangente do Headers Analyzer
Testa todas as funcionalidades implementadas e melhoradas
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from spectra.modules.headers_analyzer import AdvancedHeadersAnalyzer
from spectra.core.console import console
import time

def test_comprehensive_analysis():
    """Teste abrangente de todas as funcionalidades."""
    
    test_sites = [
        {
            'url': 'https://google.com',
            'description': 'Google - Site com alta segurança',
            'expected_features': ['HSTS', 'CSP', 'Strong security']
        },
        {
            'url': 'https://github.com',
            'description': 'GitHub - Plataforma de desenvolvimento',
            'expected_features': ['Security headers', 'Cookies', 'CORS']
        },
        {
            'url': 'https://httpbin.org/headers',
            'description': 'HTTPBin - Teste de cabeçalhos',
            'expected_features': ['Basic headers', 'Simple response']
        },
        {
            'url': 'http://httpforever.com',
            'description': 'Site HTTP - Teste de problemas de segurança',
            'expected_features': ['No HTTPS', 'Security issues']
        }
    ]
    
    console.print("[bold cyan]🔍 TESTE ABRANGENTE DO HEADERS ANALYZER[/bold cyan]")
    console.print("=" * 70)
    
    total_tests = len(test_sites)
    successful_tests = 0
    
    for i, site in enumerate(test_sites, 1):
        console.print(f"\n[bold yellow]📊 Teste {i}/{total_tests}: {site['description']}[/bold yellow]")
        console.print(f"URL: {site['url']}")
        console.print("-" * 50)
        
        try:
            # Inicializa analisador
            analyzer = AdvancedHeadersAnalyzer(site['url'], timeout=15)
            
            # Executa análise completa
            start_time = time.time()
            results = analyzer.analyze_headers(verbose=True, include_advanced=True)
            end_time = time.time()
            
            if results:
                # Apresenta resultados
                analyzer.present_results('table')
                
                # Estatísticas do teste
                console.print(f"\n[bold green]✅ Teste concluído em {end_time - start_time:.2f}s[/bold green]")
                
                # Verifica aspectos específicos
                security_analysis = results['security_analysis']
                console.print(f"[cyan]📈 Resumo da Análise:[/cyan]")
                console.print(f"  • Pontuação de Segurança: {security_analysis['security_score']}/100")
                console.print(f"  • Total de Findings: {security_analysis['total_findings']}")
                console.print(f"  • Problemas HIGH: {security_analysis['findings_by_severity']['HIGH']}")
                console.print(f"  • Problemas MEDIUM: {security_analysis['findings_by_severity']['MEDIUM']}")
                console.print(f"  • Problemas LOW: {security_analysis['findings_by_severity']['LOW']}")
                console.print(f"  • Informações: {security_analysis['findings_by_severity']['INFO']}")
                
                # Verifica categorias específicas
                categories = security_analysis.get('categories', {})
                console.print(f"[cyan]📊 Análises por Categoria:[/cyan]")
                for category, count in categories.items():
                    console.print(f"  • {category.replace('_', ' ').title()}: {count}")
                
                # Verifica se CSP foi analisado
                if hasattr(analyzer, 'csp_analysis') and analyzer.csp_analysis:
                    csp_score = analyzer.csp_analysis.get('score', 0)
                    console.print(f"[cyan]🛡️  Análise CSP: {csp_score}/100[/cyan]")
                
                # Verifica se cookies foram analisados
                if hasattr(analyzer, 'cookie_analysis') and analyzer.cookie_analysis:
                    cookie_count = analyzer.cookie_analysis.get('total_cookies', 0)
                    console.print(f"[cyan]🍪 Cookies Analisados: {cookie_count}[/cyan]")
                
                # Verifica se redirecionamentos foram analisados
                if hasattr(analyzer, 'redirect_analysis') and analyzer.redirect_analysis:
                    redirect_info = analyzer.redirect_analysis.get('info', {})
                    redirect_count = redirect_info.get('total_redirects', 0)
                    console.print(f"[cyan]🔄 Redirecionamentos: {redirect_count}[/cyan]")
                
                successful_tests += 1
                
                # Validações específicas
                _validate_analysis_completeness(analyzer, site['url'])
                
            else:
                console.print(f"[bold red]❌ Falha na análise de {site['url']}[/bold red]")
                
        except Exception as e:
            console.print(f"[bold red]❌ Erro no teste: {str(e)}[/bold red]")
            continue
        
        # Pausa entre testes para evitar rate limiting
        if i < total_tests:
            console.print("[dim]Aguardando 2 segundos antes do próximo teste...[/dim]")
            time.sleep(2)
    
    # Resultado final
    console.print(f"\n[bold cyan]📋 RESULTADO FINAL DOS TESTES[/bold cyan]")
    console.print("=" * 50)
    console.print(f"Testes Executados: {total_tests}")
    console.print(f"Testes Bem-sucedidos: {successful_tests}")
    console.print(f"Taxa de Sucesso: {(successful_tests/total_tests)*100:.1f}%")
    
    if successful_tests == total_tests:
        console.print(f"[bold green]🎉 TODOS OS TESTES PASSARAM![/bold green]")
    else:
        console.print(f"[bold yellow]⚠️  {total_tests - successful_tests} teste(s) falharam[/bold yellow]")
    
    return successful_tests == total_tests

def _validate_analysis_completeness(analyzer, url):
    """Valida se a análise está completa e correta."""
    console.print(f"[dim]🔍 Validando completude da análise...[/dim]")
    
    validations = []
    
    # Verifica se informações básicas estão presentes
    if hasattr(analyzer, 'headers_info') and analyzer.headers_info:
        validations.append("✅ Informações básicas de cabeçalhos")
    else:
        validations.append("❌ Informações básicas ausentes")
    
    # Verifica se análise de segurança foi executada
    if hasattr(analyzer, 'security_analysis') and analyzer.security_analysis:
        validations.append("✅ Análise de segurança executada")
    else:
        validations.append("❌ Análise de segurança ausente")
    
    # Verifica se análises avançadas foram executadas
    advanced_features = [
        ('csp_analysis', 'Análise CSP'),
        ('cookie_analysis', 'Análise de Cookies'),
        ('redirect_analysis', 'Análise de Redirecionamentos')
    ]
    
    for attr, description in advanced_features:
        if hasattr(analyzer, attr) and getattr(analyzer, attr):
            validations.append(f"✅ {description}")
        else:
            validations.append(f"⚠️  {description} não aplicável ou ausente")
    
    # Mostra resultados da validação
    for validation in validations:
        console.print(f"  {validation}")

def test_specific_features():
    """Testa funcionalidades específicas implementadas."""
    console.print(f"\n[bold cyan]🧪 TESTE DE FUNCIONALIDADES ESPECÍFICAS[/bold cyan]")
    console.print("-" * 50)
    
    # Teste de parsing de CSP
    console.print("[yellow]Testando parsing de CSP...[/yellow]")
    analyzer = AdvancedHeadersAnalyzer("https://example.com")
    
    # Simula CSP com problemas
    test_csp = "default-src 'self'; script-src 'self' 'unsafe-inline' https://*.example.com; object-src *"
    csp_analysis = analyzer._analyze_csp_advanced(test_csp)
    
    console.print(f"CSP Score: {csp_analysis['score']}/100")
    console.print(f"Problemas encontrados: {len(csp_analysis['findings'])}")
    
    for finding in csp_analysis['findings']:
        console.print(f"  • {finding['severity']}: {finding['description']}")
    
    # Teste de análise de Permissions Policy
    console.print(f"\n[yellow]Testando análise de Permissions Policy...[/yellow]")
    test_permissions = "camera=(self), microphone=*, geolocation=(self \"https://trusted.com\")"
    permissions_analysis = analyzer._analyze_permissions_policy(test_permissions)
    
    console.print(f"Permissions Score: {permissions_analysis['score']}/100")
    console.print(f"Problemas encontrados: {len(permissions_analysis['findings'])}")
    
    for finding in permissions_analysis['findings']:
        console.print(f"  • {finding['severity']}: {finding['description']}")
    
    console.print("[green]✅ Testes de funcionalidades específicas concluídos[/green]")

def main():
    """Função principal do teste."""
    console.print("[bold blue]INÍCIO DOS TESTES ABRANGENTES DO HEADERS ANALYZER[/bold blue]")
    console.print(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    try:
        # Executa testes específicos de funcionalidades
        test_specific_features()
        
        # Executa testes abrangentes
        success = test_comprehensive_analysis()
        
        if success:
            console.print(f"\n[bold green]🎊 TODOS OS TESTES FORAM CONCLUÍDOS COM SUCESSO![/bold green]")
            return 0
        else:
            console.print(f"\n[bold red]⚠️  ALGUNS TESTES FALHARAM![/bold red]")
            return 1
            
    except KeyboardInterrupt:
        console.print(f"\n[bold yellow]⏹️  Testes interrompidos pelo usuário[/bold yellow]")
        return 1
    except Exception as e:
        console.print(f"\n[bold red]💥 Erro crítico nos testes: {str(e)}[/bold red]")
        return 1

if __name__ == "__main__":
    exit(main())
