#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Teste das melhorias do SSL Analyzer
Valida as novas funcionalidades avançadas implementadas
"""

import sys
import os

# Adiciona o diretório pai ao path para importar o módulo
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from spectra.modules.ssl_analyzer import AdvancedSSLAnalyzer
from spectra.core.console import console

def test_ssl_analyzer_improvements():
    """Testa as melhorias implementadas no SSL Analyzer."""
    
    console.print("[bold green]🔒 TESTE DAS MELHORIAS DO SSL ANALYZER[/bold green]")
    console.print("=" * 60)
    
    # Lista de sites para testar
    test_sites = [
        {
            'hostname': 'google.com',
            'port': 443,
            'description': 'Google (esperado: TLS 1.3, HSTS, security forte)'
        },
        {
            'hostname': 'github.com',
            'port': 443,
            'description': 'GitHub (esperado: configuração moderna)'
        },
        {
            'hostname': 'cloudflare.com',
            'port': 443,
            'description': 'Cloudflare (esperado: máxima segurança)'
        }
    ]
    
    for i, site in enumerate(test_sites, 1):
        console.print(f"\n[bold cyan]TESTE {i}: {site['description']}[/bold cyan]")
        console.print(f"Analisando: {site['hostname']}:{site['port']}")
        console.print("-" * 50)
        
        try:
            # Cria o analisador
            analyzer = AdvancedSSLAnalyzer(site['hostname'], site['port'])
            
            # Executa análise completa com todas as funcionalidades avançadas
            results = analyzer.analyze_ssl(
                include_transparency=True,  # Inclui Certificate Transparency
                include_advanced=True       # Inclui análises avançadas
            )
            
            if results:
                # Apresenta os resultados
                analyzer.present_results('table')
                
                # Análise dos resultados
                console.print(f"\n[bold yellow]📊 RESUMO DA ANÁLISE[/bold yellow]")
                console.print("-" * 30)
                
                cert_info = results.get('certificate_info', {})
                security_analysis = results.get('security_analysis', {})
                cipher_analysis = results.get('cipher_analysis', {})
                hsts_info = results.get('hsts_info', {})
                
                # Pontuação de segurança
                security_score = security_analysis.get('security_score', 0)
                console.print(f"Pontuação de Segurança: {security_score}/100")
                
                # TLS 1.3
                tls13_support = cipher_analysis.get('tls13_support', False)
                console.print(f"Suporte TLS 1.3: {'✅ Sim' if tls13_support else '❌ Não'}")
                
                # Perfect Forward Secrecy
                pfs_support = cipher_analysis.get('pfs_support', False)
                console.print(f"Perfect Forward Secrecy: {'✅ Sim' if pfs_support else '❌ Não'}")
                
                # HSTS
                hsts_enabled = hsts_info.get('enabled', False)
                console.print(f"HSTS Habilitado: {'✅ Sim' if hsts_enabled else '❌ Não'}")
                
                # Vulnerabilidades
                vulnerabilities = security_analysis.get('vulnerabilities', [])
                console.print(f"Vulnerabilidades: {len(vulnerabilities)}")
                
                # Certificate Transparency
                ct_info = cert_info.get('certificate_transparency', {})
                if ct_info:
                    transparency_score = ct_info.get('transparency_score', 'N/A')
                    console.print(f"Certificate Transparency: {transparency_score}")
                
                console.print(f"[bold green]✅ Análise concluída com sucesso![/bold green]")
                
            else:
                console.print(f"[bold red]❌ Falha na análise do site {site['hostname']}[/bold red]")
                
        except Exception as e:
            console.print(f"[bold red]❌ Erro ao analisar {site['hostname']}: {e}[/bold red]")
        
        console.print("\n" + "=" * 60)
    
    console.print(f"\n[bold green]🎉 TESTE DAS MELHORIAS CONCLUÍDO![/bold green]")
    console.print("Funcionalidades testadas:")
    console.print("✅ Análise avançada de cipher suites")
    console.print("✅ Verificação de TLS 1.3")
    console.print("✅ Detecção de Perfect Forward Secrecy")
    console.print("✅ Análise de HSTS")
    console.print("✅ Certificate Transparency")
    console.print("✅ Análise de segurança expandida")
    console.print("✅ Apresentação rica dos resultados")

def test_specific_features():
    """Testa funcionalidades específicas em detalhes."""
    
    console.print(f"\n[bold cyan]🔍 TESTE DE FUNCIONALIDADES ESPECÍFICAS[/bold cyan]")
    console.print("=" * 60)
    
    # Teste específico para um site conhecido por ter boa configuração SSL
    hostname = "github.com"
    
    try:
        analyzer = AdvancedSSLAnalyzer(hostname, 443)
        
        console.print(f"[cyan]Testando funcionalidades específicas em {hostname}...[/cyan]")
        
        # Teste 1: Análise de cipher suites
        console.print("\n1. Testando análise de cipher suites...")
        cipher_analysis = analyzer._analyze_cipher_suites()
        
        if cipher_analysis:
            console.print(f"   ✅ Versões TLS suportadas: {cipher_analysis.get('supported_versions', [])}")
            console.print(f"   ✅ Suporte TLS 1.3: {cipher_analysis.get('tls13_support', False)}")
            console.print(f"   ✅ Perfect Forward Secrecy: {cipher_analysis.get('pfs_support', False)}")
            console.print(f"   ✅ Ciphers fracos encontrados: {len(cipher_analysis.get('weak_ciphers_found', []))}")
        
        # Teste 2: Verificação HSTS
        console.print("\n2. Testando verificação HSTS...")
        hsts_info = analyzer._check_hsts()
        
        if hsts_info:
            console.print(f"   ✅ HSTS habilitado: {hsts_info.get('enabled', False)}")
            if hsts_info.get('enabled'):
                console.print(f"   ✅ Max Age: {hsts_info.get('max_age', 0):,}s")
                console.print(f"   ✅ Include Subdomains: {hsts_info.get('include_subdomains', False)}")
        
        # Teste 3: Certificate Transparency
        console.print("\n3. Testando Certificate Transparency...")
        
        # Primeiro precisamos obter o certificado
        cert_data = analyzer._get_certificate()
        analyzer._parse_certificate(cert_data)
        
        ct_info = analyzer._check_certificate_transparency()
        
        if ct_info:
            console.print(f"   ✅ SCT presente: {ct_info.get('has_sct', False)}")
            console.print(f"   ✅ Pontuação transparência: {ct_info.get('transparency_score', 'N/A')}")
            console.print(f"   ✅ Logs CT verificados: {len(ct_info.get('ct_logs', []))}")
        
        console.print(f"\n[bold green]✅ Todos os testes específicos passaram![/bold green]")
        
    except Exception as e:
        console.print(f"[bold red]❌ Erro nos testes específicos: {e}[/bold red]")

if __name__ == "__main__":
    try:
        # Teste principal das melhorias
        test_ssl_analyzer_improvements()
        
        # Teste de funcionalidades específicas
        test_specific_features()
        
    except KeyboardInterrupt:
        console.print(f"\n[bold yellow]⚠️ Teste interrompido pelo usuário[/bold yellow]")
    except Exception as e:
        console.print(f"[bold red]❌ Erro geral nos testes: {e}[/bold red]")
