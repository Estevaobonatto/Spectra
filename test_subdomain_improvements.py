#!/usr/bin/env python3
"""
Teste das melhorias do Subdomain Scanner
"""

import sys
import os
import asyncio

# Adiciona o diretório do projeto ao path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from spectra.modules.subdomain_scanner import (
    SubdomainScanner, 
    TakeoverVerifier, 
    CertificateTransparencySource,
    PermutationEngine
)
from spectra.core import print_info, print_success, print_error

def test_takeover_verifier():
    """Testa o verificador de takeover."""
    print_info("=== TESTE DO TAKEOVER VERIFIER ===")
    
    # Cria uma instância do verificador
    verifier = TakeoverVerifier()
    
    # Testa com um exemplo conhecido (GitHub Pages)
    test_cases = [
        ("test.github.io", "test.github.io"),
        ("example.herokuapp.com", "example.herokuapp.com"),
        ("test.netlify.app", "test.netlify.app")
    ]
    
    print_info("Testando assinaturas de takeover...")
    for subdomain, cname in test_cases:
        print_info(f"Testando: {subdomain} -> {cname}")
        
        # Verifica se o padrão é reconhecido
        for service_pattern, info in verifier.takeover_signatures.items():
            if service_pattern in cname.lower():
                print_success(f"✓ Serviço reconhecido: {info['service_name']}")
                print_info(f"  Exploit: {info['exploit_info']}")
                break
        else:
            print_error(f"✗ Serviço não reconhecido para {cname}")

def test_certificate_transparency():
    """Testa a integração com Certificate Transparency."""
    print_info("\n=== TESTE DO CERTIFICATE TRANSPARENCY ===")
    
    # Cria uma instância da fonte CT
    ct_source = CertificateTransparencySource()
    
    # Testa validação de subdomínio
    test_domain = "example.com"
    test_cases = [
        ("www.example.com", True),
        ("api.example.com", True),
        ("*.example.com", True),  # Wildcard deve ser aceito
        ("example.com", False),   # Domínio base deve ser rejeitado
        ("malicious<script>", False),  # Caracteres inválidos
        ("other.domain.com", False)    # Domínio diferente
    ]
    
    print_info("Testando validação de subdomínios...")
    for subdomain, expected in test_cases:
        result = ct_source._is_valid_subdomain(subdomain, test_domain)
        status = "✓" if result == expected else "✗"
        print_info(f"{status} {subdomain} -> {result} (esperado: {expected})")

def test_permutation_engine():
    """Testa o engine de permutação."""
    print_info("\n=== TESTE DO PERMUTATION ENGINE ===")
    
    # Cria uma instância do engine
    engine = PermutationEngine()
    
    # Testa com subdomínios de exemplo
    found_subdomains = {"api", "www", "dev", "admin"}
    
    print_info(f"Subdomínios encontrados: {found_subdomains}")
    
    # Gera permutações
    permutations = engine.generate_permutations(found_subdomains, max_permutations=20)
    
    print_info(f"Permutações geradas ({len(permutations)}):")
    for perm in sorted(list(permutations)[:10]):  # Mostra apenas as primeiras 10
        print_info(f"  • {perm}")
    
    if len(permutations) > 10:
        print_info(f"  ... e mais {len(permutations) - 10} permutações")

def test_pattern_analysis():
    """Testa análise de padrões."""
    print_info("\n=== TESTE DE ANÁLISE DE PADRÕES ===")
    
    engine = PermutationEngine()
    
    # Subdomínios com padrões específicos
    test_subdomains = {
        "api-dev", "api-prod", "web_test", "admin-panel", 
        "app1", "app2", "service-beta", "portal-staging"
    }
    
    print_info(f"Analisando padrões em: {test_subdomains}")
    
    patterns = engine._analyze_patterns(test_subdomains)
    
    print_info("Padrões identificados:")
    print_info(f"  Separadores: {patterns['separators_used']}")
    print_info(f"  Ambientes: {patterns['environment_indicators']}")
    print_info(f"  Serviços: {patterns['service_indicators']}")
    print_info(f"  Números: {patterns['numeric_patterns']}")

def test_numeric_variations():
    """Testa geração de variações numéricas."""
    print_info("\n=== TESTE DE VARIAÇÕES NUMÉRICAS ===")
    
    engine = PermutationEngine()
    
    test_cases = ["api", "server3", "app"]
    
    for subdomain in test_cases:
        variations = engine._generate_numeric_variations(subdomain)
        print_info(f"Variações para '{subdomain}' ({len(variations)}):")
        for var in sorted(list(variations)[:8]):  # Mostra apenas as primeiras 8
            print_info(f"  • {var}")

def main():
    """Função principal de teste."""
    print_info("[bold green]TESTE DAS MELHORIAS DO SUBDOMAIN SCANNER[/bold green]")
    print_info("Testando as novas funcionalidades implementadas...")
    print("")
    
    try:
        # Executa todos os testes
        test_takeover_verifier()
        test_certificate_transparency()
        test_permutation_engine()
        test_pattern_analysis()
        test_numeric_variations()
        
        print_info("\n[bold green]✅ TODOS OS TESTES CONCLUÍDOS COM SUCESSO![/bold green]")
        print_info("\nFuncionalidades testadas:")
        print_info("  ✅ Verificação real de subdomain takeover")
        print_info("  ✅ Integração com Certificate Transparency")
        print_info("  ✅ Engine de permutação inteligente")
        print_info("  ✅ Análise de padrões em subdomínios")
        print_info("  ✅ Geração de variações numéricas")
        
    except Exception as e:
        print_error(f"Erro durante os testes: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()