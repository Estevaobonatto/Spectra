#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Teste do IDOR Scanner - Spectra
Demonstra o uso do scanner IDOR com diferentes cenários
"""

import sys
import os

# Adiciona o diretório do projeto ao path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from spectra.modules.idor_scanner import idor_scan
from spectra.core import print_info, print_success, print_error

def test_idor_basic():
    """Teste básico do IDOR scanner."""
    print_info("=== TESTE BÁSICO IDOR SCANNER ===")
    
    # URL de exemplo com parâmetro ID
    test_url = "https://httpbin.org/get?id=123"
    
    print_info(f"Testando URL: {test_url}")
    
    try:
        vulnerabilities = idor_scan(
            url=test_url,
            enumerate_range=(1, 10),  # Range pequeno para teste
            test_uuid=False,
            test_hash=False,
            max_workers=5,
            delay=0.5  # Delay maior para ser respeitoso com o serviço
        )
        
        if vulnerabilities:
            print_success(f"Teste concluído - {len(vulnerabilities)} possíveis vulnerabilidades encontradas")
        else:
            print_info("Teste concluído - Nenhuma vulnerabilidade detectada")
            
    except Exception as e:
        print_error(f"Erro no teste: {e}")

def test_idor_path():
    """Teste do IDOR scanner com ID no path."""
    print_info("\n=== TESTE IDOR COM ID NO PATH ===")
    
    # URL de exemplo com ID no path
    test_url = "https://jsonplaceholder.typicode.com/users/1"
    
    print_info(f"Testando URL: {test_url}")
    
    try:
        vulnerabilities = idor_scan(
            url=test_url,
            enumerate_range=(1, 5),  # Range pequeno para teste
            test_uuid=False,
            test_hash=False,
            max_workers=3,
            delay=1.0  # Delay maior para ser respeitoso
        )
        
        if vulnerabilities:
            print_success(f"Teste concluído - {len(vulnerabilities)} possíveis vulnerabilidades encontradas")
        else:
            print_info("Teste concluído - Nenhuma vulnerabilidade detectada")
            
    except Exception as e:
        print_error(f"Erro no teste: {e}")

def test_idor_uuid():
    """Teste do IDOR scanner com UUIDs."""
    print_info("\n=== TESTE IDOR COM UUIDs ===")
    
    # URL de exemplo
    test_url = "https://httpbin.org/get?user_id=550e8400-e29b-41d4-a716-446655440000"
    
    print_info(f"Testando URL: {test_url}")
    
    try:
        vulnerabilities = idor_scan(
            url=test_url,
            enumerate_range=(1, 3),  # Range muito pequeno
            test_uuid=True,  # Ativa teste de UUIDs
            test_hash=False,
            max_workers=2,
            delay=1.0
        )
        
        if vulnerabilities:
            print_success(f"Teste concluído - {len(vulnerabilities)} possíveis vulnerabilidades encontradas")
        else:
            print_info("Teste concluído - Nenhuma vulnerabilidade detectada")
            
    except Exception as e:
        print_error(f"Erro no teste: {e}")

def demonstrate_cli_usage():
    """Demonstra como usar o IDOR scanner via CLI."""
    print_info("\n=== EXEMPLOS DE USO VIA CLI ===")
    
    examples = [
        "# Teste básico com range de IDs",
        "python -m spectra -idor http://example.com/user?id=123 --idor-range 1-100",
        "",
        "# Teste com UUIDs e hashes",
        "python -m spectra -idor http://api.com/profile/456 --test-uuid --test-hash",
        "",
        "# Teste com wordlist customizada",
        "python -m spectra -idor http://app.com/document?doc_id=789 --idor-wordlist custom_ids.txt",
        "",
        "# Teste com múltiplos métodos HTTP",
        "python -m spectra -idor http://secure.com/order/100 --idor-methods GET,POST,PUT,DELETE",
        "",
        "# Teste com configurações avançadas",
        "python -m spectra -idor http://admin.com/file?file_id=abc123 --idor-range 1-1000 --test-uuid --test-hash --workers 20 --idor-delay 0.05",
        "",
        "# Teste com ID no path da URL",
        "python -m spectra -idor http://site.com/users/123/profile --idor-range 1-500 --test-uuid"
    ]
    
    for example in examples:
        if example.startswith("#"):
            print_info(f"[bold cyan]{example}[/bold cyan]")
        elif example == "":
            print("")
        else:
            print_info(f"[dim]{example}[/dim]")

def main():
    """Função principal de teste."""
    print_info("[bold green]SPECTRA IDOR SCANNER - TESTES E DEMONSTRAÇÃO[/bold green]")
    print_info("Este script demonstra o uso do IDOR Scanner integrado ao Spectra")
    print("")
    
    # Executa testes básicos
    test_idor_basic()
    test_idor_path()
    test_idor_uuid()
    
    # Mostra exemplos de uso
    demonstrate_cli_usage()
    
    print_info("\n[bold green]FUNCIONALIDADES IMPLEMENTADAS:[/bold green]")
    features = [
        "✅ Detecção automática de parâmetros ID em URLs",
        "✅ Extração de IDs do path da URL",
        "✅ Teste com ranges numéricos configuráveis",
        "✅ Suporte a UUIDs (comuns e aleatórios)",
        "✅ Suporte a hashes (MD5, SHA1, SHA256)",
        "✅ Teste com múltiplos métodos HTTP",
        "✅ Wordlists customizadas",
        "✅ Análise de padrões de resposta",
        "✅ Detecção de dados sensíveis",
        "✅ Classificação de severidade",
        "✅ Threading paralelo otimizado",
        "✅ Rate limiting configurável",
        "✅ Relatórios detalhados com tabelas",
        "✅ Estatísticas de performance",
        "✅ Integração completa com CLI do Spectra"
    ]
    
    for feature in features:
        print_info(feature)
    
    print_info("\n[bold yellow]NOTA:[/bold yellow] Os testes usam serviços públicos como httpbin.org e jsonplaceholder.typicode.com")
    print_info("para demonstração. Em uso real, sempre obtenha autorização antes de testar.")

if __name__ == "__main__":
    main()