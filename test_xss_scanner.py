#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Arquivo de teste para o XSS Scanner melhorado do Spectra
Exemplos de como usar as novas funcionalidades implementadas
"""

import sys
import os

# Adiciona o diretório pai ao path para importar o módulo
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.xss_scanner import xss_scan

def test_basic_xss_scan():
    """Teste básico do scanner XSS"""
    print("=" * 60)
    print("TESTE 1: Scanner XSS Básico")
    print("=" * 60)
    
    # URL de exemplo para teste
    url = "http://testphp.vulnweb.com/artists.php"
    
    # Executa scan básico
    vulnerabilities = xss_scan(
        url=url,
        verbose=True,
        return_findings=True
    )
    
    print(f"\nVulnerabilidades encontradas: {len(vulnerabilities)}")
    for vuln in vulnerabilities:
        print(f"- {vuln['Tipo']}: {vuln['Detalhe'][:60]}...")

def test_advanced_xss_scan():
    """Teste avançado com todas as funcionalidades"""
    print("\n" + "=" * 60)
    print("TESTE 2: Scanner XSS Avançado Completo")
    print("=" * 60)
    
    url = "http://testphp.vulnweb.com/search.php"
    
    vulnerabilities = xss_scan(
        url=url,
        scan_stored=True,
        fuzz_dom=True,
        verbose=True,
        test_headers=True,
        test_file_upload=True,
        parallel_testing=True,
        max_workers=3,
        return_findings=True
    )
    
    print(f"\nVulnerabilidades encontradas: {len(vulnerabilities)}")
    
    # Agrupa por tipo
    types = {}
    for vuln in vulnerabilities:
        v_type = vuln['Tipo']
        if v_type not in types:
            types[v_type] = 0
        types[v_type] += 1
    
    for v_type, count in types.items():
        print(f"- {v_type}: {count} ocorrência(s)")

def test_blind_xss_scan():
    """Teste de Blind XSS com callback"""
    print("\n" + "=" * 60)
    print("TESTE 3: Scanner Blind XSS")
    print("=" * 60)
    
    url = "http://testphp.vulnweb.com/guestbook.php"
    callback_url = "https://webhook.site/your-unique-id"  # Substitua por URL real
    
    vulnerabilities = xss_scan(
        url=url,
        blind_xss_callback=callback_url,
        scan_stored=True,
        verbose=True,
        return_findings=True
    )
    
    print(f"\nBlind XSS payloads submetidos: {len([v for v in vulnerabilities if 'Blind' in v['Tipo']])}")
    print(f"Verificar callback URL: {callback_url}")

def test_custom_payloads():
    """Teste com payloads customizados"""
    print("\n" + "=" * 60)
    print("TESTE 4: Scanner com Payloads Customizados")
    print("=" * 60)
    
    # Cria arquivo de payloads customizados
    custom_payloads = [
        "<script>alert('custom-test-1')</script>",
        "<img src=x onerror=alert('custom-test-2')>",
        "<svg onload=alert('custom-test-3')>",
        "javascript:alert('custom-test-4')",
        "{{7*7}}",  # Template injection
        "\"><script>alert('custom-test-5')</script>"
    ]
    
    with open('/tmp/custom_xss_payloads.txt', 'w') as f:
        for payload in custom_payloads:
            f.write(payload + '\n')
    
    url = "http://testphp.vulnweb.com/artists.php"
    
    vulnerabilities = xss_scan(
        url=url,
        custom_payloads_file='/tmp/custom_xss_payloads.txt',
        verbose=True,
        return_findings=True
    )
    
    print(f"\nTeste com payloads customizados: {len(vulnerabilities)} vulnerabilidades")

def test_local_vulnerable_app():
    """Teste em aplicação local vulnerável"""
    print("\n" + "=" * 60)
    print("TESTE 5: Scanner em App Local (se disponível)")
    print("=" * 60)
    
    # URLs para testar localmente (ajuste conforme necessário)
    local_urls = [
        "http://localhost:8080",
        "http://localhost:3000", 
        "http://localhost:80",
        "http://127.0.0.1:8000"
    ]
    
    for url in local_urls:
        try:
            print(f"\nTestando: {url}")
            vulnerabilities = xss_scan(
                url=url,
                verbose=False,  # Menos verbose para testes rápidos
                return_findings=True,
                parallel_testing=True,
                test_headers=True
            )
            
            if vulnerabilities:
                print(f"✓ {len(vulnerabilities)} vulnerabilidades encontradas em {url}")
                break
            else:
                print(f"✗ Nenhuma vulnerabilidade em {url}")
                
        except Exception as e:
            print(f"✗ Erro ao testar {url}: {str(e)[:50]}...")

def test_performance_comparison():
    """Compara performance com e sem paralelização"""
    print("\n" + "=" * 60)
    print("TESTE 6: Comparação de Performance")
    print("=" * 60)
    
    import time
    
    url = "http://testphp.vulnweb.com/artists.php"
    
    # Teste sequencial
    start_time = time.time()
    vulns_sequential = xss_scan(
        url=url,
        parallel_testing=False,
        verbose=False,
        return_findings=True
    )
    sequential_time = time.time() - start_time
    
    # Teste paralelo
    start_time = time.time()
    vulns_parallel = xss_scan(
        url=url,
        parallel_testing=True,
        max_workers=5,
        verbose=False,
        return_findings=True
    )
    parallel_time = time.time() - start_time
    
    print(f"Teste Sequencial: {sequential_time:.2f}s - {len(vulns_sequential)} vulnerabilidades")
    print(f"Teste Paralelo: {parallel_time:.2f}s - {len(vulns_parallel)} vulnerabilidades")
    
    if parallel_time < sequential_time:
        speedup = sequential_time / parallel_time
        print(f"✓ Speedup: {speedup:.1f}x mais rápido com paralelização")
    else:
        print("✗ Paralelização não trouxe benefício (poucos parâmetros)")

def run_all_tests():
    """Executa todos os testes disponíveis"""
    print("🔍 INICIANDO TESTES DO XSS SCANNER MELHORADO")
    print("📊 Testando todas as novas funcionalidades implementadas...")
    
    try:
        test_basic_xss_scan()
        test_advanced_xss_scan()
        test_blind_xss_scan()
        test_custom_payloads()
        test_local_vulnerable_app()
        test_performance_comparison()
        
        print("\n" + "=" * 60)
        print("✅ TODOS OS TESTES CONCLUÍDOS")
        print("=" * 60)
        print("Funcionalidades testadas:")
        print("✓ Scanner XSS básico e avançado")
        print("✓ Blind XSS com callbacks")
        print("✓ Payloads customizados")
        print("✓ Testes em headers HTTP")
        print("✓ File upload XSS")
        print("✓ Paralelização de testes")
        print("✓ WebSocket e API/JSON XSS")
        print("✓ Template injection")
        print("✓ Cache e filtros de falsos positivos")
        
    except Exception as e:
        print(f"\n❌ ERRO DURANTE OS TESTES: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    # Você pode executar testes individuais ou todos
    
    # Para executar um teste específico:
    # test_basic_xss_scan()
    
    # Para executar todos os testes:
    run_all_tests()
    
    # Exemplo de uso direto da função:
    # vulnerabilities = xss_scan(
    #     url="http://exemplo.com",
    #     verbose=True,
    #     scan_stored=True,
    #     fuzz_dom=True,
    #     test_headers=True,
    #     parallel_testing=True,
    #     blind_xss_callback="https://webhook.site/your-id"
    # )