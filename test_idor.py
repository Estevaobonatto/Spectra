#!/usr/bin/env python3
"""
Test script for IDOR scanner
"""

import sys
sys.path.append('/home/spectra/Projetos/Spectra')

from spectra.modules.idor_scanner import AdvancedIDORScanner

def test_idor_scanner():
    """Testa o scanner IDOR com configuração otimizada."""
    print("=== Teste do Scanner IDOR Avançado ===")
    
    # Configuração otimizada para teste
    scanner = AdvancedIDORScanner(
        base_url='https://httpbin.org/get?id=123',
        enumerate_range=(1, 5),  # Apenas 5 IDs
        test_uuid=False,
        test_hash=False,
        max_workers=3,
        delay=0.1
    )
    
    # Desabilita testes avançados para foco no básico
    scanner.test_timestamp_ids = False
    scanner.test_predictable_ids = False
    scanner.test_encoded_ids = False
    scanner.test_header_injection = False
    scanner.test_cookie_manipulation = False
    scanner.test_logic_flaws = False
    scanner.test_bypass_techniques = False
    
    print(f"Testando: {scanner.base_url}")
    print(f"Range: {scanner.enumerate_range}")
    print(f"Workers: {scanner.max_workers}")
    print("")
    
    try:
        # Executa o scan
        results = scanner.scan()
        
        print(f"\n=== Resultados ===")
        print(f"Vulnerabilidades encontradas: {len(results)}")
        
        if results:
            print("\nDetalhes das vulnerabilidades:")
            for i, vuln in enumerate(results, 1):
                print(f"{i}. URL: {vuln.url}")
                print(f"   Método: {vuln.method}")
                print(f"   Parâmetro: {vuln.parameter}")
                print(f"   Valor testado: {vuln.test_value}")
                print(f"   Status: {vuln.status_code}")
                print(f"   Severidade: {vuln.severity.value}")
                print(f"   Confiança: {vuln.confidence:.2f}")
                print(f"   Indicadores: {', '.join(vuln.indicators[:3])}")
                print("")
        
        # Mostra estatísticas
        stats = scanner.get_scan_statistics()
        print("=== Estatísticas ===")
        print(f"Tempo total: {stats['scan_duration']:.2f}s")
        print(f"Requisições feitas: {stats['total_requests']}")
        print(f"Taxa de sucesso: {stats['success_rate']:.2%}")
        print(f"Dados sensíveis: {stats['sensitive_data_found']}")
        print(f"Rate limit: {stats['rate_limited_responses']}")
        
        return results
        
    except Exception as e:
        print(f"Erro durante o teste: {e}")
        return []

if __name__ == "__main__":
    test_idor_scanner()