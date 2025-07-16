#!/usr/bin/env python3
"""
Teste e demonstração do XXE Scanner - Spectra Security Suite
"""

import asyncio
import sys
import os

# Adiciona o diretório do projeto ao path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from spectra.modules.xxe_scanner import xxe_scan, XXEScanner
from spectra.core import print_info, print_success, print_warning, print_error

def test_xxe_basic():
    """Teste básico do XXE Scanner."""
    print_info("\n[bold blue]TESTE 1: XXE Scanner Básico[/bold blue]")
    print_info("Testando detecção de vulnerabilidades XXE...")
    
    # URL de teste que aceita XML (simulado)
    test_url = "http://httpbin.org/post"
    
    try:
        # Executa scan básico
        results = asyncio.run(xxe_scan(
            url=test_url,
            max_workers=5,
            timeout=10,
            return_findings=True
        ))
        
        if results:
            print_success(f"✓ Scan executado com sucesso - {len(results)} vulnerabilidades encontradas")
            for result in results[:3]:  # Mostra apenas as primeiras 3
                print_info(f"  - {result.vulnerability_type}: {result.evidence}")
        else:
            print_info("✓ Scan executado - Nenhuma vulnerabilidade XXE encontrada")
            
    except Exception as e:
        print_error(f"✗ Erro no teste básico: {e}")

def test_xxe_with_collaborator():
    """Teste com servidor colaborador para Blind XXE."""
    print_info("\n[bold blue]TESTE 2: XXE com Servidor Colaborador[/bold blue]")
    print_info("Testando detecção de Blind XXE...")
    
    # URL de colaborador simulada
    collaborator_url = "http://your-collaborator.com"
    test_url = "http://httpbin.org/post"
    
    try:
        results = asyncio.run(xxe_scan(
            url=test_url,
            collaborator_url=collaborator_url,
            max_workers=3,
            return_findings=True
        ))
        
        if results:
            blind_xxe = [r for r in results if 'blind' in r.payload_type]
            print_success(f"✓ Teste com colaborador executado - {len(blind_xxe)} blind XXE encontrados")
        else:
            print_info("✓ Teste com colaborador executado - Nenhum blind XXE encontrado")
            
    except Exception as e:
        print_error(f"✗ Erro no teste com colaborador: {e}")

def test_xxe_file_disclosure():
    """Teste específico para file disclosure."""
    print_info("\n[bold blue]TESTE 3: XXE File Disclosure[/bold blue]")
    print_info("Testando payloads de file disclosure...")
    
    test_url = "http://httpbin.org/post"
    
    try:
        scanner = XXEScanner(
            target_url=test_url,
            max_workers=3,
            timeout=8
        )
        
        # Testa apenas payloads de file disclosure
        results = asyncio.run(scanner.scan())
        
        file_disclosures = [r for r in results if 'file_disclosure' in r.payload_type]
        
        if file_disclosures:
            print_success(f"✓ File disclosure test - {len(file_disclosures)} vulnerabilidades encontradas")
            for result in file_disclosures[:2]:
                print_info(f"  - Arquivo: {result.payload_type}")
                print_info(f"  - Evidência: {result.evidence}")
        else:
            print_info("✓ File disclosure test executado - Nenhuma vulnerabilidade encontrada")
            
    except Exception as e:
        print_error(f"✗ Erro no teste de file disclosure: {e}")

def test_xxe_ssrf():
    """Teste específico para SSRF via XXE."""
    print_info("\n[bold blue]TESTE 4: XXE SSRF Detection[/bold blue]")
    print_info("Testando detecção de SSRF via XXE...")
    
    test_url = "http://httpbin.org/post"
    
    try:
        results = asyncio.run(xxe_scan(
            url=test_url,
            max_workers=5,
            return_findings=True
        ))
        
        ssrf_findings = [r for r in results if r.payload_type == 'ssrf']
        
        if ssrf_findings:
            print_success(f"✓ SSRF test - {len(ssrf_findings)} vulnerabilidades SSRF encontradas")
            for result in ssrf_findings[:2]:
                print_info(f"  - Target: {result.url}")
                print_info(f"  - Evidência: {result.evidence}")
        else:
            print_info("✓ SSRF test executado - Nenhuma vulnerabilidade SSRF encontrada")
            
    except Exception as e:
        print_error(f"✗ Erro no teste SSRF: {e}")

def test_xxe_dos():
    """Teste para DoS via XXE."""
    print_info("\n[bold blue]TESTE 5: XXE DoS Detection[/bold blue]")
    print_info("Testando payloads de DoS (Billion Laughs, etc.)...")
    
    test_url = "http://httpbin.org/post"
    
    try:
        results = asyncio.run(xxe_scan(
            url=test_url,
            max_workers=2,  # Menos workers para DoS
            timeout=15,     # Timeout maior para detectar DoS
            return_findings=True
        ))
        
        dos_findings = [r for r in results if 'dos' in r.payload_type]
        
        if dos_findings:
            print_success(f"✓ DoS test - {len(dos_findings)} vulnerabilidades DoS encontradas")
            for result in dos_findings:
                print_info(f"  - Tipo: {result.vulnerability_type}")
                print_info(f"  - Tempo de resposta: {result.response_time:.2f}s")
        else:
            print_info("✓ DoS test executado - Nenhuma vulnerabilidade DoS encontrada")
            
    except Exception as e:
        print_error(f"✗ Erro no teste DoS: {e}")

def test_xxe_export():
    """Teste de exportação de resultados."""
    print_info("\n[bold blue]TESTE 6: Exportação de Resultados[/bold blue]")
    print_info("Testando exportação em diferentes formatos...")
    
    test_url = "http://httpbin.org/post"
    
    try:
        scanner = XXEScanner(target_url=test_url, max_workers=3)
        results = asyncio.run(scanner.scan())
        
        # Testa exportação JSON
        json_export = scanner.export_results(results, 'json')
        print_success(f"✓ Exportação JSON: {len(json_export)} caracteres")
        
        # Testa exportação XML
        xml_export = scanner.export_results(results, 'xml')
        print_success(f"✓ Exportação XML: {len(xml_export)} caracteres")
        
        # Testa exportação CSV
        csv_export = scanner.export_results(results, 'csv')
        print_success(f"✓ Exportação CSV: {len(csv_export)} caracteres")
        
        # Salva exemplo JSON
        with open('xxe_scan_results.json', 'w', encoding='utf-8') as f:
            f.write(json_export)
        print_info("✓ Resultados salvos em xxe_scan_results.json")
        
    except Exception as e:
        print_error(f"✗ Erro no teste de exportação: {e}")

def demonstrate_cli_usage():
    """Demonstra uso via CLI."""
    print_info("\n[bold green]EXEMPLOS DE USO VIA CLI:[/bold green]")
    
    examples = [
        "# Scan básico de XXE",
        "python -m spectra xxe --url https://example.com/api",
        "",
        "# Scan com servidor colaborador para Blind XXE",
        "python -m spectra xxe --url https://example.com/api --collaborator http://your-server.com",
        "",
        "# Scan com payloads customizados",
        "python -m spectra xxe --url https://example.com/api --custom-payloads xxe_payloads.txt",
        "",
        "# Scan com configurações avançadas",
        "python -m spectra xxe --url https://example.com/api --max-workers 15 --timeout 20",
        "",
        "# Exportar resultados",
        "python -m spectra xxe --url https://example.com/api --output results.json --format json"
    ]
    
    for example in examples:
        if example.startswith('#'):
            print_info(f"[bold cyan]{example}[/bold cyan]")
        elif example.startswith('python'):
            print_info(f"[green]{example}[/green]")
        else:
            print_info(example)

def test_payload_generation():
    """Teste do gerador de payloads."""
    print_info("\n[bold blue]TESTE 7: Geração de Payloads[/bold blue]")
    print_info("Testando gerador de payloads XXE...")
    
    try:
        from spectra.modules.xxe_scanner import XXEPayloadGenerator
        
        # Sem colaborador
        generator = XXEPayloadGenerator()
        payloads = generator.get_all_payloads()
        
        print_success(f"✓ Gerados {len(payloads)} payloads sem colaborador")
        
        # Categorias de payloads
        categories = {}
        for payload in payloads:
            category = payload['type'].split('_')[0]
            categories[category] = categories.get(category, 0) + 1
        
        print_info("Distribuição por categoria:")
        for category, count in categories.items():
            print_info(f"  - {category}: {count} payloads")
        
        # Com colaborador
        generator_with_collab = XXEPayloadGenerator("http://collaborator.com")
        payloads_with_collab = generator_with_collab.get_all_payloads()
        
        print_success(f"✓ Gerados {len(payloads_with_collab)} payloads com colaborador")
        
        # Mostra exemplos de payloads
        print_info("\nExemplos de payloads:")
        for i, payload in enumerate(payloads[:3]):
            print_info(f"  {i+1}. {payload['description']}")
            print_info(f"     Tipo: {payload['type']}")
        
    except Exception as e:
        print_error(f"✗ Erro no teste de payloads: {e}")

def main():
    """Função principal de teste."""
    print_info("[bold green]SPECTRA XXE SCANNER - TESTES E DEMONSTRAÇÃO[/bold green]")
    print_info("Este script demonstra o uso do XXE Scanner integrado ao Spectra")
    print("")
    
    # Executa testes
    test_payload_generation()
    test_xxe_basic()
    test_xxe_with_collaborator()
    test_xxe_file_disclosure()
    test_xxe_ssrf()
    test_xxe_dos()
    test_xxe_export()
    
    # Mostra exemplos de uso
    demonstrate_cli_usage()
    
    print_info("\n[bold green]FUNCIONALIDADES IMPLEMENTADAS:[/bold green]")
    features = [
        "✅ Descoberta automática de endpoints XML",
        "✅ Detecção de file disclosure via XXE",
        "✅ Detecção de SSRF via XXE",
        "✅ Detecção de Blind XXE com colaborador",
        "✅ Detecção de DoS (Billion Laughs, Quadratic Blowup)",
        "✅ Bypass de WAF com encoding variations",
        "✅ Suporte a payloads customizados",
        "✅ Threading paralelo otimizado",
        "✅ Rate limiting adaptativo",
        "✅ Análise de Content-Type e headers",
        "✅ Múltiplos formatos de export (JSON, XML, CSV)",
        "✅ Estatísticas detalhadas de performance",
        "✅ Integração completa com CLI do Spectra",
        "✅ Logging detalhado para debugging",
        "✅ Tratamento robusto de erros"
    ]
    
    for feature in features:
        print_info(feature)
    
    print_info("\n[bold yellow]NOTA:[/bold yellow] Os testes usam httpbin.org para demonstração.")
    print_info("Em uso real, sempre obtenha autorização antes de testar.")
    print_info("\n[bold red]IMPORTANTE:[/bold red] Configure um servidor colaborador para testes completos de Blind XXE.")

if __name__ == "__main__":
    main()