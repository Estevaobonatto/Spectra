#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Teste do modo verbose do Basic Vulnerability Scanner
"""

import sys
import os
import io
from contextlib import redirect_stdout, redirect_stderr
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'spectra'))

from spectra.modules.basic_vulnerability_scanner import BasicVulnerabilityScanner
from unittest.mock import Mock, patch
import requests


def capture_console_output(func, *args, **kwargs):
    """Captura a saída do console durante a execução de uma função."""
    # Captura stdout e stderr
    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()
    
    with redirect_stdout(stdout_capture), redirect_stderr(stderr_capture):
        try:
            result = func(*args, **kwargs)
        except Exception as e:
            result = None
    
    return {
        'result': result,
        'stdout': stdout_capture.getvalue(),
        'stderr': stderr_capture.getvalue()
    }


def test_verbose_mode_basic():
    """Testa se o modo verbose mostra informações básicas."""
    print("🔍 Testando modo verbose básico...")
    
    # Mock response simples
    mock_response = Mock()
    mock_response.text = '<html><body>Test page</body></html>'
    mock_response.content = mock_response.text.encode()
    mock_response.status_code = 200
    mock_response.headers = {'Content-Type': 'text/html'}
    mock_response.cookies = []
    
    # Testa sem verbose
    scanner_normal = BasicVulnerabilityScanner("https://example.com", verbose=False)
    
    with patch.object(scanner_normal.session, 'get', return_value=mock_response):
        output_normal = capture_console_output(scanner_normal._test_information_disclosure)
    
    # Testa com verbose
    scanner_verbose = BasicVulnerabilityScanner("https://example.com", verbose=True)
    
    with patch.object(scanner_verbose.session, 'get', return_value=mock_response):
        output_verbose = capture_console_output(scanner_verbose._test_information_disclosure)
    
    # Verifica se o modo verbose produz mais saída
    normal_lines = len(output_normal['stdout'].split('\n'))
    verbose_lines = len(output_verbose['stdout'].split('\n'))
    
    print(f"   ✓ Modo normal: {normal_lines} linhas de saída")
    print(f"   ✓ Modo verbose: {verbose_lines} linhas de saída")
    
    return verbose_lines > normal_lines


def test_verbose_configuration_display():
    """Testa se o modo verbose mostra as configurações."""
    print("⚙️ Testando exibição de configurações...")
    
    scanner = BasicVulnerabilityScanner("https://example.com", timeout=15, workers=20, verbose=True)
    
    # Mock para evitar requisições reais
    mock_response = Mock()
    mock_response.text = '<html><body>Test</body></html>'
    mock_response.content = mock_response.text.encode()
    mock_response.status_code = 200
    mock_response.headers = {}
    mock_response.cookies = []
    
    with patch.object(scanner.session, 'get', return_value=mock_response):
        output = capture_console_output(scanner.scan)
    
    stdout = output['stdout']
    
    # Verifica se as configurações aparecem na saída
    config_indicators = [
        "Configurações:",
        "Timeout: 15s",
        "Workers: 20",
        "URL Base: https://example.com"
    ]
    
    found_configs = 0
    for indicator in config_indicators:
        if indicator in stdout:
            found_configs += 1
            print(f"   ✓ Encontrado: {indicator}")
    
    print(f"   ✓ {found_configs}/{len(config_indicators)} configurações exibidas")
    
    return found_configs >= 3


def test_verbose_test_details():
    """Testa se o modo verbose mostra detalhes dos testes."""
    print("🔬 Testando detalhes dos testes...")
    
    scanner = BasicVulnerabilityScanner("https://example.com", verbose=True)
    
    # Mock response com informações sensíveis para testar information disclosure
    mock_response = Mock()
    mock_response.text = '''
    <html>
        <script>
            var api_key = "AKIAIOSFODNN7EXAMPLE";
            var password = "admin123";
        </script>
    </html>
    '''
    mock_response.content = mock_response.text.encode()
    mock_response.status_code = 200
    mock_response.headers = {}
    
    with patch.object(scanner.session, 'get', return_value=mock_response):
        output = capture_console_output(scanner._test_information_disclosure)
    
    stdout = output['stdout']
    
    # Verifica se os detalhes dos testes aparecem
    test_details = [
        "Analisando conteúdo da página principal",
        "Procurando por",
        "tipos de informações sensíveis",
        "detectado!"
    ]
    
    found_details = 0
    for detail in test_details:
        if detail in stdout:
            found_details += 1
            print(f"   ✓ Encontrado: {detail}")
    
    print(f"   ✓ {found_details}/{len(test_details)} detalhes de teste exibidos")
    
    return found_details >= 2


def test_verbose_vulnerability_detection():
    """Testa se o modo verbose mostra detecção de vulnerabilidades."""
    print("🚨 Testando detecção de vulnerabilidades...")
    
    scanner = BasicVulnerabilityScanner("https://example.com", verbose=True)
    
    # Mock response sem headers de segurança
    mock_response = Mock()
    mock_response.text = '<html><body>Test</body></html>'
    mock_response.content = mock_response.text.encode()
    mock_response.status_code = 200
    mock_response.headers = {'Content-Type': 'text/html'}  # Sem headers de segurança
    
    with patch.object(scanner.session, 'get', return_value=mock_response):
        output = capture_console_output(scanner._test_security_headers)
    
    stdout = output['stdout']
    
    # Verifica se as detecções aparecem
    detection_indicators = [
        "Analisando headers de segurança",
        "header(s) recebido(s)",
        "ausente"
    ]
    
    found_detections = 0
    for indicator in detection_indicators:
        if indicator in stdout:
            found_detections += 1
            print(f"   ✓ Encontrado: {indicator}")
    
    print(f"   ✓ {found_detections}/{len(detection_indicators)} indicadores de detecção")
    
    return found_detections >= 2


def test_verbose_open_redirect():
    """Testa se o modo verbose mostra detalhes do teste de open redirect."""
    print("🔄 Testando detalhes do Open Redirect...")
    
    scanner = BasicVulnerabilityScanner("https://example.com", verbose=True)
    
    # Mock response com redirecionamento
    mock_response = Mock()
    mock_response.status_code = 302
    mock_response.headers = {'Location': 'http://evil.com'}
    mock_response.text = ''
    mock_response.content = b''
    
    with patch.object(scanner.session, 'get', return_value=mock_response):
        # Testa apenas um parâmetro para simplificar
        test_url = f"{scanner.base_url}?redirect=http://evil.com"
        
        # Simula o teste de um parâmetro específico
        output = capture_console_output(lambda: scanner._test_open_redirect())
    
    stdout = output['stdout']
    
    # Verifica se os detalhes do teste aparecem
    redirect_details = [
        "Testando",
        "Status:",
        "Location:"
    ]
    
    found_redirect_details = 0
    for detail in redirect_details:
        if detail in stdout:
            found_redirect_details += 1
            print(f"   ✓ Encontrado: {detail}")
    
    print(f"   ✓ {found_redirect_details}/{len(redirect_details)} detalhes de redirect")
    
    return found_redirect_details >= 1


def test_verbose_rate_limiting():
    """Testa se o modo verbose mostra detalhes do teste de rate limiting."""
    print("⏱️ Testando detalhes do Rate Limiting...")
    
    scanner = BasicVulnerabilityScanner("https://example.com", verbose=True)
    
    # Mock responses para simular múltiplas requisições
    mock_responses = []
    for i in range(20):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_responses.append(mock_response)
    
    with patch.object(scanner.session, 'get', side_effect=mock_responses):
        output = capture_console_output(scanner._test_rate_limiting)
    
    stdout = output['stdout']
    
    # Verifica se os detalhes do rate limiting aparecem
    rate_limit_details = [
        "Enviando 20 requisições rápidas",
        "requisições bem-sucedidas em",
        "requisições com rate limiting"
    ]
    
    found_rate_details = 0
    for detail in rate_limit_details:
        if detail in stdout:
            found_rate_details += 1
            print(f"   ✓ Encontrado: {detail}")
    
    print(f"   ✓ {found_rate_details}/{len(rate_limit_details)} detalhes de rate limiting")
    
    return found_rate_details >= 2


def main():
    """Executa todos os testes do modo verbose."""
    print("🚀 Testando modo verbose do Basic Vulnerability Scanner\n")
    
    tests = [
        ("Modo Verbose Básico", test_verbose_mode_basic),
        ("Exibição de Configurações", test_verbose_configuration_display),
        ("Detalhes dos Testes", test_verbose_test_details),
        ("Detecção de Vulnerabilidades", test_verbose_vulnerability_detection),
        ("Open Redirect Verbose", test_verbose_open_redirect),
        ("Rate Limiting Verbose", test_verbose_rate_limiting)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result, None))
            print(f"   {'✅' if result else '❌'} {test_name}: {'PASSOU' if result else 'FALHOU'}\n")
        except Exception as e:
            results.append((test_name, False, str(e)))
            print(f"   ❌ {test_name}: ERRO - {e}\n")
    
    # Resumo final
    print("📊 RESUMO DOS TESTES VERBOSE:")
    print("=" * 50)
    
    passed = sum(1 for _, result, _ in results if result)
    total = len(results)
    
    for test_name, result, error in results:
        status = "✅ PASSOU" if result else f"❌ FALHOU{' - ' + error if error else ''}"
        print(f"{test_name:.<30} {status}")
    
    print("=" * 50)
    print(f"Total: {passed}/{total} testes passaram ({passed/total*100:.1f}%)")
    
    if passed == total:
        print("🎉 Modo verbose está funcionando corretamente!")
        print("\n💡 Para testar manualmente:")
        print("   python -m spectra -bvs https://httpbin.org --verbose")
    else:
        print("⚠️ Alguns testes do modo verbose falharam.")
    
    return passed == total


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)