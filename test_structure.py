#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Teste básico para verificar se a estrutura modular está funcionando
"""

def test_imports():
    """Testa se todos os imports estão funcionando."""
    print("🔍 Testando imports...")
    
    try:
        # Testa import principal
        import spectra
        print("✅ Import principal: OK")
        
        # Testa core components
        from spectra.core import console, config, display_banner
        print("✅ Core components: OK")
        
        # Testa utils
        from spectra.utils import parse_ports, validate_url, normalize_url
        print("✅ Utils: OK")
        
        # Testa módulos
        from spectra.modules.port_scanner import scan_ports, AdvancedPortScanner
        print("✅ Port Scanner: OK")
        
        from spectra.modules.banner_grabber import BannerGrabber
        print("✅ Banner Grabber: OK")
        
        from spectra.modules.directory_scanner import AdvancedDirectoryScanner, advanced_directory_scan
        print("✅ Directory Scanner: OK")
        
        from spectra.modules.metadata_extractor import MetadataExtractor, extract_metadata
        print("✅ Metadata Extractor: OK")
        
        from spectra.modules.subdomain_scanner import SubdomainScanner, discover_subdomains
        print("✅ Subdomain Scanner: OK")
        
        from spectra.modules.dns_analyzer import DNSAnalyzer, query_dns
        print("✅ DNS Analyzer: OK")
        
        from spectra.modules.whois_analyzer import WhoisAnalyzer, get_whois_info
        print("✅ WHOIS Analyzer: OK")
        
        # Testa CLI
        from spectra.cli.main import main
        print("✅ CLI: OK")
        
        return True
        
    except ImportError as e:
        print(f"❌ Erro de import: {e}")
        return False

def test_basic_functionality():
    """Testa funcionalidades básicas."""
    print("\n🧪 Testando funcionalidades básicas...")
    
    try:
        # Testa parse de portas
        from spectra.utils import parse_ports
        ports = parse_ports("80,443,22")
        assert ports == [22, 80, 443], "Parse de portas falhou"
        print("✅ Parse de portas: OK")
        
        # Testa validação de URL
        from spectra.utils import validate_url
        valid, url = validate_url("example.com")
        assert valid == True, "Validação de URL falhou"
        print("✅ Validação de URL: OK")
        
        # Testa banner
        from spectra.core import display_banner
        print("✅ Banner: OK")
        
        return True
        
    except Exception as e:
        print(f"❌ Erro de funcionalidade: {e}")
        return False

def test_module_initialization():
    """Testa inicialização dos módulos (sem fazer operações reais)."""
    print("\n� Testando inicialização dos módulos...")
    
    try:
        from spectra.modules.port_scanner import AdvancedPortScanner
        scanner = AdvancedPortScanner("127.0.0.1", verbose=False)
        scanner.resolve_target()
        print("✅ Port Scanner inicialização: OK")
        
        from spectra.modules.banner_grabber import BannerGrabber
        grabber = BannerGrabber(timeout=1)
        print("✅ Banner Grabber inicialização: OK")
        
        from spectra.modules.directory_scanner import AdvancedDirectoryScanner
        dir_scanner = AdvancedDirectoryScanner("http://example.com", None, workers=1)
        print("✅ Directory Scanner inicialização: OK")
        
        from spectra.modules.metadata_extractor import MetadataExtractor
        metadata_extractor = MetadataExtractor(timeout=1)
        print("✅ Metadata Extractor inicialização: OK")
        
        from spectra.modules.subdomain_scanner import SubdomainScanner
        sub_scanner = SubdomainScanner("example.com", None, workers=1)
        print("✅ Subdomain Scanner inicialização: OK")
        
        from spectra.modules.dns_analyzer import DNSAnalyzer
        dns_analyzer = DNSAnalyzer(timeout=1)
        print("✅ DNS Analyzer inicialização: OK")
        
        from spectra.modules.whois_analyzer import WhoisAnalyzer
        whois_analyzer = WhoisAnalyzer(timeout=1)
        print("✅ WHOIS Analyzer inicialização: OK")
        
        return True
        
    except Exception as e:
        print(f"❌ Erro na inicialização dos módulos: {e}")
        return False

def test_legacy_functions():
    """Testa funções de compatibilidade legacy."""
    print("\n🔄 Testando funções de compatibilidade legacy...")
    
    try:
        # Testa funções legacy (sem executar)
        from spectra.modules.port_scanner import scan_ports
        from spectra.modules.directory_scanner import check_directory
        from spectra.modules.metadata_extractor import extract_metadata
        from spectra.modules.subdomain_scanner import check_subdomain, discover_subdomains
        from spectra.modules.dns_analyzer import query_dns
        from spectra.modules.whois_analyzer import get_whois_info
        
        print("✅ Funções legacy importadas: OK")
        
        return True
        
    except Exception as e:
        print(f"❌ Erro nas funções legacy: {e}")
        return False

def main():
    """Função principal de teste."""
    print("🚀 Iniciando testes da estrutura modular do Spectra...\n")
    
    tests = [
        ("Imports", test_imports),
        ("Funcionalidades Básicas", test_basic_functionality),
        ("Inicialização dos Módulos", test_module_initialization),
        ("Funções Legacy", test_legacy_functions)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"📋 {test_name}:")
        if test_func():
            passed += 1
            print(f"✅ {test_name}: PASSOU\n")
        else:
            print(f"❌ {test_name}: FALHOU\n")
    
    print("="*50)
    print(f"📊 Resultados: {passed}/{total} testes passaram")
    
    if passed == total:
        print("🎉 Todos os testes passaram! A estrutura modular está funcionando.")
        print("\n📚 Módulos refatorados com sucesso:")
        print("   • Core: config, console, banner, logger")
        print("   • Utils: network, parsers, validators")
        print("   • Modules: port_scanner, banner_grabber, directory_scanner,")
        print("             metadata_extractor, subdomain_scanner, dns_analyzer, whois_analyzer")
        print("   • CLI: main interface com todos os módulos")
        return True
    else:
        print("⚠️ Alguns testes falharam. Verifique os erros acima.")
        return False

if __name__ == '__main__':
    success = main()
    exit(0 if success else 1)
