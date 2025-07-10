#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Teste simples do WAF Detector
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_waf_detector():
    """Testa o WAF Detector com um site conhecido por ter Cloudflare."""
    try:
        from spectra.modules.waf_detector import AdvancedWAFDetector
        
        print("🧪 Testando WAF Detector...")
        print("-" * 50)
        
        # Teste com sites que têm WAF conhecidos
        test_sites = [
            "https://httpbin.org",  # Sem WAF
            "https://www.shopify.com",  # Cloudflare
            "https://github.com",  # Github Pages
        ]
        # Teste com sites que têm WAF conhecidos
        test_sites = [
            "https://httpbin.org",  # Sem WAF
            "https://www.shopify.com",  # Cloudflare
            "https://github.com",  # Github Pages
        ]
        
        for test_url in test_sites:
            print(f"\n📡 Testando detecção de WAF em: {test_url}")
            print("-" * 60)
            
            detector = AdvancedWAFDetector(test_url)
            
            # Executa detecção
            results = detector.detect_waf(verbose=False, timing_analysis=False)
            
            print(f"WAFs detectados: {len(results['detected_wafs'])}")
            
            if results['detected_wafs']:
                for waf in results['detected_wafs']:
                    print(f"  ✅ {waf['name']} ({waf['type']}) - Confiança: {waf['confidence']}%")
                    if waf['sources']:
                        print(f"     Fontes: {', '.join(waf['sources'][:3])}")
            else:
                print("  ❌ Nenhum WAF detectado")
        
        print("\n🎨 Teste de formatação com o primeiro site:")
        detector = AdvancedWAFDetector(test_sites[0])
        results = detector.detect_waf(verbose=True, timing_analysis=True)
        detector.present_results()
        
        print("\n✅ Teste concluído com sucesso!")
        return True
        
    except Exception as e:
        print(f"❌ Erro no teste: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_waf_detector()
    sys.exit(0 if success else 1)
