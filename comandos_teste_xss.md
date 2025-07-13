# 🔍 Comandos de Teste - XSS Scanner Melhorado

## 🚀 Comandos Rápidos (Uma Linha)

```bash
# 1. Teste básico
cd /home/spectra/Projetos/Spectra/spectra && python3 -c "from modules.xss_scanner import xss_scan; xss_scan('http://testphp.vulnweb.com/artists.php', verbose=True)"

# 2. Teste completo avançado
python3 -c "from modules.xss_scanner import xss_scan; print(f'Vulnerabilidades: {len(xss_scan(\"http://testphp.vulnweb.com/search.php\", scan_stored=True, test_headers=True, test_file_upload=True, parallel_testing=True, verbose=True, return_findings=True))}')"

# 3. Teste com Blind XSS
python3 -c "from modules.xss_scanner import xss_scan; xss_scan('http://testphp.vulnweb.com/guestbook.php', blind_xss_callback='https://webhook.site/YOUR-ID', scan_stored=True, verbose=True)"

# 4. Teste com payloads customizados
echo '<script>alert(1)</script>' > /tmp/payloads.txt && python3 -c "from modules.xss_scanner import xss_scan; xss_scan('http://testphp.vulnweb.com/artists.php', custom_payloads_file='/tmp/payloads.txt', verbose=True)"

# 5. Teste de performance (paralelo vs sequencial)
python3 -c "import time; from modules.xss_scanner import xss_scan; s=time.time(); v1=xss_scan('http://testphp.vulnweb.com/artists.php', parallel_testing=False, return_findings=True); t1=time.time()-s; s=time.time(); v2=xss_scan('http://testphp.vulnweb.com/artists.php', parallel_testing=True, return_findings=True); t2=time.time()-s; print(f'Seq: {t1:.2f}s ({len(v1)}) vs Par: {t2:.2f}s ({len(v2)}) - Speedup: {t1/t2:.1f}x')"

# 6. Teste apenas headers XSS
python3 -c "from modules.xss_scanner import xss_scan; xss_scan('http://exemplo.com', test_headers=True, scan_stored=False, fuzz_dom=False, test_file_upload=False, verbose=True)"

# 7. Teste múltiplas URLs
python3 -c "from modules.xss_scanner import xss_scan; [print(f'{url}: {len(xss_scan(url, verbose=False, return_findings=True))} vulns') for url in ['http://testphp.vulnweb.com/artists.php', 'http://testphp.vulnweb.com/search.php']]"

# 8. Validar funcionalidades instaladas
python3 -c "from modules.xss_scanner import XSSScanner; s=XSSScanner('http://test.com'); print(f'✓ Blind: {bool(hasattr(s, \"blind_xss_callback\"))}, Headers: {s.test_headers}, Upload: {s.test_file_upload}, Parallel: {s.parallel_testing}, Cache: {hasattr(s, \"tested_parameters\")}')"

# 9. Teste arquivo local simples
python3 test_xss_simple.py

# 10. Capturar estatísticas detalhadas
python3 -c "from modules.xss_scanner import XSSScanner; s=XSSScanner('http://testphp.vulnweb.com/artists.php'); s.run_scan(); print(f'Stats: {s.stats[\"total_requests\"]} requests, {s.stats[\"reflected_params\"]} reflected, WAF: {s.stats[\"waf_detected\"]}')"
```

## 📋 Preparação Rápida

```bash
cd /home/spectra/Projetos/Spectra/spectra && pip install requests beautifulsoup4 selenium websockets rich
```

## 🎯 URLs de Teste

```bash
# DVWA: http://dvwa.local/
# WebGoat: http://localhost:8080/WebGoat/
# TestPHP: http://testphp.vulnweb.com/artists.php
# Local: http://localhost:3000
```

## 📊 Tipos de Vulnerabilidades

- **XSS Refletido**: Payload refletido imediatamente
- **XSS Armazenado**: Payload persistiu na aplicação  
- **DOM XSS**: Executado via JavaScript no navegador
- **Blind XSS**: Payload submetido, verificar callback
- **XSS em Headers**: Detectado em User-Agent, Referer, etc.
- **XSS File Upload**: Arquivo malicioso aceito
- **WebSocket XSS**: Payload refletido em WebSocket
- **API/JSON XSS**: Payload refletido em endpoint de API
- **Template Injection**: Template engine vulnerável

## 🚨 Exemplo Completo

```bash
python3 -c "
from modules.xss_scanner import xss_scan
vulns = xss_scan(
    url='http://testphp.vulnweb.com/search.php',
    scan_stored=True,
    test_headers=True, 
    test_file_upload=True,
    parallel_testing=True,
    max_workers=5,
    verbose=True,
    return_findings=True
)
print(f'🎯 Total: {len(vulns)} vulnerabilidades encontradas')
types = {}
for v in vulns:
    t = v['Tipo']
    types[t] = types.get(t, 0) + 1
for tipo, count in types.items():
    print(f'  • {tipo}: {count}')
"
```