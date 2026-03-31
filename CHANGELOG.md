# Changelog

Todas as mudanças notáveis neste projeto serão documentadas neste arquivo.

O formato é baseado em [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
e este projeto adere ao [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.1] - 2026-03-31

### Changed
- Reorganização da estrutura do projeto: payloads movidos para `spectra/data/payloads/`, wordlists soltas para `spectra/data/wordlists/`
- `build.ps1` atualizado para v2.0.1; `safety` substituído por `pip-audit`; referência ao `release-check.ps1` removida
- `.gitignore` expandido para cobrir `.spectra_cache/`, novos paths de wordlists e artefatos de release locais

### Removed
- Scripts legados `publish.ps1` e `release-check.ps1` (substituídos pelo workflow CI/CD `.github/workflows/release.yml`)
- `.pypirc-example` (autenticação agora via OIDC Trusted Publisher)
- Arquivos de saída de scan comprometidos na raiz (`xxe_scan_results.json`, `report.html`)
- `release.md` temporário

### Fixed
- CI/CD (`release.yml`) agora é o único ponto de publicação no PyPI — sem tokens em disco

## [2.0.0] - 2026-03-31

### Added
- **CI/CD completo**: `.github/workflows/ci.yml` (lint + tests + pip-audit em Python 3.9–3.12) e `.github/workflows/release.yml` (build → GitHub Release → PyPI via OIDC Trusted Publisher)
- **OAST client** (`spectra/utils/oast.py`): suporte ao protocolo Interactsh para detecção blind de XXE, SSRF, XSS e Command Injection
- **Blind XSS** via OAST no `xss_scanner.py` + mXSS/DOM clobbering payloads
- **SSRF blind** via OAST + DNS rebinding (`nip.io`) no `ssrf_scanner.py`
- **Command Injection OOB DNS** via OAST + timing adaptativo no `command_injection_scanner.py`
- **PHP filter chain** + log poisoning no `lfi_scanner.py`
- **SQLi UNION fingerprinting** automático (ORDER BY N), baseline anti-FP, payloads por DBMS no `sql_injection_scanner.py`
- **Passive subdomain enumeration** via `crt.sh` + HackerTarget + RapidDNS
- **DNSSEC validation**, AXFR zone transfer attempt e DMARC deep analysis no `dns_analyzer.py`
- **WAF bypass strategies** por produto (Cloudflare, ModSecurity, AWS WAF) no `waf_detector.py`
- **CSP directive-level parsing** e CORS misconfiguration no `headers_analyzer.py`
- **OCSP validation** em tempo real via AIA extension no `ssl_analyzer.py`
- **Favicon hash fingerprinting** + JS globals detection no `technology_detector.py`
- **OS fingerprinting por TTL** no `port_scanner.py`
- **Protocol-specific probes** (29 portas) + `grab_multiple_banners()` paralelo no `banner_grabber.py`
- **Rich Live dashboard** + psutil fallback (Windows) no `network_monitor.py`
- **EPSS scoring** (FIRST.org), **CISA KEV** check e **SQLite cache** no `cve_integrator.py`
- **NVD API key** via env `SPECTRA_NVD_API_KEY` (50 req/30s)
- **CLI modernizada**: `show_rich_help()` com tabelas categorizadas; novos flags `--xss-oast`, `--cmdi-oast`, `--cve-epss`, `--cve-kev`, `--banner-ports`

### Fixed
- Bug crítico de indentação no `command_injection_scanner.py` (variantes de evasão geradas apenas 1× em vez de por-payload)
- `metadata_extractor.py`: `img._getexif()` → `img.getexif()` (Pillow 10+)
- `ssrf_scanner.py`: remoção de indicadores genéricos de falso-positivo (`Server:`, `HTTP/1.`, etc.)
- `xxe_scanner.py`: `asyncio.run()` falhava em event loops já ativos
- `directory_scanner.py` e `port_scanner.py`: `pass` nu em excepts substituído por `logger.debug()`

## [1.0.0] - 2024-12-XX - 🎉 PRIMEIRO LANÇAMENTO OFICIAL

### 🚀 Funcionalidades Principais
- **15+ Módulos de Segurança**: SQL Injection, XSS, IDOR, XXE, Command Injection, LFI/RFI
- **Scanner de Diretórios Avançado**: Competitivo com Dirsearch/Feroxbuster/Gobuster
- **Hash Cracker GPU**: 27+ algoritmos, 11 modos de ataque, aceleração CUDA/OpenCL
- **Network Monitor**: Interface TUI similar ao Wireshark para análise de tráfego
- **Detector de Tecnologias**: 500+ tecnologias web suportadas
- **Basic Vulnerability Scanner**: Scanner de vulnerabilidades básicas web

### 🔍 Módulos de Scanning
- **Port Scanner**: TCP, SYN e UDP com detecção de serviços
- **Directory Scanner**: Descoberta de diretórios e arquivos com performance otimizada
- **Subdomain Scanner**: Descoberta passiva e ativa com Certificate Transparency
- **SQL Injection Scanner**: Detecção avançada com bypass de WAF
- **XSS Scanner**: Stored, Reflected e DOM XSS
- **Command Injection Scanner**: Detecção de injeção de comandos OS
- **LFI/RFI Scanner**: Local e Remote File Inclusion
- **XXE Scanner**: XML External Entity com OAST
- **IDOR Scanner**: Insecure Direct Object Reference

### 🛡️ Análise de Segurança
- **WAF Detector**: Detecção e bypass de Web Application Firewall
- **SSL/TLS Analyzer**: Análise completa de certificados e configurações
- **Headers Analyzer**: Verificação de headers de segurança HTTP
- **Banner Grabber**: Identificação de serviços e versões
- **Metadata Extractor**: Extração de metadados de imagens

### 🔧 Funcionalidades Avançadas
- **Sistema de Help**: Metadata estruturada com instruções de teste
- **Modo Verbose**: Logs detalhados para debugging e aprendizado
- **Performance Extrema**: Multi-threading, connection pooling, rate limiting adaptativo
- **Rainbow Tables**: Lookup instantâneo O(1) para quebra de hashes
- **GPU Acceleration**: Suporte CUDA/OpenCL para hash cracking

### 🔒 Segurança e Qualidade
- **Rate Limiting**: Proteção contra DoS acidental
- **Validação de Entrada**: Sanitização completa de inputs
- **Logs Seguros**: Prevenção de log injection
- **Testes Automatizados**: Cobertura de testes abrangente
- **CI/CD Pipeline**: Verificações automáticas de segurança e qualidade

### 📚 Documentação
- **README Completo**: Guia de instalação e uso
- **CONTRIBUTING**: Guia para contribuidores
- **SECURITY**: Política de segurança e uso ético
- **LICENSE**: Licença MIT com disclaimer ético

---

## 🔗 Links

- [Releases](https://github.com/spectra-team/spectra/releases)
- [Issues](https://github.com/spectra-team/spectra/issues)
- [Pull Requests](https://github.com/spectra-team/spectra/pulls)