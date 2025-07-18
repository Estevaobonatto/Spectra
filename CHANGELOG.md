# Changelog

Todas as mudanças notáveis neste projeto serão documentadas neste arquivo.

O formato é baseado em [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
e este projeto adere ao [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.2.6] - 2024-12-XX

### 🚀 Adicionado
- **Sistema de Help Avançado**: Metadata estruturada para todos os módulos
- **Modo Verbose**: Logs detalhados para debugging e aprendizado
- **Instruções de Teste**: Guias práticos para exploração manual
- **GPU Hash Cracking**: Aceleração CUDA/OpenCL para quebra de hash
- **Network Monitor**: Interface TUI similar ao Wireshark
- **Basic Vulnerability Scanner**: Scanner de vulnerabilidades básicas
- **XXE Scanner**: Detecção de XML External Entity
- **IDOR Scanner**: Insecure Direct Object Reference
- **Rainbow Tables**: Lookup instantâneo O(1) para hashes

### 🔧 Melhorado
- **Performance**: Connection pooling e rate limiting adaptativo
- **Directory Scanner**: Competitivo com Dirsearch/Feroxbuster
- **Hash Cracker**: 27+ algoritmos, 11 modos de ataque
- **Technology Detector**: 500+ tecnologias suportadas
- **SQL Injection**: Detecção avançada com bypass de WAF
- **XSS Scanner**: Stored, Reflected e DOM XSS

### 🐛 Corrigido
- Falsos positivos em detecção de vulnerabilidades
- Memory leaks em operações de rede intensivas
- Timeout issues em scans de larga escala
- Encoding problems com caracteres especiais

### 🔒 Segurança
- Implementação de rate limiting para evitar DoS
- Validação de entrada aprimorada
- Sanitização de logs para evitar log injection
- Verificação de integridade de wordlists

## [3.1.0] - 2024-11-XX

### 🚀 Adicionado
- **Advanced Subdomain Scanner**: Certificate Transparency, permutations
- **Command Injection Scanner**: Detecção de injeção de comandos
- **LFI/RFI Scanner**: Local/Remote File Inclusion
- **WAF Detector**: Detecção e bypass de Web Application Firewall
- **SSL/TLS Analyzer**: Análise completa de certificados
- **Headers Analyzer**: Verificação de headers de segurança

### 🔧 Melhorado
- **Port Scanner**: Suporte a TCP, SYN e UDP
- **Banner Grabber**: Detecção de serviços aprimorada
- **Metadata Extractor**: Suporte a mais formatos de imagem
- **DNS Analyzer**: Consultas avançadas e threat intelligence

## [3.0.0] - 2024-10-XX

### 🚀 Adicionado
- **Arquitetura Modular**: Sistema de módulos independentes
- **CLI Avançado**: Interface de linha de comando completa
- **Report Generator**: Relatórios em múltiplos formatos
- **Core Framework**: Base sólida para extensibilidade

### 💥 Breaking Changes
- Reestruturação completa do código
- Nova interface de linha de comando
- Mudanças na API interna

## [2.x.x] - Legacy

Versões anteriores com funcionalidades básicas de scanning.

---

## 🔗 Links

- [Releases](https://github.com/spectra-team/spectra/releases)
- [Issues](https://github.com/spectra-team/spectra/issues)
- [Pull Requests](https://github.com/spectra-team/spectra/pulls)