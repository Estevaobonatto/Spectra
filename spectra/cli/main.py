# -*- coding: utf-8 -*-
"""
Main CLI interface for Spectra
"""

import sys
import argparse
from ..core import display_banner, display_legal_warning, console, print_error, print_info
from ..core.report_generator import ReportGenerator
from ..modules.port_scanner import scan_ports
from ..modules.banner_grabber import BannerGrabber
from ..modules.directory_scanner import advanced_directory_scan
from ..modules.metadata_extractor import extract_metadata
from ..modules.subdomain_scanner import discover_subdomains
from ..modules.advanced_subdomain_scanner import discover_subdomains_advanced
from ..modules.dns_analyzer import query_dns
from ..modules.whois_analyzer import get_whois_info
from ..modules.waf_detector import detect_waf
from ..modules.ssl_analyzer import get_ssl_info
from ..modules.headers_analyzer import get_http_headers
from ..modules.technology_detector import AdvancedTechnologyDetector, quick_tech_scan, deep_tech_scan
from ..modules.sql_injection_scanner import sql_injection_scan
from ..modules.xss_scanner import xss_scan
from ..modules.command_injection_scanner import command_injection_scan
from ..modules.lfi_scanner import lfi_scan
from ..modules.cve_integrator import integrate_cve_data, CVEIntegrator
from ..modules.hash_cracker import AdvancedHashCracker, crack_hash, detect_hash_type
from ..modules.network_monitor import network_monitor_interface

def create_parser():
    """Cria o parser de argumentos da linha de comando."""
    parser = argparse.ArgumentParser(
        description='Spectra - Web Security Suite',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:

[ Reconhecimento & Enumeração ]
  %(prog)s -ps example.com -p 80,443,22,21,25
  %(prog)s -ds http://example.com -w wordlist.txt --recursive
  %(prog)s -ss example.com -w subdomains.txt --advanced
  %(prog)s -dns example.com --record-type ALL
  %(prog)s -whois example.com --security-analysis --threat-intel

[ Directory Scanner Avançado - Rivaliza com Dirsearch/Feroxbuster/Gobuster/ffuf ]
  %(prog)s -ds https://example.com -w common.txt
  %(prog)s -ds https://site.com -w dirs.txt --http-methods GET,POST,PUT,HEAD
  %(prog)s -ds https://app.com -w wordlist.txt --exclude-status 404,500 --content-length-min 100
  %(prog)s -ds https://target.com -w big.txt --recursive --max-depth 2 --adaptive-delay
  %(prog)s -ds https://secure.com -w dirs.txt --stealth --status-codes 200,403,301,302
  %(prog)s -ds https://api.com -w api.txt --http-methods GET,POST,PUT,DELETE,OPTIONS
  %(prog)s -ds https://webapp.com -w common.txt --response-time-max 2.0 --content-length-max 10000
  %(prog)s -ds https://backup.com -w files.txt --no-backup-discovery --no-content-discovery

[ Performance Otimizada - Auto-ajuste de Threads & Connection Pooling ]
  %(prog)s -ds https://fast.com -w dirs.txt --performance-mode fast --workers 100
  %(prog)s -ds https://extreme.com -w big.txt --performance-mode aggressive --show-performance-stats
  %(prog)s -ds https://balanced.com -w wordlist.txt --connection-pool-size 150 --verbose
  %(prog)s -ds https://custom.com -w files.txt --workers 200 --adaptive-delay --show-performance-stats

[ Funcionalidades Únicas do Directory Scanner ]
  • Múltiplos métodos HTTP simultâneos (GET,POST,PUT,HEAD,OPTIONS,DELETE,PATCH)
  • Filtragem avançada por status codes, tamanho de conteúdo e tempo de resposta
  • Descoberta automática de arquivos de backup (.bak, .old, ~, _backup, etc)
  • Content-based discovery (extrai paths de HTML/JS/CSS automaticamente)
  • Rate limiting adaptativo inteligente (ajusta velocidade baseado em responses 429/503)
  • Detecção de WAF integrada com modo de evasão
  • Análise de tecnologias web durante o scan (WordPress, Drupal, etc)
  • False positive filtering avançado com baseline 404 detection
  • Scan recursivo com controle de profundidade
  • Threading otimizado com progress bars em tempo real

[ Performance & Otimizações Avançadas ]
  • Auto-ajuste inteligente de workers baseado em CPUs disponíveis (até 500 threads)
  • Connection pooling HTTP otimizado com retry strategy integrada
  • 3 modos de performance: balanced, fast (8x CPUs), aggressive (10x CPUs)
  • Estatísticas detalhadas de performance com score calculado automaticamente
  • Detecção de GPU disponível (informacional - HTTP é I/O bound, não CPU bound)
  • Pool de conexões configurável para máxima eficiência de rede
  • Controle granular de workers via CLI (--workers 1-500)
  • Taxa de sucesso e métricas de rate limiting em tempo real

[ Hash Cracker ]
  • Detecção automática de 27+ tipos de hash (MD5, SHA1/256/512, NTLM, bcrypt, LM, CRC32, xxHash)
  • 11 modos de ataque: Dictionary, Brute Force, Mask, Rainbow, Hybrid, Combinator, PRINCE, Toggle Case, Increment, Online
  • Algoritmos seguros: SHA-256/512, SHA-3, BLAKE2B/S, Argon2, scrypt, bcrypt
  • Algoritmos legados: MD5, SHA1, LM Hash, MD4, RIPEMD160, Whirlpool  
  • Checksums rápidos: CRC32, Adler32, xxHash32/64 (>10M hashes/s)
  • Unix Crypt variants: MD5/SHA-256/SHA-512 crypt ($1$, $5$, $6$)
  • Rule-based transformations (uppercase, digits, leet speak, years, reverse)
  • Mask attacks com padrões HashCat (?l ?u ?d ?s ?a)
  • Performance threading otimizado (até 500 workers em modo aggressive)
  • Cache inteligente para evitar re-computação de hashes
  • Estatísticas em tempo real (tentativas/s, progresso, ETA, performance score)
  • Wordlists integradas + suporte a wordlists customizadas
  • Online hash lookup em múltiplos serviços
  • Rainbow tables com geração automática e lookup O(1)
  • Sistema de help avançado com exemplos e benchmarks
  
[ GPU Acceleration - 50-1000x Performance Boost ]
  • Auto-detecção de NVIDIA CUDA, CuPy e OpenCL
  • Processamento paralelo massivo (milhares de threads simultâneas)
  • Memory management otimizado para grandes datasets
  • Fallback automático para CPU se GPU indisponível
  • Support para multi-GPU systems
  • Performance estimation e estatísticas detalhadas

[ Network Monitor - Wireshark-like Interface ]
  • Captura de pacotes em tempo real com interface TUI avançada
  • Análise detalhada de protocolos (TCP, UDP, ICMP, ARP, DNS)
  • Filtros BPF (Berkeley Packet Filter) interativos
  • Busca em tempo real com navegação por setas
  • Múltiplas visualizações: pacotes, estatísticas, hex, detalhes
  • Identificação automática de serviços (HTTP, HTTPS, SSH, FTP, DNS, etc.)
  • Análise de flags TCP (SYN, ACK, FIN, RST, PSH, URG)
  • Exportação para JSON e estatísticas de tráfego
  • Seleção de interfaces de rede com troca em tempo real

[ Detecção de Tecnologias Avançada - 500+ Tecnologias ]
  %(prog)s -tech https://example.com
  %(prog)s -tech https://target.com --tech-quick --verbose
  %(prog)s -tech https://company.com --tech-deep --tech-save-report report.html
  %(prog)s -tech https://site.com --tech-no-passive --tech-format json
  %(prog)s -tech https://enterprise.com --tech-deep --tech-threads 20

[ Análise de Vulnerabilidades ]
  %(prog)s -sqli http://example.com/page?id=1 --sqli-level 2
  %(prog)s -xss http://example.com/form --xss-stored --xss-dom
  %(prog)s -cmdi http://example.com/cmd --cmdi-level 3
  %(prog)s -lfi http://example.com/file?name=test

[ Hash Cracker Avançado - 27+ Algoritmos + 11 Modos de Ataque ]
  %(prog)s -hc 5d41402abc4b2a76b9719d911017c592 --attack-mode dictionary
  %(prog)s -hc 356a192b7913b04c54574d18c28d46e6395428ab --hash-type sha1 --attack-mode all
  %(prog)s -hc F054A2BB --hash-type crc32 --attack-mode brute_force --max-length 8
  %(prog)s -hc AAD3B435B51404EEAAD3B435B51404EE --hash-type lm --attack-mode dictionary
  %(prog)s -hc 098f6bcd4621d373cade4e832627b4f6 --attack-mode mask --mask-pattern "?l?l?l?l"
  %(prog)s -hc 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 --attack-mode hybrid --hash-wordlist base.txt
  %(prog)s -hc ad0234829205b9033196ba818f7a872b --attack-mode prince --hash-performance extreme --show-hash-stats
  
[ GPU Hash Cracking - Performance Extrema ]
  %(prog)s -hc d41d8cd98f00b204e9800998ecf8427e --use-gpu --gpu-info
  %(prog)s -hc 5d41402abc4b2a76b9719d911017c592 --use-gpu --attack-mode dictionary --hash-wordlist huge.txt
  %(prog)s -hc 098f6bcd4621d373cade4e832627b4f6 --use-gpu --attack-mode brute_force --max-length 8 --charset alphanum
  %(prog)s -hc ad0234829205b9033196ba818f7a872b --no-gpu --hash-performance extreme
  %(prog)s -hc 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 --use-gpu --show-performance-estimate

[ Rainbow Tables - Lookup Instantâneo O(1) ]
  %(prog)s -hc 5d41402abc4b2a76b9719d911017c592 --attack-mode rainbow --rainbow-generate
  %(prog)s -hc 098f6bcd4621d373cade4e832627b4f6 --attack-mode rainbow --rainbow-table md5_1_6_36chars.rt
  %(prog)s --rainbow-list
  %(prog)s --rainbow-info md5_1_6_36chars.rt
  %(prog)s -hc d41d8cd98f00b204e9800998ecf8427e --attack-mode rainbow --rainbow-charset "abc123" --rainbow-max-length 4
  %(prog)s -hc 356a192b7913b04c54574d18c28d46e6395428ab --attack-mode all

[ Network Monitor - Análise de Tráfego em Tempo Real ]
  %(prog)s -nm
  %(prog)s --network-monitor

[ Análise de Segurança ]
  %(prog)s -waf https://example.com
  %(prog)s -ssl example.com 443
  %(prog)s -headers https://example.com
  %(prog)s -bg example.com 80
        """
    )
    
    # === SCANNER DE PORTAS ===
    parser.add_argument('-ps', '--port-scan', 
                       metavar='TARGET',
                       help='Executa scan de portas no alvo especificado')
    
    parser.add_argument('-p', '--ports',
                       default='80,443,22,21,25,53,110,143,993,995,3306,3389,5432',
                       help='Portas para scanear (ex: 80,443 ou 1-1000)')
    
    parser.add_argument('--top-ports',
                       type=int,
                       metavar='N',
                       help='Scanear as N portas mais comuns')
    
    parser.add_argument('--scan-type',
                       choices=['tcp', 'syn', 'udp'],
                       default='tcp',
                       help='Tipo de scan de porta')
    
    # === SCANNER DE DIRETÓRIOS AVANÇADO ===
    parser.add_argument('-ds', '--directory-scan',
                       metavar='URL',
                       help='Executa scan avançado de diretórios (competitivo com Dirsearch/Feroxbuster/Gobuster)')
    
    parser.add_argument('-w', '--wordlist',
                       metavar='FILE',
                       help='Arquivo de wordlist para scans (obrigatório para directory/subdomain scan)')
    
    parser.add_argument('--recursive',
                       action='store_true',
                       help='Ativar modo recursivo para directory scan (explora subdiretórios encontrados)')
    
    parser.add_argument('--max-depth',
                       type=int,
                       default=3,
                       help='Profundidade máxima para scan recursivo (padrão: 3)')
    
    parser.add_argument('--stealth',
                       action='store_true',
                       help='Ativar modo stealth com delays extras (mais lento mas menos detectável)')
    
    # Funcionalidades avançadas do directory scanner
    parser.add_argument('--http-methods',
                       default='GET',
                       help='Métodos HTTP para testar separados por vírgula (ex: GET,POST,PUT,HEAD,OPTIONS,DELETE)')
    
    parser.add_argument('--status-codes',
                       metavar='CODES',
                       help='Incluir apenas estes status codes (ex: 200,403,500) - filtragem positiva')
    
    parser.add_argument('--exclude-status',
                       metavar='CODES',
                       help='Excluir estes status codes dos resultados (ex: 404,500,502) - filtragem negativa')
    
    parser.add_argument('--content-length-min',
                       type=int,
                       metavar='BYTES',
                       help='Filtrar responses com tamanho mínimo em bytes (remove respostas muito pequenas)')
    
    parser.add_argument('--content-length-max',
                       type=int,
                       metavar='BYTES',
                       help='Filtrar responses com tamanho máximo em bytes (remove respostas muito grandes)')
    
    parser.add_argument('--response-time-min',
                       type=float,
                       metavar='SECONDS',
                       help='Filtrar responses com tempo mínimo de resposta em segundos')
    
    parser.add_argument('--response-time-max',
                       type=float,
                       metavar='SECONDS',
                       help='Filtrar responses com tempo máximo de resposta em segundos')
    
    parser.add_argument('--no-backup-discovery',
                       action='store_true',
                       help='Desabilita descoberta automática de arquivos de backup (.bak, .old, ~, etc)')
    
    parser.add_argument('--no-content-discovery',
                       action='store_true',
                       help='Desabilita descoberta baseada em análise de conteúdo HTML/JS/CSS')
    
    parser.add_argument('--adaptive-delay',
                       action='store_true',
                       help='Ativa rate limiting adaptativo inteligente (ajusta velocidade baseado em 429/503)')
    
    # Performance avançada
    parser.add_argument('--performance-mode',
                       choices=['balanced', 'fast', 'aggressive'],
                       default='balanced',
                       help='Modo de performance: balanced (padrão), fast (threads otimizadas), aggressive (máxima velocidade)')
    
    parser.add_argument('--connection-pool-size',
                       type=int,
                       metavar='SIZE',
                       help='Tamanho do pool de conexões HTTP (padrão: workers * 2)')
    
    parser.add_argument('--show-performance-stats',
                       action='store_true',
                       help='Mostra estatísticas detalhadas de performance durante o scan')
    
    # === SCANNER DE SUBDOMÍNIOS ===
    parser.add_argument('-ss', '--subdomain-scan',
                       metavar='DOMAIN',
                       help='Executa scan de subdomínios no domínio especificado')
    
    parser.add_argument('--advanced',
                       action='store_true',
                       help='Usar scanner avançado (Certificate Transparency, passive sources, permutations)')
    
    parser.add_argument('--passive-only',
                       action='store_true',
                       help='Apenas descoberta passiva (sem bruteforce DNS)')
    
    parser.add_argument('--verify-takeover',
                       action='store_true',
                       help='Verificar subdomain takeover vulnerabilities')
    
    parser.add_argument('--max-concurrent',
                       type=int,
                       default=1000,
                       help='Máximo de queries DNS concorrentes (padrão: 1000)')
    
    # === ANÁLISE DNS ===
    parser.add_argument('-dns', '--dns-query',
                       metavar='DOMAIN',
                       help='Executa consulta DNS no domínio especificado')
    
    parser.add_argument('--record-type',
                       default='ALL',
                       help='Tipo de registro DNS (A, MX, TXT, ALL, etc.)')
    
    # === ANÁLISE WHOIS ===
    parser.add_argument('-whois', '--whois-query',
                       metavar='DOMAIN',
                       help='Executa consulta WHOIS no domínio especificado')
    
    parser.add_argument('--security-analysis',
                       action='store_true',
                       help='Ativar análise de segurança WHOIS')
    
    parser.add_argument('--threat-intel',
                       action='store_true',
                       help='Ativar verificação de threat intelligence')
    
    parser.add_argument('--check-blocklists',
                       action='store_true',
                       help='Verificar blocklists')
    
    parser.add_argument('--typosquatting-check',
                       action='store_true',
                       help='Verificar typosquatting')
    
    # === BANNER GRABBER ===
    parser.add_argument('-bg', '--banner-grab',
                       nargs=2,
                       metavar=('HOST', 'PORT'),
                       help='Captura banner do serviço (host porta)')
    
    # === EXTRATOR DE METADADOS ===
    parser.add_argument('-md', '--metadata',
                       metavar='URL',
                       help='Extrai metadados de uma imagem')
    
    # === WAF DETECTOR ===
    parser.add_argument('-waf', '--waf-detect',
                       metavar='URL',
                       help='Detecta WAF (Web Application Firewall)')
    
    # === ANALISADOR SSL/TLS ===
    parser.add_argument('-ssl', '--ssl-info',
                       metavar='HOSTNAME',
                       help='Analisa certificado SSL/TLS')
    
    # === ANALISADOR DE HEADERS HTTP ===
    parser.add_argument('-headers', '--http-headers',
                       metavar='URL',
                       help='Analisa headers de segurança HTTP')
    
    # === DETECTOR DE TECNOLOGIAS AVANÇADO ===
    parser.add_argument('-tech', '--tech-detect',
                       metavar='URL',
                       help='Detecção avançada de tecnologias web (500+ tecnologias suportadas)')
    
    parser.add_argument('--tech-quick',
                       action='store_true',
                       help='Scan rápido de tecnologias (sem análise passiva)')
    
    parser.add_argument('--tech-deep',
                       action='store_true',
                       help='Análise profunda com todas as funcionalidades (fingerprinting, passive scan, WAF, API)')
    
    parser.add_argument('--tech-no-passive',
                       action='store_true',
                       help='Desabilita scan passivo (robots.txt, sitemap, etc)')
    
    parser.add_argument('--tech-no-fingerprint',
                       action='store_true',
                       help='Desabilita fingerprinting de arquivos')
    
    parser.add_argument('--tech-save-report',
                       metavar='FILE',
                       help='Salva relatório de tecnologias em arquivo (formato baseado na extensão)')
    
    parser.add_argument('--tech-format',
                       choices=['table', 'json', 'xml', 'csv', 'html', 'markdown'],
                       default='table',
                       help='Formato de output para detecção de tecnologias')
    
    parser.add_argument('--tech-threads',
                       type=int,
                       default=10,
                       help='Número de threads para requests paralelos (padrão: 10)')
    
    parser.add_argument('--tech-timeout',
                       type=int,
                       default=10,
                       help='Timeout para requests de tecnologias em segundos (padrão: 10)')
    
    # === SCANNER DE SQL INJECTION ===
    parser.add_argument('-sqli', '--sql-injection',
                       metavar='URL',
                       help='Executa scan de SQL Injection')
    
    parser.add_argument('--sqli-level',
                       type=int,
                       choices=[1, 2, 3],
                       default=1,
                       help='Nível de agressividade do scan SQLi (1-3)')
    
    parser.add_argument('--sqli-dbms',
                       choices=['mysql', 'postgresql', 'mssql', 'oracle', 'sqlite'],
                       help='SGBD específico para o scan SQLi')
    
    parser.add_argument('--sqli-collaborator',
                       metavar='URL',
                       help='URL do servidor OAST para testes out-of-band')
    
    # === XSS SCANNER ===
    parser.add_argument('-xss', '--xss-scan',
                       metavar='URL',
                       help='Executa scan de XSS (Cross-Site Scripting)')
    
    parser.add_argument('--xss-payloads',
                       metavar='FILE',
                       help='Arquivo com payloads customizados para XSS')
    
    parser.add_argument('--xss-stored',
                       action='store_true',
                       help='Ativar detecção de XSS armazenado')
    
    parser.add_argument('--xss-dom',
                       action='store_true',
                       help='Ativar fuzzing de DOM XSS')
    
    # === COMMAND INJECTION SCANNER ===
    parser.add_argument('-cmdi', '--command-injection',
                       metavar='URL',
                       help='Executa scan de Command Injection')
    
    parser.add_argument('--cmdi-level',
                       type=int,
                       choices=[1, 2, 3],
                       default=1,
                       help='Nível de agressividade do scan Command Injection (1-3)')
    
    parser.add_argument('--cmdi-os',
                       choices=['linux', 'windows', 'auto'],
                       default='auto',
                       help='Sistema operacional alvo para Command Injection')
    
    parser.add_argument('--cmdi-time-delay',
                       type=float,
                       default=5.0,
                       help='Delay em segundos para técnicas time-based (padrão: 5.0)')
    
    # === LFI/RFI SCANNER ===
    parser.add_argument('-lfi', '--lfi-scan',
                       metavar='URL',
                       help='Executa scan de Local File Inclusion (LFI) e Remote File Inclusion (RFI)')
    
    parser.add_argument('--lfi-fast',
                       action='store_true',
                       help='Modo rápido para LFI (menos técnicas de bypass)')
    
    parser.add_argument('--lfi-stop-first',
                       action='store_true',
                       help='Para na primeira vulnerabilidade LFI encontrada')
    
    parser.add_argument('--lfi-depth',
                       type=int,
                       default=10,
                       help='Profundidade de path traversal para LFI (padrão: 10)')
    
    # === HASH CRACKER AVANÇADO ===
    parser.add_argument('-hc', '--hash-crack',
                       metavar='HASH',
                       help='Quebra hash usando múltiplos métodos de ataque (dictionary, brute force, mask, online)')
    
    parser.add_argument('--hash-type',
                       choices=['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'md4', 'ntlm', 'lm', 
                               'blake2b', 'blake2s', 'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512', 
                               'ripemd160', 'whirlpool', 'adler32', 'crc32', 'xxhash32', 'xxhash64',
                               'bcrypt', 'argon2', 'scrypt', 'pbkdf2', 'md5crypt', 'sha256crypt', 'sha512crypt', 'auto'],
                       default='auto',
                       help='Tipo de hash (27+ algoritmos suportados, auto-detectado por padrão)')
    
    parser.add_argument('--attack-mode',
                       choices=['dictionary', 'brute_force', 'mask', 'rainbow', 'hybrid', 'combinator', 
                               'toggle_case', 'increment', 'prince', 'online', 'all'],
                       default='dictionary',
                       help='Modo de ataque para quebra de hash (11 modos disponíveis)')
    
    parser.add_argument('--hash-wordlist',
                       metavar='FILE',
                       help='Wordlist para ataque de dicionário (usa padrão se não especificado)')
    
    parser.add_argument('--hash-rules',
                       metavar='RULES',
                       help='Regras para transformação de senhas (ex: uppercase,digits,leet)')
    
    parser.add_argument('--min-length',
                       type=int,
                       default=1,
                       help='Comprimento mínimo para brute force (padrão: 1)')
    
    parser.add_argument('--max-length',
                       type=int,
                       default=6,
                       help='Comprimento máximo para brute force (padrão: 6)')
    
    parser.add_argument('--charset',
                       default='abcdefghijklmnopqrstuvwxyz0123456789',
                       help='Charset para brute force (padrão: lowercase + digits)')
    
    parser.add_argument('--mask-pattern',
                       metavar='MASK',
                       help='Padrão de máscara (?l=lower, ?u=upper, ?d=digits, ?s=special)')
    
    parser.add_argument('--hash-performance',
                       choices=['balanced', 'fast', 'extreme'],
                       default='balanced',
                       help='Modo de performance para quebra de hash')
    
    parser.add_argument('--show-hash-stats',
                       action='store_true',
                       help='Mostra estatísticas detalhadas durante quebra de hash')
    
    # === NETWORK MONITOR ===
    parser.add_argument('-nm', '--network-monitor',
                       action='store_true',
                       help='Inicia monitor de rede similar ao Wireshark')
    
    parser.add_argument('--network-interface',
                       metavar='INTERFACE',
                       help='Interface de rede específica para captura (ex: wlan0, eth0)')
    
    # === GPU ACCELERATION ===
    parser.add_argument('--use-gpu',
                       action='store_true',
                       help='Ativa aceleração GPU para hash cracking (CUDA/OpenCL)')
    
    parser.add_argument('--no-gpu',
                       action='store_true',
                       help='Força uso apenas de CPU (desativa GPU)')
    
    parser.add_argument('--gpu-info',
                       action='store_true',
                       help='Mostra informações detalhadas sobre GPUs disponíveis')
    
    parser.add_argument('--show-performance-estimate',
                       action='store_true',
                       help='Mostra estimativa de performance GPU vs CPU')
    
    parser.add_argument('--gpu-memory-limit',
                       type=int,
                       metavar='MB',
                       help='Limita uso de memória GPU em MB')
    
    # === RAINBOW TABLES ===
    parser.add_argument('--rainbow-table',
                       metavar='FILE',
                       help='Caminho para rainbow table (.rt)')
    
    parser.add_argument('--rainbow-generate',
                       action='store_true',
                       help='Gera rainbow table automaticamente se não existir')
    
    parser.add_argument('--rainbow-list',
                       action='store_true',
                       help='Lista rainbow tables disponíveis')
    
    parser.add_argument('--rainbow-info',
                       metavar='FILE',
                       help='Mostra informações detalhadas sobre uma rainbow table')
    
    parser.add_argument('--rainbow-charset',
                       metavar='CHARS',
                       default='abcdefghijklmnopqrstuvwxyz0123456789',
                       help='Charset para gerar rainbow table')
    
    parser.add_argument('--rainbow-min-length',
                       type=int,
                       default=1,
                       metavar='N',
                       help='Comprimento mínimo para rainbow table (padrão: 1)')
    
    parser.add_argument('--rainbow-max-length',
                       type=int,
                       default=6,
                       metavar='N',
                       help='Comprimento máximo para rainbow table (padrão: 6)')
    
    # === INTEGRAÇÃO CVE ===
    parser.add_argument('--enrich-cve',
                       action='store_true',
                       help='Enriquecer resultados com dados de CVE')
    
    parser.add_argument('--cve-search',
                       metavar='KEYWORD',
                       help='Buscar CVEs por palavra-chave')
    
    parser.add_argument('--cve-details',
                       metavar='CVE_ID',
                       help='Obter detalhes específicos de um CVE')
    
    parser.add_argument('--trending-cves',
                       type=int,
                       metavar='DAYS',
                       help='Mostrar CVEs em tendência dos últimos N dias')
    
    # === OPÇÕES GERAIS ===
    parser.add_argument('--timeout',
                       type=float,
                       default=1.0,
                       help='Timeout em segundos (padrão: 1.0)')
    
    parser.add_argument('--delay',
                       type=int,
                       default=0,
                       help='Delay entre requests em ms (padrão: 0)')
    
    parser.add_argument('--workers',
                       type=int,
                       default=50,
                       help='Número de threads (padrão: 50)')
    
    parser.add_argument('--host-discovery',
                       action='store_true',
                       help='Verifica se o host está ativo antes do scan')
    
    parser.add_argument('--output-format',
                       choices=['table', 'json', 'xml'],
                       default='table',
                       help='Formato de saída')
    
    parser.add_argument('--generate-report',
                       choices=['json', 'xml', 'html', 'all'],
                       help='Gera relatório no formato especificado')
    
    parser.add_argument('--report-file',
                       metavar='FILENAME',
                       help='Nome do arquivo de relatório (sem extensão se --generate-report=all)')
    
    parser.add_argument('--verbose', '-v',
                       action='store_true',
                       help='Modo verbose')
    
    parser.add_argument('--no-banner',
                       action='store_true',
                       help='Não exibe o banner')
    
    parser.add_argument('--version',
                       action='version',
                       version='Spectra v3.3.0 - Advanced Directory Scanner Edition')
    
    return parser

def generate_report_wrapper(scan_results, target_url, scan_type, output_format, output_file=None):
    """Wrapper para geração de relatórios."""
    try:
        # Garantir que scan_results é uma lista de dicionários válida
        if not isinstance(scan_results, list):
            scan_results = []
        
        # Filtrar apenas itens que são dicionários (vulnerabilidades)
        valid_results = []
        for item in scan_results:
            if isinstance(item, dict) and any(key in item for key in ['Risco', 'Tipo', 'Detalhe']):
                valid_results.append(item)
        
        generator = ReportGenerator(valid_results, target_url, scan_type)
        
        if output_format == 'all':
            # Gerar todos os formatos
            base_name = output_file or f"spectra_report_{scan_type.lower().replace(' ', '_')}"
            results = {}
            
            results['json'] = generator.generate_json_report(f"{base_name}.json")
            results['xml'] = generator.generate_xml_report(f"{base_name}.xml")
            results['html'] = generator.generate_html_report(f"{base_name}.html")
            
            return results
        else:
            # Gerar formato específico
            if output_format == 'json':
                return generator.generate_json_report(output_file)
            elif output_format == 'xml':
                return generator.generate_xml_report(output_file)
            elif output_format == 'html':
                return generator.generate_html_report(output_file)
    except Exception as e:
        raise Exception(f"Erro na geração do relatório: {e}")

def main():
    """Função principal do CLI."""
    parser = create_parser()
    
    # Se nenhum argumento, mostra ajuda
    if len(sys.argv) == 1:
        display_banner()
        display_legal_warning()
        parser.print_help()
        return
    
    args = parser.parse_args()
    
    # Exibe banner se não desabilitado
    if not args.no_banner:
        display_banner()
    
    try:
        # === INTEGRAÇÃO CVE (verificar primeiro) ===
        if args.cve_search:
            print_info(f"Buscando CVEs para: {args.cve_search}")
            
            integrator = CVEIntegrator()
            cves = integrator.search_cve_by_keyword(args.cve_search, limit=10)
            
            if cves:
                console.print(f"\n[bold green]Encontrados {len(cves)} CVEs:[/bold green]")
                
                from rich.table import Table
                table = Table(title=f"CVEs relacionados a '{args.cve_search}'")
                table.add_column("CVE ID", style="cyan")
                table.add_column("Severity", style="yellow")
                table.add_column("Description", style="white", max_width=50)
                table.add_column("Published", style="green")
                
                for cve in cves:
                    severity = "N/A"
                    if cve.get('cvss_v3') and 'baseScore' in cve['cvss_v3']:
                        score = cve['cvss_v3']['baseScore']
                        if score >= 9.0:
                            severity = f"[red]CRITICAL ({score})[/red]"
                        elif score >= 7.0:
                            severity = f"[orange1]HIGH ({score})[/orange1]"
                        elif score >= 4.0:
                            severity = f"[yellow]MEDIUM ({score})[/yellow]"
                        else:
                            severity = f"[green]LOW ({score})[/green]"
                    
                    table.add_row(
                        cve.get('id', 'N/A'),
                        severity,
                        cve.get('description', 'N/A')[:100] + "..." if len(cve.get('description', '')) > 100 else cve.get('description', 'N/A'),
                        cve.get('published', 'N/A')[:10]
                    )
                
                console.print(table)
            else:
                print_info("Nenhum CVE encontrado para o termo buscado.")
            
            return
        
        elif args.cve_details:
            print_info(f"Obtendo detalhes do CVE: {args.cve_details}")
            
            integrator = CVEIntegrator()
            cve_details = integrator.get_cve_details(args.cve_details)
            
            if cve_details:
                console.print(f"\n[bold green]Detalhes do {args.cve_details}:[/bold green]")
                console.print(f"[cyan]Descrição:[/cyan] {cve_details.get('description', 'N/A')}")
                console.print(f"[cyan]Publicado:[/cyan] {cve_details.get('published', 'N/A')}")
                console.print(f"[cyan]Modificado:[/cyan] {cve_details.get('modified', 'N/A')}")
                
                if cve_details.get('cvss_v3'):
                    cvss = cve_details['cvss_v3']
                    console.print(f"[cyan]CVSS v3:[/cyan] {cvss.get('baseScore', 'N/A')} ({cvss.get('baseSeverity', 'N/A')})")
                    console.print(f"[cyan]Vector:[/cyan] {cvss.get('vectorString', 'N/A')}")
                
                if cve_details.get('weaknesses'):
                    console.print(f"[cyan]Weaknesses:[/cyan] {', '.join(cve_details['weaknesses'])}")
                
                if cve_details.get('references'):
                    console.print("[cyan]Referências:[/cyan]")
                    for ref in cve_details['references'][:5]:  # Mostrar apenas as primeiras 5
                        console.print(f"  • {ref.get('url', 'N/A')}")
            else:
                print_error(f"CVE {args.cve_details} não encontrado.")
            
            return
        
        elif args.trending_cves:
            print_info(f"Buscando CVEs em tendência dos últimos {args.trending_cves} dias...")
            
            integrator = CVEIntegrator()
            trending = integrator.get_trending_vulnerabilities(args.trending_cves)
            
            if trending:
                console.print(f"\n[bold green]CVEs em tendência ({len(trending)} encontrados):[/bold green]")
                
                from rich.table import Table
                table = Table(title=f"CVEs dos últimos {args.trending_cves} dias")
                table.add_column("CVE ID", style="cyan")
                table.add_column("Severity", style="yellow")
                table.add_column("Description", style="white", max_width=60)
                table.add_column("Published", style="green")
                
                for cve in trending[:20]:  # Mostrar apenas os primeiros 20
                    severity = "N/A"
                    if cve.get('cvss_v3') and 'baseScore' in cve['cvss_v3']:
                        score = cve['cvss_v3']['baseScore']
                        if score >= 9.0:
                            severity = f"[red]CRITICAL ({score})[/red]"
                        elif score >= 7.0:
                            severity = f"[orange1]HIGH ({score})[/orange1]"
                        elif score >= 4.0:
                            severity = f"[yellow]MEDIUM ({score})[/yellow]"
                        else:
                            severity = f"[green]LOW ({score})[/green]"
                    
                    table.add_row(
                        cve.get('id', 'N/A'),
                        severity,
                        cve.get('description', 'N/A')[:120] + "..." if len(cve.get('description', '')) > 120 else cve.get('description', 'N/A'),
                        cve.get('published', 'N/A')[:10]
                    )
                
                console.print(table)
            else:
                print_info("Nenhum CVE em tendência encontrado.")
            
            return

        # === SCANNER DE PORTAS ===
        if args.port_scan:
            print_info(f"Iniciando scan de portas em: {args.port_scan}")
            
            results = scan_ports(
                target=args.port_scan,
                port_spec=args.ports,
                scan_type=args.scan_type,
                timeout=args.timeout,
                delay=args.delay,
                workers=args.workers,
                verbose=args.verbose,
                top_ports=args.top_ports,
                host_discovery=args.host_discovery,
                output_format=args.output_format
            )
            
            # Para formato não-table, imprime resultado
            if args.output_format != 'table' and results:
                console.print(results)
        
        # === SCANNER DE DIRETÓRIOS ===
        elif args.directory_scan:
            if not args.wordlist:
                print_error("Wordlist é obrigatória para directory scan")
                sys.exit(1)
            
            print_info(f"Iniciando scan de diretórios em: {args.directory_scan}")
            
            # Cria e configura scanner avançado
            from ..modules.directory_scanner import AdvancedDirectoryScanner
            
            scanner = AdvancedDirectoryScanner(
                base_url=args.directory_scan,
                wordlist_path=args.wordlist,
                workers=args.workers,
                timeout=args.timeout
            )
            
            # Configura métodos HTTP
            if args.http_methods:
                scanner.http_methods = [method.strip().upper() for method in args.http_methods.split(',')]
            
            # Configura filtros de status code
            if args.status_codes:
                scanner.include_status_codes = [int(code.strip()) for code in args.status_codes.split(',')]
            
            if args.exclude_status:
                scanner.exclude_status_codes = [int(code.strip()) for code in args.exclude_status.split(',')]
            
            # Configura filtros de tamanho de conteúdo
            if args.content_length_min or args.content_length_max:
                scanner.content_length_filter = {}
                if args.content_length_min:
                    scanner.content_length_filter['min'] = args.content_length_min
                if args.content_length_max:
                    scanner.content_length_filter['max'] = args.content_length_max
            
            # Configura filtros de tempo de resposta
            if args.response_time_min or args.response_time_max:
                scanner.response_time_filter = {}
                if args.response_time_min:
                    scanner.response_time_filter['min'] = args.response_time_min
                if args.response_time_max:
                    scanner.response_time_filter['max'] = args.response_time_max
            
            # Configura opções de descoberta
            scanner.backup_discovery = not args.no_backup_discovery
            scanner.content_discovery = not args.no_content_discovery
            scanner.adaptive_delay = args.adaptive_delay
            
            # Configura modo de performance
            scanner.set_performance_mode(args.performance_mode, args.workers if args.workers != 50 else None)
            
            # Configura connection pool customizado se especificado
            if args.connection_pool_size:
                scanner.connection_pool_size = args.connection_pool_size
            
            # Configura exibição de stats de performance
            scanner.show_performance_stats = args.show_performance_stats
            
            # Verifica GPU (informacional apenas)
            if args.verbose:
                gpu_available, gpu_info = scanner._check_gpu_acceleration()
                if gpu_available:
                    console.print(f"[*] GPU Info: {gpu_info}")
            
            if args.verbose:
                console.print(f"[*] Modo de performance: {args.performance_mode}")
                console.print(f"[*] Workers: {scanner.workers} {'(auto-ajustado)' if scanner.max_workers_auto else ''}")
                console.print(f"[*] Connection pool: {scanner.connection_pool_size}")
                console.print(f"[*] Métodos HTTP: {', '.join(scanner.http_methods)}")
                if scanner.include_status_codes:
                    console.print(f"[*] Incluir status: {', '.join(map(str, scanner.include_status_codes))}")
                if scanner.exclude_status_codes != [404]:
                    console.print(f"[*] Excluir status: {', '.join(map(str, scanner.exclude_status_codes))}")
                if scanner.content_length_filter:
                    console.print(f"[*] Filtro tamanho: {scanner.content_length_filter}")
                if scanner.backup_discovery:
                    console.print(f"[*] Descoberta de backup: Ativada")
                if scanner.content_discovery:
                    console.print(f"[*] Descoberta de conteúdo: Ativada")
                if scanner.adaptive_delay:
                    console.print(f"[*] Rate limiting adaptativo: Ativado")
            
            results = scanner.scan(
                recursive=args.recursive,
                max_depth=args.max_depth,
                stealth=args.stealth,
                output_format=args.output_format
            )
        
        # === SCANNER DE SUBDOMÍNIOS ===
        elif args.subdomain_scan:
            print_info(f"Iniciando scan de subdomínios em: {args.subdomain_scan}")
            
            if args.advanced:
                # Scanner avançado - assíncrono
                import asyncio
                
                enable_passive = True
                enable_permutations = not args.passive_only
                enable_bruteforce = not args.passive_only and args.wordlist
                
                if args.passive_only:
                    print_info("Modo passivo ativado - usando Certificate Transparency e passive sources")
                else:
                    if not args.wordlist:
                        print_error("Wordlist é obrigatória para bruteforce DNS (use --passive-only para modo passivo)")
                        sys.exit(1)
                
                results = asyncio.run(discover_subdomains_advanced(
                    domain=args.subdomain_scan,
                    wordlist_path=args.wordlist if enable_bruteforce else None,
                    max_concurrent=args.max_concurrent,
                    enable_passive=enable_passive,
                    enable_permutations=enable_permutations,
                    verify_takeover=args.verify_takeover
                ))
            else:
                # Scanner tradicional
                if not args.wordlist:
                    print_error("Wordlist é obrigatória para subdomain scan (use --advanced --passive-only para modo passivo)")
                    sys.exit(1)
                
                results = discover_subdomains(
                    domain=args.subdomain_scan,
                    wordlist_path=args.wordlist,
                    workers=args.workers
                )
        
        # === ANÁLISE DNS ===
        elif args.dns_query:
            print_info(f"Iniciando consulta DNS para: {args.dns_query}")
            
            results = query_dns(
                domain=args.dns_query,
                record_type=args.record_type
            )
        
        # === ANÁLISE WHOIS ===
        elif args.whois_query:
            print_info(f"Iniciando consulta WHOIS para: {args.whois_query}")
            
            results = get_whois_info(
                domain=args.whois_query,
                verbose=args.verbose,
                output_format=args.output_format,
                security_analysis=args.security_analysis,
                threat_intel=args.threat_intel,
                check_blocklists=args.check_blocklists,
                typosquatting_check=args.typosquatting_check
            )
        
        # === BANNER GRABBER ===
        elif args.banner_grab:
            host, port = args.banner_grab
            print_info(f"Capturando banner de {host}:{port}")
            
            grabber = BannerGrabber(timeout=args.timeout)
            banner = grabber.grab_banner(host, int(port))
        
        # === EXTRATOR DE METADADOS ===
        elif args.metadata:
            print_info(f"Extraindo metadados de: {args.metadata}")
            
            metadata = extract_metadata(args.metadata)
        
        # === DETECTOR DE WAF ===
        elif args.waf_detect:
            print_info(f"Detectando WAF em: {args.waf_detect}")
            
            results = detect_waf(
                url=args.waf_detect,
                verbose=args.verbose,
                output_format=args.output_format,
                test_bypasses=args.test_bypasses,
                timing_analysis=args.timing_analysis
            )
        
        # === ANALISADOR SSL/TLS ===
        elif args.ssl_info:
            hostname, port = args.ssl_info
            print_info(f"Analisando SSL/TLS de {hostname}:{port}")
            
            results = get_ssl_info(
                hostname=hostname,
                port=int(port),
                output_format=args.output_format
            )
        
        # === ANALISADOR DE HEADERS HTTP ===
        elif args.http_headers:
            print_info(f"Analisando cabeçalhos de: {args.http_headers}")
            
            results = get_http_headers(
                url=args.http_headers,
                verbose=args.verbose,
                output_format=args.output_format
            )
        
        # === DETECTOR DE TECNOLOGIAS AVANÇADO ===
        elif args.tech_detect:
            print_info(f"Detectando tecnologias em: {args.tech_detect}")
            
            # Determina o tipo de scan baseado nos argumentos
            if args.tech_quick:
                # Scan rápido
                print_info("Executando scan rápido (sem análise passiva ou fingerprinting)")
                results = quick_tech_scan(args.tech_detect, verbose=args.verbose)
                
            elif args.tech_deep:
                # Scan profundo
                print_info("Executando análise profunda com todas as funcionalidades")
                save_file = args.tech_save_report if args.tech_save_report else None
                results = deep_tech_scan(
                    args.tech_detect, 
                    verbose=args.verbose, 
                    save_report=save_file, 
                    report_format=args.tech_format
                )
                
            else:
                # Scan customizado com opções avançadas
                print_info("Executando scan customizado de tecnologias")
                detector = AdvancedTechnologyDetector(args.tech_detect, timeout=args.tech_timeout)
                detector.max_workers = args.tech_threads
                
                # Configura opções de scan
                enable_passive = not args.tech_no_passive
                enable_fingerprint = not args.tech_no_fingerprint
                
                if args.verbose:
                    if enable_passive:
                        print_info("✓ Análise passiva ativada (robots.txt, sitemap, etc)")
                    else:
                        print_info("✗ Análise passiva desativada")
                    
                    if enable_fingerprint:
                        print_info("✓ Fingerprinting de arquivos ativado")
                    else:
                        print_info("✗ Fingerprinting de arquivos desativado")
                
                # Executa detecção
                results = detector.detect_technologies(
                    verbose=args.verbose,
                    enable_passive_scan=enable_passive,
                    enable_file_fingerprinting=enable_fingerprint
                )
                
                # Apresenta resultados ou salva arquivo
                if args.tech_save_report:
                    # Determina formato pelo arquivo ou usa args.tech_format
                    if '.' in args.tech_save_report:
                        file_ext = args.tech_save_report.split('.')[-1].lower()
                        format_map = {
                            'json': 'json', 'xml': 'xml', 'csv': 'csv', 
                            'html': 'html', 'htm': 'html', 'md': 'markdown'
                        }
                        report_format = format_map.get(file_ext, args.tech_format)
                    else:
                        report_format = args.tech_format
                    
                    print_info(f"Salvando relatório em formato {report_format}")
                    detector.save_report(args.tech_save_report, report_format)
                else:
                    # Apresenta na tela
                    detector.present_results(args.tech_format)
        
        # === SCANNER DE SQL INJECTION ===
        elif args.sql_injection:
            print_info(f"Executando scan de SQL Injection em: {args.sql_injection}")
            
            results = sql_injection_scan(
                url=args.sql_injection,
                level=args.sqli_level,
                dbms=args.sqli_dbms,
                collaborator_url=args.sqli_collaborator
            )
        
        # === SCANNER DE XSS ===
        elif args.xss_scan:
            print_info(f"Executando scan de XSS em: {args.xss_scan}")
            
            results = xss_scan(
                url=args.xss_scan,
                custom_payloads_file=args.xss_payloads,
                scan_stored=args.xss_stored,
                fuzz_dom=args.xss_dom,
                verbose=args.verbose
            )
        
        # === COMMAND INJECTION SCANNER ===
        elif args.command_injection:
            print_info(f"Executando scan de Command Injection em: {args.command_injection}")
            
            results = command_injection_scan(
                url=args.command_injection,
                level=args.cmdi_level,
                target_os=args.cmdi_os,
                time_delay=args.cmdi_time_delay,
                verbose=args.verbose
            )
        
        # === LFI/RFI SCANNER ===
        elif args.lfi_scan:
            print_info(f"Executando scan de LFI/RFI em: {args.lfi_scan}")
            
            results = lfi_scan(
                url=args.lfi_scan,
                timeout=args.timeout,
                threads=args.workers,
                verbose=args.verbose,
                fast_mode=args.lfi_fast,
                stop_on_first=args.lfi_stop_first
            )
        
        # === RAINBOW TABLES MANAGEMENT ===
        elif args.rainbow_list:
            from ..modules.hash_cracker import RainbowTableManager
            
            manager = RainbowTableManager()
            tables = manager.list_available_tables()
            
            if tables:
                console.print("\n[bold cyan]=== Rainbow Tables Disponíveis ===[/bold cyan]")
                from rich.table import Table
                
                table = Table(title="Rainbow Tables")
                table.add_column("Nome", style="cyan")
                table.add_column("Tamanho", style="yellow")
                table.add_column("Caminho", style="white", max_width=60)
                
                for rt in tables:
                    table.add_row(
                        rt['name'],
                        f"{rt['size_mb']:.1f} MB",
                        rt['path']
                    )
                
                console.print(table)
            else:
                console.print("[yellow][-] Nenhuma rainbow table encontrada[/yellow]")
                console.print("[*] Use --rainbow-generate para criar uma nova tabela")
            
            return
        
        elif args.rainbow_info:
            from ..modules.hash_cracker import RainbowTableManager
            
            manager = RainbowTableManager()
            info = manager.get_table_info(args.rainbow_info)
            
            if info['exists']:
                console.print(f"\n[bold cyan]=== Rainbow Table Info ===[/bold cyan]")
                console.print(f"[cyan]Arquivo:[/cyan] {args.rainbow_info}")
                console.print(f"[cyan]Tamanho:[/cyan] {info['size_mb']:.1f} MB")
                console.print(f"[cyan]Hash Type:[/cyan] {info.get('hash_type', 'Unknown')}")
                console.print(f"[cyan]Charset:[/cyan] {info.get('charset', 'Unknown')}")
                console.print(f"[cyan]Comprimento:[/cyan] {info.get('length_range', 'Unknown')}")
                console.print(f"[cyan]Chains:[/cyan] {info.get('chain_count', 0):,}")
                if 'chain_length' in info:
                    console.print(f"[cyan]Chain Length:[/cyan] {info['chain_length']:,}")
            else:
                console.print(f"[red][!] Rainbow Table não encontrada: {args.rainbow_info}[/red]")
            
            return
        
        # === HASH CRACKER AVANÇADO ===
        elif args.hash_crack:
            print_info(f"Iniciando quebra de hash: {args.hash_crack[:16]}...")
            
            # Detecta tipo se auto
            hash_type = args.hash_type
            if hash_type == 'auto':
                hash_type = detect_hash_type(args.hash_crack)
                console.print(f"[*] Tipo de hash detectado: [cyan]{hash_type}[/cyan]")
            
            # Configura uso de GPU
            use_gpu = args.use_gpu or (not args.no_gpu)  # Default true, unless --no-gpu
            
            # Mostra info de GPU se solicitado
            if args.gpu_info or args.show_performance_estimate:
                from ..modules.hash_cracker import GPUManager
                gpu_manager = GPUManager()
                
                if args.gpu_info:
                    console.print("\n[bold cyan]=== Informações GPU ===[/bold cyan]")
                    if gpu_manager.gpu_available:
                        console.print(f"[bold green][+] GPU Disponível: {gpu_manager.gpu_type}[/bold green]")
                        for gpu in gpu_manager.gpu_devices:
                            console.print(f"    Nome: {gpu.get('name', 'Unknown')}")
                            console.print(f"    Memória: {gpu.get('memory', 0) / (1024**3):.1f} GB")
                            if gpu_manager.gpu_type == 'CUDA':
                                console.print(f"    CUDA Cores: ~{gpu.get('cuda_cores', 0)}")
                    else:
                        console.print("[yellow][-] Nenhuma GPU compatível detectada[/yellow]")
                
                if args.show_performance_estimate:
                    estimate = gpu_manager.estimate_performance_gain()
                    console.print(f"\n[bold cyan]Estimativa de Performance:[/bold cyan]")
                    console.print(f"GPU vs CPU: [bold green]{estimate:.0f}x mais rápido[/bold green]")
                    if estimate > 100:
                        console.print("[bold yellow]RECOMENDAÇÃO: Use GPU para máxima performance![/bold yellow]")
                    console.print()
            
            # Cria cracker com configurações GPU
            cracker = AdvancedHashCracker(args.hash_crack, hash_type, use_gpu=use_gpu, verbose=args.verbose)
            cracker.set_performance_mode(args.hash_performance)
            
            # Aplica limite de memória GPU se especificado
            if args.gpu_memory_limit and cracker.use_gpu:
                console.print(f"[*] Limitando uso de GPU a {args.gpu_memory_limit} MB")
                # Implementar limitação de memória (futuro)
            
            if args.verbose:
                console.print(f"[*] Modo de performance: {args.hash_performance}")
                console.print(f"[*] Workers: {cracker.workers}")
                console.print(f"[*] Tipo de hash: {cracker.hash_type}")
                console.print(f"[*] GPU: {'Ativada' if cracker.use_gpu else 'Desativada'}")
                if cracker.use_gpu and cracker.gpu_manager:
                    console.print(f"[*] GPU Type: {cracker.gpu_manager.gpu_type}")
                    gain = cracker.gpu_manager.estimate_performance_gain()
                    console.print(f"[*] Estimativa de ganho: {gain:.0f}x")
            
            # Determina wordlist padrão se não especificada
            wordlist_path = args.hash_wordlist
            if not wordlist_path and args.attack_mode in ['dictionary', 'all']:
                import os
                default_wordlist = os.path.join(os.path.dirname(__file__), '..', 'data', 'wordlists', 'common_passwords.txt')
                if os.path.exists(default_wordlist):
                    wordlist_path = default_wordlist
                    console.print(f"[*] Usando wordlist padrão: {os.path.basename(wordlist_path)}")
            
            results = None
            password_found = False
            
            # Executa ataques baseado no modo
            if args.attack_mode == 'rainbow':
                console.print(f"\n[*] === ATAQUE RAINBOW TABLE ===")
                
                password, attempts, time_taken = cracker.rainbow_table_attack(
                    table_path=args.rainbow_table,
                    auto_generate=args.rainbow_generate
                )
                if password:
                    password_found = True
                    results = {
                        'mode': 'rainbow',
                        'password': password,
                        'attempts': attempts,
                        'time': time_taken
                    }
            
            # Para modo 'all', executa sequência otimizada diretamente
            if args.attack_mode == 'all':
                console.print("[*] Modo 'all': tentando todos os ataques disponíveis")
                
                # 1. Rainbow Tables (mais rápido)
                console.print("\n[*] === TENTATIVA 1: RAINBOW TABLES ===")
                password, attempts, time_taken = cracker.rainbow_table_attack(auto_generate=False)
                if password:
                    password_found = True
                    results = {
                        'mode': 'rainbow',
                        'password': password,
                        'attempts': attempts,
                        'time': time_taken
                    }
                
                # 2. Dictionary Attack
                if not password_found and wordlist_path:
                    console.print("\n[*] === TENTATIVA 2: DICTIONARY ATTACK ===")
                    password, attempts, time_taken = cracker.dictionary_attack(wordlist_path)
                    if password:
                        password_found = True
                        results = {
                            'mode': 'dictionary',
                            'password': password,
                            'attempts': attempts,
                            'time': time_taken
                        }
                
                # 3. Toggle Case Attack
                if not password_found and wordlist_path:
                    console.print("\n[*] === TENTATIVA 3: TOGGLE CASE ATTACK ===")
                    password, attempts, time_taken = cracker.toggle_case_attack(wordlist_path)
                    if password:
                        password_found = True
                        results = {
                            'mode': 'toggle_case',
                            'password': password,
                            'attempts': attempts,
                            'time': time_taken
                        }
                
                # 4. Hybrid Attack (wordlist + common suffixes)
                if not password_found and wordlist_path:
                    console.print("\n[*] === TENTATIVA 4: HYBRID ATTACK (suffix ?d?d) ===")
                    password, attempts, time_taken = cracker.hybrid_attack(wordlist_path, mask_suffix="?d?d")
                    if password:
                        password_found = True
                        results = {
                            'mode': 'hybrid',
                            'password': password,
                            'attempts': attempts,
                            'time': time_taken
                        }
                
                # 5. PRINCE Attack (se wordlist disponível)
                if not password_found and wordlist_path:
                    console.print("\n[*] === TENTATIVA 5: PRINCE ATTACK ===")
                    password, attempts, time_taken = cracker.prince_attack(wordlist_path, elements_per_chain=3)
                    if password:
                        password_found = True
                        results = {
                            'mode': 'prince',
                            'password': password,
                            'attempts': attempts,
                            'time': time_taken
                        }
                
                # 6. Increment Attack (otimizado)
                if not password_found:
                    console.print("\n[*] === TENTATIVA 6: INCREMENT ATTACK (1-4 chars) ===")
                    password, attempts, time_taken = cracker.increment_attack(1, 4)
                    if password:
                        password_found = True
                        results = {
                            'mode': 'increment',
                            'password': password,
                            'attempts': attempts,
                            'time': time_taken
                        }
                
                # 7. Brute Force (último recurso - mais lento)
                if not password_found:
                    console.print("\n[*] === TENTATIVA 7: BRUTE FORCE (1-4 chars) - ÚLTIMO RECURSO ===")
                    password, attempts, time_taken = cracker.brute_force_attack(1, 4, "abcdefghijklmnopqrstuvwxyz0123456789")
                    if password:
                        password_found = True
                        results = {
                            'mode': 'brute_force',
                            'password': password,
                            'attempts': attempts,
                            'time': time_taken
                        }
            
            # Para ataques individuais, mantém implementação específica
            elif args.attack_mode == 'dictionary':
                if wordlist_path:
                    console.print(f"\n[*] === ATAQUE DE DICIONÁRIO ===")
                    
                    # Aplica regras se especificadas
                    rules = None
                    if args.hash_rules:
                        rules = args.hash_rules.split(',')
                        console.print(f"[*] Regras ativas: {', '.join(rules)}")
                    
                    password, attempts, time_taken = cracker.dictionary_attack(wordlist_path, rules)
                    if password:
                        password_found = True
                        results = {
                            'mode': 'dictionary',
                            'password': password,
                            'attempts': attempts,
                            'time': time_taken
                        }
                else:
                    console.print(f"[yellow][!] Wordlist não especificada para ataque de dicionário[/yellow]")
            
            elif args.attack_mode == 'hybrid':
                if wordlist_path:
                    console.print(f"\n[*] === ATAQUE HÍBRIDO ===")
                    mask_suffix = getattr(args, 'mask_suffix', '?d?d')
                    mask_prefix = getattr(args, 'mask_prefix', '')
                    password, attempts, time_taken = cracker.hybrid_attack(wordlist_path, mask_suffix, mask_prefix)
                    if password:
                        password_found = True
                        results = {
                            'mode': 'hybrid',
                            'password': password,
                            'attempts': attempts,
                            'time': time_taken
                        }
                else:
                    console.print(f"[yellow][!] Wordlist não especificada para ataque híbrido[/yellow]")
            
            elif args.attack_mode == 'combinator':
                if wordlist_path:
                    wordlist2_path = getattr(args, 'wordlist2', None)
                    if wordlist2_path:
                        console.print(f"\n[*] === ATAQUE COMBINADOR ===")
                        separator = getattr(args, 'separator', '')
                        password, attempts, time_taken = cracker.combinator_attack(wordlist_path, wordlist2_path, separator)
                        if password:
                            password_found = True
                            results = {
                                'mode': 'combinator',
                                'password': password,
                                'attempts': attempts,
                                'time': time_taken
                            }
                    else:
                        console.print(f"[yellow][!] Segunda wordlist não especificada (use --wordlist2)[/yellow]")
                else:
                    console.print(f"[yellow][!] Wordlists não especificadas para ataque combinador[/yellow]")
            
            elif args.attack_mode == 'toggle_case':
                if wordlist_path:
                    console.print(f"\n[*] === ATAQUE TOGGLE CASE ===")
                    password, attempts, time_taken = cracker.toggle_case_attack(wordlist_path)
                    if password:
                        password_found = True
                        results = {
                            'mode': 'toggle_case',
                            'password': password,
                            'attempts': attempts,
                            'time': time_taken
                        }
                else:
                    console.print(f"[yellow][!] Wordlist não especificada para ataque toggle case[/yellow]")
            
            elif args.attack_mode == 'increment':
                console.print(f"\n[*] === ATAQUE INCREMENTAL ===")
                password, attempts, time_taken = cracker.increment_attack(args.min_length, args.max_length, args.charset)
                if password:
                    password_found = True
                    results = {
                        'mode': 'increment',
                        'password': password,
                        'attempts': attempts,
                        'time': time_taken
                    }
            
            elif args.attack_mode == 'prince':
                if wordlist_path:
                    console.print(f"\n[*] === ATAQUE PRINCE ===")
                    elements_per_chain = getattr(args, 'elements_per_chain', 4)
                    password, attempts, time_taken = cracker.prince_attack(wordlist_path, elements_per_chain)
                    if password:
                        password_found = True
                        results = {
                            'mode': 'prince',
                            'password': password,
                            'attempts': attempts,
                            'time': time_taken
                        }
                else:
                    console.print(f"[yellow][!] Wordlist não especificada para ataque PRINCE[/yellow]")
            
            elif args.attack_mode == 'online':
                console.print(f"\n[*] === LOOKUP ONLINE ===")
                password = cracker.online_lookup()
                if password:
                    password_found = True
                    results = {
                        'mode': 'online',
                        'password': password,
                        'attempts': 0,
                        'time': 0
                    }
            
            elif args.attack_mode == 'mask':
                if args.mask_pattern:
                    console.print(f"\n[*] === ATAQUE POR MÁSCARA ===")
                    password, attempts, time_taken = cracker.mask_attack(args.mask_pattern)
                    if password:
                        password_found = True
                        results = {
                            'mode': 'mask',
                            'password': password,
                            'attempts': attempts,
                            'time': time_taken
                        }
                else:
                    console.print(f"[yellow][!] Padrão de máscara não especificado (use --mask-pattern)[/yellow]")
            
            elif args.attack_mode == 'brute_force':
                console.print(f"\n[*] === ATAQUE DE FORÇA BRUTA ===")
                if args.max_length > 8:
                    console.print(f"[yellow][!] Aviso: Comprimento máximo {args.max_length} pode demorar muito![/yellow]")
                
                password, attempts, time_taken = cracker.brute_force_attack(
                    args.min_length, 
                    args.max_length, 
                    args.charset
                )
                if password:
                    password_found = True
                    results = {
                        'mode': 'brute_force',
                        'password': password,
                        'attempts': attempts,
                        'time': time_taken
                    }
            
            # Exibe estatísticas finais
            if args.show_hash_stats:
                stats = cracker.get_statistics()
                console.print(f"\n[bold cyan]📊 Estatísticas Finais:[/bold cyan]")
                console.print(f"    • Hash Type: {stats.get('hash_type', 'N/A')}")
                console.print(f"    • Total Attempts: {stats.get('attempts', 0):,}")
                console.print(f"    • Workers: {stats.get('workers', 0)}")
                console.print(f"    • Performance Mode: {stats.get('performance_mode', 'N/A')}")
                if stats.get('elapsed_time', 0) > 0:
                    console.print(f"    • Rate: {stats.get('rate_per_second', 0):.0f} hashes/second")
            
            if not password_found:
                console.print(f"\n[red][-] Hash não foi quebrado com os métodos utilizados[/red]")
                console.print(f"[*] Sugestões:")
                console.print(f"    • Tente uma wordlist maior")
                console.print(f"    • Use modo 'all' para tentar todos os ataques")
                console.print(f"    • Considere usar --hash-rules para transformações")
                if args.attack_mode != 'all':
                    console.print(f"    • Tente --attack-mode all")
            
            results = results or {'success': False}
        
        # === NETWORK MONITOR ===
        elif args.network_monitor:
            print_info("Iniciando Network Monitor...")
            network_monitor_interface(interface=args.network_interface)
            return
        
        else:
            print_error("Nenhuma operação especificada")
            parser.print_help()
            return
        
        # Enriquecer resultados com CVE se solicitado
        if args.enrich_cve and 'results' in locals() and results:
            print_info("Enriquecendo resultados com dados de CVE...")
            results = integrate_cve_data(results)
        
        # Gerar relatório se solicitado
        if args.generate_report and 'results' in locals() and results:
            try:
                # Determinar o tipo de scan baseado nos argumentos
                scan_type = "unknown"
                target_url = "unknown"
                
                if args.sql_injection:
                    scan_type = "SQL Injection"
                    target_url = args.sql_injection
                elif args.xss_scan:
                    scan_type = "XSS"
                    target_url = args.xss_scan
                elif args.command_injection:
                    scan_type = "Command Injection"
                    target_url = args.command_injection
                elif args.lfi_scan:
                    scan_type = "LFI/RFI"
                    target_url = args.lfi_scan
                elif args.port_scan:
                    scan_type = "Port Scan"
                    target_url = args.port_scan
                
                print_info(f"Gerando relatório em formato {args.generate_report}...")
                
                # Garantir que results é uma lista
                if not isinstance(results, list):
                    results = []
                
                report_file = generate_report_wrapper(
                    scan_results=results,
                    target_url=target_url,
                    scan_type=scan_type,
                    output_format=args.generate_report,
                    output_file=args.report_file
                )
                
                if args.generate_report == 'all':
                    print_info("Relatórios gerados:")
                    for format_type, file_path in report_file.items():
                        print_info(f"  {format_type.upper()}: {file_path}")
                else:
                    print_info(f"Relatório gerado: {report_file}")
                    
            except Exception as e:
                print_error(f"Erro ao gerar relatório: {e}")
                if args.verbose:
                    import traceback
                    traceback.print_exc()
            
    except KeyboardInterrupt:
        print_error("Operação cancelada pelo usuário")
        sys.exit(1)
    except Exception as e:
        print_error(f"Erro inesperado: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
