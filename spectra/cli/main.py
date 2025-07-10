# -*- coding: utf-8 -*-
"""
Main CLI interface for Spectra
"""

import sys
import argparse
from ..core import display_banner, display_legal_warning, console, print_error, print_info
from ..modules.port_scanner import scan_ports
from ..modules.banner_grabber import BannerGrabber
from ..modules.directory_scanner import advanced_directory_scan
from ..modules.metadata_extractor import extract_metadata
from ..modules.subdomain_scanner import discover_subdomains
from ..modules.dns_analyzer import query_dns
from ..modules.whois_analyzer import get_whois_info
from ..modules.waf_detector import detect_waf
from ..modules.ssl_analyzer import get_ssl_info
from ..modules.headers_analyzer import get_http_headers
from ..modules.sql_injection_scanner import sql_injection_scan
from ..modules.xss_scanner import xss_scan
from ..modules.command_injection_scanner import command_injection_scan

def create_parser():
    """Cria o parser de argumentos da linha de comando."""
    parser = argparse.ArgumentParser(
        description='Spectra - Web Security Suite',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  %(prog)s -ps example.com -p 80,443,22
  %(prog)s -ds http://example.com -w wordlist.txt
  %(prog)s -ss example.com -w subdomains.txt
  %(prog)s -dns example.com
  %(prog)s -whois example.com --security-analysis
  %(prog)s -bg example.com 80
  %(prog)s -md http://example.com/image.jpg
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
    
    # === SCANNER DE DIRETÓRIOS ===
    parser.add_argument('-ds', '--directory-scan',
                       metavar='URL',
                       help='Executa scan de diretórios na URL especificada')
    
    parser.add_argument('-w', '--wordlist',
                       metavar='FILE',
                       help='Arquivo de wordlist para scans')
    
    parser.add_argument('--recursive',
                       action='store_true',
                       help='Ativar modo recursivo para directory scan')
    
    parser.add_argument('--max-depth',
                       type=int,
                       default=3,
                       help='Profundidade máxima para scan recursivo')
    
    parser.add_argument('--stealth',
                       action='store_true',
                       help='Ativar modo stealth (mais lento)')
    
    # === SCANNER DE SUBDOMÍNIOS ===
    parser.add_argument('-ss', '--subdomain-scan',
                       metavar='DOMAIN',
                       help='Executa scan de subdomínios no domínio especificado')
    
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
    
    parser.add_argument('--verbose', '-v',
                       action='store_true',
                       help='Modo verbose')
    
    parser.add_argument('--no-banner',
                       action='store_true',
                       help='Não exibe o banner')
    
    parser.add_argument('--version',
                       action='version',
                       version='Spectra v3.2.6')
    
    return parser

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
            
            results = advanced_directory_scan(
                base_url=args.directory_scan,
                wordlist_path=args.wordlist,
                workers=args.workers,
                timeout=args.timeout,
                recursive=args.recursive,
                max_depth=args.max_depth,
                stealth=args.stealth,
                output_format=args.output_format
            )
        
        # === SCANNER DE SUBDOMÍNIOS ===
        elif args.subdomain_scan:
            if not args.wordlist:
                print_error("Wordlist é obrigatória para subdomain scan")
                sys.exit(1)
            
            print_info(f"Iniciando scan de subdomínios em: {args.subdomain_scan}")
            
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
        
        else:
            print_error("Nenhuma operação especificada")
            parser.print_help()
            
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
