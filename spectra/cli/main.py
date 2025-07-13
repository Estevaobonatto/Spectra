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
from ..modules.sql_injection_scanner import sql_injection_scan
from ..modules.xss_scanner import xss_scan
from ..modules.command_injection_scanner import command_injection_scan
from ..modules.lfi_scanner import lfi_scan
from ..modules.cve_integrator import integrate_cve_data, CVEIntegrator

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
    
    parser.add_argument('--advanced-subdomain',
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
                       version='Spectra v3.2.6')
    
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
            print_info(f"Iniciando scan de subdomínios em: {args.subdomain_scan}")
            
            if args.advanced_subdomain:
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
                    print_error("Wordlist é obrigatória para subdomain scan (use --advanced-subdomain --passive-only para modo passivo)")
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
