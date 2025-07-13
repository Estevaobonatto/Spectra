# -*- coding: utf-8 -*-
"""
Advanced Port Scanner for Spectra
"""

import socket
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core import console, print_info, print_success, print_error
from ..core.logger import logger
from ..utils import parse_ports, get_top_ports, validate_timeout, validate_workers
from ..utils.network import resolve_hostname, ping_host, is_valid_ip

class AdvancedPortScanner:
    """Scanner de portas avançado com múltiplas funcionalidades."""
    
    def __init__(self, target, scan_type='tcp', timeout=1.0, delay=0, max_workers=50, verbose=False):
        self.target = target
        self.target_ip = None
        self.scan_type = scan_type.lower()
        self.timeout = timeout
        self.delay = delay
        self.max_workers = max_workers
        self.verbose = verbose
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
            if is_valid_ip(self.target):
                self.target_ip = self.target
            else:
                self.target_ip = resolve_hostname(self.target)
                
            if not self.target_ip:
                print_error(f"Não foi possível resolver '{self.target}'")
                return False
                
            if self.verbose:
                console.print(f"[dim cyan]→[/dim cyan] [dim]DNS resolvido: {self.target} → {self.target_ip}[/dim]")
            return True
        except Exception as e:
            print_error(f"Erro ao resolver '{self.target}': {e}")
            return False
    
    def host_discovery(self):
        """Verifica se o host está ativo usando ping."""
        if self.verbose:
            console.print(f"[dim cyan]→[/dim cyan] [dim]Verificando conectividade: {self.target}[/dim]")
        
        # Tenta ping primeiro
        if ping_host(self.target_ip, count=1, timeout=2):
            if self.verbose:
                console.print(f"  [dim green]✓[/dim green] [dim]Host responde ao ping[/dim]")
            return True
        
        if self.verbose:
            console.print(f"  [dim yellow]⚠[/dim yellow] [dim]Ping falhou, testando portas TCP[/dim]")
        
        # Fallback: tenta conectar em portas comuns
        common_ports = [80, 443, 22, 21, 25, 53]
        for port in common_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1.0)
                    result = s.connect_ex((self.target_ip, port))
                    if result == 0:
                        if self.verbose:
                            console.print(f"  [dim green]✓[/dim green] [dim]Conectou na porta {port}[/dim]")
                        return True
            except:
                continue
        
        if self.verbose:
            console.print(f"  [dim red]✗[/dim red] [dim]Host não respondeu em nenhuma porta[/dim]")
        return False
    
    def tcp_connect_scan(self, port):
        """TCP Connect scan - mais compatível mas detectável."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                result = s.connect_ex((self.target_ip, port))
                if result == 0:
                    if self.verbose:
                        console.print(f"[dim cyan]•[/dim cyan] [dim]Porta {port}/tcp[/dim] [green]ABERTA[/green]")
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
                
                # Payloads específicos
                payload = self._get_udp_payload(port)
                
                # Tenta múltiplas vezes para UDP (pode haver perda de pacotes)
                for attempt in range(2):
                    s.sendto(payload, (self.target_ip, port))
                    
                    try:
                        data, addr = s.recvfrom(1024)
                        # Analisa a resposta para determinar o serviço
                        service_info = self._analyze_udp_response(port, data)
                        if self.verbose:
                            console.print(f"[dim cyan]•[/dim cyan] [dim]Porta {port}/udp[/dim] [green]RESPOSTA[/green]")
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
    
    def _get_udp_payload(self, port):
        """Retorna payload UDP específico para a porta."""
        payloads = {
            53: b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01',  # DNS query
            123: b'\x1b' + b'\x00' * 47,  # NTP query
            161: b'\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00',  # SNMP query
            67: b'\x01\x01\x06\x00\x00\x00\x3d\x1d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # DHCP Discover
            68: b'\x01\x01\x06\x00\x00\x00\x3d\x1d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # DHCP
            69: b'\x00\x01test\x00netascii\x00',  # TFTP
            514: b'<14>test syslog message',  # Syslog
            1900: b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nST: upnp:rootdevice\r\nMX: 3\r\n\r\n',  # UPnP SSDP
            5353: b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01'  # mDNS
        }
        
        return payloads.get(port, b'')
    
    def _analyze_udp_response(self, port, data):
        """Analisa resposta UDP para identificar serviço."""
        info = {}
        
        if port == 53 and len(data) >= 12:  # DNS
            info['service'] = 'DNS'
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
        
        if self.verbose:
            console.print(f"[dim cyan]→[/dim cyan] [dim]Capturando banner: {port}[/dim]")
        
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
                    if self.verbose:
                        truncated_banner = banner.replace('\n', ' ').strip()[:60]
                        console.print(f"  [dim green]✓[/dim green] [dim]Banner: {truncated_banner}{'...' if len(banner) > 60 else ''}[/dim]")
                    service_info.update(self._analyze_banner(banner, port))
                elif self.verbose:
                    console.print(f"  [dim yellow]⚠[/dim yellow] [dim]Nenhum banner recebido[/dim]")
                
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
        print_info(f"Scanner Avançado de Portas - Spectra v3.3.0")
        print_info(f"Alvo: [bold cyan]{self.target}[/bold cyan] ({self.target_ip})")
        print_info(f"Tipo de scan: [bold cyan]{self.scan_type.upper()}[/bold cyan]")
        print_info(f"Portas: [bold cyan]{len(ports)}[/bold cyan]")
        print_info(f"Timeout: [bold cyan]{self.timeout}s[/bold cyan]")
        print_info(f"Workers: [bold cyan]{self.max_workers}[/bold cyan]")
        if self.delay > 0:
            print_info(f"Delay: [bold cyan]{self.delay}ms[/bold cyan]")
        if self.verbose:
            print_info(f"Modo verbose: [bold cyan]Ativado[/bold cyan]")
            console.print("[dim]  → Mostrando detalhes do scan[/dim]")
        print_info(f"Início: [bold cyan]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/bold cyan]")
        console.print("-" * 60)
        
        # Log do início do scan
        logger.scan_start("PORT_SCAN", self.target)
        
        results = {}
        open_ports = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_port = {executor.submit(self.scan_single_port, port): port for port in ports}
            
            if show_progress:
                from ..core.console import create_progress
                with create_progress() as progress:
                    task = progress.add_task(f"[green]Scan {self.scan_type.upper()}...", total=len(ports))
                    
                    for future in as_completed(future_to_port):
                        result = future.result()
                        if result:
                            port = result['port']
                            results[port] = result
                            
                            # Adiciona à lista de portas abertas
                            if result.get('status') == 'open':
                                open_ports.append(result)
                                service = result.get('service_info', {}).get('service', result.get('service', 'Unknown'))
                                protocol = result.get('method', 'tcp').replace('_connect', '').replace('_', '-')
                                print_success(f"{port}/{protocol} open [cyan]{service}[/cyan]")
                            elif result.get('status') == 'open|filtered' and self.scan_type == 'udp':
                                # Para UDP, inclui portas filtered nos resultados se payload foi enviado
                                if result.get('payload_sent'):
                                    open_ports.append(result)
                                    console.print(f"[bold yellow][?] {port}/udp open|filtered [cyan](payload sent)[/cyan][/bold yellow]")
                        
                        progress.update(task, advance=1)
            else:
                for future in as_completed(future_to_port):
                    result = future.result()
                    if result:
                        port = result['port']
                        results[port] = result
                        
                        # Adiciona à lista de portas abertas
                        if result.get('status') == 'open':
                            open_ports.append(result)
                            service = result.get('service_info', {}).get('service', result.get('service', 'Unknown'))
                            protocol = result.get('method', 'tcp').replace('_connect', '').replace('_', '-')
                            print_success(f"{port}/{protocol} open [cyan]{service}[/cyan]")
        
        self.results = results
        self._display_results(open_ports)
        
        # Log do fim do scan
        logger.scan_end("PORT_SCAN", self.target, len(open_ports))
        
        return results
    
    def _display_results(self, open_ports):
        """Exibe resultados de forma organizada."""
        console.print("-" * 60)
        print_info("Scan concluído.")
        
        if not open_ports:
            console.print("[bold yellow][-] Nenhuma porta aberta encontrada.[/bold yellow]")
            console.print("-" * 60)
            return
        
        # Organiza por porta
        open_ports.sort(key=lambda x: x['port'])
        
        # Tabela principal
        from ..core.console import create_table
        table = create_table(f"Portas Abertas - {self.target}", [
            {"header": "Porta", "justify": "center", "style": "cyan"},
            {"header": "Status", "justify": "center", "style": "green"},
            {"header": "Serviço", "style": "magenta"},
            {"header": "Software", "style": "yellow"},
            {"header": "Banner/Info", "style": "dim", "max_width": 40}
        ])
        
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
        print_success(f"{len(open_ports)} portas abertas encontradas")
        
        # Serviços únicos
        services = set()
        for result in open_ports:
            service_info = result.get('service_info', {})
            if service_info.get('software'):
                services.add(service_info['software'])
            elif result.get('service') and result.get('service') != 'Unknown':
                services.add(result['service'])
            elif service_info.get('service'):
                services.add(service_info['service'])
        
        # Filtra valores None e ordena
        valid_services = [s for s in services if s is not None]
        if valid_services:
            print_info(f"Serviços detectados: [cyan]{', '.join(sorted(valid_services))}[/cyan]")
        
        console.print("-" * 60)

# Funções de compatibilidade
def scan_ports(target, port_spec="80,443,22,21,25", scan_type='tcp', timeout=1.0, delay=0, 
               workers=50, verbose=False, top_ports=None, host_discovery=False, 
               output_format='table', **kwargs):
    """
    Interface principal para scan de portas.
    
    Args:
        target: Host ou IP para scanear
        port_spec: Especificação de portas (ex: "80,443", "1-1000")
        scan_type: Tipo de scan ('tcp', 'syn', 'udp')
        timeout: Timeout em segundos
        delay: Delay entre requests em ms
        workers: Número de threads
        verbose: Modo verbose
        top_ports: Número de top ports para usar
        host_discovery: Fazer discovery do host antes
        output_format: Formato de saída ('table', 'json', 'xml')
    """
    
    # Valida parâmetros
    valid_timeout, timeout = validate_timeout(timeout)
    if not valid_timeout:
        print_error(f"Timeout inválido: {timeout}")
        return {}
    
    valid_workers, workers = validate_workers(workers)
    if not valid_workers:
        print_error(f"Workers inválido: {workers}")
        return {}
    
    # Cria scanner
    scanner = AdvancedPortScanner(
        target=target,
        scan_type=scan_type,
        timeout=timeout,
        delay=delay,
        max_workers=workers,
        verbose=verbose
    )
    
    # Resolve o target
    if not scanner.resolve_target():
        return {}
    
    # Host discovery se solicitado
    if host_discovery:
        print_info(f"Verificando se {target} está ativo...")
        if not scanner.host_discovery():
            console.print(f"[yellow]Host {target} não responde - prosseguindo mesmo assim[/yellow]")
    
    # Determina portas para escanear
    if top_ports:
        ports_to_scan = get_top_ports(top_ports)
        print_info(f"Escaneando top {top_ports} portas mais comuns")
        if verbose:
            ports_preview = ", ".join(map(str, ports_to_scan[:10]))
            console.print(f"[dim cyan]→[/dim cyan] [dim]Portas: {ports_preview}{'...' if len(ports_to_scan) > 10 else ''}[/dim]")
    else:
        try:
            ports_to_scan = parse_ports(port_spec)
        except ValueError as e:
            print_error(str(e))
            return {}
        
        if not ports_to_scan:
            print_error("Nenhuma porta válida especificada")
            return {}
        
        if verbose:
            ports_preview = ", ".join(map(str, ports_to_scan[:10]))
            console.print(f"[dim cyan]→[/dim cyan] [dim]Portas: {ports_preview}{'...' if len(ports_to_scan) > 10 else ''}[/dim]")
    
    results = scanner.scan_ports(ports_to_scan)
    
    # Output em diferentes formatos
    if output_format == 'json':
        import json
        return json.dumps(results, default=str, indent=2)
    elif output_format == 'xml':
        return _results_to_xml(results, target)
    
    return results

def _results_to_xml(results, target):
    """Converte resultados para formato XML (similar ao nmap)."""
    xml_output = f"""<?xml version="1.0" encoding="UTF-8"?>
<spectra_scan>
    <scaninfo type="port" protocol="tcp" numservices="{len(results)}"/>
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

# Funções legacy para compatibilidade
def scan_port(target_ip, port, grab_banner_flag=False):
    """Função legacy para compatibilidade."""
    scanner = AdvancedPortScanner(target_ip, verbose=False)
    if not scanner.resolve_target():
        return None
    
    result = scanner.scan_single_port(port)
    if result and result.get('status') == 'open':
        service = result.get('service', 'Unknown')
        banner = result.get('banner', '') if grab_banner_flag else ''
        return (port, service, banner)
    
    return None

def scan_ports_threaded(host, port_spec, verbose=False, grab_banner_flag=False, 
                       workers=100, scan_type='tcp', timeout=1.0, delay=0):
    """Interface de compatibilidade - usa o scanner avançado."""
    return scan_ports(
        target=host,
        port_spec=port_spec,
        scan_type=scan_type,
        timeout=timeout,
        delay=delay,
        workers=workers,
        verbose=verbose
    )
