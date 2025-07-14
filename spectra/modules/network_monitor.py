# -*- coding: utf-8 -*-
"""
Network Monitor Module - Spectra
Interface similar ao Wireshark para monitoramento de rede
Versão TUI com captura e análise de pacotes em tempo real
"""

import threading
import time
import os
from datetime import datetime
from collections import defaultdict
from typing import List
import json

try:
    from scapy.all import (
        sniff, get_if_list, Ether, IP, TCP, UDP, ICMP, ARP, DNS, 
        conf
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Aviso: Scapy não está disponível. Instale com: pip install scapy")

try:
    import curses
    CURSES_AVAILABLE = True
except ImportError:
    CURSES_AVAILABLE = False

from ..core.console import console
from ..core.logger import get_logger

logger = get_logger(__name__)

class HTTPAnalyzer:
    """Classe para análise detalhada de tráfego HTTP/HTTPS"""
    
    def __init__(self):
        self.http_requests = []
        self.http_responses = []
        self.suspicious_patterns = [
            # Padrões de ataques comuns
            b'<script',  # Possível XSS
            b'union.*select',  # SQL Injection
            b'../../../',  # Directory Traversal
            b'eval(',  # Code Injection
            b'system(',  # Command Injection
            b'passwd',  # Password file access
            b'/etc/shadow',  # Shadow file access
            b'drop table',  # SQL Drop
            b'wget',  # Download commands
            b'curl',  # Download commands
        ]
    
    def analyze_http_packet(self, packet):
        """Analisa pacote HTTP e extrai informações detalhadas"""
        if not hasattr(packet, 'raw_packet') or not hasattr(packet.raw_packet, 'load'):
            return None
        
        try:
            payload = bytes(packet.raw_packet.load)
            text_payload = payload.decode('utf-8', errors='ignore')
            
            # Detecta se é request ou response
            if self._is_http_request(text_payload):
                return self._parse_http_request(packet, payload, text_payload)
            elif self._is_http_response(text_payload):
                return self._parse_http_response(packet, payload, text_payload)
                
        except Exception as e:
            logger.debug(f"Erro ao analisar HTTP: {e}")
        
        return None
    
    def _is_http_request(self, text):
        """Verifica se é uma requisição HTTP"""
        methods = ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ', 'TRACE ']
        return any(text.startswith(method) for method in methods)
    
    def _is_http_response(self, text):
        """Verifica se é uma resposta HTTP"""
        return text.startswith('HTTP/')
    
    def _parse_http_request(self, packet, payload, text):
        """Analisa requisição HTTP em detalhes"""
        lines = text.split('\n')
        if not lines:
            return None
        
        # Parse da primeira linha (método, URL, versão)
        first_line = lines[0].strip()
        parts = first_line.split(' ')
        if len(parts) < 3:
            return None
        
        method = parts[0]
        url = parts[1]
        version = parts[2]
        
        # Parse dos headers
        headers = {}
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if line.strip() == '':
                body_start = i + 1
                break
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
        
        # Parse do body (se houver)
        body = '\n'.join(lines[body_start:]) if body_start < len(lines) else ''
        
        # Análise de segurança
        security_issues = self._analyze_security_issues(payload, text, method, url, headers, body)
        
        return {
            'type': 'request',
            'timestamp': packet.timestamp,
            'src_ip': packet.src_ip,
            'dst_ip': packet.dst_ip,
            'src_port': packet.src_port,
            'dst_port': packet.dst_port,
            'method': method,
            'url': url,
            'version': version,
            'headers': headers,
            'body': body,
            'size': len(payload),
            'security_issues': security_issues,
            'user_agent': headers.get('user-agent', 'N/A'),
            'host': headers.get('host', 'N/A'),
            'content_type': headers.get('content-type', 'N/A'),
            'cookies': headers.get('cookie', 'N/A')
        }
    
    def _parse_http_response(self, packet, payload, text):
        """Analisa resposta HTTP em detalhes"""
        lines = text.split('\n')
        if not lines:
            return None
        
        # Parse da primeira linha (versão, status, reason)
        first_line = lines[0].strip()
        parts = first_line.split(' ', 2)
        if len(parts) < 2:
            return None
        
        version = parts[0]
        status_code = parts[1]
        reason = parts[2] if len(parts) > 2 else ''
        
        # Parse dos headers
        headers = {}
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if line.strip() == '':
                body_start = i + 1
                break
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
        
        # Parse do body
        body = '\n'.join(lines[body_start:]) if body_start < len(lines) else ''
        
        # Análise de segurança da resposta
        security_issues = self._analyze_response_security(payload, text, status_code, headers, body)
        
        return {
            'type': 'response',
            'timestamp': packet.timestamp,
            'src_ip': packet.src_ip,
            'dst_ip': packet.dst_ip,
            'src_port': packet.src_port,
            'dst_port': packet.dst_port,
            'version': version,
            'status_code': status_code,
            'reason': reason,
            'headers': headers,
            'body': body,
            'size': len(payload),
            'security_issues': security_issues,
            'content_type': headers.get('content-type', 'N/A'),
            'server': headers.get('server', 'N/A'),
            'set_cookies': headers.get('set-cookie', 'N/A')
        }
    
    def _analyze_security_issues(self, _payload, _text, method, url, headers, body):
        """Analisa problemas de segurança em requisições HTTP"""
        issues = []
        
        # Verifica padrões suspeitos na URL
        url_lower = url.lower()
        if any(pattern.decode('utf-8', errors='ignore') in url_lower for pattern in self.suspicious_patterns):
            issues.append("SUSPICIOUS_URL_PATTERN")
        
        # Verifica SQL injection patterns
        if any(pattern in url_lower for pattern in ['union', 'select', 'drop', 'insert', 'update', 'delete']):
            issues.append("POSSIBLE_SQL_INJECTION")
        
        # Verifica XSS patterns
        if any(pattern in url_lower for pattern in ['<script', 'javascript:', 'onerror', 'onload']):
            issues.append("POSSIBLE_XSS")
        
        # Verifica directory traversal
        if '../' in url or '..\\' in url:
            issues.append("DIRECTORY_TRAVERSAL")
        
        # Verifica User-Agent suspeito
        user_agent = headers.get('user-agent', '').lower()
        suspicious_agents = ['sqlmap', 'nikto', 'burp', 'nmap', 'gobuster', 'dirb']
        if any(agent in user_agent for agent in suspicious_agents):
            issues.append("SUSPICIOUS_USER_AGENT")
        
        # Verifica body para padrões suspeitos (em POST requests)
        if method == 'POST' and body:
            body_lower = body.lower()
            if any(pattern.decode('utf-8', errors='ignore') in body_lower for pattern in self.suspicious_patterns):
                issues.append("SUSPICIOUS_POST_DATA")
        
        return issues
    
    def _analyze_response_security(self, _payload, _text, status_code, headers, body):
        """Analisa problemas de segurança em respostas HTTP"""
        issues = []
        
        # Verifica headers de segurança ausentes
        security_headers = [
            'x-frame-options',
            'x-content-type-options', 
            'x-xss-protection',
            'strict-transport-security',
            'content-security-policy'
        ]
        
        missing_headers = [h for h in security_headers if h not in headers]
        if missing_headers:
            issues.append(f"MISSING_SECURITY_HEADERS: {', '.join(missing_headers)}")
        
        # Verifica vazamento de informações no Server header
        server = headers.get('server', '')
        if any(info in server.lower() for info in ['apache/', 'nginx/', 'iis/', 'tomcat/']):
            issues.append("SERVER_VERSION_DISCLOSURE")
        
        # Verifica status codes suspeitos
        if status_code in ['500', '501', '502', '503']:
            issues.append("SERVER_ERROR_RESPONSE")
        
        # Verifica possível vazamento de dados no body
        if body and any(pattern.decode('utf-8', errors='ignore') in body.lower() for pattern in [b'error', b'exception', b'stack trace']):
            issues.append("POSSIBLE_INFO_DISCLOSURE")
        
        return issues

class TCPStream:
    """Classe para representar um stream TCP completo"""
    
    def __init__(self, src_ip, src_port, dst_ip, dst_port):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.packets = []
        self.client_data = b""
        self.server_data = b""
        self.start_time = None
        self.end_time = None
        self.is_http = False
        self.http_requests = []
        self.http_responses = []
    
    def get_stream_id(self):
        """Retorna identificador único do stream"""
        return f"{self.src_ip}:{self.src_port}-{self.dst_ip}:{self.dst_port}"
    
    def add_packet(self, packet):
        """Adiciona pacote ao stream"""
        if not self.start_time:
            self.start_time = packet.timestamp
        self.end_time = packet.timestamp
        self.packets.append(packet)
        
        # Extrai dados do payload se disponível
        if hasattr(packet, 'raw_packet') and hasattr(packet.raw_packet, 'load'):
            payload = bytes(packet.raw_packet.load)
            
            # Determina direção do fluxo
            if (packet.src_ip == self.src_ip and packet.src_port == self.src_port):
                self.client_data += payload
            else:
                self.server_data += payload
            
            # Detecta se é HTTP
            if not self.is_http and (b'HTTP/' in payload or b'GET ' in payload or b'POST ' in payload):
                self.is_http = True
                self._parse_http_data()
    
    def _parse_http_data(self):
        """Analisa dados HTTP do stream"""
        try:
            # Parse HTTP requests
            client_text = self.client_data.decode('utf-8', errors='ignore')
            for line in client_text.split('\n'):
                if any(method in line for method in ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ']):
                    self.http_requests.append(line.strip())
            
            # Parse HTTP responses
            server_text = self.server_data.decode('utf-8', errors='ignore')
            for line in server_text.split('\n'):
                if line.startswith('HTTP/'):
                    self.http_responses.append(line.strip())
        except:
            pass
    
    def get_conversation_text(self):
        """Retorna conversação formatada do stream"""
        conversation = []
        conversation.append(f"=== TCP Stream: {self.get_stream_id()} ===")
        conversation.append(f"Start: {self.start_time}")
        conversation.append(f"End: {self.end_time}")
        conversation.append(f"Packets: {len(self.packets)}")
        conversation.append(f"Protocol: {'HTTP' if self.is_http else 'TCP'}")
        conversation.append("")
        
        if self.is_http:
            conversation.append("=== HTTP Requests ===")
            for req in self.http_requests:
                conversation.append(f">>> {req}")
            conversation.append("")
            conversation.append("=== HTTP Responses ===")
            for resp in self.http_responses:
                conversation.append(f"<<< {resp}")
            conversation.append("")
        
        conversation.append("=== Client Data ===")
        try:
            client_text = self.client_data.decode('utf-8', errors='ignore')
            conversation.extend(client_text.split('\n'))
        except:
            conversation.append(f"[Binary data: {len(self.client_data)} bytes]")
        
        conversation.append("")
        conversation.append("=== Server Data ===")
        try:
            server_text = self.server_data.decode('utf-8', errors='ignore')
            conversation.extend(server_text.split('\n'))
        except:
            conversation.append(f"[Binary data: {len(self.server_data)} bytes]")
        
        return conversation

class NetworkPacket:
    """Classe para representar um pacote de rede capturado"""
    
    def __init__(self, packet_data):
        self.timestamp = datetime.now()
        self.raw_packet = packet_data
        self.size = len(packet_data) if hasattr(packet_data, '__len__') else 0
        self.src_ip = ""
        self.dst_ip = ""
        self.src_port = ""
        self.dst_port = ""
        self.protocol = ""
        self.info = ""
        
        if SCAPY_AVAILABLE:
            self._parse_scapy_packet(packet_data)
    
    def _parse_scapy_packet(self, pkt):
        """Parse detalhado do pacote usando Scapy"""
        try:
            # Ethernet layer
            if pkt.haslayer(Ether):
                self.src_mac = pkt[Ether].src
                self.dst_mac = pkt[Ether].dst
                self.eth_type = pkt[Ether].type
            
            # IP layer
            if pkt.haslayer(IP):
                self.src_ip = pkt[IP].src
                self.dst_ip = pkt[IP].dst
                self.protocol = pkt[IP].proto
                self.ttl = pkt[IP].ttl
                self.ip_len = pkt[IP].len
                self.ip_flags = pkt[IP].flags
                self.ip_frag = pkt[IP].frag
                
                # TCP
                if pkt.haslayer(TCP):
                    self.src_port = pkt[TCP].sport
                    self.dst_port = pkt[TCP].dport
                    self.protocol = "TCP"
                    self.tcp_flags = pkt[TCP].flags
                    self.tcp_seq = pkt[TCP].seq
                    self.tcp_ack = pkt[TCP].ack
                    self.tcp_window = pkt[TCP].window
                    
                    # Análise detalhada de flags TCP
                    flags = []
                    if pkt[TCP].flags & 0x01: flags.append("FIN")
                    if pkt[TCP].flags & 0x02: flags.append("SYN")
                    if pkt[TCP].flags & 0x04: flags.append("RST")
                    if pkt[TCP].flags & 0x08: flags.append("PSH")
                    if pkt[TCP].flags & 0x10: flags.append("ACK")
                    if pkt[TCP].flags & 0x20: flags.append("URG")
                    
                    # Identificar serviços e análise detalhada
                    if self.dst_port == 80:
                        self.info = f"HTTP [{','.join(flags)}]"
                        if hasattr(pkt, 'load') and b'HTTP' in bytes(pkt):
                            self.info += " - HTTP Request/Response"
                    elif self.dst_port == 443:
                        self.info = f"HTTPS/TLS [{','.join(flags)}]"
                        if 'SYN' in flags and 'ACK' not in flags:
                            self.info += " - TLS Handshake"
                    elif self.dst_port == 22:
                        self.info = f"SSH [{','.join(flags)}]"
                    elif self.dst_port == 21:
                        self.info = f"FTP [{','.join(flags)}]"
                    elif self.dst_port == 25:
                        self.info = f"SMTP [{','.join(flags)}]"
                    elif self.dst_port == 53:
                        self.info = f"DNS/TCP [{','.join(flags)}]"
                    elif self.dst_port == 993:
                        self.info = f"IMAPS [{','.join(flags)}]"
                    elif self.dst_port == 995:
                        self.info = f"POP3S [{','.join(flags)}]"
                    elif self.dst_port == 465 or self.dst_port == 587:
                        self.info = f"SMTPS [{','.join(flags)}]"
                    else:
                        self.info = f"TCP:{self.dst_port} [{','.join(flags)}]"
                
                # UDP
                elif pkt.haslayer(UDP):
                    self.src_port = pkt[UDP].sport
                    self.dst_port = pkt[UDP].dport
                    self.protocol = "UDP"
                    self.udp_len = pkt[UDP].len
                    
                    if self.dst_port == 53:
                        self.info = "DNS Query/Response"
                    elif self.dst_port == 67 or self.dst_port == 68:
                        self.info = "DHCP Discovery/Offer/Request/ACK"
                    elif self.dst_port == 123:
                        self.info = "NTP Time Sync"
                    elif self.dst_port == 161:
                        self.info = "SNMP"
                    elif self.dst_port == 69:
                        self.info = "TFTP"
                    elif self.dst_port == 137 or self.dst_port == 138:
                        self.info = "NetBIOS"
                    elif self.dst_port == 500:
                        self.info = "IKE/IPSec"
                    elif self.dst_port >= 1024:
                        self.info = f"UDP:{self.dst_port} (High Port)"
                    else:
                        self.info = f"UDP:{self.dst_port}"
                
                # ICMP
                elif pkt.haslayer(ICMP):
                    self.protocol = "ICMP"
                    icmp_type = pkt[ICMP].type
                    icmp_code = pkt[ICMP].code
                    
                    # Análise detalhada de tipos ICMP
                    if icmp_type == 0:
                        self.info = "ICMP Echo Reply (Ping Reply)"
                    elif icmp_type == 3:
                        dest_unreach_codes = {
                            0: "Network Unreachable",
                            1: "Host Unreachable", 
                            2: "Protocol Unreachable",
                            3: "Port Unreachable",
                            4: "Fragmentation Required",
                            13: "Communication Prohibited"
                        }
                        self.info = f"ICMP Dest Unreachable: {dest_unreach_codes.get(icmp_code, f'Code {icmp_code}')}"
                    elif icmp_type == 8:
                        self.info = "ICMP Echo Request (Ping)"
                    elif icmp_type == 11:
                        self.info = "ICMP Time Exceeded (TTL)"
                    else:
                        self.info = f"ICMP Type {icmp_type} Code {icmp_code}"
            
            # ARP
            elif pkt.haslayer(ARP):
                self.protocol = "ARP"
                self.src_ip = pkt[ARP].psrc
                self.dst_ip = pkt[ARP].pdst
                self.src_mac = pkt[ARP].hwsrc
                self.dst_mac = pkt[ARP].hwdst
                
                if pkt[ARP].op == 1:
                    self.info = f"ARP Request: Who has {pkt[ARP].pdst}?"
                elif pkt[ARP].op == 2:
                    self.info = f"ARP Reply: {pkt[ARP].psrc} is at {pkt[ARP].hwsrc}"
                else:
                    self.info = f"ARP Operation {pkt[ARP].op}"
            
            # DNS analysis
            if pkt.haslayer(DNS):
                dns_query = ""
                if pkt[DNS].qd:
                    dns_query = pkt[DNS].qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                
                if pkt[DNS].qr == 0:  # Query
                    qtype_map = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA"}
                    qtype = qtype_map.get(pkt[DNS].qd.qtype if pkt[DNS].qd else 1, "Unknown")
                    self.info = f"DNS Query: {dns_query} ({qtype})"
                else:  # Response
                    rcode_map = {0: "No Error", 1: "Format Error", 2: "Server Failure", 3: "Name Error", 5: "Refused"}
                    rcode = rcode_map.get(pkt[DNS].rcode, f"Code {pkt[DNS].rcode}")
                    answer_count = pkt[DNS].ancount
                    self.info = f"DNS Response: {dns_query} [{rcode}] ({answer_count} answers)"
                
        except Exception as e:
            logger.error(f"Erro ao analisar pacote: {e}")
            self.info = "Pacote inválido"
    
    def is_relevant(self) -> bool:
        """Determina se o pacote contém informações relevantes"""
        # Sempre mostrar se não é tráfego local
        if self.src_ip and self.dst_ip:
            # Não é loopback
            if not (self.src_ip.startswith("127.") or self.dst_ip.startswith("127.")):
                return True
        
        # Protocolos sempre interessantes
        if self.protocol in ["ICMP", "ARP"]:
            return True
        
        # DNS queries/responses
        if "DNS" in self.info:
            return True
        
        # HTTP/HTTPS
        if any(service in self.info for service in ["HTTP", "HTTPS", "TLS"]):
            return True
        
        # Serviços conhecidos
        if any(service in self.info for service in ["SSH", "FTP", "SMTP", "DHCP", "NTP"]):
            return True
        
        # Flags TCP interessantes (não apenas ACK)
        if self.protocol == "TCP":
            if hasattr(self, 'tcp_flags'):
                # SYN, FIN, RST são sempre interessantes
                if self.tcp_flags & 0x07:  # SYN, FIN, RST bits
                    return True
                # PSH com dados
                if self.tcp_flags & 0x08:  # PSH bit
                    return True
            
            # Conexões em portas não-efêmeras (< 1024)
            if hasattr(self, 'dst_port') and self.dst_port and self.dst_port < 1024:
                return True
        
        # UDP em portas conhecidas
        if self.protocol == "UDP":
            if hasattr(self, 'dst_port') and self.dst_port:
                known_udp_ports = [53, 67, 68, 123, 161, 69, 137, 138, 500]
                if self.dst_port in known_udp_ports:
                    return True
        
        # Pacotes com erro ou informações especiais
        if any(keyword in self.info.lower() for keyword in 
               ["error", "unreachable", "refused", "timeout", "request", "response"]):
            return True
        
        # Por padrão, puro tráfego ACK em portas altas = não relevante
        return False

class NetworkStats:
    """Classe para estatísticas de rede"""
    
    def __init__(self):
        self.reset()
    
    def reset(self):
        self.total_packets = 0
        self.total_bytes = 0
        self.protocol_counts = defaultdict(int)
        self.ip_counts = defaultdict(int)
        self.port_counts = defaultdict(int)
        self.start_time = datetime.now()
    
    def update(self, packet: NetworkPacket):
        self.total_packets += 1
        self.total_bytes += packet.size
        self.protocol_counts[packet.protocol] += 1
        if packet.src_ip:
            self.ip_counts[packet.src_ip] += 1
        if packet.dst_ip:
            self.ip_counts[packet.dst_ip] += 1
        if packet.dst_port:
            self.port_counts[packet.dst_port] += 1

class NetworkMonitorTUI:
    """Interface TUI para monitoramento de rede similar ao Wireshark"""
    
    def __init__(self):
        self.packets: List[NetworkPacket] = []
        self.stats = NetworkStats()
        self.is_capturing = False
        self.capture_thread = None
        self.interface = None
        self.packet_filter = ""
        self.max_packets = 10000
        self.selected_packet = 0
        self.scroll_offset = 0
        self.current_view = "packets"  # packets, stats, details
        self.stdscr = None
        self.search_term = ""
        self.search_mode = False
        self.filter_active = ""
        self.interfaces_list = []
        self.selected_interface = 0
        self.hex_view = False
        self.follow_stream = False
        self.show_relevant_only = True  # Por padrão, mostra apenas pacotes relevantes
        self.tcp_streams = {}  # Dicionário para armazenar streams TCP
        self.current_stream = None  # Stream atualmente sendo seguido
        self.stream_view = False  # Se está visualizando um stream específico
        self.http_analyzer = HTTPAnalyzer()  # Analisador HTTP/HTTPS
        self.http_transactions = []  # Lista de transações HTTP analisadas
        
    def get_available_interfaces(self) -> List[str]:
        """Retorna lista de interfaces disponíveis"""
        if SCAPY_AVAILABLE:
            try:
                return get_if_list()
            except:
                pass
        return ["eth0", "wlan0", "lo"]
    
    def start_capture(self, interface: str, packet_filter: str = ""):
        """Inicia captura de pacotes"""
        if not SCAPY_AVAILABLE:
            raise Exception("Scapy não está disponível")
        
        self.interface = interface
        self.packet_filter = packet_filter
        self.is_capturing = True
        self.stats.reset()
        
        # Configura Scapy para não mostrar warnings
        conf.verb = 0
        
        self.capture_thread = threading.Thread(
            target=self._capture_packets,
            daemon=True
        )
        self.capture_thread.start()
        logger.info(f"Captura iniciada na interface {interface}")
    
    def _capture_packets(self):
        """Thread para captura de pacotes"""
        try:
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                filter=self.packet_filter if self.packet_filter else None,
                stop_filter=lambda _: not self.is_capturing,
                store=False
            )
        except Exception as e:
            logger.error(f"Erro na captura: {e}")
            self.is_capturing = False
    
    def _process_packet(self, pkt):
        """Processa pacote capturado"""
        if not self.is_capturing:
            return
        
        packet = NetworkPacket(pkt)
        
        # Limita número de pacotes armazenados
        if len(self.packets) >= self.max_packets:
            self.packets.pop(0)
        
        self.packets.append(packet)
        self.stats.update(packet)
        
        # Processa TCP streams
        self._process_tcp_stream(packet)
        
        # Processa análise HTTP
        self._process_http_packet(packet)
    
    def stop_capture(self):
        """Para captura de pacotes"""
        self.is_capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
        logger.info("Captura parada")
    
    def _process_tcp_stream(self, packet):
        """Processa pacote para TCP streams"""
        try:
            # Verifica se é um pacote TCP com dados
            if packet.protocol != "TCP" or not hasattr(packet, 'src_port') or not hasattr(packet, 'dst_port'):
                return
            
            # Cria identificadores para ambas as direções do stream
            stream_id1 = f"{packet.src_ip}:{packet.src_port}-{packet.dst_ip}:{packet.dst_port}"
            stream_id2 = f"{packet.dst_ip}:{packet.dst_port}-{packet.src_ip}:{packet.src_port}"
            
            # Procura stream existente em qualquer direção
            tcp_stream = None
            if stream_id1 in self.tcp_streams:
                tcp_stream = self.tcp_streams[stream_id1]
            elif stream_id2 in self.tcp_streams:
                tcp_stream = self.tcp_streams[stream_id2]
            
            # Se não existe, cria novo stream
            if not tcp_stream:
                tcp_stream = TCPStream(packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port)
                self.tcp_streams[stream_id1] = tcp_stream
                self.tcp_streams[stream_id2] = tcp_stream  # Ambas as direções apontam para o mesmo stream
            
            # Adiciona pacote ao stream
            tcp_stream.add_packet(packet)
            
        except Exception as e:
            logger.debug(f"Erro ao processar TCP stream: {e}")
    
    def get_tcp_streams(self):
        """Retorna lista única de TCP streams"""
        seen_streams = set()
        unique_streams = []
        
        for stream in self.tcp_streams.values():
            stream_id = stream.get_stream_id()
            if stream_id not in seen_streams:
                seen_streams.add(stream_id)
                unique_streams.append(stream)
        
        return sorted(unique_streams, key=lambda x: x.start_time, reverse=True)
    
    def _process_http_packet(self, packet):
        """Processa pacote para análise HTTP"""
        try:
            # Verifica se é tráfego HTTP (porta 80, 8080) ou HTTPS (porta 443)
            if packet.protocol == "TCP" and hasattr(packet, 'dst_port'):
                if packet.dst_port in [80, 8080, 443] or packet.src_port in [80, 8080, 443]:
                    http_data = self.http_analyzer.analyze_http_packet(packet)
                    if http_data:
                        self.http_transactions.append(http_data)
                        
                        # Limita número de transações HTTP armazenadas
                        if len(self.http_transactions) > 1000:
                            self.http_transactions.pop(0)
        except Exception as e:
            logger.debug(f"Erro ao processar HTTP: {e}")
    
    def get_http_transactions(self):
        """Retorna transações HTTP ordenadas por timestamp"""
        return sorted(self.http_transactions, key=lambda x: x['timestamp'], reverse=True)
    
    def get_security_alerts(self):
        """Retorna alertas de segurança baseados em análise HTTP"""
        alerts = []
        for transaction in self.http_transactions:
            if transaction.get('security_issues'):
                alerts.append({
                    'timestamp': transaction['timestamp'],
                    'type': transaction['type'],
                    'src_ip': transaction['src_ip'],
                    'dst_ip': transaction['dst_ip'],
                    'issues': transaction['security_issues'],
                    'details': transaction
                })
        return sorted(alerts, key=lambda x: x['timestamp'], reverse=True)
    
    def export_packets(self, filename: str, format: str = "json"):
        """Exporta pacotes capturados"""
        try:
            if format == "json":
                data = []
                for packet in self.packets:
                    data.append({
                        "timestamp": packet.timestamp.isoformat(),
                        "src_ip": packet.src_ip,
                        "dst_ip": packet.dst_ip,
                        "src_port": packet.src_port,
                        "dst_port": packet.dst_port,
                        "protocol": packet.protocol,
                        "size": packet.size,
                        "info": packet.info
                    })
                
                with open(filename, 'w') as f:
                    json.dump(data, f, indent=2)
                    
            logger.info(f"Pacotes exportados para {filename}")
        except Exception as e:
            logger.error(f"Erro ao exportar: {e}")
    
    def run_tui(self):
        """Executa interface TUI"""
        if not CURSES_AVAILABLE:
            return self._run_simple_interface()
        
        try:
            curses.wrapper(self._main_tui)
        except KeyboardInterrupt:
            self.stop_capture()
    
    def _main_tui(self, stdscr):
        """Main loop da interface TUI"""
        self.stdscr = stdscr
        curses.curs_set(0)  # Hide cursor
        stdscr.nodelay(1)   # Non-blocking getch
        stdscr.timeout(100) # Refresh every 100ms
        
        # Cores
        curses.start_color()
        curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLUE)   # Header
        curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_WHITE)  # Selected
        curses.init_pair(3, curses.COLOR_GREEN, curses.COLOR_BLACK)  # TCP
        curses.init_pair(4, curses.COLOR_YELLOW, curses.COLOR_BLACK) # UDP
        curses.init_pair(5, curses.COLOR_RED, curses.COLOR_BLACK)    # ICMP
        curses.init_pair(6, curses.COLOR_BLACK, curses.COLOR_CYAN)   # Footer - fundo cyan
        curses.init_pair(7, curses.COLOR_WHITE, curses.COLOR_RED)    # Footer - destaque vermelho
        curses.init_pair(8, curses.COLOR_YELLOW, curses.COLOR_BLUE)  # Footer - teclas amarelas
        
        while True:
            try:
                self._draw_interface()
                key = stdscr.getch()
                
                if key == ord('q') or key == 27:  # q or ESC
                    break
                elif key == ord('s'):  # Start/Stop capture
                    self._toggle_capture()
                elif key == ord('c'):  # Clear packets
                    self._clear_packets()
                elif key == ord('e'):  # Export
                    self._export_dialog()
                elif key == ord('i'):  # Interactive filter
                    self._filter_dialog()
                elif key == ord('1'):
                    self.current_view = "packets"
                elif key == ord('2'):
                    self.current_view = "stats"
                elif key == ord('3'):
                    self.current_view = "details"
                elif key == ord('4'):
                    self.current_view = "interfaces"
                elif key == ord('5'):
                    self.current_view = "streams"
                elif key == ord('6'):
                    self.current_view = "http"
                elif key == ord('7'):
                    self.current_view = "security"
                elif key == ord('h'):
                    self._toggle_hex_view()
                elif key == ord('t'):  # TCP streams
                    self.current_view = "streams"
                elif key == ord('f'):  # Follow stream (quando um pacote TCP está selecionado)
                    self._follow_tcp_stream()
                elif key == ord('r'):
                    self._toggle_relevant_filter()
                elif key == ord('/'):
                    self._start_search()
                elif key == ord('n'):
                    self._next_search()
                elif key == ord('N'):
                    self._prev_search()
                elif key == curses.KEY_UP:
                    self._scroll_up()
                elif key == curses.KEY_DOWN:
                    self._scroll_down()
                elif key == curses.KEY_LEFT:
                    self._scroll_left()
                elif key == curses.KEY_RIGHT:
                    self._scroll_right()
                elif key == curses.KEY_PPAGE:  # Page Up
                    self._page_up()
                elif key == curses.KEY_NPAGE:  # Page Down
                    self._page_down()
                elif key == curses.KEY_HOME:
                    self._go_to_top()
                elif key == curses.KEY_END:
                    self._go_to_bottom()
                elif key == curses.KEY_ENTER or key == 10:
                    if self.search_mode:
                        self._end_search()
                    elif self.current_view == "interfaces":
                        self._select_interface()
                    elif self.current_view == "streams":
                        self._select_stream()
                    else:
                        self._select_packet()
                elif key == 27:  # ESC
                    if self.search_mode:
                        self._cancel_search()
                    else:
                        break
                elif self.search_mode and key >= 32 and key <= 126:
                    self._add_search_char(chr(key))
                elif self.search_mode and key == curses.KEY_BACKSPACE or key == 8:
                    self._backspace_search()
                    
            except KeyboardInterrupt:
                break
        
        self.stop_capture()
    
    def _draw_interface(self):
        """Desenha interface principal"""
        self.stdscr.clear()
        
        # Header
        self._draw_header()
        
        # Status line
        self._draw_status_line()
        
        # Main content based on current view
        if self.current_view == "packets":
            self._draw_packets_view()
        elif self.current_view == "stats":
            self._draw_stats_view()
        elif self.current_view == "details":
            self._draw_details_view()
        elif self.current_view == "interfaces":
            self._draw_interfaces_view()
        elif self.current_view == "streams":
            self._draw_streams_view()
        elif self.current_view == "stream_details":
            self._draw_stream_details_view()
        elif self.current_view == "http":
            self._draw_http_view()
        elif self.current_view == "security":
            self._draw_security_view()
        elif self.current_view == "hex":
            self._draw_hex_view()
        
        # Footer with commands
        self._draw_footer()
        
        self.stdscr.refresh()
    
    def _draw_header(self):
        """Desenha cabeçalho"""
        header = "Spectra Network Monitor - Wireshark-like Interface"
        self.stdscr.addstr(0, 0, header.center(curses.COLS), curses.color_pair(1))
    
    def _draw_status_line(self):
        """Desenha linha de status"""
        # Calcula pacotes relevantes
        relevant_count = len([p for p in self.packets if p.is_relevant()]) if self.show_relevant_only else len(self.packets)
        
        status = f"Interface: {self.interface or 'None'} | "
        status += f"Capturing: {'Yes' if self.is_capturing else 'No'} | "
        
        if self.show_relevant_only:
            status += f"Packets: {relevant_count}/{len(self.packets)} (Relevant) | "
        else:
            status += f"Packets: {len(self.packets)} (All) | "
            
        status += f"Filter: {self.packet_filter or 'None'}"
        
        self.stdscr.addstr(2, 0, status[:curses.COLS-1])
    
    def _draw_packets_view(self):
        """Desenha visualização de pacotes"""
        start_y = 4
        height = curses.LINES - 7  # Ajustado para footer de 2 linhas
        
        # Filtra pacotes por relevância se ativado
        if self.show_relevant_only:
            filtered_packets = [p for p in self.packets if p.is_relevant()]
        else:
            filtered_packets = self.packets
        
        # Pacotes mais novos primeiro (ordem reversa)
        reversed_packets = list(reversed(filtered_packets))
        
        # Headers com indicador de filtro - largura fixa para alinhamento
        filter_indicator = "[RELEVANT]" if self.show_relevant_only else "[ALL]     "
        headers = f"{'#':<6} {'Time':<12} {'Source':<15} {':Port':<6} {'Destination':<15} {':Port':<6} {'Proto':<6} {'Flags':<8} {'Size':<6} {'Info':<20} {filter_indicator}"
        self.stdscr.addstr(start_y, 0, headers[:curses.COLS-1], curses.color_pair(1))
        
        # Calcula índices para ordem reversa
        visible_packets = reversed_packets[self.scroll_offset:self.scroll_offset + height - 1]
        
        # Packets
        for display_i, packet in enumerate(visible_packets):
            y = start_y + 1 + display_i
            if y >= curses.LINES - 3:
                break
            
            # Número do pacote (baseado na lista filtrada)
            packet_num = len(filtered_packets) - self.scroll_offset - display_i
            
            time_str = packet.timestamp.strftime("%H:%M:%S.%f")[:-3]
            
            # Portas (com fallback para protocolos sem porta)
            src_port = str(packet.src_port) if hasattr(packet, 'src_port') and packet.src_port else "-"
            dst_port = str(packet.dst_port) if hasattr(packet, 'dst_port') and packet.dst_port else "-"
            
            # Flags TCP (se disponível)
            flags = ""
            if hasattr(packet, 'tcp_flags') and packet.protocol == "TCP":
                flag_list = []
                if hasattr(packet, 'tcp_flags'):
                    tcp_flags = packet.tcp_flags
                    if tcp_flags & 0x01: flag_list.append("F")  # FIN
                    if tcp_flags & 0x02: flag_list.append("S")  # SYN  
                    if tcp_flags & 0x04: flag_list.append("R")  # RST
                    if tcp_flags & 0x08: flag_list.append("P")  # PSH
                    if tcp_flags & 0x10: flag_list.append("A")  # ACK
                    if tcp_flags & 0x20: flag_list.append("U")  # URG
                flags = ",".join(flag_list) if flag_list else "-"
            elif packet.protocol == "ICMP":
                flags = "ICMP"
            elif packet.protocol == "ARP":
                flags = "ARP"
            else:
                flags = "-"
            
            # Tamanho do pacote
            size = str(packet.size) if packet.size else "-"
            
            # Monta linha com mais informações
            line = f"{packet_num:<6} {time_str:<12} {packet.src_ip:<15} {src_port:<6} {packet.dst_ip:<15} {dst_port:<6} {packet.protocol:<6} {flags:<8} {size:<6} {packet.info:<25}"
            
            # Color based on protocol
            color = curses.color_pair(0)
            if packet.protocol == "TCP":
                color = curses.color_pair(3)
            elif packet.protocol == "UDP":
                color = curses.color_pair(4)
            elif packet.protocol == "ICMP":
                color = curses.color_pair(5)
            
            # Highlight selected (ajusta para ordem reversa na lista filtrada)
            actual_packet_index = len(filtered_packets) - 1 - (self.scroll_offset + display_i)
            if actual_packet_index == self.selected_packet:
                color = curses.color_pair(2)
            
            try:
                self.stdscr.addstr(y, 0, line[:curses.COLS-1], color)
            except:
                pass
    
    def _draw_stats_view(self):
        """Desenha visualização de estatísticas"""
        start_y = 4
        
        # Estatísticas gerais
        duration = (datetime.now() - self.stats.start_time).total_seconds()
        pps = self.stats.total_packets / duration if duration > 0 else 0
        bps = self.stats.total_bytes / duration if duration > 0 else 0
        
        lines = [
            f"Total Packets: {self.stats.total_packets}",
            f"Total Bytes: {self.stats.total_bytes:,}",
            f"Duration: {duration:.1f}s",
            f"Packets/sec: {pps:.1f}",
            f"Bytes/sec: {bps:,.0f}",
            "",
            "Top Protocols:",
        ]
        
        # Top protocolos
        for proto, count in sorted(self.stats.protocol_counts.items(), 
                                 key=lambda x: x[1], reverse=True)[:5]:
            percentage = (count / self.stats.total_packets * 100) if self.stats.total_packets > 0 else 0
            lines.append(f"  {proto}: {count} ({percentage:.1f}%)")
        
        lines.extend(["", "Top IPs:"])
        
        # Top IPs
        for ip, count in sorted(self.stats.ip_counts.items(), 
                               key=lambda x: x[1], reverse=True)[:5]:
            percentage = (count / (self.stats.total_packets * 2) * 100) if self.stats.total_packets > 0 else 0
            lines.append(f"  {ip}: {count} ({percentage:.1f}%)")
        
        for i, line in enumerate(lines):
            if start_y + i >= curses.LINES - 3:
                break
            try:
                self.stdscr.addstr(start_y + i, 0, line[:curses.COLS-1])
            except:
                pass
    
    def _draw_details_view(self):
        """Desenha visualização de detalhes do pacote selecionado"""
        start_y = 4
        
        if not self.packets or self.selected_packet >= len(self.packets):
            self.stdscr.addstr(start_y, 0, "Nenhum pacote selecionado")
            return
        
        packet = self.packets[self.selected_packet]
        
        lines = [
            f"Packet Details - #{self.selected_packet + 1}",
            f"Timestamp: {packet.timestamp}",
            f"Size: {packet.size} bytes",
            f"Source IP: {packet.src_ip}",
            f"Destination IP: {packet.dst_ip}",
            f"Source Port: {packet.src_port}",
            f"Destination Port: {packet.dst_port}",
            f"Protocol: {packet.protocol}",
            f"Info: {packet.info}",
        ]
        
        if hasattr(packet, 'src_mac'):
            lines.extend([
                f"Source MAC: {packet.src_mac}",
                f"Destination MAC: {packet.dst_mac}",
            ])
        
        for i, line in enumerate(lines):
            if start_y + i >= curses.LINES - 3:
                break
            try:
                self.stdscr.addstr(start_y + i, 0, line[:curses.COLS-1])
            except:
                pass
    
    def _draw_footer(self):
        """Desenha rodapé com comandos em destaque"""
        try:
            # Limpa as duas últimas linhas
            self.stdscr.addstr(curses.LINES - 2, 0, " " * (curses.COLS - 1), curses.color_pair(6))
            self.stdscr.addstr(curses.LINES - 1, 0, " " * (curses.COLS - 1), curses.color_pair(6))
            
            if self.search_mode:
                # Modo de busca - linha única
                footer = f" Search: {self.search_term}_ (Enter to search, Esc to cancel) "
                self.stdscr.addstr(curses.LINES - 1, 0, footer[:curses.COLS-1], curses.color_pair(7))
            else:
                # Comandos principais - duas linhas para melhor visibilidade
                line1 = " NETWORK MONITOR: "
                
                # Comandos principais com destaque nas teclas
                commands1 = "[S]tart/Stop  [C]lear  [E]xport  [I]filter  [R]elevant  [F]ollow  [T]CP"
                commands2 = "[1]Packets [2]Stats [3]Details [4]Interfaces [5]Streams [6]HTTP [7]Security [Q]uit"
                
                # Linha 1 - título e comandos principais
                self.stdscr.addstr(curses.LINES - 2, 0, line1, curses.color_pair(7))
                self.stdscr.addstr(curses.LINES - 2, len(line1), commands1[:curses.COLS-len(line1)-1], curses.color_pair(8))
                
                # Linha 2 - comandos de visualização
                prefix = " VIEW MODES:  "
                self.stdscr.addstr(curses.LINES - 1, 0, prefix, curses.color_pair(7))
                self.stdscr.addstr(curses.LINES - 1, len(prefix), commands2[:curses.COLS-len(prefix)-1], curses.color_pair(8))
        except:
            pass
    
    def _toggle_capture(self):
        """Alterna estado da captura"""
        if self.is_capturing:
            self.stop_capture()
        else:
            interfaces = self.get_available_interfaces()
            if interfaces:
                try:
                    # Tenta primeira interface
                    self.start_capture(interfaces[0])
                except Exception as e:
                    logger.error(f"Erro ao iniciar captura: {e}")
                    # Tenta interface loopback como fallback
                    for iface in interfaces:
                        if 'lo' in iface.lower() or 'loopback' in iface.lower():
                            try:
                                self.start_capture(iface)
                                break
                            except:
                                continue
    
    def _clear_packets(self):
        """Limpa pacotes capturados"""
        self.packets.clear()
        self.stats.reset()
        self.selected_packet = 0
        self.scroll_offset = 0
    
    def _scroll_up(self):
        """Scroll para cima (navega para pacotes mais novos)"""
        if self.current_view == "packets":
            # Com ordem reversa, scroll up vai para pacotes mais novos (índices maiores)
            current_list = [p for p in self.packets if p.is_relevant()] if self.show_relevant_only else self.packets
            if self.selected_packet < len(current_list) - 1:
                self.selected_packet += 1
                # Ajusta scroll se necessário
                if len(current_list) - 1 - self.selected_packet < self.scroll_offset:
                    self.scroll_offset = max(0, len(current_list) - 1 - self.selected_packet)
        elif self.current_view == "interfaces":
            if self.selected_interface > 0:
                self.selected_interface -= 1
        elif self.current_view == "streams":
            if self.selected_packet > 0:
                self.selected_packet -= 1
        elif self.current_view == "stream_details":
            if self.scroll_offset > 0:
                self.scroll_offset -= 1
        elif self.current_view == "http":
            if self.selected_packet > 0:
                self.selected_packet -= 1
        elif self.current_view == "security":
            if self.selected_packet > 0:
                self.selected_packet -= 1
    
    def _scroll_down(self):
        """Scroll para baixo (navega para pacotes mais antigos)"""
        if self.current_view == "packets":
            # Com ordem reversa, scroll down vai para pacotes mais antigos (índices menores)
            if self.selected_packet > 0:
                self.selected_packet -= 1
                # Ajusta scroll se necessário  
                visible_height = curses.LINES - 7  # Ajustado para footer de 2 linhas
                display_index = len(self.packets) - 1 - self.selected_packet
                if display_index >= self.scroll_offset + visible_height:
                    self.scroll_offset = display_index - visible_height + 1
        elif self.current_view == "interfaces":
            interfaces = self.get_available_interfaces()
            if self.selected_interface < len(interfaces) - 1:
                self.selected_interface += 1
        elif self.current_view == "streams":
            streams = self.get_tcp_streams()
            if self.selected_packet < len(streams) - 1:
                self.selected_packet += 1
        elif self.current_view == "stream_details":
            # Verifica se há mais linhas para mostrar
            if self.current_stream:
                conversation = self.current_stream.get_conversation_text()
                max_scroll = max(0, len(conversation) - (curses.LINES - 9))
                if self.scroll_offset < max_scroll:
                    self.scroll_offset += 1
        elif self.current_view == "http":
            transactions = self.get_http_transactions()
            if self.selected_packet < len(transactions) - 1:
                self.selected_packet += 1
        elif self.current_view == "security":
            alerts = self.get_security_alerts()
            if self.selected_packet < len(alerts) - 1:
                self.selected_packet += 1
    
    def _select_packet(self):
        """Seleciona pacote atual"""
        if self.current_view == "packets":
            self.current_view = "details"
    
    def _export_dialog(self):
        """Dialog para exportar pacotes"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"network_capture_{timestamp}.json"
        self.export_packets(filename)
    
    def _draw_interfaces_view(self):
        """Desenha visualização de interfaces disponíveis"""
        start_y = 4
        
        interfaces = self.get_available_interfaces()
        
        # Garante que a seleção está dentro dos limites
        if self.selected_interface >= len(interfaces):
            self.selected_interface = len(interfaces) - 1
        if self.selected_interface < 0:
            self.selected_interface = 0
        
        # Cabeçalho
        header = "Interfaces de Rede Disponíveis"
        try:
            self.stdscr.addstr(start_y, 0, header, curses.color_pair(1))
        except:
            pass
        
        # Lista interfaces
        for i, interface in enumerate(interfaces):
            y = start_y + 2 + i
            if y >= curses.LINES - 3:
                break
            
            # Verifica se é a interface atual
            status = "[ATIVA]" if interface == self.interface else "[INATIVA]"
            
            # Indicador de seleção
            selector = "→ " if i == self.selected_interface else "  "
            line = f"{selector}{interface:<15} {status}"
            
            # Highlight da interface selecionada
            color = curses.color_pair(2) if i == self.selected_interface else curses.color_pair(0)
            
            try:
                self.stdscr.addstr(y, 0, line[:curses.COLS-1], color)
            except:
                pass
        
        # Instruções
        instructions = [
            "",
            "Navegação:",
            "  ↑/↓ - Navegar entre interfaces",
            "  Enter - Selecionar interface",
            "  Esc - Voltar"
        ]
        
        for i, instruction in enumerate(instructions):
            y = start_y + 5 + len(interfaces) + i
            if y >= curses.LINES - 3:
                break
            try:
                self.stdscr.addstr(y, 0, instruction[:curses.COLS-1])
            except:
                pass
    
    def _draw_hex_view(self):
        """Desenha visualização hexadecimal do pacote selecionado"""
        start_y = 4
        
        if not self.packets or self.selected_packet >= len(self.packets):
            self.stdscr.addstr(start_y, 0, "Nenhum pacote selecionado para visualização hex")
            return
        
        packet = self.packets[self.selected_packet]
        
        # Cabeçalho
        header = f"Hex View - Packet #{self.selected_packet + 1} ({packet.size} bytes)"
        try:
            self.stdscr.addstr(start_y, 0, header, curses.color_pair(1))
        except:
            pass
        
        # Dados hexadecimais (simulados - em implementação real usaria packet.raw_packet)
        hex_data = f"Sample hex data for packet {self.selected_packet + 1}"
        hex_lines = []
        
        # Formata em linhas de 16 bytes
        for i in range(0, len(hex_data), 16):
            chunk = hex_data[i:i+16]
            hex_part = ' '.join(f"{ord(c):02x}" for c in chunk)
            ascii_part = ''.join(c if 32 <= ord(c) <= 126 else '.' for c in chunk)
            line = f"{i:08x}: {hex_part:<48} {ascii_part}"
            hex_lines.append(line)
        
        # Mostra as linhas hex
        for i, line in enumerate(hex_lines[:curses.LINES - 9]):  # Ajustado para footer de 2 linhas
            y = start_y + 2 + i
            try:
                self.stdscr.addstr(y, 0, line[:curses.COLS-1])
            except:
                pass
    
    def _toggle_hex_view(self):
        """Alterna para visualização hexadecimal"""
        if self.current_view == "hex":
            self.current_view = "packets"
        else:
            self.current_view = "hex"
    
    def _toggle_relevant_filter(self):
        """Alterna filtro de pacotes relevantes"""
        self.show_relevant_only = not self.show_relevant_only
        # Reset da seleção ao mudar filtro
        self.selected_packet = 0
        self.scroll_offset = 0
    
    def _draw_streams_view(self):
        """Desenha visualização de TCP streams"""
        start_y = 4
        height = curses.LINES - 7  # Ajustado para footer de 2 linhas
        
        streams = self.get_tcp_streams()
        
        # Headers
        headers = f"{'#':<4} {'Start Time':<12} {'Duration':<10} {'Packets':<8} {'Protocol':<8} {'Stream':<40}"
        self.stdscr.addstr(start_y, 0, headers[:curses.COLS-1], curses.color_pair(1))
        
        # Streams
        for i, stream in enumerate(streams[self.scroll_offset:self.scroll_offset + height - 1]):
            y = start_y + 1 + i
            if y >= curses.LINES - 3:
                break
            
            # Calcula duração
            duration = ""
            if stream.end_time and stream.start_time:
                delta = stream.end_time - stream.start_time
                duration = f"{delta.total_seconds():.1f}s"
            
            start_time = stream.start_time.strftime("%H:%M:%S") if stream.start_time else "N/A"
            protocol = "HTTP" if stream.is_http else "TCP"
            stream_id = stream.get_stream_id()
            
            line = f"{i+1:<4} {start_time:<12} {duration:<10} {len(stream.packets):<8} {protocol:<8} {stream_id:<40}"
            
            # Destacar se selecionado
            attr = curses.color_pair(2) if i == self.selected_packet else curses.color_pair(0)
            
            try:
                self.stdscr.addstr(y, 0, line[:curses.COLS-1], attr)
            except:
                pass
    
    def _draw_stream_details_view(self):
        """Desenha visualização detalhada de um TCP stream"""
        start_y = 4
        
        if not self.current_stream:
            self.stdscr.addstr(start_y, 0, "Nenhum stream selecionado")
            return
        
        # Cabeçalho
        header = f"TCP Stream Details: {self.current_stream.get_stream_id()}"
        try:
            self.stdscr.addstr(start_y, 0, header, curses.color_pair(1))
        except:
            pass
        
        # Conversação
        conversation = self.current_stream.get_conversation_text()
        visible_lines = conversation[self.scroll_offset:self.scroll_offset + curses.LINES - 9]
        
        for i, line in enumerate(visible_lines):
            y = start_y + 2 + i
            if y >= curses.LINES - 3:
                break
            
            # Color coding para diferentes tipos de dados
            attr = curses.color_pair(0)
            if line.startswith(">>>"):  # HTTP Request
                attr = curses.color_pair(3)  # Verde
            elif line.startswith("<<<"):  # HTTP Response
                attr = curses.color_pair(4)  # Amarelo
            elif line.startswith("==="):  # Headers
                attr = curses.color_pair(1)  # Azul
            
            try:
                self.stdscr.addstr(y, 0, line[:curses.COLS-1], attr)
            except:
                pass
    
    def _follow_tcp_stream(self):
        """Segue TCP stream do pacote selecionado"""
        if self.current_view != "packets" or not self.packets:
            return
        
        # Filtra pacotes por relevância se ativado
        if self.show_relevant_only:
            filtered_packets = [p for p in self.packets if p.is_relevant()]
        else:
            filtered_packets = self.packets
        
        if self.selected_packet >= len(filtered_packets):
            return
        
        # Pacotes em ordem reversa (mais novos primeiro)
        reversed_packets = list(reversed(filtered_packets))
        packet = reversed_packets[self.selected_packet]
        
        # Verifica se é TCP
        if packet.protocol != "TCP" or not hasattr(packet, 'src_port'):
            return
        
        # Procura stream correspondente
        stream_id1 = f"{packet.src_ip}:{packet.src_port}-{packet.dst_ip}:{packet.dst_port}"
        stream_id2 = f"{packet.dst_ip}:{packet.dst_port}-{packet.src_ip}:{packet.src_port}"
        
        stream = None
        if stream_id1 in self.tcp_streams:
            stream = self.tcp_streams[stream_id1]
        elif stream_id2 in self.tcp_streams:
            stream = self.tcp_streams[stream_id2]
        
        if stream:
            self.current_stream = stream
            self.current_view = "stream_details"
            self.scroll_offset = 0
    
    def _draw_http_view(self):
        """Desenha visualização de transações HTTP"""
        start_y = 4
        height = curses.LINES - 7
        
        transactions = self.get_http_transactions()
        
        # Headers
        headers = f"{'#':<4} {'Time':<12} {'Type':<8} {'Method':<8} {'URL/Status':<30} {'Host/Server':<20} {'Security':<10}"
        self.stdscr.addstr(start_y, 0, headers[:curses.COLS-1], curses.color_pair(1))
        
        # Transações
        for i, transaction in enumerate(transactions[self.scroll_offset:self.scroll_offset + height - 1]):
            y = start_y + 1 + i
            if y >= curses.LINES - 3:
                break
            
            time_str = transaction['timestamp'].strftime("%H:%M:%S")
            trans_type = transaction['type'][:8]
            
            if transaction['type'] == 'request':
                method = transaction['method'][:8]
                url = transaction['url'][:30]
                host = transaction['host'][:20]
            else:
                method = transaction['status_code'][:8]
                url = transaction['reason'][:30]
                host = transaction['server'][:20]
            
            security = "🚨" if transaction.get('security_issues') else "✓"
            
            line = f"{i+1:<4} {time_str:<12} {trans_type:<8} {method:<8} {url:<30} {host:<20} {security:<10}"
            
            # Color based on security issues
            attr = curses.color_pair(5) if transaction.get('security_issues') else curses.color_pair(3)
            if i == self.selected_packet:
                attr = curses.color_pair(2)
            
            try:
                self.stdscr.addstr(y, 0, line[:curses.COLS-1], attr)
            except:
                pass
    
    def _draw_security_view(self):
        """Desenha visualização de alertas de segurança"""
        start_y = 4
        height = curses.LINES - 7
        
        alerts = self.get_security_alerts()
        
        # Headers
        headers = f"{'#':<4} {'Time':<12} {'Source':<15} {'Destination':<15} {'Alert Type':<20} {'Severity':<10}"
        self.stdscr.addstr(start_y, 0, headers[:curses.COLS-1], curses.color_pair(1))
        
        # Alertas
        for i, alert in enumerate(alerts[self.scroll_offset:self.scroll_offset + height - 1]):
            y = start_y + 1 + i
            if y >= curses.LINES - 3:
                break
            
            time_str = alert['timestamp'].strftime("%H:%M:%S")
            src_ip = alert['src_ip'][:15]
            dst_ip = alert['dst_ip'][:15]
            
            # Combina issues em uma string
            alert_type = ', '.join(alert['issues'])[:20] if alert['issues'] else "Unknown"
            
            # Determina severidade baseada no tipo de issue
            high_severity = ['SQL_INJECTION', 'XSS', 'DIRECTORY_TRAVERSAL', 'SUSPICIOUS_USER_AGENT']
            severity = "HIGH" if any(issue in alert_type for issue in high_severity) else "MEDIUM"
            
            line = f"{i+1:<4} {time_str:<12} {src_ip:<15} {dst_ip:<15} {alert_type:<20} {severity:<10}"
            
            # Color based on severity
            attr = curses.color_pair(5) if severity == "HIGH" else curses.color_pair(4)
            if i == self.selected_packet:
                attr = curses.color_pair(2)
            
            try:
                self.stdscr.addstr(y, 0, line[:curses.COLS-1], attr)
            except:
                pass
    
    def _start_search(self):
        """Inicia modo de busca"""
        self.search_mode = True
        self.search_term = ""
    
    def _end_search(self):
        """Finaliza busca e procura primeira ocorrência"""
        self.search_mode = False
        if self.search_term:
            self._find_next_match()
    
    def _cancel_search(self):
        """Cancela busca"""
        self.search_mode = False
        self.search_term = ""
    
    def _add_search_char(self, char):
        """Adiciona caractere ao termo de busca"""
        self.search_term += char
    
    def _backspace_search(self):
        """Remove último caractere da busca"""
        if self.search_term:
            self.search_term = self.search_term[:-1]
    
    def _next_search(self):
        """Próxima ocorrência da busca"""
        if self.search_term:
            self._find_next_match()
    
    def _prev_search(self):
        """Ocorrência anterior da busca"""
        if self.search_term:
            self._find_prev_match()
    
    def _find_next_match(self):
        """Encontra próxima ocorrência do termo de busca"""
        search_lower = self.search_term.lower()
        start_index = (self.selected_packet + 1) % len(self.packets)
        
        for i in range(len(self.packets)):
            packet_index = (start_index + i) % len(self.packets)
            packet = self.packets[packet_index]
            
            # Busca em vários campos
            search_fields = [
                packet.src_ip, packet.dst_ip, packet.protocol, 
                packet.info, str(packet.src_port), str(packet.dst_port)
            ]
            
            if any(search_lower in str(field).lower() for field in search_fields if field):
                self.selected_packet = packet_index
                self._adjust_scroll_to_selection()
                break
    
    def _find_prev_match(self):
        """Encontra ocorrência anterior do termo de busca"""
        search_lower = self.search_term.lower()
        start_index = (self.selected_packet - 1) % len(self.packets)
        
        for i in range(len(self.packets)):
            packet_index = (start_index - i) % len(self.packets)
            packet = self.packets[packet_index]
            
            # Busca em vários campos
            search_fields = [
                packet.src_ip, packet.dst_ip, packet.protocol, 
                packet.info, str(packet.src_port), str(packet.dst_port)
            ]
            
            if any(search_lower in str(field).lower() for field in search_fields if field):
                self.selected_packet = packet_index
                self._adjust_scroll_to_selection()
                break
    
    def _adjust_scroll_to_selection(self):
        """Ajusta scroll para mostrar pacote selecionado"""
        visible_height = curses.LINES - 7  # Ajustado para footer de 2 linhas
        if self.selected_packet < self.scroll_offset:
            self.scroll_offset = self.selected_packet
        elif self.selected_packet >= self.scroll_offset + visible_height:
            self.scroll_offset = self.selected_packet - visible_height + 1
    
    def _scroll_left(self):
        """Scroll horizontal para esquerda"""
        # Implementação para scroll horizontal se necessário
        pass
    
    def _scroll_right(self):
        """Scroll horizontal para direita"""
        # Implementação para scroll horizontal se necessário  
        pass
    
    def _page_up(self):
        """Página para cima (pacotes mais novos)"""
        visible_height = curses.LINES - 7  # Ajustado para footer de 2 linhas
        if self.current_view == "packets":
            # Com ordem reversa, page up vai para pacotes mais novos
            self.selected_packet = min(len(self.packets) - 1, self.selected_packet + visible_height)
            self.scroll_offset = max(0, self.scroll_offset - visible_height)
        elif self.current_view == "interfaces":
            self.selected_interface = max(0, self.selected_interface - visible_height)
    
    def _page_down(self):
        """Página para baixo (pacotes mais antigos)"""
        visible_height = curses.LINES - 7  # Ajustado para footer de 2 linhas
        if self.current_view == "packets":
            # Com ordem reversa, page down vai para pacotes mais antigos  
            self.selected_packet = max(0, self.selected_packet - visible_height)
            max_scroll = max(0, len(self.packets) - visible_height)
            self.scroll_offset = min(max_scroll, self.scroll_offset + visible_height)
        elif self.current_view == "interfaces":
            interfaces = self.get_available_interfaces()
            self.selected_interface = min(len(interfaces) - 1, self.selected_interface + visible_height)
    
    def _go_to_top(self):
        """Vai para o topo (pacotes mais novos)"""
        if self.current_view == "packets":
            # Com ordem reversa, topo = pacotes mais novos (índice mais alto)
            self.selected_packet = len(self.packets) - 1 if self.packets else 0
            self.scroll_offset = 0
        elif self.current_view == "interfaces":
            self.selected_interface = 0
    
    def _go_to_bottom(self):
        """Vai para o final (pacotes mais antigos)"""
        if self.current_view == "packets" and self.packets:
            # Com ordem reversa, final = pacotes mais antigos (índice 0)
            self.selected_packet = 0
            visible_height = curses.LINES - 7  # Ajustado para footer de 2 linhas
            self.scroll_offset = max(0, len(self.packets) - visible_height)
        elif self.current_view == "interfaces":
            interfaces = self.get_available_interfaces()
            if interfaces:
                self.selected_interface = len(interfaces) - 1
    
    def _select_interface(self):
        """Seleciona interface e volta para visualização de pacotes"""
        interfaces = self.get_available_interfaces()
        if self.selected_interface < len(interfaces):
            selected_if = interfaces[self.selected_interface]
            
            # Para captura atual se estiver rodando
            if self.is_capturing:
                self.stop_capture()
            
            # Inicia captura na nova interface
            try:
                self.start_capture(selected_if, self.packet_filter)
                self.current_view = "packets"
            except Exception:
                # Em caso de erro, volta para packets sem trocar interface
                self.current_view = "packets"
    
    def _select_stream(self):
        """Seleciona stream e mostra detalhes"""
        streams = self.get_tcp_streams()
        if self.selected_packet < len(streams):
            self.current_stream = streams[self.selected_packet]
            self.current_view = "stream_details"
            self.scroll_offset = 0
    
    def _filter_dialog(self):
        """Dialog interativo avançado para definir filtros BPF"""
        # Cria janela grande para filtros avançados
        filter_win_height = 20
        filter_win_width = 80
        start_y = (curses.LINES - filter_win_height) // 2
        start_x = (curses.COLS - filter_win_width) // 2
        
        # Filtros pré-definidos comuns
        preset_filters = [
            ("Limpar filtro", ""),
            ("Apenas HTTP", "port 80 or port 8080"),
            ("Apenas HTTPS", "port 443"),
            ("Apenas DNS", "port 53"),
            ("Apenas SSH", "port 22"),
            ("Apenas FTP", "port 21 or port 20"),
            ("Apenas TCP", "tcp"),
            ("Apenas UDP", "udp"),
            ("Apenas ICMP", "icmp"),
            ("Apenas IPv6", "ip6"),
            ("Host específico", "host "),
            ("Rede específica", "net "),
            ("Portas altas", "portrange 1024-65535"),
            ("Tráfego local", "src net 192.168.0.0/16 or dst net 192.168.0.0/16"),
            ("Não ARP", "not arp"),
            ("HTTP GET", "tcp port 80 and (tcp[tcpflags] & tcp-push != 0)")
        ]
        
        selected_preset = 0
        current_filter = ""
        
        try:
            filter_win = curses.newwin(filter_win_height, filter_win_width, start_y, start_x)
            
            while True:
                filter_win.clear()
                filter_win.box()
                
                # Título
                filter_win.addstr(1, 2, "BPF FILTER CONFIGURATOR", curses.color_pair(1))
                filter_win.addstr(2, 2, f"Filtro atual: {self.packet_filter or '(nenhum)'}")
                filter_win.addstr(3, 2, "-" * (filter_win_width - 4))
                
                # Filtros pré-definidos
                filter_win.addstr(4, 2, "FILTROS PRE-DEFINIDOS (Use ↑↓ para navegar, Enter para aplicar):")
                
                # Lista de presets
                for i, (name, filter_expr) in enumerate(preset_filters[:12]):  # Mostra até 12 presets
                    y = 5 + i
                    if y >= filter_win_height - 4:
                        break
                    
                    attr = curses.color_pair(2) if i == selected_preset else curses.color_pair(0)
                    prefix = "► " if i == selected_preset else "  "
                    
                    display_filter = filter_expr if len(filter_expr) <= 35 else filter_expr[:35] + "..."
                    line = f"{prefix}{name:<20} {display_filter}"
                    
                    try:
                        filter_win.addstr(y, 2, line[:filter_win_width-4], attr)
                    except:
                        pass
                
                # Filtro customizado
                filter_win.addstr(filter_win_height - 4, 2, "FILTRO CUSTOMIZADO:")
                filter_win.addstr(filter_win_height - 3, 2, f"Digite: {current_filter}")
                filter_win.addstr(filter_win_height - 2, 2, "[Enter] Aplicar [C] Custom [ESC] Cancelar")
                
                filter_win.refresh()
                
                # Input
                key = filter_win.getch()
                
                if key == 27:  # ESC
                    break
                elif key == curses.KEY_UP:
                    selected_preset = max(0, selected_preset - 1)
                elif key == curses.KEY_DOWN:
                    selected_preset = min(len(preset_filters) - 1, selected_preset + 1)
                elif key == ord('c') or key == ord('C'):
                    # Modo de entrada customizada
                    current_filter = self._get_custom_filter_input()
                    if current_filter is not None:
                        self._apply_filter(current_filter)
                        break
                elif key == curses.KEY_ENTER or key == 10:
                    # Aplica filtro selecionado
                    if selected_preset < len(preset_filters):
                        name, filter_expr = preset_filters[selected_preset]
                        if name == "Host específico" or name == "Rede específica":
                            # Precisa de input adicional
                            additional_input = self._get_additional_input(name)
                            if additional_input:
                                filter_expr += additional_input
                        self._apply_filter(filter_expr)
                        break
            
            del filter_win
            
        except Exception:
            curses.noecho()
            curses.curs_set(0)
            pass
    
    def _get_custom_filter_input(self):
        """Obtém entrada customizada para filtro BPF"""
        try:
            input_win = curses.newwin(3, 70, curses.LINES//2, curses.COLS//2 - 35)
            input_win.box()
            input_win.addstr(1, 2, "Digite o filtro BPF: ")
            input_win.refresh()
            
            curses.echo()
            curses.curs_set(1)
            
            user_input = input_win.getstr(1, 22, 45).decode('utf-8')
            
            curses.noecho()
            curses.curs_set(0)
            del input_win
            
            return user_input
        except:
            curses.noecho()
            curses.curs_set(0)
            return None
    
    def _get_additional_input(self, filter_type):
        """Obtém entrada adicional para filtros que precisam de parâmetros"""
        try:
            input_win = curses.newwin(3, 70, curses.LINES//2, curses.COLS//2 - 35)
            input_win.box()
            
            if "Host" in filter_type:
                input_win.addstr(1, 2, "Digite o IP/hostname: ")
            elif "Rede" in filter_type:
                input_win.addstr(1, 2, "Digite a rede (ex: 192.168.1.0/24): ")
            
            input_win.refresh()
            
            curses.echo()
            curses.curs_set(1)
            
            user_input = input_win.getstr(1, 25, 40).decode('utf-8')
            
            curses.noecho()
            curses.curs_set(0)
            del input_win
            
            return user_input
        except:
            curses.noecho()
            curses.curs_set(0)
            return None
    
    def _apply_filter(self, new_filter):
        """Aplica novo filtro BPF"""
        if new_filter != self.packet_filter:
            old_capturing = self.is_capturing
            if old_capturing:
                self.stop_capture()
            
            self.packet_filter = new_filter
            
            if old_capturing and self.interface:
                try:
                    self.start_capture(self.interface, self.packet_filter)
                except Exception as e:
                    logger.error(f"Erro ao aplicar filtro: {e}")
                    # Remove filtro inválido e tenta sem filtro
                    self.packet_filter = ""
                    if self.interface:
                        self.start_capture(self.interface, "")
    
    def _run_simple_interface(self):
        """Interface simples sem curses"""
        console.print("\n[bold cyan]Spectra Network Monitor[/bold cyan]")
        console.print("[yellow]Interface simples (curses não disponível)[/yellow]")
        
        interfaces = self.get_available_interfaces()
        console.print(f"\n[bold]Interfaces disponíveis:[/bold] {', '.join(interfaces)}")
        
        if not interfaces:
            console.print("[red]Nenhuma interface encontrada[/red]")
            return
        
        # Usa primeira interface disponível
        interface = interfaces[0]
        console.print(f"[green]Usando interface:[/green] {interface}")
        
        # Verifica privilégios
        try:
            if os.geteuid() != 0:
                console.print("[yellow]⚠️  Aviso: Sem privilégios de root - captura pode ser limitada[/yellow]")
        except AttributeError:
            console.print("[yellow]⚠️  Aviso: Execute como administrador para captura completa[/yellow]")
        
        try:
            console.print("\n[cyan]Iniciando captura...[/cyan]")
            self.start_capture(interface)
            console.print("[green]✓ Captura iniciada com sucesso![/green]")
            console.print("[dim]Pressione Ctrl+C para parar...[/dim]\n")
            
            packet_count = 0
            while self.is_capturing:
                time.sleep(0.5)  # Reduz intervalo para mais responsividade
                
                # Mostra novos pacotes
                if len(self.packets) > packet_count:
                    for i in range(packet_count, len(self.packets)):
                        packet = self.packets[i]
                        timestamp = packet.timestamp.strftime('%H:%M:%S.%f')[:-3]
                        console.print(f"[{timestamp}] {packet.src_ip:<15} → {packet.dst_ip:<15} "
                                    f"[cyan]{packet.protocol}[/cyan] {packet.info}")
                    packet_count = len(self.packets)
                
                # Mostra estatísticas periodicamente
                if packet_count > 0 and packet_count % 50 == 0:
                    console.print(f"\n[dim]--- {packet_count} pacotes capturados ---[/dim]\n")
                
        except KeyboardInterrupt:
            console.print("\n[yellow]Parando captura...[/yellow]")
            self.stop_capture()
            
            if self.packets:
                console.print(f"\n[green]✓ Capturados {len(self.packets)} pacotes[/green]")
                
                # Mostra estatísticas finais
                protocol_counts = {}
                for packet in self.packets:
                    protocol_counts[packet.protocol] = protocol_counts.get(packet.protocol, 0) + 1
                
                console.print("\n[bold]Estatísticas por protocolo:[/bold]")
                for proto, count in sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True):
                    percentage = (count / len(self.packets)) * 100
                    console.print(f"  {proto}: {count} ({percentage:.1f}%)")
                
                # Exporta automaticamente
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"network_capture_{timestamp}.json"
                self.export_packets(filename)
                console.print(f"\n[cyan]Pacotes exportados para {filename}[/cyan]")
            else:
                console.print("\n[yellow]Nenhum pacote foi capturado[/yellow]")
                console.print("[dim]Verifique se você tem privilégios suficientes e se há tráfego na interface[/dim]")
        
        except Exception as e:
            console.print(f"\n[red]Erro durante captura: {e}[/red]")
            console.print("[dim]Tente executar como root/administrador[/dim]")

def network_monitor_interface(interface=None):
    """Interface principal do monitor de rede"""
    if not SCAPY_AVAILABLE:
        console.print("[red]Erro: Scapy não está instalado[/red]")
        console.print("Instale com: [cyan]pip install scapy[/cyan]")
        return
    
    # Mostra informações iniciais
    console.print("\n[bold cyan]🌐 Spectra Network Monitor[/bold cyan]")
    console.print("[yellow]Interface similar ao Wireshark para análise de tráfego de rede[/yellow]\n")
    
    # Verifica privilégios
    try:
        if os.geteuid() != 0:
            console.print("[yellow]⚠️  Aviso: Execute como root/administrador para captura completa[/yellow]")
            console.print("[dim]sudo python main.py --network-monitor[/dim]\n")
    except AttributeError:
        # Sistema Windows
        console.print("[yellow]⚠️  Aviso: Execute como administrador para captura completa[/yellow]\n")
    
    # Mostra controles
    console.print("[bold]Controles da Interface:[/bold]")
    console.print("[green]s[/green] - Iniciar/parar captura")
    console.print("[green]c[/green] - Limpar pacotes") 
    console.print("[green]e[/green] - Exportar para JSON")
    console.print("[green]f[/green] - Configurar filtros BPF")
    console.print("[green]r[/green] - Alternar filtro relevante/todos pacotes")
    console.print("[green]/[/green] - Buscar pacotes (n/N para próximo/anterior)")
    console.print("[green]h[/green] - Visualização hexadecimal")
    console.print("[green]1-4[/green] - Alternar views (pacotes/stats/detalhes/interfaces)")
    console.print("[green]↑↓←→[/green] - Navegação com setas")
    console.print("[green]PgUp/PgDn[/green] - Navegação por páginas")
    console.print("[green]Home/End[/green] - Ir para início/fim")
    console.print("[green]q/ESC[/green] - Sair\n")
    
    try:
        console.print("[dim]Pressione qualquer tecla para continuar...[/dim]")
        input()
    except (EOFError, KeyboardInterrupt):
        console.print("[yellow]Iniciando em modo automático...[/yellow]")
    
    monitor = NetworkMonitorTUI()
    
    # Se interface específica foi fornecida, inicia captura automaticamente
    if interface:
        console.print(f"[green]Forçando interface: {interface}[/green]")
        try:
            monitor.start_capture(interface)
        except Exception as e:
            console.print(f"[red]Erro ao iniciar captura na interface {interface}: {e}[/red]")
    
    monitor.run_tui()

if __name__ == "__main__":
    network_monitor_interface()