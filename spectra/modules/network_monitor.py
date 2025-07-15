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
        sniff, get_if_list, Ether, IP, IPv6, TCP, UDP, ICMP, 
        ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6DestUnreach,
        ARP, DNS, conf
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

class BandwidthAnalyzer:
    """Classe para análise de bandwidth e performance de rede em tempo real"""
    
    def __init__(self):
        self.bandwidth_history = defaultdict(list)  # Por interface
        self.traffic_by_ip = defaultdict(int)  # Tráfego por IP
        self.traffic_by_protocol = defaultdict(int)  # Tráfego por protocolo
        self.packet_count_history = []
        self.latency_samples = []
        self.start_time = time.time()
        self.last_update = time.time()
        self.total_bytes = 0
        self.total_packets = 0
        self.bytes_per_second = 0
        self.packets_per_second = 0
        self.peak_bandwidth = 0
        self.avg_packet_size = 0
        
        # Histórico para gráficos (últimos 60 segundos)
        self.bandwidth_timeline = []
        self.max_history_points = 60
        
    def update(self, packet):
        """Atualiza estatísticas com novo pacote"""
        current_time = time.time()
        packet_size = packet.size if packet.size else 0
        
        # Atualiza contadores totais
        self.total_bytes += packet_size
        self.total_packets += 1
        
        # Calcula estatísticas por segundo
        time_diff = current_time - self.last_update
        if time_diff >= 1.0:  # Atualiza a cada segundo
            self.bytes_per_second = packet_size / time_diff if time_diff > 0 else 0
            self.packets_per_second = 1 / time_diff if time_diff > 0 else 0
            
            # Adiciona ao histórico
            self.bandwidth_timeline.append({
                'timestamp': current_time,
                'bps': self.bytes_per_second,
                'pps': self.packets_per_second
            })
            
            # Mantém apenas últimos 60 pontos
            if len(self.bandwidth_timeline) > self.max_history_points:
                self.bandwidth_timeline.pop(0)
            
            # Atualiza pico
            if self.bytes_per_second > self.peak_bandwidth:
                self.peak_bandwidth = self.bytes_per_second
            
            self.last_update = current_time
        
        # Estatísticas por IP
        if hasattr(packet, 'src_ip') and packet.src_ip:
            self.traffic_by_ip[packet.src_ip] += packet_size
        if hasattr(packet, 'dst_ip') and packet.dst_ip:
            self.traffic_by_ip[packet.dst_ip] += packet_size
        
        # Estatísticas por protocolo
        if hasattr(packet, 'protocol') and packet.protocol:
            self.traffic_by_protocol[packet.protocol] += packet_size
        
        # Calcula tamanho médio de pacote
        self.avg_packet_size = self.total_bytes / self.total_packets if self.total_packets > 0 else 0
    
    def get_top_talkers(self, limit=10):
        """Retorna top IPs por tráfego"""
        sorted_ips = sorted(self.traffic_by_ip.items(), key=lambda x: x[1], reverse=True)
        return sorted_ips[:limit]
    
    def get_protocol_distribution(self):
        """Retorna distribuição de tráfego por protocolo"""
        total = sum(self.traffic_by_protocol.values())
        if total == 0:
            return []
        
        distribution = []
        for protocol, bytes_count in self.traffic_by_protocol.items():
            percentage = (bytes_count / total) * 100
            distribution.append((protocol, bytes_count, percentage))
        
        return sorted(distribution, key=lambda x: x[1], reverse=True)
    
    def get_bandwidth_graph(self, width=50, height=10):
        """Gera gráfico ASCII de bandwidth"""
        if len(self.bandwidth_timeline) < 2:
            return ["No data available for graph"]
        
        # Extrai valores de bandwidth
        values = [point['bps'] for point in self.bandwidth_timeline]
        max_val = max(values) if values else 1
        min_val = min(values) if values else 0
        
        graph_lines = []
        
        # Cria escala vertical
        for i in range(height):
            line = ""
            threshold = max_val - (i * (max_val - min_val) / (height - 1))
            
            for value in values[-width:]:  # Últimos 'width' pontos
                if value >= threshold:
                    line += "█"
                elif value >= threshold * 0.75:
                    line += "▆"
                elif value >= threshold * 0.5:
                    line += "▄"
                elif value >= threshold * 0.25:
                    line += "▂"
                else:
                    line += " "
            
            # Adiciona escala no lado direito
            scale_val = threshold
            if scale_val >= 1024*1024:
                scale_str = f"{scale_val/(1024*1024):.1f}MB/s"
            elif scale_val >= 1024:
                scale_str = f"{scale_val/1024:.1f}KB/s"
            else:
                scale_str = f"{scale_val:.0f}B/s"
            
            graph_lines.append(f"{line} {scale_str}")
        
        # Adiciona linha de tempo no final
        time_line = "─" * min(width, len(values))
        graph_lines.append(time_line + " Time →")
        
        return graph_lines
    
    def get_summary_stats(self):
        """Retorna resumo das estatísticas"""
        uptime = time.time() - self.start_time
        
        # Formata valores
        def format_bytes(bytes_val):
            if bytes_val >= 1024*1024*1024:
                return f"{bytes_val/(1024*1024*1024):.2f} GB"
            elif bytes_val >= 1024*1024:
                return f"{bytes_val/(1024*1024):.2f} MB"
            elif bytes_val >= 1024:
                return f"{bytes_val/1024:.2f} KB"
            else:
                return f"{bytes_val:.0f} B"
        
        def format_bandwidth(bps):
            return format_bytes(bps) + "/s"
        
        return {
            'uptime': f"{uptime:.0f}s",
            'total_bytes': format_bytes(self.total_bytes),
            'total_packets': f"{self.total_packets:,}",
            'current_bandwidth': format_bandwidth(self.bytes_per_second),
            'peak_bandwidth': format_bandwidth(self.peak_bandwidth),
            'avg_packet_size': f"{self.avg_packet_size:.0f} bytes",
            'packets_per_second': f"{self.packets_per_second:.1f} pps"
        }

class DNSAnalyzer:
    """Classe para análise de DNS com cache e detecção de anomalias"""
    
    def __init__(self):
        self.dns_cache = {}  # Cache de resoluções DNS
        self.dns_queries = []  # Lista de queries DNS
        self.dns_responses = []  # Lista de responses DNS
        self.suspicious_domains = []  # Domínios suspeitos
        self.dns_tunneling_patterns = []  # Padrões de DNS tunneling
        
        # Blacklists conhecidas (exemplo)
        self.known_malicious_domains = {
            'malware.com', 'phishing.net', 'botnet.org',
            'c2server.com', 'malicious.info'
        }
        
        # Padrões suspeitos para detecção de DNS tunneling
        self.tunneling_indicators = [
            'long_subdomain',  # Subdomínios muito longos
            'base64_pattern',  # Padrões base64
            'high_frequency',  # Muitas queries para mesmo domínio
            'unusual_tld',     # TLDs incomuns
            'hex_pattern'      # Padrões hexadecimais
        ]
    
    def analyze_dns_packet(self, packet):
        """Analisa pacote DNS e extrai informações"""
        if not hasattr(packet, 'raw_packet') or not hasattr(packet.raw_packet, 'load'):
            return None
        
        try:
            # Verifica se é DNS (porta 53)
            if not (hasattr(packet, 'dst_port') and (packet.dst_port == 53 or packet.src_port == 53)):
                return None
            
            payload = bytes(packet.raw_packet.load)
            
            # Parse básico de DNS (simulado - implementação real seria mais complexa)
            dns_data = self._parse_dns_payload(payload)
            if dns_data:
                # Análise de segurança
                security_issues = self._analyze_dns_security(dns_data)
                
                dns_info = {
                    'timestamp': packet.timestamp,
                    'src_ip': packet.src_ip,
                    'dst_ip': packet.dst_ip,
                    'type': dns_data.get('type', 'unknown'),
                    'domain': dns_data.get('domain', ''),
                    'response_ip': dns_data.get('response_ip', ''),
                    'query_type': dns_data.get('query_type', 'A'),
                    'security_issues': security_issues,
                    'is_suspicious': len(security_issues) > 0
                }
                
                # Adiciona ao cache se for response
                if dns_data.get('type') == 'response' and dns_data.get('domain') and dns_data.get('response_ip'):
                    self.dns_cache[dns_data['domain']] = {
                        'ip': dns_data['response_ip'],
                        'timestamp': packet.timestamp,
                        'ttl': dns_data.get('ttl', 3600)
                    }
                
                # Adiciona às listas
                if dns_data.get('type') == 'query':
                    self.dns_queries.append(dns_info)
                else:
                    self.dns_responses.append(dns_info)
                
                return dns_info
                
        except Exception as e:
            logger.debug(f"Erro ao analisar DNS: {e}")
        
        return None
    
    def _parse_dns_payload(self, payload):
        """Parse básico de payload DNS (simulado)"""
        try:
            # Em uma implementação real, seria usado um parser DNS completo
            # Aqui fazemos uma simulação básica
            text = payload.decode('utf-8', errors='ignore')
            
            # Detecta domínios com regex simples
            import re
            domain_pattern = r'([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}'
            domains = re.findall(domain_pattern, text)
            
            if domains:
                return {
                    'type': 'query' if len(payload) < 100 else 'response',
                    'domain': domains[0],
                    'query_type': 'A',
                    'response_ip': '192.168.1.1' if len(payload) > 100 else None,
                    'ttl': 3600
                }
        except:
            pass
        
        return None
    
    def _analyze_dns_security(self, dns_data):
        """Analisa problemas de segurança em DNS"""
        issues = []
        domain = dns_data.get('domain', '').lower()
        
        # Verifica domínios maliciosos conhecidos
        if domain in self.known_malicious_domains:
            issues.append('KNOWN_MALICIOUS_DOMAIN')
        
        # Verifica indicadores de DNS tunneling
        if len(domain) > 50:  # Domínio muito longo
            issues.append('POSSIBLE_DNS_TUNNELING_LONG_DOMAIN')
        
        # Verifica padrões suspeitos
        if any(char in domain for char in ['0x', '==', '+', '/']):
            issues.append('SUSPICIOUS_DOMAIN_PATTERN')
        
        # Verifica TLDs incomuns
        uncommon_tlds = ['.tk', '.ml', '.ga', '.cf', '.onion']
        if any(domain.endswith(tld) for tld in uncommon_tlds):
            issues.append('UNCOMMON_TLD')
        
        # Verifica subdomínios muito longos
        parts = domain.split('.')
        if any(len(part) > 20 for part in parts):
            issues.append('LONG_SUBDOMAIN')
        
        return issues
    
    def get_dns_cache(self):
        """Retorna cache DNS atual"""
        return dict(sorted(self.dns_cache.items(), key=lambda x: x[1]['timestamp'], reverse=True))
    
    def get_recent_queries(self, limit=20):
        """Retorna queries DNS recentes"""
        return sorted(self.dns_queries, key=lambda x: x['timestamp'], reverse=True)[:limit]
    
    def get_suspicious_activity(self):
        """Retorna atividade DNS suspeita"""
        suspicious = []
        
        # Combina queries e responses suspeitas
        all_dns = self.dns_queries + self.dns_responses
        for item in all_dns:
            if item['is_suspicious']:
                suspicious.append(item)
        
        return sorted(suspicious, key=lambda x: x['timestamp'], reverse=True)
    
    def resolve_ip(self, ip):
        """Resolução reversa de IP (usando cache)"""
        for domain, data in self.dns_cache.items():
            if data['ip'] == ip:
                return domain
        return None

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

class IPv6Analyzer:
    """Classe para análise avançada de IPv6 e dual-stack"""
    
    def __init__(self):
        self.ipv6_packets = []
        self.ipv4_packets = []
        self.dual_stack_connections = {}
        self.ipv6_extensions = defaultdict(int)
        self.tunnel_protocols = defaultdict(int)
        self.icmpv6_types = defaultdict(int)
        self.neighbor_discovery = []
        self.router_advertisements = []
        
        # Tipos de túneis IPv6
        self.tunnel_types = {
            41: "6in4",     # IPv6 in IPv4
            47: "GRE",      # Generic Routing Encapsulation
            50: "ESP",      # Encapsulating Security Payload
            51: "AH"        # Authentication Header
        }
        
        # Extension headers IPv6
        self.extension_headers = {
            0: "Hop-by-Hop",
            6: "TCP",
            17: "UDP",
            43: "Routing",
            44: "Fragment", 
            51: "Authentication",
            60: "Destination Options"
        }
    
    def analyze_ipv6_packet(self, packet):
        """Analisa pacote IPv6 em detalhes"""
        if not hasattr(packet, 'raw_packet'):
            return None
            
        try:
            pkt = packet.raw_packet
            
            # Análise IPv6
            if hasattr(pkt, 'haslayer') and pkt.haslayer(IPv6):
                ipv6_info = self._parse_ipv6_layer(pkt)
                self.ipv6_packets.append(ipv6_info)
                
                # Detecta dual-stack
                self._detect_dual_stack(packet, ipv6_info)
                
                # Analisa extension headers
                self._analyze_extension_headers(pkt)
                
                # Analisa ICMPv6
                if pkt.haslayer(ICMPv6EchoRequest) or pkt.haslayer(ICMPv6EchoReply) or pkt.haslayer(ICMPv6DestUnreach):
                    self._analyze_icmpv6(pkt)
                
                return ipv6_info
            
            # Análise IPv4 para dual-stack
            elif hasattr(pkt, 'haslayer') and pkt.haslayer(IP):
                ipv4_info = self._parse_ipv4_layer(pkt)
                self.ipv4_packets.append(ipv4_info)
                return ipv4_info
                
        except Exception as e:
            logger.debug(f"Erro ao analisar IPv6: {e}")
        
        return None
    
    def _parse_ipv6_layer(self, pkt):
        """Parse da camada IPv6"""
        ipv6_layer = pkt[IPv6]
        
        return {
            'version': 6,
            'src': ipv6_layer.src,
            'dst': ipv6_layer.dst,
            'traffic_class': ipv6_layer.tc,
            'flow_label': ipv6_layer.fl,
            'payload_length': ipv6_layer.plen,
            'next_header': ipv6_layer.nh,
            'hop_limit': ipv6_layer.hlim,
            'is_link_local': self._is_link_local(ipv6_layer.src),
            'is_multicast': self._is_multicast(ipv6_layer.dst),
            'is_loopback': ipv6_layer.src == "::1",
            'address_type_src': self._classify_ipv6_address(ipv6_layer.src),
            'address_type_dst': self._classify_ipv6_address(ipv6_layer.dst)
        }
    
    def _parse_ipv4_layer(self, pkt):
        """Parse da camada IPv4 para comparação dual-stack"""
        ip_layer = pkt[IP]
        
        return {
            'version': 4,
            'src': ip_layer.src,
            'dst': ip_layer.dst,
            'ttl': ip_layer.ttl,
            'protocol': ip_layer.proto,
            'flags': ip_layer.flags,
            'fragment_offset': ip_layer.frag
        }
    
    def _is_link_local(self, addr):
        """Verifica se é endereço link-local"""
        return addr.startswith("fe80:")
    
    def _is_multicast(self, addr):
        """Verifica se é endereço multicast"""
        return addr.startswith("ff")
    
    def _classify_ipv6_address(self, addr):
        """Classifica tipo de endereço IPv6"""
        if addr == "::1":
            return "loopback"
        elif addr.startswith("fe80:"):
            return "link-local"
        elif addr.startswith("ff"):
            return "multicast"
        elif addr.startswith("fc") or addr.startswith("fd"):
            return "unique-local"
        elif addr.startswith("::ffff:"):
            return "ipv4-mapped"
        elif addr.startswith("2001:db8:"):
            return "documentation"
        elif addr.startswith("2001:"):
            return "global-unicast"
        else:
            return "global-unicast"
    
    def _detect_dual_stack(self, packet, _ipv6_info):
        """Detecta conexões dual-stack"""
        try:
            host_key = f"{packet.src_ip}-{packet.dst_ip}"
            
            if host_key not in self.dual_stack_connections:
                self.dual_stack_connections[host_key] = {
                    'ipv4_count': 0,
                    'ipv6_count': 0,
                    'first_seen': packet.timestamp,
                    'protocols': set()
                }
            
            conn = self.dual_stack_connections[host_key]
            conn['ipv6_count'] += 1
            if hasattr(packet, 'protocol'):
                conn['protocols'].add(packet.protocol)
                
        except Exception as e:
            logger.debug(f"Erro ao detectar dual-stack: {e}")
    
    def _analyze_extension_headers(self, pkt):
        """Analisa extension headers IPv6"""
        try:
            current_header = pkt[IPv6].nh
            self.ipv6_extensions[current_header] += 1
            
            # Verifica headers específicos
            if current_header == 44:  # Fragment header
                logger.debug("IPv6 fragment detected")
            elif current_header == 43:  # Routing header
                logger.debug("IPv6 routing header detected")
                
        except Exception as e:
            logger.debug(f"Erro ao analisar extension headers: {e}")
    
    def _analyze_icmpv6(self, pkt):
        """Analisa mensagens ICMPv6"""
        try:
            # Encontrar o primeiro layer ICMPv6 disponível
            icmpv6_layer = None
            if pkt.haslayer(ICMPv6EchoRequest):
                icmpv6_layer = pkt[ICMPv6EchoRequest]
            elif pkt.haslayer(ICMPv6EchoReply):
                icmpv6_layer = pkt[ICMPv6EchoReply]
            elif pkt.haslayer(ICMPv6DestUnreach):
                icmpv6_layer = pkt[ICMPv6DestUnreach]
            
            if not icmpv6_layer:
                return
            icmp_type = icmpv6_layer.type
            self.icmpv6_types[icmp_type] += 1
            
            # Neighbor Discovery Protocol
            if icmp_type in [135, 136]:  # Neighbor Solicitation/Advertisement
                self.neighbor_discovery.append({
                    'type': 'NS' if icmp_type == 135 else 'NA',
                    'timestamp': datetime.now(),
                    'src': pkt[IPv6].src,
                    'dst': pkt[IPv6].dst
                })
            
            # Router Advertisement
            elif icmp_type == 134:
                self.router_advertisements.append({
                    'timestamp': datetime.now(),
                    'src': pkt[IPv6].src,
                    'hop_limit': getattr(icmpv6_layer, 'chlim', 0),
                    'flags': getattr(icmpv6_layer, 'M', 0)
                })
                
        except Exception as e:
            logger.debug(f"Erro ao analisar ICMPv6: {e}")
    
    def get_ipv6_statistics(self):
        """Retorna estatísticas IPv6"""
        total_ipv6 = len(self.ipv6_packets)
        total_ipv4 = len(self.ipv4_packets)
        total_packets = total_ipv6 + total_ipv4
        
        return {
            'total_packets': total_packets,
            'ipv6_packets': total_ipv6,
            'ipv4_packets': total_ipv4,
            'ipv6_percentage': (total_ipv6 / total_packets * 100) if total_packets > 0 else 0,
            'dual_stack_connections': len(self.dual_stack_connections),
            'extension_headers': dict(self.ipv6_extensions),
            'icmpv6_types': dict(self.icmpv6_types),
            'neighbor_discoveries': len(self.neighbor_discovery),
            'router_advertisements': len(self.router_advertisements)
        }
    
    def get_address_summary(self):
        """Retorna resumo de tipos de endereços"""
        address_types = defaultdict(int)
        
        for packet in self.ipv6_packets:
            address_types[packet['address_type_src']] += 1
            address_types[packet['address_type_dst']] += 1
        
        return dict(address_types)

class AlertManager:
    """Sistema de alertas e notificações em tempo real"""
    
    def __init__(self):
        self.alerts = []
        self.alert_rules = []
        self.alert_counters = defaultdict(int)
        self.alert_history = defaultdict(list)
        self.max_alerts = 1000
        
        # Configurações de alertas
        self.alert_config = {
            'rate_limits': {
                'port_scan': {'count': 10, 'window': 60},  # 10 portas em 60s
                'dns_flood': {'count': 50, 'window': 10},  # 50 queries em 10s
                'syn_flood': {'count': 100, 'window': 5},  # 100 SYNs em 5s
                'bandwidth_spike': {'threshold': 10485760}  # 10MB/s
            },
            'severity_levels': {
                'CRITICAL': {'color': 5, 'priority': 1},
                'HIGH': {'color': 5, 'priority': 2},
                'MEDIUM': {'color': 4, 'priority': 3},
                'LOW': {'color': 3, 'priority': 4},
                'INFO': {'color': 0, 'priority': 5}
            }
        }
        
        # Tipos de alertas
        self.alert_types = {
            'SECURITY_THREAT': 'CRITICAL',
            'MALWARE_DETECTED': 'CRITICAL',
            'SUSPICIOUS_TRAFFIC': 'HIGH',
            'ANOMALY_DETECTED': 'HIGH',
            'PERFORMANCE_ISSUE': 'MEDIUM',
            'UNUSUAL_PATTERN': 'MEDIUM',
            'PROTOCOL_VIOLATION': 'LOW',
            'INFO_DISCLOSURE': 'LOW'
        }
    
    def create_alert(self, alert_type, message, details=None, source_ip=None, destination_ip=None):
        """Cria um novo alerta"""
        try:
            severity = self.alert_types.get(alert_type, 'INFO')
            
            alert = {
                'id': len(self.alerts) + 1,
                'timestamp': datetime.now(),
                'type': alert_type,
                'severity': severity,
                'message': message,
                'details': details or {},
                'source_ip': source_ip,
                'destination_ip': destination_ip,
                'acknowledged': False,
                'false_positive': False
            }
            
            # Adiciona à lista
            self.alerts.append(alert)
            
            # Mantém limite de alertas
            if len(self.alerts) > self.max_alerts:
                self.alerts.pop(0)
            
            # Adiciona ao histórico
            self.alert_history[alert_type].append(alert['timestamp'])
            
            # Incrementa contador
            self.alert_counters[alert_type] += 1
            
            logger.info(f"Alert created: {alert_type} - {message}")
            return alert
            
        except Exception as e:
            logger.error(f"Erro ao criar alerta: {e}")
            return None
    
    def analyze_traffic_patterns(self, packets, bandwidth_stats):
        """Analisa padrões de tráfego e gera alertas"""
        try:
            current_time = time.time()
            
            # Análise de port scanning
            self._detect_port_scanning(packets)
            
            # Análise de DNS flooding
            self._detect_dns_flooding(packets)
            
            # Análise de SYN flooding
            self._detect_syn_flooding(packets)
            
            # Análise de bandwidth spike
            self._detect_bandwidth_spike(bandwidth_stats)
            
            # Análise de conexões suspeitas
            self._detect_suspicious_connections(packets)
            
        except Exception as e:
            logger.error(f"Erro na análise de padrões: {e}")
    
    def _detect_port_scanning(self, packets):
        """Detecta port scanning"""
        try:
            # Agrupa por IP source nos últimos 60 segundos
            recent_time = datetime.now() - timedelta(seconds=60)
            recent_packets = [p for p in packets if p.timestamp > recent_time and p.protocol == "TCP"]
            
            ip_ports = defaultdict(set)
            for packet in recent_packets:
                if hasattr(packet, 'src_ip') and hasattr(packet, 'dst_port'):
                    ip_ports[packet.src_ip].add(packet.dst_port)
            
            # Alerta se um IP tocou muitas portas
            for ip, ports in ip_ports.items():
                if len(ports) >= self.alert_config['rate_limits']['port_scan']['count']:
                    self.create_alert(
                        'SUSPICIOUS_TRAFFIC',
                        f"Possible port scan from {ip}",
                        {'scanned_ports': len(ports), 'ports': list(ports)[:10]},
                        source_ip=ip
                    )
                    
        except Exception as e:
            logger.debug(f"Erro na detecção de port scan: {e}")
    
    def _detect_dns_flooding(self, packets):
        """Detecta DNS flooding"""
        try:
            recent_time = datetime.now() - timedelta(seconds=10)
            dns_packets = [p for p in packets if p.timestamp > recent_time and 
                          hasattr(p, 'dst_port') and p.dst_port == 53]
            
            ip_queries = defaultdict(int)
            for packet in dns_packets:
                if hasattr(packet, 'src_ip'):
                    ip_queries[packet.src_ip] += 1
            
            for ip, count in ip_queries.items():
                if count >= self.alert_config['rate_limits']['dns_flood']['count']:
                    self.create_alert(
                        'ANOMALY_DETECTED',
                        f"DNS flooding from {ip}",
                        {'query_count': count, 'time_window': '10s'},
                        source_ip=ip
                    )
                    
        except Exception as e:
            logger.debug(f"Erro na detecção de DNS flood: {e}")
    
    def _detect_syn_flooding(self, packets):
        """Detecta SYN flooding"""
        try:
            recent_time = datetime.now() - timedelta(seconds=5)
            syn_packets = [p for p in packets if p.timestamp > recent_time and 
                          p.protocol == "TCP" and hasattr(p, 'tcp_flags') and 
                          p.tcp_flags & 0x02]  # SYN flag
            
            ip_syns = defaultdict(int)
            for packet in syn_packets:
                if hasattr(packet, 'src_ip'):
                    ip_syns[packet.src_ip] += 1
            
            for ip, count in ip_syns.items():
                if count >= self.alert_config['rate_limits']['syn_flood']['count']:
                    self.create_alert(
                        'SECURITY_THREAT',
                        f"SYN flood attack from {ip}",
                        {'syn_count': count, 'time_window': '5s'},
                        source_ip=ip
                    )
                    
        except Exception as e:
            logger.debug(f"Erro na detecção de SYN flood: {e}")
    
    def _detect_bandwidth_spike(self, bandwidth_stats):
        """Detecta picos de bandwidth"""
        try:
            current_bps = bandwidth_stats.get('bytes_per_second', 0)
            threshold = self.alert_config['rate_limits']['bandwidth_spike']['threshold']
            
            if current_bps > threshold:
                self.create_alert(
                    'PERFORMANCE_ISSUE',
                    f"High bandwidth usage detected",
                    {
                        'current_bps': current_bps,
                        'threshold': threshold,
                        'usage_mb': current_bps / 1024 / 1024
                    }
                )
                
        except Exception as e:
            logger.debug(f"Erro na detecção de bandwidth spike: {e}")
    
    def _detect_suspicious_connections(self, packets):
        """Detecta conexões suspeitas"""
        try:
            # Conexões para portas não-padrão
            for packet in packets[-50:]:  # Últimos 50 pacotes
                if hasattr(packet, 'dst_port') and packet.dst_port:
                    # Portas suspeitas conhecidas
                    suspicious_ports = [4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345]
                    if packet.dst_port in suspicious_ports:
                        self.create_alert(
                            'SUSPICIOUS_TRAFFIC',
                            f"Connection to suspicious port {packet.dst_port}",
                            {'port': packet.dst_port, 'protocol': packet.protocol},
                            source_ip=packet.src_ip,
                            destination_ip=packet.dst_ip
                        )
                        
        except Exception as e:
            logger.debug(f"Erro na detecção de conexões suspeitas: {e}")
    
    def get_recent_alerts(self, limit=20):
        """Retorna alertas recentes"""
        return sorted(self.alerts, key=lambda x: x['timestamp'], reverse=True)[:limit]
    
    def get_alerts_by_severity(self, severity):
        """Retorna alertas por severidade"""
        return [alert for alert in self.alerts if alert['severity'] == severity]
    
    def get_alert_summary(self):
        """Retorna resumo de alertas"""
        total = len(self.alerts)
        unacknowledged = len([a for a in self.alerts if not a['acknowledged']])
        
        by_severity = defaultdict(int)
        for alert in self.alerts:
            by_severity[alert['severity']] += 1
        
        by_type = defaultdict(int)
        for alert in self.alerts:
            by_type[alert['type']] += 1
        
        return {
            'total_alerts': total,
            'unacknowledged': unacknowledged,
            'by_severity': dict(by_severity),
            'by_type': dict(by_type),
            'acknowledgment_rate': ((total - unacknowledged) / total * 100) if total > 0 else 0
        }
    
    def acknowledge_alert(self, alert_id):
        """Marca alerta como reconhecido"""
        for alert in self.alerts:
            if alert['id'] == alert_id:
                alert['acknowledged'] = True
                return True
        return False

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
            
            # IP layer (IPv4)
            if pkt.haslayer(IP):
                self.src_ip = pkt[IP].src
                self.dst_ip = pkt[IP].dst
                self.protocol = pkt[IP].proto
                self.ttl = pkt[IP].ttl
                self.ip_len = pkt[IP].len
                self.ip_flags = pkt[IP].flags
                self.ip_frag = pkt[IP].frag
                self.ip_version = 4
            
            # IPv6 layer
            elif pkt.haslayer(IPv6):
                self.src_ip = pkt[IPv6].src
                self.dst_ip = pkt[IPv6].dst
                self.protocol = pkt[IPv6].nh  # Next Header
                self.ttl = pkt[IPv6].hlim     # Hop Limit (equivalent to TTL)
                self.ip_len = pkt[IPv6].plen  # Payload Length
                self.ip_version = 6
                
                # IPv6 specific fields
                self.traffic_class = pkt[IPv6].tc
                self.flow_label = pkt[IPv6].fl
                self.hop_limit = pkt[IPv6].hlim
                
                # Classify IPv6 address types
                self.ipv6_src_type = self._classify_ipv6_address(self.src_ip)
                self.ipv6_dst_type = self._classify_ipv6_address(self.dst_ip)
                
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
    
    def _classify_ipv6_address(self, addr):
        """Classifica tipo de endereço IPv6"""
        if addr == "::1":
            return "loopback"
        elif addr.startswith("fe80:"):
            return "link-local"
        elif addr.startswith("ff"):
            return "multicast"
        elif addr.startswith("fc") or addr.startswith("fd"):
            return "unique-local"
        elif addr.startswith("::ffff:"):
            return "ipv4-mapped"
        elif addr.startswith("2001:db8:"):
            return "documentation"
        elif addr.startswith("2001:"):
            return "global-unicast"
        else:
            return "global-unicast"
    
    def is_relevant(self) -> bool:
        """Determina se o pacote contém informações relevantes"""
        # Filtra tráfego loopback (sempre irrelevante)
        if self.src_ip and self.dst_ip:
            if self.src_ip.startswith("127.") or self.dst_ip.startswith("127."):
                return False
        
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
                # Só ACK sem dados = não relevante
                if self.tcp_flags == 0x10:  # Apenas ACK
                    return False
            
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
        
        # Tráfego TCP comum em portas altas (provavelmente só ACK)
        if self.protocol == "TCP":
            if hasattr(self, 'src_port') and hasattr(self, 'dst_port'):
                # Ambas as portas são altas (> 1024) = tráfego comum
                if self.src_port > 1024 and self.dst_port > 1024:
                    return False
        
        # Tráfego UDP em portas altas sem conteúdo específico
        if self.protocol == "UDP":
            if hasattr(self, 'src_port') and hasattr(self, 'dst_port'):
                if self.src_port > 1024 and self.dst_port > 1024:
                    # Só relevante se tem informação específica
                    if not any(keyword in self.info.lower() for keyword in 
                              ["dns", "dhcp", "ntp", "request", "response"]):
                        return False
        
        # Por padrão, se chegou até aqui, pode ser relevante
        return True
    
    def is_ipv6(self) -> bool:
        """Determina se o pacote é IPv6"""
        return hasattr(self, 'ip_version') and self.ip_version == 6

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
        self.show_ipv6 = False  # Por padrão, IPv6 desabilitado
        self.tcp_streams = {}  # Dicionário para armazenar streams TCP
        self.current_stream = None  # Stream atualmente sendo seguido
        self.stream_view = False  # Se está visualizando um stream específico
        self.http_analyzer = HTTPAnalyzer()  # Analisador HTTP/HTTPS
        self.http_transactions = []  # Lista de transações HTTP analisadas
        self.bandwidth_analyzer = BandwidthAnalyzer()  # Analisador de bandwidth
        self.dns_analyzer = DNSAnalyzer()  # Analisador DNS
        self.ipv6_analyzer = IPv6Analyzer()  # Analisador IPv6
        self.alert_manager = AlertManager()  # Sistema de alertas
        self.last_analysis_time = time.time()  # Última análise de padrões
        
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
        
        # Atualiza estatísticas de bandwidth
        self.bandwidth_analyzer.update(packet)
        
        # Processa análise DNS
        self._process_dns_packet(packet)
        
        # Processa análise IPv6 (apenas se habilitado)
        if self.show_ipv6:
            self._process_ipv6_packet(packet)
        
        # Análise de alertas (a cada 10 segundos)
        self._process_alert_analysis()
    
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
    
    def _process_dns_packet(self, packet):
        """Processa pacote para análise DNS"""
        try:
            dns_data = self.dns_analyzer.analyze_dns_packet(packet)
            if dns_data:
                logger.debug(f"DNS packet processed: {dns_data['domain']}")
        except Exception as e:
            logger.debug(f"Erro ao processar DNS: {e}")
    
    def _process_ipv6_packet(self, packet):
        """Processa pacote para análise IPv6"""
        try:
            ipv6_data = self.ipv6_analyzer.analyze_ipv6_packet(packet)
            if ipv6_data:
                logger.debug(f"IPv6 packet processed: {ipv6_data.get('version', 'unknown')}")
        except Exception as e:
            logger.debug(f"Erro ao processar IPv6: {e}")
    
    def _process_alert_analysis(self):
        """Processa análise de alertas periodicamente"""
        try:
            current_time = time.time()
            # Executa análise a cada 10 segundos
            if current_time - self.last_analysis_time >= 10:
                bandwidth_stats = self.bandwidth_analyzer.get_summary_stats()
                self.alert_manager.analyze_traffic_patterns(self.packets, bandwidth_stats)
                self.last_analysis_time = current_time
        except Exception as e:
            logger.debug(f"Erro na análise de alertas: {e}")
    
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
                elif key == ord('8'):
                    self.current_view = "bandwidth"
                elif key == ord('9'):
                    self.current_view = "dashboard"
                elif key == ord('h'):
                    self._toggle_hex_view()
                elif key == ord('t'):  # TCP streams
                    self.current_view = "streams"
                elif key == ord('f'):  # Follow stream (quando um pacote TCP está selecionado)
                    self._follow_tcp_stream()
                elif key == ord('r'):
                    self._toggle_relevant_filter()
                elif key == ord('v'):  # Toggle IPv6 view
                    self._toggle_ipv6_view()
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
        elif self.current_view == "bandwidth":
            self._draw_bandwidth_view()
        elif self.current_view == "dashboard":
            self._draw_dashboard_view()
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
        # Calcula pacotes filtrados (relevância + IPv6)
        filtered_packets = self.packets
        if self.show_relevant_only:
            filtered_packets = [p for p in filtered_packets if p.is_relevant()]
        if not self.show_ipv6:
            filtered_packets = [p for p in filtered_packets if not p.is_ipv6()]
        filtered_count = len(filtered_packets)
        
        status = f"Interface: {self.interface or 'None'} | "
        status += f"Capturing: {'Yes' if self.is_capturing else 'No'} | "
        
        if self.show_relevant_only:
            status += f"Packets: {filtered_count}/{len(self.packets)} (Relevant) | "
        else:
            status += f"Packets: {filtered_count}/{len(self.packets)} (All) | "
            
        status += f"Filter: {self.packet_filter or 'None'}"
        
        self.stdscr.addstr(2, 0, status[:curses.COLS-1])
    
    def _draw_packets_view(self):
        """Desenha visualização de pacotes"""
        start_y = 4
        height = curses.LINES - 7  # Ajustado para footer de 2 linhas
        
        # Filtra pacotes por relevância e IPv6
        filtered_packets = self.packets
        if self.show_relevant_only:
            filtered_packets = [p for p in filtered_packets if p.is_relevant()]
        if not self.show_ipv6:
            filtered_packets = [p for p in filtered_packets if not p.is_ipv6()]
        
        # Pacotes mais novos primeiro (ordem reversa)
        reversed_packets = list(reversed(filtered_packets))
        
        # Headers com indicador de filtro - largura fixa para alinhamento
        filter_indicator = "[RELEVANT]" if self.show_relevant_only else "[ALL]     "
        ipv6_indicator = "[IPv6 ON]" if self.show_ipv6 else "[IPv6 OFF]"
        headers = f"{'#':<6} {'Time':<12} {'Source':<15} {':Port':<6} {'Destination':<15} {':Port':<6} {'Proto':<6} {'Flags':<8} {'Size':<6} {'Info':<20} {filter_indicator} {ipv6_indicator}"
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
                commands1 = "[S]tart/Stop  [C]lear  [E]xport  [I]filter  [R]elevant  [V]IPv6  [F]ollow  [9]Dashboard"
                commands2 = "[1]Packets [2]Stats [3]Details [4]Interfaces [5]Streams [6]HTTP [7]Security [8]Bandwidth [Q]uit"
                
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
            # Filtrar pacotes por relevância e IPv6
            filtered_packets = self.packets
            if self.show_relevant_only:
                filtered_packets = [p for p in filtered_packets if p.is_relevant()]
            if not self.show_ipv6:
                filtered_packets = [p for p in filtered_packets if not p.is_ipv6()]
            current_list = filtered_packets
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
            # Filtrar pacotes por relevância e IPv6
            filtered_packets = self.packets
            if self.show_relevant_only:
                filtered_packets = [p for p in filtered_packets if p.is_relevant()]
            if not self.show_ipv6:
                filtered_packets = [p for p in filtered_packets if not p.is_ipv6()]
            
            # Com ordem reversa, scroll down vai para pacotes mais antigos (índices menores)
            if self.selected_packet > 0:
                self.selected_packet -= 1
                # Ajusta scroll se necessário  
                visible_height = curses.LINES - 7  # Ajustado para footer de 2 linhas
                display_index = len(filtered_packets) - 1 - self.selected_packet
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
        
        # Debug: mostrar estado atual no log
        total_packets = len(self.packets)
        relevant_packets = len([p for p in self.packets if p.is_relevant()])
        mode = "RELEVANT" if self.show_relevant_only else "ALL"
        
        # Garantir que estamos na view de packets para ver a mudança
        if self.current_view != "packets":
            self.current_view = "packets"
        
        # Força refresh da tela
        if hasattr(self, 'stdscr') and self.stdscr:
            self.stdscr.clear()
            self.stdscr.refresh()
    
    def _toggle_ipv6_view(self):
        """Alterna visualização de IPv6"""
        self.show_ipv6 = not self.show_ipv6
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
        
        # Filtra pacotes por relevância e IPv6
        filtered_packets = self.packets
        if self.show_relevant_only:
            filtered_packets = [p for p in filtered_packets if p.is_relevant()]
        if not self.show_ipv6:
            filtered_packets = [p for p in filtered_packets if not p.is_ipv6()]
        
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
    
    def _draw_bandwidth_view(self):
        """Desenha visualização de bandwidth e estatísticas de rede"""
        start_y = 4
        
        # Obtém estatísticas
        stats = self.bandwidth_analyzer.get_summary_stats()
        top_talkers = self.bandwidth_analyzer.get_top_talkers(8)
        protocol_dist = self.bandwidth_analyzer.get_protocol_distribution()
        
        # Título
        try:
            self.stdscr.addstr(start_y, 0, "BANDWIDTH & NETWORK STATISTICS", curses.color_pair(1))
        except:
            pass
        
        # Estatísticas resumo
        col1_x = 2
        col2_x = 40
        current_y = start_y + 2
        
        try:
            self.stdscr.addstr(current_y, col1_x, "NETWORK SUMMARY", curses.color_pair(1))
            current_y += 1
            self.stdscr.addstr(current_y, col1_x, f"Uptime: {stats['uptime']}")
            current_y += 1
            self.stdscr.addstr(current_y, col1_x, f"Total Bytes: {stats['total_bytes']}")
            current_y += 1
            self.stdscr.addstr(current_y, col1_x, f"Total Packets: {stats['total_packets']}")
            current_y += 1
            self.stdscr.addstr(current_y, col1_x, f"Current BW: {stats['current_bandwidth']}")
            current_y += 1
            self.stdscr.addstr(current_y, col1_x, f"Peak BW: {stats['peak_bandwidth']}")
            current_y += 1
            self.stdscr.addstr(current_y, col1_x, f"Avg Packet: {stats['avg_packet_size']}")
            current_y += 1
            self.stdscr.addstr(current_y, col1_x, f"PPS: {stats['packets_per_second']}")
        except:
            pass
        
        # Top Talkers
        try:
            current_y = start_y + 2
            self.stdscr.addstr(current_y, col2_x, "TOP TALKERS", curses.color_pair(1))
            current_y += 1
            for i, (ip, bytes_count) in enumerate(top_talkers):
                if current_y >= curses.LINES - 12:  # Espaço para gráfico
                    break
                # Formata bytes
                if bytes_count >= 1024*1024:
                    size_str = f"{bytes_count/(1024*1024):.1f}MB"
                elif bytes_count >= 1024:
                    size_str = f"{bytes_count/1024:.1f}KB"
                else:
                    size_str = f"{bytes_count}B"
                
                line = f"{i+1:2}. {ip:<15} {size_str:>10}"
                attr = curses.color_pair(3) if i < 3 else curses.color_pair(0)
                self.stdscr.addstr(current_y, col2_x, line, attr)
                current_y += 1
        except:
            pass
        
        # Distribuição por protocolo
        try:
            protocol_y = start_y + 2
            protocol_x = 75
            if curses.COLS > protocol_x + 20:
                self.stdscr.addstr(protocol_y, protocol_x, "PROTOCOLS", curses.color_pair(1))
                protocol_y += 1
                for i, (protocol, bytes_count, percentage) in enumerate(protocol_dist[:6]):
                    if protocol_y >= curses.LINES - 12:
                        break
                    bar_length = int(percentage / 10)  # Barra de 0-10 caracteres
                    bar = "█" * bar_length + "░" * (10 - bar_length)
                    line = f"{protocol:<4} {bar} {percentage:5.1f}%"
                    self.stdscr.addstr(protocol_y, protocol_x, line)
                    protocol_y += 1
        except:
            pass
        
        # Gráfico de bandwidth
        try:
            graph_start_y = curses.LINES - 14
            self.stdscr.addstr(graph_start_y - 1, 2, "BANDWIDTH GRAPH (Last 60 seconds)", curses.color_pair(1))
            
            graph_width = min(60, curses.COLS - 20)
            graph_height = 8
            graph_lines = self.bandwidth_analyzer.get_bandwidth_graph(graph_width, graph_height)
            
            for i, line in enumerate(graph_lines):
                if graph_start_y + i >= curses.LINES - 3:
                    break
                # Color para o gráfico
                attr = curses.color_pair(4) if "█" in line else curses.color_pair(0)
                self.stdscr.addstr(graph_start_y + i, 2, line[:curses.COLS-4], attr)
        except:
            pass
    
    def _draw_dashboard_view(self):
        """Desenha dashboard completo de rede em tempo real"""
        start_y = 4
        
        # Título principal
        try:
            title = "╔═══════════════════════════════════════════════════════════════════════════════════╗"
            subtitle = "║                           SPECTRA NETWORK DASHBOARD                              ║"
            border = "╚═══════════════════════════════════════════════════════════════════════════════════╝"
            
            self.stdscr.addstr(start_y, 0, title[:curses.COLS-1], curses.color_pair(1))
            self.stdscr.addstr(start_y + 1, 0, subtitle[:curses.COLS-1], curses.color_pair(1))
            self.stdscr.addstr(start_y + 2, 0, border[:curses.COLS-1], curses.color_pair(1))
        except:
            pass
        
        # Layout em quadrantes
        mid_x = curses.COLS // 2
        mid_y = (curses.LINES - 10) // 2 + start_y + 4
        
        # Quadrante 1: Status e Estatísticas Básicas
        try:
            stats = self.bandwidth_analyzer.get_summary_stats()
            
            self.stdscr.addstr(start_y + 4, 2, "📊 NETWORK STATUS", curses.color_pair(1))
            self.stdscr.addstr(start_y + 5, 2, f"Interface: {self.interface or 'N/A'}")
            self.stdscr.addstr(start_y + 6, 2, f"Status: {'🟢 CAPTURING' if self.is_capturing else '🔴 STOPPED'}")
            self.stdscr.addstr(start_y + 7, 2, f"Uptime: {stats['uptime']}")
            self.stdscr.addstr(start_y + 8, 2, f"Packets: {stats['total_packets']}")
            self.stdscr.addstr(start_y + 9, 2, f"Traffic: {stats['total_bytes']}")
            self.stdscr.addstr(start_y + 10, 2, f"Current: {stats['current_bandwidth']}")
        except:
            pass
        
        # Quadrante 2: Alertas de Segurança
        try:
            alerts = self.get_security_alerts()
            alert_count = len(alerts)
            
            self.stdscr.addstr(start_y + 4, mid_x + 2, "🛡️ SECURITY ALERTS", curses.color_pair(1))
            
            if alert_count == 0:
                self.stdscr.addstr(start_y + 5, mid_x + 2, "✅ No threats detected", curses.color_pair(3))
            else:
                self.stdscr.addstr(start_y + 5, mid_x + 2, f"⚠️  {alert_count} alerts detected", curses.color_pair(5))
                
                # Mostra últimos 3 alertas
                for i, alert in enumerate(alerts[:3]):
                    if start_y + 6 + i >= mid_y:
                        break
                    time_str = alert['timestamp'].strftime("%H:%M:%S")
                    alert_type = ', '.join(alert['issues'])[:20]
                    line = f"{time_str} {alert_type}"
                    attr = curses.color_pair(5) if "HIGH" in str(alert) else curses.color_pair(4)
                    self.stdscr.addstr(start_y + 6 + i, mid_x + 2, line[:curses.COLS//2-4], attr)
        except:
            pass
        
        # Quadrante 3: Top Talkers
        try:
            top_talkers = self.bandwidth_analyzer.get_top_talkers(5)
            
            self.stdscr.addstr(mid_y, 2, "🔝 TOP TALKERS", curses.color_pair(1))
            
            for i, (ip, bytes_count) in enumerate(top_talkers):
                if mid_y + 1 + i >= curses.LINES - 5:
                    break
                
                # Formata tamanho
                if bytes_count >= 1024*1024:
                    size_str = f"{bytes_count/(1024*1024):.1f}MB"
                elif bytes_count >= 1024:
                    size_str = f"{bytes_count/1024:.1f}KB"
                else:
                    size_str = f"{bytes_count}B"
                
                # Cria barra visual
                max_bytes = max([b for _, b in top_talkers]) if top_talkers else 1
                bar_length = int((bytes_count / max_bytes) * 20) if max_bytes > 0 else 0
                bar = "█" * bar_length + "░" * (20 - bar_length)
                
                line = f"{i+1}. {ip:<15} {bar} {size_str:>8}"
                attr = curses.color_pair(3) if i < 3 else curses.color_pair(0)
                self.stdscr.addstr(mid_y + 1 + i, 2, line[:mid_x-4], attr)
        except:
            pass
        
        # Quadrante 4: Atividade Recente
        try:
            recent_transactions = self.get_http_transactions()[:5]
            streams = self.get_tcp_streams()[:3]
            
            self.stdscr.addstr(mid_y, mid_x + 2, "⚡ RECENT ACTIVITY", curses.color_pair(1))
            
            activity_y = mid_y + 1
            
            # HTTP transactions
            if recent_transactions:
                self.stdscr.addstr(activity_y, mid_x + 2, "HTTP:")
                activity_y += 1
                for transaction in recent_transactions[:2]:
                    if activity_y >= curses.LINES - 5:
                        break
                    time_str = transaction['timestamp'].strftime("%H:%M:%S")
                    if transaction['type'] == 'request':
                        info = f"{transaction['method']} {transaction['url'][:15]}"
                    else:
                        info = f"Response {transaction['status_code']}"
                    
                    line = f"  {time_str} {info}"
                    attr = curses.color_pair(5) if transaction.get('security_issues') else curses.color_pair(0)
                    self.stdscr.addstr(activity_y, mid_x + 2, line[:curses.COLS//2-4], attr)
                    activity_y += 1
            
            # TCP streams
            if streams and activity_y < curses.LINES - 4:
                self.stdscr.addstr(activity_y, mid_x + 2, "TCP Streams:")
                activity_y += 1
                for stream in streams[:2]:
                    if activity_y >= curses.LINES - 5:
                        break
                    time_str = stream.start_time.strftime("%H:%M:%S") if stream.start_time else "N/A"
                    protocol = "HTTP" if stream.is_http else "TCP"
                    line = f"  {time_str} {protocol} {len(stream.packets)}pkts"
                    self.stdscr.addstr(activity_y, mid_x + 2, line[:curses.COLS//2-4])
                    activity_y += 1
        except:
            pass
        
        # Mini gráfico de bandwidth na parte inferior
        try:
            graph_y = curses.LINES - 8
            self.stdscr.addstr(graph_y - 1, 2, "📈 BANDWIDTH TREND", curses.color_pair(1))
            
            # Gráfico compacto
            graph_width = min(50, curses.COLS - 10)
            graph_height = 4
            graph_lines = self.bandwidth_analyzer.get_bandwidth_graph(graph_width, graph_height)
            
            for i, line in enumerate(graph_lines[:graph_height]):
                if graph_y + i >= curses.LINES - 3:
                    break
                attr = curses.color_pair(4) if "█" in line else curses.color_pair(0)
                self.stdscr.addstr(graph_y + i, 2, line[:curses.COLS-4], attr)
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
            filter_win.keypad(True)  # Habilita teclas especiais
            
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
                try:
                    key = filter_win.getch()
                    
                    if key == -1:  # Timeout ou erro
                        continue
                    elif key == 27:  # ESC
                        break
                    elif key == curses.KEY_UP:
                        selected_preset = max(0, selected_preset - 1)
                    elif key == curses.KEY_DOWN:
                        selected_preset = min(len(preset_filters) - 1, selected_preset + 1)
                    elif key == ord('c') or key == ord('C'):
                        # Modo de entrada customizada
                        try:
                            current_filter = self._get_custom_filter_input()
                            if current_filter is not None:
                                self._apply_filter(current_filter)
                                break
                        except Exception:
                            continue
                    elif key == curses.KEY_ENTER or key == 10:
                        # Aplica filtro selecionado
                        try:
                            if selected_preset < len(preset_filters):
                                name, filter_expr = preset_filters[selected_preset]
                                if name == "Host específico" or name == "Rede específica":
                                    # Precisa de input adicional
                                    additional_input = self._get_additional_input(name)
                                    if additional_input:
                                        filter_expr += additional_input
                                self._apply_filter(filter_expr)
                                break
                        except Exception:
                            continue
                    else:
                        # Teclas não mapeadas são ignoradas (não fecha o diálogo)
                        continue
                except Exception:
                    continue
            
        except Exception:
            pass
        finally:
            # Cleanup garantido
            try:
                if 'filter_win' in locals():
                    del filter_win
            except:
                pass
            curses.noecho()
            curses.curs_set(0)
            # Força refresh da tela principal
            self.stdscr.clear()
            self.stdscr.refresh()
    
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