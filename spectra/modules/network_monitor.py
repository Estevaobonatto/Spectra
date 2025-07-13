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
    
    def stop_capture(self):
        """Para captura de pacotes"""
        self.is_capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
        logger.info("Captura parada")
    
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
                elif key == ord('f'):  # Filter
                    self._filter_dialog()
                elif key == ord('1'):
                    self.current_view = "packets"
                elif key == ord('2'):
                    self.current_view = "stats"
                elif key == ord('3'):
                    self.current_view = "details"
                elif key == ord('4'):
                    self.current_view = "interfaces"
                elif key == ord('h'):
                    self._toggle_hex_view()
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
        status = f"Interface: {self.interface or 'None'} | "
        status += f"Capturing: {'Yes' if self.is_capturing else 'No'} | "
        status += f"Packets: {len(self.packets)} | "
        status += f"Filter: {self.packet_filter or 'None'}"
        
        self.stdscr.addstr(2, 0, status[:curses.COLS-1])
    
    def _draw_packets_view(self):
        """Desenha visualização de pacotes"""
        start_y = 4
        height = curses.LINES - 6
        
        # Headers
        headers = f"{'Time':<12} {'Source':<15} {'Destination':<15} {'Protocol':<8} {'Info':<20}"
        self.stdscr.addstr(start_y, 0, headers[:curses.COLS-1], curses.color_pair(1))
        
        # Packets
        for i, packet in enumerate(self.packets[self.scroll_offset:self.scroll_offset + height - 1]):
            y = start_y + 1 + i
            if y >= curses.LINES - 2:
                break
                
            time_str = packet.timestamp.strftime("%H:%M:%S.%f")[:-3]
            line = f"{time_str:<12} {packet.src_ip:<15} {packet.dst_ip:<15} {packet.protocol:<8} {packet.info:<20}"
            
            # Color based on protocol
            color = curses.color_pair(0)
            if packet.protocol == "TCP":
                color = curses.color_pair(3)
            elif packet.protocol == "UDP":
                color = curses.color_pair(4)
            elif packet.protocol == "ICMP":
                color = curses.color_pair(5)
            
            # Highlight selected
            if i + self.scroll_offset == self.selected_packet:
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
            if start_y + i >= curses.LINES - 2:
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
            if start_y + i >= curses.LINES - 2:
                break
            try:
                self.stdscr.addstr(start_y + i, 0, line[:curses.COLS-1])
            except:
                pass
    
    def _draw_footer(self):
        """Desenha rodapé com comandos"""
        if self.search_mode:
            footer = f"Search: {self.search_term}_ (Enter to search, Esc to cancel)"
        else:
            footer = "[s]tart/stop [c]lear [e]xport [f]ilter [/]search [h]ex [1]packets [2]stats [3]details [4]interfaces [q]uit"
        try:
            self.stdscr.addstr(curses.LINES - 1, 0, footer[:curses.COLS-1], curses.color_pair(1))
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
        """Scroll para cima"""
        if self.current_view == "packets":
            if self.selected_packet > 0:
                self.selected_packet -= 1
                if self.selected_packet < self.scroll_offset:
                    self.scroll_offset = self.selected_packet
    
    def _scroll_down(self):
        """Scroll para baixo"""
        if self.current_view == "packets":
            if self.selected_packet < len(self.packets) - 1:
                self.selected_packet += 1
                visible_height = curses.LINES - 6
                if self.selected_packet >= self.scroll_offset + visible_height:
                    self.scroll_offset = self.selected_packet - visible_height + 1
    
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
        
        # Cabeçalho
        header = "Interfaces de Rede Disponíveis"
        try:
            self.stdscr.addstr(start_y, 0, header, curses.color_pair(1))
        except:
            pass
        
        # Lista interfaces
        for i, interface in enumerate(interfaces):
            y = start_y + 2 + i
            if y >= curses.LINES - 2:
                break
            
            # Verifica se é a interface atual
            status = "[ATIVA]" if interface == self.interface else "[INATIVA]"
            line = f"  {interface:<15} {status}"
            
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
            if y >= curses.LINES - 2:
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
        for i, line in enumerate(hex_lines[:curses.LINES - 8]):
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
        visible_height = curses.LINES - 6
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
        """Página para cima"""
        visible_height = curses.LINES - 6
        if self.current_view == "packets":
            self.selected_packet = max(0, self.selected_packet - visible_height)
            self.scroll_offset = max(0, self.scroll_offset - visible_height)
        elif self.current_view == "interfaces":
            self.selected_interface = max(0, self.selected_interface - visible_height)
    
    def _page_down(self):
        """Página para baixo"""
        visible_height = curses.LINES - 6
        if self.current_view == "packets":
            self.selected_packet = min(len(self.packets) - 1, self.selected_packet + visible_height)
            max_scroll = max(0, len(self.packets) - visible_height)
            self.scroll_offset = min(max_scroll, self.scroll_offset + visible_height)
        elif self.current_view == "interfaces":
            interfaces = self.get_available_interfaces()
            self.selected_interface = min(len(interfaces) - 1, self.selected_interface + visible_height)
    
    def _go_to_top(self):
        """Vai para o topo"""
        if self.current_view == "packets":
            self.selected_packet = 0
            self.scroll_offset = 0
        elif self.current_view == "interfaces":
            self.selected_interface = 0
    
    def _go_to_bottom(self):
        """Vai para o final"""
        if self.current_view == "packets" and self.packets:
            self.selected_packet = len(self.packets) - 1
            visible_height = curses.LINES - 6
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
    
    def _filter_dialog(self):
        """Dialog interativo para definir filtros"""
        # Cria uma pequena janela para input de filtro
        filter_win_height = 5
        filter_win_width = 60
        start_y = (curses.LINES - filter_win_height) // 2
        start_x = (curses.COLS - filter_win_width) // 2
        
        try:
            # Cria janela de filtro
            filter_win = curses.newwin(filter_win_height, filter_win_width, start_y, start_x)
            filter_win.box()
            
            # Título
            filter_win.addstr(1, 2, "Filtro de Captura (sintaxe BPF):", curses.color_pair(1))
            filter_win.addstr(2, 2, "Atual: " + (self.packet_filter or "(nenhum)"))
            filter_win.addstr(3, 2, "Novo: ")
            
            filter_win.refresh()
            
            # Input do usuário
            curses.echo()
            curses.curs_set(1)
            
            new_filter = filter_win.getstr(3, 8, 40).decode('utf-8')
            
            curses.noecho()
            curses.curs_set(0)
            
            # Aplica o filtro
            if new_filter != self.packet_filter:
                old_capturing = self.is_capturing
                if old_capturing:
                    self.stop_capture()
                
                self.packet_filter = new_filter
                
                if old_capturing and self.interface:
                    self.start_capture(self.interface, self.packet_filter)
            
            del filter_win
            
        except Exception:
            curses.noecho()
            curses.curs_set(0)
            pass
    
    def _run_simple_interface(self):
        """Interface simples sem curses"""
        console.print("\n[bold cyan]Spectra Network Monitor[/bold cyan]")
        console.print("Interface simples (curses não disponível)")
        
        interfaces = self.get_available_interfaces()
        console.print(f"\nInterfaces disponíveis: {', '.join(interfaces)}")
        
        if not interfaces:
            console.print("[red]Nenhuma interface encontrada[/red]")
            return
        
        # Usa primeira interface disponível
        interface = interfaces[0]
        console.print(f"Usando interface: {interface}")
        
        try:
            self.start_capture(interface)
            console.print("Captura iniciada. Pressione Ctrl+C para parar.")
            
            while self.is_capturing:
                time.sleep(1)
                if len(self.packets) > 0:
                    last_packet = self.packets[-1]
                    console.print(f"[{last_packet.timestamp.strftime('%H:%M:%S')}] "
                                f"{last_packet.src_ip} -> {last_packet.dst_ip} "
                                f"({last_packet.protocol}) {last_packet.info}")
                
        except KeyboardInterrupt:
            console.print("\nParando captura...")
            self.stop_capture()
            
            if self.packets:
                console.print(f"\nCapturados {len(self.packets)} pacotes")
                
                # Exporta automaticamente
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"network_capture_{timestamp}.json"
                self.export_packets(filename)
                console.print(f"Pacotes exportados para {filename}")

def network_monitor_interface():
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
    monitor.run_tui()

if __name__ == "__main__":
    network_monitor_interface()