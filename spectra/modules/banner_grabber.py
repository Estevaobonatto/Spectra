"""
Módulo para captura de banners de serviços de rede.
"""
import socket
import ssl
import concurrent.futures
from typing import Dict, List, Optional, Tuple

from ..core.console import console
from ..core.logger import get_logger


# Probes específicos por porta (enviados antes de aguardar resposta)
PROTOCOL_PROBES: Dict[int, bytes] = {
    21:   b'',                         # FTP — aguarda banner passivo
    22:   b'',                         # SSH — banner enviado pelo servidor
    23:   b'\xff\xfd\x18',             # Telnet — DO TERMINAL-TYPE
    25:   b'EHLO spectra-probe\r\n',   # SMTP
    53:   (                            # DNS version.bind query (UDP-like via TCP)
        b'\x00\x1d\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        b'\x07version\x04bind\x00\x00\x10\x00\x03'
    ),
    79:   b'\r\n',                     # Finger
    80:   b'HEAD / HTTP/1.0\r\nHost: probe\r\n\r\n',  # HTTP
    110:  b'',                         # POP3 — banner passivo
    111:  b'\x00\x00\x00\x28\x72\xfe\x1d\x13\x00\x00\x00\x00\x00\x00\x00\x02',  # RPC portmapper
    119:  b'',                         # NNTP
    143:  b'',                         # IMAP — banner passivo
    443:  b'HEAD / HTTP/1.0\r\nHost: probe\r\n\r\n',  # HTTPS (TLS handled separately)
    445:  b'\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00',  # SMB negotiate
    465:  b'EHLO spectra-probe\r\n',   # SMTPS
    587:  b'EHLO spectra-probe\r\n',   # SMTP Submission
    993:  b'',                         # IMAPS
    995:  b'',                         # POP3S
    1433: b'',                         # MSSQL
    1521: b'',                         # Oracle
    3306: b'',                         # MySQL — banner passivo
    3389: b'\x03\x00\x00\x0b\x06\xe0\x00\x00\x00\x00\x00',  # RDP TPKT
    5432: b'',                         # PostgreSQL
    5900: b'',                         # VNC
    6379: b'*1\r\n$4\r\nPING\r\n',    # Redis RESP
    8080: b'HEAD / HTTP/1.0\r\nHost: probe\r\n\r\n',  # HTTP-alt
    8443: b'HEAD / HTTP/1.0\r\nHost: probe\r\n\r\n',  # HTTPS-alt
    9200: b'GET / HTTP/1.0\r\nHost: probe\r\n\r\n',   # Elasticsearch
    11211: b'version\r\n',            # Memcached
    27017: b'\x48\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00'
           b'\x00\x00\x00\x00\x00',   # MongoDB isMaster (wire protocol)
}

# Portas que usam TLS nativo
TLS_PORTS = {443, 465, 636, 993, 995, 8443, 8883}


class BannerGrabber:
    """Classe para capturar banners de serviços de rede com suporte a probes por protocolo."""

    def __init__(self, timeout: int = 4):
        """
        Inicializa o grabber de banners.

        Args:
            timeout: Timeout em segundos para conexões.
        """
        self.timeout = timeout
        self.logger = get_logger(__name__)

    # ------------------------------------------------------------------
    # Core grab — single port
    # ------------------------------------------------------------------

    def grab_banner(self, host: str, port: int) -> Optional[str]:
        """Conecta a uma porta e captura o banner do serviço.

        Envia um probe protocolar quando disponível. Usa TLS para portas
        bem-conhecidas de SSL. Retorna None se falhar ou banner vazio.

        Args:
            host: Host alvo.
            port: Porta alvo.

        Returns:
            Banner como string, ou None.
        """
        console.print("-" * 60)
        console.print(f"[*] Capturando banner de [bold cyan]{host}:{port}[/bold cyan]")
        console.print("-" * 60)

        banner = self._grab(host, port)

        if banner:
            console.print(f"[bold green][+] Banner da porta {port}:[/bold green]")
            console.print(banner)
        else:
            console.print(f"[bold yellow][-] Porta {port}: Banner vazio ou não recebido.[/bold yellow]")

        console.print("-" * 60)
        return banner

    def _grab(self, host: str, port: int) -> Optional[str]:
        """Implementação interna de captura de banner (sem output)."""
        probe = PROTOCOL_PROBES.get(port, b'')
        use_tls = port in TLS_PORTS

        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.settimeout(self.timeout)
            raw_sock.connect((host, port))

            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(raw_sock, server_hostname=host)
            else:
                sock = raw_sock

            with sock:
                if probe:
                    sock.sendall(probe)
                try:
                    data = sock.recv(4096)
                    return data.decode('utf-8', errors='replace').strip() or None
                except socket.timeout:
                    return None
        except Exception as exc:
            self.logger.debug(f"grab_banner {host}:{port} → {exc}")
            return None

    # ------------------------------------------------------------------
    # Multi-host ThreadPoolExecutor variant
    # ------------------------------------------------------------------

    def grab_multiple_banners(
        self,
        host: str,
        ports: List[int],
        max_workers: int = 20,
    ) -> Dict[int, str]:
        """Captura banners de múltiplas portas em paralelo.

        Args:
            host: Host alvo.
            ports: Lista de portas para sondar.
            max_workers: Máximo de threads paralelas (padrão 20).

        Returns:
            Dict mapeando porta → banner (apenas portas com resposta).
        """
        results: Dict[int, str] = {}

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            future_to_port = {pool.submit(self._grab, host, p): p for p in ports}
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    banner = future.result()
                    if banner:
                        results[port] = banner
                except Exception as exc:
                    self.logger.debug(f"grab worker {host}:{port} → {exc}")

        return results

    def grab_multiple_hosts(
        self,
        hosts_ports: List[Tuple[str, int]],
        max_workers: int = 20,
    ) -> Dict[str, Dict[int, str]]:
        """Captura banners de múltiplos hosts e portas em paralelo.

        Args:
            hosts_ports: Lista de tuplas (host, port).
            max_workers: Máximo de threads paralelas.

        Returns:
            Dict aninhado: host → {port: banner}.
        """
        results: Dict[str, Dict[int, str]] = {}

        def _task(hp: Tuple[str, int]) -> Tuple[str, int, Optional[str]]:
            h, p = hp
            return h, p, self._grab(h, p)

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            for host, port, banner in pool.map(_task, hosts_ports):
                if banner:
                    results.setdefault(host, {})[port] = banner

        return results

