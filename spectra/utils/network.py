# -*- coding: utf-8 -*-
"""
Network utilities for Spectra
"""

import socket
import subprocess
import os
import re
import requests
from urllib.parse import urlparse, urljoin
from ..core.console import console


class _TimeoutSession(requests.Session):
    """Sessão HTTP que aplica timeout padrão em todas as requisições."""

    def __init__(self, default_timeout=10):
        super().__init__()
        self.default_timeout = default_timeout

    def request(self, method, url, **kwargs):
        kwargs.setdefault('timeout', self.default_timeout)
        return super().request(method, url, **kwargs)


def create_session(timeout=10, max_retries=3):
    """
    Cria uma sessão HTTP configurada com headers padrão, retry policy
    e timeout default aplicado a todas as requisições.
    
    Args:
        timeout (int): Timeout em segundos (default em cada request).
        max_retries (int): Número máximo de tentativas.
        
    Returns:
        _TimeoutSession: Sessão HTTP configurada.
    """
    session = _TimeoutSession(default_timeout=timeout)
    
    # Headers padrão
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    })
    
    # Configurações de adapter
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=10,
        pool_maxsize=20,
        max_retries=max_retries
    )
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    
    return session

def is_valid_ip(ip_string):
    """Verifica se uma string é um IP válido."""
    try:
        socket.inet_aton(ip_string)
        return True
    except socket.error:
        return False

def is_valid_domain(domain):
    """Verifica se um domínio é válido."""
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
    return bool(domain_pattern.match(domain))

def resolve_hostname(hostname):
    """Resolve hostname para IP."""
    try:
        ip = socket.gethostbyname(hostname)
        return ip
    except socket.gaierror:
        return None

def normalize_url(url):
    """Normaliza uma URL."""
    if not url:
        return None
    
    # Adiciona esquema se não existir
    if not re.match(r'^https?://', url):
        url = 'http://' + url
    
    # Remove trailing slash
    parsed = urlparse(url)
    if parsed.path == '/':
        url = url.rstrip('/')
    
    return url

def extract_domain(url):
    """Extrai o domínio de uma URL."""
    try:
        parsed = urlparse(url)
        return parsed.netloc
    except:
        return None

def extract_scheme(url):
    """Extrai o esquema de uma URL."""
    try:
        parsed = urlparse(url)
        return parsed.scheme
    except:
        return None

def extract_port(url):
    """Extrai a porta de uma URL."""
    try:
        parsed = urlparse(url)
        if parsed.port:
            return parsed.port
        # Porta padrão baseada no esquema
        return 443 if parsed.scheme == 'https' else 80
    except:
        return None

def ping_host(host, count=1, timeout=1):
    """Executa ping para um host."""
    try:
        # Comando ping baseado no OS
        if os.name == 'nt':  # Windows
            cmd = ['ping', '-n', str(count), '-w', str(timeout * 1000), host]
        else:  # Unix/Linux
            cmd = ['ping', '-c', str(count), '-W', str(timeout), host]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
        return result.returncode == 0
    except:
        return False

def test_port_open(host, port, timeout=1):
    """Testa se uma porta está aberta."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            return result == 0
    except:
        return False

def get_local_ip():
    """Obtém o IP local da máquina."""
    try:
        # Conecta a um endereço externo para descobrir o IP local
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except:
        return "127.0.0.1"

def is_private_ip(ip):
    """Verifica se um IP é privado."""
    try:
        import ipaddress
        return ipaddress.ip_address(ip).is_private
    except:
        # Fallback para verificação manual
        octets = ip.split('.')
        if len(octets) != 4:
            return False
        
        try:
            first = int(octets[0])
            second = int(octets[1])
            
            # Ranges privados
            if first == 10:
                return True
            elif first == 172 and 16 <= second <= 31:
                return True
            elif first == 192 and second == 168:
                return True
            elif first == 127:  # Loopback
                return True
            
            return False
        except:
            return False

def expand_cidr(cidr):
    """Expande notação CIDR em lista de IPs."""
    try:
        import ipaddress
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except:
        return []

def validate_port_range(port_spec):
    """Valida especificação de portas."""
    if not port_spec:
        return False
    
    # Porta única
    if port_spec.isdigit():
        port = int(port_spec)
        return 1 <= port <= 65535
    
    # Range de portas
    if '-' in port_spec:
        try:
            start, end = map(int, port_spec.split('-', 1))
            return 1 <= start <= end <= 65535
        except:
            return False
    
    # Lista de portas
    if ',' in port_spec:
        try:
            ports = [int(p.strip()) for p in port_spec.split(',')]
            return all(1 <= p <= 65535 for p in ports)
        except:
            return False
    
    return False
