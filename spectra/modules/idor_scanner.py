# -*- coding: utf-8 -*-
"""
IDOR (Insecure Direct Object Reference) Scanner Module
Módulo para detecção de vulnerabilidades IDOR com múltiplas técnicas de enumeração.
"""

import requests
import re
import time
import uuid
import hashlib
import json
import base64
import random
import string
import html
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
from difflib import SequenceMatcher
import threading
from collections import defaultdict, deque
from functools import lru_cache
from typing import List, Dict, Tuple, Optional, Set, Any, Union
from dataclasses import dataclass, field
from enum import Enum
import secrets
import itertools
from datetime import datetime
import socket
from urllib.robotparser import RobotFileParser

from rich.table import Table

from ..core import console, print_info, print_error, print_warning, print_success
from ..core.console import create_progress
from ..core.logger import get_logger
from ..utils.network import create_session


class DevelopmentWarningManager:
    """Gerencia avisos sobre status de desenvolvimento do módulo IDOR."""
    
    @staticmethod
    def show_development_warning(verbose: bool = False):
        """Exibe aviso de desenvolvimento com detalhes baseados no modo verbose."""
        console.print("\n" + "⚠️ " * 20)
        console.print("[bold yellow]AVISO: MÓDULO EM DESENVOLVIMENTO[/bold yellow]")
        console.print("⚠️ " * 20)
        
        console.print("\n[yellow]O Scanner IDOR está em desenvolvimento ativo e pode apresentar:[/yellow]")
        console.print("  • [red]Falsos positivos[/red] - Vulnerabilidades reportadas incorretamente")
        console.print("  • [red]Falsos negativos[/red] - Vulnerabilidades não detectadas")
        console.print("  • [yellow]Instabilidade[/yellow] - Comportamento inconsistente em alguns cenários")
        
        console.print("\n[cyan]RECOMENDAÇÕES IMPORTANTES:[/cyan]")
        console.print("  ✓ [green]Sempre valide manualmente[/green] os resultados encontrados")
        console.print("  ✓ [green]Use em ambiente de teste[/green] antes de produção")
        console.print("  ✓ [green]Reporte bugs e problemas[/green] para melhorar o módulo")
        
        if verbose:
            console.print("\n[dim]DETALHES TÉCNICOS (Modo Verbose):[/dim]")
            console.print("  • [dim]Análise de resposta pode ser imprecisa em alguns casos[/dim]")
            console.print("  • [dim]Detecção de dados sensíveis usa padrões heurísticos[/dim]")
            console.print("  • [dim]Rate limiting pode não ser ideal para todos os targets[/dim]")
            console.print("  • [dim]Classificação de severidade é baseada em indicadores simples[/dim]")
        
        console.print("\n[green]Continue apenas se você entende essas limitações.[/green]")
        console.print("=" * 60 + "\n")
    
    @staticmethod
    def show_post_scan_recommendations():
        """Mostra recomendações após o scan."""
        console.print("\n[cyan]📋 PRÓXIMOS PASSOS RECOMENDADOS:[/cyan]")
        console.print("  1. [yellow]Valide manualmente[/yellow] cada vulnerabilidade encontrada")
        console.print("  2. [yellow]Teste os payloads[/yellow] em ambiente controlado")
        console.print("  3. [yellow]Documente os achados[/yellow] com evidências adicionais")
        console.print("  4. [yellow]Considere usar outras ferramentas[/yellow] para confirmação")
        console.print("  5. [yellow]Reporte falsos positivos[/yellow] para melhorar o scanner")
        console.print("")


class Severity(Enum):
    """Enum para níveis de severidade."""
    CRITICAL = "CRÍTICA"
    HIGH = "ALTA"
    MEDIUM = "MÉDIA"
    LOW = "BAIXA"
    INFO = "INFO"


class IDORTechnique(Enum):
    """Técnicas de teste IDOR."""
    SEQUENTIAL = "sequential"
    PREDICTABLE = "predictable"
    ENCODED = "encoded"
    HASH_BASED = "hash_based"
    UUID_BASED = "uuid_based"
    TIMESTAMP = "timestamp"
    MIXED = "mixed"
    BRUTEFORCE = "bruteforce"
    PERMUTATION = "permutation"
    LOGIC_FLAW = "logic_flaw"


@dataclass
class VulnerabilityInfo:
    """Classe para armazenar informações de vulnerabilidade."""
    url: str
    method: str
    technique: IDORTechnique = IDORTechnique.SEQUENTIAL
    parameter: Optional[str] = None
    path_position: Optional[int] = None
    header_name: Optional[str] = None
    cookie_name: Optional[str] = None
    original_value: str = ""
    test_value: str = ""
    id_type: str = "numeric"
    status_code: int = 0
    response_size: int = 0
    response_time: float = 0.0
    indicators: List[str] = field(default_factory=list)
    severity: Severity = Severity.LOW
    confidence: float = 0.0
    false_positive_score: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)
    request_headers: Dict[str, str] = field(default_factory=dict)
    response_headers: Dict[str, str] = field(default_factory=dict)
    sensitive_data: List[str] = field(default_factory=list)
    bypass_technique: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte para dicionário para exportação."""
        return {
            'url': self.url,
            'method': self.method,
            'technique': self.technique.value,
            'parameter': self.parameter,
            'path_position': self.path_position,
            'header_name': self.header_name,
            'cookie_name': self.cookie_name,
            'original_value': self.original_value,
            'test_value': self.test_value,
            'id_type': self.id_type,
            'status_code': self.status_code,
            'response_size': self.response_size,
            'response_time': self.response_time,
            'indicators': self.indicators,
            'severity': self.severity.value,
            'confidence': self.confidence,
            'false_positive_score': self.false_positive_score,
            'timestamp': self.timestamp.isoformat(),
            'request_headers': self.request_headers,
            'response_headers': dict(self.response_headers),
            'sensitive_data': self.sensitive_data,
            'bypass_technique': self.bypass_technique
        }


class AdvancedRateLimiter:
    """Controla rate limiting com backoff exponencial."""
    
    def __init__(self, initial_delay: float = 0.1, max_delay: float = 30.0, 
                 backoff_factor: float = 2.0, jitter: bool = True):
        self.initial_delay = initial_delay
        self.max_delay = max_delay
        self.backoff_factor = backoff_factor
        self.jitter = jitter
        self.current_delay = initial_delay
        self.last_request_time = 0
        self.consecutive_errors = 0
        self.consecutive_429s = 0
        self.adaptive_delays = deque(maxlen=10)
        self._lock = threading.Lock()
        self.blocked_until = 0
    
    def wait(self):
        """Aguarda o tempo necessário antes da próxima requisição."""
        with self._lock:
            current_time = time.time()
            
            # Verifica se ainda está bloqueado
            if current_time < self.blocked_until:
                time.sleep(self.blocked_until - current_time)
                current_time = time.time()
            
            elapsed = current_time - self.last_request_time
            delay = self.current_delay
            
            # Adiciona jitter para evitar sincronização
            if self.jitter:
                delay *= (0.5 + random.random() * 0.5)
            
            if elapsed < delay:
                time.sleep(delay - elapsed)
            
            self.last_request_time = time.time()
    
    def on_error(self, status_code: int = None):
        """Ajusta delay baseado no tipo de erro."""
        with self._lock:
            self.consecutive_errors += 1
            
            if status_code == 429:  # Too Many Requests
                self.consecutive_429s += 1
                # Aumenta drasticamente o delay para 429
                self.current_delay = min(
                    self.initial_delay * (3 ** self.consecutive_429s),
                    self.max_delay
                )
                # Bloqueia por tempo adicional
                self.blocked_until = time.time() + self.current_delay
            elif status_code in [503, 502, 504]:  # Server errors
                self.current_delay = min(
                    self.initial_delay * (self.backoff_factor ** self.consecutive_errors),
                    self.max_delay
                )
            else:
                self.current_delay = min(
                    self.current_delay * self.backoff_factor,
                    self.max_delay
                )
    
    def on_success(self, response_time: float = None):
        """Ajusta delay baseado no sucesso e tempo de resposta."""
        with self._lock:
            self.consecutive_errors = 0
            self.consecutive_429s = 0
            
            if response_time:
                self.adaptive_delays.append(response_time)
                avg_response_time = sum(self.adaptive_delays) / len(self.adaptive_delays)
                
                # Ajusta delay baseado no tempo de resposta médio
                if avg_response_time > 2.0:  # Resposta lenta
                    self.current_delay = max(self.initial_delay * 2, self.current_delay)
                elif avg_response_time < 0.5:  # Resposta rápida
                    self.current_delay = max(self.initial_delay, self.current_delay * 0.9)
                else:
                    self.current_delay = max(self.initial_delay, self.current_delay * 0.95)
    
    def get_current_delay(self) -> float:
        """Retorna o delay atual."""
        with self._lock:
            return self.current_delay


class ResponseCache:
    """Cache LRU para respostas HTTP com métricas."""
    
    def __init__(self, max_size: int = 1000):
        self.cache = {}
        self.access_order = deque()
        self.max_size = max_size
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0
    
    def get(self, key: str) -> Optional[Dict[str, Any]]:
        """Recupera uma resposta do cache."""
        with self._lock:
            if key in self.cache:
                self.access_order.remove(key)
                self.access_order.append(key)
                self.hits += 1
                return self.cache[key]
            self.misses += 1
        return None
    
    def put(self, key: str, response_data: Dict[str, Any]):
        """Armazena dados de resposta no cache."""
        with self._lock:
            if key in self.cache:
                self.access_order.remove(key)
            elif len(self.cache) >= self.max_size:
                oldest = self.access_order.popleft()
                del self.cache[oldest]
            
            self.cache[key] = response_data
            self.access_order.append(key)
    
    def clear(self):
        """Limpa o cache."""
        with self._lock:
            self.cache.clear()
            self.access_order.clear()
            self.hits = 0
            self.misses = 0
    
    def get_hit_rate(self) -> float:
        """Retorna a taxa de acerto do cache."""
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0


class SessionManager:
    """Gerenciador de sessões para testes autenticados."""
    
    def __init__(self, session: requests.Session):
        self.session = session
        self.auth_headers = {}
        self.auth_cookies = {}
        self.csrf_token = None
        self.jwt_token = None
        self.session_id = None
        self.auth_type = None
        self.user_context = {}
        
    def extract_auth_info(self, response: requests.Response, url: str):
        """Extrai informações de autenticação da resposta."""
        content = response.text
        
        # Extrai tokens CSRF - padrões simples
        csrf_match = re.search(r'<input[^>]*name=["\']?_token["\']?[^>]*value=["\']?([^">]+)', content, re.IGNORECASE)
        if csrf_match:
            self.csrf_token = csrf_match.group(1)
        else:
            csrf_match = re.search(r'<meta[^>]*name=["\']?csrf-token["\']?[^>]*content=["\']?([^">]+)', content, re.IGNORECASE)
            if csrf_match:
                self.csrf_token = csrf_match.group(1)
        
        # Extrai JWT tokens
        jwt_match = re.search(r'["\']?token["\']?\s*:\s*["\']([A-Za-z0-9-_.]+)', content, re.IGNORECASE)
        if jwt_match:
            token_value = jwt_match.group(1)
            if token_value.count('.') == 2:  # JWT tem 3 partes separadas por pontos
                self.jwt_token = token_value
                self.auth_headers['Authorization'] = f'Bearer {self.jwt_token}'
        
        # Extrai session IDs
        for cookie in response.cookies:
            if 'session' in cookie.name.lower() or 'sess' in cookie.name.lower():
                self.session_id = cookie.value
                self.auth_cookies[cookie.name] = cookie.value
        
        # Detecta tipo de autenticação
        if self.jwt_token:
            self.auth_type = 'jwt'
        elif self.session_id:
            self.auth_type = 'session'
        elif self.csrf_token:
            self.auth_type = 'csrf'
        
        # Extrai informações do usuário - padrões simples
        user_id_match = re.search(r'["\']?user_id["\']?\s*:\s*["\']?([^",}]+)', content, re.IGNORECASE)
        if user_id_match:
            self.user_context['user_id'] = user_id_match.group(1)
        
        username_match = re.search(r'["\']?username["\']?\s*:\s*["\']([^",}]+)', content, re.IGNORECASE)
        if username_match:
            self.user_context['username'] = username_match.group(1)
        
        email_match = re.search(r'["\']?email["\']?\s*:\s*["\']([^",}]+)', content, re.IGNORECASE)
        if email_match:
            self.user_context['email'] = email_match.group(1)
    
    def get_auth_headers(self) -> Dict[str, str]:
        """Retorna headers de autenticação."""
        headers = self.auth_headers.copy()
        if self.csrf_token:
            headers['X-CSRF-Token'] = self.csrf_token
            headers['X-Requested-With'] = 'XMLHttpRequest'
        return headers
    
    def get_auth_cookies(self) -> Dict[str, str]:
        """Retorna cookies de autenticação."""
        return self.auth_cookies.copy()
    
    def is_authenticated(self) -> bool:
        """Verifica se há autenticação ativa."""
        return bool(self.auth_type and (self.jwt_token or self.session_id or self.csrf_token))


class ResponseAnalyzer:
    """Analisador avançado de respostas HTTP."""
    
    def __init__(self):
        self.baseline_responses = {}
        self.common_false_positives = [
            'error', 'not found', '404', 'access denied', 'forbidden',
            'unauthorized', 'invalid', 'expired', 'maintenance'
        ]
        
    def analyze_response_similarity(self, response1: requests.Response, 
                                  response2: requests.Response) -> float:
        """Calcula similaridade entre duas respostas."""
        if not response1 or not response2:
            return 0.0
        
        # Similaridade de status code
        status_similarity = 1.0 if response1.status_code == response2.status_code else 0.0
        
        # Similaridade de tamanho
        size1, size2 = len(response1.content), len(response2.content)
        size_similarity = 1.0 - abs(size1 - size2) / max(size1, size2, 1)
        
        # Similaridade de conteúdo
        content_similarity = SequenceMatcher(None, response1.text, response2.text).ratio()
        
        # Similaridade de headers
        headers1 = set(response1.headers.keys())
        headers2 = set(response2.headers.keys())
        header_similarity = len(headers1 & headers2) / len(headers1 | headers2) if headers1 | headers2 else 1.0
        
        # Média ponderada
        return (status_similarity * 0.3 + size_similarity * 0.2 + 
                content_similarity * 0.4 + header_similarity * 0.1)
    
    def detect_sensitive_data(self, response: requests.Response) -> List[str]:
        """Detecta dados sensíveis em respostas."""
        sensitive_data = []
        content = response.text.lower()
        
        # Padrões de dados sensíveis mais precisos
        patterns = {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'phone': r'\b(?:\+?1[-. ]?)?\(?[0-9]{3}\)?[-. ]?[0-9]{3}[-. ]?[0-9]{4}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'credit_card': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
            'api_key': r'\b[A-Za-z0-9]{32,}\b',
            'password_hash': r'\$[0-9a-z]+\$[0-9]+\$[A-Za-z0-9./]{22,}',
            'ip_address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'private_key': r'-----BEGIN (?:RSA )?PRIVATE KEY-----',
            'jwt_token': r'\beyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b',
            'session_token': r'\b[A-Fa-f0-9]{32,}\b',
            'guid': r'\b[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}\b'
        }
        
        for data_type, pattern in patterns.items():
            matches = re.findall(pattern, response.text, re.IGNORECASE)
            if matches:
                sensitive_data.extend([f"{data_type}: {match[:20]}..." for match in matches[:3]])
        
        return sensitive_data
    
    def calculate_false_positive_score(self, response: requests.Response, 
                                     indicators: List[str]) -> float:
        """Calcula probabilidade de falso positivo."""
        score = 0.0
        content = response.text.lower()
        
        # Verifica padrões de falso positivo
        for fp_pattern in self.common_false_positives:
            if fp_pattern in content:
                score += 0.2
        
        # Verifica se é uma página de erro genérica
        if response.status_code in [404, 403, 500] and len(response.content) < 1000:
            score += 0.3
        
        # Verifica se o conteúdo é muito similar ao baseline
        if hasattr(self, 'baseline_content') and self.baseline_content:
            similarity = SequenceMatcher(None, content, self.baseline_content.lower()).ratio()
            if similarity > 0.8:
                score += 0.4
        
        # Verifica indicadores fracos
        weak_indicators = ['acesso bem-sucedido', 'status 200']
        weak_count = sum(1 for indicator in indicators if any(weak in indicator.lower() for weak in weak_indicators))
        score += weak_count * 0.1
        
        return min(score, 1.0)


class AdvancedIDORScanner:
    """Scanner avançado para detecção de vulnerabilidades IDOR."""

    def __init__(self, base_url: str, enumerate_range: Optional[Tuple[int, int]] = None, 
                 test_uuid: bool = True, test_hash: bool = True, 
                 custom_wordlist: Optional[str] = None, max_workers: int = 10, 
                 delay: float = 0.1, session_cookies: Optional[Dict[str, str]] = None,
                 auth_headers: Optional[Dict[str, str]] = None, 
                 respect_robots: bool = True, deep_scan: bool = False, verbose: bool = False):
        self.base_url = self._validate_url(base_url)
        self.session = create_session()
        self.vulnerable_endpoints = []
        self.enumerate_range = enumerate_range or (1, 1000)
        self.test_uuid = test_uuid
        self.test_hash = test_hash
        self.custom_wordlist = custom_wordlist
        self.max_workers = max_workers
        self.delay = delay
        self.respect_robots = respect_robots
        self.deep_scan = deep_scan
        self.verbose = verbose
        
        # Otimizações de performance
        import os
        self.max_workers = min(max_workers, os.cpu_count() * 2, 50)  # Limita workers baseado no sistema
        
        # Configurações avançadas
        self.test_negative_ids = True
        self.test_large_ids = True
        self.test_string_ids = True
        self.test_encoded_ids = True
        self.test_timestamp_ids = True
        self.test_predictable_ids = True
        self.test_logic_flaws = True
        self.test_header_injection = True
        self.test_cookie_manipulation = True
        self.test_http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
        self.test_parameter_variations = True
        self.test_bypass_techniques = True
        
        # Componentes avançados
        self.rate_limiter = AdvancedRateLimiter(initial_delay=delay)
        self.response_cache = ResponseCache()
        self.session_manager = SessionManager(self.session)
        self.response_analyzer = ResponseAnalyzer()
        
        # Thread safety
        self.results_lock = threading.Lock()
        self.stats_lock = threading.Lock()
        
        # Estatísticas expandidas
        self.stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'unauthorized_responses': 0,
            'forbidden_responses': 0,
            'not_found_responses': 0,
            'rate_limited_responses': 0,
            'server_error_responses': 0,
            'different_responses': 0,
            'potential_vulns': 0,
            'confirmed_vulns': 0,
            'false_positives': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'scan_start_time': time.time(),
            'techniques_used': set(),
            'sensitive_data_found': 0,
            'bypasses_successful': 0
        }
        
        # Cache de respostas para análise de padrões
        self.baseline_responses = {}
        self.access_patterns = defaultdict(list)
        self.fingerprints = {}
        
        # Cache manual para IDs (mais controlado que @lru_cache)
        self._cached_test_ids = None
        
        # Configuração de sessão
        if session_cookies:
            self.session.cookies.update(session_cookies)
            self.session_manager.auth_cookies.update(session_cookies)
        
        if auth_headers:
            self.session.headers.update(auth_headers)
            self.session_manager.auth_headers.update(auth_headers)
        
        # Verifica robots.txt
        if self.respect_robots:
            self._check_robots_txt()
        
        self.logger = get_logger(__name__)
    
    def _check_robots_txt(self):
        """Verifica robots.txt para restrições."""
        try:
            parsed_url = urlparse(self.base_url)
            robots_url = f"{parsed_url.scheme}://{parsed_url.netloc}/robots.txt"
            
            rp = RobotFileParser()
            rp.set_url(robots_url)
            rp.read()
            
            if not rp.can_fetch('*', self.base_url):
                print_warning(f"robots.txt desencoraja o acesso a {self.base_url}")
                if not self.deep_scan:
                    print_info("Use --deep-scan para ignorar robots.txt")
        except Exception as e:
            self.logger.debug(f"Erro ao verificar robots.txt: {e}")

    def _validate_url(self, url: str) -> str:
        """Valida e sanitiza a URL de entrada com verificações robustas."""
        if not url or not isinstance(url, str):
            raise ValueError("URL deve ser uma string não vazia")
        
        # Remove espaços e caracteres de controle
        url = url.strip()
        
        # Verifica comprimento mínimo
        if len(url) < 10:
            raise ValueError("URL muito curta para ser válida")
        
        # Verifica se é uma URL válida
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError("URL inválida: deve conter scheme e netloc")
            
            # Verifica schemes permitidos
            if parsed.scheme not in ['http', 'https']:
                raise ValueError("Apenas URLs HTTP/HTTPS são permitidas")
            
            # Verifica se o netloc não contém caracteres suspeitos
            if any(char in parsed.netloc for char in ['<', '>', '"', "'"]):
                raise ValueError("URL contém caracteres suspeitos no domínio")
            
            # Verifica se não é um IP privado (opcional, para segurança)
            try:
                import ipaddress
                # Extrai IP se for um endereço IP direto
                hostname = parsed.netloc.split(':')[0]
                if hostname.replace('.', '').isdigit():
                    ip = ipaddress.ip_address(hostname)
                    if ip.is_private and not self.deep_scan:
                        print_warning(f"Detectado IP privado: {ip}. Use --deep-scan para continuar")
            except (ValueError, ipaddress.AddressValueError):
                pass  # Não é um IP, continua normalmente
            
            return url
        except Exception as e:
            raise ValueError(f"URL inválida: {e}")

    def _generate_test_ids(self) -> List[str]:
        """Gera lista de IDs para teste baseado nas configurações."""
        # Verifica cache manual para garantir consistência
        if self._cached_test_ids is not None:
            return self._cached_test_ids
        
        test_ids = set()  # Usa set para evitar duplicatas automaticamente
        
        # IDs sequenciais no range especificado
        start, end = self.enumerate_range
        
        # Validação de range
        if start < 0:
            print_warning("Range inicial negativo, ajustando para 1")
            start = 1
        
        if end <= start:
            print_warning("Range final deve ser maior que inicial, ajustando")
            end = start + 100
        
        if end - start > 10000:  # Limite para evitar overhead
            print_warning(f"Range muito grande ({end - start} IDs), limitando a 10000")
            end = start + 10000
        
        test_ids.update(str(i) for i in range(start, min(end + 1, start + 10001)))
        
        # IDs negativos
        if self.test_negative_ids:
            test_ids.update(['-1', '-10', '-100'])
        
        # IDs grandes
        if self.test_large_ids:
            test_ids.update(['999999', '1000000', '2147483647', '9999999999'])
        
        # IDs string comuns
        if self.test_string_ids:
            string_ids = [
                'admin', 'administrator', 'root', 'test', 'demo', 'guest',
                'user', 'default', 'null', 'undefined', '0', 'false', 'true'
            ]
            test_ids.update(string_ids)
        
        # UUIDs se habilitado
        if self.test_uuid:
            # UUIDs comuns/previsíveis (apenas determinísticos)
            uuid_tests = [
                '00000000-0000-0000-0000-000000000000',
                '11111111-1111-1111-1111-111111111111',
                'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
                '12345678-1234-5678-9012-123456789012',  # UUID fixo para teste
                'ffffffff-ffff-ffff-ffff-ffffffffffff',  # UUID com todos F's
            ]
            test_ids.update(uuid_tests)
        
        # Hashes se habilitado
        if self.test_hash:
            hash_tests = [
                hashlib.md5(b'1').hexdigest(),
                hashlib.md5(b'admin').hexdigest(),
                hashlib.sha1(b'1').hexdigest(),
                hashlib.sha256(b'1').hexdigest()[:8],  # Hash truncado
            ]
            test_ids.update(hash_tests)
        
        # IDs codificados
        if self.test_encoded_ids:
            import base64
            encoded_ids = []
            for i in [1, 2, 100]:
                # Base64
                encoded_ids.append(base64.b64encode(str(i).encode()).decode())
                # URL encoding
                encoded_ids.append(f"%{ord(str(i)[0]):02x}")
            test_ids.update(encoded_ids)
        
        # Wordlist customizada
        if self.custom_wordlist:
            try:
                with open(self.custom_wordlist, 'r', encoding='utf-8') as f:
                    custom_ids = [line.strip() for line in f if line.strip()]
                    test_ids.update(custom_ids[:1000])  # Limite de 1000 IDs
                    if self.verbose:
                        print_info(f"Carregados {len(custom_ids[:1000])} IDs da wordlist customizada")
            except Exception as e:
                print_warning(f"Erro ao carregar wordlist: {e}")
        
        # Cache o resultado para garantir consistência
        self._cached_test_ids = list(test_ids)
        return self._cached_test_ids
    
    def _clear_cache(self):
        """Limpa todos os caches para nova execução."""
        self._cached_test_ids = None
        self.response_cache.clear()
        self.baseline_responses.clear()
        self.access_patterns.clear()
        self.fingerprints.clear()

    def _extract_parameters_from_url(self, url):
        """Extrai parâmetros da URL que podem conter IDs."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Parâmetros comuns que podem conter IDs
        id_params = []
        common_id_names = [
            'id', 'user_id', 'userid', 'uid', 'account_id', 'profile_id',
            'doc_id', 'file_id', 'item_id', 'product_id', 'order_id',
            'invoice_id', 'ticket_id', 'message_id', 'post_id', 'comment_id',
            'session_id', 'token', 'key', 'ref', 'reference'
        ]
        
        for param_name, param_values in params.items():
            param_lower = param_name.lower()
            if any(id_name in param_lower for id_name in common_id_names):
                id_params.append((param_name, param_values[0] if param_values else ''))
        
        # Se não encontrou parâmetros óbvios, tenta todos os parâmetros numéricos
        if not id_params:
            for param_name, param_values in params.items():
                if param_values and param_values[0].isdigit():
                    id_params.append((param_name, param_values[0]))
        
        return id_params

    def _extract_path_ids(self, url):
        """Extrai IDs potenciais do path da URL."""
        parsed = urlparse(url)
        path_parts = parsed.path.split('/')  # Mantém partes vazias para posicionamento correto
        
        potential_ids = []
        for i, part in enumerate(path_parts):
            if not part:  # Pula partes vazias
                continue
                
            # Verifica se é um ID numérico
            if part.isdigit():
                potential_ids.append((i, part, 'numeric'))
            # Verifica se é um UUID
            elif self._is_uuid(part):
                potential_ids.append((i, part, 'uuid'))
            # Verifica se é um hash
            elif self._is_hash(part):
                potential_ids.append((i, part, 'hash'))
            # Verifica se parece com um ID alfanumérico
            elif len(part) > 2 and any(c.isdigit() for c in part) and any(c.isalpha() for c in part):
                potential_ids.append((i, part, 'alphanumeric'))
        
        return potential_ids

    def _is_uuid(self, value):
        """Verifica se o valor é um UUID válido."""
        try:
            uuid.UUID(value)
            return True
        except ValueError:
            return False

    def _is_hash(self, value):
        """Verifica se o valor parece ser um hash."""
        if not isinstance(value, str):
            return False
        
        # MD5: 32 chars hex
        if len(value) == 32 and all(c in '0123456789abcdefABCDEF' for c in value):
            return True
        # SHA1: 40 chars hex
        if len(value) == 40 and all(c in '0123456789abcdefABCDEF' for c in value):
            return True
        # SHA256: 64 chars hex
        if len(value) == 64 and all(c in '0123456789abcdefABCDEF' for c in value):
            return True
        
        return False

    def _make_request(self, url, method='GET', data=None, headers=None, bypass_technique=None):
        """Faz uma requisição HTTP com tratamento de erros e técnicas de bypass."""
        try:
            with self.stats_lock:
                self.stats['total_requests'] += 1
            
            if headers is None:
                headers = {}
            
            # Aplica técnicas de bypass se especificadas
            if bypass_technique:
                headers = self._apply_bypass_technique(headers, bypass_technique)
            
            # Aplica rate limiting
            self.rate_limiter.wait()
            
            start_time = time.time()
            response = self.session.request(
                method=method,
                url=url,
                data=data,
                headers=headers,
                timeout=10,
                allow_redirects=False
            )
            response_time = time.time() - start_time
            
            with self.stats_lock:
                self.stats['successful_requests'] += 1
                
                # Atualiza estatísticas por status code
                if response.status_code == 401:
                    self.stats['unauthorized_responses'] += 1
                elif response.status_code == 403:
                    self.stats['forbidden_responses'] += 1
                elif response.status_code == 404:
                    self.stats['not_found_responses'] += 1
                elif response.status_code == 429:
                    self.stats['rate_limited_responses'] += 1
                elif response.status_code >= 500:
                    self.stats['server_error_responses'] += 1
            
            # Notifica rate limiter sobre sucesso
            self.rate_limiter.on_success(response_time)
            
            return response
            
        except requests.exceptions.RequestException as e:
            self.logger.debug(f"Erro na requisição para {url}: {e}")
            # Notifica rate limiter sobre erro
            self.rate_limiter.on_error()
            return None
    
    def _apply_bypass_technique(self, headers: Dict[str, str], technique: str) -> Dict[str, str]:
        """Aplica técnicas de bypass aos headers."""
        bypass_headers = headers.copy()
        
        if technique == 'x_forwarded_for':
            bypass_headers['X-Forwarded-For'] = '127.0.0.1'
            bypass_headers['X-Real-IP'] = '127.0.0.1'
        elif technique == 'x_forwarded_host':
            bypass_headers['X-Forwarded-Host'] = 'localhost'
            bypass_headers['X-Forwarded-Proto'] = 'https'
        elif technique == 'method_override':
            bypass_headers['X-HTTP-Method-Override'] = 'GET'
            bypass_headers['X-Method-Override'] = 'GET'
        elif technique == 'content_type_override':
            bypass_headers['Content-Type'] = 'application/json'
            bypass_headers['Accept'] = 'application/json'
        elif technique == 'cors_bypass':
            bypass_headers['Origin'] = 'null'
            bypass_headers['Access-Control-Request-Method'] = 'GET'
        
        return bypass_headers

    def _analyze_response(self, response: requests.Response, test_id: str, 
                         original_response: Optional[requests.Response] = None,
                         technique: IDORTechnique = IDORTechnique.SEQUENTIAL) -> Tuple[bool, List[str], float]:
        """Analisa a resposta para detectar possíveis vulnerabilidades IDOR."""
        if not response:
            return False, ["Erro na requisição"], 0.0
        
        vulnerability_indicators = []
        confidence = 0.0
        
        # Detecta dados sensíveis
        sensitive_data = self.response_analyzer.detect_sensitive_data(response)
        if sensitive_data:
            vulnerability_indicators.extend(sensitive_data)
            confidence += 0.4
            with self.stats_lock:
                self.stats['sensitive_data_found'] += len(sensitive_data)
        
        # Compara com resposta original se disponível
        if original_response:
            # Diferentes status codes podem indicar acesso
            if response.status_code != original_response.status_code:
                if response.status_code == 200 and original_response.status_code in [401, 403, 404]:
                    vulnerability_indicators.append(f"Status mudou de {original_response.status_code} para 200")
                    confidence += 0.6
                elif response.status_code in [401, 403] and original_response.status_code == 404:
                    vulnerability_indicators.append(f"Objeto existe mas acesso negado (status {response.status_code})")
                    confidence += 0.3
                elif response.status_code == 404 and original_response.status_code in [401, 403]:
                    vulnerability_indicators.append(f"Objeto não existe para ID {test_id}")
                    confidence += 0.1
            
            # Diferentes tamanhos de resposta
            size_diff = abs(len(response.content) - len(original_response.content))
            size_ratio = size_diff / max(len(original_response.content), 1)
            
            if size_diff > 50 and size_ratio > 0.05:  # Diferença mais sensível
                vulnerability_indicators.append(f"Tamanho da resposta diferente ({size_diff} bytes, {size_ratio:.2%})")
                confidence += min(size_ratio, 0.3)
            
            # Similaridade de conteúdo
            similarity = self.response_analyzer.analyze_response_similarity(response, original_response)
            if similarity < 0.8:  # Conteúdo significativamente diferente
                vulnerability_indicators.append(f"Conteúdo diferente (similaridade: {similarity:.2%})")
                confidence += 0.2
            
            # Análise específica de mudanças no conteúdo JSON
            try:
                orig_json = original_response.json()
                resp_json = response.json()
                
                # Verifica se os valores de ID mudaram
                if isinstance(orig_json, dict) and isinstance(resp_json, dict):
                    # Procura por campos que podem conter IDs
                    id_fields = ['id', 'user_id', 'userId', 'ID', 'args']
                    for field in id_fields:
                        if field in orig_json and field in resp_json:
                            if str(orig_json[field]) != str(resp_json[field]):
                                vulnerability_indicators.append(f"Campo {field} mudou de {orig_json[field]} para {resp_json[field]}")
                                confidence += 0.4
                                break
                    
                    # Para httpbin.org/get, verifica se o parâmetro id foi refletido
                    if 'args' in resp_json and isinstance(resp_json['args'], dict):
                        if 'id' in resp_json['args']:
                            reflected_id = resp_json['args']['id']
                            if str(reflected_id) == str(test_id):
                                vulnerability_indicators.append(f"Parâmetro ID refletido corretamente: {reflected_id}")
                                confidence += 0.3
            except:
                pass
        
        # Análise de conteúdo estruturado
        try:
            json_data = response.json()
            if isinstance(json_data, dict):
                # Procura por campos sensíveis em JSON
                sensitive_fields = ['email', 'password', 'ssn', 'phone', 'address', 'balance', 'salary', 'credit_card']
                found_fields = [field for field in sensitive_fields if field in str(json_data).lower()]
                if found_fields:
                    vulnerability_indicators.append(f"Campos sensíveis em JSON: {', '.join(found_fields)}")
                    confidence += 0.4
                
                # Verifica estrutura de dados de usuário
                user_indicators = ['id', 'user_id', 'username', 'profile', 'account']
                if any(indicator in str(json_data).lower() for indicator in user_indicators):
                    vulnerability_indicators.append("Dados de usuário detectados em JSON")
                    confidence += 0.2
        except:
            pass
        
        # Status codes que indicam acesso
        if response.status_code == 200:
            vulnerability_indicators.append("Acesso bem-sucedido (200 OK)")
            confidence += 0.2
        elif response.status_code in [401, 403]:
            vulnerability_indicators.append(f"Objeto existe mas acesso negado ({response.status_code})")
            confidence += 0.1
        elif response.status_code == 302:
            location = response.headers.get('location', '')
            if location and 'login' not in location.lower():
                vulnerability_indicators.append(f"Redirecionamento para: {location}")
                confidence += 0.1
        
        # Análise de headers
        suspicious_headers = ['x-user-id', 'x-account-id', 'x-profile-id', 'x-customer-id']
        for header in suspicious_headers:
            if header in response.headers:
                vulnerability_indicators.append(f"Header suspeito: {header}")
                confidence += 0.1
        
        # Verifica padrões de erro que indicam existência
        error_patterns = [
            (r'(permission|access)\s+(denied|forbidden)', 'Acesso negado - objeto existe'),
            (r'unauthorized\s+access', 'Acesso não autorizado - objeto existe'),
            (r'insufficient\s+privileges', 'Privilégios insuficientes - objeto existe'),
            (r'not\s+authorized', 'Não autorizado - objeto existe')
        ]
        
        for pattern, message in error_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                vulnerability_indicators.append(message)
                confidence += 0.2
        
        # Ajusta confiança baseada na técnica utilizada
        technique_confidence = {
            IDORTechnique.SEQUENTIAL: 0.8,
            IDORTechnique.PREDICTABLE: 0.7,
            IDORTechnique.UUID_BASED: 0.6,
            IDORTechnique.HASH_BASED: 0.5,
            IDORTechnique.ENCODED: 0.4,
            IDORTechnique.TIMESTAMP: 0.3,
            IDORTechnique.MIXED: 0.5
        }
        
        confidence *= technique_confidence.get(technique, 0.5)
        confidence = min(confidence, 1.0)
        
        return len(vulnerability_indicators) > 0, vulnerability_indicators, confidence

    def _test_parameter_idor(self, url, param_name, original_value, test_ids):
        """Testa IDOR em um parâmetro específico."""
        vulnerabilities = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Faz requisição baseline
        baseline_response = self._make_request(url)
        
        with create_progress() as progress:
            task = progress.add_task(
                f"[cyan]Testando parâmetro {param_name}...", 
                total=len(test_ids)
            )
            
            def test_single_id(test_id):
                # Modifica o parâmetro
                test_params = params.copy()
                test_params[param_name] = [str(test_id)]
                
                # Reconstrói a URL
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))
                
                # Testa diferentes métodos HTTP se habilitado
                methods_to_test = self.test_http_methods if hasattr(self, 'test_http_methods') else ['GET']
                
                for method in methods_to_test:
                    response = self._make_request(test_url, method=method)
                    
                    if response:
                        is_vulnerable, indicators, confidence = self._analyze_response(response, test_id, baseline_response, IDORTechnique.SEQUENTIAL)
                        
                        if is_vulnerable:
                            vuln_info = VulnerabilityInfo(
                                url=test_url,
                                method=method,
                                technique=IDORTechnique.SEQUENTIAL,
                                parameter=param_name,
                                original_value=original_value,
                                test_value=test_id,
                                status_code=response.status_code,
                                response_size=len(response.content),
                                indicators=indicators,
                                confidence=confidence,
                                severity=self._calculate_severity(indicators, confidence)
                            )
                            
                            with self.results_lock:
                                vulnerabilities.append(vuln_info)
                                with self.stats_lock:
                                    self.stats['potential_vulns'] += 1
                    
                    time.sleep(self.delay)
                
                progress.advance(task)
            
            # Executa testes em paralelo
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = [executor.submit(test_single_id, test_id) for test_id in test_ids]
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        self.logger.error(f"Erro no teste de ID: {e}")
        
        return vulnerabilities

    def _test_path_idor(self, url, path_ids, test_ids):
        """Testa IDOR em IDs encontrados no path da URL."""
        vulnerabilities = []
        parsed = urlparse(url)
        path_parts = parsed.path.split('/')
        
        # Faz requisição baseline
        baseline_response = self._make_request(url)
        
        for position, original_id, id_type in path_ids:
            with create_progress() as progress:
                task = progress.add_task(
                    f"[cyan]Testando ID no path (posição {position})...", 
                    total=len(test_ids)
                )
                
                def test_single_path_id(test_id):
                    # Modifica o path - corrige o cálculo da posição
                    new_path_parts = path_parts.copy()
                    if position < len(new_path_parts):
                        new_path_parts[position] = str(test_id)
                    else:
                        self.logger.warning(f"Posição {position} inválida para path {parsed.path}")
                        return
                    
                    new_path = '/'.join(new_path_parts)
                    
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, new_path,
                        parsed.params, parsed.query, parsed.fragment
                    ))
                    
                    for method in self.test_http_methods:
                        response = self._make_request(test_url, method=method)
                        
                        if response:
                            is_vulnerable, indicators, confidence = self._analyze_response(response, test_id, baseline_response, IDORTechnique.SEQUENTIAL)
                            
                            if is_vulnerable:
                                vuln_info = VulnerabilityInfo(
                                    url=test_url,
                                    method=method,
                                    technique=IDORTechnique.SEQUENTIAL,
                                    path_position=position,
                                    original_value=original_id,
                                    test_value=test_id,
                                    id_type=id_type,
                                    status_code=response.status_code,
                                    response_size=len(response.content),
                                    indicators=indicators,
                                    confidence=confidence,
                                    severity=self._calculate_severity(indicators, confidence)
                                )
                                
                                with self.results_lock:
                                    vulnerabilities.append(vuln_info)
                                    with self.stats_lock:
                                        self.stats['potential_vulns'] += 1
                        
                        time.sleep(self.delay)
                    
                    progress.advance(task)
                
                # Executa testes em paralelo
                with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                    futures = [executor.submit(test_single_path_id, test_id) for test_id in test_ids]
                    for future in as_completed(futures):
                        try:
                            future.result()
                        except Exception as e:
                            self.logger.error(f"Erro no teste de path ID: {e}")
        
        return vulnerabilities

    def _calculate_severity(self, indicators: List[str], confidence: float = 0.5) -> Severity:
        """Calcula a severidade da vulnerabilidade baseada nos indicadores e confiança."""
        critical_patterns = [
            'private key', 'secret key', 'api key', 'password', 'ssn', 'credit_card',
            'balance', 'salary', 'financial', 'payment', 'bank'
        ]
        
        high_risk_patterns = [
            'dados sensíveis', 'credit card', 'phone', 'address', 'email',
            'personal', 'profile', 'account', 'user_id'
        ]
        
        medium_risk_patterns = [
            'token', 'session', 'cookie', 'header', 'json', 'xml'
        ]
        
        low_risk_patterns = [
            'acesso bem-sucedido', 'objeto existe', 'status 200'
        ]
        
        severity_score = 0
        
        for indicator in indicators:
            indicator_lower = indicator.lower()
            
            if any(pattern in indicator_lower for pattern in critical_patterns):
                severity_score += 5
            elif any(pattern in indicator_lower for pattern in high_risk_patterns):
                severity_score += 3
            elif any(pattern in indicator_lower for pattern in medium_risk_patterns):
                severity_score += 2
            elif any(pattern in indicator_lower for pattern in low_risk_patterns):
                severity_score += 1
        
        # Ajusta baseado na confiança
        if confidence >= 0.8:
            severity_score += 2
        elif confidence >= 0.6:
            severity_score += 1
        elif confidence < 0.3:
            severity_score -= 1
        
        # Determina severidade final
        if severity_score >= 8:
            return Severity.CRITICAL
        elif severity_score >= 5:
            return Severity.HIGH
        elif severity_score >= 3:
            return Severity.MEDIUM
        elif severity_score >= 1:
            return Severity.LOW
        else:
            return Severity.INFO

    def _display_results(self, vulnerabilities):
        """Exibe os resultados do scan de forma organizada."""
        if not vulnerabilities:
            print_info("Nenhuma vulnerabilidade IDOR detectada.")
            return
        
        # Agrupa vulnerabilidades por severidade
        by_severity = defaultdict(list)
        for vuln in vulnerabilities:
            by_severity[vuln.severity.value].append(vuln)
        
        # Exibe estatísticas gerais
        console.print("\n" + "="*60)
        console.print("[bold red]RESULTADOS DO SCAN IDOR[/bold red]")
        console.print("="*60)
        
        stats_table = Table(title="Estatísticas do Scan")
        stats_table.add_column("Métrica", style="cyan")
        stats_table.add_column("Valor", style="green")
        
        elapsed_time = time.time() - self.stats['scan_start_time']
        
        stats_table.add_row("Tempo de Scan", f"{elapsed_time:.2f}s")
        stats_table.add_row("Total de Requisições", str(self.stats['total_requests']))
        stats_table.add_row("Requisições Bem-sucedidas", str(self.stats['successful_requests']))
        stats_table.add_row("Vulnerabilidades Encontradas", str(len(vulnerabilities)))
        stats_table.add_row("Taxa de Sucesso", f"{(self.stats['successful_requests']/max(self.stats['total_requests'], 1)*100):.1f}%")
        
        console.print(stats_table)
        
        # Exibe vulnerabilidades por severidade
        severity_colors = {
            'CRÍTICA': 'bold red',
            'ALTA': 'red',
            'MÉDIA': 'yellow',
            'BAIXA': 'blue'
        }
        
        for severity in ['CRÍTICA', 'ALTA', 'MÉDIA', 'BAIXA']:
            if severity in by_severity:
                console.print(f"\n[{severity_colors[severity]}]VULNERABILIDADES {severity}S ({len(by_severity[severity])})[/{severity_colors[severity]}]")
                
                vuln_table = Table()
                vuln_table.add_column("URL", style="cyan", max_width=50)
                vuln_table.add_column("Método", style="green")
                vuln_table.add_column("Parâmetro/Posição", style="yellow")
                vuln_table.add_column("Valor Original", style="blue")
                vuln_table.add_column("Valor Teste", style="magenta")
                vuln_table.add_column("Status", style="green")
                vuln_table.add_column("Indicadores", style="red", max_width=40)
                
                for vuln in by_severity[severity][:10]:  # Mostra até 10 por severidade
                    param_info = vuln.parameter or vuln.header_name or vuln.cookie_name or f"Path pos {vuln.path_position or 'N/A'}"
                    indicators_text = "; ".join(vuln.indicators[:3])  # Primeiros 3 indicadores
                    if len(vuln.indicators) > 3:
                        indicators_text += "..."
                    
                    vuln_table.add_row(
                        vuln.url[:47] + "..." if len(vuln.url) > 50 else vuln.url,
                        vuln.method,
                        param_info,
                        str(vuln.original_value or 'N/A')[:15],
                        str(vuln.test_value)[:15],
                        str(vuln.status_code),
                        indicators_text
                    )
                
                console.print(vuln_table)
                
                if len(by_severity[severity]) > 10:
                    console.print(f"[dim]... e mais {len(by_severity[severity]) - 10} vulnerabilidades {severity.lower()}s[/dim]")

    def scan(self) -> List[VulnerabilityInfo]:
        """Executa o scan IDOR completo com técnicas avançadas."""
        # Exibe aviso de desenvolvimento
        DevelopmentWarningManager.show_development_warning(verbose=self.verbose)
        
        print_info(f"Iniciando scan IDOR avançado em: [bold cyan]{self.base_url}[/bold cyan]")
        
        # Gera IDs para teste
        test_ids = self._generate_test_ids()
        print_info(f"Gerados [bold cyan]{len(test_ids)}[/bold cyan] IDs para teste")
        
        if self.verbose:
            print_info(f"Configurações do scan:")
            console.print(f"  [dim cyan]→[/dim cyan] [dim]Workers: {self.max_workers}[/dim]")
            console.print(f"  [dim cyan]→[/dim cyan] [dim]Delay: {self.delay}s[/dim]")
            console.print(f"  [dim cyan]→[/dim cyan] [dim]Range: {self.enumerate_range[0]}-{self.enumerate_range[1]}[/dim]")
            console.print(f"  [dim cyan]→[/dim cyan] [dim]UUID: {'Sim' if self.test_uuid else 'Não'}[/dim]")
            console.print(f"  [dim cyan]→[/dim cyan] [dim]Hash: {'Sim' if self.test_hash else 'Não'}[/dim]")
            console.print(f"  [dim cyan]→[/dim cyan] [dim]Deep Scan: {'Sim' if self.deep_scan else 'Não'}[/dim]")
            console.print(f"  [dim cyan]→[/dim cyan] [dim]Robots.txt: {'Respeitado' if self.respect_robots else 'Ignorado'}[/dim]")
        
        all_vulnerabilities = []
        
        # Estabelece baseline
        if self.verbose:
            print_info("Estabelecendo baseline de respostas...")
        self._establish_baseline()
        
        # Testa parâmetros da URL
        url_params = self._extract_parameters_from_url(self.base_url)
        if url_params:
            if self.verbose:
                print_info(f"Encontrados [bold cyan]{len(url_params)}[/bold cyan] parâmetros para teste")
            
            for param_name, original_value in url_params:
                if self.verbose:
                    print_info(f"Testando parâmetro: [bold yellow]{param_name}[/bold yellow]")
                param_vulns = self._test_parameter_idor(self.base_url, param_name, original_value, test_ids)
                all_vulnerabilities.extend(param_vulns)
        
        # Testa IDs no path
        path_ids = self._extract_path_ids(self.base_url)
        if path_ids:
            if self.verbose:
                print_info(f"Encontrados [bold cyan]{len(path_ids)}[/bold cyan] IDs no path para teste")
            path_vulns = self._test_path_idor(self.base_url, path_ids, test_ids)
            all_vulnerabilities.extend(path_vulns)
        
        # Testa headers se habilitado (apenas em deep scan para evitar travamento)
        if self.test_header_injection and self.deep_scan:
            if self.verbose:
                print_info("Testando injeção de headers...")
            header_vulns = self._test_header_injection(self.base_url, test_ids)
            all_vulnerabilities.extend(header_vulns)
        elif self.test_header_injection and self.verbose:
            print_info("Teste de headers pulado (use --deep-scan para ativar)")
        
        # Testa cookies se habilitado (apenas em deep scan para evitar travamento)
        if self.test_cookie_manipulation and self.deep_scan:
            if self.verbose:
                print_info("Testando manipulação de cookies...")
            cookie_vulns = self._test_cookie_manipulation(self.base_url, test_ids)
            all_vulnerabilities.extend(cookie_vulns)
        elif self.test_cookie_manipulation and self.verbose:
            print_info("Teste de cookies pulado (use --deep-scan para ativar)")
        
        # Testa falhas lógicas (apenas em deep scan para evitar travamento)
        if self.test_logic_flaws and self.deep_scan:
            if self.verbose:
                print_info("Testando falhas lógicas...")
            logic_vulns = self._test_logic_flaws(self.base_url, test_ids)
            all_vulnerabilities.extend(logic_vulns)
        elif self.test_logic_flaws and self.verbose:
            print_info("Teste de falhas lógicas pulado (use --deep-scan para ativar)")
        
        # Testa técnicas de bypass (apenas em deep scan para evitar travamento)
        if self.test_bypass_techniques and self.deep_scan:
            if self.verbose:
                print_info("Testando técnicas de bypass...")
            bypass_vulns = self._test_bypass_techniques(self.base_url, test_ids)
            all_vulnerabilities.extend(bypass_vulns)
        elif self.test_bypass_techniques and self.verbose:
            print_info("Teste de bypass pulado (use --deep-scan para ativar)")
        
        if not url_params and not path_ids:
            print_warning("Nenhum parâmetro ou ID identificado na URL para teste IDOR")
            print_info("Dica: Certifique-se de que a URL contém parâmetros (ex: ?id=123) ou IDs no path (ex: /user/123)")
        
        # Filtra falsos positivos
        filtered_vulnerabilities = self._filter_false_positives(all_vulnerabilities)
        
        # Exibe resultados
        self._display_results(filtered_vulnerabilities)
        
        # Mostra recomendações pós-scan
        if filtered_vulnerabilities:
            DevelopmentWarningManager.show_post_scan_recommendations()
        
        # Salva vulnerabilidades para uso posterior
        self.vulnerable_endpoints = filtered_vulnerabilities
        
        return filtered_vulnerabilities

    def _establish_baseline(self):
        """Estabelece respostas baseline para comparação."""
        baseline_requests = [
            (self.base_url, 'GET'),
            (self.base_url, 'POST'),
            (self.base_url, 'HEAD')
        ]
        
        for url, method in baseline_requests:
            response = self._make_request(url, method)
            if response:
                self.baseline_responses[method] = response

    def _test_header_injection(self, url: str, test_ids: List[str]) -> List[VulnerabilityInfo]:
        """Testa injeção de IDs em headers HTTP."""
        vulnerabilities = []
        
        # Headers comuns que podem conter IDs
        id_headers = [
            'X-User-ID', 'X-Account-ID', 'X-Customer-ID', 'X-Profile-ID',
            'X-Session-ID', 'X-Request-ID', 'X-Correlation-ID',
            'User-ID', 'Account-ID', 'Customer-ID', 'Profile-ID'
        ]
        
        baseline_response = self._make_request(url)
        
        # Limita IDs para evitar overhead excessivo
        limited_test_ids = test_ids[:10]  # Reduz de 100 para 10 IDs
        total_tests = len(id_headers) * len(limited_test_ids)
        
        if self.verbose:
            print_info(f"Testando {len(id_headers)} headers com {len(limited_test_ids)} IDs cada ({total_tests} testes)")
        
        with create_progress() as progress:
            task = progress.add_task(
                f"[cyan]Testando headers...", 
                total=total_tests
            )
            
            for header_name in id_headers:
                for test_id in limited_test_ids:
                    headers = {header_name: str(test_id)}
                    response = self._make_request(url, headers=headers)
                    
                    if response:
                        is_vulnerable, indicators, confidence = self._analyze_response(
                            response, test_id, baseline_response, IDORTechnique.MIXED
                        )
                        
                        if is_vulnerable:
                            vuln_info = VulnerabilityInfo(
                                url=url,
                                method='GET',
                                technique=IDORTechnique.MIXED,
                                header_name=header_name,
                                test_value=test_id,
                                status_code=response.status_code,
                                response_size=len(response.content),
                                indicators=indicators,
                                confidence=confidence,
                                severity=self._calculate_severity(indicators, confidence)
                            )
                            vulnerabilities.append(vuln_info)
                    
                    progress.advance(task)
        
        return vulnerabilities

    def _test_cookie_manipulation(self, url: str, test_ids: List[str]) -> List[VulnerabilityInfo]:
        """Testa manipulação de cookies com IDs."""
        vulnerabilities = []
        
        # Cookies comuns que podem conter IDs
        id_cookies = [
            'user_id', 'account_id', 'customer_id', 'profile_id',
            'session_id', 'uid', 'cid', 'pid'
        ]
        
        baseline_response = self._make_request(url)
        
        # Limita IDs para evitar overhead excessivo
        limited_test_ids = test_ids[:5]  # Reduz de 50 para 5 IDs
        total_tests = len(id_cookies) * len(limited_test_ids)
        
        if self.verbose:
            print_info(f"Testando {len(id_cookies)} cookies com {len(limited_test_ids)} IDs cada ({total_tests} testes)")
        
        with create_progress() as progress:
            task = progress.add_task(
                f"[cyan]Testando cookies...", 
                total=total_tests
            )
            
            for cookie_name in id_cookies:
                for test_id in limited_test_ids:
                    # Adiciona cookie temporariamente
                    original_cookies = self.session.cookies.copy()
                    self.session.cookies[cookie_name] = str(test_id)
                    
                    response = self._make_request(url)
                    
                    # Restaura cookies originais
                    self.session.cookies = original_cookies
                    
                    if response:
                        is_vulnerable, indicators, confidence = self._analyze_response(
                            response, test_id, baseline_response, IDORTechnique.MIXED
                        )
                        
                        if is_vulnerable:
                            vuln_info = VulnerabilityInfo(
                                url=url,
                                method='GET',
                                technique=IDORTechnique.MIXED,
                                cookie_name=cookie_name,
                                test_value=test_id,
                                status_code=response.status_code,
                                response_size=len(response.content),
                                indicators=indicators,
                                confidence=confidence,
                                severity=self._calculate_severity(indicators, confidence)
                            )
                            vulnerabilities.append(vuln_info)
                    
                    progress.advance(task)
        
        return vulnerabilities

    def _test_logic_flaws(self, url: str, test_ids: List[str]) -> List[VulnerabilityInfo]:
        """Testa falhas lógicas em controle de acesso."""
        vulnerabilities = []
        
        # Testa diferentes combinações de parâmetros
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if params:
            # Testa remoção de parâmetros de autenticação
            auth_params = ['token', 'auth', 'key', 'session', 'csrf']
            for auth_param in auth_params:
                if auth_param in params:
                    # Remove parâmetro de autenticação
                    test_params = params.copy()
                    del test_params[auth_param]
                    
                    # Testa com IDs diferentes
                    for test_id in test_ids[:20]:
                        # Se existe parâmetro de ID, modifica ele
                        for param_name in test_params:
                            if 'id' in param_name.lower():
                                test_params[param_name] = [str(test_id)]
                                break
                        
                        new_query = urlencode(test_params, doseq=True)
                        test_url = urlunparse((
                            parsed.scheme, parsed.netloc, parsed.path,
                            parsed.params, new_query, parsed.fragment
                        ))
                        
                        response = self._make_request(test_url)
                        if response and response.status_code == 200:
                            vuln_info = VulnerabilityInfo(
                                url=test_url,
                                method='GET',
                                technique=IDORTechnique.LOGIC_FLAW,
                                test_value=test_id,
                                status_code=response.status_code,
                                response_size=len(response.content),
                                indicators=[f"Bypass de autenticação removendo parâmetro {auth_param}"],
                                confidence=0.8,
                                severity=Severity.HIGH,
                                bypass_technique=f"Parameter removal: {auth_param}"
                            )
                            vulnerabilities.append(vuln_info)
                            
                            with self.stats_lock:
                                self.stats['bypasses_successful'] += 1
        
        return vulnerabilities

    def _test_bypass_techniques(self, url: str, test_ids: List[str]) -> List[VulnerabilityInfo]:
        """Testa técnicas de bypass de controle de acesso."""
        vulnerabilities = []
        
        bypass_techniques = [
            'x_forwarded_for',
            'x_forwarded_host', 
            'method_override',
            'content_type_override',
            'cors_bypass'
        ]
        
        baseline_response = self._make_request(url)
        
        for technique in bypass_techniques:
            for test_id in test_ids[:20]:
                # Modifica URL com test_id se possível
                test_url = url
                if '?' in url:
                    # Adiciona ou modifica parâmetro id
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    params['id'] = [str(test_id)]
                    new_query = urlencode(params, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))
                
                response = self._make_request(test_url, bypass_technique=technique)
                
                if response:
                    is_vulnerable, indicators, confidence = self._analyze_response(
                        response, test_id, baseline_response, IDORTechnique.MIXED
                    )
                    
                    if is_vulnerable:
                        vuln_info = VulnerabilityInfo(
                            url=test_url,
                            method='GET',
                            technique=IDORTechnique.MIXED,
                            test_value=test_id,
                            status_code=response.status_code,
                            response_size=len(response.content),
                            indicators=indicators,
                            confidence=confidence,
                            severity=self._calculate_severity(indicators, confidence),
                            bypass_technique=technique
                        )
                        vulnerabilities.append(vuln_info)
                        
                        with self.stats_lock:
                            self.stats['bypasses_successful'] += 1
        
        return vulnerabilities

    def _filter_false_positives(self, vulnerabilities: List[VulnerabilityInfo]) -> List[VulnerabilityInfo]:
        """Filtra falsos positivos usando análise avançada."""
        filtered = []
        
        for vuln in vulnerabilities:
            # Simula resposta para análise
            mock_response = type('MockResponse', (), {
                'text': '',
                'status_code': vuln.status_code,
                'content': b'',
                'headers': vuln.response_headers
            })()
            
            fp_score = self.response_analyzer.calculate_false_positive_score(
                mock_response, vuln.indicators
            )
            
            vuln.false_positive_score = fp_score
            
            # Filtra com base no score e confiança
            if fp_score < 0.7 and vuln.confidence > 0.3:
                filtered.append(vuln)
            elif vuln.confidence > 0.7:  # Alta confiança passa mesmo com FP score alto
                filtered.append(vuln)
        
        return filtered

    def _export_results(self, vulnerabilities: List[VulnerabilityInfo], 
                       export_format: str, output_file: str):
        """Exporta resultados em diferentes formatos."""
        try:
            if export_format.lower() == 'json':
                data = {
                    'scan_info': {
                        'target': self.base_url,
                        'timestamp': datetime.now().isoformat(),
                        'total_vulnerabilities': len(vulnerabilities),
                        'statistics': self.stats
                    },
                    'vulnerabilities': [vuln.to_dict() for vuln in vulnerabilities]
                }
                
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                
                print_success(f"Resultados exportados para {output_file}")
                
            elif export_format.lower() == 'csv':
                import csv
                with open(output_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=[
                        'url', 'method', 'technique', 'parameter', 'test_value',
                        'status_code', 'severity', 'confidence', 'indicators'
                    ])
                    writer.writeheader()
                    for vuln in vulnerabilities:
                        writer.writerow({
                            'url': vuln.url,
                            'method': vuln.method,
                            'technique': vuln.technique.value,
                            'parameter': vuln.parameter or vuln.header_name or vuln.cookie_name,
                            'test_value': vuln.test_value,
                            'status_code': vuln.status_code,
                            'severity': vuln.severity.value,
                            'confidence': vuln.confidence,
                            'indicators': '; '.join(vuln.indicators)
                        })
                
                print_success(f"Resultados exportados para {output_file}")
                
        except Exception as e:
            print_error(f"Erro ao exportar resultados: {e}")

    def get_scan_statistics(self) -> Dict[str, Any]:
        """Retorna estatísticas detalhadas do scan."""
        elapsed_time = time.time() - self.stats['scan_start_time']
        
        return {
            'scan_duration': elapsed_time,
            'requests_per_second': self.stats['total_requests'] / max(elapsed_time, 1),
            'success_rate': self.stats['successful_requests'] / max(self.stats['total_requests'], 1),
            'cache_hit_rate': self.response_cache.get_hit_rate(),
            'current_delay': self.rate_limiter.get_current_delay(),
            **self.stats
        }


def idor_scan(url: str, enumerate_range: Optional[Tuple[int, int]] = None, 
              test_uuid: bool = True, test_hash: bool = True, 
              custom_wordlist: Optional[str] = None, max_workers: int = 10, 
              delay: float = 0.1, session_cookies: Optional[Dict[str, str]] = None,
              auth_headers: Optional[Dict[str, str]] = None, 
              respect_robots: bool = True, deep_scan: bool = False,
              verbose: bool = False, export_format: Optional[str] = None, 
              output_file: Optional[str] = None) -> List[VulnerabilityInfo]:
    """Função principal para executar scan IDOR avançado."""
    try:
        scanner = AdvancedIDORScanner(
            base_url=url,
            enumerate_range=enumerate_range,
            test_uuid=test_uuid,
            test_hash=test_hash,
            custom_wordlist=custom_wordlist,
            max_workers=max_workers,
            delay=delay,
            session_cookies=session_cookies,
            auth_headers=auth_headers,
            respect_robots=respect_robots,
            deep_scan=deep_scan,
            verbose=verbose
        )
        
        # Limpa cache para garantir execução consistente
        scanner._clear_cache()
        
        # Executa o scan
        results = scanner.scan()
        
        # Exporta resultados se solicitado
        if export_format and output_file:
            scanner._export_results(results, export_format, output_file)
        
        return results
        
    except KeyboardInterrupt:
        print_warning("\nScan IDOR interrompido pelo usuário")
        return []
    except ValueError as e:
        print_error(f"Erro de validação: {e}")
        return []
    except Exception as e:
        print_error(f"Erro durante scan IDOR: {e}")
        return []