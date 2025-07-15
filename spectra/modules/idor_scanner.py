# -*- coding: utf-8 -*-
"""
IDOR (Insecure Direct Object Reference) Scanner Module
Módulo para detecção de vulnerabilidades IDOR com múltiplas técnicas de enumeração.
"""

import requests
import re
import time
import json
import random
import string
import uuid
import hashlib
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from difflib import SequenceMatcher
import threading
from collections import defaultdict

from rich.table import Table

from ..core import console, print_info, print_success, print_error, print_warning
from ..core.console import create_progress
from ..core.logger import get_logger
from ..utils.network import create_session


class IDORScanner:
    """Scanner avançado para detecção de vulnerabilidades IDOR."""

    def __init__(self, base_url, enumerate_range=None, test_uuid=False, test_hash=False, 
                 custom_wordlist=None, max_workers=10, delay=0.1):
        self.base_url = base_url
        self.session = create_session()
        self.vulnerable_endpoints = []
        self.enumerate_range = enumerate_range or (1, 100)
        self.test_uuid = test_uuid
        self.test_hash = test_hash
        self.custom_wordlist = custom_wordlist
        self.max_workers = max_workers
        self.delay = delay
        
        # Configurações avançadas
        self.test_negative_ids = True
        self.test_large_ids = True
        self.test_string_ids = True
        self.test_encoded_ids = True
        self.analyze_response_patterns = True
        self.detect_access_control = True
        self.test_http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
        self.test_parameter_variations = True
        
        # Thread safety
        self.results_lock = threading.Lock()
        self.stats_lock = threading.Lock()
        
        # Estatísticas
        self.stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'unauthorized_responses': 0,
            'forbidden_responses': 0,
            'not_found_responses': 0,
            'different_responses': 0,
            'potential_vulns': 0,
            'confirmed_vulns': 0,
            'false_positives': 0,
            'scan_start_time': time.time()
        }
        
        # Cache de respostas para análise de padrões
        self.response_cache = {}
        self.baseline_response = None
        self.access_patterns = defaultdict(list)
        
        self.logger = get_logger(__name__)

    def _generate_test_ids(self):
        """Gera lista de IDs para teste baseado nas configurações."""
        test_ids = []
        
        # IDs sequenciais no range especificado
        start, end = self.enumerate_range
        test_ids.extend(range(start, end + 1))
        
        # IDs negativos
        if self.test_negative_ids:
            test_ids.extend([-1, -10, -100])
        
        # IDs grandes
        if self.test_large_ids:
            test_ids.extend([999999, 1000000, 2147483647, 9999999999])
        
        # IDs string comuns
        if self.test_string_ids:
            string_ids = [
                'admin', 'administrator', 'root', 'test', 'demo', 'guest',
                'user', 'default', 'null', 'undefined', '0', 'false', 'true'
            ]
            test_ids.extend(string_ids)
        
        # UUIDs se habilitado
        if self.test_uuid:
            # UUIDs comuns/previsíveis
            uuid_tests = [
                '00000000-0000-0000-0000-000000000000',
                '11111111-1111-1111-1111-111111111111',
                'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
                str(uuid.uuid4()),  # UUID aleatório
                str(uuid.uuid1()),  # UUID baseado em timestamp
            ]
            test_ids.extend(uuid_tests)
        
        # Hashes se habilitado
        if self.test_hash:
            hash_tests = [
                hashlib.md5(b'1').hexdigest(),
                hashlib.md5(b'admin').hexdigest(),
                hashlib.sha1(b'1').hexdigest(),
                hashlib.sha256(b'1').hexdigest()[:8],  # Hash truncado
            ]
            test_ids.extend(hash_tests)
        
        # IDs codificados
        if self.test_encoded_ids:
            import base64
            encoded_ids = []
            for i in [1, 2, 100]:
                # Base64
                encoded_ids.append(base64.b64encode(str(i).encode()).decode())
                # URL encoding
                encoded_ids.append(f"%{ord(str(i)[0]):02x}")
            test_ids.extend(encoded_ids)
        
        # Wordlist customizada
        if self.custom_wordlist:
            try:
                with open(self.custom_wordlist, 'r', encoding='utf-8') as f:
                    custom_ids = [line.strip() for line in f if line.strip()]
                    test_ids.extend(custom_ids[:1000])  # Limite de 1000 IDs
                    print_info(f"Carregados {len(custom_ids[:1000])} IDs da wordlist customizada")
            except Exception as e:
                print_warning(f"Erro ao carregar wordlist: {e}")
        
        return list(set(str(id_val) for id_val in test_ids))  # Remove duplicatas

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
        path_parts = [part for part in parsed.path.split('/') if part]
        
        potential_ids = []
        for i, part in enumerate(path_parts):
            # Verifica se é um ID numérico
            if part.isdigit():
                potential_ids.append((i, part, 'numeric'))
            # Verifica se é um UUID
            elif self._is_uuid(part):
                potential_ids.append((i, part, 'uuid'))
            # Verifica se é um hash
            elif self._is_hash(part):
                potential_ids.append((i, part, 'hash'))
        
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

    def _make_request(self, url, method='GET', data=None, headers=None):
        """Faz uma requisição HTTP com tratamento de erros."""
        try:
            with self.stats_lock:
                self.stats['total_requests'] += 1
            
            if headers is None:
                headers = {}
            
            response = self.session.request(
                method=method,
                url=url,
                data=data,
                headers=headers,
                timeout=10,
                allow_redirects=False
            )
            
            with self.stats_lock:
                self.stats['successful_requests'] += 1
                
                # Atualiza estatísticas por status code
                if response.status_code == 401:
                    self.stats['unauthorized_responses'] += 1
                elif response.status_code == 403:
                    self.stats['forbidden_responses'] += 1
                elif response.status_code == 404:
                    self.stats['not_found_responses'] += 1
            
            return response
            
        except requests.exceptions.RequestException as e:
            self.logger.debug(f"Erro na requisição para {url}: {e}")
            return None

    def _analyze_response(self, response, test_id, original_response=None):
        """Analisa a resposta para detectar possíveis vulnerabilidades IDOR."""
        if not response:
            return False, "Erro na requisição"
        
        vulnerability_indicators = []
        
        # Compara com resposta original se disponível
        if original_response:
            # Diferentes status codes podem indicar acesso
            if response.status_code != original_response.status_code:
                if response.status_code == 200 and original_response.status_code in [401, 403, 404]:
                    vulnerability_indicators.append(f"Status mudou de {original_response.status_code} para 200")
                elif response.status_code in [401, 403] and original_response.status_code == 404:
                    vulnerability_indicators.append(f"Objeto existe mas acesso negado (status {response.status_code})")
            
            # Diferentes tamanhos de resposta
            size_diff = abs(len(response.content) - len(original_response.content))
            if size_diff > 100:  # Diferença significativa
                vulnerability_indicators.append(f"Tamanho da resposta diferente ({size_diff} bytes)")
        
        # Análise de conteúdo para dados sensíveis
        content = response.text.lower()
        sensitive_patterns = [
            r'email.*@.*\.',
            r'password.*:',
            r'ssn.*\d{3}-\d{2}-\d{4}',
            r'credit.*card',
            r'phone.*\d{3}.*\d{3}.*\d{4}',
            r'address.*:',
            r'private.*key',
            r'secret.*key',
            r'api.*key',
            r'token.*:',
            r'balance.*\$\d+',
            r'salary.*\$\d+'
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, content):
                vulnerability_indicators.append(f"Dados sensíveis detectados: {pattern}")
        
        # Verifica se há dados estruturados (JSON/XML)
        try:
            json_data = response.json()
            if isinstance(json_data, dict):
                # Procura por campos sensíveis em JSON
                sensitive_fields = ['email', 'password', 'ssn', 'phone', 'address', 'balance', 'salary']
                found_fields = [field for field in sensitive_fields if field in str(json_data).lower()]
                if found_fields:
                    vulnerability_indicators.append(f"Campos sensíveis em JSON: {', '.join(found_fields)}")
        except:
            pass
        
        # Status codes que indicam acesso
        if response.status_code == 200:
            vulnerability_indicators.append("Acesso bem-sucedido (200 OK)")
        elif response.status_code in [401, 403]:
            vulnerability_indicators.append(f"Objeto existe mas acesso negado ({response.status_code})")
        
        return len(vulnerability_indicators) > 0, vulnerability_indicators

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
                        is_vulnerable, indicators = self._analyze_response(response, test_id, baseline_response)
                        
                        if is_vulnerable:
                            vuln_info = {
                                'url': test_url,
                                'method': method,
                                'parameter': param_name,
                                'original_value': original_value,
                                'test_value': test_id,
                                'status_code': response.status_code,
                                'response_size': len(response.content),
                                'indicators': indicators,
                                'severity': self._calculate_severity(indicators)
                            }
                            
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
                    # Modifica o path
                    new_path_parts = path_parts.copy()
                    new_path_parts[position + 1] = str(test_id)  # +1 porque split('/') cria elemento vazio no início
                    new_path = '/'.join(new_path_parts)
                    
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, new_path,
                        parsed.params, parsed.query, parsed.fragment
                    ))
                    
                    for method in self.test_http_methods:
                        response = self._make_request(test_url, method=method)
                        
                        if response:
                            is_vulnerable, indicators = self._analyze_response(response, test_id, baseline_response)
                            
                            if is_vulnerable:
                                vuln_info = {
                                    'url': test_url,
                                    'method': method,
                                    'path_position': position,
                                    'original_value': original_id,
                                    'test_value': test_id,
                                    'id_type': id_type,
                                    'status_code': response.status_code,
                                    'response_size': len(response.content),
                                    'indicators': indicators,
                                    'severity': self._calculate_severity(indicators)
                                }
                                
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

    def _calculate_severity(self, indicators):
        """Calcula a severidade da vulnerabilidade baseada nos indicadores."""
        high_risk_patterns = [
            'dados sensíveis', 'password', 'ssn', 'credit card', 'private key',
            'secret key', 'api key', 'balance', 'salary'
        ]
        
        medium_risk_patterns = [
            'email', 'phone', 'address', 'token'
        ]
        
        severity_score = 0
        
        for indicator in indicators:
            indicator_lower = indicator.lower()
            
            if any(pattern in indicator_lower for pattern in high_risk_patterns):
                severity_score += 3
            elif any(pattern in indicator_lower for pattern in medium_risk_patterns):
                severity_score += 2
            elif 'acesso bem-sucedido' in indicator_lower:
                severity_score += 1
            elif 'objeto existe' in indicator_lower:
                severity_score += 1
        
        if severity_score >= 5:
            return 'CRÍTICA'
        elif severity_score >= 3:
            return 'ALTA'
        elif severity_score >= 1:
            return 'MÉDIA'
        else:
            return 'BAIXA'

    def _display_results(self, vulnerabilities):
        """Exibe os resultados do scan de forma organizada."""
        if not vulnerabilities:
            print_info("Nenhuma vulnerabilidade IDOR detectada.")
            return
        
        # Agrupa vulnerabilidades por severidade
        by_severity = defaultdict(list)
        for vuln in vulnerabilities:
            by_severity[vuln['severity']].append(vuln)
        
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
                    param_info = vuln.get('parameter', f"Path pos {vuln.get('path_position', 'N/A')}")
                    indicators_text = "; ".join(vuln['indicators'][:3])  # Primeiros 3 indicadores
                    if len(vuln['indicators']) > 3:
                        indicators_text += "..."
                    
                    vuln_table.add_row(
                        vuln['url'][:47] + "..." if len(vuln['url']) > 50 else vuln['url'],
                        vuln['method'],
                        param_info,
                        str(vuln.get('original_value', 'N/A'))[:15],
                        str(vuln['test_value'])[:15],
                        str(vuln['status_code']),
                        indicators_text
                    )
                
                console.print(vuln_table)
                
                if len(by_severity[severity]) > 10:
                    console.print(f"[dim]... e mais {len(by_severity[severity]) - 10} vulnerabilidades {severity.lower()}s[/dim]")

    def scan(self):
        """Executa o scan IDOR completo."""
        print_info(f"Iniciando scan IDOR em: [bold cyan]{self.base_url}[/bold cyan]")
        
        # Gera IDs para teste
        test_ids = self._generate_test_ids()
        print_info(f"Gerados [bold cyan]{len(test_ids)}[/bold cyan] IDs para teste")
        
        all_vulnerabilities = []
        
        # Testa parâmetros da URL
        url_params = self._extract_parameters_from_url(self.base_url)
        if url_params:
            print_info(f"Encontrados [bold cyan]{len(url_params)}[/bold cyan] parâmetros para teste")
            
            for param_name, original_value in url_params:
                print_info(f"Testando parâmetro: [bold yellow]{param_name}[/bold yellow]")
                param_vulns = self._test_parameter_idor(self.base_url, param_name, original_value, test_ids)
                all_vulnerabilities.extend(param_vulns)
        
        # Testa IDs no path
        path_ids = self._extract_path_ids(self.base_url)
        if path_ids:
            print_info(f"Encontrados [bold cyan]{len(path_ids)}[/bold cyan] IDs no path para teste")
            path_vulns = self._test_path_idor(self.base_url, path_ids, test_ids)
            all_vulnerabilities.extend(path_vulns)
        
        if not url_params and not path_ids:
            print_warning("Nenhum parâmetro ou ID identificado na URL para teste IDOR")
            print_info("Dica: Certifique-se de que a URL contém parâmetros (ex: ?id=123) ou IDs no path (ex: /user/123)")
        
        # Exibe resultados
        self._display_results(all_vulnerabilities)
        
        # Salva vulnerabilidades para uso posterior
        self.vulnerable_endpoints = all_vulnerabilities
        
        return all_vulnerabilities


def idor_scan(url, enumerate_range=None, test_uuid=False, test_hash=False, 
              custom_wordlist=None, max_workers=10, delay=0.1):
    """Função principal para executar scan IDOR."""
    try:
        scanner = IDORScanner(
            base_url=url,
            enumerate_range=enumerate_range,
            test_uuid=test_uuid,
            test_hash=test_hash,
            custom_wordlist=custom_wordlist,
            max_workers=max_workers,
            delay=delay
        )
        
        return scanner.scan()
        
    except KeyboardInterrupt:
        print_warning("\nScan IDOR interrompido pelo usuário")
        return []
    except Exception as e:
        print_error(f"Erro durante scan IDOR: {e}")
        return []