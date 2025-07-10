# -*- coding: utf-8 -*-
"""
XSS Scanner Module
Módulo para detecção de vulnerabilidades de Cross-Site Scripting (XSS).
"""

import requests
import re
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn

from ..core.logger import get_logger
from ..utils.network import create_session


class XSSScanner:
    """Scanner para detecção de vulnerabilidades XSS."""

    def __init__(self, base_url, custom_payloads_file=None, scan_stored=False, fuzz_dom=False):
        self.base_url = base_url
        self.session = create_session()
        self.vulnerable_points = []
        self.payloads = self._load_payloads(custom_payloads_file)
        self.scan_stored = scan_stored
        self.fuzz_dom = fuzz_dom
        
        # Configurações padrão das novas funcionalidades
        self.enable_bypasses = True
        self.context_analysis = True
        self.validate_execution = True
        self.analyze_csp = True
        self.verbose = False
        
        self.logger = get_logger(__name__)
        self.console = Console()

    def _load_payloads(self, custom_payloads_file):
        """Carrega payloads de um ficheiro ou usa payloads padrão."""
        default_payloads = self._get_default_payloads()
        
        if custom_payloads_file:
            try:
                with open(custom_payloads_file, 'r', errors='ignore') as f:
                    payloads = [line.strip() for line in f if line.strip()]
                    if not payloads:
                        self.console.print(f"[bold yellow]Aviso: O ficheiro de payloads '{custom_payloads_file}' está vazio. Usando payloads padrão.[/bold yellow]")
                        return default_payloads
                    self.console.print(f"[*] Carregados [bold cyan]{len(payloads)}[/bold cyan] payloads de XSS de '{custom_payloads_file}'.")
                    return payloads
            except FileNotFoundError:
                self.console.print(f"[bold red][!] Erro: O ficheiro de payloads '{custom_payloads_file}' não foi encontrado. Usando payloads padrão.[/bold red]")
                return default_payloads
        return default_payloads
    
    def _get_default_payloads(self):
        """Retorna payloads de XSS padrão."""
        return [
            "<script>alert('xss-test-spectra')</script>",
            "<img src=x onerror=alert('xss-test-spectra')>",
            "<svg onload=alert('xss-test-spectra')>",
            "<iframe src=javascript:alert('xss-test-spectra')>",
            "<body onload=alert('xss-test-spectra')>",
            "<div onclick=alert('xss-test-spectra')>Click</div>",
            "<marquee onstart=alert('xss-test-spectra')>",
            "<video src=x onerror=alert('xss-test-spectra')>",
            "<audio src=x onerror=alert('xss-test-spectra')>",
            "<object data=javascript:alert('xss-test-spectra')>",
            "<embed src=javascript:alert('xss-test-spectra')>",
            "<base href=javascript:alert('xss-test-spectra')//>",
            "<link rel=stylesheet href=javascript:alert('xss-test-spectra')>",
            "<meta http-equiv=refresh content=0;url=javascript:alert('xss-test-spectra')>",
            "<form action=javascript:alert('xss-test-spectra')><input type=submit>",
            "<table background=javascript:alert('xss-test-spectra')>",
            "<td background=javascript:alert('xss-test-spectra')>",
            "<input type=image src=x onerror=alert('xss-test-spectra')>",
            "<button onclick=alert('xss-test-spectra')>Click</button>",
            "<select onfocus=alert('xss-test-spectra')>",
            "<textarea onfocus=alert('xss-test-spectra')>",
            "<keygen onfocus=alert('xss-test-spectra')>",
            "<details open ontoggle=alert('xss-test-spectra')>",
            "<summary onclick=alert('xss-test-spectra')>Click</summary>",
            # Payloads para contornos de filtros
            "' onmouseover=alert('xss-test-spectra') '",
            "\" onmouseover=alert('xss-test-spectra') \"",
            "' onfocus=alert('xss-test-spectra') '",
            "\" onfocus=alert('xss-test-spectra') \"",
            "' onclick=alert('xss-test-spectra') '",
            "\" onclick=alert('xss-test-spectra') \"",
            "javascript:alert('xss-test-spectra')",
            "';alert('xss-test-spectra');//",
            "\";alert('xss-test-spectra');//",
            "';alert('xss-test-spectra');var a='",
            "\";alert('xss-test-spectra');var a=\"",
            "</script><script>alert('xss-test-spectra')</script>",
            "/**/alert('xss-test-spectra')/**/",
            # Encoding bypasses
            "%3Cscript%3Ealert('xss-test-spectra')%3C/script%3E",
            "&#60;script&#62;alert('xss-test-spectra')&#60;/script&#62;",
            "&lt;script&gt;alert('xss-test-spectra')&lt;/script&gt;",
            # Case variation
            "<ScRiPt>alert('xss-test-spectra')</ScRiPt>",
            "<SCRIPT>alert('xss-test-spectra')</SCRIPT>",
            # Polyglot payloads
            "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert('xss-test-spectra')//'>",
            "\"'><img src=x onerror=alert('xss-test-spectra')>",
            "';alert('xss-test-spectra');//'><script>alert('xss-test-spectra')</script>",
            "\"><svg/onload=alert('xss-test-spectra')>",
            "*/alert('xss-test-spectra')/*"
        ]

    def _detect_context(self, response_text, payload):
        """Detecta o contexto onde o payload foi refletido."""
        contexts = []
        
        # Verifica se está em um script tag
        if re.search(r'<script[^>]*>.*?' + re.escape(payload) + r'.*?</script>', response_text, re.DOTALL | re.IGNORECASE):
            contexts.append('script')
        
        # Verifica se está em um atributo HTML
        attr_pattern = r'[a-zA-Z-]+\s*=\s*[\'"].*?' + re.escape(payload) + r'.*?[\'"]'
        if re.search(attr_pattern, response_text, re.IGNORECASE):
            contexts.append('attribute')
        
        # Verifica se está em um event handler
        event_pattern = r'on[a-zA-Z]+\s*=\s*[\'"].*?' + re.escape(payload) + r'.*?[\'"]'
        if re.search(event_pattern, response_text, re.IGNORECASE):
            contexts.append('event_handler')
        
        # Verifica se está em CSS
        css_pattern = r'<style[^>]*>.*?' + re.escape(payload) + r'.*?</style>'
        if re.search(css_pattern, response_text, re.DOTALL | re.IGNORECASE):
            contexts.append('css')
        
        # Verifica se está em URL (href, src, etc.)
        url_pattern = r'(?:href|src|action|formaction)\s*=\s*[\'"].*?' + re.escape(payload) + r'.*?[\'"]'
        if re.search(url_pattern, response_text, re.IGNORECASE):
            contexts.append('url')
        
        # Verifica se está em texto HTML normal
        if payload in response_text and not contexts:
            contexts.append('html_text')
        
        return contexts

    def _analyze_csp(self, response):
        """Analisa Content Security Policy se presente."""
        csp_header = response.headers.get('Content-Security-Policy', '')
        if not csp_header:
            csp_header = response.headers.get('Content-Security-Policy-Report-Only', '')
        
        if csp_header:
            csp_info = {
                'present': True,
                'header': csp_header,
                'allows_inline_script': "'unsafe-inline'" in csp_header or 'script-src' not in csp_header,
                'allows_eval': "'unsafe-eval'" in csp_header,
                'allows_data_uri': 'data:' in csp_header,
                'report_only': 'Content-Security-Policy-Report-Only' in response.headers
            }
            return csp_info
        
        return {'present': False}

    def _add_finding(self, risk, v_type, detail, recommendation):
        """Adiciona ou atualiza uma descoberta, priorizando XSS Armazenado."""
        # Verifica se uma descoberta para este 'detalhe' já existe
        for i, finding in enumerate(self.vulnerable_points):
            if finding["Detalhe"] == detail:
                # Se a nova descoberta for "Armazenado" e a existente não for, atualiza-a.
                if v_type == "XSS Armazenado" and finding["Tipo"] != "XSS Armazenado":
                    self.vulnerable_points[i].update({
                        "Risco": "Alto",
                        "Tipo": "XSS Armazenado",
                        "Recomendação": recommendation
                    })
                return  # Evita adicionar uma duplicada

        # Se não houver correspondência, adiciona a nova descoberta
        self.vulnerable_points.append({"Risco": risk, "Tipo": v_type, "Detalhe": detail, "Recomendação": recommendation})
        self.logger.info(f"Vulnerabilidade XSS detectada: {v_type} - {detail}")

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
                    progress.update(submission_task, advance=1, description=f"[green]Testando campo [cyan]{field_name}[/cyan]...")
                    
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

    def run_scan(self, return_findings=False):
        """Orquestra os diferentes tipos de scans de XSS."""
        if not return_findings:
            self.console.print("-" * 60)
            self.console.print(f"[*] Executando scanner de XSS em: [bold cyan]{self.base_url}[/bold cyan]")
            if self.scan_stored: 
                self.console.print("[*] Modo XSS Armazenado: [bold green]Ativado[/bold green]")
            if self.fuzz_dom: 
                self.console.print("[*] Modo XSS DOM: [bold green]Ativado[/bold green]")
            self.console.print("-" * 60)

        try:
            with self.console.status("[bold green]Coletando pontos de entrada...[/bold green]"):
                response = self.session.get(self.base_url, timeout=10, verify=False)
                soup = BeautifulSoup(response.content, 'html.parser')
        except requests.RequestException as e:
            if not return_findings: 
                self.console.print(f"[bold red][!] Não foi possível aceder à página inicial: {e}[/bold red]")
            return [] if return_findings else None

        # Coleta de tarefas (pontos de entrada)
        tasks = []
        links = {urljoin(self.base_url, a['href']) for a in soup.find_all('a', href=True) if '?' in a['href'] and '=' in a['href']}
        for link in links:
            parsed = urlparse(link)
            base = urlunparse(parsed._replace(query=""))
            for param in parse_qs(parsed.query): 
                tasks.append(('get', base, param, None))

        forms = soup.find_all('form')
        for form in forms:
            action = urljoin(self.base_url, form.get('action', ''))
            method = form.get('method', 'post').lower()
            data = {i.get('name'): 'test' for i in form.find_all(['input', 'textarea'], {'name': True})}
            for param in data: 
                tasks.append((method, action, param, data))
        
        if not tasks and not forms:
            if not return_findings: 
                self.console.print("[yellow]Nenhum ponto de entrada (parâmetro ou formulário) encontrado para testar XSS.[/yellow]")
            return [] if return_findings else None
        
        # Execução dos scans
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=self.console, transient=return_findings) as progress:
            # 1. Scan de XSS Refletido
            if tasks:
                self._scan_reflected(tasks, progress)

            # 2. Scan de XSS Armazenado (se ativado)
            if self.scan_stored and forms:
                post_forms = [form for form in forms if form.get('method', 'get').lower() == 'post']
                if post_forms:
                    self._inject_into_forms(post_forms, progress)
                    self._verify_storage(progress)

        if return_findings: 
            return self.vulnerable_points
        self._present_findings()

    def _present_findings(self):
        """Apresenta os resultados do scan de XSS."""
        self.console.print("-" * 60)
        if not self.vulnerable_points:
            self.console.print("[bold green][+] Nenhuma vulnerabilidade de XSS foi encontrada.[/bold green]")
        else:
            table = Table(title="Potenciais Vulnerabilidades de XSS Encontradas")
            table.add_column("Risco", style="cyan")
            table.add_column("Tipo", style="yellow")
            table.add_column("Detalhe", style="magenta")
            table.add_column("Recomendação", style="white")
            
            risk_order = {"Alto": 0, "Médio": 1, "Baixo": 2}
            sorted_findings = sorted(self.vulnerable_points, key=lambda x: risk_order.get(x["Risco"], 99))

            for f in sorted_findings:
                risk_style = "red" if f['Risco'] == 'Alto' else "yellow"
                table.add_row(f"[{risk_style}]{f['Risco']}[/{risk_style}]", f['Tipo'], f['Detalhe'], f['Recomendação'])
            self.console.print(table)
        self.console.print("-" * 60)


def xss_scan(url, custom_payloads_file=None, scan_stored=False, fuzz_dom=False, enable_bypasses=True, context_analysis=True, validate_execution=True, analyze_csp=True, verbose=False, return_findings=False):
    """
    Executa scan de XSS em uma URL.
    
    Args:
        url (str): URL alvo para o scan
        custom_payloads_file (str): Arquivo com payloads customizados
        scan_stored (bool): Ativar detecção de XSS armazenado
        fuzz_dom (bool): Ativar fuzzing de DOM XSS
        enable_bypasses (bool): Ativar técnicas de bypass
        context_analysis (bool): Ativar análise de contexto
        validate_execution (bool): Ativar validação de execução
        analyze_csp (bool): Ativar análise de CSP
        verbose (bool): Modo verbose
        return_findings (bool): Se True, retorna lista de vulnerabilidades ao invés de imprimir
    
    Returns:
        list ou None: Lista de vulnerabilidades encontradas se return_findings=True
    """
    scanner = XSSScanner(url, custom_payloads_file=custom_payloads_file, scan_stored=scan_stored, fuzz_dom=fuzz_dom)
    scanner.enable_bypasses = enable_bypasses
    scanner.context_analysis = context_analysis  
    scanner.validate_execution = validate_execution
    scanner.analyze_csp = analyze_csp
    scanner.verbose = verbose
    return scanner.run_scan(return_findings=return_findings)
