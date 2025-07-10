"""
Módulo de scanner de subdomínios avançado com análise de segurança.
"""
import socket
import dns.resolver
import random
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
from rich.table import Table

from ..core.console import console
from ..core.logger import logger
from ..utils.network import create_session


class SubdomainScanner:
    """Scanner avançado de subdomínios com análise de segurança."""
    
    def __init__(self, domain, wordlist_path, workers=100):
        """
        Inicializa o scanner de subdomínios.
        
        Args:
            domain (str): Domínio alvo para scan.
            wordlist_path (str): Caminho para wordlist de subdomínios.
            workers (int): Número de threads para scan.
        """
        self.domain = domain
        self.wordlist_path = wordlist_path
        self.workers = workers
        self.found_subdomains = []
        self.takeover_risks = []
        self.wildcard_ip = None
        
        logger.info(f"Scanner de subdomínios inicializado para {domain}")
    
    def check_subdomain(self, subdomain):
        """
        Verifica se um subdomínio existe com análise avançada de DNS.
        
        Args:
            subdomain (str): Subdomínio para verificar.
            
        Returns:
            dict: Informações do subdomínio ou None se não existir.
        """
        if not subdomain:
            return None
        
        full_domain = f"{subdomain}.{self.domain}"
        
        try:
            # Resolução básica
            ip_address = socket.gethostbyname(full_domain)
            
            # Análise avançada de DNS
            dns_info = self._analyze_subdomain_dns(full_domain)
            
            return {
                'domain': full_domain,
                'ip': ip_address,
                'dns_info': dns_info,
                'status': 'active'
            }
        except (socket.gaierror, UnicodeEncodeError):
            return None
    
    def _analyze_subdomain_dns(self, domain):
        """
        Analisa registros DNS de um subdomínio.
        
        Args:
            domain (str): Domínio para análise.
            
        Returns:
            dict: Informações DNS do subdomínio.
        """
        dns_info = {
            'cname': None,
            'mx_records': [],
            'txt_records': [],
            'has_wildcard': False,
            'takeover_risk': False,
            'cloud_service': None
        }
        
        try:
            # Verifica CNAME
            try:
                cname_answer = dns.resolver.resolve(domain, 'CNAME')
                dns_info['cname'] = str(cname_answer[0]).rstrip('.')
                
                # Verifica potential subdomain takeover
                dns_info['takeover_risk'] = self._check_subdomain_takeover(dns_info['cname'])
                dns_info['cloud_service'] = self._identify_cloud_service(dns_info['cname'])
                
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            # Verifica MX records
            try:
                mx_answers = dns.resolver.resolve(domain, 'MX')
                dns_info['mx_records'] = [str(mx.exchange).rstrip('.') for mx in mx_answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            # Verifica TXT records
            try:
                txt_answers = dns.resolver.resolve(domain, 'TXT')
                dns_info['txt_records'] = [str(txt).strip('"') for txt in txt_answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
                
        except Exception as e:
            logger.error(f"Erro ao analisar DNS de {domain}: {e}")
        
        return dns_info
    
    def _check_subdomain_takeover(self, cname):
        """
        Verifica se um CNAME aponta para serviços vulneráveis a subdomain takeover.
        
        Args:
            cname (str): CNAME para verificar.
            
        Returns:
            bool: True se há risco de takeover.
        """
        if not cname:
            return False
        
        # Padrões conhecidos de subdomain takeover
        vulnerable_patterns = [
            'amazonaws.com',
            'azurewebsites.net',
            'herokuapp.com',
            'github.io',
            'netlify.app',
            'vercel.app',
            'surge.sh',
            'bitbucket.io',
            'gitlab.io',
            'wordpress.com',
            'tumblr.com',
            'shopify.com'
        ]
        
        return any(pattern in cname.lower() for pattern in vulnerable_patterns)
    
    def _identify_cloud_service(self, cname):
        """
        Identifica o serviço de cloud baseado no CNAME.
        
        Args:
            cname (str): CNAME para análise.
            
        Returns:
            str: Nome do serviço de cloud ou None.
        """
        if not cname:
            return None
        
        cloud_patterns = {
            'amazonaws.com': 'AWS',
            'azurewebsites.net': 'Azure',
            'googleapis.com': 'Google Cloud',
            'herokuapp.com': 'Heroku',
            'netlify.app': 'Netlify',
            'vercel.app': 'Vercel',
            'github.io': 'GitHub Pages',
            'cloudflare.net': 'Cloudflare',
            'fastly.com': 'Fastly'
        }
        
        for pattern, service in cloud_patterns.items():
            if pattern in cname.lower():
                return service
        
        return None
    
    def _check_dns_wildcard(self):
        """
        Verifica se o domínio tem wildcard DNS configurado.
        
        Returns:
            str: IP do wildcard ou None.
        """
        # Gera subdomínio aleatório
        random_subdomain = ''.join(random.choices(string.ascii_lowercase + string.digits, k=20))
        test_domain = f"{random_subdomain}.{self.domain}"
        
        try:
            ip_address = socket.gethostbyname(test_domain)
            return ip_address  # Retorna IP do wildcard
        except (socket.gaierror, UnicodeEncodeError):
            return None  # Sem wildcard
    
    def _load_wordlist(self):
        """
        Carrega wordlist de subdomínios.
        
        Returns:
            list: Lista de subdomínios para testar.
        """
        try:
            with open(self.wordlist_path, 'r', errors='ignore') as f:
                subdomains = [
                    line.strip() for line in f 
                    if line.strip() and not line.startswith('#') and line.strip() not in ('.', '..')
                ]
            return subdomains
        except FileNotFoundError:
            console.print(f"[bold red][!] Erro: O ficheiro da wordlist '{self.wordlist_path}' não foi encontrado.[/bold red]")
            logger.error(f"Wordlist não encontrada: {self.wordlist_path}")
            return []
    
    def discover_subdomains(self):
        """
        Executa a varredura avançada de subdomínios com análise de segurança.
        
        Returns:
            list: Lista de subdomínios encontrados.
        """
        console.print("-" * 60)
        console.print(f"[*] Domínio Alvo: [bold cyan]{self.domain}[/bold cyan]")
        console.print(f"[*] Wordlist: [bold cyan]{self.wordlist_path}[/bold cyan]")
        console.print("-" * 60)
        
        # Primeiro verifica wildcard DNS
        self.wildcard_ip = self._check_dns_wildcard()
        if self.wildcard_ip:
            console.print(f"[bold yellow][!] Wildcard DNS detectado: {self.wildcard_ip}[/bold yellow]")
            console.print("[*] Continuando varredura com filtro de wildcard...")
        
        # Carrega wordlist
        subdomains = self._load_wordlist()
        if not subdomains:
            return []
        
        console.print(f"[*] A iniciar a varredura com {len(subdomains)} palavras...")
        
        # Executa scan em paralelo
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            future_to_subdomain = {
                executor.submit(self.check_subdomain, sub): sub 
                for sub in subdomains
            }
            
            with Progress(
                SpinnerColumn(), 
                TextColumn("[progress.description]{task.description}"), 
                BarColumn(), 
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), 
                TimeRemainingColumn(), 
                console=console
            ) as progress:
                task = progress.add_task("[green]Buscando Subdomínios...", total=len(subdomains))
                
                for future in as_completed(future_to_subdomain):
                    result = future.result()
                    if result:
                        # Filtra wildcard se necessário
                        if self.wildcard_ip and result['ip'] == self.wildcard_ip:
                            progress.update(task, advance=1)
                            continue
                        
                        # Exibe resultado com informações avançadas
                        status_info = []
                        if result['dns_info']['cloud_service']:
                            status_info.append(f"[blue]{result['dns_info']['cloud_service']}[/blue]")
                        if result['dns_info']['takeover_risk']:
                            status_info.append("[bold red]TAKEOVER RISK[/bold red]")
                            self.takeover_risks.append(result)
                        if result['dns_info']['cname']:
                            status_info.append(f"CNAME: {result['dns_info']['cname']}")
                        
                        status_str = f" ({' | '.join(status_info)})" if status_info else ""
                        console.print(f"[bold green][+] {result['domain']} -> {result['ip']}{status_str}[/bold green]")
                        self.found_subdomains.append(result)
                    
                    progress.update(task, advance=1)
        
        # Exibe resultados
        self._display_results()
        
        logger.info(f"Scan de subdomínios concluído: {len(self.found_subdomains)} encontrados")
        return self.found_subdomains
    
    def _display_results(self):
        """Exibe resultados da varredura."""
        console.print("-" * 60)
        console.print("[*] Varredura de subdomínios concluída.")
        
        if self.found_subdomains:
            # Tabela principal de subdomínios
            table = Table(title=f"Relatório de Subdomínios para {self.domain}")
            table.add_column("Subdomínio", style="cyan")
            table.add_column("IP", style="magenta")
            table.add_column("Cloud Service", style="blue")
            table.add_column("CNAME", style="yellow")
            table.add_column("Status", style="green")
            
            for result in sorted(self.found_subdomains, key=lambda x: x['domain']):
                cloud_service = result['dns_info']['cloud_service'] or 'N/A'
                cname = result['dns_info']['cname'] or 'N/A'
                status = "🔴 TAKEOVER RISK" if result['dns_info']['takeover_risk'] else "✅ OK"
                
                table.add_row(result['domain'], result['ip'], cloud_service, cname, status)
            
            console.print(table)
            
            # Relatório de segurança
            if self.takeover_risks:
                console.print("\n[bold red]⚠️  ALERTAS DE SEGURANÇA[/bold red]")
                risk_table = Table(title="Subdomínios com Risco de Takeover")
                risk_table.add_column("Subdomínio", style="red")
                risk_table.add_column("CNAME Vulnerável", style="yellow")
                risk_table.add_column("Serviço", style="blue")
                
                for risk in self.takeover_risks:
                    risk_table.add_row(
                        risk['domain'],
                        risk['dns_info']['cname'],
                        risk['dns_info']['cloud_service'] or 'Desconhecido'
                    )
                
                console.print(risk_table)
                console.print("[bold red]⚠️  RECOMENDAÇÃO: Verificar se estes subdomínios estão ativos nos serviços de destino[/bold red]")
            
            # Estatísticas
            console.print(f"\n[*] Total encontrado: [bold cyan]{len(self.found_subdomains)}[/bold cyan] subdomínios")
            cloud_services = {}
            for result in self.found_subdomains:
                service = result['dns_info']['cloud_service']
                if service:
                    cloud_services[service] = cloud_services.get(service, 0) + 1
            
            if cloud_services:
                console.print("[*] Serviços de cloud detectados:")
                for service, count in cloud_services.items():
                    console.print(f"    • {service}: {count} subdomínio(s)")
                    
        else:
            console.print(f"[bold yellow][-] Nenhum subdomínio encontrado com esta wordlist.[/bold yellow]")
        
        console.print("-" * 60)
    
    def get_takeover_risks(self):
        """
        Retorna subdomínios com risco de takeover.
        
        Returns:
            list: Lista de subdomínios com risco.
        """
        return self.takeover_risks
    
    def export_results(self, output_format='json'):
        """
        Exporta resultados em formato especificado.
        
        Args:
            output_format (str): Formato de saída ('json', 'csv', 'txt').
            
        Returns:
            str: Dados formatados.
        """
        if output_format == 'json':
            import json
            return json.dumps({
                'domain': self.domain,
                'found_subdomains': self.found_subdomains,
                'takeover_risks': self.takeover_risks,
                'wildcard_ip': self.wildcard_ip
            }, indent=2)
        
        elif output_format == 'csv':
            import csv
            from io import StringIO
            
            output = StringIO()
            writer = csv.writer(output)
            writer.writerow(['Subdomain', 'IP', 'CNAME', 'Cloud Service', 'Takeover Risk'])
            
            for result in self.found_subdomains:
                writer.writerow([
                    result['domain'],
                    result['ip'],
                    result['dns_info']['cname'] or '',
                    result['dns_info']['cloud_service'] or '',
                    'YES' if result['dns_info']['takeover_risk'] else 'NO'
                ])
            
            return output.getvalue()
        
        elif output_format == 'txt':
            lines = [f"Subdomain scan results for {self.domain}"]
            lines.append("=" * 50)
            
            for result in self.found_subdomains:
                lines.append(f"{result['domain']} -> {result['ip']}")
                if result['dns_info']['cname']:
                    lines.append(f"  CNAME: {result['dns_info']['cname']}")
                if result['dns_info']['cloud_service']:
                    lines.append(f"  Cloud: {result['dns_info']['cloud_service']}")
                if result['dns_info']['takeover_risk']:
                    lines.append(f"  ⚠️  TAKEOVER RISK")
                lines.append("")
            
            return '\n'.join(lines)
        
        return ""


# Funções para compatibilidade com versão anterior
def check_subdomain(subdomain, domain):
    """
    Função legacy para compatibilidade - verifica um subdomínio.
    
    Args:
        subdomain (str): Subdomínio para verificar.
        domain (str): Domínio base.
        
    Returns:
        dict: Informações do subdomínio ou None.
    """
    scanner = SubdomainScanner(domain, None)
    return scanner.check_subdomain(subdomain)


def discover_subdomains(domain, wordlist_path, workers=100):
    """
    Função legacy para compatibilidade - executa scan de subdomínios.
    
    Args:
        domain (str): Domínio alvo.
        wordlist_path (str): Caminho para wordlist.
        workers (int): Número de workers.
        
    Returns:
        list: Lista de subdomínios encontrados.
    """
    scanner = SubdomainScanner(domain, wordlist_path, workers)
    return scanner.discover_subdomains()
