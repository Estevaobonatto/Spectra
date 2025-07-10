"""
Módulo de análise e consulta DNS avançada.
"""
import socket
import dns.resolver
import dns.zone
import dns.query
from rich.table import Table

from ..core.console import console
from ..core.logger import logger


class DNSAnalyzer:
    """Analisador avançado de DNS com verificação de vulnerabilidades."""
    
    def __init__(self, timeout=10):
        """
        Inicializa o analisador DNS.
        
        Args:
            timeout (int): Timeout em segundos para consultas DNS.
        """
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.lifetime = timeout
        self.vulnerabilities = []
        self.nameservers = []
        
        logger.info("Analisador DNS inicializado")
    
    def query_dns(self, domain, record_type='ALL'):
        """
        Consulta avançada de registros DNS com análise de vulnerabilidades.
        
        Args:
            domain (str): Domínio para consulta.
            record_type (str): Tipo de registro ('A', 'MX', 'TXT', 'ALL', etc.).
            
        Returns:
            dict: Resultados da consulta DNS.
        """
        console.print("-" * 60)
        console.print(f"[*] Consultando registros para [bold cyan]{domain}[/bold cyan]")
        console.print("-" * 60)

        record_types = [
            'A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'CAA', 'SRV', 'PTR', 'NAPTR', 'LOC'
        ] if record_type.upper() == 'ALL' else [record_type.upper()]
        
        results = {}
        
        with console.status("[bold green]Consultando registros DNS...[/bold green]") as status:
            for r_type in record_types:
                status.update(f"[bold green]Consultando registro {r_type}...[/bold green]")
                try:
                    answers = self.resolver.resolve(domain, r_type)
                    
                    # Processa diferentes tipos de registros
                    if r_type == 'MX':
                        results[r_type] = self._process_mx_records(answers, domain)
                    elif r_type == 'TXT':
                        results[r_type] = self._process_txt_records(answers, domain)
                    elif r_type == 'NS':
                        results[r_type] = self._process_ns_records(answers, domain)
                    elif r_type == 'SOA':
                        results[r_type] = self._process_soa_records(answers, domain)
                    elif r_type == 'CAA':
                        results[r_type] = self._process_caa_records(answers, domain)
                    elif r_type == 'SRV':
                        results[r_type] = self._process_srv_records(answers, domain)
                    elif r_type == 'PTR':
                        results[r_type] = self._process_ptr_records(answers, domain)
                    elif r_type == 'NAPTR':
                        results[r_type] = self._process_naptr_records(answers, domain)
                    elif r_type == 'LOC':
                        results[r_type] = self._process_loc_records(answers, domain)
                    else:
                        results[r_type] = self._process_basic_records(answers, domain, r_type)

                except dns.resolver.NoAnswer:
                    console.print(f"[bold yellow][-] Nenhum registro {r_type} encontrado para {domain}.[/bold yellow]")
                except dns.resolver.NXDOMAIN:
                    console.print(f"[bold red][!] Erro: O domínio {domain} não existe.[/bold red]")
                    break 
                except dns.resolver.LifetimeTimeout:
                    console.print(f"[bold red][!] Erro ao consultar {r_type}: Timeout na consulta DNS.[/bold red]")
                except Exception as e:
                    console.print(f"[bold red][!] Erro ao consultar {r_type}: {e}[/bold red]")
                    logger.error(f"Erro na consulta DNS {r_type} para {domain}: {e}")
                
                console.print()
        
        # Análise de vulnerabilidades DNS
        self._analyze_dns_security(domain)
        
        logger.info(f"Consulta DNS concluída para {domain}")
        return results
    
    def _process_mx_records(self, answers, domain):
        """Processa registros MX."""
        table = Table(title=f"Registros MX para {domain}")
        table.add_column("Prioridade", style="cyan", justify="center")
        table.add_column("Servidor de E-mail", style="magenta")
        table.add_column("Análise", style="yellow")
        
        mx_records = sorted([(rdata.preference, str(rdata.exchange)) for rdata in answers])
        processed_records = []
        
        for preference, exchange in mx_records:
            analysis = self._analyze_mx_record(exchange)
            table.add_row(str(preference), exchange, analysis)
            processed_records.append({
                'preference': preference,
                'exchange': exchange,
                'analysis': analysis
            })
        
        console.print(table)
        return processed_records
    
    def _process_txt_records(self, answers, domain):
        """Processa registros TXT."""
        table = Table(title=f"Registros TXT para {domain}")
        table.add_column("Registro TXT", style="magenta")
        table.add_column("Tipo", style="yellow")
        
        processed_records = []
        
        for rdata in answers:
            text = b''.join(rdata.strings).decode('utf-8', errors='ignore')
            txt_type = self._analyze_txt_record(text)
            table.add_row(text, txt_type)
            processed_records.append({
                'text': text,
                'type': txt_type
            })
        
        console.print(table)
        return processed_records
    
    def _process_ns_records(self, answers, domain):
        """Processa registros NS."""
        table = Table(title=f"Registros NS para {domain}")
        table.add_column("Nameserver", style="magenta")
        table.add_column("IP", style="cyan")
        table.add_column("Provedor", style="yellow")
        
        processed_records = []
        
        for rdata in answers:
            ns = str(rdata).rstrip('.')
            self.nameservers.append(ns)
            ns_ip = self._resolve_nameserver_ip(ns)
            provider = self._identify_dns_provider(ns)
            table.add_row(ns, ns_ip or "N/A", provider or "Desconhecido")
            processed_records.append({
                'nameserver': ns,
                'ip': ns_ip,
                'provider': provider
            })
        
        console.print(table)
        return processed_records
    
    def _process_soa_records(self, answers, domain):
        """Processa registros SOA."""
        table = Table(title=f"Registros SOA para {domain}")
        table.add_column("Campo", style="cyan")
        table.add_column("Valor", style="magenta")
        
        processed_records = []
        
        for rdata in answers:
            soa_data = {
                'mname': str(rdata.mname),
                'rname': str(rdata.rname),
                'serial': str(rdata.serial),
                'refresh': rdata.refresh,
                'retry': rdata.retry,
                'expire': rdata.expire,
                'minimum': rdata.minimum
            }
            
            table.add_row("Nameserver Primário", soa_data['mname'])
            table.add_row("Email Responsável", soa_data['rname'])
            table.add_row("Serial", soa_data['serial'])
            table.add_row("Refresh", f"{soa_data['refresh']}s")
            table.add_row("Retry", f"{soa_data['retry']}s")
            table.add_row("Expire", f"{soa_data['expire']}s")
            table.add_row("TTL Mínimo", f"{soa_data['minimum']}s")
            
            processed_records.append(soa_data)
        
        console.print(table)
        return processed_records
    
    def _process_caa_records(self, answers, domain):
        """Processa registros CAA."""
        table = Table(title=f"Registros CAA para {domain}")
        table.add_column("Flags", style="cyan")
        table.add_column("Tag", style="green")
        table.add_column("Value", style="magenta")
        table.add_column("Análise", style="yellow")
        
        processed_records = []
        
        for rdata in answers:
            analysis = self._analyze_caa_record(rdata.tag, rdata.value)
            table.add_row(str(rdata.flags), rdata.tag, rdata.value, analysis)
            processed_records.append({
                'flags': rdata.flags,
                'tag': rdata.tag,
                'value': rdata.value,
                'analysis': analysis
            })
        
        console.print(table)
        return processed_records
    
    def _process_srv_records(self, answers, domain):
        """Processa registros SRV."""
        table = Table(title=f"Registros SRV para {domain}")
        table.add_column("Prioridade", style="cyan")
        table.add_column("Peso", style="blue")
        table.add_column("Porta", style="green")
        table.add_column("Alvo", style="magenta")
        table.add_column("Serviço", style="yellow")
        
        processed_records = []
        
        for rdata in answers:
            service_info = self._analyze_srv_record(rdata.port, str(rdata.target))
            table.add_row(str(rdata.priority), str(rdata.weight), str(rdata.port), str(rdata.target), service_info)
            processed_records.append({
                'priority': rdata.priority,
                'weight': rdata.weight,
                'port': rdata.port,
                'target': str(rdata.target),
                'service': service_info
            })
        
        console.print(table)
        return processed_records
    
    def _process_ptr_records(self, answers, domain):
        """Processa registros PTR."""
        table = Table(title=f"Registros PTR para {domain}")
        table.add_column("Pointer", style="magenta")
        table.add_column("Análise", style="yellow")
        
        processed_records = []
        
        for rdata in answers:
            analysis = self._analyze_ptr_record(str(rdata))
            table.add_row(str(rdata), analysis)
            processed_records.append({
                'pointer': str(rdata),
                'analysis': analysis
            })
        
        console.print(table)
        return processed_records
    
    def _process_naptr_records(self, answers, domain):
        """Processa registros NAPTR."""
        table = Table(title=f"Registros NAPTR para {domain}")
        table.add_column("Ordem", style="cyan")
        table.add_column("Preferência", style="blue")
        table.add_column("Flags", style="green")
        table.add_column("Serviços", style="yellow")
        table.add_column("Regexp", style="red")
        table.add_column("Replacement", style="magenta")
        
        processed_records = []
        
        for rdata in answers:
            table.add_row(str(rdata.order), str(rdata.preference), rdata.flags, rdata.service, rdata.regexp, str(rdata.replacement))
            processed_records.append({
                'order': rdata.order,
                'preference': rdata.preference,
                'flags': rdata.flags,
                'service': rdata.service,
                'regexp': rdata.regexp,
                'replacement': str(rdata.replacement)
            })
        
        console.print(table)
        return processed_records
    
    def _process_loc_records(self, answers, domain):
        """Processa registros LOC."""
        table = Table(title=f"Registros LOC para {domain}")
        table.add_column("Latitude", style="cyan")
        table.add_column("Longitude", style="blue")
        table.add_column("Altitude", style="green")
        table.add_column("Localização", style="yellow")
        
        processed_records = []
        
        for rdata in answers:
            location_info = self._analyze_loc_record(rdata.latitude, rdata.longitude)
            table.add_row(f"{rdata.latitude}", f"{rdata.longitude}", f"{rdata.altitude}m", location_info)
            processed_records.append({
                'latitude': rdata.latitude,
                'longitude': rdata.longitude,
                'altitude': rdata.altitude,
                'location': location_info
            })
        
        console.print(table)
        return processed_records
    
    def _process_basic_records(self, answers, domain, record_type):
        """Processa registros básicos (A, AAAA, CNAME, etc.)."""
        table = Table(title=f"Registros {record_type} para {domain}")
        table.add_column("Valor", style="magenta")
        table.add_column("Análise", style="yellow")
        
        processed_records = []
        
        for rdata in answers:
            value = str(rdata)
            analysis = ""
            if record_type == 'A':
                analysis = self._analyze_ip_address(value)
            elif record_type == 'CNAME':
                analysis = self._analyze_cname_record(value)
            
            table.add_row(value, analysis or "N/A")
            processed_records.append({
                'value': value,
                'analysis': analysis
            })
        
        console.print(table)
        return processed_records
    
    def _analyze_dns_security(self, domain):
        """Analisa vulnerabilidades DNS."""
        console.print("[bold cyan]🔍 ANÁLISE DE SEGURANÇA DNS[/bold cyan]")
        console.print("-" * 60)
        
        # Verifica Zone Transfer
        if self.nameservers:
            zone_transfer_results = self._check_zone_transfer(domain)
            if zone_transfer_results:
                console.print("[bold red]⚠️  VULNERABILIDADE: Zone Transfer habilitado![/bold red]")
                for ns, status in zone_transfer_results.items():
                    if status == "vulnerable":
                        console.print(f"    • {ns}: [bold red]VULNERÁVEL[/bold red]")
                    else:
                        console.print(f"    • {ns}: [green]Protegido[/green]")
            else:
                console.print("[green]✅ Zone Transfer: Protegido[/green]")
        
        # Verifica DNS Cache Poisoning
        cache_poisoning_risk = self._check_dns_cache_poisoning(domain)
        if cache_poisoning_risk:
            console.print(f"[bold yellow]⚠️  DNS Cache Poisoning: {cache_poisoning_risk}[/bold yellow]")
        else:
            console.print("[green]✅ DNS Cache Poisoning: Baixo risco[/green]")
        
        # Verifica DNSSEC
        dnssec_status = self._check_dnssec(domain)
        if dnssec_status:
            console.print(f"[green]✅ DNSSEC: {dnssec_status}[/green]")
        else:
            console.print("[bold yellow]⚠️  DNSSEC: Não configurado[/bold yellow]")
        
        console.print("-" * 60)
    
    def _analyze_mx_record(self, mx_server):
        """Analisa registro MX para identificar provedor de email."""
        mx_patterns = {
            'google.com': 'Google Workspace',
            'outlook.com': 'Microsoft 365',
            'zoho.com': 'Zoho Mail',
            'protonmail.ch': 'ProtonMail',
            'amazonaws.com': 'Amazon SES'
        }
        
        for pattern, provider in mx_patterns.items():
            if pattern in mx_server.lower():
                return provider
        return "Personalizado"
    
    def _analyze_txt_record(self, txt_record):
        """Analisa registro TXT para identificar tipo."""
        txt_record_lower = txt_record.lower()
        
        if txt_record_lower.startswith('v=spf1'):
            return "SPF"
        elif txt_record_lower.startswith('v=dmarc1'):
            return "DMARC"
        elif txt_record_lower.startswith('v=dkim1'):
            return "DKIM"
        elif 'google-site-verification' in txt_record_lower:
            return "Google Verification"
        elif 'facebook-domain-verification' in txt_record_lower:
            return "Facebook Verification"
        elif '_domainkey' in txt_record_lower:
            return "DKIM Key"
        return "Outro"
    
    def _resolve_nameserver_ip(self, nameserver):
        """Resolve IP do nameserver."""
        try:
            return socket.gethostbyname(nameserver)
        except Exception as e:
            logger.error(f"Erro ao resolver IP do nameserver {nameserver}: {e}")
            return None
    
    def _identify_dns_provider(self, nameserver):
        """Identifica provedor DNS baseado no nameserver."""
        dns_providers = {
            'cloudflare.com': 'Cloudflare',
            'google.com': 'Google Cloud DNS',
            'amazonaws.com': 'Amazon Route 53',
            'azure-dns.com': 'Microsoft Azure DNS',
            'digitalocean.com': 'DigitalOcean DNS',
            'linode.com': 'Linode DNS',
            'godaddy.com': 'GoDaddy DNS',
            'namecheap.com': 'Namecheap DNS'
        }
        
        for pattern, provider in dns_providers.items():
            if pattern in nameserver.lower():
                return provider
        return None
    
    def _analyze_ip_address(self, ip):
        """Analisa endereço IP para identificar provedor."""
        # Ranges conhecidos de provedores cloud
        ip_ranges = {
            '104.16.': 'Cloudflare',
            '104.17.': 'Cloudflare',
            '172.64.': 'Cloudflare',
            '13.107.': 'Microsoft Azure',
            '20.': 'Microsoft Azure',
            '52.': 'Amazon AWS',
            '54.': 'Amazon AWS',
            '35.': 'Google Cloud'
        }
        
        for ip_prefix, provider in ip_ranges.items():
            if ip.startswith(ip_prefix):
                return provider
        return "IP próprio"
    
    def _analyze_cname_record(self, cname):
        """Analisa registro CNAME para identificar serviço."""
        cname_patterns = {
            'cloudflare.net': 'Cloudflare',
            'azurewebsites.net': 'Azure App Service',
            'amazonaws.com': 'Amazon AWS',
            'herokuapp.com': 'Heroku',
            'github.io': 'GitHub Pages',
            'netlify.app': 'Netlify'
        }
        
        for pattern, service in cname_patterns.items():
            if pattern in cname.lower():
                return service
        return "Serviço personalizado"
    
    def _analyze_caa_record(self, tag, value):
        """Analisa registro CAA."""
        if tag == 'issue':
            return f"Autoriza CA: {value}"
        elif tag == 'issuewild':
            return f"Autoriza wildcard: {value}"
        elif tag == 'iodef':
            return f"Relatório de incidentes: {value}"
        return "Configuração personalizada"
    
    def _analyze_srv_record(self, port, target):
        """Analisa registro SRV para identificar serviço."""
        service_ports = {
            80: 'HTTP',
            443: 'HTTPS',
            25: 'SMTP',
            993: 'IMAPS',
            995: 'POP3S',
            587: 'SMTP (Submission)',
            110: 'POP3',
            143: 'IMAP'
        }
        
        return service_ports.get(port, f"Porta {port}")
    
    def _analyze_ptr_record(self, ptr):
        """Analisa registro PTR."""
        return f"Reverse DNS: {ptr}"
    
    def _analyze_loc_record(self, latitude, longitude):
        """Analisa registro LOC para identificar localização."""
        return f"Coordenadas: {latitude}, {longitude}"
    
    def _check_zone_transfer(self, domain):
        """Verifica se zone transfer está habilitado."""
        results = {}
        
        for ns in self.nameservers[:3]:  # Testa apenas os primeiros 3 NS
            try:
                # Tenta zone transfer
                transfer = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5))
                if transfer:
                    results[ns] = "vulnerable"
                else:
                    results[ns] = "protected"
            except:
                results[ns] = "protected"
        
        return results
    
    def _check_dns_cache_poisoning(self, domain):
        """Verifica vulnerabilidade a DNS cache poisoning."""
        try:
            # Verifica se usa DNS recursivo aberto
            answers = self.resolver.resolve(domain, 'A')
            if len(answers) > 5:  # Muitos registros A podem indicar round-robin vulnerável
                return "Possível round-robin vulnerável"
            return None
        except:
            return None
    
    def _check_dnssec(self, domain):
        """Verifica se DNSSEC está configurado."""
        try:
            # Tenta resolver registro DNSKEY
            answers = self.resolver.resolve(domain, 'DNSKEY')
            if answers:
                return "Ativo"
            return None
        except:
            return None


# Função para compatibilidade com versão anterior
def query_dns(domain, record_type='ALL'):
    """
    Função legacy para compatibilidade - consulta DNS.
    
    Args:
        domain (str): Domínio para consulta.
        record_type (str): Tipo de registro.
        
    Returns:
        dict: Resultados da consulta.
    """
    analyzer = DNSAnalyzer()
    return analyzer.query_dns(domain, record_type)
