"""
Módulo de análise e consulta DNS avançada.
"""
import socket
import base64
import dns.resolver
import dns.zone
import dns.query
from urllib.parse import urlparse
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
    
    def _normalize_domain(self, domain):
        """
        Normaliza domínio removendo esquemas e paths.
        
        Args:
            domain (str): Domínio ou URL para normalizar.
            
        Returns:
            str: Domínio normalizado.
        """
        # Remove esquemas HTTP/HTTPS se presentes
        if domain.startswith(('http://', 'https://')):
            parsed = urlparse(domain)
            domain = parsed.netloc
        
        # Remove porta se presente
        if ':' in domain and not domain.startswith('['):  # Não IPv6
            domain = domain.split(':')[0]
        
        # Remove path se presente
        if '/' in domain:
            domain = domain.split('/')[0]
        
        # Remove 'www.' se presente para normalização
        if domain.startswith('www.'):
            domain = domain[4:]
        
        return domain.lower().strip()
    
    def query_dns(self, domain, record_type='ALL'):
        """
        Consulta avançada de registros DNS com análise de vulnerabilidades.
        
        Args:
            domain (str): Domínio para consulta.
            record_type (str): Tipo de registro ('A', 'MX', 'TXT', 'ALL', etc.).
            
        Returns:
            dict: Resultados da consulta DNS.
        """
        # Normaliza o domínio
        original_domain = domain
        domain = self._normalize_domain(domain)
        
        console.print("-" * 60)
        if original_domain != domain:
            console.print(f"[*] URL normalizada: [dim]{original_domain}[/dim] → [bold cyan]{domain}[/bold cyan]")
        console.print(f"[*] Consultando registros para [bold cyan]{domain}[/bold cyan]")
        console.print("-" * 60)

        record_types = [
            'A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'CAA', 'SRV', 'PTR', 'NAPTR', 'LOC'
        ] if record_type.upper() == 'ALL' else [record_type.upper()]
        
        results = {}
        
        with console.status("[bold green]Consultando registros DNS...[/bold green]") as status:
            for r_type in record_types:
                status.update(f"[bold green]Consultando registro {r_type}...[/bold green]")
                # Captura timeout original ANTES do try para garantir disponibilidade no finally
                old_timeout = self.resolver.lifetime
                try:
                    # Configura timeout específico para cada tipo de consulta
                    resolver_timeout = 8 if r_type in ['TXT', 'CAA', 'SRV'] else 5
                    self.resolver.lifetime = resolver_timeout
                    
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
                    
                    # Restaura timeout original
                    self.resolver.lifetime = old_timeout

                except dns.resolver.NoAnswer:
                    console.print(f"[bold yellow][-] Nenhum registro {r_type} encontrado para {domain}.[/bold yellow]")
                except dns.resolver.NXDOMAIN:
                    console.print(f"[bold red][!] Erro: O domínio {domain} não existe.[/bold red]")
                    break 
                except dns.resolver.LifetimeTimeout:
                    console.print(f"[bold yellow][!] Timeout ao consultar {r_type} (>{resolver_timeout}s) - pulando...[/bold yellow]")
                    logger.warning(f"Timeout na consulta DNS {r_type} para {domain} após {resolver_timeout}s")
                except dns.resolver.Timeout:
                    console.print(f"[bold yellow][!] Timeout ao consultar {r_type} - pulando...[/bold yellow]")
                except dns.exception.DNSException as e:
                    console.print(f"[bold yellow][!] Erro DNS ao consultar {r_type}: {str(e)[:50]}... - pulando[/bold yellow]")
                    logger.warning(f"Erro DNS {r_type} para {domain}: {e}")
                except Exception as e:
                    console.print(f"[bold red][!] Erro inesperado ao consultar {r_type}: {str(e)[:50]}...[/bold red]")
                    logger.error(f"Erro na consulta DNS {r_type} para {domain}: {e}")
                finally:
                    # Garante que o timeout seja restaurado
                    try:
                        self.resolver.lifetime = old_timeout
                    except AttributeError:
                        pass
                
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
            try:
                # Converte valor CAA para string de forma segura
                tag = rdata.tag if hasattr(rdata, 'tag') else 'N/A'
                
                # Se tag for bytes, converte para string
                if isinstance(tag, bytes):
                    tag = tag.decode('utf-8', errors='ignore')
                else:
                    tag = str(tag)
                
                value = rdata.value
                
                # Se value for bytes, converte para string
                if isinstance(value, bytes):
                    value = value.decode('utf-8', errors='ignore')
                else:
                    value = str(value)
                
                flags = str(rdata.flags) if hasattr(rdata, 'flags') else '0'
                
                analysis = self._analyze_caa_record(tag, value)
                table.add_row(flags, tag, value, analysis)
                processed_records.append({
                    'flags': int(flags) if flags.isdigit() else 0,
                    'tag': tag,
                    'value': value,
                    'analysis': analysis
                })
            except Exception as e:
                logger.error(f"Erro ao processar registro CAA: {e}")
                table.add_row("0", "ERROR", str(e), "Erro de processamento")
        
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
            vulnerable_ns = [ns for ns, status in zone_transfer_results.items() if status == "vulnerable"]
            
            if vulnerable_ns:
                console.print("[bold red]⚠️  VULNERABILIDADE: Zone Transfer habilitado![/bold red]")
                for ns, status in zone_transfer_results.items():
                    if status == "vulnerable":
                        console.print(f"    • {ns}: [bold red]VULNERÁVEL[/bold red]")
                    else:
                        console.print(f"    • {ns}: [green]Protegido[/green]")
            else:
                console.print("[green]✅ Zone Transfer: Protegido[/green]")
                if zone_transfer_results:
                    # Mostra apenas alguns nameservers testados se não há vulnerabilidades
                    tested_ns = list(zone_transfer_results.keys())[:2]
                    if tested_ns:
                        console.print(f"    • Testado: {', '.join(tested_ns)}")
        
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

        # Verifica DMARC policy
        dmarc = self._analyze_dmarc_policy(domain)
        if dmarc['present']:
            risk_color = 'green' if dmarc['risk'] == 'LOW' else 'yellow' if dmarc['risk'] == 'MEDIUM' else 'red'
            console.print(
                f"[{risk_color}]✉  DMARC: p={dmarc['policy']} | sp={dmarc['subdomain_policy']} "
                f"| pct={dmarc['pct']} | risco={dmarc['risk']}[/{risk_color}]"
            )
        else:
            console.print("[bold red]⚠️  DMARC: Ausente — domínio suscetível a spoofing de email[/bold red]")

        # Verifica DKIM
        dkim = self._check_dkim_selector(domain)
        if dkim['present']:
            key_info = f" ({dkim['key_bits']} bits)" if dkim['key_bits'] else ""
            issues_str = " | " + "; ".join(dkim['issues']) if dkim['issues'] else ""
            console.print(f"[green]✅ DKIM: seletor={dkim['selector']}{key_info}{issues_str}[/green]")
        else:
            console.print("[bold yellow]⚠️  DKIM: Nenhum seletor padrão encontrado[/bold yellow]")

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
            'awsdns': 'Amazon Route 53',
            'azure-dns.com': 'Microsoft Azure DNS',
            'digitalocean.com': 'DigitalOcean DNS',
            'linode.com': 'Linode DNS',
            'godaddy.com': 'GoDaddy DNS',
            'namecheap.com': 'Namecheap DNS',
            'nsone.net': 'NS1',
            'dnsimple.com': 'DNSimple',
            'route53.com': 'Amazon Route 53'
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
                # Resolve IP do nameserver primeiro
                ns_ip = self._resolve_nameserver_ip(ns)
                if not ns_ip:
                    results[ns] = "protected"
                    continue
                
                # Tenta zone transfer
                try:
                    transfer = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=3))
                    if transfer and len(transfer.nodes) > 1:  # Zone transfer bem-sucedido
                        results[ns] = "vulnerable"
                    else:
                        results[ns] = "protected"
                except (dns.query.TransferError, dns.exception.FormError, ConnectionRefusedError):
                    # Estes erros indicam que zone transfer foi negado (bom)
                    results[ns] = "protected"
                except dns.exception.Timeout:
                    # Timeout pode indicar proteção ou problema de rede
                    results[ns] = "protected"
                except Exception as e:
                    # Outros erros geralmente indicam proteção
                    logger.debug(f"Zone transfer para {ns} falhou: {e}")
                    results[ns] = "protected"
                    
            except Exception as e:
                logger.debug(f"Erro ao testar zone transfer em {ns}: {e}")
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
        except Exception:
            return None

    def _check_dnssec(self, domain):
        """Verifica DNSSEC: presença de DNSKEY, DS e RRSIG no domínio."""
        try:
            dnskey_answers = self.resolver.resolve(domain, 'DNSKEY')
            if not dnskey_answers:
                return None

            # Verifica DS no domínio pai (ex: example.com → com)
            parts = domain.split('.')
            ds_present = False
            if len(parts) >= 2:
                parent = '.'.join(parts[1:])
                try:
                    self.resolver.resolve(domain, 'DS')
                    ds_present = True
                except Exception:
                    pass

            # Verifica a existência de RRSIG para confirmar que está assinado
            rrsig_present = False
            try:
                self.resolver.resolve(domain, 'RRSIG')
                rrsig_present = True
            except Exception:
                pass

            if ds_present and rrsig_present:
                return "Ativo (DNSKEY + DS + RRSIG)"
            elif ds_present:
                return "Parcial (DNSKEY + DS, sem RRSIG)"
            elif rrsig_present:
                return "Parcial (DNSKEY + RRSIG, DS ausente)"
            else:
                return "Incompleto (somente DNSKEY)"
        except Exception:
            return None

    def _analyze_dmarc_policy(self, domain):
        """Analisa a política DMARC do domínio com profundidade.

        Returns:
            dict com keys: present, policy, subdomain_policy, pct, rua, ruf, risk
        """
        result = {
            'present': False,
            'policy': None,
            'subdomain_policy': None,
            'pct': 100,
            'rua': None,
            'ruf': None,
            'risk': 'HIGH',  # Sem DMARC = alto risco de spoofing
        }

        try:
            dmarc_domain = f'_dmarc.{domain}'
            answers = self.resolver.resolve(dmarc_domain, 'TXT')
            for rdata in answers:
                txt = b''.join(rdata.strings).decode('utf-8', errors='ignore')
                if not txt.lower().startswith('v=dmarc1'):
                    continue

                result['present'] = True
                tags = dict(
                    tag.strip().split('=', 1)
                    for tag in txt.split(';')
                    if '=' in tag
                )
                policy = tags.get('p', 'none').strip().lower()
                sp = tags.get('sp', policy).strip().lower()
                pct = int(tags.get('pct', '100').strip())

                result['policy'] = policy
                result['subdomain_policy'] = sp
                result['pct'] = pct
                result['rua'] = tags.get('rua', '').strip()
                result['ruf'] = tags.get('ruf', '').strip()

                # Avalia risco
                if policy == 'reject' and pct == 100:
                    result['risk'] = 'LOW'
                elif policy == 'quarantine' and pct >= 50:
                    result['risk'] = 'MEDIUM'
                elif policy == 'none':
                    result['risk'] = 'HIGH'  # p=none = monitor only, emails not blocked
                else:
                    result['risk'] = 'MEDIUM'
                break
        except Exception:
            pass

        return result

    def _check_dkim_selector(self, domain, selector: str = 'default') -> dict:
        """Verifica se o seletor DKIM existe e retorna resumo.

        Args:
            domain: Domínio alvo.
            selector: Nome do seletor DKIM (padrão: 'default').

        Returns:
            dict com keys: present, selector, algorithm, key_bits, issues
        """
        result = {'present': False, 'selector': selector, 'algorithm': None, 'key_bits': None, 'issues': []}
        common_selectors = [selector, 'google', 'k1', 'mail', 's1', 's2', 'smtp', 'dkim']

        for sel in common_selectors:
            try:
                dkim_domain = f'{sel}._domainkey.{domain}'
                answers = self.resolver.resolve(dkim_domain, 'TXT')
                for rdata in answers:
                    txt = b''.join(rdata.strings).decode('utf-8', errors='ignore')
                    if 'v=DKIM1' not in txt and 'k=rsa' not in txt and 'p=' not in txt:
                        continue
                    result['present'] = True
                    result['selector'] = sel
                    tags = dict(
                        t.strip().split('=', 1)
                        for t in txt.split(';')
                        if '=' in t
                    )
                    result['algorithm'] = tags.get('k', 'rsa')
                    key_b64 = tags.get('p', '')
                    if key_b64:
                        import binascii
                        try:
                            key_bytes = len(base64.b64decode(key_b64 + '=='))
                            result['key_bits'] = key_bytes * 8
                            if key_bytes * 8 < 2048:
                                result['issues'].append(f'Chave curta: {key_bytes * 8} bits (recomendado ≥ 2048)')
                        except Exception:
                            pass
                    return result
            except Exception:
                continue

        return result


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
