"""
Módulo de consulta WHOIS com análise de segurança.
"""
import socket
import ssl
import json
from datetime import datetime
import whois
from rich.table import Table

from ..core.console import console
from ..core.logger import logger


class WhoisAnalyzer:
    """Analisador WHOIS com verificação de segurança e threat intelligence."""
    
    def __init__(self, timeout=10):
        """
        Inicializa o analisador WHOIS.
        
        Args:
            timeout (int): Timeout em segundos para verificações de rede.
        """
        self.timeout = timeout
        self.whois_data = {}
        self.security_alerts = []
        self.threat_intel_results = {}
        self.blocklist_results = {}
        self.typosquatting_results = []
        
        logger.info("Analisador WHOIS inicializado")
    
    def get_whois_info(self, domain, verbose=False, output_format='table', 
                      security_analysis=False, threat_intel=False, 
                      check_blocklists=False, typosquatting_check=False):
        """
        Obtém e exibe informações WHOIS para um domínio com análise avançada de segurança.
        
        Args:
            domain (str): Domínio para consulta WHOIS.
            verbose (bool): Exibir informações detalhadas.
            output_format (str): Formato de saída ('table', 'json', 'xml').
            security_analysis (bool): Realizar análise de segurança.
            threat_intel (bool): Verificar threat intelligence.
            check_blocklists (bool): Verificar blocklists.
            typosquatting_check (bool): Verificar typosquatting.
            
        Returns:
            dict: Resultados da análise WHOIS.
        """
        console.print("-" * 60)
        console.print(f"[*] Obtendo informações WHOIS para: [bold cyan]{domain}[/bold cyan]")
        if verbose:
            console.print(f"[*] Análise de segurança: [bold cyan]{security_analysis}[/bold cyan]")
            console.print(f"[*] Threat Intelligence: [bold cyan]{threat_intel}[/bold cyan]")
            console.print(f"[*] Verificar blocklists: [bold cyan]{check_blocklists}[/bold cyan]")
            console.print(f"[*] Detecção typosquatting: [bold cyan]{typosquatting_check}[/bold cyan]")
            console.print(f"[*] Formato de saída: [bold cyan]{output_format}[/bold cyan]")
        console.print("-" * 60)
        
        # Reset dos resultados
        self.whois_data = {}
        self.security_alerts = []
        self.threat_intel_results = {}
        self.blocklist_results = {}
        self.typosquatting_results = []
        
        try:
            with console.status(f"[bold green]Consultando servidor WHOIS para {domain}...[/bold green]"):
                w = whois.whois(domain)

            if not w.domain_name:
                console.print(f"[bold yellow][-] Nenhuma informação WHOIS encontrada para {domain}.[/bold yellow]")
                return None

            # Processa dados WHOIS
            self._process_whois_data(w, domain)
            
            # Análises opcionais
            if security_analysis:
                self._analyze_security(w, verbose)
            
            if threat_intel:
                self._analyze_threat_intelligence(domain, verbose)
            
            if check_blocklists:
                self._check_blocklists(domain, verbose)
            
            if typosquatting_check:
                self._check_typosquatting(domain, verbose)
            
            # Exibe resultados
            self._display_results(w, domain, output_format)
            
            logger.info(f"Consulta WHOIS concluída para {domain}")
            
            return {
                'whois_data': self.whois_data,
                'security_alerts': self.security_alerts,
                'threat_intelligence': self.threat_intel_results,
                'blocklist_results': self.blocklist_results,
                'typosquatting_variants': self.typosquatting_results
            }

        except whois.parser.PywhoisError:
            console.print(f"[bold red][!] Erro: Não foi possível analisar a resposta WHOIS para '{domain}'. O domínio pode não ser válido ou o TLD não é suportado.[/bold red]")
            logger.error(f"Erro ao analisar resposta WHOIS para {domain}")
            return None
        except Exception as e:
            console.print(f"[bold red][!] Ocorreu um erro inesperado ao consultar o WHOIS: {e}[/bold red]")
            logger.error(f"Erro inesperado na consulta WHOIS para {domain}: {e}")
            return None
        finally:
            console.print("-" * 60)
    
    def _process_whois_data(self, w, domain):
        """Processa dados WHOIS básicos."""
        def get_date_obj(date_value):
            if not date_value:
                return None
            return date_value[0] if isinstance(date_value, list) else date_value

        creation_date = get_date_obj(w.creation_date)
        expiration_date = get_date_obj(w.expiration_date)
        updated_date = get_date_obj(w.updated_date)
        
        self.whois_data = {
            'domain': domain,
            'creation_date': creation_date.isoformat() if creation_date else None,
            'expiration_date': expiration_date.isoformat() if expiration_date else None,
            'updated_date': updated_date.isoformat() if updated_date else None,
            'registrar': w.registrar,
            'name_servers': w.name_servers,
            'status': w.status,
            'emails': w.emails,
            'country': getattr(w, 'country', None),
            'org': getattr(w, 'org', None),
            'registrant': getattr(w, 'registrant', None)
        }
    
    def _analyze_security(self, w, verbose):
        """Realiza análise de segurança dos dados WHOIS."""
        now = datetime.now()
        
        def get_date_obj(date_value):
            if not date_value:
                return None
            return date_value[0] if isinstance(date_value, list) else date_value

        creation_date = get_date_obj(w.creation_date)
        expiration_date = get_date_obj(w.expiration_date)
        updated_date = get_date_obj(w.updated_date)
        
        # 1. Verificar idade do domínio
        if creation_date:
            domain_age = (now - creation_date).days
            if domain_age < 30:
                self.security_alerts.append("🚨 Domínio muito recente (< 30 dias) - Possível ameaça")
            elif domain_age < 90:
                self.security_alerts.append("⚠️ Domínio recente (< 90 dias) - Monitorar")
            elif verbose:
                console.print(f"[bold green][✓][/bold green] Idade do domínio: {domain_age} dias")
        
        # 2. Verificar expiração próxima
        if expiration_date:
            days_to_expire = (expiration_date - now).days
            if days_to_expire < 30:
                self.security_alerts.append("🚨 Domínio expira em breve (< 30 dias)")
            elif days_to_expire < 90:
                self.security_alerts.append("⚠️ Domínio expira em menos de 90 dias")
            elif verbose:
                console.print(f"[bold green][✓][/bold green] Expira em: {days_to_expire} dias")
        
        # 3. Detectar Privacy Protection
        privacy_indicators = ['privacy', 'protection', 'private', 'redacted', 'whoisguard', 'domainsByProxy']
        has_privacy = False
        
        for field in [w.registrar, w.emails, getattr(w, 'org', ''), getattr(w, 'registrant', '')]:
            if field and any(indicator in str(field).lower() for indicator in privacy_indicators):
                has_privacy = True
                break
        
        if has_privacy:
            self.security_alerts.append("🔒 Privacy Protection detectada")
        elif verbose:
            console.print("[bold yellow][!][/bold yellow] Sem privacy protection - dados expostos")
        
        # 4. Verificar registrador suspeito
        suspicious_registrars = ['cheap', 'free', 'anonymous', 'hidden']
        if w.registrar and any(susp in str(w.registrar).lower() for susp in suspicious_registrars):
            self.security_alerts.append("⚠️ Registrador potencialmente suspeito")
        
        # 5. Verificar múltiplas atualizações recentes
        if updated_date and creation_date:
            if (now - updated_date).days < 7 and (now - creation_date).days > 30:
                self.security_alerts.append("🔄 Atualizado recentemente - Possível mudança de propriedade")
        
        # 6. Verificar status suspeito
        if w.status:
            status_str = str(w.status).lower()
            if 'hold' in status_str or 'suspended' in status_str:
                self.security_alerts.append("🚨 Status suspeito: Domínio em hold/suspended")
    
    def _analyze_threat_intelligence(self, domain, verbose):
        """Realiza verificação de threat intelligence."""
        if verbose:
            console.print("\n[bold blue][INFO][/bold blue] Consultando bases de threat intelligence...")
        
        try:
            # Verificar se domínio resolve
            try:
                ip = socket.gethostbyname(domain)
                self.threat_intel_results['ip'] = ip
                if verbose:
                    console.print(f"[bold green][✓][/bold green] Domínio resolve para: {ip}")
                
                # Verificar se IP está em ranges suspeitos
                suspicious_ranges = ['192.168.', '10.', '172.16.', '127.']
                if any(ip.startswith(range_) for range_ in suspicious_ranges):
                    self.security_alerts.append("⚠️ Domínio resolve para IP privado/local")
                
            except socket.gaierror:
                self.security_alerts.append("🚨 Domínio não resolve - Possível domínio morto")
                self.threat_intel_results['resolution'] = 'failed'
            
            # Verificar certificado SSL
            try:
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        self.threat_intel_results['ssl_cert'] = {
                            'subject': dict(x[0] for x in cert['subject']),
                            'issuer': dict(x[0] for x in cert['issuer']),
                            'expiry': cert['notAfter']
                        }
                        if verbose:
                            console.print(f"[bold green][✓][/bold green] Certificado SSL válido")
            except:
                self.security_alerts.append("⚠️ Sem certificado SSL válido")
                self.threat_intel_results['ssl'] = 'invalid'
                
        except Exception as e:
            if verbose:
                console.print(f"[bold yellow][W][/bold yellow] Erro na verificação de threat intelligence: {e}")
            logger.error(f"Erro na verificação de threat intelligence para {domain}: {e}")
    
    def _check_blocklists(self, domain, verbose):
        """Verifica domain/IP em blocklists."""
        if verbose:
            console.print("\n[bold blue][INFO][/bold blue] Verificando blocklists...")
        
        try:
            # Lista de servidores de blocklist para verificar
            blocklists = {
                'Spamhaus': 'zen.spamhaus.org',
                'SURBL': 'multi.surbl.org', 
                'URIBL': 'multi.uribl.com'
            }
            
            try:
                domain_ip = socket.gethostbyname(domain)
                reversed_ip = '.'.join(domain_ip.split('.')[::-1])
                
                for bl_name, bl_server in blocklists.items():
                    try:
                        query = f"{reversed_ip}.{bl_server}"
                        socket.gethostbyname(query)
                        self.security_alerts.append(f"🚨 BLOCKLIST: Encontrado em {bl_name}")
                        self.blocklist_results[bl_name] = 'listed'
                    except socket.gaierror:
                        self.blocklist_results[bl_name] = 'clean'
                        if verbose:
                            console.print(f"[bold green][✓][/bold green] Não listado em {bl_name}")
            
            except socket.gaierror:
                self.blocklist_results['error'] = 'domain_not_resolved'
                
        except Exception as e:
            if verbose:
                console.print(f"[bold yellow][W][/bold yellow] Erro na verificação de blocklists: {e}")
            logger.error(f"Erro na verificação de blocklists para {domain}: {e}")
    
    def _check_typosquatting(self, domain, verbose):
        """Verifica variações de typosquatting."""
        if verbose:
            console.print("\n[bold blue][INFO][/bold blue] Gerando variações para detecção de typosquatting...")
        
        try:
            variants = self._generate_typosquatting_variants(domain)
            registered_variants = []
            
            for variant in variants:
                try:
                    variant_whois = whois.whois(variant)
                    if variant_whois.domain_name:
                        registered_variants.append(variant)
                        if len(registered_variants) < 5:  # Mostrar apenas os primeiros 5
                            self.typosquatting_results.append(variant)
                            self.security_alerts.append(f"⚠️ TYPOSQUATTING: Variação registrada - {variant}")
                except:
                    pass  # Variação não registrada
            
            if verbose:
                console.print(f"[bold blue][INFO][/bold blue] Verificadas {len(variants)} variações, {len(registered_variants)} registradas")
                
        except Exception as e:
            if verbose:
                console.print(f"[bold yellow][W][/bold yellow] Erro na detecção de typosquatting: {e}")
            logger.error(f"Erro na detecção de typosquatting para {domain}: {e}")
    
    def _generate_typosquatting_variants(self, domain):
        """Gera variações comuns de typosquatting."""
        variants = set()
        domain_parts = domain.split('.')
        if len(domain_parts) < 2:
            return variants
        
        base_domain = domain_parts[0]
        tld = '.'.join(domain_parts[1:])
        
        # 1. Substituições de caracteres comuns
        common_subs = {
            'o': '0', '0': 'o', 'i': '1', '1': 'i', 'l': '1', 
            'e': '3', 'a': '@', 's': '$', 'g': '9'
        }
        
        for i, char in enumerate(base_domain):
            if char in common_subs:
                variant = base_domain[:i] + common_subs[char] + base_domain[i+1:]
                variants.add(f"{variant}.{tld}")
        
        # 2. Omissão de caracteres
        for i in range(len(base_domain)):
            if len(base_domain) > 3:  # Evitar domínios muito curtos
                variant = base_domain[:i] + base_domain[i+1:]
                variants.add(f"{variant}.{tld}")
        
        # 3. Duplicação de caracteres
        for i in range(len(base_domain)):
            variant = base_domain[:i] + base_domain[i] + base_domain[i:]
            variants.add(f"{variant}.{tld}")
        
        # 4. TLDs comuns
        common_tlds = ['com', 'org', 'net', 'info', 'biz']
        for tld_variant in common_tlds:
            variants.add(f"{base_domain}.{tld_variant}")
        
        return list(variants)[:20]  # Limitar a 20 variações
    
    def _display_results(self, w, domain, output_format):
        """Exibe resultados da análise WHOIS."""
        def format_date_entry(date_value):
            if not date_value:
                return "N/A"
            date_obj = date_value[0] if isinstance(date_value, list) else date_value
            now = datetime.now()
            delta = abs(now - date_obj)
            
            if delta.days > 365:
                years = delta.days // 365
                months = (delta.days % 365) // 30
                duration = f"{years} anos e {months} meses"
            else:
                duration = f"{delta.days} dias"
            
            if date_obj > now:
                return f"{date_obj.strftime('%Y-%m-%d')} ([bold green]em {duration}[/bold green])"
            else:
                return f"{date_obj.strftime('%Y-%m-%d')} ([bold blue]{duration} atrás[/bold blue])"

        if output_format == 'json':
            result = {
                'whois_data': self.whois_data,
                'security_alerts': self.security_alerts,
                'threat_intelligence': self.threat_intel_results,
                'blocklist_results': self.blocklist_results,
                'typosquatting_variants': self.typosquatting_results
            }
            console.print(json.dumps(result, indent=2, ensure_ascii=False))
        elif output_format == 'xml':
            console.print("<?xml version='1.0' encoding='UTF-8'?>")
            console.print("<whois_result>")
            console.print(f"  <domain>{domain}</domain>")
            for key, value in self.whois_data.items():
                if value:
                    console.print(f"  <{key}>{value}</{key}>")
            if self.security_alerts:
                console.print("  <security_alerts>")
                for alert in self.security_alerts:
                    console.print(f"    <alert>{alert}</alert>")
                console.print("  </security_alerts>")
            console.print("</whois_result>")
        else:
            # Formato tabela
            info_map = {
                "Domínio": w.domain_name,
                "Registrador": w.registrar,
                "Data de Criação": format_date_entry(w.creation_date),
                "Data de Expiração": format_date_entry(w.expiration_date),
                "Última Atualização": format_date_entry(w.updated_date),
                "Servidores de Nomes": w.name_servers,
                "Status": w.status,
                "E-mail (Admin)": w.emails,
                "País": getattr(w, 'country', None),
                "Organização": getattr(w, 'org', None),
                "Registrant": getattr(w, 'registrant', None)
            }
            
            table = Table(title=f"Informações WHOIS para {w.domain_name[0] if isinstance(w.domain_name, list) else w.domain_name}")
            table.add_column("Campo", style="cyan", no_wrap=True)
            table.add_column("Valor", style="magenta")

            for field, value in info_map.items():
                if value:
                    value_str = "\n".join(map(str, value)) if isinstance(value, list) else str(value)
                    table.add_row(field, value_str)
            
            console.print(table)
            
            # Exibir análise de segurança
            if self.security_alerts:
                console.print("\n[bold red]🛡️ Análise de Segurança[/bold red]")
                for alert in self.security_alerts:
                    console.print(f"  {alert}")
            elif hasattr(self, 'security_alerts'):
                console.print("\n[bold green]🛡️ Nenhum alerta de segurança detectado[/bold green]")
            
            # Exibir resultados de threat intelligence
            if self.threat_intel_results:
                console.print("\n[bold magenta]🔍 Threat Intelligence[/bold magenta]")
                if 'ip' in self.threat_intel_results:
                    console.print(f"  📍 IP: {self.threat_intel_results['ip']}")
                if 'ssl_cert' in self.threat_intel_results:
                    cert = self.threat_intel_results['ssl_cert']
                    console.print(f"  🔒 SSL Issuer: {cert['issuer'].get('organizationName', 'N/A')}")
                    console.print(f"  📅 SSL Expiry: {cert['expiry']}")
            
            # Exibir resultados de blocklists
            if self.blocklist_results:
                console.print("\n[bold yellow]📋 Verificação de Blocklists[/bold yellow]")
                for bl_name, status in self.blocklist_results.items():
                    if status == 'listed':
                        console.print(f"  🚨 {bl_name}: [bold red]LISTADO[/bold red]")
                    elif status == 'clean':
                        console.print(f"  ✅ {bl_name}: [bold green]Limpo[/bold green]")
            
            # Exibir resultados de typosquatting
            if self.typosquatting_results:
                console.print("\n[bold cyan]🎭 Variações Detectadas (Typosquatting)[/bold cyan]")
                for variant in self.typosquatting_results[:5]:  # Mostrar apenas os primeiros 5
                    console.print(f"  ⚠️ {variant}")
                if len(self.typosquatting_results) > 5:
                    console.print(f"  ... e {len(self.typosquatting_results) - 5} mais")


# Função para compatibilidade com versão anterior
def get_whois_info(domain, verbose=False, output_format='table', security_analysis=False, 
                  threat_intel=False, check_blocklists=False, typosquatting_check=False):
    """
    Função legacy para compatibilidade - consulta WHOIS.
    
    Args:
        domain (str): Domínio para consulta.
        verbose (bool): Exibir informações detalhadas.
        output_format (str): Formato de saída.
        security_analysis (bool): Análise de segurança.
        threat_intel (bool): Threat intelligence.
        check_blocklists (bool): Verificar blocklists.
        typosquatting_check (bool): Verificar typosquatting.
        
    Returns:
        dict: Resultados da análise.
    """
    analyzer = WhoisAnalyzer()
    return analyzer.get_whois_info(domain, verbose, output_format, security_analysis, 
                                  threat_intel, check_blocklists, typosquatting_check)
