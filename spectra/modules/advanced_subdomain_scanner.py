"""
Módulo de scanner de subdomínios avançado - Inspirado nas melhores ferramentas.
Combina técnicas do Subfinder, Amass, Assetfinder e Findomain.
"""

import asyncio
import aiohttp
import aiodns
import time
import json
import re
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass, asdict
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from ..core.console import console, print_info, print_success, print_warning, print_error, print_separator, create_table, create_progress
from ..core.logger import get_logger
from .technology_detector import AdvancedTechnologyDetector


@dataclass
class SubdomainResult:
    """Estrutura de dados para resultado de subdomain."""
    domain: str
    ip: str
    ipv6: Optional[str] = None
    cname: Optional[str] = None
    mx_records: List[str] = None
    txt_records: List[str] = None
    cloud_service: Optional[str] = None
    takeover_risk: bool = False
    takeover_verified: bool = False
    takeover_service: Optional[str] = None
    open_ports: List[int] = None
    technologies: List[str] = None
    source: str = "dns"
    response_time: float = 0.0
    
    def __post_init__(self):
        if self.mx_records is None:
            self.mx_records = []
        if self.txt_records is None:
            self.txt_records = []
        if self.open_ports is None:
            self.open_ports = []
        if self.technologies is None:
            self.technologies = []


class RateLimiter:
    """Rate limiter adaptativo para diferentes tipos de requests."""
    
    def __init__(self):
        self.delays = {
            'dns_queries': 0.1,
            'api_requests': 1.0,
            'certificate_logs': 0.5,
            'web_scraping': 2.0,
            'takeover_verification': 1.5
        }
        self.error_rates = {key: 0.0 for key in self.delays}
        self.last_requests = {key: [] for key in self.delays}
        
    async def wait(self, source_type: str):
        """Aplica delay baseado no tipo de source e taxa de erro."""
        current_time = time.time()
        
        # Remove requests antigos (janela de 60 segundos)
        self.last_requests[source_type] = [
            req_time for req_time in self.last_requests[source_type]
            if current_time - req_time < 60
        ]
        
        delay = self.delays.get(source_type, 1.0)
        
        # Ajusta delay baseado na taxa de erro
        if self.error_rates[source_type] > 0.3:
            delay *= 2
        elif self.error_rates[source_type] > 0.5:
            delay *= 4
            
        await asyncio.sleep(delay)
        self.last_requests[source_type].append(current_time)
    
    def record_error(self, source_type: str):
        """Registra erro para ajustar rate limiting."""
        if source_type in self.error_rates:
            self.error_rates[source_type] = min(1.0, self.error_rates[source_type] + 0.1)
    
    def record_success(self, source_type: str):
        """Registra sucesso para ajustar rate limiting."""
        if source_type in self.error_rates:
            self.error_rates[source_type] = max(0.0, self.error_rates[source_type] - 0.05)


class CertificateTransparency:
    """Integração com Certificate Transparency logs."""
    
    def __init__(self, session: aiohttp.ClientSession, rate_limiter: RateLimiter):
        self.session = session
        self.rate_limiter = rate_limiter
        self.logger = get_logger(__name__)
    
    async def query_crt_sh(self, domain: str) -> Set[str]:
        """Query crt.sh para certificados."""
        subdomains = set()
        
        try:
            await self.rate_limiter.wait('certificate_logs')
            
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            
            async with self.session.get(url, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for cert in data:
                        # Extrai subdomains do name_value
                        names = cert.get('name_value', '').split('\\n')
                        for name in names:
                            name = name.strip().lower()
                            if name and name.endswith(f'.{domain}'):
                                # Remove wildcards
                                if name.startswith('*.'):
                                    name = name[2:]
                                if self._is_valid_subdomain(name, domain):
                                    subdomains.add(name)
                    
                    self.rate_limiter.record_success('certificate_logs')
                else:
                    self.rate_limiter.record_error('certificate_logs')
                    
        except Exception as e:
            self.logger.debug(f"Erro no crt.sh para {domain}: {e}")
            self.rate_limiter.record_error('certificate_logs')
        
        return subdomains
    
    async def query_censys(self, domain: str, api_key: Optional[str] = None) -> Set[str]:
        """Query Censys certificates API."""
        if not api_key:
            return set()
            
        subdomains = set()
        
        try:
            await self.rate_limiter.wait('api_requests')
            
            # Censys Search API v2
            url = "https://search.censys.io/api/v2/certificates/search"
            headers = {"Authorization": f"Bearer {api_key}"}
            
            query_data = {
                "q": f"names: *.{domain}",
                "per_page": 100
            }
            
            async with self.session.post(url, headers=headers, json=query_data, timeout=15) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for cert in data.get('result', {}).get('hits', []):
                        names = cert.get('names', [])
                        for name in names:
                            name = name.strip().lower()
                            if name.endswith(f'.{domain}'):
                                if name.startswith('*.'):
                                    name = name[2:]
                                if self._is_valid_subdomain(name, domain):
                                    subdomains.add(name)
                    
                    self.rate_limiter.record_success('api_requests')
                else:
                    self.rate_limiter.record_error('api_requests')
                    
        except Exception as e:
            self.logger.debug(f"Erro no Censys para {domain}: {e}")
            self.rate_limiter.record_error('api_requests')
        
        return subdomains
    
    def _is_valid_subdomain(self, subdomain: str, domain: str) -> bool:
        """Valida se é um subdomain válido."""
        if not subdomain or subdomain == domain:
            return False
        
        # Remove wildcard prefixes
        if subdomain.startswith('*.'):
            subdomain = subdomain[2:]
        
        # Verifica se termina com o domínio
        if not subdomain.endswith(f'.{domain}'):
            return False
        
        # Extrai apenas o subdomain
        subdomain_part = subdomain[:-len(f'.{domain}')]
        
        # Valida caracteres
        if not re.match(r'^[a-zA-Z0-9\-\.]+$', subdomain_part):
            return False
        
        # Evita subdomains muito longos ou inválidos
        if len(subdomain_part) > 63 or len(subdomain) > 253:
            return False
        
        return True


class PermutationEngine:
    """Engine para gerar permutações inteligentes de subdomains."""
    
    def __init__(self):
        self.prefixes = [
            'www', 'api', 'dev', 'test', 'staging', 'stage', 'prod', 'production',
            'admin', 'administrator', 'root', 'mail', 'email', 'smtp', 'pop', 'imap',
            'ftp', 'sftp', 'ssh', 'vpn', 'portal', 'app', 'mobile', 'web', 'webapp',
            'cdn', 'static', 'assets', 'media', 'img', 'images', 'upload', 'downloads',
            'blog', 'news', 'forum', 'chat', 'support', 'help', 'docs', 'documentation',
            'demo', 'beta', 'alpha', 'preview', 'sandbox', 'internal', 'intranet',
            'secure', 'ssl', 'shop', 'store', 'payment', 'pay', 'billing', 'invoice'
        ]
        
        self.suffixes = [
            'dev', 'test', 'staging', 'stage', 'prod', 'production', 'live',
            'old', 'new', 'backup', 'bak', 'temp', 'tmp', 'internal', 'external',
            'public', 'private', 'secure', 'v1', 'v2', 'v3', 'api', 'web'
        ]
        
        self.separators = ['-', '_', '.']
        self.numbers = ['1', '2', '3', '01', '02', '03', '001', '002', '003']
    
    def generate_permutations(self, base_subdomains: Set[str], domain: str) -> Set[str]:
        """Gera permutações inteligentes baseadas nos subdomains encontrados."""
        permutations = set()
        
        for subdomain in base_subdomains:
            # Remove o domínio para obter apenas a parte do subdomain
            if f'.{domain}' in subdomain:
                sub_part = subdomain.replace(f'.{domain}', '')
            else:
                sub_part = subdomain
            
            # Permutações com prefixos
            for prefix in self.prefixes:
                for sep in self.separators:
                    new_sub = f"{prefix}{sep}{sub_part}.{domain}"
                    permutations.add(new_sub)
            
            # Permutações com sufixos
            for suffix in self.suffixes:
                for sep in self.separators:
                    new_sub = f"{sub_part}{sep}{suffix}.{domain}"
                    permutations.add(new_sub)
            
            # Permutações com números
            for num in self.numbers:
                new_sub = f"{sub_part}{num}.{domain}"
                permutations.add(new_sub)
                new_sub = f"{sub_part}-{num}.{domain}"
                permutations.add(new_sub)
        
        # Adiciona permutações básicas do domínio principal
        for prefix in self.prefixes[:20]:  # Top 20 mais comuns
            permutations.add(f"{prefix}.{domain}")
        
        return permutations


class TakeoverVerifier:
    """Verificador real de subdomain takeover."""
    
    def __init__(self, session: aiohttp.ClientSession, rate_limiter: RateLimiter):
        self.session = session
        self.rate_limiter = rate_limiter
        self.logger = get_logger(__name__)
        
        # Assinaturas reais de takeover por serviço
        self.takeover_signatures = {
            'github.io': [
                'There isn\'t a GitHub Pages site here.',
                'For root URLs (like http://example.com/) you must provide an index.html file'
            ],
            'herokuapp.com': [
                'No such app',
                'heroku-router'
            ],
            'netlify.app': [
                'Not Found',
                'Page not found'
            ],
            'netlify.com': [
                'Not Found',
                'Page not found'
            ],
            'azurewebsites.net': [
                'Web Site not found',
                'Error 404'
            ],
            'wordpress.com': [
                'Domain mapping upgrade for this domain not found'
            ],
            'tumblr.com': [
                'Whatever you were looking for doesn\'t currently exist at this address'
            ],
            'surge.sh': [
                'project not found'
            ],
            'bitbucket.io': [
                'Repository not found'
            ],
            'gitlab.io': [
                'The page you\'re looking for could not be found'
            ],
            'shopify.com': [
                'Sorry, this shop is currently unavailable'
            ],
            'unbounce.com': [
                'The requested URL was not found on this server'
            ],
            'tilda.ws': [
                'Domain has been assigned'
            ]
        }
    
    async def verify_takeover(self, subdomain: str, cname: Optional[str]) -> Tuple[bool, Optional[str]]:
        """Verifica se subdomain takeover é realmente possível."""
        if not cname:
            return False, None
        
        # Identifica o serviço baseado no CNAME
        service = None
        for pattern in self.takeover_signatures.keys():
            if pattern in cname.lower():
                service = pattern
                break
        
        if not service:
            return False, None
        
        try:
            await self.rate_limiter.wait('takeover_verification')
            
            # Tenta HTTP e HTTPS
            for protocol in ['http', 'https']:
                try:
                    url = f"{protocol}://{subdomain}"
                    
                    async with self.session.get(
                        url, 
                        timeout=10,
                        allow_redirects=True,
                        ssl=False if protocol == 'http' else None
                    ) as response:
                        
                        content = await response.text()
                        
                        # Verifica assinaturas específicas do serviço
                        for signature in self.takeover_signatures[service]:
                            if signature.lower() in content.lower():
                                self.rate_limiter.record_success('takeover_verification')
                                return True, service
                        
                except Exception:
                    continue
            
            self.rate_limiter.record_success('takeover_verification')
            
        except Exception as e:
            self.logger.debug(f"Erro na verificação de takeover para {subdomain}: {e}")
            self.rate_limiter.record_error('takeover_verification')
        
        return False, None


class AsyncDNSResolver:
    """Resolver DNS assíncrono avançado."""
    
    def __init__(self, max_concurrent: int = 1000):
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.resolver = aiodns.DNSResolver(timeout=5, tries=2)
        self.logger = get_logger(__name__)
        self.rate_limiter = RateLimiter()
    
    async def resolve_subdomain(self, subdomain: str) -> Optional[SubdomainResult]:
        """Resolve um subdomain com análise completa."""
        async with self.semaphore:
            try:
                await self.rate_limiter.wait('dns_queries')
                start_time = time.time()
                
                result = SubdomainResult(domain=subdomain, ip="", source="dns")
                
                # Resolve A record (IPv4)
                try:
                    a_records = await self.resolver.query(subdomain, 'A')
                    if a_records:
                        result.ip = str(a_records[0].host)
                except Exception:
                    return None
                
                # Resolve AAAA record (IPv6)
                try:
                    aaaa_records = await self.resolver.query(subdomain, 'AAAA')
                    if aaaa_records:
                        result.ipv6 = str(aaaa_records[0].host)
                except Exception:
                    pass
                
                # Resolve CNAME
                try:
                    cname_records = await self.resolver.query(subdomain, 'CNAME')
                    if cname_records:
                        result.cname = str(cname_records[0].cname).rstrip('.')
                        result.cloud_service = self._identify_cloud_service(result.cname)
                        result.takeover_risk = self._check_takeover_patterns(result.cname)
                except Exception:
                    pass
                
                # Resolve MX
                try:
                    mx_records = await self.resolver.query(subdomain, 'MX')
                    result.mx_records = [str(mx.host).rstrip('.') for mx in mx_records]
                except Exception:
                    pass
                
                # Resolve TXT
                try:
                    txt_records = await self.resolver.query(subdomain, 'TXT')
                    result.txt_records = [txt.text.decode() if isinstance(txt.text, bytes) else str(txt.text) for txt in txt_records]
                except Exception:
                    pass
                
                result.response_time = time.time() - start_time
                self.rate_limiter.record_success('dns_queries')
                
                return result
                
            except Exception as e:
                self.rate_limiter.record_error('dns_queries')
                self.logger.debug(f"Erro resolvendo {subdomain}: {e}")
                return None
    
    def _identify_cloud_service(self, cname: str) -> Optional[str]:
        """Identifica serviço de cloud baseado no CNAME."""
        if not cname:
            return None
        
        cloud_patterns = {
            'amazonaws.com': 'AWS',
            'awsdns': 'AWS',
            'cloudfront.net': 'AWS CloudFront',
            'elb.amazonaws.com': 'AWS ELB',
            'azurewebsites.net': 'Azure',
            'azure.com': 'Azure',
            'googleapis.com': 'Google Cloud',
            'googleusercontent.com': 'Google Cloud',
            'gcp.': 'Google Cloud',
            'herokuapp.com': 'Heroku',
            'netlify.app': 'Netlify',
            'netlify.com': 'Netlify',
            'vercel.app': 'Vercel',
            'vercel.com': 'Vercel',
            'github.io': 'GitHub Pages',
            'github.com': 'GitHub',
            'cloudflare.net': 'Cloudflare',
            'cloudflare.com': 'Cloudflare',
            'fastly.com': 'Fastly',
            'fastly.': 'Fastly',
            'akamai.net': 'Akamai',
            'akamaiedge.net': 'Akamai'
        }
        
        cname_lower = cname.lower()
        for pattern, service in cloud_patterns.items():
            if pattern in cname_lower:
                return service
        
        return None
    
    def _check_takeover_patterns(self, cname: str) -> bool:
        """Verifica padrões conhecidos de subdomain takeover."""
        if not cname:
            return False
        
        vulnerable_patterns = [
            'github.io', 'herokuapp.com', 'netlify.app', 'netlify.com',
            'azurewebsites.net', 'wordpress.com', 'tumblr.com', 'surge.sh',
            'bitbucket.io', 'gitlab.io', 'shopify.com', 'unbounce.com',
            'tilda.ws', 'vercel.app', 'webflow.io'
        ]
        
        return any(pattern in cname.lower() for pattern in vulnerable_patterns)


class PassiveSourcesEngine:
    """Engine para consultar múltiplas fontes passivas."""
    
    def __init__(self, session: aiohttp.ClientSession, rate_limiter: RateLimiter):
        self.session = session
        self.rate_limiter = rate_limiter
        self.logger = get_logger(__name__)
    
    async def query_dnsdumpster(self, domain: str) -> Set[str]:
        """Query DNSDumpster."""
        subdomains = set()
        
        try:
            await self.rate_limiter.wait('web_scraping')
            
            url = "https://dnsdumpster.com/"
            
            # Primeiro GET para obter CSRF token
            async with self.session.get(url) as response:
                if response.status != 200:
                    return subdomains
                
                html = await response.text()
                csrf_token = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', html)
                
                if not csrf_token:
                    return subdomains
                
                csrf_token = csrf_token.group(1)
            
            # POST com o domínio
            data = {
                'csrfmiddlewaretoken': csrf_token,
                'targetip': domain,
                'user': 'free'
            }
            
            headers = {
                'Referer': url,
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            async with self.session.post(url, data=data, headers=headers) as response:
                if response.status == 200:
                    html = await response.text()
                    
                    # Extrai subdomains do HTML
                    pattern = rf'([a-zA-Z0-9\-\.]+\.{re.escape(domain)})'
                    matches = re.findall(pattern, html)
                    
                    for match in matches:
                        if match != domain:
                            subdomains.add(match.lower())
                    
                    self.rate_limiter.record_success('web_scraping')
                else:
                    self.rate_limiter.record_error('web_scraping')
                    
        except Exception as e:
            self.logger.debug(f"Erro no DNSDumpster para {domain}: {e}")
            self.rate_limiter.record_error('web_scraping')
        
        return subdomains
    
    async def query_threatcrowd(self, domain: str) -> Set[str]:
        """Query ThreatCrowd API."""
        subdomains = set()
        
        try:
            await self.rate_limiter.wait('api_requests')
            
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/"
            params = {'domain': domain}
            
            async with self.session.get(url, params=params, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for subdomain in data.get('subdomains', []):
                        if subdomain and subdomain != domain:
                            subdomains.add(subdomain.lower())
                    
                    self.rate_limiter.record_success('api_requests')
                else:
                    self.rate_limiter.record_error('api_requests')
                    
        except Exception as e:
            self.logger.debug(f"Erro no ThreatCrowd para {domain}: {e}")
            self.rate_limiter.record_error('api_requests')
        
        return subdomains
    
    async def query_hackertarget(self, domain: str) -> Set[str]:
        """Query HackerTarget API."""
        subdomains = set()
        
        try:
            await self.rate_limiter.wait('api_requests')
            
            url = f"https://api.hackertarget.com/hostsearch/"
            params = {'q': domain}
            
            async with self.session.get(url, params=params, timeout=10) as response:
                if response.status == 200:
                    text = await response.text()
                    
                    lines = text.strip().split('\\n')
                    for line in lines:
                        if ',' in line:
                            subdomain = line.split(',')[0].strip()
                            if subdomain and subdomain != domain and subdomain.endswith(f'.{domain}'):
                                subdomains.add(subdomain.lower())
                    
                    self.rate_limiter.record_success('api_requests')
                else:
                    self.rate_limiter.record_error('api_requests')
                    
        except Exception as e:
            self.logger.debug(f"Erro no HackerTarget para {domain}: {e}")
            self.rate_limiter.record_error('api_requests')
        
        return subdomains


class AdvancedSubdomainScanner:
    """Scanner avançado de subdomínios - Inspirado nas melhores ferramentas."""
    
    def __init__(self, domain: str, wordlist_path: Optional[str] = None, 
                 max_concurrent: int = 1000, enable_passive: bool = True,
                 enable_permutations: bool = True, verify_takeover: bool = True):
        """
        Inicializa o scanner avançado.
        
        Args:
            domain: Domínio alvo (pode ser URL completa ou apenas domínio)
            wordlist_path: Caminho para wordlist (opcional)
            max_concurrent: Máximo de queries concorrentes
            enable_passive: Habilita descoberta passiva
            enable_permutations: Habilita engine de permutações
            verify_takeover: Habilita verificação real de takeover
        """
        # Extrai domínio de URL se necessário
        self.domain = self._extract_domain(domain)
        self.wordlist_path = wordlist_path
        self.max_concurrent = max_concurrent
        self.enable_passive = enable_passive
        self.enable_permutations = enable_permutations
        self.verify_takeover = verify_takeover
        
        # Resultados
        self.found_subdomains: Dict[str, SubdomainResult] = {}
        self.takeover_risks: List[SubdomainResult] = []
        self.stats = {
            'total_discovered': 0,
            'passive_sources': 0,
            'dns_bruteforce': 0,
            'permutations': 0,
            'certificate_transparency': 0,
            'verified_takeovers': 0,
            'scan_time': 0.0
        }
        
        # Components
        self.dns_resolver = AsyncDNSResolver(max_concurrent)
        self.rate_limiter = RateLimiter()
        self.permutation_engine = PermutationEngine()
        self.logger = get_logger(__name__)
        
        # Session será inicializada no scan
        self.session: Optional[aiohttp.ClientSession] = None
        self.ct_scanner: Optional[CertificateTransparency] = None
        self.passive_engine: Optional[PassiveSourcesEngine] = None
        self.takeover_verifier: Optional[TakeoverVerifier] = None
    
    def _extract_domain(self, domain_or_url: str) -> str:
        """Extrai domínio de uma URL ou retorna o domínio se já for apenas domínio."""
        domain_or_url = domain_or_url.lower().strip()
        
        # Remove protocolo se presente
        if domain_or_url.startswith(('http://', 'https://')):
            domain_or_url = domain_or_url.split('://', 1)[1]
        
        # Remove path se presente
        if '/' in domain_or_url:
            domain_or_url = domain_or_url.split('/', 1)[0]
        
        # Remove porta se presente
        if ':' in domain_or_url:
            domain_or_url = domain_or_url.split(':', 1)[0]
        
        # Remove www. se presente
        if domain_or_url.startswith('www.'):
            domain_or_url = domain_or_url[4:]
        
        return domain_or_url
    
    async def scan(self) -> Dict[str, SubdomainResult]:
        """Executa scan completo de subdomínios."""
        start_time = time.time()
        
        print_separator(60)
        print_info("Scanner Avançado de Subdomínios - Spectra v3.2.6")
        print_info(f"Alvo: [bold cyan]{self.domain}[/bold cyan]")
        features = []
        if self.enable_passive:
            features.append("[green]Passive Discovery[/green]")
        if self.enable_permutations:
            features.append("[green]Permutations[/green]")
        if self.verify_takeover:
            features.append("[green]Takeover Verification[/green]")
        if self.wordlist_path:
            features.append("[green]DNS Bruteforce[/green]")
        
        if features:
            print_info(f"Recursos: {' | '.join(features)}")
        print_info(f"Máximo concorrente: [bold cyan]{self.max_concurrent}[/bold cyan]")
        print_separator(60)
        
        # Inicializa components
        connector = aiohttp.TCPConnector(limit=self.max_concurrent, limit_per_host=100)
        timeout = aiohttp.ClientTimeout(total=30)
        
        async with aiohttp.ClientSession(
            connector=connector, 
            timeout=timeout,
            headers={'User-Agent': 'Spectra-SubdomainScanner/1.0'}
        ) as session:
            self.session = session
            self.ct_scanner = CertificateTransparency(session, self.rate_limiter)
            self.passive_engine = PassiveSourcesEngine(session, self.rate_limiter)
            self.takeover_verifier = TakeoverVerifier(session, self.rate_limiter)
            
            # Coleta subdomains de múltiplas fontes
            all_subdomains = set()
            
            # 1. Certificate Transparency
            if self.enable_passive:
                print_info("Consultando Certificate Transparency logs...")
                ct_subdomains = await self._scan_certificate_transparency()
                all_subdomains.update(ct_subdomains)
                self.stats['certificate_transparency'] = len(ct_subdomains)
                print_success(f"Encontrados {len(ct_subdomains)} subdomínios via CT logs")
            
            # 2. Passive Sources
            if self.enable_passive:
                print_info("Consultando fontes passivas...")
                passive_subdomains = await self._scan_passive_sources()
                all_subdomains.update(passive_subdomains)
                self.stats['passive_sources'] = len(passive_subdomains)
                print_success(f"Encontrados {len(passive_subdomains)} subdomínios via fontes passivas")
            
            # 3. DNS Bruteforce (se wordlist fornecida)
            if self.wordlist_path:
                print_info("Executando DNS bruteforce...")
                bruteforce_subdomains = await self._scan_dns_bruteforce()
                all_subdomains.update(bruteforce_subdomains)
                self.stats['dns_bruteforce'] = len(bruteforce_subdomains)
                print_success(f"Encontrados {len(bruteforce_subdomains)} subdomínios via bruteforce")
            
            # 4. Permutations
            if self.enable_permutations and all_subdomains:
                print_info("Gerando permutações inteligentes...")
                permutation_subdomains = await self._scan_permutations(all_subdomains)
                all_subdomains.update(permutation_subdomains)
                self.stats['permutations'] = len(permutation_subdomains)
                print_success(f"Encontrados {len(permutation_subdomains)} subdomínios via permutações")
            
            # 5. Resolve todos os subdomains encontrados
            print_info(f"Resolvendo {len(all_subdomains)} subdomínios únicos...")
            await self._resolve_all_subdomains(all_subdomains)
            
            # 6. Verificação de takeover
            if self.verify_takeover:
                print_info("Verificando vulnerabilidades de subdomain takeover...")
                await self._verify_takeover_risks()
            
            # 7. Detecção de tecnologias (opcional)
            if len(self.found_subdomains) <= 50:  # Limita para evitar muitas requisições
                print_info("Detectando tecnologias web...")
                await self._detect_technologies()
                
        self.stats['total_discovered'] = len(self.found_subdomains)
        self.stats['scan_time'] = time.time() - start_time
        
        # Display results
        self._display_results()
        
        return self.found_subdomains
    
    async def _scan_certificate_transparency(self) -> Set[str]:
        """Scan Certificate Transparency logs."""
        subdomains = set()
        
        tasks = [
            self.ct_scanner.query_crt_sh(self.domain),
            # Adicionar mais CT sources aqui se necessário
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, set):
                subdomains.update(result)
        
        return subdomains
    
    async def _scan_passive_sources(self) -> Set[str]:
        """Scan passive sources."""
        subdomains = set()
        
        tasks = [
            self.passive_engine.query_dnsdumpster(self.domain),
            self.passive_engine.query_threatcrowd(self.domain),
            self.passive_engine.query_hackertarget(self.domain)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, set):
                subdomains.update(result)
        
        return subdomains
    
    async def _scan_dns_bruteforce(self) -> Set[str]:
        """Scan usando wordlist."""
        if not self.wordlist_path:
            return set()
        
        subdomains = set()
        
        try:
            with open(self.wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                wordlist = [
                    line.strip().lower() for line in f 
                    if line.strip() and not line.startswith('#')
                ]
            
            # Adiciona domínio base a cada palavra
            potential_subdomains = [f"{word}.{self.domain}" for word in wordlist]
            
            # Resolve em batches
            batch_size = 100
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=console
            ) as progress:
                
                task = progress.add_task("DNS Bruteforce", total=len(potential_subdomains))
                
                for i in range(0, len(potential_subdomains), batch_size):
                    batch = potential_subdomains[i:i + batch_size]
                    
                    tasks = [self.dns_resolver.resolve_subdomain(sub) for sub in batch]
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    
                    for result in results:
                        if isinstance(result, SubdomainResult):
                            subdomains.add(result.domain)
                    
                    progress.update(task, advance=len(batch))
        
        except Exception as e:
            self.logger.error(f"Erro no DNS bruteforce: {e}")
        
        return subdomains
    
    async def _scan_permutations(self, base_subdomains: Set[str]) -> Set[str]:
        """Scan permutações baseadas nos subdomains encontrados."""
        permutations = self.permutation_engine.generate_permutations(base_subdomains, self.domain)
        
        # Limita permutações para evitar explosão
        permutations = list(permutations)[:5000]  # Máximo 5000 permutações
        
        found_subdomains = set()
        
        # Resolve permutações em batches
        batch_size = 100
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            
            task = progress.add_task("Permutations", total=len(permutations))
            
            for i in range(0, len(permutations), batch_size):
                batch = permutations[i:i + batch_size]
                
                tasks = [self.dns_resolver.resolve_subdomain(sub) for sub in batch]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for result in results:
                    if isinstance(result, SubdomainResult):
                        found_subdomains.add(result.domain)
                
                progress.update(task, advance=len(batch))
        
        return found_subdomains
    
    async def _resolve_all_subdomains(self, subdomains: Set[str]):
        """Resolve todos os subdomains encontrados."""
        batch_size = 100
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            
            task = progress.add_task("[green]Resolvendo subdomínios...", total=len(subdomains))
            
            subdomain_list = list(subdomains)
            for i in range(0, len(subdomain_list), batch_size):
                batch = subdomain_list[i:i + batch_size]
                
                tasks = [self.dns_resolver.resolve_subdomain(sub) for sub in batch]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for result in results:
                    if isinstance(result, SubdomainResult):
                        self.found_subdomains[result.domain] = result
                        
                        # Display em tempo real usando padrão Spectra
                        status_info = []
                        if result.cloud_service:
                            status_info.append(f"[blue]{result.cloud_service}[/blue]")
                        if result.takeover_risk:
                            status_info.append("[bold red]RISCO TAKEOVER[/bold red]")
                        if result.cname:
                            status_info.append(f"CNAME: {result.cname}")
                        
                        status_str = f" ({' | '.join(status_info)})" if status_info else ""
                        print_success(f"{result.domain} -> {result.ip}{status_str}")
                
                progress.update(task, advance=len(batch))
    
    async def _verify_takeover_risks(self):
        """Verifica riscos reais de subdomain takeover."""
        potential_takeovers = [
            result for result in self.found_subdomains.values()
            if result.takeover_risk and result.cname
        ]
        
        if not potential_takeovers:
            return
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            
            task = progress.add_task("[yellow]Verificando takeovers...", total=len(potential_takeovers))
            
            for result in potential_takeovers:
                is_vulnerable, service = await self.takeover_verifier.verify_takeover(
                    result.domain, result.cname
                )
                
                if is_vulnerable:
                    result.takeover_verified = True
                    result.takeover_service = service
                    self.takeover_risks.append(result)
                    self.stats['verified_takeovers'] += 1
                    
                    print_error(f"TAKEOVER VERIFICADO: {result.domain} -> {service}")
                
                progress.update(task, advance=1)
    
    async def _detect_technologies(self):
        """Detecta tecnologias web nos subdomínios encontrados."""
        if not self.found_subdomains:
            return
        
        try:
            # Limita a detecção para evitar muitas requisições
            subdomains_to_check = list(self.found_subdomains.values())[:20]
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=console
            ) as progress:
                
                task = progress.add_task("[blue]Detectando tecnologias...", total=len(subdomains_to_check))
                
                for result in subdomains_to_check:
                    try:
                        # Tenta HTTP e HTTPS
                        for protocol in ['https', 'http']:
                            try:
                                url = f"{protocol}://{result.domain}"
                                
                                async with self.session.get(
                                    url, 
                                    timeout=5,
                                    allow_redirects=True,
                                    ssl=False if protocol == 'http' else None
                                ) as response:
                                    
                                    if response.status == 200:
                                        # Análise básica de tecnologias
                                        headers = dict(response.headers)
                                        content = await response.text()
                                        
                                        technologies = self._analyze_technologies(headers, content)
                                        if technologies:
                                            result.technologies = technologies
                                        
                                        break  # Se conseguiu conectar, para aqui
                                        
                            except Exception:
                                continue  # Tenta próximo protocolo
                                
                    except Exception as e:
                        self.logger.debug(f"Erro detectando tecnologias para {result.domain}: {e}")
                    
                    progress.update(task, advance=1)
                    
        except Exception as e:
            self.logger.error(f"Erro na detecção de tecnologias: {e}")
    
    def _analyze_technologies(self, headers: Dict[str, str], content: str) -> List[str]:
        """Análise básica de tecnologias baseada em headers e conteúdo."""
        technologies = []
        
        # Análise de headers
        server = headers.get('server', '').lower()
        if 'nginx' in server:
            technologies.append('Nginx')
        elif 'apache' in server:
            technologies.append('Apache')
        elif 'iis' in server:
            technologies.append('IIS')
        elif 'cloudflare' in server:
            technologies.append('Cloudflare')
        
        # X-Powered-By
        powered_by = headers.get('x-powered-by', '').lower()
        if 'php' in powered_by:
            technologies.append('PHP')
        elif 'asp.net' in powered_by:
            technologies.append('ASP.NET')
        elif 'express' in powered_by:
            technologies.append('Express.js')
        
        # Análise básica de conteúdo (primeiros 2KB para performance)
        content_sample = content[:2048].lower()
        
        # Frameworks JavaScript
        if 'react' in content_sample:
            technologies.append('React')
        if 'vue' in content_sample:
            technologies.append('Vue.js')
        if 'angular' in content_sample:
            technologies.append('Angular')
        if 'jquery' in content_sample:
            technologies.append('jQuery')
        
        # CMS
        if 'wp-content' in content_sample or 'wordpress' in content_sample:
            technologies.append('WordPress')
        if 'drupal' in content_sample:
            technologies.append('Drupal')
        if 'joomla' in content_sample:
            technologies.append('Joomla')
        
        return technologies
    
    def _display_results(self):
        """Display final results."""
        print_separator(60)
        print_info("Varredura de subdomínios concluída.")
        
        if self.found_subdomains:
            # Main results table usando padrão Spectra
            table = create_table(f"Relatório de Subdomínios - {self.domain}", [
                {"header": "Subdomínio", "style": "cyan"},
                {"header": "IP", "style": "magenta"},
                {"header": "IPv6", "style": "blue"},
                {"header": "Cloud Service", "style": "green"},
                {"header": "CNAME", "style": "yellow"},
                {"header": "Status", "style": "bold"}
            ])
            
            sorted_results = sorted(self.found_subdomains.values(), key=lambda x: x.domain)
            
            for result in sorted_results:
                ipv6 = result.ipv6 or 'N/A'
                cloud = result.cloud_service or 'N/A'
                cname = result.cname or 'N/A'
                
                if result.takeover_verified:
                    status = f"[bold red]TAKEOVER ({result.takeover_service})[/bold red]"
                elif result.takeover_risk:
                    status = "[bold yellow]RISCO TAKEOVER[/bold yellow]"
                else:
                    status = "[green]OK[/green]"
                
                table.add_row(result.domain, result.ip, ipv6, cloud, cname, status)
            
            console.print(table)
            
            # Takeover risks table
            if self.takeover_risks:
                console.print()
                print_warning("VULNERABILIDADES DE SUBDOMAIN TAKEOVER VERIFICADAS")
                risk_table = create_table("Problemas Críticos de Segurança", [
                    {"header": "Subdomínio", "style": "red"},
                    {"header": "Serviço", "style": "yellow"},
                    {"header": "CNAME", "style": "blue"},
                    {"header": "Recomendação", "style": "white"}
                ])
                
                for risk in self.takeover_risks:
                    risk_table.add_row(
                        risk.domain,
                        risk.takeover_service or 'Desconhecido',
                        risk.cname,
                        "Remover registro DNS ou reivindicar serviço"
                    )
                
                console.print(risk_table)
            
            # Statistics usando padrão Spectra
            console.print()
            print_info("Estatísticas do scan:")
            console.print(f"    • Total encontrado: [bold cyan]{self.stats['total_discovered']}[/bold cyan] subdomínios")
            console.print(f"    • Certificate Transparency: [cyan]{self.stats['certificate_transparency']}[/cyan]")
            console.print(f"    • Fontes passivas: [cyan]{self.stats['passive_sources']}[/cyan]")
            console.print(f"    • DNS bruteforce: [cyan]{self.stats['dns_bruteforce']}[/cyan]")
            console.print(f"    • Permutações: [cyan]{self.stats['permutations']}[/cyan]")
            console.print(f"    • Takeovers verificados: [bold red]{self.stats['verified_takeovers']}[/bold red]")
            console.print(f"    • Tempo de scan: [cyan]{self.stats['scan_time']:.2f}s[/cyan]")
            
            # Cloud services breakdown
            cloud_services = {}
            for result in self.found_subdomains.values():
                if result.cloud_service:
                    cloud_services[result.cloud_service] = cloud_services.get(result.cloud_service, 0) + 1
            
            if cloud_services:
                print_info("Serviços de cloud detectados:")
                for service, count in sorted(cloud_services.items()):
                    console.print(f"    • {service}: {count} subdomínio(s)")
        
        else:
            print_warning("Nenhum subdomínio encontrado com a configuração atual.")
        
        print_separator(60)
    
    def export_results(self, format_type: str = 'json') -> str:
        """Export results em diferentes formatos."""
        if format_type == 'json':
            export_data = {
                'domain': self.domain,
                'scan_time': self.stats['scan_time'],
                'statistics': self.stats,
                'subdomains': [asdict(result) for result in self.found_subdomains.values()],
                'takeover_risks': [asdict(result) for result in self.takeover_risks]
            }
            return json.dumps(export_data, indent=2)
        
        elif format_type == 'csv':
            import csv
            from io import StringIO
            
            output = StringIO()
            writer = csv.writer(output)
            writer.writerow([
                'Subdomain', 'IP', 'IPv6', 'CNAME', 'Cloud Service', 
                'Takeover Risk', 'Takeover Verified', 'Response Time'
            ])
            
            for result in self.found_subdomains.values():
                writer.writerow([
                    result.domain, result.ip, result.ipv6 or '', result.cname or '',
                    result.cloud_service or '', result.takeover_risk, result.takeover_verified,
                    f"{result.response_time:.3f}s"
                ])
            
            return output.getvalue()
        
        elif format_type == 'txt':
            lines = [f"Subdomain scan results for {self.domain}"]
            lines.append("=" * 60)
            lines.append(f"Scan completed in {self.stats['scan_time']:.2f} seconds")
            lines.append(f"Total subdomains found: {self.stats['total_discovered']}")
            lines.append("")
            
            for result in sorted(self.found_subdomains.values(), key=lambda x: x.domain):
                lines.append(f"{result.domain} -> {result.ip}")
                if result.ipv6:
                    lines.append(f"  IPv6: {result.ipv6}")
                if result.cname:
                    lines.append(f"  CNAME: {result.cname}")
                if result.cloud_service:
                    lines.append(f"  Cloud: {result.cloud_service}")
                if result.takeover_verified:
                    lines.append(f"  ⚠️  VERIFIED TAKEOVER VULNERABILITY ({result.takeover_service})")
                elif result.takeover_risk:
                    lines.append(f"  ⚠️  POTENTIAL TAKEOVER RISK")
                lines.append("")
            
            return '\\n'.join(lines)
        
        return ""


# Função de conveniência para compatibilidade
async def discover_subdomains_advanced(domain: str, wordlist_path: Optional[str] = None,
                                     max_concurrent: int = 1000, enable_passive: bool = True,
                                     enable_permutations: bool = True, verify_takeover: bool = True) -> Dict[str, SubdomainResult]:
    """
    Função de conveniência para executar scan avançado de subdomínios.
    
    Args:
        domain: Domínio alvo
        wordlist_path: Caminho para wordlist (opcional)
        max_concurrent: Máximo de queries concorrentes
        enable_passive: Habilita descoberta passiva
        enable_permutations: Habilita engine de permutações
        verify_takeover: Habilita verificação real de takeover
    
    Returns:
        Dict com resultados dos subdomínios
    """
    scanner = AdvancedSubdomainScanner(
        domain=domain,
        wordlist_path=wordlist_path,
        max_concurrent=max_concurrent,
        enable_passive=enable_passive,
        enable_permutations=enable_permutations,
        verify_takeover=verify_takeover
    )
    
    return await scanner.scan()