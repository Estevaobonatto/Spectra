"""
Módulo de scanner de subdomínios avançado com análise de segurança.
"""
import socket
import dns.resolver
import random
import string
import asyncio
import aiohttp
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
from rich.table import Table
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime

from ..core.console import console
from ..core.logger import logger
from ..utils.network import create_session


class TakeoverVerifier:
    """Verifica realmente se subdomain takeover é possível."""
    
    def __init__(self):
        self.takeover_signatures = {
            'github.io': {
                'signatures': [
                    'There isn\'t a GitHub Pages site here',
                    'Not Found',
                    'For root URLs (like http://example.com/) you must provide an index.html file'
                ],
                'status_codes': [404],
                'exploit_info': 'Create GitHub Pages repository with same name as subdomain',
                'service_name': 'GitHub Pages',
                'confidence': 'high'
            },
            'herokuapp.com': {
                'signatures': [
                    'No such app',
                    'Application Error',
                    'Heroku | No such app'
                ],
                'status_codes': [404, 503],
                'exploit_info': 'Create Heroku app with same name as subdomain',
                'service_name': 'Heroku',
                'confidence': 'high'
            },
            'netlify.app': {
                'signatures': [
                    'Not Found',
                    'Page Not Found',
                    'The site you were looking for couldn\'t be found'
                ],
                'status_codes': [404],
                'exploit_info': 'Deploy site to Netlify with custom domain pointing to subdomain',
                'service_name': 'Netlify',
                'confidence': 'high'
            },
            'azurewebsites.net': {
                'signatures': [
                    'Web Site not found',
                    'Error 404',
                    'This web app has been stopped'
                ],
                'status_codes': [404, 403],
                'exploit_info': 'Create Azure Web App with same name as subdomain',
                'service_name': 'Azure Web Apps',
                'confidence': 'high'
            },
            'amazonaws.com': {
                'signatures': [
                    'NoSuchBucket',
                    'The specified bucket does not exist',
                    'NoSuchKey'
                ],
                'status_codes': [404, 403],
                'exploit_info': 'Create S3 bucket with same name (if available)',
                'service_name': 'AWS S3',
                'confidence': 'medium'
            },
            'surge.sh': {
                'signatures': [
                    'project not found',
                    'Repository not found'
                ],
                'status_codes': [404],
                'exploit_info': 'Deploy to Surge.sh with custom domain',
                'service_name': 'Surge.sh',
                'confidence': 'high'
            },
            'bitbucket.io': {
                'signatures': [
                    'Repository not found',
                    'The page you\'re looking for doesn\'t exist'
                ],
                'status_codes': [404],
                'exploit_info': 'Create Bitbucket repository with GitHub Pages',
                'service_name': 'Bitbucket Pages',
                'confidence': 'high'
            },
            'wordpress.com': {
                'signatures': [
                    'Do you want to register',
                    'doesn\'t exist'
                ],
                'status_codes': [404],
                'exploit_info': 'Register WordPress.com site with same name',
                'service_name': 'WordPress.com',
                'confidence': 'medium'
            },
            'tumblr.com': {
                'signatures': [
                    'Whatever you were looking for doesn\'t currently exist',
                    'There\'s nothing here'
                ],
                'status_codes': [404],
                'exploit_info': 'Create Tumblr blog with same name',
                'service_name': 'Tumblr',
                'confidence': 'medium'
            },
            'shopify.com': {
                'signatures': [
                    'Sorry, this shop is currently unavailable',
                    'This shop is unavailable'
                ],
                'status_codes': [404, 503],
                'exploit_info': 'Create Shopify store with same name',
                'service_name': 'Shopify',
                'confidence': 'high'
            },
            'vercel.app': {
                'signatures': [
                    'The deployment could not be found',
                    'NOT_FOUND'
                ],
                'status_codes': [404],
                'exploit_info': 'Deploy to Vercel with custom domain',
                'service_name': 'Vercel',
                'confidence': 'high'
            }
        }
    
    async def verify_takeover(self, subdomain: str, cname: str) -> Dict[str, Any]:
        """Verifica se takeover é realmente possível."""
        result = {
            'subdomain': subdomain,
            'cname': cname,
            'takeover_possible': False,
            'service': None,
            'confidence': 'none',
            'exploit_info': None,
            'evidence': [],
            'http_status': None,
            'response_content': None,
            'verified_at': datetime.now().isoformat()
        }
        
        if not cname:
            return result
        
        # Identifica o serviço baseado no CNAME
        service_info = None
        for service_pattern, info in self.takeover_signatures.items():
            if service_pattern in cname.lower():
                service_info = info
                result['service'] = info['service_name']
                break
        
        if not service_info:
            return result
        
        # Testa HTTP response
        http_result = await self._test_http_response(subdomain)
        result.update(http_result)
        
        # Analisa se takeover é possível
        if self._analyze_takeover_possibility(http_result, service_info):
            result['takeover_possible'] = True
            result['confidence'] = service_info['confidence']
            result['exploit_info'] = service_info['exploit_info']
        
        return result
    
    async def _test_http_response(self, subdomain: str) -> Dict[str, Any]:
        """Testa resposta HTTP do subdomínio."""
        result = {
            'http_status': None,
            'response_content': None,
            'response_headers': {},
            'response_time': None,
            'error': None
        }
        
        timeout = aiohttp.ClientTimeout(total=10)
        
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                start_time = time.time()
                
                # Testa HTTP e HTTPS
                for protocol in ['http', 'https']:
                    try:
                        url = f"{protocol}://{subdomain}"
                        async with session.get(url, allow_redirects=False) as response:
                            result['http_status'] = response.status
                            result['response_headers'] = dict(response.headers)
                            result['response_content'] = await response.text()
                            result['response_time'] = time.time() - start_time
                            break  # Se conseguiu conectar, para aqui
                    except Exception:
                        continue  # Tenta o próximo protocolo
                        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _analyze_takeover_possibility(self, http_result: Dict[str, Any], 
                                    service_info: Dict[str, Any]) -> bool:
        """Analisa se takeover é possível baseado na resposta."""
        if not http_result.get('response_content'):
            return False
        
        content = http_result['response_content'].lower()
        status_code = http_result.get('http_status')
        
        # Verifica status codes suspeitos
        if status_code in service_info.get('status_codes', []):
            # Verifica assinaturas no conteúdo
            for signature in service_info.get('signatures', []):
                if signature.lower() in content:
                    return True
        
        return False
    
    async def verify_multiple_takeovers(self, subdomains_with_cnames: List[Tuple[str, str]]) -> List[Dict[str, Any]]:
        """Verifica múltiplos takeovers em paralelo."""
        tasks = []
        for subdomain, cname in subdomains_with_cnames:
            task = self.verify_takeover(subdomain, cname)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filtra exceções
        valid_results = []
        for result in results:
            if isinstance(result, dict):
                valid_results.append(result)
        
        return valid_results


class CertificateTransparencySource:
    """Integração com Certificate Transparency logs para descoberta passiva."""
    
    def __init__(self):
        self.ct_sources = {
            'crt_sh': 'https://crt.sh/?q=%.{domain}&output=json',
            'certspotter': 'https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names'
        }
        self.session = None
    
    async def discover_from_ct_logs(self, domain: str) -> Set[str]:
        """Descobre subdomínios via Certificate Transparency logs."""
        all_subdomains = set()
        
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            self.session = session
            
            # Query crt.sh
            crt_subdomains = await self._query_crt_sh(domain)
            all_subdomains.update(crt_subdomains)
            
            # Query CertSpotter (se disponível)
            try:
                certspotter_subdomains = await self._query_certspotter(domain)
                all_subdomains.update(certspotter_subdomains)
            except Exception as e:
                logger.debug(f"CertSpotter query failed: {e}")
        
        return all_subdomains
    
    async def _query_crt_sh(self, domain: str) -> Set[str]:
        """Query crt.sh para certificados."""
        subdomains = set()
        url = self.ct_sources['crt_sh'].format(domain=domain)
        
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for cert in data:
                        # Extrai nomes do certificado
                        if 'name_value' in cert:
                            names = cert['name_value'].split('\n')
                            for name in names:
                                name = name.strip().lower()
                                if name and self._is_valid_subdomain(name, domain):
                                    subdomains.add(name)
                        
                        # Extrai common name se disponível
                        if 'common_name' in cert:
                            cn = cert['common_name'].strip().lower()
                            if cn and self._is_valid_subdomain(cn, domain):
                                subdomains.add(cn)
                                
        except Exception as e:
            logger.error(f"Erro ao consultar crt.sh: {e}")
        
        return subdomains
    
    async def _query_certspotter(self, domain: str) -> Set[str]:
        """Query CertSpotter API para certificados."""
        subdomains = set()
        url = self.ct_sources['certspotter'].format(domain=domain)
        
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for cert in data:
                        if 'dns_names' in cert:
                            for name in cert['dns_names']:
                                name = name.strip().lower()
                                if name and self._is_valid_subdomain(name, domain):
                                    subdomains.add(name)
                                    
        except Exception as e:
            logger.error(f"Erro ao consultar CertSpotter: {e}")
        
        return subdomains
    
    def _is_valid_subdomain(self, name: str, domain: str) -> bool:
        """Verifica se o nome é um subdomínio válido do domínio alvo."""
        if not name or name == domain:
            return False
        
        # Remove wildcards
        if name.startswith('*.'):
            name = name[2:]
            # Se após remover o wildcard não sobrou nada válido, rejeita
            if not name or name == domain:
                return False
        
        # Verifica se termina com o domínio alvo
        if not name.endswith(f'.{domain}'):
            return False
        
        # Verifica se não contém caracteres inválidos
        if any(char in name for char in ['<', '>', '"', "'", '\\', '\n', '\r']):
            return False
        
        # Verifica se não é muito longo
        if len(name) > 253:
            return False
        
        return True


class PermutationEngine:
    """Engine inteligente de permutação de subdomínios."""
    
    def __init__(self):
        self.common_prefixes = [
            'www', 'api', 'dev', 'test', 'stage', 'staging', 'prod', 'production',
            'admin', 'mail', 'email', 'ftp', 'ssh', 'vpn', 'portal', 'app',
            'mobile', 'web', 'cdn', 'static', 'assets', 'media', 'img', 'images',
            'blog', 'news', 'shop', 'store', 'support', 'help', 'docs', 'doc',
            'beta', 'alpha', 'demo', 'sandbox', 'secure', 'old', 'new', 'backup'
        ]
        
        self.common_suffixes = [
            'dev', 'test', 'staging', 'prod', 'production', 'old', 'new',
            'backup', 'temp', 'internal', 'external', 'v1', 'v2', 'v3',
            'beta', 'alpha', 'demo', 'live', 'stage', 'qa', 'uat'
        ]
        
        self.separators = ['-', '_', '.', '']
        
        self.environment_keywords = [
            'dev', 'development', 'test', 'testing', 'stage', 'staging',
            'prod', 'production', 'live', 'demo', 'beta', 'alpha', 'qa', 'uat'
        ]
        
        self.service_keywords = [
            'api', 'app', 'web', 'mobile', 'admin', 'portal', 'dashboard',
            'panel', 'console', 'manager', 'service', 'gateway', 'proxy'
        ]
    
    def generate_permutations(self, found_subdomains: Set[str], max_permutations: int = 500) -> Set[str]:
        """Gera permutações inteligentes baseadas nos subdomínios encontrados."""
        if not found_subdomains:
            return set()
        
        permutations = set()
        
        # Analisa padrões nos subdomínios encontrados
        patterns = self._analyze_patterns(found_subdomains)
        
        for subdomain in found_subdomains:
            # Gera variações numéricas
            numeric_variations = self._generate_numeric_variations(subdomain)
            permutations.update(numeric_variations)
            
            # Gera variações de ambiente
            env_variations = self._generate_environment_variations(subdomain)
            permutations.update(env_variations)
            
            # Gera variações com prefixos/sufixos
            prefix_suffix_variations = self._generate_prefix_suffix_variations(subdomain)
            permutations.update(prefix_suffix_variations)
            
            # Para de gerar se atingiu o limite
            if len(permutations) >= max_permutations:
                break
        
        # Gera permutações baseadas em padrões identificados
        pattern_permutations = self._generate_pattern_based_permutations(patterns)
        permutations.update(pattern_permutations)
        
        # Remove subdomínios já encontrados
        permutations -= found_subdomains
        
        # Limita o número de permutações
        if len(permutations) > max_permutations:
            permutations = set(list(permutations)[:max_permutations])
        
        return permutations
    
    def _analyze_patterns(self, subdomains: Set[str]) -> Dict[str, Any]:
        """Analisa padrões nos subdomínios encontrados."""
        patterns = {
            'common_prefixes': set(),
            'common_suffixes': set(),
            'separators_used': set(),
            'numeric_patterns': [],
            'length_distribution': {},
            'environment_indicators': set(),
            'service_indicators': set()
        }
        
        for subdomain in subdomains:
            # Analisa separadores
            for sep in self.separators:
                if sep in subdomain:
                    patterns['separators_used'].add(sep)
            
            # Analisa comprimento
            length = len(subdomain)
            patterns['length_distribution'][length] = patterns['length_distribution'].get(length, 0) + 1
            
            # Analisa indicadores de ambiente
            for env in self.environment_keywords:
                if env in subdomain.lower():
                    patterns['environment_indicators'].add(env)
            
            # Analisa indicadores de serviço
            for service in self.service_keywords:
                if service in subdomain.lower():
                    patterns['service_indicators'].add(service)
            
            # Analisa padrões numéricos
            import re
            numbers = re.findall(r'\d+', subdomain)
            patterns['numeric_patterns'].extend(numbers)
        
        return patterns
    
    def _generate_numeric_variations(self, subdomain: str) -> Set[str]:
        """Gera variações numéricas (api1, api2, api01, etc)."""
        variations = set()
        
        # Adiciona números simples
        for i in range(1, 11):
            variations.add(f"{subdomain}{i}")
            variations.add(f"{subdomain}-{i}")
            variations.add(f"{subdomain}_{i}")
            variations.add(f"{subdomain}.{i}")
        
        # Adiciona números com zero à esquerda
        for i in range(1, 6):
            variations.add(f"{subdomain}{i:02d}")
            variations.add(f"{subdomain}-{i:02d}")
            variations.add(f"{subdomain}_{i:02d}")
        
        # Se o subdomínio já tem número, tenta variações
        import re
        numbers = re.findall(r'\d+', subdomain)
        if numbers:
            for num_str in numbers:
                num = int(num_str)
                # Tenta números adjacentes
                for offset in [-2, -1, 1, 2]:
                    new_num = num + offset
                    if new_num > 0:
                        new_subdomain = subdomain.replace(num_str, str(new_num))
                        variations.add(new_subdomain)
        
        return variations
    
    def _generate_environment_variations(self, subdomain: str) -> Set[str]:
        """Gera variações de ambiente (api-dev, api-prod, etc)."""
        variations = set()
        
        for env in self.environment_keywords:
            for sep in self.separators:
                if sep:  # Não usa separador vazio para ambientes
                    variations.add(f"{subdomain}{sep}{env}")
                    variations.add(f"{env}{sep}{subdomain}")
        
        return variations
    
    def _generate_prefix_suffix_variations(self, subdomain: str) -> Set[str]:
        """Gera variações com prefixos e sufixos comuns."""
        variations = set()
        
        # Prefixos
        for prefix in self.common_prefixes[:10]:  # Limita para não gerar muitas
            for sep in self.separators:
                if prefix != subdomain:  # Evita duplicatas
                    variations.add(f"{prefix}{sep}{subdomain}")
        
        # Sufixos
        for suffix in self.common_suffixes[:10]:  # Limita para não gerar muitas
            for sep in self.separators:
                if suffix != subdomain:  # Evita duplicatas
                    variations.add(f"{subdomain}{sep}{suffix}")
        
        return variations
    
    def _generate_pattern_based_permutations(self, patterns: Dict[str, Any]) -> Set[str]:
        """Gera permutações baseadas em padrões identificados."""
        permutations = set()
        
        # Combina indicadores de ambiente e serviço encontrados
        for env in patterns['environment_indicators']:
            for service in patterns['service_indicators']:
                for sep in patterns['separators_used']:
                    if sep:
                        permutations.add(f"{service}{sep}{env}")
                        permutations.add(f"{env}{sep}{service}")
        
        return permutations


class SubdomainScanner:
    """Scanner avançado de subdomínios com análise de segurança."""
    
    def __init__(self, domain, wordlist_path, workers=100, verify_takeovers=True, use_passive_sources=True):
        """
        Inicializa o scanner de subdomínios.
        
        Args:
            domain (str): Domínio alvo para scan.
            wordlist_path (str): Caminho para wordlist de subdomínios.
            workers (int): Número de threads para scan.
            verify_takeovers (bool): Se deve verificar takeovers realmente.
            use_passive_sources (bool): Se deve usar fontes passivas (CT logs).
        """
        self.domain = domain
        self.wordlist_path = wordlist_path
        self.workers = workers
        self.verify_takeovers = verify_takeovers
        self.use_passive_sources = use_passive_sources
        self.found_subdomains = []
        self.takeover_risks = []
        self.verified_takeovers = []
        self.passive_subdomains = []
        self.wildcard_ip = None
        
        # Inicializa verificador de takeover
        if self.verify_takeovers:
            self.takeover_verifier = TakeoverVerifier()
        
        # Inicializa fonte de Certificate Transparency
        if self.use_passive_sources:
            self.ct_source = CertificateTransparencySource()
        
        # Inicializa engine de permutação
        self.permutation_engine = PermutationEngine()
        
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
        
        # Descoberta passiva via Certificate Transparency se habilitado
        if self.use_passive_sources:
            console.print("[*] Executando descoberta passiva via Certificate Transparency...")
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                
                passive_subdomains = loop.run_until_complete(
                    self.ct_source.discover_from_ct_logs(self.domain)
                )
                loop.close()
                
                if passive_subdomains:
                    console.print(f"[bold green][+] {len(passive_subdomains)} subdomínios descobertos via CT logs[/bold green]")
                    
                    # Remove o domínio base e converte para lista de subdomínios
                    for full_domain in passive_subdomains:
                        if full_domain.endswith(f'.{self.domain}'):
                            subdomain = full_domain[:-len(f'.{self.domain}')]
                            if subdomain and subdomain not in subdomains:
                                subdomains.append(subdomain)
                                self.passive_subdomains.append(subdomain)
                else:
                    console.print("[yellow][-] Nenhum subdomínio encontrado via CT logs[/yellow]")
                    
            except Exception as e:
                console.print(f"[red]Erro na descoberta passiva: {e}[/red]")
                logger.error(f"Erro na descoberta passiva: {e}")
        
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
        
        # Verifica takeovers reais se habilitado
        if self.verify_takeovers and self.takeover_risks:
            console.print(f"\n[*] Verificando {len(self.takeover_risks)} possíveis takeovers...")
            self._verify_real_takeovers()
        
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
    
    def _verify_real_takeovers(self):
        """Verifica takeovers reais usando o TakeoverVerifier."""
        if not self.takeover_risks:
            return
        
        # Prepara lista de subdomínios e CNAMEs para verificação
        subdomains_to_verify = []
        for risk in self.takeover_risks:
            subdomain = risk['domain']
            cname = risk['dns_info']['cname']
            if cname:
                subdomains_to_verify.append((subdomain, cname))
        
        if not subdomains_to_verify:
            return
        
        # Executa verificação assíncrona
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeRemainingColumn(),
                console=console
            ) as progress:
                task = progress.add_task("[red]Verificando Takeovers...", total=len(subdomains_to_verify))
                
                # Verifica em lotes para não sobrecarregar
                batch_size = 10
                for i in range(0, len(subdomains_to_verify), batch_size):
                    batch = subdomains_to_verify[i:i + batch_size]
                    
                    # Executa verificação do lote
                    results = loop.run_until_complete(
                        self.takeover_verifier.verify_multiple_takeovers(batch)
                    )
                    
                    # Processa resultados
                    for result in results:
                        if result.get('takeover_possible'):
                            self.verified_takeovers.append(result)
                            console.print(f"[bold red]🚨 TAKEOVER CONFIRMADO: {result['subdomain']}[/bold red]")
                            console.print(f"   Serviço: {result['service']}")
                            console.print(f"   Confiança: {result['confidence']}")
                            console.print(f"   Como explorar: {result['exploit_info']}")
                    
                    progress.update(task, advance=len(batch))
            
            loop.close()
            
            # Atualiza exibição de resultados se houver takeovers confirmados
            if self.verified_takeovers:
                console.print(f"\n[bold red]🚨 {len(self.verified_takeovers)} TAKEOVERS CONFIRMADOS![/bold red]")
                
                # Tabela de takeovers confirmados
                takeover_table = Table(title="Subdomain Takeovers Confirmados")
                takeover_table.add_column("Subdomínio", style="red")
                takeover_table.add_column("Serviço", style="yellow")
                takeover_table.add_column("Confiança", style="green")
                takeover_table.add_column("Status HTTP", style="blue")
                takeover_table.add_column("Como Explorar", style="cyan", max_width=40)
                
                for takeover in self.verified_takeovers:
                    takeover_table.add_row(
                        takeover['subdomain'],
                        takeover['service'] or 'Desconhecido',
                        takeover['confidence'].upper(),
                        str(takeover['http_status']) if takeover['http_status'] else 'N/A',
                        takeover['exploit_info'] or 'Verificar manualmente'
                    )
                
                console.print(takeover_table)
                console.print("[bold red]⚠️  AÇÃO REQUERIDA: Estes takeovers foram confirmados e devem ser corrigidos imediatamente![/bold red]")
            else:
                console.print("[green]✅ Nenhum takeover real confirmado - apenas riscos potenciais[/green]")
                
        except Exception as e:
            console.print(f"[red]Erro durante verificação de takeovers: {e}[/red]")
            logger.error(f"Erro na verificação de takeovers: {e}")
    
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
