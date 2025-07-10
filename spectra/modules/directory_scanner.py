"""
Módulo de scanner de diretórios web avançado.
"""
import re
import time
import hashlib
import uuid
import requests
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
from rich.table import Table

from ..core.console import console
from ..core.logger import logger
from ..utils.validators import validate_url
from ..utils.network import create_session


class AdvancedDirectoryScanner:
    """Scanner avançado de diretórios web com detecção de false positives."""
    
    def __init__(self, base_url, wordlist_path, workers=30, timeout=10, retries=3):
        """
        Inicializa o scanner de diretórios.
        
        Args:
            base_url (str): URL base para scan.
            wordlist_path (str): Caminho para wordlist.
            workers (int): Número de threads.
            timeout (int): Timeout em segundos.
            retries (int): Número de tentativas.
        """
        self.base_url = base_url.rstrip('/')
        self.wordlist_path = wordlist_path
        self.workers = workers
        self.timeout = timeout
        self.retries = retries
        self.session = None
        self.baseline_404 = None
        self.waf_detected = False
        self.detected_technologies = set()
        self.results = []
        self.errors = []
        
        # Configurações avançadas
        self.smart_filtering = True
        self.extension_fuzzing = True
        self.recursive_enabled = False
        self.max_depth = 3
        self.stealth_mode = False
        
        # Estatísticas
        self.requests_made = 0
        self.false_positives_filtered = 0
        
        logger.info(f"Scanner de diretórios inicializado para {base_url}")
        
    def _setup_session(self):
        """Configura sessão HTTP otimizada para directory discovery."""
        self.session = create_session(timeout=self.timeout)
        
        # Headers para bypass de WAF se detectado
        if self.waf_detected:
            self.session.headers.update(self._get_waf_bypass_headers())
        
        logger.debug("Sessão HTTP configurada")
        
    def _get_waf_bypass_headers(self):
        """Headers para bypass de WAF."""
        return {
            'X-Forwarded-For': '127.0.0.1',
            'X-Real-IP': '127.0.0.1',
            'X-Originating-IP': '127.0.0.1',
            'X-Remote-IP': '127.0.0.1',
            'X-Remote-Addr': '127.0.0.1',
            'X-Forwarded-Host': 'localhost',
            'X-Forwarded-Proto': 'https'
        }
    
    def _detect_baseline_404(self):
        """Detecta características de páginas 404 customizadas."""
        console.print("[*] Detectando baseline 404...")
        
        # Gera URLs aleatórias que certamente não existem
        random_paths = [
            f"/{uuid.uuid4().hex}",
            f"/{uuid.uuid4().hex}.html",
            f"/{uuid.uuid4().hex}.php",
            f"/{uuid.uuid4().hex}.asp",
            f"/test{uuid.uuid4().hex[:8]}"
        ]
        
        baseline_responses = []
        
        for path in random_paths:
            url = f"{self.base_url}{path}"
            response = self._make_request(url)
            
            if response:
                baseline_responses.append({
                    'status': response.status_code,
                    'length': len(response.content),
                    'hash': hashlib.md5(response.content).hexdigest(),
                    'headers': dict(response.headers),
                    'content_preview': response.text[:500]
                })
        
        # Analisa padrões comuns nas respostas 404
        if baseline_responses:
            status_codes = [r['status'] for r in baseline_responses]
            content_lengths = [r['length'] for r in baseline_responses]
            content_hashes = [r['hash'] for r in baseline_responses]
            
            # Determina padrão mais comum
            most_common_status = Counter(status_codes).most_common(1)[0][0]
            avg_length = sum(content_lengths) // len(content_lengths)
            
            self.baseline_404 = {
                'status_codes': set(status_codes),
                'avg_length': avg_length,
                'length_variance': max(content_lengths) - min(content_lengths),
                'content_hashes': set(content_hashes),
                'common_status': most_common_status,
                'samples': baseline_responses
            }
            
            console.print(f"[*] Baseline 404 detectado: Status {most_common_status}, Length ~{avg_length}")
            logger.debug(f"Baseline 404 configurado: {self.baseline_404}")
        else:
            console.print("[!] Falha ao detectar baseline 404 - usando detecção padrão")
            self.baseline_404 = None
    
    def _detect_waf(self):
        """Detecta presença de Web Application Firewall."""
        console.print("[*] Verificando presença de WAF...")
        
        waf_payloads = [
            "<script>alert(1)</script>",
            "' OR '1'='1",
            "../../../etc/passwd",
            "<img src=x onerror=alert(1)>",
            "UNION SELECT * FROM users--"
        ]
        
        for payload in waf_payloads:
            test_url = f"{self.base_url}?test={payload}"
            response = self._make_request(test_url)
            
            if response and self._is_waf_response(response):
                self.waf_detected = True
                console.print("[!] WAF detectado - ativando modo evasão")
                logger.warning("WAF detectado, ativando modo evasão")
                return True
        
        console.print("[*] Nenhum WAF detectado")
        return False
    
    def _is_waf_response(self, response):
        """Verifica se a resposta indica bloqueio por WAF."""
        waf_indicators = [
            # Status codes comuns de WAF
            response.status_code in [403, 406, 429, 501, 503],
            
            # Headers de WAF
            any(header.lower() in ['cloudflare', 'akamai', 'incapsula', 'sucuri', 'barracuda'] 
                for header in response.headers.keys()),
            
            # Conteúdo de bloqueio
            any(phrase in response.text.lower() for phrase in [
                'blocked', 'forbidden', 'access denied', 'security',
                'firewall', 'protection', 'cloudflare', 'ray id'
            ])
        ]
        
        return any(waf_indicators)
    
    def _make_request(self, url, method='GET'):
        """Faz requisição com retry logic e error handling robusto."""
        for attempt in range(self.retries):
            try:
                if self.stealth_mode and attempt > 0:
                    time.sleep(0.5 * attempt)  # Delay progressivo em modo stealth
                
                if method == 'GET':
                    response = self.session.get(url, timeout=self.timeout, 
                                              allow_redirects=False, verify=False)
                elif method == 'HEAD':
                    response = self.session.head(url, timeout=self.timeout, 
                                               allow_redirects=False, verify=False)
                
                self.requests_made += 1
                return response
                
            except requests.exceptions.Timeout:
                if attempt == self.retries - 1:
                    self.errors.append(f"Timeout após {self.retries} tentativas: {url}")
                    logger.warning(f"Timeout para {url}")
                continue
                
            except requests.exceptions.ConnectionError as e:
                if "Max retries exceeded" in str(e) or "429" in str(e):
                    self.errors.append(f"Rate limited: {url}")
                    time.sleep(2 ** attempt)  # Backoff exponencial
                    continue
                if attempt == self.retries - 1:
                    self.errors.append(f"Erro de conexão: {url}")
                    logger.error(f"Erro de conexão para {url}: {e}")
                continue
                
            except requests.exceptions.RequestException as e:
                self.errors.append(f"Erro de requisição: {url} - {e}")
                logger.error(f"Erro de requisição para {url}: {e}")
                break
        
        return None
    
    def _is_false_positive(self, response, url):
        """Verifica se a resposta é um false positive baseado no baseline 404."""
        if not self.baseline_404 or not response:
            return response is None or response.status_code == 404
        
        content_length = len(response.content)
        content_hash = hashlib.md5(response.content).hexdigest()
        
        # Verifica contra padrões conhecidos de 404
        if (response.status_code in self.baseline_404['status_codes'] and
            content_hash in self.baseline_404['content_hashes']):
            self.false_positives_filtered += 1
            return True
        
        # Verifica similaridade de tamanho (páginas 404 customizadas)
        if (response.status_code == self.baseline_404['common_status'] and
            abs(content_length - self.baseline_404['avg_length']) < 50):
            
            # Análise adicional de conteúdo para páginas similares
            if self._content_similarity_check(response.text):
                self.false_positives_filtered += 1
                return True
        
        return False
    
    def _content_similarity_check(self, content):
        """Verifica similaridade de conteúdo com amostras 404."""
        if not self.baseline_404:
            return False
        
        # Palavras-chave comuns em páginas 404
        error_keywords = ['not found', '404', 'page not found', 'file not found', 
                         'does not exist', 'cannot be found', 'error']
        
        content_lower = content.lower()
        
        # Se contém muitas palavras-chave de erro, provavelmente é 404
        keyword_count = sum(1 for keyword in error_keywords if keyword in content_lower)
        
        return keyword_count >= 2
    
    def _analyze_response(self, response, url):
        """Análise abrangente da resposta HTTP."""
        if not response:
            return None
        
        # Verifica se é false positive primeiro
        if self._is_false_positive(response, url):
            return None
        
        status = response.status_code
        headers = response.headers
        
        result = {
            'url': url,
            'status': status,
            'length': len(response.content),
            'content_type': headers.get('Content-Type', ''),
            'server': headers.get('Server', ''),
            'redirect_location': '',
            'directory_type': 'unknown',
            'interesting_headers': {},
            'notes': []
        }
        
        # Análise específica por status code
        if status == 200:
            result.update(self._analyze_200_response(response, url))
        elif status == 403:
            result.update(self._analyze_403_response(response, url))
        elif status in [301, 302, 303, 307, 308]:
            result.update(self._analyze_redirect_response(response, url))
        elif status == 401:
            result.update(self._analyze_auth_required(response, url))
        elif status == 405:
            result.update(self._analyze_method_not_allowed(response, url))
        elif status == 500:
            result['notes'].append('Internal Server Error - possível vulnerabilidade')
        
        # Detecta headers interessantes
        interesting_headers = {}
        for header, value in headers.items():
            if header.lower() in ['server', 'x-powered-by', 'x-generator', 'x-drupal-cache']:
                interesting_headers[header] = value
        
        result['interesting_headers'] = interesting_headers
        
        return result
    
    def _analyze_200_response(self, response, url):
        """Analisa resposta 200 OK."""
        content = response.text.lower()
        
        analysis = {
            'directory_type': 'file',
            'notes': []
        }
        
        # Detecta se é um diretório baseado no conteúdo
        if ('index of' in content or 
            'directory listing' in content or
            '<title>index of' in content):
            analysis['directory_type'] = 'directory_listing'
            analysis['notes'].append('Directory listing ativo')
        
        # Detecta tecnologias baseadas no conteúdo
        if 'wp-content' in content or 'wordpress' in content:
            self.detected_technologies.add('wordpress')
            analysis['notes'].append('WordPress detectado')
        elif 'drupal' in content:
            self.detected_technologies.add('drupal')
            analysis['notes'].append('Drupal detectado')
        elif 'joomla' in content:
            self.detected_technologies.add('joomla')
            analysis['notes'].append('Joomla detectado')
        
        # Detecta arquivos sensíveis
        sensitive_indicators = {
            'config': 'Arquivo de configuração',
            'database': 'Arquivo de database',
            'backup': 'Arquivo de backup',
            'admin': 'Painel administrativo',
            'login': 'Página de login',
            '.env': 'Arquivo de ambiente',
            'robots.txt': 'Arquivo robots.txt'
        }
        
        for keyword, description in sensitive_indicators.items():
            if keyword in url.lower():
                analysis['notes'].append(description)
                break
        
        return analysis
    
    def _analyze_403_response(self, response, url):
        """Analisa resposta 403 Forbidden."""
        return {
            'directory_type': 'directory_protected',
            'notes': ['Diretório protegido - potencial interesse']
        }
    
    def _analyze_redirect_response(self, response, url):
        """Analisa respostas de redirecionamento."""
        location = response.headers.get('Location', '')
        
        analysis = {
            'redirect_location': location,
            'directory_type': 'redirect',
            'notes': [f'Redireciona para: {location}']
        }
        
        # Se redireciona para URL com trailing slash, é provavelmente um diretório
        if location.endswith('/') and not url.endswith('/'):
            analysis['directory_type'] = 'directory'
            analysis['notes'].append('Diretório confirmado pelo redirect')
        
        return analysis
    
    def _analyze_auth_required(self, response, url):
        """Analisa resposta 401 Unauthorized."""
        auth_type = response.headers.get('WWW-Authenticate', '')
        
        return {
            'directory_type': 'auth_required',
            'notes': [f'Autenticação requerida: {auth_type}']
        }
    
    def _analyze_method_not_allowed(self, response, url):
        """Analisa resposta 405 Method Not Allowed."""
        allowed_methods = response.headers.get('Allow', '')
        
        return {
            'directory_type': 'method_restricted',
            'notes': [f'Métodos permitidos: {allowed_methods}']
        }
    
    def _load_wordlist(self):
        """Carrega e processa wordlist."""
        if not self.wordlist_path:
            return []
        
        try:
            with open(self.wordlist_path, 'r', errors='ignore') as f:
                words = [line.strip() for line in f 
                        if line.strip() and not line.startswith('#')]
            
            # Remove duplicatas e ordena
            words = list(set(words))
            
            # Adiciona extensões se habilitado
            if self.extension_fuzzing:
                words = self._add_file_extensions(words)
            
            return words
            
        except FileNotFoundError:
            console.print(f"[bold red][!] Wordlist não encontrada: {self.wordlist_path}[/bold red]")
            logger.error(f"Wordlist não encontrada: {self.wordlist_path}")
            return []
    
    def _add_file_extensions(self, words):
        """Adiciona extensões de arquivo baseadas nas tecnologias detectadas."""
        extensions = ['.txt', '.html', '.php', '.asp', '.aspx', '.jsp', '.js', '.css']
        
        # Extensões específicas por tecnologia
        if 'wordpress' in self.detected_technologies:
            extensions.extend(['.php', '.inc', '.conf'])
        if 'drupal' in self.detected_technologies:
            extensions.extend(['.module', '.install', '.inc'])
        if 'asp' in self.detected_technologies:
            extensions.extend(['.asp', '.aspx', '.config'])
        
        extended_words = words.copy()
        
        # Adiciona extensões apenas para palavras sem extensão
        for word in words:
            if '.' not in word.split('/')[-1]:  # Se não tem extensão
                for ext in extensions:
                    extended_words.append(f"{word}{ext}")
        
        return extended_words
    
    def scan(self, recursive=False, max_depth=3, stealth=False, output_format='table'):
        """Executa o scan principal de diretórios."""
        self.recursive_enabled = recursive
        self.max_depth = max_depth
        self.stealth_mode = stealth
        
        console.print("-" * 60)
        console.print(f"[*] Scanner Avançado de Diretórios - Spectra")
        console.print(f"[*] Alvo: [bold cyan]{self.base_url}[/bold cyan]")
        console.print(f"[*] Wordlist: [bold cyan]{self.wordlist_path}[/bold cyan]")
        console.print(f"[*] Workers: [bold cyan]{self.workers}[/bold cyan]")
        console.print(f"[*] Timeout: [bold cyan]{self.timeout}s[/bold cyan]")
        
        if recursive:
            console.print(f"[*] Modo Recursivo: [bold green]Ativado[/bold green] (Máx: {max_depth})")
        else:
            console.print(f"[*] Modo Recursivo: [bold red]Desativado[/bold red]")
        
        if stealth:
            console.print(f"[*] Modo Stealth: [bold yellow]Ativado[/bold yellow]")
        
        console.print("-" * 60)
        
        # Setup inicial
        self._setup_session()
        self._detect_waf()
        self._detect_baseline_404()
        
        # Carrega wordlist
        words = self._load_wordlist()
        if not words:
            console.print("[bold red][!] Nenhuma palavra encontrada na wordlist[/bold red]")
            return []
        
        console.print(f"[*] Carregadas [bold cyan]{len(words)}[/bold cyan] palavras para teste")
        
        # Executa scan principal
        self.results = self._scan_directory(self.base_url, words, depth=1)
        
        # Exibe resultados
        self._display_results(output_format)
        
        # Estatísticas finais
        console.print("-" * 60)
        console.print(f"[*] Scan concluído:")
        console.print(f"    • {len(self.results)} recursos encontrados")
        console.print(f"    • {self.requests_made} requisições realizadas")
        console.print(f"    • {self.false_positives_filtered} falsos positivos filtrados")
        console.print(f"    • {len(self.errors)} erros encontrados")
        
        if self.errors:
            console.print(f"[bold yellow][!] Primeiros 5 erros:[/bold yellow]")
            for error in self.errors[:5]:
                console.print(f"    [dim]{error}[/dim]")
        
        console.print("-" * 60)
        
        logger.info(f"Scan concluído: {len(self.results)} recursos encontrados")
        return self.results
    
    def _scan_directory(self, base_url, words, depth=1, visited=None):
        """Executa scan de um diretório específico."""
        if visited is None:
            visited = set()
        
        if depth > self.max_depth:
            return []
        
        results = []
        
        # Cria URLs para testar
        urls_to_test = []
        for word in words:
            url = f"{base_url}/{word}"
            if url not in visited:
                urls_to_test.append(url)
                visited.add(url)
        
        if not urls_to_test:
            return results
        
        console.print(f"[*] Testando {len(urls_to_test)} URLs (profundidade {depth})...")
        
        # Executa requests em paralelo
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            future_to_url = {
                executor.submit(self._make_request, url): url 
                for url in urls_to_test
            }
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeRemainingColumn(),
                console=console
            ) as progress:
                task = progress.add_task(f"[green]Scan profundidade {depth}...", total=len(future_to_url))
                
                directories_found = []
                
                for future in as_completed(future_to_url):
                    url = future_to_url[future]
                    response = future.result()
                    
                    # Analisa resposta
                    analysis = self._analyze_response(response, url)
                    
                    if analysis:
                        results.append(analysis)
                        
                        # Mostra resultado em tempo real
                        status = analysis['status']
                        notes = ' | '.join(analysis['notes']) if analysis['notes'] else ''
                        
                        if status == 200:
                            color = "green"
                        elif status == 403:
                            color = "yellow"
                        elif str(status).startswith('3'):
                            color = "cyan"
                        else:
                            color = "white"
                        
                        console.print(f"[bold {color}][+] {url} ({status})[/bold {color}] {notes}")
                        
                        # Se é um diretório e modo recursivo está ativo
                        if (self.recursive_enabled and 
                            analysis['directory_type'] in ['directory', 'directory_listing'] and
                            depth < self.max_depth):
                            directories_found.append(url)
                    
                    progress.update(task, advance=1)
                    
                    if self.stealth_mode:
                        time.sleep(0.1)  # Delay em modo stealth
        
        # Scan recursivo dos diretórios encontrados
        if self.recursive_enabled and directories_found:
            console.print(f"[*] Encontrados {len(directories_found)} diretórios para scan recursivo")
            
            for directory in directories_found:
                recursive_results = self._scan_directory(directory, words, depth + 1, visited)
                results.extend(recursive_results)
        
        return results
    
    def _display_results(self, output_format='table'):
        """Exibe resultados em diferentes formatos."""
        if output_format == 'json':
            import json
            print(json.dumps(self.results, indent=2, default=str))
            return
        
        if not self.results:
            console.print("[bold yellow][-] Nenhum recurso encontrado.[/bold yellow]")
            return
        
        # Organiza resultados por status
        self.results.sort(key=lambda x: (x['status'], x['url']))
        
        # Tabela principal
        table = Table(title=f"Recursos Descobertos - {self.base_url}")
        table.add_column("URL", style="cyan", no_wrap=False)
        table.add_column("Status", justify="center", style="green")
        table.add_column("Tamanho", justify="right", style="yellow")
        table.add_column("Tipo", style="magenta")
        table.add_column("Notas", style="dim", max_width=40)
        
        for result in self.results:
            url = result['url']
            status = str(result['status'])
            size = str(result['length'])
            dir_type = result['directory_type']
            notes = ' | '.join(result['notes']) if result['notes'] else ''
            
            table.add_row(url, status, size, dir_type, notes)
        
        console.print(table)
        
        # Estatísticas por tipo
        type_stats = Counter(r['directory_type'] for r in self.results)
        if type_stats:
            console.print(f"\n[*] Tipos encontrados:")
            for dir_type, count in type_stats.most_common():
                console.print(f"    • {dir_type}: {count}")
        
        # Tecnologias detectadas
        if self.detected_technologies:
            console.print(f"\n[*] Tecnologias detectadas: [cyan]{', '.join(self.detected_technologies)}[/cyan]")


# Funções para compatibilidade com versão anterior
def advanced_directory_scan(base_url, wordlist_path, workers=30, timeout=10, 
                          recursive=False, max_depth=3, stealth=False, 
                          extension_fuzzing=True, output_format='table'):
    """
    Interface para o scanner avançado de diretórios.
    
    Args:
        base_url (str): URL base para scan
        wordlist_path (str): Caminho para wordlist
        workers (int): Número de workers
        timeout (int): Timeout em segundos
        recursive (bool): Ativar modo recursivo
        max_depth (int): Profundidade máxima
        stealth (bool): Modo stealth
        extension_fuzzing (bool): Fuzzing de extensões
        output_format (str): Formato de saída
        
    Returns:
        list: Lista de resultados encontrados
    """
    # Normaliza URL
    if not re.match(r'^https?://', base_url):
        base_url = 'http://' + base_url
    base_url = base_url.rstrip('/')
    
    # Cria e configura scanner
    scanner = AdvancedDirectoryScanner(base_url, wordlist_path, workers, timeout)
    scanner.extension_fuzzing = extension_fuzzing
    
    # Executa scan
    return scanner.scan(recursive, max_depth, stealth, output_format)


def check_directory(url, session):
    """
    Função legacy para compatibilidade - verifica um diretório específico.
    
    Args:
        url (str): URL para verificar
        session: Sessão HTTP
        
    Returns:
        tuple: (url, status_code, location) ou None
    """
    try:
        response = session.get(url, timeout=10, allow_redirects=False, verify=False)
        if response.status_code != 404:
            location = response.headers.get('Location', '')
            return (url, response.status_code, location)
    except Exception as e:
        logger.error(f"Erro ao verificar diretório {url}: {e}")
    
    return None
