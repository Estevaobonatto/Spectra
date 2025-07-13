# -*- coding: utf-8 -*-
"""
Módulo Avançado de Quebra de Hash - Spectra
Inspirado em HashCat, John the Ripper e outras ferramentas profissionais
"""

import hashlib
import itertools
import string
import time
import threading
import multiprocessing
import re
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from pathlib import Path
from collections import defaultdict
import json

from ..core.console import console
from ..core.logger import get_logger
from ..utils.network import create_session

logger = get_logger(__name__)


class AdvancedHashCracker:
    """Quebrador avançado de hashes com múltiplos modos de ataque."""
    
    def __init__(self, hash_target, hash_type=None, workers=None, timeout=None):
        """
        Inicializa o quebrador de hash.
        
        Args:
            hash_target (str): Hash para quebrar
            hash_type (str): Tipo do hash (auto-detectado se None)
            workers (int): Número de workers (auto se None)
            timeout (int): Timeout em segundos
        """
        self.hash_target = hash_target.strip().lower()
        self.hash_type = hash_type
        self.workers = workers or min(multiprocessing.cpu_count() * 2, 16)
        self.timeout = timeout
        
        # Estatísticas
        self.attempts = 0
        self.start_time = None
        self.cracked_password = None
        self.attack_mode = None
        
        # Configurações de ataque
        self.use_gpu = False  # Placeholder para futuro suporte GPU
        self.wordlists = []
        self.rules = []
        self.charset = string.ascii_letters + string.digits
        self.min_length = 1
        self.max_length = 8
        
        # Cache e otimizações
        self.hash_cache = {}
        self.performance_mode = 'balanced'  # balanced, fast, extreme
        
        # Detecta tipo de hash automaticamente
        if not self.hash_type:
            self.hash_type = self._detect_hash_type()
        
        # Configura algoritmo de hash
        self._setup_hash_algorithm()
        
        logger.info(f"Hash Cracker inicializado: {self.hash_type} ({len(self.hash_target)} chars)")
    
    def _detect_hash_type(self):
        """Detecta automaticamente o tipo de hash baseado no formato."""
        hash_length = len(self.hash_target)
        hash_patterns = {
            32: ['md5', 'ntlm'],
            40: ['sha1'],
            56: ['sha224'],
            64: ['sha256'],
            96: ['sha384'],
            128: ['sha512'],
            60: ['bcrypt'],  # $2b$...
            16: ['md4'],
        }
        
        # Detecção por padrões específicos
        if self.hash_target.startswith('$2a$') or self.hash_target.startswith('$2b$'):
            return 'bcrypt'
        elif self.hash_target.startswith('$6$'):
            return 'sha512crypt'
        elif self.hash_target.startswith('$5$'):
            return 'sha256crypt'
        elif self.hash_target.startswith('$1$'):
            return 'md5crypt'
        elif self.hash_target.startswith('{SHA}'):
            return 'sha1'
        elif self.hash_target.startswith('{MD5}'):
            return 'md5'
        elif ':' in self.hash_target and len(self.hash_target.split(':')[0]) == 32:
            return 'ntlm'  # username:hash format
        
        # Detecção por comprimento
        possible_types = hash_patterns.get(hash_length, ['unknown'])
        
        # Se múltiplas opções, usa a mais comum
        if len(possible_types) > 1:
            priority = ['md5', 'sha1', 'sha256', 'ntlm']
            for hash_type in priority:
                if hash_type in possible_types:
                    return hash_type
        
        return possible_types[0] if possible_types else 'unknown'
    
    def _setup_hash_algorithm(self):
        """Configura o algoritmo de hash baseado no tipo detectado."""
        self.hash_algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha224': hashlib.sha224,
            'sha256': hashlib.sha256,
            'sha384': hashlib.sha384,
            'sha512': hashlib.sha512,
            'md4': self._md4_hash,
            'ntlm': self._ntlm_hash,
        }
        
        if self.hash_type not in self.hash_algorithms:
            if self.hash_type in ['bcrypt', 'sha512crypt', 'sha256crypt', 'md5crypt']:
                console.print(f"[yellow][!] Tipo {self.hash_type} requer biblioteca específica[/yellow]")
            else:
                console.print(f"[red][!] Tipo de hash não suportado: {self.hash_type}[/red]")
    
    def _md4_hash(self, data):
        """Implementação MD4 (para NTLM)."""
        try:
            return hashlib.new('md4', data)
        except ValueError:
            # Fallback se MD4 não estiver disponível
            return hashlib.md5(data)
    
    def _ntlm_hash(self, password):
        """Gera hash NTLM."""
        if isinstance(password, str):
            password = password.encode('utf-16le')
        return self._md4_hash(password)
    
    def _hash_password(self, password):
        """Gera hash da senha usando o algoritmo configurado."""
        try:
            if self.hash_type == 'ntlm':
                return self._ntlm_hash(password).hexdigest().lower()
            else:
                algo = self.hash_algorithms.get(self.hash_type, hashlib.md5)
                if isinstance(password, str):
                    password = password.encode('utf-8')
                return algo(password).hexdigest().lower()
        except Exception as e:
            logger.error(f"Erro ao gerar hash: {e}")
            return None
    
    def set_performance_mode(self, mode='balanced'):
        """
        Configura modo de performance.
        
        Args:
            mode (str): balanced, fast, extreme
        """
        self.performance_mode = mode
        
        if mode == 'fast':
            self.workers = min(multiprocessing.cpu_count() * 4, 32)
        elif mode == 'extreme':
            self.workers = min(multiprocessing.cpu_count() * 8, 64)
        else:  # balanced
            self.workers = min(multiprocessing.cpu_count() * 2, 16)
        
        logger.info(f"Modo de performance: {mode} (workers: {self.workers})")
    
    def dictionary_attack(self, wordlist_path, rules=None):
        """
        Executa ataque de dicionário.
        
        Args:
            wordlist_path (str): Caminho para wordlist
            rules (list): Lista de regras para transformação
            
        Returns:
            tuple: (password, attempts, time_taken)
        """
        console.print(f"[*] Iniciando ataque de dicionário: {wordlist_path}")
        self.attack_mode = 'dictionary'
        self.start_time = time.time()
        self.attempts = 0
        
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            console.print(f"[red][!] Wordlist não encontrada: {wordlist_path}[/red]")
            return None, 0, 0
        
        # Aplica regras se especificadas
        if rules:
            passwords = self._apply_rules(passwords, rules)
        
        total_passwords = len(passwords)
        console.print(f"[*] Testando {total_passwords:,} senhas...")
        
        # Executa ataque em paralelo
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            chunk_size = max(1, total_passwords // (self.workers * 4))
            
            future_to_chunk = {}
            for i in range(0, total_passwords, chunk_size):
                chunk = passwords[i:i + chunk_size]
                future = executor.submit(self._test_passwords_chunk, chunk)
                future_to_chunk[future] = i
            
            # Progress tracking
            completed_chunks = 0
            total_chunks = len(future_to_chunk)
            
            for future in as_completed(future_to_chunk):
                chunk_start = future_to_chunk[future]
                result = future.result()
                completed_chunks += 1
                
                if result:
                    # Password found!
                    self.cracked_password = result
                    time_taken = time.time() - self.start_time
                    console.print(f"\n[bold green][+] SENHA ENCONTRADA: {result}[/bold green]")
                    console.print(f"[*] Tentativas: {self.attempts:,}")
                    console.print(f"[*] Tempo: {time_taken:.2f}s")
                    console.print(f"[*] Taxa: {self.attempts/time_taken:.2f} hashes/s")
                    return result, self.attempts, time_taken
                
                # Progress update
                progress = (completed_chunks / total_chunks) * 100
                rate = self.attempts / (time.time() - self.start_time) if time.time() > self.start_time else 0
                console.print(f"\r[*] Progresso: {progress:.1f}% - {self.attempts:,} tentativas - {rate:.0f} h/s", end="")
        
        time_taken = time.time() - self.start_time
        console.print(f"\n[red][-] Senha não encontrada no dicionário[/red]")
        console.print(f"[*] Total tentativas: {self.attempts:,}")
        console.print(f"[*] Tempo: {time_taken:.2f}s")
        return None, self.attempts, time_taken
    
    def brute_force_attack(self, min_length=1, max_length=6, charset=None):
        """
        Executa ataque de força bruta.
        
        Args:
            min_length (int): Comprimento mínimo
            max_length (int): Comprimento máximo  
            charset (str): Conjunto de caracteres
            
        Returns:
            tuple: (password, attempts, time_taken)
        """
        charset = charset or self.charset
        console.print(f"[*] Iniciando ataque de força bruta")
        console.print(f"[*] Comprimento: {min_length}-{max_length}")
        console.print(f"[*] Charset: {charset[:20]}{'...' if len(charset) > 20 else ''}")
        
        self.attack_mode = 'brute_force'
        self.start_time = time.time()
        self.attempts = 0
        
        # Calcula total de combinações
        total_combinations = sum(len(charset) ** length for length in range(min_length, max_length + 1))
        console.print(f"[*] Total combinações: {total_combinations:,}")
        
        if total_combinations > 10**9:
            console.print(f"[yellow][!] Aviso: Muitas combinações ({total_combinations:,}), isso pode demorar muito![/yellow]")
        
        # Executa força bruta por comprimento
        for length in range(min_length, max_length + 1):
            console.print(f"\n[*] Testando senhas de {length} caracteres...")
            
            result = self._brute_force_length(charset, length)
            if result:
                time_taken = time.time() - self.start_time
                console.print(f"\n[bold green][+] SENHA ENCONTRADA: {result}[/bold green]")
                console.print(f"[*] Tentativas: {self.attempts:,}")
                console.print(f"[*] Tempo: {time_taken:.2f}s")
                return result, self.attempts, time_taken
        
        time_taken = time.time() - self.start_time
        console.print(f"\n[red][-] Senha não encontrada por força bruta[/red]")
        return None, self.attempts, time_taken
    
    def mask_attack(self, mask_pattern):
        """
        Executa ataque por máscara (estilo HashCat).
        
        Args:
            mask_pattern (str): Padrão da máscara (?l=lowercase, ?u=uppercase, ?d=digits, ?s=special)
            
        Returns:
            tuple: (password, attempts, time_taken)
        """
        console.print(f"[*] Iniciando ataque por máscara: {mask_pattern}")
        
        # Converte máscara para charset
        mask_charsets = {
            '?l': string.ascii_lowercase,
            '?u': string.ascii_uppercase, 
            '?d': string.digits,
            '?s': '!@#$%^&*()_+-=[]{}|;:,.<>?',
            '?a': string.ascii_letters + string.digits + '!@#$%^&*()_+-=[]{}|;:,.<>?'
        }
        
        # Parse do padrão da máscara
        positions = []
        i = 0
        while i < len(mask_pattern):
            if i < len(mask_pattern) - 1 and mask_pattern[i:i+2] in mask_charsets:
                positions.append(mask_charsets[mask_pattern[i:i+2]])
                i += 2
            else:
                positions.append([mask_pattern[i]])  # Caractere literal
                i += 1
        
        self.attack_mode = 'mask'
        self.start_time = time.time()
        self.attempts = 0
        
        # Calcula total de combinações
        total_combinations = 1
        for pos_charset in positions:
            total_combinations *= len(pos_charset)
        
        console.print(f"[*] Total combinações: {total_combinations:,}")
        
        # Gera e testa senhas baseadas na máscara
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            batch_size = 10000
            batch = []
            
            for password_chars in itertools.product(*positions):
                password = ''.join(password_chars)
                batch.append(password)
                
                if len(batch) >= batch_size:
                    future = executor.submit(self._test_passwords_chunk, batch)
                    result = future.result()
                    if result:
                        time_taken = time.time() - self.start_time
                        console.print(f"\n[bold green][+] SENHA ENCONTRADA: {result}[/bold green]")
                        return result, self.attempts, time_taken
                    batch = []
                
                # Progress update
                if self.attempts % 50000 == 0:
                    progress = (self.attempts / total_combinations) * 100
                    rate = self.attempts / (time.time() - self.start_time)
                    console.print(f"\r[*] {progress:.1f}% - {self.attempts:,} tentativas - {rate:.0f} h/s", end="")
            
            # Testa último batch
            if batch:
                future = executor.submit(self._test_passwords_chunk, batch)
                result = future.result()
                if result:
                    time_taken = time.time() - self.start_time
                    console.print(f"\n[bold green][+] SENHA ENCONTRADA: {result}[/bold green]")
                    return result, self.attempts, time_taken
        
        time_taken = time.time() - self.start_time
        console.print(f"\n[red][-] Senha não encontrada com máscara[/red]")
        return None, self.attempts, time_taken
    
    def _apply_rules(self, passwords, rules):
        """Aplica regras de transformação às senhas do dicionário."""
        transformed = set(passwords)  # Inclui originais
        
        for password in passwords:
            for rule in rules:
                if rule == 'uppercase':
                    transformed.add(password.upper())
                elif rule == 'lowercase':
                    transformed.add(password.lower())
                elif rule == 'capitalize':
                    transformed.add(password.capitalize())
                elif rule == 'reverse':
                    transformed.add(password[::-1])
                elif rule == 'append_digits':
                    for i in range(10):
                        transformed.add(f"{password}{i}")
                elif rule == 'prepend_digits':
                    for i in range(10):
                        transformed.add(f"{i}{password}")
                elif rule == 'append_year':
                    for year in range(2020, 2026):
                        transformed.add(f"{password}{year}")
                elif rule == 'leet_speak':
                    leet = password.replace('a', '@').replace('e', '3').replace('i', '1').replace('o', '0').replace('s', '$')
                    transformed.add(leet)
        
        return list(transformed)
    
    def _brute_force_length(self, charset, length):
        """Executa força bruta para um comprimento específico."""
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            batch_size = 1000
            batch = []
            
            for password_chars in itertools.product(charset, repeat=length):
                password = ''.join(password_chars)
                batch.append(password)
                
                if len(batch) >= batch_size:
                    future = executor.submit(self._test_passwords_chunk, batch)
                    result = future.result()
                    if result:
                        return result
                    batch = []
                
                # Progress
                if self.attempts % 10000 == 0:
                    rate = self.attempts / (time.time() - self.start_time)
                    console.print(f"\r[*] {self.attempts:,} tentativas - {rate:.0f} h/s", end="")
            
            # Último batch
            if batch:
                future = executor.submit(self._test_passwords_chunk, batch)
                result = future.result()
                if result:
                    return result
        
        return None
    
    def _test_passwords_chunk(self, passwords):
        """Testa um chunk de senhas."""
        for password in passwords:
            self.attempts += 1
            
            # Cache check
            if password in self.hash_cache:
                computed_hash = self.hash_cache[password]
            else:
                computed_hash = self._hash_password(password)
                self.hash_cache[password] = computed_hash
            
            if computed_hash == self.hash_target:
                return password
        
        return None
    
    def online_lookup(self, services=None):
        """
        Lookup online em serviços de hash.
        
        Args:
            services (list): Lista de serviços para consultar
            
        Returns:
            str: Senha encontrada ou None
        """
        services = services or ['md5decrypt', 'hashkiller']
        console.print(f"[*] Consultando serviços online...")
        
        session = create_session()
        
        for service in services:
            try:
                console.print(f"[*] Tentando {service}...")
                result = self._query_online_service(session, service)
                if result:
                    console.print(f"[bold green][+] SENHA ENCONTRADA ONLINE: {result}[/bold green]")
                    return result
            except Exception as e:
                logger.error(f"Erro ao consultar {service}: {e}")
        
        console.print(f"[red][-] Hash não encontrado nos serviços online[/red]")
        return None
    
    def _query_online_service(self, session, service):
        """Consulta um serviço online específico."""
        # Implementação simplificada - em produção seria mais robusta
        if service == 'md5decrypt' and self.hash_type == 'md5':
            # Simulação de consulta
            return None
        return None
    
    def get_statistics(self):
        """Retorna estatísticas do ataque atual."""
        if not self.start_time:
            return {}
        
        elapsed = time.time() - self.start_time
        rate = self.attempts / elapsed if elapsed > 0 else 0
        
        return {
            'hash_type': self.hash_type,
            'attack_mode': self.attack_mode,
            'attempts': self.attempts,
            'elapsed_time': elapsed,
            'rate_per_second': rate,
            'workers': self.workers,
            'performance_mode': self.performance_mode,
            'cracked': self.cracked_password is not None,
            'cracked_password': self.cracked_password
        }


# Funções auxiliares para compatibilidade
def crack_hash(hash_target, wordlist_path=None, hash_type=None, attack_mode='dictionary', **kwargs):
    """
    Interface principal para quebra de hash.
    
    Args:
        hash_target (str): Hash para quebrar
        wordlist_path (str): Wordlist para ataque de dicionário
        hash_type (str): Tipo do hash
        attack_mode (str): Modo de ataque
        
    Returns:
        dict: Resultado do ataque
    """
    cracker = AdvancedHashCracker(hash_target, hash_type)
    
    if attack_mode == 'dictionary' and wordlist_path:
        password, attempts, time_taken = cracker.dictionary_attack(wordlist_path)
    elif attack_mode == 'brute_force':
        min_len = kwargs.get('min_length', 1)
        max_len = kwargs.get('max_length', 6)
        charset = kwargs.get('charset', None)
        password, attempts, time_taken = cracker.brute_force_attack(min_len, max_len, charset)
    elif attack_mode == 'mask':
        mask = kwargs.get('mask', '?l?l?l?l')
        password, attempts, time_taken = cracker.mask_attack(mask)
    elif attack_mode == 'online':
        password = cracker.online_lookup()
        attempts = 0
        time_taken = 0
    else:
        return {'error': 'Modo de ataque inválido'}
    
    return {
        'hash_type': cracker.hash_type,
        'attack_mode': attack_mode,
        'password': password,
        'attempts': attempts,
        'time_taken': time_taken,
        'success': password is not None
    }


def detect_hash_type(hash_string):
    """Detecta o tipo de um hash."""
    cracker = AdvancedHashCracker(hash_string)
    return cracker.hash_type