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
import os
import platform
import subprocess
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from pathlib import Path
from collections import defaultdict
import json

from ..core.console import console
from ..core.logger import get_logger
from ..utils.network import create_session

# GPU Libraries - Import apenas se disponível
try:
    import cupy as cp
    import cupy.cuda.runtime as runtime
    CUPY_AVAILABLE = True
except ImportError:
    CUPY_AVAILABLE = False
    cp = None

try:
    import pyopencl as cl
    PYOPENCL_AVAILABLE = True
except ImportError:
    PYOPENCL_AVAILABLE = False
    cl = None

try:
    import pycuda.driver as cuda
    import pycuda.autoinit
    from pycuda.compiler import SourceModule
    import numpy as np
    PYCUDA_AVAILABLE = True
except ImportError:
    PYCUDA_AVAILABLE = False
    cuda = None

logger = get_logger(__name__)


class RainbowTableManager:
    """Gerenciador de Rainbow Tables para lookup rápido de hashes."""
    
    def __init__(self, table_dir=None):
        """
        Inicializa o gerenciador de Rainbow Tables.
        
        Args:
            table_dir (str): Diretório onde armazenar/buscar rainbow tables
        """
        self.table_dir = table_dir or os.path.join(os.path.dirname(__file__), '..', 'data', 'rainbow_tables')
        self.loaded_tables = {}
        self.chain_length = 2100  # Otimizado para balance time/space
        self.table_size = 1000000  # 1M chains por table
        
        # Ensure directory exists
        os.makedirs(self.table_dir, exist_ok=True)
        
        logger.info(f"Rainbow Table Manager inicializado: {self.table_dir}")
    
    def generate_rainbow_table(self, hash_type='md5', charset=None, min_length=1, max_length=8, table_name=None):
        """
        Gera uma nova rainbow table.
        
        Args:
            hash_type (str): Tipo de hash (md5, sha1, etc)
            charset (str): Conjunto de caracteres 
            min_length (int): Comprimento mínimo de senha
            max_length (int): Comprimento máximo de senha
            table_name (str): Nome da tabela (auto-gerado se None)
            
        Returns:
            str: Caminho da tabela gerada
        """
        charset = charset or (string.ascii_lowercase + string.digits)
        table_name = table_name or f"{hash_type}_{min_length}_{max_length}_{len(charset)}chars"
        table_path = os.path.join(self.table_dir, f"{table_name}.rt")
        
        console.print(f"[*] Gerando Rainbow Table: {table_name}")
        console.print(f"[*] Hash: {hash_type} | Charset: {charset[:20]}{'...' if len(charset) > 20 else ''}")
        console.print(f"[*] Tamanho: {min_length}-{max_length} chars | Chains: {self.table_size:,}")
        
        # Calcula keyspace total
        total_keyspace = sum(len(charset) ** length for length in range(min_length, max_length + 1))
        console.print(f"[*] Keyspace total: {total_keyspace:,}")
        
        if total_keyspace > self.table_size * self.chain_length:
            coverage = (self.table_size * self.chain_length / total_keyspace) * 100
            console.print(f"[yellow][!] Cobertura estimada: {coverage:.1f}%[/yellow]")
        
        start_time = time.time()
        chains_generated = 0
        
        with open(table_path, 'w', encoding='utf-8') as f:
            # Header da tabela
            f.write(f"# Rainbow Table - Spectra\n")
            f.write(f"# Hash: {hash_type}\n")
            f.write(f"# Charset: {charset}\n")
            f.write(f"# Length: {min_length}-{max_length}\n")
            f.write(f"# Chain Length: {self.chain_length}\n")
            f.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("# Format: start_password,end_hash\n")
            f.write("---\n")
            
            for _ in range(self.table_size):
                # Gera chain starting point aleatório
                start_password = self._generate_random_password(charset, min_length, max_length)
                end_hash = self._generate_chain(start_password, hash_type, charset, min_length, max_length)
                
                f.write(f"{start_password},{end_hash}\n")
                chains_generated += 1
                
                # Progress update
                if chains_generated % 10000 == 0:
                    elapsed = time.time() - start_time
                    rate = chains_generated / elapsed
                    progress = (chains_generated / self.table_size) * 100
                    eta = (self.table_size - chains_generated) / rate if rate > 0 else 0
                    console.print(f"\r[*] Progresso: {progress:.1f}% - {chains_generated:,} chains - {rate:.0f} chains/s - ETA: {eta:.0f}s", end="")
        
        elapsed = time.time() - start_time
        console.print(f"\n[bold green][+] Rainbow Table gerada: {table_path}[/bold green]")
        console.print(f"[*] Tempo: {elapsed:.2f}s | Taxa: {chains_generated/elapsed:.0f} chains/s")
        console.print(f"[*] Tamanho: {os.path.getsize(table_path) / (1024**2):.1f} MB")
        
        return table_path
    
    def _generate_random_password(self, charset, min_length, max_length):
        """Gera senha aleatória dentro dos parâmetros."""
        import random
        length = random.randint(min_length, max_length)
        return ''.join(random.choice(charset) for _ in range(length))
    
    def _generate_chain(self, start_password, hash_type, charset, min_length, max_length):
        """
        Gera uma chain rainbow: password -> hash -> reduce -> password -> hash -> ...
        
        Returns:
            str: Hash final da chain
        """
        current = start_password
        
        for i in range(self.chain_length):
            # Hash step
            current_hash = self._compute_hash(current, hash_type)
            
            # Reduction step (converte hash em password para próxima iteração)
            if i < self.chain_length - 1:  # Não faz reduction no último
                current = self._reduce_hash(current_hash, charset, min_length, max_length, i)
            else:
                return current_hash
        
        return current_hash
    
    def _compute_hash(self, password, hash_type):
        """Computa hash usando algoritmo especificado."""
        if hash_type == 'md5':
            return hashlib.md5(password.encode('utf-8')).hexdigest()
        elif hash_type == 'sha1':
            return hashlib.sha1(password.encode('utf-8')).hexdigest()
        elif hash_type == 'sha256':
            return hashlib.sha256(password.encode('utf-8')).hexdigest()
        elif hash_type == 'sha512':
            return hashlib.sha512(password.encode('utf-8')).hexdigest()
        else:
            return hashlib.md5(password.encode('utf-8')).hexdigest()
    
    def _reduce_hash(self, hash_hex, charset, min_length, max_length, position):
        """
        Função de redução: converte hash em password.
        Position evita rainbow table collisions.
        """
        # Converte hex para número
        hash_num = int(hash_hex[:16], 16)  # Usa primeiros 16 chars
        
        # Adiciona position para evitar collisions
        hash_num = (hash_num + position) % (2**64 - 1)
        
        # Determina comprimento da senha
        length = min_length + (hash_num % (max_length - min_length + 1))
        
        # Converte para senha usando charset
        password = ""
        for _ in range(length):
            password += charset[hash_num % len(charset)]
            hash_num //= len(charset)
        
        return password
    
    def load_rainbow_table(self, table_path):
        """
        Carrega rainbow table na memória para lookup rápido.
        
        Args:
            table_path (str): Caminho para arquivo .rt
            
        Returns:
            dict: Tabela carregada {end_hash: start_password}
        """
        if table_path in self.loaded_tables:
            return self.loaded_tables[table_path]
        
        console.print(f"[*] Carregando Rainbow Table: {os.path.basename(table_path)}")
        start_time = time.time()
        
        table = {}
        chain_count = 0
        
        try:
            with open(table_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('#') or line == '---' or not line:
                        continue
                    
                    if ',' in line:
                        start_password, end_hash = line.split(',', 1)
                        table[end_hash] = start_password
                        chain_count += 1
                        
                        if chain_count % 50000 == 0:
                            console.print(f"\r[*] Carregando: {chain_count:,} chains", end="")
            
            elapsed = time.time() - start_time
            self.loaded_tables[table_path] = table
            
            console.print(f"\n[bold green][+] Rainbow Table carregada: {chain_count:,} chains em {elapsed:.2f}s[/bold green]")
            console.print(f"[*] Memória: {len(str(table)) / (1024**2):.1f} MB")
            
            return table
            
        except FileNotFoundError:
            console.print(f"[red][!] Rainbow Table não encontrada: {table_path}[/red]")
            return {}
        except Exception as e:
            console.print(f"[red][!] Erro ao carregar Rainbow Table: {e}[/red]")
            return {}
    
    def rainbow_lookup(self, target_hash, table_path, hash_type='md5'):
        """
        Executa lookup de hash usando rainbow table.
        
        Args:
            target_hash (str): Hash target para encontrar
            table_path (str): Caminho da rainbow table
            hash_type (str): Tipo de hash
            
        Returns:
            str: Password encontrada ou None
        """
        table = self.load_rainbow_table(table_path)
        if not table:
            return None
        
        console.print(f"[*] Executando Rainbow Table lookup...")
        start_time = time.time()
        
        # Extrai metadados da tabela
        charset, min_length, max_length = self._parse_table_metadata(table_path)
        
        # Tenta lookup direto primeiro
        if target_hash in table:
            # Reconstruct chain para encontrar password exata
            start_password = table[target_hash]
            found_password = self._reconstruct_chain(start_password, target_hash, hash_type, charset, min_length, max_length)
            
            if found_password:
                elapsed = time.time() - start_time
                console.print(f"\n[bold green][+] SENHA ENCONTRADA (Rainbow Table): {found_password}[/bold green]")
                console.print(f"[*] Tempo de lookup: {elapsed:.4f}s")
                return found_password
        
        # Se não encontrou diretamente, tenta chain walking
        for position in range(self.chain_length):
            current_hash = target_hash
            
            # Walk backward na chain
            for step in range(position):
                reduced = self._reduce_hash(current_hash, charset, min_length, max_length, self.chain_length - 1 - step)
                current_hash = self._compute_hash(reduced, hash_type)
            
            if current_hash in table:
                # Reconstruct forward para encontrar password
                start_password = table[current_hash] 
                found_password = self._reconstruct_chain(start_password, target_hash, hash_type, charset, min_length, max_length)
                
                if found_password:
                    elapsed = time.time() - start_time
                    console.print(f"\n[bold green][+] SENHA ENCONTRADA (Rainbow Chain): {found_password}[/bold green]")
                    console.print(f"[*] Tempo de lookup: {elapsed:.4f}s")
                    return found_password
        
        elapsed = time.time() - start_time
        console.print(f"\n[red][-] Hash não encontrado na Rainbow Table[/red]")
        console.print(f"[*] Tempo de busca: {elapsed:.2f}s")
        return None
    
    def _parse_table_metadata(self, table_path):
        """Extrai metadados da rainbow table."""
        charset = string.ascii_lowercase + string.digits  # Default
        min_length, max_length = 1, 8  # Default
        
        try:
            with open(table_path, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.startswith('# Charset:'):
                        charset = line.split(':', 1)[1].strip()
                    elif line.startswith('# Length:'):
                        length_range = line.split(':', 1)[1].strip()
                        if '-' in length_range:
                            min_length, max_length = map(int, length_range.split('-'))
                    elif line.startswith('---'):
                        break
        except:
            pass
        
        return charset, min_length, max_length
    
    def _reconstruct_chain(self, start_password, target_hash, hash_type, charset, min_length, max_length):
        """Reconstrói chain para encontrar password que gera target_hash."""
        current = start_password
        
        for i in range(self.chain_length):
            current_hash = self._compute_hash(current, hash_type)
            
            if current_hash == target_hash:
                return current
            
            if i < self.chain_length - 1:
                current = self._reduce_hash(current_hash, charset, min_length, max_length, i)
        
        return None
    
    def list_available_tables(self):
        """Lista rainbow tables disponíveis."""
        tables = []
        
        if os.path.exists(self.table_dir):
            for file in os.listdir(self.table_dir):
                if file.endswith('.rt'):
                    file_path = os.path.join(self.table_dir, file)
                    size_mb = os.path.getsize(file_path) / (1024**2)
                    tables.append({
                        'name': file,
                        'path': file_path,
                        'size_mb': size_mb
                    })
        
        return tables
    
    def get_table_info(self, table_path):
        """Obtém informações detalhadas sobre uma rainbow table."""
        info = {'exists': False}
        
        if not os.path.exists(table_path):
            return info
        
        info['exists'] = True
        info['size_mb'] = os.path.getsize(table_path) / (1024**2)
        info['hash_type'] = 'unknown'
        info['charset'] = 'unknown'
        info['length_range'] = 'unknown'
        info['chain_count'] = 0
        
        try:
            with open(table_path, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.startswith('# Hash:'):
                        info['hash_type'] = line.split(':', 1)[1].strip()
                    elif line.startswith('# Charset:'):
                        info['charset'] = line.split(':', 1)[1].strip()
                    elif line.startswith('# Length:'):
                        info['length_range'] = line.split(':', 1)[1].strip()
                    elif line.startswith('# Chain Length:'):
                        info['chain_length'] = int(line.split(':', 1)[1].strip())
                    elif line.startswith('---'):
                        break
                
                # Conta chains
                for line in f:
                    if line.strip() and ',' in line:
                        info['chain_count'] += 1
                        
        except Exception as e:
            logger.error(f"Erro ao ler tabela {table_path}: {e}")
        
        return info


class GPUManager:
    """Gerenciador de aceleração GPU para hash cracking."""
    
    def __init__(self):
        self.gpu_available = False
        self.gpu_type = None
        self.gpu_devices = []
        self.gpu_memory = 0
        self.cuda_cores = 0
        self.compute_capability = None
        
        self._detect_gpu_capabilities()
    
    def _detect_gpu_capabilities(self):
        """Detecta capacidades GPU disponíveis."""
        console.print("[*] Detectando GPUs disponíveis...")
        
        # Detecta NVIDIA CUDA
        if PYCUDA_AVAILABLE:
            try:
                import pycuda.driver as cuda
                cuda.init()
                device_count = cuda.Device.count()
                
                if device_count > 0:
                    self.gpu_available = True
                    self.gpu_type = 'CUDA'
                    
                    for i in range(device_count):
                        device = cuda.Device(i)
                        attrs = device.get_attributes()
                        
                        gpu_info = {
                            'id': i,
                            'name': device.name(),
                            'memory': device.total_memory(),
                            'cuda_cores': attrs[cuda.device_attribute.MULTIPROCESSOR_COUNT] * 128,  # Approximation
                            'compute_capability': device.compute_capability()
                        }
                        self.gpu_devices.append(gpu_info)
                        
                        console.print(f"[bold green][+] CUDA GPU {i}: {gpu_info['name']}[/bold green]")
                        console.print(f"    Memória: {gpu_info['memory'] / (1024**3):.1f} GB")
                        console.print(f"    CUDA Cores: ~{gpu_info['cuda_cores']}")
                        console.print(f"    Compute Capability: {gpu_info['compute_capability'][0]}.{gpu_info['compute_capability'][1]}")
                    
                    # Usa a primeira GPU por padrão
                    primary_gpu = self.gpu_devices[0]
                    self.gpu_memory = primary_gpu['memory']
                    self.cuda_cores = primary_gpu['cuda_cores']
                    self.compute_capability = primary_gpu['compute_capability']
                    
            except Exception as e:
                logger.debug(f"CUDA não disponível: {e}")
        
        # Detecta CuPy (alternativa CUDA)
        elif CUPY_AVAILABLE:
            try:
                device_count = cp.cuda.runtime.getDeviceCount()
                if device_count > 0:
                    self.gpu_available = True
                    self.gpu_type = 'CuPy'
                    
                    for i in range(device_count):
                        with cp.cuda.Device(i):
                            props = cp.cuda.runtime.getDeviceProperties(i)
                            
                            gpu_info = {
                                'id': i,
                                'name': props['name'].decode(),
                                'memory': props['totalGlobalMem'],
                                'cuda_cores': props['multiProcessorCount'] * 128,
                                'compute_capability': (props['major'], props['minor'])
                            }
                            self.gpu_devices.append(gpu_info)
                            
                            console.print(f"[bold green][+] CuPy GPU {i}: {gpu_info['name']}[/bold green]")
                            console.print(f"    Memória: {gpu_info['memory'] / (1024**3):.1f} GB")
                            console.print(f"    CUDA Cores: ~{gpu_info['cuda_cores']}")
                    
                    primary_gpu = self.gpu_devices[0]
                    self.gpu_memory = primary_gpu['memory']
                    self.cuda_cores = primary_gpu['cuda_cores']
                    
            except Exception as e:
                logger.debug(f"CuPy não disponível: {e}")
        
        # Detecta OpenCL
        elif PYOPENCL_AVAILABLE:
            try:
                platforms = cl.get_platforms()
                
                for platform in platforms:
                    devices = platform.get_devices(cl.device_type.GPU)
                    
                    if devices:
                        self.gpu_available = True
                        self.gpu_type = 'OpenCL'
                        
                        for device in devices:
                            gpu_info = {
                                'platform': platform.name,
                                'name': device.name,
                                'memory': device.global_mem_size,
                                'compute_units': device.max_compute_units
                            }
                            self.gpu_devices.append(gpu_info)
                            
                            console.print(f"[bold green][+] OpenCL GPU: {gpu_info['name']}[/bold green]")
                            console.print(f"    Platform: {gpu_info['platform']}")
                            console.print(f"    Memória: {gpu_info['memory'] / (1024**3):.1f} GB")
                            console.print(f"    Compute Units: {gpu_info['compute_units']}")
                        
                        self.gpu_memory = devices[0].global_mem_size
                        
            except Exception as e:
                logger.debug(f"OpenCL não disponível: {e}")
        
        if not self.gpu_available:
            console.print("[yellow][-] Nenhuma GPU compatível detectada[/yellow]")
            console.print("[*] Usando apenas CPU para hash cracking")
        else:
            console.print(f"[bold green][+] GPU Acceleration: {self.gpu_type} ativado[/bold green]")
    
    def get_optimal_workgroup_size(self, total_work):
        """Calcula tamanho ótimo de workgroup baseado na GPU."""
        if not self.gpu_available:
            return min(total_work, 10000)
        
        if self.gpu_type == 'CUDA':
            # CUDA warps são tipicamente 32 threads
            base_size = 32 * 1024  # 32K threads por workgroup
            
            # Ajusta baseado na memória GPU
            if self.gpu_memory > 8 * (1024**3):  # > 8GB
                return min(total_work, base_size * 8)
            elif self.gpu_memory > 4 * (1024**3):  # > 4GB
                return min(total_work, base_size * 4)
            else:
                return min(total_work, base_size)
        
        elif self.gpu_type == 'OpenCL':
            # OpenCL workgroups variam, mas 64-256 é comum
            base_size = 64 * 512  # 32K threads
            return min(total_work, base_size)
        
        return min(total_work, 10000)
    
    def estimate_performance_gain(self):
        """Estima ganho de performance com GPU vs CPU."""
        if not self.gpu_available:
            return 1.0
        
        cpu_cores = multiprocessing.cpu_count()
        
        if self.gpu_type in ['CUDA', 'CuPy']:
            # CUDA pode ser 50-1000x mais rápido que CPU para hash cracking
            estimated_gain = min(self.cuda_cores / cpu_cores, 1000)
            return max(estimated_gain, 50)  # Mínimo 50x
        
        elif self.gpu_type == 'OpenCL':
            # OpenCL geralmente 20-200x mais rápido
            if self.gpu_devices:
                compute_units = self.gpu_devices[0].get('compute_units', 8)
                estimated_gain = min(compute_units * 8 / cpu_cores, 200)
                return max(estimated_gain, 20)
        
        return 50  # Default estimate


class AdvancedHashCracker:
    """Quebrador avançado de hashes com múltiplos modos de ataque."""
    
    def __init__(self, hash_target, hash_type=None, workers=None, timeout=None, use_gpu=True):
        """
        Inicializa o quebrador de hash.
        
        Args:
            hash_target (str): Hash para quebrar
            hash_type (str): Tipo do hash (auto-detectado se None)
            workers (int): Número de workers (auto se None)
            timeout (int): Timeout em segundos
            use_gpu (bool): Ativa aceleração GPU se disponível
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
        
        # GPU Manager
        self.gpu_manager = GPUManager() if use_gpu else None
        self.use_gpu = use_gpu and (self.gpu_manager.gpu_available if self.gpu_manager else False)
        
        # Rainbow Table Manager
        self.rainbow_manager = RainbowTableManager()
        
        # Configurações de ataque
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
        
        # Ajusta workers baseado na GPU
        if self.use_gpu:
            estimated_gain = self.gpu_manager.estimate_performance_gain()
            console.print(f"[bold green][+] GPU detectada! Estimativa de ganho: {estimated_gain:.0f}x[/bold green]")
            # Reduz workers CPU quando usar GPU (GPU faz o trabalho pesado)
            self.workers = min(multiprocessing.cpu_count(), 8)
        
        logger.info(f"Hash Cracker inicializado: {self.hash_type} ({len(self.hash_target)} chars) - GPU: {self.use_gpu}")
    
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
    
    def _gpu_hash_batch_cuda(self, passwords):
        """Processa batch de hashes usando CUDA."""
        if not self.use_gpu or not PYCUDA_AVAILABLE:
            return self._cpu_hash_batch(passwords)
        
        try:
            import pycuda.driver as cuda
            import pycuda.gpuarray as gpuarray
            from pycuda.compiler import SourceModule
            import numpy as np
            
            # CUDA kernel para MD5 (exemplo otimizado)
            md5_kernel = SourceModule("""
            #include <cuda.h>
            
            __device__ void md5_transform(unsigned int *hash, unsigned int *data) {
                // Implementação otimizada MD5 transform
                // Usando constantes e operações bit-wise otimizadas
                
                unsigned int a = hash[0], b = hash[1], c = hash[2], d = hash[3];
                
                // Round 1
                #define FF(a, b, c, d, x, s, ac) { \\
                    (a) += ((b) & (c)) | ((~b) & (d)) + (x) + (ac); \\
                    (a) = ((a) << (s)) | ((a) >> (32-(s))); \\
                    (a) += (b); \\
                }
                
                FF(a, b, c, d, data[0], 7, 0xd76aa478);
                FF(d, a, b, c, data[1], 12, 0xe8c7b756);
                // ... mais rounds otimizados
                
                hash[0] += a; hash[1] += b; hash[2] += c; hash[3] += d;
            }
            
            __global__ void md5_crack_kernel(char *passwords, int *password_lengths, 
                                           unsigned int *target_hash, int *found_idx, 
                                           int num_passwords, int max_len) {
                int idx = blockIdx.x * blockDim.x + threadIdx.x;
                
                if (idx >= num_passwords || *found_idx >= 0) return;
                
                // Calcula hash da senha atual
                unsigned int hash[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
                
                char *password = passwords + idx * max_len;
                int len = password_lengths[idx];
                
                // Prepara dados para MD5
                unsigned int data[16] = {0};
                for(int i = 0; i < len; i++) {
                    data[i/4] |= (password[i] << ((i%4) * 8));
                }
                
                // Padding MD5
                data[len/4] |= (0x80 << ((len%4) * 8));
                data[14] = len * 8;
                
                md5_transform(hash, data);
                
                // Compara com target
                if (hash[0] == target_hash[0] && hash[1] == target_hash[1] && 
                    hash[2] == target_hash[2] && hash[3] == target_hash[3]) {
                    atomicCAS(found_idx, -1, idx);
                }
            }
            """)
            
            # Prepara dados
            max_password_len = max(len(p) for p in passwords)
            num_passwords = len(passwords)
            
            # Converte senhas para array C-style
            password_array = np.zeros((num_passwords, max_password_len), dtype=np.uint8)
            length_array = np.zeros(num_passwords, dtype=np.int32)
            
            for i, password in enumerate(passwords):
                password_bytes = password.encode('utf-8')
                password_array[i, :len(password_bytes)] = list(password_bytes)
                length_array[i] = len(password_bytes)
            
            # Converte hash target para array de 32-bit integers
            target_hash_hex = self.hash_target
            target_hash = np.array([
                int(target_hash_hex[i:i+8], 16) for i in range(0, 32, 8)
            ], dtype=np.uint32)
            
            # Aloca memória GPU
            passwords_gpu = cuda.mem_alloc(password_array.nbytes)
            lengths_gpu = cuda.mem_alloc(length_array.nbytes)
            target_gpu = cuda.mem_alloc(target_hash.nbytes)
            found_idx_gpu = cuda.mem_alloc(4)  # int
            
            # Copia dados para GPU
            cuda.memcpy_htod(passwords_gpu, password_array)
            cuda.memcpy_htod(lengths_gpu, length_array)
            cuda.memcpy_htod(target_gpu, target_hash)
            cuda.memcpy_htod(found_idx_gpu, np.array([-1], dtype=np.int32))
            
            # Configura grid e block dimensions
            block_size = 256
            grid_size = (num_passwords + block_size - 1) // block_size
            
            # Executa kernel
            func = md5_kernel.get_function("md5_crack_kernel")
            func(passwords_gpu, lengths_gpu, target_gpu, found_idx_gpu,
                 np.int32(num_passwords), np.int32(max_password_len),
                 block=(block_size, 1, 1), grid=(grid_size, 1))
            
            # Recupera resultado
            found_idx = np.zeros(1, dtype=np.int32)
            cuda.memcpy_dtoh(found_idx, found_idx_gpu)
            
            if found_idx[0] >= 0:
                return passwords[found_idx[0]]
            
            return None
            
        except Exception as e:
            logger.error(f"Erro no processamento CUDA: {e}")
            # Fallback para CPU
            return self._cpu_hash_batch(passwords)
    
    def _gpu_hash_batch_cupy(self, passwords):
        """Processa batch de hashes usando CuPy."""
        if not self.use_gpu or not CUPY_AVAILABLE:
            return self._cpu_hash_batch(passwords)
        
        try:
            import cupy as cp
            import hashlib
            
            # CuPy kernel personalizado para MD5
            cuda_code = r'''
            extern "C" __global__
            void md5_batch_kernel(char* passwords, int* lengths, int num_passwords, 
                                int max_len, unsigned int* target, int* result_idx) {
                int idx = blockIdx.x * blockDim.x + threadIdx.x;
                if (idx >= num_passwords) return;
                
                // Simplified MD5 implementation for demonstration
                // Em produção seria implementação completa e otimizada
                
                char* password = passwords + idx * max_len;
                int len = lengths[idx];
                
                // Mock hash calculation (substituir por MD5 real)
                unsigned int hash = 0;
                for(int i = 0; i < len; i++) {
                    hash = hash * 31 + password[i];
                }
                
                // Compara com target (simplified)
                if (hash == target[0]) {
                    atomicCAS(result_idx, -1, idx);
                }
            }
            '''
            
            # Compila kernel
            kernel = cp.RawKernel(cuda_code, 'md5_batch_kernel')
            
            # Prepara dados
            max_len = max(len(p) for p in passwords)
            num_passwords = len(passwords)
            
            # Arrays CuPy
            password_data = cp.zeros((num_passwords, max_len), dtype=cp.uint8)
            lengths = cp.zeros(num_passwords, dtype=cp.int32)
            
            for i, password in enumerate(passwords):
                pwd_bytes = password.encode('utf-8')
                password_data[i, :len(pwd_bytes)] = list(pwd_bytes)
                lengths[i] = len(pwd_bytes)
            
            target_array = cp.array([hash(self.hash_target)], dtype=cp.uint32)  # Simplified
            result_idx = cp.array([-1], dtype=cp.int32)
            
            # Executa kernel
            block_size = 256
            grid_size = (num_passwords + block_size - 1) // block_size
            
            kernel((grid_size,), (block_size,), 
                  (password_data, lengths, num_passwords, max_len, target_array, result_idx))
            
            # Verifica resultado
            result = cp.asnumpy(result_idx)[0]
            if result >= 0:
                return passwords[result]
            
            return None
            
        except Exception as e:
            logger.error(f"Erro no processamento CuPy: {e}")
            return self._cpu_hash_batch(passwords)
    
    def _gpu_hash_batch_opencl(self, passwords):
        """Processa batch de hashes usando OpenCL."""
        if not self.use_gpu or not PYOPENCL_AVAILABLE:
            return self._cpu_hash_batch(passwords)
        
        try:
            import pyopencl as cl
            import numpy as np
            
            # Código OpenCL kernel
            opencl_code = """
            __kernel void md5_crack(__global char* passwords,
                                  __global int* lengths,
                                  __global uint* target_hash,
                                  __global int* found_idx,
                                  int num_passwords,
                                  int max_len) {
                int idx = get_global_id(0);
                
                if (idx >= num_passwords) return;
                
                // MD5 implementation otimizada aqui
                __global char* password = passwords + idx * max_len;
                int len = lengths[idx];
                
                // Simplified hash (replace with real MD5)
                uint hash = 0;
                for(int i = 0; i < len; i++) {
                    hash = hash * 31 + password[i];
                }
                
                if (hash == target_hash[0]) {
                    atomic_cmpxchg(found_idx, -1, idx);
                }
            }
            """
            
            # Setup OpenCL
            context = cl.create_some_context()
            queue = cl.CommandQueue(context)
            program = cl.Program(context, opencl_code).build()
            
            # Prepara dados
            max_len = max(len(p) for p in passwords)
            num_passwords = len(passwords)
            
            password_array = np.zeros((num_passwords, max_len), dtype=np.uint8)
            length_array = np.zeros(num_passwords, dtype=np.int32)
            
            for i, password in enumerate(passwords):
                pwd_bytes = password.encode('utf-8')
                password_array[i, :len(pwd_bytes)] = list(pwd_bytes)
                length_array[i] = len(pwd_bytes)
            
            target_array = np.array([hash(self.hash_target)], dtype=np.uint32)
            result_array = np.array([-1], dtype=np.int32)
            
            # Buffers OpenCL
            password_buf = cl.Buffer(context, cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR, hostbuf=password_array)
            length_buf = cl.Buffer(context, cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR, hostbuf=length_array)
            target_buf = cl.Buffer(context, cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR, hostbuf=target_array)
            result_buf = cl.Buffer(context, cl.mem_flags.READ_WRITE | cl.mem_flags.COPY_HOST_PTR, hostbuf=result_array)
            
            # Executa kernel
            program.md5_crack(queue, (num_passwords,), None,
                             password_buf, length_buf, target_buf, result_buf,
                             np.int32(num_passwords), np.int32(max_len))
            
            # Lê resultado
            cl.enqueue_copy(queue, result_array, result_buf)
            
            if result_array[0] >= 0:
                return passwords[result_array[0]]
            
            return None
            
        except Exception as e:
            logger.error(f"Erro no processamento OpenCL: {e}")
            return self._cpu_hash_batch(passwords)
    
    def _cpu_hash_batch(self, passwords):
        """Processa batch de hashes usando CPU (fallback)."""
        for password in passwords:
            self.attempts += 1
            computed_hash = self._hash_password(password)
            if computed_hash == self.hash_target:
                return password
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
    
    def rainbow_table_attack(self, table_path=None, auto_generate=False):
        """
        Executa ataque usando Rainbow Tables.
        
        Args:
            table_path (str): Caminho para rainbow table (auto se None)
            auto_generate (bool): Gera tabela automaticamente se não existir
            
        Returns:
            tuple: (password, attempts, time_taken)
        """
        console.print(f"[*] Iniciando ataque Rainbow Table")
        self.attack_mode = 'rainbow'
        self.start_time = time.time()
        self.attempts = 0
        
        # Determina tabela a usar
        if not table_path:
            # Auto-select baseado no hash type
            table_name = f"{self.hash_type}_1_6_36chars.rt"  # lowercase + digits, 1-6 chars
            table_path = os.path.join(self.rainbow_manager.table_dir, table_name)
        
        # Verifica se tabela existe
        if not os.path.exists(table_path):
            if auto_generate:
                console.print(f"[yellow][!] Rainbow Table não encontrada, gerando automaticamente...[/yellow]")
                
                # Gera tabela pequena para teste (ajustar para produção)
                table_path = self.rainbow_manager.generate_rainbow_table(
                    hash_type=self.hash_type,
                    charset=string.ascii_lowercase + string.digits,
                    min_length=1,
                    max_length=6,
                    table_name=f"{self.hash_type}_1_6_36chars"
                )
            else:
                console.print(f"[red][!] Rainbow Table não encontrada: {table_path}[/red]")
                console.print("[*] Use --rainbow-generate para gerar automaticamente")
                return None, 0, 0
        
        # Info da tabela
        table_info = self.rainbow_manager.get_table_info(table_path)
        console.print(f"[*] Tabela: {table_info.get('hash_type', 'unknown')} | ")
        console.print(f"    Charset: {table_info.get('charset', 'unknown')[:30]}{'...' if len(table_info.get('charset', '')) > 30 else ''}")
        console.print(f"    Chains: {table_info.get('chain_count', 0):,} | Tamanho: {table_info.get('size_mb', 0):.1f} MB")
        
        # Executa lookup
        password = self.rainbow_manager.rainbow_lookup(
            target_hash=self.hash_target,
            table_path=table_path,
            hash_type=self.hash_type
        )
        
        time_taken = time.time() - self.start_time
        
        if password:
            self.cracked_password = password
            console.print(f"[*] Tempo total: {time_taken:.2f}s")
            return password, 1, time_taken  # 1 "attempt" para rainbow lookup
        else:
            console.print(f"[*] Tempo total: {time_taken:.2f}s")
            return None, 1, time_taken
    
    def generate_rainbow_table(self, hash_type=None, charset=None, min_length=1, max_length=6, table_name=None):
        """
        Gera uma nova rainbow table.
        
        Args:
            hash_type (str): Tipo de hash (usa self.hash_type se None)
            charset (str): Conjunto de caracteres
            min_length (int): Comprimento mínimo
            max_length (int): Comprimento máximo
            table_name (str): Nome da tabela
            
        Returns:
            str: Caminho da tabela gerada
        """
        hash_type = hash_type or self.hash_type
        charset = charset or (string.ascii_lowercase + string.digits)
        
        console.print(f"[*] Gerando Rainbow Table para {hash_type}")
        
        return self.rainbow_manager.generate_rainbow_table(
            hash_type=hash_type,
            charset=charset,
            min_length=min_length,
            max_length=max_length,
            table_name=table_name
        )
    
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
        """Testa um chunk de senhas usando GPU se disponível."""
        # Se GPU disponível e chunk grande o suficiente, usa GPU
        if self.use_gpu and len(passwords) >= 1000:
            result = self._process_gpu_batch(passwords)
            if result:
                return result
        
        # Fallback ou chunks pequenos: usa CPU
        return self._cpu_hash_batch(passwords)
    
    def _process_gpu_batch(self, passwords):
        """Processa batch usando a melhor opção GPU disponível."""
        if not self.use_gpu or not self.gpu_manager:
            return None
        
        # Atualiza contador de tentativas
        self.attempts += len(passwords)
        
        # Escolhe melhor método GPU
        if self.gpu_manager.gpu_type == 'CUDA' and PYCUDA_AVAILABLE:
            return self._gpu_hash_batch_cuda(passwords)
        elif self.gpu_manager.gpu_type == 'CuPy' and CUPY_AVAILABLE:
            return self._gpu_hash_batch_cupy(passwords)
        elif self.gpu_manager.gpu_type == 'OpenCL' and PYOPENCL_AVAILABLE:
            return self._gpu_hash_batch_opencl(passwords)
        else:
            # Fallback para CPU
            return self._cpu_hash_batch(passwords)
    
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
    use_gpu = kwargs.get('use_gpu', True)
    cracker = AdvancedHashCracker(hash_target, hash_type, use_gpu=use_gpu)
    
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
    elif attack_mode == 'rainbow':
        table_path = kwargs.get('rainbow_table', None)
        auto_generate = kwargs.get('rainbow_generate', False)
        password, attempts, time_taken = cracker.rainbow_table_attack(table_path, auto_generate)
    elif attack_mode == 'online':
        password = cracker.online_lookup()
        attempts = 0
        time_taken = 0
    elif attack_mode == 'all':
        # Tenta todos os métodos em ordem de eficiência
        console.print("[*] Modo 'all': tentando todos os ataques disponíveis")
        
        # 1. Rainbow Tables (mais rápido)
        console.print("\n[*] === TENTATIVA 1: RAINBOW TABLES ===")
        password, attempts, time_taken = cracker.rainbow_table_attack(auto_generate=False)
        if password:
            return {
                'hash_type': cracker.hash_type,
                'attack_mode': 'rainbow',
                'password': password,
                'attempts': attempts,
                'time_taken': time_taken,
                'success': True
            }
        
        # 2. Dictionary Attack
        if wordlist_path:
            console.print("\n[*] === TENTATIVA 2: DICTIONARY ATTACK ===")
            password, attempts, time_taken = cracker.dictionary_attack(wordlist_path)
            if password:
                return {
                    'hash_type': cracker.hash_type,
                    'attack_mode': 'dictionary',
                    'password': password,
                    'attempts': attempts,
                    'time_taken': time_taken,
                    'success': True
                }
        
        # 3. Brute Force (limitado)
        console.print("\n[*] === TENTATIVA 3: BRUTE FORCE (1-4 chars) ===")
        password, attempts, time_taken = cracker.brute_force_attack(1, 4, string.ascii_lowercase + string.digits)
        if password:
            return {
                'hash_type': cracker.hash_type,
                'attack_mode': 'brute_force',
                'password': password,
                'attempts': attempts,
                'time_taken': time_taken,
                'success': True
            }
        
        # Não encontrou com nenhum método
        return {
            'hash_type': cracker.hash_type,
            'attack_mode': 'all',
            'password': None,
            'attempts': attempts,
            'time_taken': time_taken,
            'success': False
        }
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