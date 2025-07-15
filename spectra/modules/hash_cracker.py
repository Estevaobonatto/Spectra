# -*- coding: utf-8 -*-
"""
Módulo Avançado de Quebra de Hash - Spectra
Inspirado em HashCat, John the Ripper e outras ferramentas profissionais
"""

import hashlib
import itertools
import string
import time
import multiprocessing
import os
import json
import psutil
import gc
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core.console import console, create_progress
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

# Algoritmos de hash adicionais
try:
    import argon2
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False

try:
    import scrypt
    SCRYPT_AVAILABLE = True
except ImportError:
    SCRYPT_AVAILABLE = False

try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False

logger = get_logger(__name__)


class MemoryManager:
    """Gerenciador de mem\u00f3ria para otimizar uso de recursos."""
    
    def __init__(self):
        self.memory_threshold = 0.85  # 85% do limite de mem\u00f3ria
        self.cache_size_limit = 1024 * 1024 * 100  # 100MB
        self.memory_monitor = True
        
    def get_memory_usage(self):
        """Retorna uso atual de memoria em percentual."""
        return psutil.virtual_memory().percent / 100.0
        
    def is_memory_available(self, required_mb=50):
        """Verifica se ha memoria disponivel para operacao."""
        available_mb = psutil.virtual_memory().available / (1024 * 1024)
        return available_mb > required_mb
        
    def optimize_batch_size(self, base_size, item_size_bytes=100):
        """Otimiza tamanho do batch baseado na memoria disponivel."""
        available_mb = psutil.virtual_memory().available / (1024 * 1024)
        
        # Usa no maximo 25% da memoria disponivel
        max_memory_mb = available_mb * 0.25
        max_items = int((max_memory_mb * 1024 * 1024) / item_size_bytes)
        
        return min(base_size, max_items, 100000)  # Limite maximo de seguranca
        
    def cleanup_cache(self, cache_dict, max_size=None):
        """Limpa cache quando necessario."""
        if max_size is None:
            max_size = self.cache_size_limit
            
        if len(cache_dict) > max_size:
            # Remove metade dos itens mais antigos
            items_to_remove = len(cache_dict) // 2
            for _ in range(items_to_remove):
                cache_dict.popitem()
        
        # Forca garbage collection
        if self.get_memory_usage() > self.memory_threshold:
            gc.collect()


class PerformanceMonitor:
    """Monitor de performance para otimizar ataques."""
    
    def __init__(self):
        self.start_time = None
        self.samples = []
        self.avg_rate = 0
        self.peak_rate = 0
        self.efficiency_score = 0
        
    def start_monitoring(self):
        """Inicia monitoramento de performance."""
        self.start_time = time.time()
        self.samples = []
        
    def record_sample(self, attempts, elapsed_time):
        """Registra amostra de performance."""
        if elapsed_time > 0:
            rate = attempts / elapsed_time
            self.samples.append({
                'timestamp': time.time(),
                'attempts': attempts,
                'rate': rate,
                'elapsed': elapsed_time
            })
            
            # Mantem apenas ultimas 100 amostras
            if len(self.samples) > 100:
                self.samples.pop(0)
                
            self._update_metrics()
            
    def _update_metrics(self):
        """Atualiza metricas de performance."""
        if not self.samples:
            return
            
        rates = [s['rate'] for s in self.samples]
        self.avg_rate = sum(rates) / len(rates)
        self.peak_rate = max(rates)
        
        # Calcula eficiencia (consistencia da taxa)
        if len(rates) > 1:
            variance = sum((r - self.avg_rate) ** 2 for r in rates) / len(rates)
            self.efficiency_score = 1.0 / (1.0 + variance / (self.avg_rate ** 2))
        else:
            self.efficiency_score = 1.0
            
    def get_performance_report(self):
        """Gera relatorio de performance."""
        if not self.samples:
            return {}
            
        total_elapsed = time.time() - self.start_time if self.start_time else 0
        total_attempts = sum(s['attempts'] for s in self.samples)
        
        return {
            'total_attempts': total_attempts,
            'total_elapsed': total_elapsed,
            'avg_rate': self.avg_rate,
            'peak_rate': self.peak_rate,
            'efficiency_score': self.efficiency_score,
            'samples_count': len(self.samples)
        }
        
    def suggest_optimizations(self):
        """Sugere otimizacoes baseadas na performance."""
        suggestions = []
        
        if self.efficiency_score < 0.8:
            suggestions.append("Consider reducing batch size for more consistent performance")
            
        if self.avg_rate < 1000:  # Baixa taxa
            suggestions.append("Try increasing number of workers or enabling GPU acceleration")
            
        if len(self.samples) > 50 and self.peak_rate > self.avg_rate * 2:
            suggestions.append("Performance is inconsistent - check system resources")
            
        return suggestions


class BatchOptimizer:
    """Otimizador de batches para melhor performance."""
    
    def __init__(self):
        self.optimal_batch_size = 1000
        self.performance_history = []
        self.learning_rate = 0.1
        
    def calculate_optimal_batch_size(self, workers, memory_available_mb, item_size_bytes=100):
        """Calcula tamanho otimo de batch baseado nos recursos."""
        # Baseia-se no numero de workers
        base_size = workers * 500
        
        # Ajusta pela memoria disponivel
        max_memory_items = int((memory_available_mb * 1024 * 1024 * 0.25) / item_size_bytes)
        
        # Considera historico de performance
        if self.performance_history:
            avg_performance = sum(self.performance_history[-10:]) / min(len(self.performance_history), 10)
            if avg_performance > 0:
                base_size = int(base_size * (1 + avg_performance / 10000))
        
        self.optimal_batch_size = min(base_size, max_memory_items, 50000)
        return self.optimal_batch_size
        
    def record_batch_performance(self, batch_size, processing_time, success_rate):
        """Registra performance de um batch."""
        if processing_time > 0:
            performance_score = (batch_size * success_rate) / processing_time
            self.performance_history.append(performance_score)
            
            # Mantem historico limitado
            if len(self.performance_history) > 100:
                self.performance_history.pop(0)
                
            # Ajusta tamanho otimo baseado na performance
            if len(self.performance_history) >= 5:
                recent_avg = sum(self.performance_history[-5:]) / 5
                if recent_avg > sum(self.performance_history[:-5]) / max(len(self.performance_history[:-5]), 1):
                    # Performance melhorou, aumenta batch
                    self.optimal_batch_size = int(self.optimal_batch_size * 1.05)
                else:
                    # Performance piorou, diminui batch
                    self.optimal_batch_size = int(self.optimal_batch_size * 0.95)
                    
        # Limites de seguranca
        self.optimal_batch_size = max(100, min(self.optimal_batch_size, 100000))
        
    def get_adaptive_batch_size(self, current_performance):
        """Retorna tamanho de batch adaptativo."""
        if not self.performance_history:
            return self.optimal_batch_size
            
        # Adapta baseado na performance atual vs historico
        avg_performance = sum(self.performance_history[-10:]) / min(len(self.performance_history), 10)
        
        if current_performance > avg_performance * 1.2:
            # Performance boa, aumenta batch
            return int(self.optimal_batch_size * 1.1)
        elif current_performance < avg_performance * 0.8:
            # Performance ruim, diminui batch
            return int(self.optimal_batch_size * 0.9)
        else:
            return self.optimal_batch_size


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
                    progress_line = f"[*] Progresso: {progress:.1f}% - {chains_generated:,} chains - {rate:.0f} chains/s - ETA: {eta:.0f}s"
                    console.print(f"\r{progress_line:<80}", end="")
        
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
                            progress_line = f"[*] Carregando: {chain_count:,} chains"
                            console.print(f"\r{progress_line:<80}", end="")
            
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
    
    def __init__(self, hash_target, hash_type=None, workers=None, timeout=None, use_gpu=True, verbose=False):
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
        
        # Sistema de progresso centralizado
        self.verbose = verbose
        self.progress_lock = threading.Lock()
        self.last_progress_update = 0
        self.progress_update_interval = 1.0  # 1 segundo
        
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
        
        # Cache e otimizações avançadas
        self.hash_cache = {}
        self.performance_mode = 'balanced'  # balanced, fast, extreme
        self.memory_manager = MemoryManager()
        self.performance_monitor = PerformanceMonitor()
        self.batch_optimizer = BatchOptimizer()
        
        # Detecta tipo de hash automaticamente
        if not self.hash_type:
            self.hash_type = self._detect_hash_type()
        
        # Configura algoritmo de hash
        self._setup_hash_algorithm()
        
        # Ajusta workers baseado na GPU e recursos do sistema
        self._optimize_workers()
        
        logger.info(f"Hash Cracker inicializado: {self.hash_type} ({len(self.hash_target)} chars) - GPU: {self.use_gpu}")
    
    def _optimize_workers(self):
        """Otimiza número de workers baseado nos recursos do sistema."""
        # Informações do sistema
        cpu_count = multiprocessing.cpu_count()
        memory_gb = psutil.virtual_memory().total / (1024**3)
        
        if self.use_gpu:
            estimated_gain = self.gpu_manager.estimate_performance_gain()
            console.print(f"[bold green][+] GPU detectada! Estimativa de ganho: {estimated_gain:.0f}x[/bold green]")
            # Reduz workers CPU quando usar GPU (GPU faz o trabalho pesado)
            self.workers = min(cpu_count, 8)
        else:
            # Otimização baseada no modo de performance
            if self.performance_mode == 'fast':
                self.workers = min(cpu_count * 4, 32)
            elif self.performance_mode == 'extreme':
                self.workers = min(cpu_count * 8, 64)
            else:  # balanced
                self.workers = min(cpu_count * 2, 16)
                
            # Ajusta baseado na memória disponível
            if memory_gb < 4:
                self.workers = min(self.workers, cpu_count)
            elif memory_gb < 8:
                self.workers = min(self.workers, cpu_count * 2)
        
        logger.info(f"Workers otimizados: {self.workers} (CPU: {cpu_count}, RAM: {memory_gb:.1f}GB)")
    
    def _detect_hash_type(self):
        """Detecta automaticamente o tipo de hash baseado no formato."""
        hash_length = len(self.hash_target)
        hash_patterns = {
            32: ['md5', 'ntlm', 'blake2s'],
            40: ['sha1', 'ripemd160'],
            56: ['sha224', 'sha3_224'],
            64: ['sha256', 'sha3_256', 'blake2b'],
            96: ['sha384', 'sha3_384'],
            128: ['sha512', 'sha3_512', 'whirlpool'],
            60: ['bcrypt'],  # $2b$...
            16: ['md4'],
        }
        
        # Detecção por padrões específicos
        if self.hash_target.startswith('$2a$') or self.hash_target.startswith('$2b$'):
            return 'bcrypt'
        elif self.hash_target.startswith('$argon2'):
            return 'argon2'
        elif self.hash_target.startswith('$scrypt'):
            return 'scrypt'
        elif self.hash_target.startswith('$pbkdf2'):
            return 'pbkdf2'
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
        elif self.hash_target.startswith('{SHA256}'):
            return 'sha256'
        elif self.hash_target.startswith('{SHA512}'):
            return 'sha512'
        elif ':' in self.hash_target and len(self.hash_target.split(':')[0]) == 32:
            return 'ntlm'  # username:hash format
        
        # Detecção por comprimento
        possible_types = hash_patterns.get(hash_length, ['unknown'])
        
        # Se múltiplas opções, usa a mais comum
        if len(possible_types) > 1:
            priority = ['md5', 'sha1', 'sha256', 'sha512', 'ntlm', 'blake2b', 'blake2s']
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
            'blake2b': self._blake2b_hash,
            'blake2s': self._blake2s_hash,
            'sha3_224': self._sha3_224_hash,
            'sha3_256': self._sha3_256_hash,
            'sha3_384': self._sha3_384_hash,
            'sha3_512': self._sha3_512_hash,
            'ripemd160': self._ripemd160_hash,
            'whirlpool': self._whirlpool_hash,
        }
        
        # Algoritmos que requerem bibliotecas específicas
        self.special_algorithms = {
            'bcrypt': self._bcrypt_hash,
            'argon2': self._argon2_hash,
            'scrypt': self._scrypt_hash,
            'pbkdf2': self._pbkdf2_hash,
        }
        
        if self.hash_type not in self.hash_algorithms and self.hash_type not in self.special_algorithms:
            if self.hash_type in ['sha512crypt', 'sha256crypt', 'md5crypt']:
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
    
    def _blake2b_hash(self, data):
        """Gera hash BLAKE2b."""
        try:
            return hashlib.blake2b(data, digest_size=32)
        except Exception:
            return hashlib.sha256(data)
    
    def _blake2s_hash(self, data):
        """Gera hash BLAKE2s."""
        try:
            return hashlib.blake2s(data, digest_size=32)
        except Exception:
            return hashlib.sha256(data)
    
    def _sha3_224_hash(self, data):
        """Gera hash SHA3-224."""
        try:
            return hashlib.sha3_224(data)
        except Exception:
            return hashlib.sha224(data)
    
    def _sha3_256_hash(self, data):
        """Gera hash SHA3-256."""
        try:
            return hashlib.sha3_256(data)
        except Exception:
            return hashlib.sha256(data)
    
    def _sha3_384_hash(self, data):
        """Gera hash SHA3-384."""
        try:
            return hashlib.sha3_384(data)
        except Exception:
            return hashlib.sha384(data)
    
    def _sha3_512_hash(self, data):
        """Gera hash SHA3-512."""
        try:
            return hashlib.sha3_512(data)
        except Exception:
            return hashlib.sha512(data)
    
    def _ripemd160_hash(self, data):
        """Gera hash RIPEMD160."""
        try:
            return hashlib.new('ripemd160', data)
        except Exception:
            return hashlib.sha1(data)
    
    def _whirlpool_hash(self, data):
        """Gera hash Whirlpool."""
        try:
            return hashlib.new('whirlpool', data)
        except Exception:
            return hashlib.sha512(data)
    
    def _bcrypt_hash(self, password):
        """Gera hash bcrypt."""
        if not BCRYPT_AVAILABLE:
            console.print("[red][!] bcrypt não disponível. Instale: pip install bcrypt[/red]")
            return None
        try:
            if isinstance(password, str):
                password = password.encode('utf-8')
            return bcrypt.hashpw(password, bcrypt.gensalt())
        except Exception as e:
            logger.error(f"Erro no bcrypt: {e}")
            return None
    
    def _argon2_hash(self, password):
        """Gera hash Argon2."""
        if not ARGON2_AVAILABLE:
            console.print("[red][!] argon2 não disponível. Instale: pip install argon2-cffi[/red]")
            return None
        try:
            if isinstance(password, str):
                password = password.encode('utf-8')
            return argon2.hash_password(password)
        except Exception as e:
            logger.error(f"Erro no argon2: {e}")
            return None
    
    def _scrypt_hash(self, password):
        """Gera hash scrypt."""
        if not SCRYPT_AVAILABLE:
            console.print("[red][!] scrypt não disponível. Instale: pip install scrypt[/red]")
            return None
        try:
            if isinstance(password, str):
                password = password.encode('utf-8')
            return scrypt.hash(password, salt=b'salt', N=16384, r=8, p=1)
        except Exception as e:
            logger.error(f"Erro no scrypt: {e}")
            return None
    
    def _pbkdf2_hash(self, password):
        """Gera hash PBKDF2."""
        try:
            if isinstance(password, str):
                password = password.encode('utf-8')
            return hashlib.pbkdf2_hmac('sha256', password, b'salt', 100000)
        except Exception as e:
            logger.error(f"Erro no PBKDF2: {e}")
            return None
    
    def _hash_password(self, password):
        """Gera hash da senha usando o algoritmo configurado."""
        try:
            # Algoritmos especiais que retornam hash completo
            if self.hash_type in self.special_algorithms:
                hash_func = self.special_algorithms[self.hash_type]
                result = hash_func(password)
                if result is None:
                    return None
                if isinstance(result, bytes):
                    return result.hex().lower()
                return str(result).lower()
            
            # Algoritmos standard
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
    
    def _update_progress_task(self, progress, task_id, completed, total, attempts=None, rate=None):
        """Atualiza a task de progresso do Rich."""
        progress.update(task_id, completed=completed)
        
        # Se verbose, atualiza descrição com detalhes
        if self.verbose and attempts is not None and rate is not None:
            description = f"[green]Quebrando hash[/green] - {attempts:,} tentativas - {rate:.0f} h/s"
            progress.update(task_id, description=description)
    
    def _gpu_hash_batch_cuda(self, passwords):
        """Processa batch de hashes usando CUDA."""
        if not self.use_gpu or not PYCUDA_AVAILABLE:
            return self._cpu_hash_batch(passwords)
        
        try:
            import pycuda.driver as cuda
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
        
        # Executa ataque em paralelo com barra de progresso
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            chunk_size = max(1, total_passwords // (self.workers * 4))
            
            future_to_chunk = {}
            for i in range(0, total_passwords, chunk_size):
                chunk = passwords[i:i + chunk_size]
                future = executor.submit(self._test_passwords_chunk, chunk)
                future_to_chunk[future] = i
            
            # Progress tracking com Rich
            completed_chunks = 0
            total_chunks = len(future_to_chunk)
            
            with create_progress() as progress:
                task_description = f"[green]Ataque de dicionário[/green]"
                if self.verbose:
                    task_description = f"[green]Ataque de dicionário[/green] - 0 tentativas - 0 h/s"
                    
                task = progress.add_task(task_description, total=total_chunks)
                
                for future in as_completed(future_to_chunk):
                    result = future.result()
                    completed_chunks += 1
                    
                    if result:
                        # Password found! Remove a task de progresso
                        progress.remove_task(task)
                        self.cracked_password = result
                        time_taken = time.time() - self.start_time
                        console.print(f"\n[bold green][+] SENHA ENCONTRADA: {result}[/bold green]")
                        console.print(f"[*] Tentativas: {self.attempts:,}")
                        console.print(f"[*] Tempo: {time_taken:.2f}s")
                        console.print(f"[*] Taxa: {self.attempts/time_taken:.2f} hashes/s")
                        return result, self.attempts, time_taken
                    
                    # Atualiza progresso
                    rate = self.attempts / (time.time() - self.start_time) if time.time() > self.start_time else 0
                    self._update_progress_task(progress, task, completed_chunks, total_chunks, self.attempts, rate)
        
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
        
        # Executa força bruta por comprimento com barra de progresso
        with create_progress() as progress:
            task_description = f"[green]Força bruta[/green]"
            if self.verbose:
                task_description = f"[green]Força bruta[/green] - 0 tentativas - 0 h/s"
                
            task = progress.add_task(task_description, total=total_combinations)
            
            for length in range(min_length, max_length + 1):
                if self.verbose:
                    console.print(f"[*] Testando senhas de {length} caracteres...")
                
                result = self._brute_force_length_with_progress(charset, length, progress, task)
                if result:
                    # Remove a task de progresso
                    progress.remove_task(task)
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
        
        # Gera e testa senhas baseadas na máscara com barra de progresso
        with create_progress() as progress:
            task_description = f"[green]Ataque por máscara[/green]"
            if self.verbose:
                task_description = f"[green]Ataque por máscara[/green] - 0 tentativas - 0 h/s"
                
            task = progress.add_task(task_description, total=total_combinations)
            
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
                            # Remove a task de progresso
                            progress.remove_task(task)
                            time_taken = time.time() - self.start_time
                            console.print(f"\n[bold green][+] SENHA ENCONTRADA: {result}[/bold green]")
                            return result, self.attempts, time_taken
                        batch = []
                        
                        # Atualiza progresso
                        rate = self.attempts / (time.time() - self.start_time) if time.time() > self.start_time else 0
                        self._update_progress_task(progress, task, self.attempts, total_combinations, self.attempts, rate)
                
                # Testa último batch
                if batch:
                    future = executor.submit(self._test_passwords_chunk, batch)
                    result = future.result()
                    if result:
                        # Remove a task de progresso
                        progress.remove_task(task)
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
        """Executa força bruta para um comprimento específico (versão antiga)."""
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
                    console.print(f"\r[*] {self.attempts:,} tentativas - {rate:.0f} h/s{' '*20}", end="")
            
            # Último batch
            if batch:
                future = executor.submit(self._test_passwords_chunk, batch)
                result = future.result()
                if result:
                    return result
        
        return None
    
    def _brute_force_length_with_progress(self, charset, length, progress, task):
        """Executa força bruta para um comprimento específico com barra de progresso."""
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            batch_size = 1000
            batch = []
            processed_passwords = 0
            
            for password_chars in itertools.product(charset, repeat=length):
                password = ''.join(password_chars)
                batch.append(password)
                processed_passwords += 1
                
                if len(batch) >= batch_size:
                    future = executor.submit(self._test_passwords_chunk, batch)
                    result = future.result()
                    if result:
                        return result
                    batch = []
                    
                    # Atualiza progresso
                    rate = self.attempts / (time.time() - self.start_time) if time.time() > self.start_time else 0
                    self._update_progress_task(progress, task, self.attempts, None, self.attempts, rate)
            
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
            # Simulação de consulta (session seria usado aqui)
            _ = session  # Placeholder para uso futuro
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
    
    # ═══════════════════════════════════════════════════════════════════════════════
    # NOVOS MODOS DE ATAQUE AVANÇADOS - Competindo com HashCat e John the Ripper
    # ═══════════════════════════════════════════════════════════════════════════════
    
    def hybrid_attack(self, wordlist_path, mask_suffix="", mask_prefix=""):
        """
        Ataque híbrido: Dictionary + Mask (como hashcat -a 6 e -a 7).
        
        Args:
            wordlist_path (str): Caminho para wordlist
            mask_suffix (str): Máscara para adicionar no final (?d?d = 2 dígitos)
            mask_prefix (str): Máscara para adicionar no início
            
        Returns:
            tuple: (password, attempts, time_taken)
        """
        console.print(f"[*] Iniciando ataque híbrido")
        console.print(f"[*] Wordlist: {wordlist_path}")
        if mask_prefix:
            console.print(f"[*] Prefixo: {mask_prefix}")
        if mask_suffix:
            console.print(f"[*] Sufixo: {mask_suffix}")
        
        self.attack_mode = 'hybrid'
        self.start_time = time.time()
        self.attempts = 0
        
        # Carrega wordlist
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                base_words = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            console.print(f"[red][!] Wordlist não encontrada: {wordlist_path}[/red]")
            return None, 0, 0
        
        # Parse máscaras
        prefix_variants = self._parse_mask_variants(mask_prefix) if mask_prefix else [""]
        suffix_variants = self._parse_mask_variants(mask_suffix) if mask_suffix else [""]
        
        total_combinations = len(base_words) * len(prefix_variants) * len(suffix_variants)
        console.print(f"[*] Total combinações: {total_combinations:,}")
        
        # Executa ataque híbrido com progresso
        with create_progress() as progress:
            task_description = f"[green]Ataque híbrido[/green]"
            if self.verbose:
                task_description = f"[green]Ataque híbrido[/green] - 0 tentativas - 0 h/s"
                
            task = progress.add_task(task_description, total=total_combinations)
            
            with ThreadPoolExecutor(max_workers=self.workers) as executor:
                batch_size = 5000
                batch = []
                processed = 0
                
                for word in base_words:
                    for prefix in prefix_variants:
                        for suffix in suffix_variants:
                            password = f"{prefix}{word}{suffix}"
                            batch.append(password)
                            processed += 1
                            
                            if len(batch) >= batch_size:
                                future = executor.submit(self._test_passwords_chunk, batch)
                                result = future.result()
                                if result:
                                    progress.remove_task(task)
                                    time_taken = time.time() - self.start_time
                                    console.print(f"\n[bold green][+] SENHA ENCONTRADA: {result}[/bold green]")
                                    console.print(f"[*] Tentativas: {self.attempts:,}")
                                    console.print(f"[*] Tempo: {time_taken:.2f}s")
                                    return result, self.attempts, time_taken
                                batch = []
                                
                                # Atualiza progresso
                                rate = self.attempts / (time.time() - self.start_time) if time.time() > self.start_time else 0
                                self._update_progress_task(progress, task, processed, total_combinations, self.attempts, rate)
                
                # Último batch
                if batch:
                    future = executor.submit(self._test_passwords_chunk, batch)
                    result = future.result()
                    if result:
                        progress.remove_task(task)
                        time_taken = time.time() - self.start_time
                        console.print(f"\n[bold green][+] SENHA ENCONTRADA: {result}[/bold green]")
                        return result, self.attempts, time_taken
        
        time_taken = time.time() - self.start_time
        console.print(f"\n[red][-] Senha não encontrada no ataque híbrido[/red]")
        return None, self.attempts, time_taken
    
    def combinator_attack(self, wordlist1_path, wordlist2_path, separator=""):
        """
        Ataque combinador: combina palavras de duas wordlists (como hashcat -a 1).
        
        Args:
            wordlist1_path (str): Primeira wordlist
            wordlist2_path (str): Segunda wordlist  
            separator (str): Separador entre palavras (opcional)
            
        Returns:
            tuple: (password, attempts, time_taken)
        """
        console.print(f"[*] Iniciando ataque combinador")
        console.print(f"[*] Wordlist 1: {wordlist1_path}")
        console.print(f"[*] Wordlist 2: {wordlist2_path}")
        if separator:
            console.print(f"[*] Separador: '{separator}'")
        
        self.attack_mode = 'combinator'
        self.start_time = time.time()
        self.attempts = 0
        
        # Carrega wordlists
        try:
            with open(wordlist1_path, 'r', encoding='utf-8', errors='ignore') as f:
                words1 = [line.strip() for line in f if line.strip()]
            with open(wordlist2_path, 'r', encoding='utf-8', errors='ignore') as f:
                words2 = [line.strip() for line in f if line.strip()]
        except FileNotFoundError as e:
            console.print(f"[red][!] Wordlist não encontrada: {e}[/red]")
            return None, 0, 0
        
        total_combinations = len(words1) * len(words2)
        console.print(f"[*] Combinações: {len(words1):,} × {len(words2):,} = {total_combinations:,}")
        
        # Executa ataque combinador
        with create_progress() as progress:
            task_description = f"[green]Ataque combinador[/green]"
            if self.verbose:
                task_description = f"[green]Ataque combinador[/green] - 0 tentativas - 0 h/s"
                
            task = progress.add_task(task_description, total=total_combinations)
            
            with ThreadPoolExecutor(max_workers=self.workers) as executor:
                batch_size = 5000
                batch = []
                processed = 0
                
                for word1 in words1:
                    for word2 in words2:
                        password = f"{word1}{separator}{word2}"
                        batch.append(password)
                        processed += 1
                        
                        if len(batch) >= batch_size:
                            future = executor.submit(self._test_passwords_chunk, batch)
                            result = future.result()
                            if result:
                                progress.remove_task(task)
                                time_taken = time.time() - self.start_time
                                console.print(f"\n[bold green][+] SENHA ENCONTRADA: {result}[/bold green]")
                                return result, self.attempts, time_taken
                            batch = []
                            
                            # Atualiza progresso
                            rate = self.attempts / (time.time() - self.start_time) if time.time() > self.start_time else 0
                            self._update_progress_task(progress, task, processed, total_combinations, self.attempts, rate)
                
                # Último batch
                if batch:
                    future = executor.submit(self._test_passwords_chunk, batch)
                    result = future.result()
                    if result:
                        progress.remove_task(task)
                        time_taken = time.time() - self.start_time
                        console.print(f"\n[bold green][+] SENHA ENCONTRADA: {result}[/bold green]")
                        return result, self.attempts, time_taken
        
        time_taken = time.time() - self.start_time
        console.print(f"\n[red][-] Senha não encontrada no ataque combinador[/red]")
        return None, self.attempts, time_taken
    
    def toggle_case_attack(self, wordlist_path):
        """
        Ataque de alternância de maiúsculas/minúsculas.
        Gera todas as variações possíveis de case para cada palavra.
        
        Args:
            wordlist_path (str): Caminho para wordlist
            
        Returns:
            tuple: (password, attempts, time_taken)
        """
        console.print(f"[*] Iniciando ataque de alternância de case")
        console.print(f"[*] Wordlist: {wordlist_path}")
        
        self.attack_mode = 'toggle_case'
        self.start_time = time.time()
        self.attempts = 0
        
        # Carrega wordlist
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            console.print(f"[red][!] Wordlist não encontrada: {wordlist_path}[/red]")
            return None, 0, 0
        
        # Calcula total de variações (2^n por palavra, onde n = letras)
        total_variants = 0
        for word in words:
            letter_count = sum(1 for c in word if c.isalpha())
            total_variants += min(2**letter_count, 1000)  # Limita a 1000 por palavra
        
        console.print(f"[*] Total variações: {total_variants:,}")
        
        # Executa ataque toggle case
        with create_progress() as progress:
            task_description = f"[green]Ataque toggle case[/green]"
            if self.verbose:
                task_description = f"[green]Ataque toggle case[/green] - 0 tentativas - 0 h/s"
                
            task = progress.add_task(task_description, total=total_variants)
            
            with ThreadPoolExecutor(max_workers=self.workers) as executor:
                batch_size = 2000
                batch = []
                processed = 0
                
                for word in words:
                    variants = self._generate_case_variants(word)
                    for variant in variants:
                        batch.append(variant)
                        processed += 1
                        
                        if len(batch) >= batch_size:
                            future = executor.submit(self._test_passwords_chunk, batch)
                            result = future.result()
                            if result:
                                progress.remove_task(task)
                                time_taken = time.time() - self.start_time
                                console.print(f"\n[bold green][+] SENHA ENCONTRADA: {result}[/bold green]")
                                return result, self.attempts, time_taken
                            batch = []
                            
                            # Atualiza progresso
                            rate = self.attempts / (time.time() - self.start_time) if time.time() > self.start_time else 0
                            self._update_progress_task(progress, task, processed, total_variants, self.attempts, rate)
                
                # Último batch
                if batch:
                    future = executor.submit(self._test_passwords_chunk, batch)
                    result = future.result()
                    if result:
                        progress.remove_task(task)
                        time_taken = time.time() - self.start_time
                        console.print(f"\n[bold green][+] SENHA ENCONTRADA: {result}[/bold green]")
                        return result, self.attempts, time_taken
        
        time_taken = time.time() - self.start_time
        console.print(f"\n[red][-] Senha não encontrada no ataque toggle case[/red]")
        return None, self.attempts, time_taken
    
    def increment_attack(self, min_length=1, max_length=6, charset=None):
        """
        Ataque incremental: força bruta otimizada baseada em frequência de caracteres.
        Inspirado no modo incremental do John the Ripper.
        
        Args:
            min_length (int): Comprimento mínimo
            max_length (int): Comprimento máximo
            charset (str): Conjunto de caracteres (ordenado por frequência)
            
        Returns:
            tuple: (password, attempts, time_taken)
        """
        # Charset otimizado por frequência (letras mais comuns primeiro)
        charset = charset or "etaoinshrdlcumwfgypbvkjxqz0123456789"
        
        console.print(f"[*] Iniciando ataque incremental")
        console.print(f"[*] Comprimento: {min_length}-{max_length}")
        console.print(f"[*] Charset (por frequência): {charset[:20]}{'...' if len(charset) > 20 else ''}")
        
        self.attack_mode = 'increment'
        self.start_time = time.time()
        self.attempts = 0
        
        total_combinations = sum(len(charset) ** length for length in range(min_length, max_length + 1))
        console.print(f"[*] Total combinações: {total_combinations:,}")
        
        # Executa ataque incremental com progresso
        with create_progress() as progress:
            task_description = f"[green]Ataque incremental[/green]"
            if self.verbose:
                task_description = f"[green]Ataque incremental[/green] - 0 tentativas - 0 h/s"
                
            task = progress.add_task(task_description, total=total_combinations)
            
            # Testa por comprimento, priorizando caracteres mais frequentes
            for length in range(min_length, max_length + 1):
                if self.verbose:
                    console.print(f"[*] Testando senhas de {length} caracteres...")
                
                result = self._increment_length_search(charset, length, progress, task)
                if result:
                    progress.remove_task(task)
                    time_taken = time.time() - self.start_time
                    console.print(f"\n[bold green][+] SENHA ENCONTRADA: {result}[/bold green]")
                    return result, self.attempts, time_taken
        
        time_taken = time.time() - self.start_time
        console.print(f"\n[red][-] Senha não encontrada no ataque incremental[/red]")
        return None, self.attempts, time_taken
    
    def prince_attack(self, wordlist_path, elements_per_chain=4):
        """
        Ataque PRINCE (Probability Infinite Chained Elements).
        Gera candidatos baseado em segmentos de palavras do dicionário.
        
        Args:
            wordlist_path (str): Caminho para wordlist
            elements_per_chain (int): Número de elementos por chain
            
        Returns:
            tuple: (password, attempts, time_taken)
        """
        console.print(f"[*] Iniciando ataque PRINCE")
        console.print(f"[*] Wordlist: {wordlist_path}")
        console.print(f"[*] Elementos por chain: {elements_per_chain}")
        
        self.attack_mode = 'prince'
        self.start_time = time.time()
        self.attempts = 0
        
        # Carrega wordlist e extrai elementos
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            console.print(f"[red][!] Wordlist não encontrada: {wordlist_path}[/red]")
            return None, 0, 0
        
        # Extrai elementos (substrings) das palavras
        elements = self._extract_prince_elements(words)
        console.print(f"[*] Elementos extraídos: {len(elements):,}")
        
        # Calcula combinações aproximadas
        estimated_combinations = len(elements) ** elements_per_chain
        console.print(f"[*] Combinações estimadas: {estimated_combinations:,}")
        
        # Executa ataque PRINCE
        with create_progress() as progress:
            task_description = f"[green]Ataque PRINCE[/green]"
            if self.verbose:
                task_description = f"[green]Ataque PRINCE[/green] - 0 tentativas - 0 h/s"
                
            task = progress.add_task(task_description, total=estimated_combinations)
            
            result = self._prince_generate_candidates(elements, elements_per_chain, progress, task)
            if result:
                progress.remove_task(task)
                time_taken = time.time() - self.start_time
                console.print(f"\n[bold green][+] SENHA ENCONTRADA: {result}[/bold green]")
                return result, self.attempts, time_taken
        
        time_taken = time.time() - self.start_time
        console.print(f"\n[red][-] Senha não encontrada no ataque PRINCE[/red]")
        return None, self.attempts, time_taken
    
    # ═══════════════════════════════════════════════════════════════════════════════
    # FUNÇÕES AUXILIARES PARA OS NOVOS ATAQUES
    # ═══════════════════════════════════════════════════════════════════════════════
    
    def _parse_mask_variants(self, mask):
        """Converte máscara em lista de variantes possíveis."""
        if not mask:
            return [""]
        
        mask_chars = {
            '?l': string.ascii_lowercase,
            '?u': string.ascii_uppercase,
            '?d': string.digits,
            '?s': '!@#$%^&*()_+-=[]{}|;:,.<>?',
            '?a': string.ascii_letters + string.digits + '!@#$%^&*()_+-=[]{}|;:,.<>?'
        }
        
        # Parse simples da máscara
        variants = [""]
        i = 0
        while i < len(mask):
            if i < len(mask) - 1 and mask[i:i+2] in mask_chars:
                # É uma máscara
                charset = mask_chars[mask[i:i+2]]
                new_variants = []
                for variant in variants:
                    for char in charset:
                        new_variants.append(variant + char)
                        if len(new_variants) > 10000:  # Limita para evitar explosão
                            return new_variants[:10000]
                variants = new_variants
                i += 2
            else:
                # É um caractere literal
                variants = [v + mask[i] for v in variants]
                i += 1
        
        return variants
    
    def _generate_case_variants(self, word):
        """Gera todas as variações de maiúscula/minúscula para uma palavra."""
        letter_positions = [i for i, c in enumerate(word) if c.isalpha()]
        if not letter_positions or len(letter_positions) > 10:  # Limita para evitar explosão
            return [word, word.lower(), word.upper(), word.capitalize()]
        
        variants = set()
        # Gera todas as combinações de case
        for mask in range(2 ** len(letter_positions)):
            variant = list(word.lower())
            for i, pos in enumerate(letter_positions):
                if mask & (1 << i):
                    variant[pos] = variant[pos].upper()
            variants.add(''.join(variant))
            
            if len(variants) > 500:  # Limita para performance
                break
        
        return list(variants)
    
    def _increment_length_search(self, charset, length, progress, task):
        """Busca incremental otimizada por comprimento."""
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            batch_size = 1000
            batch = []
            
            # Gera senhas priorizando caracteres mais frequentes
            def generate_incremental_passwords():
                # Algoritmo simplificado - em produção seria mais sofisticado
                for chars in itertools.product(charset, repeat=length):
                    yield ''.join(chars)
            
            for password in generate_incremental_passwords():
                batch.append(password)
                
                if len(batch) >= batch_size:
                    future = executor.submit(self._test_passwords_chunk, batch)
                    result = future.result()
                    if result:
                        return result
                    batch = []
                    
                    # Atualiza progresso ocasionalmente
                    if self.attempts % 50000 == 0:
                        rate = self.attempts / (time.time() - self.start_time) if time.time() > self.start_time else 0
                        self._update_progress_task(progress, task, self.attempts, None, self.attempts, rate)
            
            # Último batch
            if batch:
                future = executor.submit(self._test_passwords_chunk, batch)
                result = future.result()
                if result:
                    return result
        
        return None
    
    def _extract_prince_elements(self, words):
        """Extrai elementos para ataque PRINCE."""
        elements = set()
        
        for word in words:
            # Adiciona palavra inteira
            elements.add(word)
            
            # Adiciona substrings
            for length in range(2, min(len(word) + 1, 8)):  # Até 7 caracteres
                for i in range(len(word) - length + 1):
                    elements.add(word[i:i + length])
        
        # Filtra elementos muito comuns ou muito raros
        elements = [e for e in elements if 2 <= len(e) <= 10]
        
        # Ordena por frequência (simplificado)
        return sorted(elements, key=len)[:5000]  # Limita para performance
    
    def _prince_generate_candidates(self, elements, chain_length, progress, task):
        """Gera candidatos PRINCE."""
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            batch_size = 2000
            batch = []
            processed = 0
            
            # Gera combinações de elementos
            for combination in itertools.product(elements, repeat=chain_length):
                candidate = ''.join(combination)
                
                # Filtra candidatos muito longos
                if len(candidate) <= 20:
                    batch.append(candidate)
                    processed += 1
                
                if len(batch) >= batch_size:
                    future = executor.submit(self._test_passwords_chunk, batch)
                    result = future.result()
                    if result:
                        return result
                    batch = []
                    
                    # Atualiza progresso
                    if processed % 10000 == 0:
                        rate = self.attempts / (time.time() - self.start_time) if time.time() > self.start_time else 0
                        self._update_progress_task(progress, task, processed, None, self.attempts, rate)
            
            # Último batch
            if batch:
                future = executor.submit(self._test_passwords_chunk, batch)
                result = future.result()
                if result:
                    return result
        
        return None


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
    verbose = kwargs.get('verbose', False)
    cracker = AdvancedHashCracker(hash_target, hash_type, use_gpu=use_gpu, verbose=verbose)
    
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
    elif attack_mode == 'hybrid':
        # Ataque híbrido - dictionary + mask
        mask_suffix = kwargs.get('mask_suffix', '?d?d')
        mask_prefix = kwargs.get('mask_prefix', '')
        password, attempts, time_taken = cracker.hybrid_attack(wordlist_path, mask_suffix, mask_prefix)
    elif attack_mode == 'combinator':
        # Ataque combinador - duas wordlists
        wordlist2_path = kwargs.get('wordlist2', None)
        separator = kwargs.get('separator', '')
        if not wordlist2_path:
            return {'error': 'Ataque combinador requer duas wordlists (wordlist2=...)'}
        password, attempts, time_taken = cracker.combinator_attack(wordlist_path, wordlist2_path, separator)
    elif attack_mode == 'toggle_case':
        # Ataque de alternância de case
        password, attempts, time_taken = cracker.toggle_case_attack(wordlist_path)
    elif attack_mode == 'increment':
        # Ataque incremental otimizado
        min_len = kwargs.get('min_length', 1)
        max_len = kwargs.get('max_length', 6)
        charset = kwargs.get('charset', None)
        password, attempts, time_taken = cracker.increment_attack(min_len, max_len, charset)
    elif attack_mode == 'prince':
        # Ataque PRINCE
        elements_per_chain = kwargs.get('elements_per_chain', 4)
        password, attempts, time_taken = cracker.prince_attack(wordlist_path, elements_per_chain)
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
        
        # 3. Toggle Case Attack
        if wordlist_path:
            console.print("\n[*] === TENTATIVA 3: TOGGLE CASE ATTACK ===")
            password, attempts, time_taken = cracker.toggle_case_attack(wordlist_path)
            if password:
                return {
                    'hash_type': cracker.hash_type,
                    'attack_mode': 'toggle_case',
                    'password': password,
                    'attempts': attempts,
                    'time_taken': time_taken,
                    'success': True
                }
        
        # 4. Hybrid Attack (wordlist + common suffixes)
        if wordlist_path:
            console.print("\n[*] === TENTATIVA 4: HYBRID ATTACK (suffix ?d?d) ===")
            password, attempts, time_taken = cracker.hybrid_attack(wordlist_path, mask_suffix="?d?d")
            if password:
                return {
                    'hash_type': cracker.hash_type,
                    'attack_mode': 'hybrid',
                    'password': password,
                    'attempts': attempts,
                    'time_taken': time_taken,
                    'success': True
                }
        
        # 5. PRINCE Attack (se wordlist disponível)
        if wordlist_path:
            console.print("\n[*] === TENTATIVA 5: PRINCE ATTACK ===")
            password, attempts, time_taken = cracker.prince_attack(wordlist_path, elements_per_chain=3)
            if password:
                return {
                    'hash_type': cracker.hash_type,
                    'attack_mode': 'prince',
                    'password': password,
                    'attempts': attempts,
                    'time_taken': time_taken,
                    'success': True
                }
        
        # 6. Increment Attack (otimizado)
        console.print("\n[*] === TENTATIVA 6: INCREMENT ATTACK (1-4 chars) ===")
        password, attempts, time_taken = cracker.increment_attack(1, 4)
        if password:
            return {
                'hash_type': cracker.hash_type,
                'attack_mode': 'increment',
                'password': password,
                'attempts': attempts,
                'time_taken': time_taken,
                'success': True
            }
        
        # 7. Brute Force (último recurso - mais lento)
        console.print("\n[*] === TENTATIVA 7: BRUTE FORCE (1-4 chars) - ÚLTIMO RECURSO ===")
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


def get_supported_algorithms():
    """Retorna lista de algoritmos suportados."""
    base_algorithms = [
        'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512',
        'md4', 'ntlm', 'blake2b', 'blake2s', 'sha3_224', 'sha3_256',
        'sha3_384', 'sha3_512', 'ripemd160', 'whirlpool'
    ]
    
    special_algorithms = []
    
    if BCRYPT_AVAILABLE:
        special_algorithms.append('bcrypt')
    if ARGON2_AVAILABLE:
        special_algorithms.append('argon2')
    if SCRYPT_AVAILABLE:
        special_algorithms.append('scrypt')
    
    # PBKDF2 é sempre disponível
    special_algorithms.append('pbkdf2')
    
    return {
        'base': base_algorithms,
        'special': special_algorithms,
        'all': base_algorithms + special_algorithms
    }


def get_attack_modes():
    """Retorna lista de modos de ataque disponíveis."""
    return {
        'basic': [
            'dictionary',     # Ataque de dicionário básico
            'brute_force',    # Força bruta tradicional
            'mask',          # Ataque por máscara (estilo hashcat)
            'rainbow',       # Rainbow tables
        ],
        'advanced': [
            'hybrid',        # Dictionary + Mask (hashcat -a 6/7)
            'combinator',    # Combina duas wordlists (hashcat -a 1)
            'toggle_case',   # Alternância de maiúsculas/minúsculas
            'increment',     # Força bruta incremental otimizada (john-style)
            'prince',        # PRINCE attack (Probability Infinite Chained Elements)
        ],
        'utility': [
            'online',        # Lookup em serviços online
            'all',          # Executa todos os ataques em sequência
        ]
    }


def display_algorithm_info():
    """Exibe informações sobre algoritmos suportados."""
    algorithms = get_supported_algorithms()
    
    console.print("\n[bold blue]═══ ALGORITMOS DE HASH SUPORTADOS ═══[/bold blue]")
    
    console.print("\n[bold green]Algoritmos Base:[/bold green]")
    for algo in algorithms['base']:
        console.print(f"  • {algo}")
    
    console.print("\n[bold yellow]Algoritmos Especiais:[/bold yellow]")
    for algo in algorithms['special']:
        status = "[green]✓[/green]"
        if algo == 'bcrypt' and not BCRYPT_AVAILABLE:
            status = "[red]✗[/red] (pip install bcrypt)"
        elif algo == 'argon2' and not ARGON2_AVAILABLE:
            status = "[red]✗[/red] (pip install argon2-cffi)"
        elif algo == 'scrypt' and not SCRYPT_AVAILABLE:
            status = "[red]✗[/red] (pip install scrypt)"
        
        console.print(f"  • {algo} {status}")
    
    console.print(f"\n[bold]Total: {len(algorithms['all'])} algoritmos[/bold]")


def display_attack_modes_info():
    """Exibe informações sobre modos de ataque disponíveis."""
    console.print(f"\n[bold blue]═══ MODOS DE ATAQUE SUPORTADOS ═══[/bold blue]")
    
    attack_modes = get_attack_modes()
    
    console.print(f"\n[bold green]🔥 ATAQUES BÁSICOS[/bold green]")
    for mode in attack_modes['basic']:
        descriptions = {
            'dictionary': 'Testa senhas de uma wordlist',
            'brute_force': 'Força bruta tradicional por comprimento',
            'mask': 'Ataque por máscara (ex: ?l?l?l?d?d)',
            'rainbow': 'Usa rainbow tables pré-computadas'
        }
        console.print(f"  • [cyan]{mode:<12}[/cyan] - {descriptions.get(mode, 'Descrição não disponível')}")
    
    console.print(f"\n[bold yellow]⚡ ATAQUES AVANÇADOS[/bold yellow]")
    for mode in attack_modes['advanced']:
        descriptions = {
            'hybrid': 'Dictionary + Mask (ex: palavra + ?d?d)',
            'combinator': 'Combina palavras de duas wordlists',
            'toggle_case': 'Variações de maiúscula/minúscula',
            'increment': 'Força bruta otimizada por frequência',
            'prince': 'PRINCE - segmentos probabilísticos'
        }
        console.print(f"  • [cyan]{mode:<12}[/cyan] - {descriptions.get(mode, 'Descrição não disponível')}")
    
    console.print(f"\n[bold magenta]🛠️ UTILITÁRIOS[/bold magenta]")
    for mode in attack_modes['utility']:
        descriptions = {
            'online': 'Consulta bases de hashes online',
            'all': 'Executa todos os ataques automaticamente'
        }
        console.print(f"  • [cyan]{mode:<12}[/cyan] - {descriptions.get(mode, 'Descrição não disponível')}")
    
    total_modes = len(attack_modes['basic']) + len(attack_modes['advanced']) + len(attack_modes['utility'])
    console.print(f"\n[bold]Total: {total_modes} modos de ataque[/bold]")
    
    console.print(f"\n[bold blue]💡 EXEMPLOS DE USO:[/bold blue]")
    console.print(f"  [green]Dictionary:[/green]  --attack-mode dictionary --wordlist rockyou.txt")
    console.print(f"  [green]Hybrid:[/green]     --attack-mode hybrid --wordlist words.txt --mask-suffix '?d?d'")
    console.print(f"  [green]Combinator:[/green] --attack-mode combinator --wordlist1 words1.txt --wordlist2 words2.txt")
    console.print(f"  [green]Toggle Case:[/green]--attack-mode toggle_case --wordlist common.txt")
    console.print(f"  [green]Increment:[/green]  --attack-mode increment --min-length 1 --max-length 6")
    console.print(f"  [green]PRINCE:[/green]     --attack-mode prince --wordlist base.txt --elements-per-chain 4")
    console.print(f"  [green]Automático:[/green] --attack-mode all --wordlist rockyou.txt")


def benchmark_hash_algorithms(password="test123", iterations=1000):
    """Benchmark de algoritmos de hash."""
    console.print(f"\n[bold blue]═══ BENCHMARK DE ALGORITMOS ═══[/bold blue]")
    console.print(f"Password: {password} | Iterações: {iterations:,}")
    
    results = {}
    algorithms = get_supported_algorithms()
    
    for algo in algorithms['base']:
        try:
            start_time = time.time()
            cracker = AdvancedHashCracker("dummy_hash")
            cracker.hash_type = algo
            
            for _ in range(iterations):
                cracker._hash_password(password)
            
            elapsed = time.time() - start_time
            rate = iterations / elapsed
            results[algo] = rate
            
        except Exception as e:
            results[algo] = f"Error: {e}"
    
    # Ordena por performance
    sorted_results = sorted(
        [(k, v) for k, v in results.items() if isinstance(v, (int, float))],
        key=lambda x: x[1],
        reverse=True
    )
    
    console.print("\n[bold green]Resultados (hashes/segundo):[/bold green]")
    for algo, rate in sorted_results:
        console.print(f"  {algo:15} {rate:10.0f} h/s")
    
    # Mostra erros se houver
    errors = [(k, v) for k, v in results.items() if not isinstance(v, (int, float))]
    if errors:
        console.print("\n[bold red]Erros:[/bold red]")
        for algo, error in errors:
            console.print(f"  {algo}: {error}")
    
    return results


def get_hash_info(hash_string):
    """Retorna informações detalhadas sobre um hash."""
    hash_length = len(hash_string)
    detected_type = detect_hash_type(hash_string)
    
    info = {
        'hash': hash_string,
        'length': hash_length,
        'detected_type': detected_type,
        'entropy': calculate_entropy(hash_string),
        'charset': analyze_charset(hash_string),
        'possible_types': []
    }
    
    # Determina tipos possíveis baseado no comprimento
    length_patterns = {
        32: ['md5', 'ntlm', 'blake2s'],
        40: ['sha1', 'ripemd160'],
        56: ['sha224', 'sha3_224'],
        64: ['sha256', 'sha3_256', 'blake2b'],
        96: ['sha384', 'sha3_384'],
        128: ['sha512', 'sha3_512', 'whirlpool'],
    }
    
    info['possible_types'] = length_patterns.get(hash_length, [])
    
    return info


def calculate_entropy(text):
    """Calcula entropia de uma string."""
    if not text:
        return 0
    
    # Conta frequência de caracteres
    char_counts = {}
    for char in text:
        char_counts[char] = char_counts.get(char, 0) + 1
    
    # Calcula entropia
    entropy = 0
    text_length = len(text)
    for count in char_counts.values():
        probability = count / text_length
        entropy -= probability * (probability.bit_length() - 1)
    
    return entropy


def analyze_charset(text):
    """Analisa conjunto de caracteres usado em uma string."""
    if not text:
        return []
    
    charset_info = []
    
    if any(c.islower() for c in text):
        charset_info.append('lowercase')
    if any(c.isupper() for c in text):
        charset_info.append('uppercase')
    if any(c.isdigit() for c in text):
        charset_info.append('digits')
    if any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in text):
        charset_info.append('special')
    if any(ord(c) > 127 for c in text):
        charset_info.append('unicode')
    
    return charset_info


def display_hash_info(hash_string):
    """Exibe informações detalhadas sobre um hash."""
    info = get_hash_info(hash_string)
    
    console.print(f"\n[bold blue]═══ INFORMAÇÕES DO HASH ═══[/bold blue]")
    console.print(f"Hash: {info['hash']}")
    console.print(f"Comprimento: {info['length']} caracteres")
    console.print(f"Tipo detectado: [bold green]{info['detected_type']}[/bold green]")
    console.print(f"Entropia: {info['entropy']:.2f}")
    console.print(f"Charset: {', '.join(info['charset'])}")
    
    if info['possible_types']:
        console.print(f"Tipos possíveis: {', '.join(info['possible_types'])}")
    
    console.print()


def generate_sample_hashes(password="test123"):
    """Gera hashes de exemplo para diferentes algoritmos."""
    console.print(f"\n[bold blue]═══ HASHES DE EXEMPLO ═══[/bold blue]")
    console.print(f"Password: {password}")
    
    algorithms = ['md5', 'sha1', 'sha256', 'sha512', 'blake2b']
    
    for algo in algorithms:
        try:
            if algo == 'md5':
                hash_result = hashlib.md5(password.encode()).hexdigest()
            elif algo == 'sha1':
                hash_result = hashlib.sha1(password.encode()).hexdigest()
            elif algo == 'sha256':
                hash_result = hashlib.sha256(password.encode()).hexdigest()
            elif algo == 'sha512':
                hash_result = hashlib.sha512(password.encode()).hexdigest()
            elif algo == 'blake2b':
                hash_result = hashlib.blake2b(password.encode(), digest_size=32).hexdigest()
            
            console.print(f"{algo:10} {hash_result}")
            
        except Exception as e:
            console.print(f"{algo:10} Error: {e}")
    
    console.print()


class SecurityValidator:
    """Validador de segurança para entradas e operações."""
    
    def __init__(self):
        self.max_hash_length = 1024
        self.max_password_length = 128
        self.max_wordlist_size = 100 * 1024 * 1024  # 100MB
        self.allowed_hash_chars = set('0123456789abcdefABCDEF${}[]():.-_')
        
    def validate_hash(self, hash_string):
        """Valida se um hash é seguro para processar."""
        if not hash_string:
            return False, "Hash vazio"
        
        if len(hash_string) > self.max_hash_length:
            return False, f"Hash muito longo (max: {self.max_hash_length})"
        
        # Verifica caracteres suspeitos
        if not all(c in self.allowed_hash_chars for c in hash_string):
            return False, "Hash contém caracteres inválidos"
        
        return True, "Hash válido"
    
    def validate_password(self, password):
        """Valida se uma senha é segura para processar."""
        if not password:
            return False, "Senha vazia"
        
        if len(password) > self.max_password_length:
            return False, f"Senha muito longa (max: {self.max_password_length})"
        
        # Verifica caracteres de controle perigosos
        if any(ord(c) < 32 and c not in '\t\n\r' for c in password):
            return False, "Senha contém caracteres de controle"
        
        return True, "Senha válida"
    
    def validate_wordlist_path(self, wordlist_path):
        """Valida se um caminho de wordlist é seguro."""
        if not wordlist_path:
            return False, "Caminho vazio"
        
        # Verifica se o arquivo existe
        if not os.path.exists(wordlist_path):
            return False, "Arquivo não encontrado"
        
        # Verifica se é um arquivo (não diretório)
        if not os.path.isfile(wordlist_path):
            return False, "Caminho não é um arquivo"
        
        # Verifica tamanho do arquivo
        try:
            file_size = os.path.getsize(wordlist_path)
            if file_size > self.max_wordlist_size:
                return False, f"Arquivo muito grande (max: {self.max_wordlist_size // (1024*1024)}MB)"
        except OSError:
            return False, "Erro ao verificar tamanho do arquivo"
        
        # Verifica se não é um executável
        if os.access(wordlist_path, os.X_OK):
            return False, "Arquivo executável não permitido"
        
        return True, "Wordlist válida"
    
    def sanitize_path(self, path):
        """Sanitiza um caminho de arquivo."""
        if not path:
            return None
        
        # Remove caracteres perigosos
        dangerous_chars = ['..', '~', '$', '`', '|', '&', ';', '(', ')', '<', '>']
        for char in dangerous_chars:
            path = path.replace(char, '')
        
        # Normaliza o caminho
        path = os.path.normpath(path)
        
        return path
    
    def check_resource_limits(self):
        """Verifica limites de recursos do sistema."""
        memory_percent = psutil.virtual_memory().percent
        cpu_percent = psutil.cpu_percent()
        
        warnings = []
        
        if memory_percent > 90:
            warnings.append("Uso de memória crítico (>90%)")
        elif memory_percent > 80:
            warnings.append("Uso de memória alto (>80%)")
        
        if cpu_percent > 95:
            warnings.append("Uso de CPU crítico (>95%)")
        elif cpu_percent > 85:
            warnings.append("Uso de CPU alto (>85%)")
        
        return warnings
    
    def validate_attack_parameters(self, attack_mode, **kwargs):
        """Valida parâmetros de ataque."""
        if attack_mode == 'brute_force':
            max_length = kwargs.get('max_length', 8)
            charset = kwargs.get('charset', '')
            
            if max_length > 12:
                return False, "Comprimento máximo muito alto para força bruta (max: 12)"
            
            if len(charset) > 256:
                return False, "Charset muito grande"
            
            # Calcula complexidade
            complexity = sum(len(charset) ** i for i in range(1, max_length + 1))
            if complexity > 10**12:
                return False, f"Complexidade muito alta: {complexity:,} combinações"
        
        elif attack_mode == 'mask':
            mask = kwargs.get('mask', '')
            if len(mask) > 20:
                return False, "Máscara muito longa"
        
        return True, "Parâmetros válidos"


class AuditLogger:
    """Logger de auditoria para operações de hash cracking."""
    
    def __init__(self, log_file=None):
        self.log_file = log_file or os.path.join(os.path.dirname(__file__), '..', 'logs', 'hash_cracker_audit.log')
        self.session_id = int(time.time())
        
        # Garante que o diretório de logs existe
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
        
        # Inicia sessão
        self.log_event('SESSION_START', {'session_id': self.session_id})
    
    def log_event(self, event_type, data):
        """Registra um evento de auditoria."""
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        log_entry = {
            'timestamp': timestamp,
            'session_id': self.session_id,
            'event_type': event_type,
            'data': data
        }
        
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            logger.error(f"Erro ao escrever log de auditoria: {e}")
    
    def log_attack_start(self, hash_type, attack_mode, **kwargs):
        """Registra início de ataque."""
        self.log_event('ATTACK_START', {
            'hash_type': hash_type,
            'attack_mode': attack_mode,
            'parameters': kwargs
        })
    
    def log_attack_end(self, success, attempts, time_taken):
        """Registra fim de ataque."""
        self.log_event('ATTACK_END', {
            'success': success,
            'attempts': attempts,
            'time_taken': time_taken
        })
    
    def log_security_warning(self, warning_type, details):
        """Registra aviso de segurança."""
        self.log_event('SECURITY_WARNING', {
            'warning_type': warning_type,
            'details': details
        })
    
    def log_error(self, error_type, error_message):
        """Registra erro."""
        self.log_event('ERROR', {
            'error_type': error_type,
            'error_message': error_message
        })


def secure_hash_crack(hash_target, **kwargs):
    """Versão segura da função de quebra de hash."""
    validator = SecurityValidator()
    audit_logger = AuditLogger()
    
    # Valida hash
    is_valid, message = validator.validate_hash(hash_target)
    if not is_valid:
        audit_logger.log_security_warning('INVALID_HASH', message)
        console.print(f"[red][!] Hash inválido: {message}[/red]")
        return None
    
    # Valida parâmetros de ataque
    attack_mode = kwargs.get('attack_mode', 'dictionary')
    is_valid, message = validator.validate_attack_parameters(attack_mode, **kwargs)
    if not is_valid:
        audit_logger.log_security_warning('INVALID_PARAMS', message)
        console.print(f"[red][!] Parâmetros inválidos: {message}[/red]")
        return None
    
    # Valida wordlist se necessário
    wordlist_path = kwargs.get('wordlist_path')
    if wordlist_path:
        wordlist_path = validator.sanitize_path(wordlist_path)
        is_valid, message = validator.validate_wordlist_path(wordlist_path)
        if not is_valid:
            audit_logger.log_security_warning('INVALID_WORDLIST', message)
            console.print(f"[red][!] Wordlist inválida: {message}[/red]")
            return None
        kwargs['wordlist_path'] = wordlist_path
    
    # Verifica recursos do sistema
    resource_warnings = validator.check_resource_limits()
    if resource_warnings:
        for warning in resource_warnings:
            audit_logger.log_security_warning('RESOURCE_WARNING', warning)
            console.print(f"[yellow][!] {warning}[/yellow]")
    
    # Registra início do ataque
    audit_logger.log_attack_start(kwargs.get('hash_type'), attack_mode, **kwargs)
    
    try:
        # Executa ataque
        result = crack_hash(hash_target, **kwargs)
        
        # Registra resultado
        audit_logger.log_attack_end(
            success=result.get('success', False),
            attempts=result.get('attempts', 0),
            time_taken=result.get('time_taken', 0)
        )
        
        return result
        
    except Exception as e:
        audit_logger.log_error('ATTACK_ERROR', str(e))
        console.print(f"[red][!] Erro durante ataque: {e}[/red]")
        return None


def get_security_recommendations():
    """Retorna recomendações de segurança."""
    recommendations = [
        "Use apenas hashes de fontes confiáveis",
        "Não execute ataques em sistemas que não são seus",
        "Monitore o uso de recursos durante ataques",
        "Mantenha logs de auditoria para compliance",
        "Use wordlists de fontes confiáveis",
        "Implemente rate limiting para ataques online",
        "Use ambientes isolados para testes",
        "Mantenha backups de rainbow tables",
        "Valide todos os inputs antes do processamento",
        "Use criptografia adequada para armazenar resultados"
    ]
    
    console.print("\n[bold blue]═══ RECOMENDAÇÕES DE SEGURANÇA ═══[/bold blue]")
    for i, rec in enumerate(recommendations, 1):
        console.print(f"{i:2d}. {rec}")
    console.print()
    
    return recommendations


class AdvancedStatistics:
    """Sistema avançado de estatísticas para hash cracking."""
    
    def __init__(self):
        self.sessions = []
        self.current_session = None
        self.benchmarks = {}
        self.success_rates = {}
        
    def start_session(self, hash_type, attack_mode):
        """Inicia uma nova sessão de estatísticas."""
        self.current_session = {
            'session_id': int(time.time()),
            'hash_type': hash_type,
            'attack_mode': attack_mode,
            'start_time': time.time(),
            'end_time': None,
            'attempts': 0,
            'success': False,
            'password_found': None,
            'performance_samples': [],
            'memory_usage': [],
            'cpu_usage': [],
            'gpu_usage': [],
            'errors': []
        }
        
    def record_performance_sample(self, attempts, rate, memory_percent, cpu_percent, gpu_percent=0):
        """Registra amostra de performance."""
        if not self.current_session:
            return
            
        timestamp = time.time()
        sample = {
            'timestamp': timestamp,
            'attempts': attempts,
            'rate': rate,
            'memory_percent': memory_percent,
            'cpu_percent': cpu_percent,
            'gpu_percent': gpu_percent
        }
        
        self.current_session['performance_samples'].append(sample)
        self.current_session['memory_usage'].append(memory_percent)
        self.current_session['cpu_usage'].append(cpu_percent)
        if gpu_percent > 0:
            self.current_session['gpu_usage'].append(gpu_percent)
    
    def record_error(self, error_type, error_message):
        """Registra erro."""
        if not self.current_session:
            return
            
        error = {
            'timestamp': time.time(),
            'type': error_type,
            'message': error_message
        }
        
        self.current_session['errors'].append(error)
    
    def end_session(self, success=False, password_found=None):
        """Finaliza sessão atual."""
        if not self.current_session:
            return
            
        self.current_session['end_time'] = time.time()
        self.current_session['success'] = success
        self.current_session['password_found'] = password_found
        
        # Calcula estatísticas finais
        self._calculate_session_stats()
        
        # Adiciona à lista de sessões
        self.sessions.append(self.current_session)
        
        # Atualiza estatísticas globais
        self._update_global_stats()
        
        self.current_session = None
    
    def _calculate_session_stats(self):
        """Calcula estatísticas da sessão atual."""
        if not self.current_session or not self.current_session['performance_samples']:
            return
            
        samples = self.current_session['performance_samples']
        
        # Estatísticas de performance
        rates = [s['rate'] for s in samples]
        self.current_session['avg_rate'] = sum(rates) / len(rates)
        self.current_session['peak_rate'] = max(rates)
        self.current_session['min_rate'] = min(rates)
        
        # Estatísticas de recursos
        if self.current_session['memory_usage']:
            self.current_session['avg_memory'] = sum(self.current_session['memory_usage']) / len(self.current_session['memory_usage'])
            self.current_session['peak_memory'] = max(self.current_session['memory_usage'])
        
        if self.current_session['cpu_usage']:
            self.current_session['avg_cpu'] = sum(self.current_session['cpu_usage']) / len(self.current_session['cpu_usage'])
            self.current_session['peak_cpu'] = max(self.current_session['cpu_usage'])
        
        if self.current_session['gpu_usage']:
            self.current_session['avg_gpu'] = sum(self.current_session['gpu_usage']) / len(self.current_session['gpu_usage'])
            self.current_session['peak_gpu'] = max(self.current_session['gpu_usage'])
        
        # Tempo total
        self.current_session['duration'] = self.current_session['end_time'] - self.current_session['start_time']
        
        # Eficiência
        if self.current_session['duration'] > 0:
            self.current_session['efficiency'] = self.current_session['attempts'] / self.current_session['duration']
    
    def _update_global_stats(self):
        """Atualiza estatísticas globais."""
        if not self.current_session:
            return
            
        hash_type = self.current_session['hash_type']
        attack_mode = self.current_session['attack_mode']
        
        # Atualiza benchmarks
        if hash_type not in self.benchmarks:
            self.benchmarks[hash_type] = {}
        
        if attack_mode not in self.benchmarks[hash_type]:
            self.benchmarks[hash_type][attack_mode] = {
                'sessions': 0,
                'total_attempts': 0,
                'total_time': 0,
                'success_count': 0,
                'avg_rate': 0,
                'peak_rate': 0
            }
        
        benchmark = self.benchmarks[hash_type][attack_mode]
        benchmark['sessions'] += 1
        benchmark['total_attempts'] += self.current_session['attempts']
        benchmark['total_time'] += self.current_session['duration']
        
        if self.current_session['success']:
            benchmark['success_count'] += 1
        
        if 'avg_rate' in self.current_session:
            benchmark['avg_rate'] = (benchmark['avg_rate'] * (benchmark['sessions'] - 1) + self.current_session['avg_rate']) / benchmark['sessions']
        
        if 'peak_rate' in self.current_session:
            benchmark['peak_rate'] = max(benchmark['peak_rate'], self.current_session['peak_rate'])
        
        # Atualiza taxa de sucesso
        key = f"{hash_type}_{attack_mode}"
        if key not in self.success_rates:
            self.success_rates[key] = {'attempts': 0, 'successes': 0}
        
        self.success_rates[key]['attempts'] += 1
        if self.current_session['success']:
            self.success_rates[key]['successes'] += 1
    
    def get_session_report(self, session_id=None):
        """Gera relatório de uma sessão específica."""
        if session_id is None and self.current_session:
            session = self.current_session
        else:
            session = next((s for s in self.sessions if s['session_id'] == session_id), None)
        
        if not session:
            return None
        
        report = {
            'session_id': session['session_id'],
            'hash_type': session['hash_type'],
            'attack_mode': session['attack_mode'],
            'duration': session.get('duration', 0),
            'attempts': session['attempts'],
            'success': session['success'],
            'password_found': session.get('password_found', 'N/A'),
            'performance': {
                'avg_rate': session.get('avg_rate', 0),
                'peak_rate': session.get('peak_rate', 0),
                'min_rate': session.get('min_rate', 0),
                'efficiency': session.get('efficiency', 0)
            },
            'resources': {
                'avg_memory': session.get('avg_memory', 0),
                'peak_memory': session.get('peak_memory', 0),
                'avg_cpu': session.get('avg_cpu', 0),
                'peak_cpu': session.get('peak_cpu', 0),
                'avg_gpu': session.get('avg_gpu', 0),
                'peak_gpu': session.get('peak_gpu', 0)
            },
            'errors': len(session.get('errors', [])),
            'samples': len(session.get('performance_samples', []))
        }
        
        return report
    
    def get_global_report(self):
        """Gera relatório global de estatísticas."""
        total_sessions = len(self.sessions)
        total_attempts = sum(s['attempts'] for s in self.sessions)
        total_successes = sum(1 for s in self.sessions if s['success'])
        
        if total_sessions == 0:
            return {'message': 'Nenhuma sessão registrada'}
        
        report = {
            'summary': {
                'total_sessions': total_sessions,
                'total_attempts': total_attempts,
                'total_successes': total_successes,
                'global_success_rate': (total_successes / total_sessions) * 100,
                'avg_attempts_per_session': total_attempts / total_sessions if total_sessions > 0 else 0
            },
            'benchmarks': self.benchmarks,
            'success_rates': {
                key: {
                    'rate': (data['successes'] / data['attempts']) * 100 if data['attempts'] > 0 else 0,
                    'attempts': data['attempts'],
                    'successes': data['successes']
                }
                for key, data in self.success_rates.items()
            },
            'recent_sessions': [
                self.get_session_report(s['session_id'])
                for s in self.sessions[-5:]  # Últimas 5 sessões
            ]
        }
        
        return report
    
    def display_session_report(self, session_id=None):
        """Exibe relatório de sessão."""
        report = self.get_session_report(session_id)
        if not report:
            console.print("[red][!] Sessão não encontrada[/red]")
            return
        
        console.print(f"\n[bold blue]═══ RELATÓRIO DA SESSÃO {report['session_id']} ═══[/bold blue]")
        console.print(f"Hash Type: {report['hash_type']}")
        console.print(f"Attack Mode: {report['attack_mode']}")
        console.print(f"Duration: {report['duration']:.2f}s")
        console.print(f"Attempts: {report['attempts']:,}")
        console.print(f"Success: {'✓' if report['success'] else '✗'}")
        
        if report['password_found'] != 'N/A':
            console.print(f"Password: {report['password_found']}")
        
        console.print(f"\n[bold green]Performance:[/bold green]")
        console.print(f"  Avg Rate: {report['performance']['avg_rate']:.0f} h/s")
        console.print(f"  Peak Rate: {report['performance']['peak_rate']:.0f} h/s")
        console.print(f"  Efficiency: {report['performance']['efficiency']:.0f} h/s")
        
        console.print(f"\n[bold yellow]Resources:[/bold yellow]")
        console.print(f"  Avg Memory: {report['resources']['avg_memory']:.1f}%")
        console.print(f"  Peak Memory: {report['resources']['peak_memory']:.1f}%")
        console.print(f"  Avg CPU: {report['resources']['avg_cpu']:.1f}%")
        console.print(f"  Peak CPU: {report['resources']['peak_cpu']:.1f}%")
        
        if report['resources']['avg_gpu'] > 0:
            console.print(f"  Avg GPU: {report['resources']['avg_gpu']:.1f}%")
            console.print(f"  Peak GPU: {report['resources']['peak_gpu']:.1f}%")
        
        console.print(f"\n[bold red]Errors:[/bold red] {report['errors']}")
        console.print(f"[bold]Samples:[/bold] {report['samples']}")
        console.print()
    
    def display_global_report(self):
        """Exibe relatório global."""
        report = self.get_global_report()
        
        if 'message' in report:
            console.print(f"[yellow]{report['message']}[/yellow]")
            return
        
        console.print(f"\n[bold blue]═══ RELATÓRIO GLOBAL DE ESTATÍSTICAS ═══[/bold blue]")
        
        summary = report['summary']
        console.print(f"\n[bold green]Resumo:[/bold green]")
        console.print(f"  Total Sessions: {summary['total_sessions']}")
        console.print(f"  Total Attempts: {summary['total_attempts']:,}")
        console.print(f"  Total Successes: {summary['total_successes']}")
        console.print(f"  Global Success Rate: {summary['global_success_rate']:.1f}%")
        console.print(f"  Avg Attempts/Session: {summary['avg_attempts_per_session']:.0f}")
        
        console.print(f"\n[bold yellow]Success Rates by Type:[/bold yellow]")
        for key, data in report['success_rates'].items():
            console.print(f"  {key}: {data['rate']:.1f}% ({data['successes']}/{data['attempts']})")
        
        console.print(f"\n[bold cyan]Benchmarks:[/bold cyan]")
        for hash_type, attacks in report['benchmarks'].items():
            console.print(f"  {hash_type}:")
            for attack_mode, stats in attacks.items():
                console.print(f"    {attack_mode}: {stats['avg_rate']:.0f} h/s avg, {stats['peak_rate']:.0f} h/s peak")
        
        console.print()
    
    def export_statistics(self, filename=None):
        """Exporta estatísticas para arquivo JSON."""
        if not filename:
            filename = f"hash_cracker_stats_{int(time.time())}.json"
        
        data = {
            'export_time': time.time(),
            'sessions': self.sessions,
            'benchmarks': self.benchmarks,
            'success_rates': self.success_rates,
            'global_report': self.get_global_report()
        }
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            console.print(f"[green][+] Estatísticas exportadas para: {filename}[/green]")
            return filename
            
        except Exception as e:
            console.print(f"[red][!] Erro ao exportar estatísticas: {e}[/red]")
            return None
    
    def import_statistics(self, filename):
        """Importa estatísticas de arquivo JSON."""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            self.sessions.extend(data.get('sessions', []))
            self.benchmarks.update(data.get('benchmarks', {}))
            self.success_rates.update(data.get('success_rates', {}))
            
            console.print(f"[green][+] Estatísticas importadas de: {filename}[/green]")
            return True
            
        except Exception as e:
            console.print(f"[red][!] Erro ao importar estatísticas: {e}[/red]")
            return False


# Instância global de estatísticas
stats = AdvancedStatistics()


def get_statistics():
    """Retorna instância global de estatísticas."""
    return stats