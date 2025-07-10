# -*- coding: utf-8 -*-
"""
Core configuration for Spectra
"""

import os
import json
from pathlib import Path

class Config:
    """Classe de configuração centralizada para o Spectra."""
    
    def __init__(self):
        self.app_name = "Spectra"
        self.version = "3.2.6"
        self.cache_dir = ".spectra_cache"
        self.cve_cache_file = os.path.join(self.cache_dir, "cve_cache.json")
        self.cache_duration_hours = 24
        
        # Configurações de rede
        self.default_timeout = 10
        self.default_workers = 30
        self.default_retries = 3
        self.max_workers = 100
        
        # Configurações de scan
        self.default_ports = "80,443,22,21,25,53,110,143,993,995,3306,3389,5432"
        self.top_ports_count = 1000
        
        # Headers padrão
        self.default_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        # Configurações de logging
        self.log_level = "INFO"
        self.log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        
        # Cria diretório de cache se não existir
        self._ensure_cache_dir()
    
    def _ensure_cache_dir(self):
        """Garante que o diretório de cache existe."""
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir, exist_ok=True)
    
    def load_config(self, config_file=None):
        """Carrega configuração de arquivo JSON."""
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    config_data = json.load(f)
                    
                # Atualiza configurações
                for key, value in config_data.items():
                    if hasattr(self, key):
                        setattr(self, key, value)
                        
                return True
            except Exception as e:
                print(f"[!] Erro ao carregar configuração: {e}")
                return False
        return False
    
    def save_config(self, config_file):
        """Salva configuração atual em arquivo JSON."""
        try:
            config_data = {
                'default_timeout': self.default_timeout,
                'default_workers': self.default_workers,
                'default_retries': self.default_retries,
                'cache_duration_hours': self.cache_duration_hours,
                'log_level': self.log_level
            }
            
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, indent=2, ensure_ascii=False)
                
            return True
        except Exception as e:
            print(f"[!] Erro ao salvar configuração: {e}")
            return False

# Instância global de configuração
config = Config()
