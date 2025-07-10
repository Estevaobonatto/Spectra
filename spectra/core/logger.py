# -*- coding: utf-8 -*-
"""
Logging system for Spectra
"""

import logging
import os
from datetime import datetime
from .config import config

class SpectraLogger:
    """Sistema de logging customizado para o Spectra."""
    
    def __init__(self, name="spectra", log_file=None):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, config.log_level))
        
        # Remove handlers existentes para evitar duplicação
        self.logger.handlers.clear()
        
        # Formatter
        formatter = logging.Formatter(config.log_format)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # File handler (se especificado)
        if log_file:
            self._setup_file_handler(log_file, formatter)
    
    def _setup_file_handler(self, log_file, formatter):
        """Configura o handler de arquivo."""
        try:
            # Cria diretório de logs se não existir
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)
            
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
        except Exception as e:
            self.logger.warning(f"Não foi possível configurar log de arquivo: {e}")
    
    def debug(self, message):
        """Log de debug."""
        self.logger.debug(message)
    
    def info(self, message):
        """Log de informação."""
        self.logger.info(message)
    
    def warning(self, message):
        """Log de aviso."""
        self.logger.warning(message)
    
    def error(self, message):
        """Log de erro."""
        self.logger.error(message)
    
    def critical(self, message):
        """Log crítico."""
        self.logger.critical(message)
    
    def scan_start(self, scan_type, target):
        """Log de início de scan."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.info(f"[SCAN_START] {scan_type} scan iniciado em {target} - {timestamp}")
    
    def scan_end(self, scan_type, target, results_count):
        """Log de fim de scan."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.info(f"[SCAN_END] {scan_type} scan finalizado em {target} - {results_count} resultados - {timestamp}")
    
    def vulnerability_found(self, vuln_type, target, severity="Unknown"):
        """Log de vulnerabilidade encontrada."""
        self.warning(f"[VULNERABILITY] {vuln_type} encontrada em {target} - Severidade: {severity}")
    
    def error_occurred(self, operation, error_msg):
        """Log de erro durante operação."""
        self.error(f"[ERROR] {operation}: {error_msg}")

# Logger global
logger = SpectraLogger()
