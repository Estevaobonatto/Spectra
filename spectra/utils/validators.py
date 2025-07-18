# -*- coding: utf-8 -*-
"""
Validation utilities for Spectra
"""

import re
import socket
from urllib.parse import urlparse

def validate_url(url):
    """Valida se uma URL é válida."""
    if not url:
        return False, "URL vazia"
    
    try:
        # Adiciona esquema se não existir
        if not re.match(r'^https?://', url):
            url = 'http://' + url
        
        parsed = urlparse(url)
        
        if not parsed.netloc:
            return False, "Domínio inválido"
        
        # Verifica se o domínio é válido
        domain = parsed.netloc.split(':')[0]  # Remove porta se existir
        if not validate_domain(domain):
            return False, f"Domínio inválido: {domain}"
        
        return True, url
    except Exception as e:
        return False, f"Erro ao validar URL: {e}"

def validate_domain(domain):
    """Valida se um domínio é válido."""
    if not domain:
        return False
    
    # Regex para validar domínio
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
    
    return bool(domain_pattern.match(domain))

def validate_ip(ip):
    """Valida se um IP é válido."""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def validate_port(port):
    """Valida se uma porta é válida."""
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except:
        return False

def validate_email(email):
    """Valida se um email é válido."""
    email_pattern = re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    )
    return bool(email_pattern.match(email))

def validate_file_path(file_path):
    """Valida se um caminho de arquivo existe."""
    import os
    return os.path.exists(file_path)

def validate_wordlist(wordlist_path):
    """Valida se uma wordlist existe e não está vazia."""
    import os
    
    if not os.path.exists(wordlist_path):
        return False, f"Arquivo não encontrado: {wordlist_path}"
    
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            if not lines:
                return False, "Wordlist está vazia"
            return True, f"Wordlist válida com {len(lines)} entradas"
    except Exception as e:
        return False, f"Erro ao ler wordlist: {e}"

def validate_timeout(timeout):
    """Valida timeout."""
    try:
        timeout_val = float(timeout)
        if timeout_val <= 0:
            return False, "Timeout deve ser maior que 0"
        if timeout_val > 300:  # 5 minutos
            return False, "Timeout muito alto (máximo 300 segundos)"
        return True, timeout_val
    except:
        return False, "Timeout deve ser um número"

def validate_workers(workers):
    """Valida número de workers."""
    try:
        workers_val = int(workers)
        if workers_val <= 0:
            return False, "Número de workers deve ser maior que 0"
        if workers_val > 200:  # Limite razoável
            return False, "Número de workers muito alto (máximo 200)"
        return True, workers_val
    except:
        return False, "Número de workers deve ser um inteiro"

def sanitize_filename(filename):
    """Sanitiza nome de arquivo."""
    # Remove caracteres perigosos
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Remove espaços extras
    filename = re.sub(r'\s+', '_', filename)
    # Remove pontos no início/fim
    filename = filename.strip('.')
    return filename

def sanitize_input(user_input, max_length=1000):
    """Sanitiza entrada do usuário."""
    if not user_input:
        return ""
    
    # Trunca se muito longo
    if len(user_input) > max_length:
        user_input = user_input[:max_length]
    
    # Remove caracteres de controle
    user_input = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', user_input)
    
    return user_input.strip()

def validate_range(value, min_val, max_val, value_name="valor"):
    """Valida se um valor está dentro de um range."""
    try:
        num_val = float(value)
        if num_val < min_val or num_val > max_val:
            return False, f"{value_name} deve estar entre {min_val} e {max_val}"
        return True, num_val
    except:
        return False, f"{value_name} deve ser um número"
