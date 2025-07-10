# -*- coding: utf-8 -*-
"""
Sistema robusto de tratamento de exceções para o Spectra
"""

class SpectraException(Exception):
    """Exceção base para o Spectra."""
    def __init__(self, message: str, details: dict = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}

class NetworkError(SpectraException):
    """Erros relacionados à rede."""
    pass

class TimeoutError(NetworkError):
    """Timeout de requisição."""
    pass

class InvalidTargetError(SpectraException):
    """Alvo inválido ou malformado."""
    pass

class ScanError(SpectraException):
    """Erro durante operação de scan."""
    pass

class ConfigurationError(SpectraException):
    """Erro de configuração."""
    pass

class AuthenticationError(SpectraException):
    """Erro de autenticação."""
    pass

class RateLimitError(SpectraException):
    """Rate limit excedido."""
    pass

class WAFDetectedError(SpectraException):
    """WAF detectado bloqueando requisições."""
    pass

# Mapping de exceções comuns para exceções específicas do Spectra
EXCEPTION_MAPPING = {
    'requests.exceptions.Timeout': TimeoutError,
    'requests.exceptions.ConnectionError': NetworkError,
    'requests.exceptions.RequestException': NetworkError,
    'socket.timeout': TimeoutError,
    'socket.gaierror': NetworkError,
    'urllib.error.URLError': NetworkError,
}

def map_exception(original_exception: Exception, context: str = "") -> SpectraException:
    """
    Mapeia exceções padrão para exceções específicas do Spectra.
    
    Args:
        original_exception: Exceção original
        context: Contexto onde ocorreu o erro
        
    Returns:
        SpectraException apropriada
    """
    exception_name = f"{original_exception.__class__.__module__}.{original_exception.__class__.__name__}"
    
    spectra_exception_class = EXCEPTION_MAPPING.get(exception_name, SpectraException)
    
    details = {
        'original_exception': str(original_exception),
        'exception_type': exception_name,
        'context': context
    }
    
    return spectra_exception_class(
        f"{context}: {str(original_exception)}" if context else str(original_exception),
        details
    )
