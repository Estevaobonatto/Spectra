# -*- coding: utf-8 -*-
"""
Módulo de Análise de Cabeçalhos HTTP
Analisa cabeçalhos de resposta HTTP e configurações de segurança
"""

import json
import re
from typing import Dict, List, Optional, Union
from urllib.parse import urlparse, parse_qs
import requests
from ..core.console import console
from ..core.logger import get_logger
from ..utils.network import create_session

logger = get_logger(__name__)

class AdvancedHeadersAnalyzer:
    """Analisador avançado de cabeçalhos HTTP com verificações de segurança."""
    
    def __init__(self, url: str, timeout: int = 10, follow_redirects: bool = True):
        self.url = url if url.startswith('http') else f'http://{url}'
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.session = create_session()
        
        self.headers_info = {}
        self.security_analysis = {}
        self.recommendations = []
        self.csp_analysis = {}
        self.cookie_analysis = {}
        self.redirect_analysis = {}
        
        logger.info(f"Headers Analyzer inicializado para {self.url}")
        
        # Inicializa database de cabeçalhos
        self._init_headers_database()
        self._init_advanced_databases()
    
    def _init_headers_database(self):
        """Inicializa a base de dados de cabeçalhos de segurança."""
        self.security_headers = {
            # Cabeçalhos de Segurança Críticos
            "Strict-Transport-Security": {
                "description": "Força o uso de HTTPS, protegendo contra ataques de downgrade e man-in-the-middle",
                "risk_level": "HIGH",
                "recommendation": "Adicione: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                "category": "Transport Security"
            },
            "Content-Security-Policy": {
                "description": "Previne ataques XSS, clickjacking e code injection",
                "risk_level": "HIGH",
                "recommendation": "Implemente uma CSP restritiva baseada nas necessidades da aplicação",
                "category": "Content Security"
            },
            "X-Frame-Options": {
                "description": "Protege contra ataques de clickjacking",
                "risk_level": "MEDIUM",
                "recommendation": "Adicione: X-Frame-Options: DENY ou SAMEORIGIN",
                "category": "Clickjacking Protection"
            },
            "X-Content-Type-Options": {
                "description": "Previne ataques de MIME sniffing",
                "risk_level": "MEDIUM",
                "recommendation": "Adicione: X-Content-Type-Options: nosniff",
                "category": "MIME Protection"
            },
            "Referrer-Policy": {
                "description": "Controla quanta informação de referência é enviada",
                "risk_level": "LOW",
                "recommendation": "Adicione: Referrer-Policy: strict-origin-when-cross-origin",
                "category": "Privacy"
            },
            "Permissions-Policy": {
                "description": "Controla quais recursos do navegador a página pode usar",
                "risk_level": "LOW",
                "recommendation": "Configure políticas apropriadas para recursos não utilizados",
                "category": "Feature Control"
            },
            "X-XSS-Protection": {
                "description": "Ativa proteção XSS do navegador (deprecated mas ainda útil)",
                "risk_level": "LOW",
                "recommendation": "Adicione: X-XSS-Protection: 1; mode=block",
                "category": "XSS Protection"
            },
            "Cross-Origin-Embedder-Policy": {
                "description": "Controla como recursos são incorporados cross-origin",
                "risk_level": "LOW",
                "recommendation": "Configure baseado nos requisitos da aplicação",
                "category": "Cross-Origin Security"
            },
            "Cross-Origin-Opener-Policy": {
                "description": "Controla acesso cross-origin a janelas abertas",
                "risk_level": "LOW",
                "recommendation": "Adicione: Cross-Origin-Opener-Policy: same-origin",
                "category": "Cross-Origin Security"
            },
            "Cross-Origin-Resource-Policy": {
                "description": "Controla quais origens podem carregar recursos",
                "risk_level": "LOW",
                "recommendation": "Configure apropriadamente para recursos públicos/privados",
                "category": "Cross-Origin Security"
            }
        }
        
        # Cabeçalhos que podem revelar informações
        self.disclosure_headers = {
            "Server": {
                "description": "Revela informações sobre o servidor web",
                "risk_level": "INFO",
                "recommendation": "Configure o servidor para não revelar versões específicas"
            },
            "X-Powered-By": {
                "description": "Revela tecnologia backend utilizada",
                "risk_level": "INFO",
                "recommendation": "Remova ou configure para não revelar informações específicas"
            },
            "X-AspNet-Version": {
                "description": "Revela versão do ASP.NET",
                "risk_level": "INFO",
                "recommendation": "Desabilite através da configuração do ASP.NET"
            },
            "X-AspNetMvc-Version": {
                "description": "Revela versão do ASP.NET MVC",
                "risk_level": "INFO",
                "recommendation": "Desabilite através da configuração do MVC"
            },
            "X-Generator": {
                "description": "Revela ferramenta geradora do conteúdo",
                "risk_level": "INFO",
                "recommendation": "Remova ou mascare informações de versão"
            },
            "X-Drupal-Cache": {
                "description": "Revela uso do CMS Drupal",
                "risk_level": "INFO",
                "recommendation": "Configure Drupal para não expor cabeçalhos desnecessários"
            }
        }
        
        # Cabeçalhos relacionados a cache e performance
        self.cache_headers = [
            "Cache-Control", "Expires", "ETag", "Last-Modified",
            "Pragma", "Vary", "Age"
        ]
        
        # Cabeçalhos relacionados a CORS
        self.cors_headers = [
            "Access-Control-Allow-Origin", "Access-Control-Allow-Methods",
            "Access-Control-Allow-Headers", "Access-Control-Expose-Headers",
            "Access-Control-Max-Age", "Access-Control-Allow-Credentials"
        ]
    
    def _init_advanced_databases(self):
        """Inicializa bases de dados avançadas para análises específicas."""
        
        # CSP Directives e suas configurações seguras
        self.csp_directives = {
            'default-src': {
                'description': 'Política padrão para carregamento de recursos',
                'secure_values': ["'none'", "'self'"],
                'insecure_patterns': ['*', 'data:', 'unsafe-inline', 'unsafe-eval']
            },
            'script-src': {
                'description': 'Política para scripts JavaScript',
                'secure_values': ["'self'", "'none'"],
                'insecure_patterns': ['*', 'unsafe-inline', 'unsafe-eval']
            },
            'object-src': {
                'description': 'Política para plugins (flash, java)',
                'secure_values': ["'none'"],
                'insecure_patterns': ['*', 'data:']
            },
            'style-src': {
                'description': 'Política para folhas de estilo CSS',
                'secure_values': ["'self'", "'none'"],
                'insecure_patterns': ['*', 'unsafe-inline']
            },
            'img-src': {
                'description': 'Política para carregamento de imagens',
                'secure_values': ["'self'", 'data:'],
                'insecure_patterns': ['*']
            },
            'frame-src': {
                'description': 'Política para frames e iframes',
                'secure_values': ["'none'", "'self'"],
                'insecure_patterns': ['*']
            },
            'frame-ancestors': {
                'description': 'Controla quem pode incorporar a página em frames',
                'secure_values': ["'none'", "'self'"],
                'insecure_patterns': ['*']
            }
        }
        
        # Padrões de cookies seguros
        self.cookie_security_attributes = {
            'Secure': {
                'description': 'Cookie só enviado via HTTPS',
                'required_for_https': True
            },
            'HttpOnly': {
                'description': 'Cookie inacessível via JavaScript',
                'recommended': True
            },
            'SameSite': {
                'description': 'Proteção contra CSRF',
                'secure_values': ['Strict', 'Lax'],
                'insecure_values': ['None']
            }
        }
        
        # Cabeçalhos suspeitos ou customizados
        self.suspicious_headers = [
            'X-Debug', 'X-Debug-Token', 'X-Forwarded-For', 'X-Real-IP',
            'X-Original-URL', 'X-Rewrite-URL', 'X-Admin', 'X-Test'
        ]
        
        # Políticas de Feature/Permissions
        self.permissions_policy_features = [
            'camera', 'microphone', 'geolocation', 'payment', 'usb',
            'accelerometer', 'gyroscope', 'magnetometer', 'fullscreen'
        ]
    
    def _analyze_csp_advanced(self, csp_header_value):
        """Análise avançada de Content Security Policy."""
        if not csp_header_value:
            return {
                'score': 0,
                'findings': [],
                'directives': {},
                'analysis': 'CSP não configurado'
            }
        
        findings = []
        directives = {}
        score = 100
        
        # Parse das diretivas CSP
        csp_parts = [part.strip() for part in csp_header_value.split(';') if part.strip()]
        
        for part in csp_parts:
            if ' ' in part:
                directive, *values = part.split()
                directives[directive] = values
            else:
                directives[part] = []
        
        # Análise de cada diretiva
        for directive, values in directives.items():
            if directive in self.csp_directives:
                directive_info = self.csp_directives[directive]
                
                # Verifica padrões inseguros
                for value in values:
                    for insecure_pattern in directive_info['insecure_patterns']:
                        if insecure_pattern in value:
                            severity = 'HIGH' if insecure_pattern in ['*', 'unsafe-eval'] else 'MEDIUM'
                            findings.append({
                                'type': 'INSECURE_CSP_DIRECTIVE',
                                'severity': severity,
                                'directive': directive,
                                'value': value,
                                'description': f"Diretiva {directive} usa valor inseguro: {value}",
                                'recommendation': f"Evite usar {value} em {directive}. {directive_info['description']}"
                            })
                            
                            score -= 20 if severity == 'HIGH' else 10
        
        # Verifica diretivas importantes ausentes
        critical_directives = ['default-src', 'script-src', 'object-src']
        for critical_dir in critical_directives:
            if critical_dir not in directives:
                findings.append({
                    'type': 'MISSING_CSP_DIRECTIVE',
                    'severity': 'MEDIUM',
                    'directive': critical_dir,
                    'description': f"Diretiva crítica {critical_dir} não configurada",
                    'recommendation': f"Configure {critical_dir} para melhor segurança"
                })
                score -= 15
        
        self.csp_analysis = {
            'score': max(0, score),
            'findings': findings,
            'directives': directives,
            'analysis': 'CSP configurado' if directives else 'CSP não configurado'
        }
        
        return self.csp_analysis
    
    def _analyze_cookies_security(self, response):
        """Analisa segurança dos cookies."""
        cookies_findings = []
        cookies_info = {}
        
        # Obtém cookies da resposta
        set_cookies = response.headers.get_list('Set-Cookie') if hasattr(response.headers, 'get_list') else []
        if not set_cookies and 'Set-Cookie' in response.headers:
            set_cookies = [response.headers['Set-Cookie']]
        
        for cookie_header in set_cookies:
            cookie_analysis = self._parse_cookie_header(cookie_header)
            cookie_name = cookie_analysis.get('name', 'unknown')
            cookies_info[cookie_name] = cookie_analysis
            
            # Verifica se é HTTPS mas cookie não tem Secure
            if self.url.startswith('https://') and not cookie_analysis.get('secure', False):
                cookies_findings.append({
                    'type': 'INSECURE_COOKIE',
                    'severity': 'MEDIUM',
                    'cookie': cookie_name,
                    'description': f"Cookie {cookie_name} enviado via HTTPS sem atributo Secure",
                    'recommendation': "Adicione atributo Secure a cookies em conexões HTTPS"
                })
            
            # Verifica HttpOnly
            if not cookie_analysis.get('httponly', False):
                cookies_findings.append({
                    'type': 'MISSING_HTTPONLY',
                    'severity': 'LOW',
                    'cookie': cookie_name,
                    'description': f"Cookie {cookie_name} sem atributo HttpOnly",
                    'recommendation': "Adicione HttpOnly para proteger contra XSS"
                })
            
            # Verifica SameSite
            samesite = cookie_analysis.get('samesite')
            if not samesite:
                cookies_findings.append({
                    'type': 'MISSING_SAMESITE',
                    'severity': 'LOW',
                    'cookie': cookie_name,
                    'description': f"Cookie {cookie_name} sem atributo SameSite",
                    'recommendation': "Configure SameSite para proteção contra CSRF"
                })
            elif samesite.lower() == 'none' and not cookie_analysis.get('secure', False):
                cookies_findings.append({
                    'type': 'INSECURE_SAMESITE',
                    'severity': 'MEDIUM',
                    'cookie': cookie_name,
                    'description': f"Cookie {cookie_name} usa SameSite=None sem Secure",
                    'recommendation': "SameSite=None requer atributo Secure"
                })
        
        self.cookie_analysis = {
            'cookies': cookies_info,
            'findings': cookies_findings,
            'total_cookies': len(cookies_info)
        }
        
        return self.cookie_analysis
    
    def _parse_cookie_header(self, cookie_header):
        """Parse de um cabeçalho Set-Cookie."""
        parts = [part.strip() for part in cookie_header.split(';')]
        
        # Primeiro part é nome=valor
        if '=' in parts[0]:
            name, value = parts[0].split('=', 1)
        else:
            name, value = parts[0], ''
        
        cookie_info = {
            'name': name,
            'value': value,
            'secure': False,
            'httponly': False,
            'samesite': None,
            'domain': None,
            'path': None,
            'expires': None,
            'max_age': None
        }
        
        # Parse dos atributos
        for part in parts[1:]:
            part_lower = part.lower()
            
            if part_lower == 'secure':
                cookie_info['secure'] = True
            elif part_lower == 'httponly':
                cookie_info['httponly'] = True
            elif part_lower.startswith('samesite='):
                cookie_info['samesite'] = part.split('=', 1)[1]
            elif part_lower.startswith('domain='):
                cookie_info['domain'] = part.split('=', 1)[1]
            elif part_lower.startswith('path='):
                cookie_info['path'] = part.split('=', 1)[1]
            elif part_lower.startswith('expires='):
                cookie_info['expires'] = part.split('=', 1)[1]
            elif part_lower.startswith('max-age='):
                cookie_info['max_age'] = part.split('=', 1)[1]
        
        return cookie_info
    
    def _analyze_redirect_security(self, response):
        """Analisa segurança dos redirecionamentos."""
        redirect_findings = []
        redirect_info = {
            'total_redirects': len(response.history),
            'redirect_chain': [],
            'final_url': response.url,
            'https_enforced': False,
            'open_redirect_risk': False
        }
        
        # Analisa cadeia de redirecionamentos
        for i, redirect_response in enumerate(response.history):
            redirect_info['redirect_chain'].append({
                'step': i + 1,
                'from_url': redirect_response.url,
                'to_url': redirect_response.headers.get('Location', ''),
                'status_code': redirect_response.status_code,
                'is_https': redirect_response.url.startswith('https://')
            })
        
        # Verifica se há enforcing de HTTPS
        for redirect in redirect_info['redirect_chain']:
            if (redirect['from_url'].startswith('http://') and 
                redirect['to_url'].startswith('https://')):
                redirect_info['https_enforced'] = True
                break
        
        # Verifica risco de open redirect
        for redirect in redirect_info['redirect_chain']:
            location = redirect['to_url']
            if location:
                parsed_location = urlparse(location)
                original_domain = urlparse(self.url).netloc
                
                if parsed_location.netloc and parsed_location.netloc != original_domain:
                    redirect_info['open_redirect_risk'] = True
                    redirect_findings.append({
                        'type': 'POTENTIAL_OPEN_REDIRECT',
                        'severity': 'MEDIUM',
                        'description': f"Redirecionamento para domínio externo: {parsed_location.netloc}",
                        'recommendation': "Valide destinos de redirecionamento para evitar open redirects"
                    })
        
        # Verifica se site HTTP não redireciona para HTTPS
        if (self.url.startswith('http://') and 
            not redirect_info['https_enforced'] and 
            not response.url.startswith('https://')):
            redirect_findings.append({
                'type': 'NO_HTTPS_REDIRECT',
                'severity': 'HIGH',
                'description': "Site HTTP não redireciona para HTTPS",
                'recommendation': "Configure redirecionamento automático para HTTPS"
            })
        
        self.redirect_analysis = {
            'info': redirect_info,
            'findings': redirect_findings
        }
        
        return self.redirect_analysis
    
    def _detect_suspicious_headers(self, headers):
        """Detecta cabeçalhos suspeitos ou que revelam informações."""
        suspicious_findings = []
        
        for header_name, header_value in headers.items():
            # Verifica cabeçalhos na lista de suspeitos
            if header_name in self.suspicious_headers:
                suspicious_findings.append({
                    'type': 'SUSPICIOUS_HEADER',
                    'severity': 'INFO',
                    'header': header_name,
                    'value': header_value,
                    'description': f"Cabeçalho suspeito detectado: {header_name}",
                    'recommendation': "Verifique se este cabeçalho é necessário em produção"
                })
            
            # Verifica cabeçalhos customizados que podem revelar informações
            if header_name.startswith('X-') and header_name not in self.security_headers:
                suspicious_findings.append({
                    'type': 'CUSTOM_HEADER',
                    'severity': 'INFO',
                    'header': header_name,
                    'value': header_value,
                    'description': f"Cabeçalho customizado detectado: {header_name}",
                    'recommendation': "Avalie se informações sensíveis estão sendo expostas"
                })
        
        return suspicious_findings
    
    def _analyze_response(self, response):
        """Analisa a resposta HTTP e seus cabeçalhos."""
        headers = dict(response.headers)
        
        self.headers_info = {
            'url': response.url,
            'status_code': response.status_code,
            'status_text': response.reason,
            'headers': headers,
            'redirect_history': [resp.url for resp in response.history],
            'final_url': response.url,
            'content_type': headers.get('Content-Type', 'Unknown'),
            'content_length': headers.get('Content-Length', 'Unknown'),
            'server': headers.get('Server', 'Unknown')
        }
        
        return self.headers_info
    
    def _analyze_security_headers(self):
        """Analisa cabeçalhos de segurança."""
        headers = self.headers_info.get('headers', {})
        security_findings = []
        security_score = 100
        
        # Verifica cabeçalhos de segurança ausentes
        for header_name, header_info in self.security_headers.items():
            if header_name not in headers:
                finding = {
                    'type': 'MISSING_SECURITY_HEADER',
                    'severity': header_info['risk_level'],
                    'header': header_name,
                    'description': header_info['description'],
                    'recommendation': header_info['recommendation'],
                    'category': header_info['category']
                }
                security_findings.append(finding)
                
                # Deduz pontos baseado na severidade
                if header_info['risk_level'] == 'HIGH':
                    security_score -= 20
                elif header_info['risk_level'] == 'MEDIUM':
                    security_score -= 10
                elif header_info['risk_level'] == 'LOW':
                    security_score -= 5
            else:
                # Analisa valor do cabeçalho presente
                header_value = headers[header_name]
                analysis = self._analyze_security_header_value(header_name, header_value)
                if analysis:
                    security_findings.extend(analysis)
        
        # Verifica cabeçalhos que revelam informações
        for header_name, header_info in self.disclosure_headers.items():
            if header_name in headers:
                finding = {
                    'type': 'INFORMATION_DISCLOSURE',
                    'severity': header_info['risk_level'],
                    'header': header_name,
                    'value': headers[header_name],
                    'description': header_info['description'],
                    'recommendation': header_info['recommendation']
                }
                security_findings.append(finding)
        
        return {
            'security_score': max(0, security_score),
            'findings': security_findings
        }
    
    def _analyze_security_header_value(self, header_name, header_value):
        """Analisa o valor de um cabeçalho de segurança específico."""
        findings = []
        
        if header_name == "Content-Security-Policy":
            if "unsafe-inline" in header_value:
                findings.append({
                    'type': 'WEAK_CSP',
                    'severity': 'MEDIUM',
                    'header': header_name,
                    'description': "CSP permite 'unsafe-inline', reduzindo proteção contra XSS",
                    'recommendation': "Remova 'unsafe-inline' e use nonces ou hashes"
                })
            
            if "unsafe-eval" in header_value:
                findings.append({
                    'type': 'WEAK_CSP',
                    'severity': 'MEDIUM',
                    'header': header_name,
                    'description': "CSP permite 'unsafe-eval', permitindo execução de código dinâmico",
                    'recommendation': "Remova 'unsafe-eval' para melhor segurança"
                })
            
            if "*" in header_value and "default-src" in header_value:
                findings.append({
                    'type': 'WEAK_CSP',
                    'severity': 'HIGH',
                    'header': header_name,
                    'description': "CSP usa wildcard (*) em default-src, oferecendo pouca proteção",
                    'recommendation': "Use origens específicas ao invés de wildcard"
                })
        
        elif header_name == "Strict-Transport-Security":
            if "max-age" not in header_value:
                findings.append({
                    'type': 'WEAK_HSTS',
                    'severity': 'MEDIUM',
                    'header': header_name,
                    'description': "HSTS sem max-age definido",
                    'recommendation': "Adicione diretiva max-age com valor apropriado"
                })
            else:
                # Extrai max-age
                max_age_match = re.search(r'max-age=(\d+)', header_value)
                if max_age_match:
                    max_age = int(max_age_match.group(1))
                    if max_age < 31536000:  # 1 ano
                        findings.append({
                            'type': 'WEAK_HSTS',
                            'severity': 'LOW',
                            'header': header_name,
                            'description': f"HSTS max-age muito baixo ({max_age} segundos)",
                            'recommendation': "Use max-age de pelo menos 31536000 (1 ano)"
                        })
            
            if "includeSubDomains" not in header_value:
                findings.append({
                    'type': 'WEAK_HSTS',
                    'severity': 'LOW',
                    'header': header_name,
                    'description': "HSTS não inclui subdomínios",
                    'recommendation': "Adicione 'includeSubDomains' para proteger subdomínios"
                })
        
        elif header_name == "X-Frame-Options":
            if header_value.upper() not in ["DENY", "SAMEORIGIN"]:
                findings.append({
                    'type': 'WEAK_X_FRAME_OPTIONS',
                    'severity': 'MEDIUM',
                    'header': header_name,
                    'description': f"X-Frame-Options com valor inseguro: {header_value}",
                    'recommendation': "Use 'DENY' ou 'SAMEORIGIN'"
                })
        
        return findings
    
    def _analyze_cors_configuration(self):
        """Analisa configuração CORS."""
        headers = self.headers_info.get('headers', {})
        cors_findings = []
        
        # Verifica Access-Control-Allow-Origin
        allow_origin = headers.get('Access-Control-Allow-Origin')
        if allow_origin:
            if allow_origin == "*":
                cors_findings.append({
                    'type': 'PERMISSIVE_CORS',
                    'severity': 'MEDIUM',
                    'description': "CORS permite qualquer origem (*)",
                    'recommendation': "Especifique origens confiáveis ao invés de usar wildcard"
                })
            
            # Verifica se permite credentials com wildcard
            allow_credentials = headers.get('Access-Control-Allow-Credentials')
            if allow_credentials and allow_credentials.lower() == 'true' and allow_origin == "*":
                cors_findings.append({
                    'type': 'DANGEROUS_CORS',
                    'severity': 'HIGH',
                    'description': "CORS permite credentials com wildcard origin",
                    'recommendation': "Nunca use wildcard com credentials habilitados"
                })
        
        # Verifica métodos permitidos
        allow_methods = headers.get('Access-Control-Allow-Methods')
        if allow_methods:
            dangerous_methods = ['DELETE', 'PUT', 'PATCH']
            for method in dangerous_methods:
                if method in allow_methods.upper():
                    cors_findings.append({
                        'type': 'PERMISSIVE_CORS_METHODS',
                        'severity': 'LOW',
                        'description': f"CORS permite método potencialmente perigoso: {method}",
                        'recommendation': "Permita apenas métodos necessários"
                    })
        
        return cors_findings
    
    def _analyze_cache_configuration(self):
        """Analisa configuração de cache."""
        headers = self.headers_info.get('headers', {})
        cache_findings = []
        
        cache_control = headers.get('Cache-Control')
        if cache_control:
            if 'no-store' not in cache_control.lower() and 'private' not in cache_control.lower():
                # Verifica se é conteúdo sensível (heurística básica)
                content_type = headers.get('Content-Type', '').lower()
                if any(sensitive in content_type for sensitive in ['json', 'xml']):
                    cache_findings.append({
                        'type': 'CACHE_SENSITIVE_CONTENT',
                        'severity': 'LOW',
                        'description': "Conteúdo potencialmente sensível pode ser cacheado",
                        'recommendation': "Use 'no-store' ou 'private' para conteúdo sensível"
                    })
        
        return cache_findings
    
    def analyze_headers(self, verbose=False, include_advanced=True):
        """Executa análise completa dos cabeçalhos."""
        try:
            console.print("[cyan]Iniciando análise de cabeçalhos HTTP...[/cyan]")
            
            # Faz requisição
            response = self.session.get(
                self.url, 
                timeout=self.timeout, 
                allow_redirects=self.follow_redirects,
                verify=False
            )
            
            # Analisa resposta
            self._analyze_response(response)
            
            # Análise de segurança básica
            security_analysis = self._analyze_security_headers()
            
            # Análise CORS
            cors_findings = self._analyze_cors_configuration()
            
            # Análise de cache
            cache_findings = self._analyze_cache_configuration()
            
            # Análises avançadas
            csp_findings = []
            cookie_findings = []
            redirect_findings = []
            suspicious_findings = []
            
            if include_advanced:
                console.print("[cyan]Executando análises avançadas...[/cyan]")
                
                # Análise avançada de CSP
                csp_header = self.headers_info['headers'].get('Content-Security-Policy', '')
                csp_analysis = self._analyze_csp_advanced(csp_header)
                csp_findings = csp_analysis['findings']
                
                # Análise de cookies seguros
                cookie_analysis = self._analyze_cookies_security(response)
                cookie_findings = cookie_analysis['findings']
                
                # Análise de redirecionamentos
                redirect_analysis = self._analyze_redirect_security(response)
                redirect_findings = redirect_analysis['findings']
                
                # Detecção de cabeçalhos suspeitos
                suspicious_findings = self._detect_suspicious_headers(self.headers_info['headers'])
            
            # Combina todos os findings
            all_findings = (security_analysis['findings'] + cors_findings + cache_findings + 
                          csp_findings + cookie_findings + redirect_findings + suspicious_findings)
            
            # Recalcula pontuação considerando novas análises
            final_score = security_analysis['security_score']
            if include_advanced and hasattr(self, 'csp_analysis'):
                # Ajusta pontuação baseado na análise CSP
                csp_score = self.csp_analysis.get('score', 100)
                final_score = (final_score + csp_score) // 2
            
            self.security_analysis = {
                'security_score': final_score,
                'total_findings': len(all_findings),
                'findings_by_severity': {
                    'HIGH': len([f for f in all_findings if f.get('severity') == 'HIGH']),
                    'MEDIUM': len([f for f in all_findings if f.get('severity') == 'MEDIUM']),
                    'LOW': len([f for f in all_findings if f.get('severity') == 'LOW']),
                    'INFO': len([f for f in all_findings if f.get('severity') == 'INFO'])
                },
                'findings': all_findings,
                'categories': {
                    'security_headers': len(security_analysis['findings']),
                    'cors': len(cors_findings),
                    'cache': len(cache_findings),
                    'csp': len(csp_findings),
                    'cookies': len(cookie_findings),
                    'redirects': len(redirect_findings),
                    'suspicious': len(suspicious_findings)
                }
            }
            
            if verbose:
                console.print(f"[*] Analisados {len(self.headers_info['headers'])} cabeçalhos")
                console.print(f"[*] Encontrados {len(all_findings)} problemas de segurança")
                if include_advanced:
                    console.print(f"[*] Análises avançadas: CSP, Cookies, Redirects, Headers Suspeitos")
            
            logger.info(f"Análise de cabeçalhos concluída para {self.url}")
            
            return {
                'headers_info': self.headers_info,
                'security_analysis': self.security_analysis,
                'csp_analysis': getattr(self, 'csp_analysis', {}),
                'cookie_analysis': getattr(self, 'cookie_analysis', {}),
                'redirect_analysis': getattr(self, 'redirect_analysis', {})
            }
            
        except requests.RequestException as e:
            logger.error(f"Erro ao analisar cabeçalhos: {e}")
            console.print(f"[bold red][!] Erro ao conectar com {self.url}: {e}[/bold red]")
            return None
    
    def present_results(self, output_format='table'):
        """Apresenta os resultados da análise."""
        if output_format == 'table':
            console.print(f"\n[bold cyan]📋 ANÁLISE DE CABEÇALHOS HTTP - {self.url}[/bold cyan]")
            console.print("-" * 60)
            
            if not self.headers_info:
                console.print("[bold red]❌ Nenhuma informação de cabeçalhos disponível[/bold red]")
                return
            
            # Informações básicas
            console.print(f"URL Final: [bold cyan]{self.headers_info['final_url']}[/bold cyan]")
            console.print(f"Status: [bold {'green' if self.headers_info['status_code'] < 400 else 'red'}]{self.headers_info['status_code']} {self.headers_info['status_text']}[/bold {'green' if self.headers_info['status_code'] < 400 else 'red'}]")
            console.print(f"Content-Type: {self.headers_info['content_type']}")
            console.print(f"Server: {self.headers_info['server']}")
            
            # Redirecionamentos
            if self.headers_info['redirect_history']:
                console.print(f"Redirecionamentos: {len(self.headers_info['redirect_history'])}")
            
            # Tabela de cabeçalhos
            from rich.table import Table
            
            headers_table = Table(title="Cabeçalhos HTTP")
            headers_table.add_column("Cabeçalho", style="cyan")
            headers_table.add_column("Valor", style="white")
            
            # Destaca cabeçalhos de informação
            disclosure_headers = [h.lower() for h in self.disclosure_headers.keys()]
            
            for header, value in self.headers_info['headers'].items():
                if header.lower() in disclosure_headers:
                    headers_table.add_row(f"[yellow]{header}[/yellow]", f"[yellow]{value}[/yellow]")
                else:
                    headers_table.add_row(header, value)
            
            console.print(headers_table)
            
            # Análise de segurança
            if self.security_analysis:
                console.print(f"\n[bold cyan]🛡️  ANÁLISE DE SEGURANÇA[/bold cyan]")
                console.print("-" * 60)
                
                security_score = self.security_analysis['security_score']
                if security_score >= 80:
                    score_color = "green"
                    score_icon = "✅"
                elif security_score >= 60:
                    score_color = "yellow"
                    score_icon = "⚠️ "
                else:
                    score_color = "red"
                    score_icon = "❌"
                
                console.print(f"Pontuação de Segurança: [{score_color}]{score_icon} {security_score}/100[/{score_color}]")
                
                # Resumo por severidade
                findings_by_severity = self.security_analysis['findings_by_severity']
                console.print(f"Total de Problemas: {self.security_analysis['total_findings']}")
                console.print(f"  • High: [bold red]{findings_by_severity['HIGH']}[/bold red]")
                console.print(f"  • Medium: [bold yellow]{findings_by_severity['MEDIUM']}[/bold yellow]")
                console.print(f"  • Low: [bold cyan]{findings_by_severity['LOW']}[/bold cyan]")
                console.print(f"  • Info: [bold blue]{findings_by_severity['INFO']}[/bold blue]")
                
                # Resumo por categoria (se disponível)
                if 'categories' in self.security_analysis:
                    categories = self.security_analysis['categories']
                    console.print(f"\nProblemas por Categoria:")
                    console.print(f"  • Cabeçalhos de Segurança: [bold cyan]{categories.get('security_headers', 0)}[/bold cyan]")
                    console.print(f"  • CSP (Content Security Policy): [bold cyan]{categories.get('csp', 0)}[/bold cyan]")
                    console.print(f"  • Cookies: [bold cyan]{categories.get('cookies', 0)}[/bold cyan]")
                    console.print(f"  • CORS: [bold cyan]{categories.get('cors', 0)}[/bold cyan]")
                    console.print(f"  • Redirecionamentos: [bold cyan]{categories.get('redirects', 0)}[/bold cyan]")
                    console.print(f"  • Headers Suspeitos: [bold cyan]{categories.get('suspicious', 0)}[/bold cyan]")
                    console.print(f"  • Cache: [bold cyan]{categories.get('cache', 0)}[/bold cyan]")
                
                # Tabela de findings
                if self.security_analysis['findings']:
                    findings_table = Table(title="Problemas de Segurança Detectados")
                    findings_table.add_column("Severidade", style="red")
                    findings_table.add_column("Tipo", style="yellow")
                    findings_table.add_column("Descrição", style="white")
                    findings_table.add_column("Recomendação", style="green")
                    
                    for finding in self.security_analysis['findings']:
                        severity_colors = {
                            'HIGH': 'bold red',
                            'MEDIUM': 'bold yellow',
                            'LOW': 'bold cyan',
                            'INFO': 'bold blue'
                        }
                        severity_color = severity_colors.get(finding.get('severity', 'INFO'), 'white')
                        
                        findings_table.add_row(
                            f"[{severity_color}]{finding.get('severity', 'INFO')}[/{severity_color}]",
                            finding.get('type', 'Unknown'),
                            finding.get('description', 'N/A'),
                            finding.get('recommendation', 'N/A')
                        )
                    
                    console.print(findings_table)
                else:
                    console.print(f"[bold green]✅ Nenhum problema de segurança detectado[/bold green]")
            
            # Análise avançada de CSP
            if hasattr(self, 'csp_analysis') and self.csp_analysis:
                console.print(f"\n[bold cyan]📋 ANÁLISE DE CSP (CONTENT SECURITY POLICY)[/bold cyan]")
                console.print("-" * 60)
                
                csp_table = Table(title="Content Security Policy")
                csp_table.add_column("Aspecto", style="cyan")
                csp_table.add_column("Status", style="white")
                
                csp_score = self.csp_analysis.get('score', 0)
                if csp_score >= 80:
                    csp_status = f"[bold green]✅ {csp_score}/100[/bold green]"
                elif csp_score >= 60:
                    csp_status = f"[bold yellow]⚠️ {csp_score}/100[/bold yellow]"
                else:
                    csp_status = f"[bold red]❌ {csp_score}/100[/bold red]"
                
                csp_table.add_row("Pontuação CSP", csp_status)
                csp_table.add_row("Status", self.csp_analysis.get('analysis', 'N/A'))
                
                directives = self.csp_analysis.get('directives', {})
                csp_table.add_row("Diretivas Configuradas", str(len(directives)))
                
                # Mostra algumas diretivas importantes
                important_directives = ['default-src', 'script-src', 'object-src', 'style-src']
                for directive in important_directives:
                    if directive in directives:
                        values = ' '.join(directives[directive])
                        status = f"[bold green]✅ {values}[/bold green]"
                    else:
                        status = "[bold red]❌ Não configurado[/bold red]"
                    csp_table.add_row(directive, status)
                
                console.print(csp_table)
            
            # Análise de Cookies
            if hasattr(self, 'cookie_analysis') and self.cookie_analysis:
                console.print(f"\n[bold cyan]🍪 ANÁLISE DE COOKIES[/bold cyan]")
                console.print("-" * 60)
                
                cookie_table = Table(title="Segurança de Cookies")
                cookie_table.add_column("Cookie", style="cyan")
                cookie_table.add_column("Secure", style="white")
                cookie_table.add_column("HttpOnly", style="white")
                cookie_table.add_column("SameSite", style="white")
                
                cookies = self.cookie_analysis.get('cookies', {})
                for cookie_name, cookie_info in cookies.items():
                    secure_status = "[bold green]✅[/bold green]" if cookie_info.get('secure') else "[bold red]❌[/bold red]"
                    httponly_status = "[bold green]✅[/bold green]" if cookie_info.get('httponly') else "[bold red]❌[/bold red]"
                    samesite_value = cookie_info.get('samesite', 'Não definido')
                    
                    cookie_table.add_row(cookie_name, secure_status, httponly_status, samesite_value)
                
                if not cookies:
                    console.print("[bold blue]ℹ️ Nenhum cookie detectado na resposta[/bold blue]")
                else:
                    console.print(cookie_table)
            
            # Análise de Redirecionamentos
            if hasattr(self, 'redirect_analysis') and self.redirect_analysis:
                redirect_info = self.redirect_analysis.get('info', {})
                if redirect_info.get('total_redirects', 0) > 0:
                    console.print(f"\n[bold cyan]🔄 ANÁLISE DE REDIRECIONAMENTOS[/bold cyan]")
                    console.print("-" * 60)
                    
                    redirect_table = Table(title="Cadeia de Redirecionamentos")
                    redirect_table.add_column("Passo", style="cyan")
                    redirect_table.add_column("De", style="white")
                    redirect_table.add_column("Para", style="white")
                    redirect_table.add_column("Status", style="white")
                    redirect_table.add_column("HTTPS", style="white")
                    
                    for redirect in redirect_info.get('redirect_chain', []):
                        https_status = "[bold green]✅[/bold green]" if redirect.get('is_https') else "[bold red]❌[/bold red]"
                        redirect_table.add_row(
                            str(redirect.get('step', '')),
                            redirect.get('from_url', '')[:50] + '...' if len(redirect.get('from_url', '')) > 50 else redirect.get('from_url', ''),
                            redirect.get('to_url', '')[:50] + '...' if len(redirect.get('to_url', '')) > 50 else redirect.get('to_url', ''),
                            str(redirect.get('status_code', '')),
                            https_status
                        )
                    
                    console.print(redirect_table)
                    
                    # Status de segurança dos redirecionamentos
                    https_enforced = redirect_info.get('https_enforced', False)
                    https_status = "[bold green]✅ HTTPS Enforced[/bold green]" if https_enforced else "[bold red]❌ HTTPS Not Enforced[/bold red]"
                    console.print(f"HTTPS Enforcement: {https_status}")
                    
                    open_redirect_risk = redirect_info.get('open_redirect_risk', False)
                    open_redirect_status = "[bold red]⚠️ Risco Detectado[/bold red]" if open_redirect_risk else "[bold green]✅ Sem Risco[/bold green]"
                    console.print(f"Open Redirect Risk: {open_redirect_status}")
        
        elif output_format == 'json':
            import json
            return json.dumps({
                'headers_info': self.headers_info,
                'security_analysis': self.security_analysis
            }, indent=2, default=str)
        
        return {
            'headers_info': self.headers_info,
            'security_analysis': self.security_analysis
        }

# Funções de compatibilidade legacy
def get_http_headers(url, return_findings=False, verbose=False, output_format='table'):
    """Função de compatibilidade para análise de cabeçalhos."""
    analyzer = AdvancedHeadersAnalyzer(url)
    results = analyzer.analyze_headers(verbose=verbose)
    
    if results and not return_findings and output_format == 'table':
        analyzer.present_results(output_format)
    
    if return_findings and results:
        return results['security_analysis']['findings']
    
    return results

def headers_analysis_scan(url, verbose=False, output_format='table'):
    """Função alternativa de compatibilidade."""
    return get_http_headers(url, return_findings=False, verbose=verbose, output_format=output_format)
