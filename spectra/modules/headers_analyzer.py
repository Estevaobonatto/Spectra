# -*- coding: utf-8 -*-
"""
Módulo de Análise de Cabeçalhos HTTP
Analisa cabeçalhos de resposta HTTP e configurações de segurança
"""

import json
from typing import Dict, List, Optional, Union
import requests
from urllib.parse import urlparse
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
        
        logger.info(f"Headers Analyzer inicializado para {self.url}")
        
        # Inicializa database de cabeçalhos
        self._init_headers_database()
    
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
                import re
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
    
    def analyze_headers(self, verbose=False):
        """Executa análise completa dos cabeçalhos."""
        try:
            # Faz requisição
            response = self.session.get(
                self.url, 
                timeout=self.timeout, 
                allow_redirects=self.follow_redirects,
                verify=False
            )
            
            # Analisa resposta
            self._analyze_response(response)
            
            # Análise de segurança
            security_analysis = self._analyze_security_headers()
            
            # Análise CORS
            cors_findings = self._analyze_cors_configuration()
            
            # Análise de cache
            cache_findings = self._analyze_cache_configuration()
            
            # Combina todos os findings
            all_findings = security_analysis['findings'] + cors_findings + cache_findings
            
            self.security_analysis = {
                'security_score': security_analysis['security_score'],
                'total_findings': len(all_findings),
                'findings_by_severity': {
                    'HIGH': len([f for f in all_findings if f.get('severity') == 'HIGH']),
                    'MEDIUM': len([f for f in all_findings if f.get('severity') == 'MEDIUM']),
                    'LOW': len([f for f in all_findings if f.get('severity') == 'LOW']),
                    'INFO': len([f for f in all_findings if f.get('severity') == 'INFO'])
                },
                'findings': all_findings
            }
            
            if verbose:
                console.print(f"[*] Analisados {len(self.headers_info['headers'])} cabeçalhos")
                console.print(f"[*] Encontrados {len(all_findings)} problemas de segurança")
            
            logger.info(f"Análise de cabeçalhos concluída para {self.url}")
            
            return {
                'headers_info': self.headers_info,
                'security_analysis': self.security_analysis
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
