# -*- coding: utf-8 -*-
"""
Módulo de Detecção de Tecnologias Web
Identifica tecnologias, frameworks e serviços utilizados em sites
"""

import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from ..core.console import console
from ..core.logger import get_logger
from ..utils.network import create_session

logger = get_logger(__name__)

class AdvancedTechnologyDetector:
    """Detector avançado de tecnologias web."""
    
    def __init__(self, url, timeout=10, retries=3):
        self.url = url if url.startswith('http') else f'http://{url}'
        self.timeout = timeout
        self.retries = retries
        self.session = create_session()
        
        # Resultados estruturados
        self.detections = {
            'web_servers': [],
            'frontend_frameworks': [],
            'backend_technologies': [],
            'cms_platforms': [],
            'javascript_libraries': [],
            'css_frameworks': [],
            'cdn_services': [],
            'security_technologies': [],
            'analytics_tools': [],
            'development_tools': [],
            'databases': [],
            'cloud_services': []
        }
        
        logger.info(f"Detector de tecnologias inicializado para {self.url}")
        
        # Database de tecnologias
        self._init_technology_database()
    
    def _init_technology_database(self):
        """Inicializa database de tecnologias."""
        self.tech_database = {
            'headers': {
                'Server': {
                    'nginx': {'name': 'Nginx', 'category': 'web_servers', 'version_regex': r'nginx/([\\d\\.]+)'},
                    'apache': {'name': 'Apache HTTP Server', 'category': 'web_servers', 'version_regex': r'Apache/([\\d\\.]+)'},
                    'microsoft-iis': {'name': 'Microsoft IIS', 'category': 'web_servers', 'version_regex': r'Microsoft-IIS/([\\d\\.]+)'},
                    'litespeed': {'name': 'LiteSpeed', 'category': 'web_servers', 'version_regex': r'LiteSpeed/([\\d\\.]+)'},
                    'caddy': {'name': 'Caddy', 'category': 'web_servers', 'version_regex': r'Caddy/([\\d\\.]+)'},
                    'gunicorn': {'name': 'Gunicorn', 'category': 'web_servers', 'version_regex': r'gunicorn/([\\d\\.]+)'},
                    'cloudflare': {'name': 'Cloudflare', 'category': 'cdn_services', 'version_regex': None},
                    'openresty': {'name': 'OpenResty', 'category': 'web_servers', 'version_regex': r'openresty/([\\d\\.]+)'},
                    'tomcat': {'name': 'Apache Tomcat', 'category': 'web_servers', 'version_regex': r'Apache-Coyote/([\\d\\.]+)'},
                    'jetty': {'name': 'Jetty', 'category': 'web_servers', 'version_regex': r'Jetty/([\\d\\.]+)'},
                    'node.js': {'name': 'Node.js', 'category': 'backend_technologies', 'version_regex': r'Node\\.js/([\\d\\.]+)'},
                },
                'X-Powered-By': {
                    'php': {'name': 'PHP', 'category': 'backend_technologies', 'version_regex': r'PHP/([\\d\\.]+)'},
                    'asp.net': {'name': 'ASP.NET', 'category': 'backend_technologies', 'version_regex': r'ASP\\.NET.*?([\\d\\.]+)'},
                    'express': {'name': 'Express.js', 'category': 'backend_technologies', 'version_regex': r'Express/([\\d\\.]+)'},
                    'django': {'name': 'Django', 'category': 'backend_technologies', 'version_regex': r'Django/([\\d\\.]+)'},
                    'rails': {'name': 'Ruby on Rails', 'category': 'backend_technologies', 'version_regex': r'Rails ([\\d\\.]+)'},
                    'laravel': {'name': 'Laravel', 'category': 'backend_technologies', 'version_regex': r'Laravel/([\\d\\.]+)'},
                    'next.js': {'name': 'Next.js', 'category': 'frontend_frameworks', 'version_regex': r'Next\\.js/([\\d\\.]+)'},
                    'node.js': {'name': 'Node.js', 'category': 'backend_technologies', 'version_regex': r'Node\\.js/([\\d\\.]+)'},
                },
                'X-Generator': {
                    'wordpress': {'name': 'WordPress', 'category': 'cms_platforms', 'version_regex': r'WordPress ([\\d\\.]+)'},
                    'drupal': {'name': 'Drupal', 'category': 'cms_platforms', 'version_regex': r'Drupal ([\\d\\.]+)'},
                    'joomla': {'name': 'Joomla', 'category': 'cms_platforms', 'version_regex': r'Joomla ([\\d\\.]+)'},
                }
            },
            'html_content': {
                # CMS Platforms
                'wordpress': {'name': 'WordPress', 'category': 'cms_platforms', 'patterns': [
                    r'wp-content', r'wp-includes', r'wp-admin', r'WordPress', r'wp_enqueue_script'
                ]},
                'drupal': {'name': 'Drupal', 'category': 'cms_platforms', 'patterns': [
                    r'drupal', r'sites/default', r'sites/all', r'drupal.js', r'Drupal.settings'
                ]},
                'joomla': {'name': 'Joomla', 'category': 'cms_platforms', 'patterns': [
                    r'joomla', r'com_content', r'mod_', r'Joomla', r'option=com_'
                ]},
                'magento': {'name': 'Magento', 'category': 'cms_platforms', 'patterns': [
                    r'magento', r'Mage.Cookies', r'skin/frontend', r'js/mage'
                ]},
                'shopify': {'name': 'Shopify', 'category': 'cms_platforms', 'patterns': [
                    r'shopify', r'shop.js', r'Shopify.theme', r'cdn.shopify.com'
                ]},
                
                # JavaScript Libraries
                'jquery': {'name': 'jQuery', 'category': 'javascript_libraries', 'patterns': [
                    r'jquery', r'jQuery', r'\\$\\(document\\)\\.ready'
                ]},
                'react': {'name': 'React', 'category': 'frontend_frameworks', 'patterns': [
                    r'react', r'React', r'__REACT_DEVTOOLS_GLOBAL_HOOK__'
                ]},
                'vue': {'name': 'Vue.js', 'category': 'frontend_frameworks', 'patterns': [
                    r'vue', r'Vue', r'__VUE__'
                ]},
                'angular': {'name': 'Angular', 'category': 'frontend_frameworks', 'patterns': [
                    r'angular', r'ng-', r'Angular', r'__karma__'
                ]},
                'bootstrap': {'name': 'Bootstrap', 'category': 'css_frameworks', 'patterns': [
                    r'bootstrap', r'Bootstrap', r'btn-', r'col-'
                ]},
                
                # Analytics & Tracking
                'google_analytics': {'name': 'Google Analytics', 'category': 'analytics_tools', 'patterns': [
                    r'google-analytics', r'ga\\(', r'gtag\\(', r'GoogleAnalyticsObject'
                ]},
                'gtm': {'name': 'Google Tag Manager', 'category': 'analytics_tools', 'patterns': [
                    r'googletagmanager', r'gtm.js', r'GTM-'
                ]},
                
                # CDN Services
                'cloudflare': {'name': 'Cloudflare', 'category': 'cdn_services', 'patterns': [
                    r'cloudflare', r'__cf_bm', r'cf-ray'
                ]},
                'fastly': {'name': 'Fastly', 'category': 'cdn_services', 'patterns': [
                    r'fastly', r'fastly-debug'
                ]},
                'akamai': {'name': 'Akamai', 'category': 'cdn_services', 'patterns': [
                    r'akamai', r'akamaized'
                ]},
            },
            'meta_tags': {
                'generator': {
                    'wordpress': {'name': 'WordPress', 'category': 'cms_platforms'},
                    'drupal': {'name': 'Drupal', 'category': 'cms_platforms'},
                    'joomla': {'name': 'Joomla', 'category': 'cms_platforms'},
                    'magento': {'name': 'Magento', 'category': 'cms_platforms'},
                    'shopify': {'name': 'Shopify', 'category': 'cms_platforms'},
                }
            },
            'cookies': {
                'PHPSESSID': {'name': 'PHP', 'category': 'backend_technologies'},
                'ASP.NET_SessionId': {'name': 'ASP.NET', 'category': 'backend_technologies'},
                'JSESSIONID': {'name': 'Java/J2EE', 'category': 'backend_technologies'},
                'connect.sid': {'name': 'Express.js', 'category': 'backend_technologies'},
                '_session_id': {'name': 'Ruby on Rails', 'category': 'backend_technologies'},
                'laravel_session': {'name': 'Laravel', 'category': 'backend_technologies'},
                'django_session': {'name': 'Django', 'category': 'backend_technologies'},
                'wp-settings': {'name': 'WordPress', 'category': 'cms_platforms'},
                'SESS': {'name': 'Drupal', 'category': 'cms_platforms'},
                'frontend': {'name': 'Magento', 'category': 'cms_platforms'},
                '_shopify_s': {'name': 'Shopify', 'category': 'cms_platforms'},
                '__cfduid': {'name': 'Cloudflare', 'category': 'cdn_services'},
                'cf_clearance': {'name': 'Cloudflare', 'category': 'cdn_services'},
            }
        }
    
    def _detect_from_headers(self, headers):
        """Detecta tecnologias a partir dos cabeçalhos HTTP."""
        detections = []
        
        for header_name, technologies in self.tech_database['headers'].items():
            header_value = headers.get(header_name, '').lower()
            if header_value:
                for tech_key, tech_info in technologies.items():
                    if tech_key in header_value:
                        version = None
                        if tech_info['version_regex']:
                            match = re.search(tech_info['version_regex'], header_value, re.IGNORECASE)
                            if match:
                                version = match.group(1)
                        
                        detection = {
                            'name': tech_info['name'],
                            'category': tech_info['category'],
                            'version': version,
                            'confidence': 95,
                            'source': f'HTTP Header: {header_name}'
                        }
                        detections.append(detection)
        
        return detections
    
    def _detect_from_html(self, html_content):
        """Detecta tecnologias a partir do conteúdo HTML."""
        detections = []
        
        # Detecta por padrões no HTML
        for tech_key, tech_info in self.tech_database['html_content'].items():
            for pattern in tech_info['patterns']:
                if re.search(pattern, html_content, re.IGNORECASE):
                    detection = {
                        'name': tech_info['name'],
                        'category': tech_info['category'],
                        'version': None,
                        'confidence': 80,
                        'source': f'HTML Content: {pattern}'
                    }
                    detections.append(detection)
                    break
        
        # Parse HTML para meta tags
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Meta generator
            generator_tag = soup.find('meta', attrs={'name': 'generator'})
            if generator_tag and generator_tag.get('content'):
                content = generator_tag['content'].lower()
                for tech_key, tech_info in self.tech_database['meta_tags']['generator'].items():
                    if tech_key in content:
                        version_match = re.search(r'([\\d\\.]+)', content)
                        version = version_match.group(1) if version_match else None
                        
                        detection = {
                            'name': tech_info['name'],
                            'category': tech_info['category'],
                            'version': version,
                            'confidence': 90,
                            'source': 'Meta Generator Tag'
                        }
                        detections.append(detection)
        except Exception as e:
            logger.error(f"Erro ao analisar HTML: {e}")
        
        return detections
    
    def _detect_from_cookies(self, cookies):
        """Detecta tecnologias a partir dos cookies."""
        detections = []
        
        for cookie in cookies:
            cookie_name = cookie.name.lower()
            for tech_cookie, tech_info in self.tech_database['cookies'].items():
                if tech_cookie.lower() in cookie_name:
                    detection = {
                        'name': tech_info['name'],
                        'category': tech_info['category'],
                        'version': None,
                        'confidence': 85,
                        'source': f'Cookie: {cookie.name}'
                    }
                    detections.append(detection)
        
        return detections
    
    def _detect_javascript_libraries(self, html_content):
        """Detecta bibliotecas JavaScript específicas."""
        detections = []
        
        # Padrões mais específicos para bibliotecas JS
        js_patterns = {
            'jquery': r'jquery[-.\\d]*\\.(?:min\\.)?js|jQuery\\.fn\\.jquery',
            'react': r'react[-.\\d]*\\.(?:min\\.)?js|React\\.version',
            'vue': r'vue[-.\\d]*\\.(?:min\\.)?js|Vue\\.version',
            'angular': r'angular[-.\\d]*\\.(?:min\\.)?js|angular\\.version',
            'bootstrap': r'bootstrap[-.\\d]*\\.(?:min\\.)?js|Bootstrap\\.version',
            'lodash': r'lodash[-.\\d]*\\.(?:min\\.)?js|_\\.VERSION',
            'moment': r'moment[-.\\d]*\\.(?:min\\.)?js|moment\\.version',
            'd3': r'd3[-.\\d]*\\.(?:min\\.)?js|d3\\.version',
            'chart.js': r'chart[-.\\d]*\\.(?:min\\.)?js|Chart\\.version',
            'axios': r'axios[-.\\d]*\\.(?:min\\.)?js|axios\\.VERSION',
        }
        
        for lib_name, pattern in js_patterns.items():
            if re.search(pattern, html_content, re.IGNORECASE):
                detection = {
                    'name': lib_name.capitalize(),
                    'category': 'javascript_libraries',
                    'version': None,
                    'confidence': 75,
                    'source': f'JavaScript Pattern: {pattern}'
                }
                detections.append(detection)
        
        return detections
    
    def _detect_cms_specifics(self, html_content, url):
        """Detecta CMS através de padrões específicos."""
        detections = []
        
        # WordPress
        wp_patterns = [
            r'/wp-content/',
            r'/wp-includes/',
            r'/wp-admin/',
            r'wp_enqueue_script',
            r'wp-json',
            r'WordPress'
        ]
        
        if any(re.search(pattern, html_content, re.IGNORECASE) for pattern in wp_patterns):
            # Tenta detectar versão do WordPress
            version_match = re.search(r'WordPress ([\\d\\.]+)', html_content)
            version = version_match.group(1) if version_match else None
            
            detection = {
                'name': 'WordPress',
                'category': 'cms_platforms',
                'version': version,
                'confidence': 95,
                'source': 'WordPress-specific patterns'
            }
            detections.append(detection)
        
        return detections
    
    def detect_technologies(self, verbose=False):
        """Detecta todas as tecnologias do site."""
        all_detections = []
        
        try:
            # Faz requisição inicial
            response = self.session.get(self.url, timeout=self.timeout, verify=False)
            html_content = response.text
            
            # Detecta por diferentes métodos
            header_detections = self._detect_from_headers(response.headers)
            html_detections = self._detect_from_html(html_content)
            cookie_detections = self._detect_from_cookies(response.cookies)
            js_detections = self._detect_javascript_libraries(html_content)
            cms_detections = self._detect_cms_specifics(html_content, self.url)
            
            # Combina todas as detecções
            all_detections.extend(header_detections)
            all_detections.extend(html_detections)
            all_detections.extend(cookie_detections)
            all_detections.extend(js_detections)
            all_detections.extend(cms_detections)
            
            # Remove duplicatas
            unique_detections = []
            seen = set()
            for detection in all_detections:
                key = (detection['name'], detection['category'])
                if key not in seen:
                    seen.add(key)
                    unique_detections.append(detection)
            
            # Organiza por categoria
            for detection in unique_detections:
                category = detection['category']
                if category in self.detections:
                    self.detections[category].append(detection)
            
            if verbose:
                console.print(f"[*] Detectadas {len(unique_detections)} tecnologias")
            
            return self.detections
            
        except requests.RequestException as e:
            logger.error(f"Erro ao detectar tecnologias: {e}")
            console.print(f"[bold red][!] Erro ao conectar com {self.url}: {e}[/bold red]")
            return self.detections
    
    def present_results(self, output_format='table'):
        """Apresenta os resultados das detecções."""
        if output_format == 'table':
            console.print("\\n[bold cyan]🔍 TECNOLOGIAS DETECTADAS[/bold cyan]")
            console.print("-" * 60)
            
            for category, detections in self.detections.items():
                if detections:
                    category_name = category.replace('_', ' ').title()
                    console.print(f"\\n[bold yellow]{category_name}:[/bold yellow]")
                    
                    for detection in detections:
                        version_info = f" v{detection['version']}" if detection['version'] else ""
                        confidence = f" ({detection['confidence']}%)"
                        console.print(f"  • {detection['name']}{version_info}{confidence}")
                        if detection.get('source'):
                            console.print(f"    Fonte: {detection['source']}")
        
        elif output_format == 'json':
            import json
            return json.dumps(self.detections, indent=2)
        
        return self.detections

# Funções de compatibilidade legacy
def detect_technologies(url, verbose=False, output_format='table'):
    """Função de compatibilidade para detecção de tecnologias."""
    detector = AdvancedTechnologyDetector(url)
    detections = detector.detect_technologies(verbose=verbose)
    
    if output_format == 'table':
        detector.present_results(output_format)
    
    return detections

def technology_detection_scan(url, verbose=False, output_format='table'):
    """Função alternativa de compatibilidade."""
    return detect_technologies(url, verbose=verbose, output_format=output_format)
