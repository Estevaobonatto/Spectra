# -*- coding: utf-8 -*-
"""
Módulo de Detecção de WAF (Web Application Firewall)
Identifica a presença de WAFs e sistemas de proteção web
"""

import re
import time
import json
from typing import Dict, List, Optional, Union
import requests
from urllib.parse import urlparse
from ..core.console import console
from ..core.logger import get_logger
from ..utils.network import create_session

logger = get_logger(__name__)

class AdvancedWAFDetector:
    """Detector avançado de WAF com análise de bypass e timing."""
    
    def __init__(self, url: str, timeout: int = 10, retries: int = 3):
        self.url = url if url.startswith('http') else f'http://{url}'
        self.timeout = timeout
        self.retries = retries
        self.session = create_session()
        
        self.detected_wafs = []
        self.timing_data = {}
        self.bypass_results = []
        self.waf_info = {}
        
        logger.info(f"WAF Detector inicializado para {self.url}")
        
        # Inicializa database de WAFs
        self._init_waf_database()
    
    def _init_waf_database(self):
        """Inicializa a base de dados de WAFs conhecidos."""
        self.waf_signatures = {
            # Cloud WAFs
            "Cloudflare": {
                "server": ["cloudflare", "cf-ray"], 
                "headers": ["cf-ray", "cf-cache-status", "cf-request-id", "cf-visitor"],
                "body": ["cloudflare", "attention required", "cf-browser-verification", "checking your browser"],
                "confidence": 95
            },
            "AWS WAF": {
                "server": ["awselb", "aws"],
                "headers": ["x-amzn-", "x-amz-cf-id", "x-amz-request-id"],
                "body": ["aws", "access denied", "request blocked"],
                "confidence": 90
            },
            "Akamai": {
                "server": ["akamaighost", "akamai"],
                "headers": ["akamai-origin-hop", "akamai-ghost-ip"],
                "body": ["akamai", "reference #", "access denied"],
                "confidence": 90
            },
            "Fastly": {
                "server": ["fastly"],
                "headers": ["fastly-debug-digest", "x-served-by", "fastly-restarts"],
                "body": ["fastly error page", "vcl_error"],
                "confidence": 85
            },
            "Azure Front Door": {
                "server": ["microsoft-azure-application-gateway"],
                "headers": ["x-azure-ref", "x-fd-healthprobe"],
                "body": ["azure", "application gateway"],
                "confidence": 85
            },
            "Google Cloud Armor": {
                "server": ["gws", "gfe"],
                "headers": ["x-cloud-trace-context", "x-goog-"],
                "body": ["denied by policy", "cloud armor"],
                "confidence": 85
            },
            
            # Commercial WAFs
            "Sucuri": {
                "server": ["sucuri", "cloudproxy"],
                "headers": ["x-sucuri-", "x-sucuri-id"],
                "body": ["blocked by sucuri", "access denied", "sucuri website firewall"],
                "confidence": 90
            },
            "Incapsula": {
                "server": ["incapsula"],
                "headers": ["x-iinfo", "x-cdn"],
                "cookies": ["incap_ses_", "visid_incap_"],
                "body": ["incapsula", "access denied", "request unsuccessful"],
                "confidence": 95
            },
            "Barracuda": {
                "server": ["barracuda"],
                "headers": ["barra", "x-barracuda"],
                "body": ["barracuda", "blocked by policy", "web application firewall"],
                "confidence": 90
            },
            "F5 BIG-IP": {
                "server": ["big-ip", "f5"],
                "headers": ["x-wa-info", "f5-trace-id"],
                "body": ["f5", "security policy", "big-ip"],
                "confidence": 90
            },
            "Imperva": {
                "server": ["imperva"],
                "headers": ["x-iinfo", "incap_ses"],
                "body": ["imperva", "blocked by policy"],
                "confidence": 85
            },
            "Fortinet FortiWeb": {
                "server": ["fortiweb"],
                "headers": ["fortigate"],
                "body": ["fortiweb", "blocked by fortinet"],
                "confidence": 85
            },
            "Wallarm": {
                "server": ["wallarm"],
                "headers": ["x-wallarm"],
                "body": ["wallarm", "blocked by wallarm"],
                "confidence": 80
            },
            "Radware": {
                "server": ["radware"],
                "headers": ["x-protected-by"],
                "body": ["radware", "defensepro"],
                "confidence": 80
            },
            "Citrix NetScaler": {
                "server": ["netscaler"],
                "headers": ["ns_af", "citrix"],
                "body": ["netscaler", "citrix"],
                "confidence": 80
            },
            
            # Open Source WAFs
            "ModSecurity": {
                "server": ["mod_security", "modsecurity"],
                "headers": ["mod_security"],
                "body": ["mod_security", "not acceptable", "406 not acceptable", "modsecurity"],
                "confidence": 85
            },
            "Wordfence": {
                "body": ["blocked by wordfence", "generated by wordfence", "wordfence security"],
                "headers": ["x-wordfence"],
                "confidence": 90
            },
            "Nginx ModSecurity": {
                "server": ["nginx"],
                "body": ["403 forbidden", "blocked by security policy", "nginx modsecurity"],
                "confidence": 70
            },
            "NAXSI": {
                "server": ["nginx", "naxsi"],
                "body": ["naxsi", "unusual request"],
                "confidence": 75
            },
            "Shadow Daemon": {
                "body": ["shadow daemon", "request blocked"],
                "confidence": 70
            },
            
            # CDN/Edge WAFs
            "StackPath": {
                "server": ["stackpath"],
                "headers": ["x-sp-", "stackpath-edge"],
                "body": ["stackpath"],
                "confidence": 75
            },
            "KeyCDN": {
                "server": ["keycdn"],
                "headers": ["x-cache", "x-edge-location"],
                "body": ["keycdn"],
                "confidence": 70
            },
            "BunnyCDN": {
                "server": ["bunnycdn"],
                "headers": ["bunny-"],
                "body": ["bunnycdn"],
                "confidence": 70
            },
            "MaxCDN": {
                "server": ["netdna"],
                "headers": ["x-cache", "maxcdn"],
                "body": ["maxcdn"],
                "confidence": 70
            },
            
            # Security Vendors
            "Comodo": {
                "server": ["protected by comodo"],
                "body": ["comodo", "access denied", "cwatch"],
                "confidence": 75
            },
            "SiteLock": {
                "body": ["sitelock", "blocked by sitelock"],
                "confidence": 80
            },
            "Malcare": {
                "body": ["malcare", "blocked by malcare"],
                "confidence": 75
            },
            "WebKnight": {
                "server": ["webknight"],
                "body": ["webknight", "blocked by webknight"],
                "confidence": 80
            },
            "DotDefender": {
                "server": ["dotdefender"],
                "body": ["dotdefender", "applicure"],
                "confidence": 80
            },
            "Profense": {
                "server": ["profense"],
                "body": ["profense", "armorlogic"],
                "confidence": 75
            },
            
            # Chinese/Asian WAFs
            "Yunjiasu": {
                "server": ["yunjiasu"],
                "headers": ["yunjiasu-cache"],
                "body": ["yunjiasu"],
                "confidence": 75
            },
            "Baidu Cloud": {
                "server": ["bce", "baidu"],
                "headers": ["baidu-"],
                "body": ["baidu", "blocked by baidu"],
                "confidence": 75
            },
            "Tencent Cloud": {
                "server": ["tencent"],
                "headers": ["tencent-"],
                "body": ["tencent", "qcloud"],
                "confidence": 75
            },
            "Alibaba Cloud": {
                "server": ["tengine", "alidns"],
                "headers": ["ali-", "eagleeye-"],
                "body": ["alibaba", "aliyun"],
                "confidence": 75
            },
            
            # Hardware WAFs
            "Cisco ASA": {
                "server": ["cisco"],
                "body": ["cisco", "asa firewall"],
                "confidence": 80
            },
            "SonicWall": {
                "server": ["sonicwall"],
                "body": ["sonicwall", "blocked by sonicwall"],
                "confidence": 80
            },
            "pfSense": {
                "server": ["pfsense"],
                "body": ["pfsense", "blocked by pfsense"],
                "confidence": 75
            },
            
            # Enterprise WAFs
            "IBM Security": {
                "server": ["ibm", "webseal"],
                "headers": ["ibm-dp", "x-ibm-"],
                "body": ["ibm security", "webseal"],
                "confidence": 80
            },
            "Oracle WAF": {
                "server": ["oracle", "oci"],
                "headers": ["x-oracle-", "oci-"],
                "body": ["oracle", "blocked by oracle"],
                "confidence": 75
            },
            "Microsoft Threat Protection": {
                "server": ["microsoft", "azure"],
                "headers": ["x-ms-", "azure-"],
                "body": ["microsoft defender", "threat protection"],
                "confidence": 75
            },
            "Symantec WAF": {
                "server": ["symantec"],
                "headers": ["symantec-", "x-symantec-"],
                "body": ["symantec", "blocked by symantec"],
                "confidence": 75
            },
            "McAfee WAF": {
                "server": ["mcafee"],
                "headers": ["mcafee-", "x-mcafee-"],
                "body": ["mcafee", "blocked by mcafee"],
                "confidence": 75
            },
            "Trend Micro": {
                "server": ["trendmicro"],
                "headers": ["tm-", "x-trend-"],
                "body": ["trend micro", "deep security"],
                "confidence": 75
            },
            "Check Point": {
                "server": ["checkpoint"],
                "headers": ["checkpoint-", "x-cp-"],
                "body": ["check point", "blocked by checkpoint"],
                "confidence": 80
            },
            "Palo Alto": {
                "server": ["paloalto", "pan-"],
                "headers": ["pan-", "x-palo-"],
                "body": ["palo alto", "wildfire"],
                "confidence": 80
            },
            "Juniper": {
                "server": ["juniper"],
                "headers": ["juniper-", "x-juniper-"],
                "body": ["juniper", "blocked by juniper"],
                "confidence": 75
            },
            "HPE Security": {
                "server": ["hpe", "arcsight"],
                "headers": ["hpe-", "x-hpe-"],
                "body": ["hpe security", "arcsight"],
                "confidence": 70
            },
            
            # Emerging WAFs
            "Cloudinary": {
                "server": ["cloudinary"],
                "headers": ["cloudinary-", "x-cld-"],
                "body": ["cloudinary"],
                "confidence": 70
            },
            "Netlify": {
                "server": ["netlify"],
                "headers": ["netlify-", "x-nf-"],
                "body": ["netlify"],
                "confidence": 70
            },
            "Vercel": {
                "server": ["vercel"],
                "headers": ["vercel-", "x-vercel-"],
                "body": ["vercel"],
                "confidence": 70
            }
        }
    
    def _detect_from_response(self, response):
        """Detecta WAF através da resposta HTTP."""
        detections = []
        
        # Headers
        headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
        
        # Content
        content = response.text.lower()
        
        # Cookies
        cookies = [cookie.name.lower() for cookie in response.cookies]
        
        for waf_name, signatures in self.waf_signatures.items():
            detection_score = 0
            detection_sources = []
            
            # Verifica server header
            if 'server' in signatures:
                for sig in signatures['server']:
                    if sig in headers_lower.get('server', ''):
                        detection_score += 30
                        detection_sources.append(f'Server: {sig}')
            
            # Verifica headers específicos
            if 'headers' in signatures:
                for header_sig in signatures['headers']:
                    for header_name, header_value in headers_lower.items():
                        if header_sig in header_name or header_sig in header_value:
                            detection_score += 25
                            detection_sources.append(f'Header: {header_name}')
            
            # Verifica conteúdo do corpo
            if 'body' in signatures:
                for body_sig in signatures['body']:
                    if body_sig in content:
                        detection_score += 20
                        detection_sources.append(f'Body: {body_sig}')
            
            # Verifica cookies
            if 'cookies' in signatures:
                for cookie_sig in signatures['cookies']:
                    for cookie in cookies:
                        if cookie_sig in cookie:
                            detection_score += 15
                            detection_sources.append(f'Cookie: {cookie}')
            
            # Se encontrou evidências suficientes
            if detection_score >= 20:
                confidence = min(signatures.get('confidence', 50) + detection_score, 100)
                detection = {
                    'name': waf_name,
                    'confidence': confidence,
                    'detection_score': detection_score,
                    'sources': detection_sources,
                    'type': self._classify_waf_type(waf_name)
                }
                detections.append(detection)
        
        return detections
    
    def _classify_waf_type(self, waf_name):
        """Classifica o tipo de WAF."""
        cloud_wafs = ['Cloudflare', 'AWS WAF', 'Akamai', 'Fastly', 'Azure Front Door', 'Google Cloud Armor',
                     'Yunjiasu', 'Baidu Cloud', 'Tencent Cloud', 'Alibaba Cloud']
        commercial_wafs = ['Sucuri', 'Incapsula', 'Barracuda', 'F5 BIG-IP', 'Imperva', 'Fortinet FortiWeb',
                          'Wallarm', 'Radware', 'Cisco ASA', 'Palo Alto', 'SonicWall', 'CheckPoint']
        open_source = ['ModSecurity', 'Wordfence', 'Nginx ModSecurity', 'NAXSI', 'Shadow Daemon']
        cdn_wafs = ['StackPath', 'KeyCDN', 'BunnyCDN', 'MaxCDN']
        security_services = ['Comodo', 'SiteLock', 'Malcare', 'WebKnight', 'DotDefender', 'Profense']
        
        if waf_name in cloud_wafs:
            return 'Cloud WAF'
        elif waf_name in commercial_wafs:
            return 'Commercial WAF'
        elif waf_name in open_source:
            return 'Open Source WAF'
        elif waf_name in cdn_wafs:
            return 'CDN Protection'
        elif waf_name in security_services:
            return 'Security Service'
        else:
            return 'Enterprise/Hardware'
    
    def _timing_analysis(self, verbose=False):
        """Realiza análise de timing para detectar WAF."""
        if verbose:
            console.print("[*] Realizando análise de timing...")
        
        # Payload normal
        normal_start = time.time()
        try:
            response = self.session.get(self.url, timeout=self.timeout)
            normal_time = time.time() - normal_start
        except:
            normal_time = self.timeout
        
        # Payload malicioso
        malicious_url = f"{self.url}?test=<script>alert('xss')</script>"
        malicious_start = time.time()
        try:
            response = self.session.get(malicious_url, timeout=self.timeout)
            malicious_time = time.time() - malicious_start
        except:
            malicious_time = self.timeout
        
        # Análise de diferença de timing
        time_diff = abs(malicious_time - normal_time)
        
        self.timing_data = {
            'normal_response_time': normal_time,
            'malicious_response_time': malicious_time,
            'time_difference': time_diff,
            'waf_suspected': time_diff > 0.5  # Diferença significativa
        }
        
        if verbose:
            console.print(f"[*] Tempo normal: {normal_time:.2f}s")
            console.print(f"[*] Tempo malicioso: {malicious_time:.2f}s")
            console.print(f"[*] Diferença: {time_diff:.2f}s")
        
        return self.timing_data
    
    def _test_bypass_techniques(self, verbose=False):
        """Testa técnicas de bypass de WAF."""
        if verbose:
            console.print("[*] Testando técnicas de bypass...")
        
        bypass_payloads = [
            # SQL Injection bypasses
            "1' OR '1'='1",
            "1' OR 1=1--",
            "1' UNION SELECT null--",
            "1' /**/OR/**/1=1--",
            "1' OR 1=1#",
            
            # XSS bypasses
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>",
            "javascript:alert('xss')",
            "<svg onload=alert('xss')>",
            
            # Command injection bypasses
            "; cat /etc/passwd",
            "| whoami",
            "& dir",
            "`id`",
            
            # Path traversal bypasses
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
        ]
        
        results = []
        for payload in bypass_payloads:
            try:
                test_url = f"{self.url}?test={payload}"
                response = self.session.get(test_url, timeout=self.timeout)
                
                result = {
                    'payload': payload,
                    'status_code': response.status_code,
                    'blocked': response.status_code in [403, 406, 429, 503],
                    'response_time': response.elapsed.total_seconds(),
                    'content_length': len(response.content)
                }
                results.append(result)
                
                if verbose:
                    status = "BLOCKED" if result['blocked'] else "ALLOWED"
                    console.print(f"[*] {payload[:30]}... -> {status}")
                    
            except Exception as e:
                if verbose:
                    console.print(f"[!] Erro testando payload: {e}")
        
        self.bypass_results = results
        return results
    
    def detect_waf(self, verbose=False, test_bypasses=False, timing_analysis=False):
        """Detecta WAF com análise completa."""
        try:
            # Requisição inicial
            response = self.session.get(self.url, timeout=self.timeout, verify=False)
            
            # Detecta WAF através da resposta
            detections = self._detect_from_response(response)
            
            # Análise de timing (opcional)
            if timing_analysis:
                self._timing_analysis(verbose=verbose)
            
            # Testes de bypass (opcional)
            if test_bypasses:
                self._test_bypass_techniques(verbose=verbose)
            
            self.detected_wafs = detections
            
            if verbose:
                console.print(f"[*] Detectados {len(detections)} WAFs")
            
            return {
                'detected_wafs': detections,
                'timing_data': self.timing_data,
                'bypass_results': self.bypass_results
            }
            
        except requests.RequestException as e:
            logger.error(f"Erro ao detectar WAF: {e}")
            console.print(f"[bold red][!] Erro ao conectar com {self.url}: {e}[/bold red]")
            return {
                'detected_wafs': [],
                'timing_data': {},
                'bypass_results': []
            }
    
    def present_results(self, output_format='table'):
        """Apresenta os resultados da detecção."""
        if output_format == 'table':
            console.print("\n[bold cyan]🛡️  WAF DETECTION RESULTS[/bold cyan]")
            console.print("-" * 60)
            
            if not self.detected_wafs:
                console.print("[bold green]✅ Nenhum WAF detectado[/bold green]")
                return
            
            # Tabela de WAFs detectados
            from rich.table import Table
            table = Table(title="WAFs Detectados")
            table.add_column("WAF", style="cyan")
            table.add_column("Tipo", style="yellow")
            table.add_column("Confiança", style="green")
            table.add_column("Fontes", style="magenta")
            
            for waf in self.detected_wafs:
                sources = ", ".join(waf['sources'][:3])  # Limita a 3 fontes
                if len(waf['sources']) > 3:
                    sources += "..."
                
                table.add_row(
                    waf['name'],
                    waf['type'],
                    f"{waf['confidence']}%",
                    sources
                )
            
            console.print(table)
            
            # Timing analysis
            if self.timing_data:
                console.print("\n[bold cyan]⏱️  TIMING ANALYSIS[/bold cyan]")
                console.print("-" * 60)
                suspected = "SIM" if self.timing_data['waf_suspected'] else "NÃO"
                console.print(f"WAF Suspeito: {suspected}")
                console.print(f"Tempo Normal: {self.timing_data['normal_response_time']:.2f}s")
                console.print(f"Tempo Malicioso: {self.timing_data['malicious_response_time']:.2f}s")
                console.print(f"Diferença: {self.timing_data['time_difference']:.2f}s")
            
            # Bypass results
            if self.bypass_results:
                console.print("\n[bold cyan]🔧 BYPASS TEST RESULTS[/bold cyan]")
                console.print("-" * 60)
                blocked = sum(1 for r in self.bypass_results if r['blocked'])
                total = len(self.bypass_results)
                console.print(f"Payloads Bloqueados: {blocked}/{total}")
                console.print(f"Taxa de Bloqueio: {(blocked/total)*100:.1f}%")
        
        elif output_format == 'json':
            import json
            return json.dumps({
                'detected_wafs': self.detected_wafs,
                'timing_data': self.timing_data,
                'bypass_results': self.bypass_results
            }, indent=2)
        
        return {
            'detected_wafs': self.detected_wafs,
            'timing_data': self.timing_data,
            'bypass_results': self.bypass_results
        }

# Funções de compatibilidade legacy
def detect_waf(url, verbose=False, output_format='table', test_bypasses=False, timing_analysis=False):
    """Função de compatibilidade para detecção de WAF."""
    detector = AdvancedWAFDetector(url)
    results = detector.detect_waf(verbose=verbose, test_bypasses=test_bypasses, timing_analysis=timing_analysis)
    
    if output_format == 'table':
        detector.present_results(output_format)
    
    return results

def waf_detection_scan(url, verbose=False, output_format='table', test_bypasses=False, timing_analysis=False):
    """Função alternativa de compatibilidade."""
    return detect_waf(url, verbose=verbose, output_format=output_format, 
                     test_bypasses=test_bypasses, timing_analysis=timing_analysis)
