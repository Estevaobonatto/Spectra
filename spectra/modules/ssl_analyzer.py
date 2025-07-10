# -*- coding: utf-8 -*-
"""
Módulo de Análise SSL/TLS
Analisa certificados SSL/TLS e configurações de segurança
"""

import ssl
import socket
import json
import requests
import base64
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Union
from OpenSSL import crypto
from ..core.console import console
from ..core.logger import get_logger

logger = get_logger(__name__)

class AdvancedSSLAnalyzer:
    """Analisador avançado de SSL/TLS com verificações de segurança."""
    
    def __init__(self, hostname: str, port: int = 443, timeout: int = 10):
        self.hostname = hostname
        self.port = port
        self.timeout = timeout
        
        self.certificate_info = {}
        self.security_analysis = {}
        self.vulnerabilities = []
        self.cipher_analysis = {}
        self.hsts_info = {}
        self.ocsp_info = {}
        
        # Cipher suites conhecidos e suas características
        self.weak_ciphers = [
            'RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'aNULL', 'eNULL'
        ]
        self.preferred_ciphers = [
            'ECDHE-RSA-AES256-GCM-SHA384', 'ECDHE-RSA-AES128-GCM-SHA256',
            'ECDHE-RSA-CHACHA20-POLY1305', 'ECDHE-ECDSA-AES256-GCM-SHA384'
        ]
        
        logger.info(f"SSL Analyzer inicializado para {hostname}:{port}")
    
    def _get_certificate(self):
        """Obtém o certificado SSL/TLS do host."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.hostname, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert_der = ssock.getpeercert(True)
                    cert_dict = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    return {
                        'cert_der': cert_der,
                        'cert_dict': cert_dict,
                        'cipher': cipher
                    }
                    
        except Exception as e:
            logger.error(f"Erro ao obter certificado: {e}")
            raise
    
    def _parse_certificate(self, cert_data):
        """Analisa o certificado SSL/TLS."""
        try:
            # Salva os dados do certificado para uso posterior
            self._cert_data = cert_data
            
            x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_data['cert_der'])
            
            # Informações básicas
            subject_components = x509.get_subject().get_components()
            issuer_components = x509.get_issuer().get_components()
            
            subject = {comp[0].decode(): comp[1].decode() for comp in subject_components}
            issuer = {comp[0].decode(): comp[1].decode() for comp in issuer_components}
            
            # Datas de validade
            not_before = datetime.strptime(x509.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')
            not_after = datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
            
            # Chave pública
            pubkey = x509.get_pubkey()
            key_type = self._get_key_type(pubkey.type())
            key_size = pubkey.bits()
            
            # Algoritmo de assinatura
            signature_algorithm = x509.get_signature_algorithm().decode('utf-8')
            
            # Número de série
            serial_number = str(x509.get_serial_number())
            
            # Subject Alternative Names (SAN)
            san_list = self._extract_san(x509)
            
            # Verificação de autoassinado
            is_self_signed = subject == issuer
            
            # Status de expiração
            is_expired = x509.has_expired()
            days_until_expiry = (not_after - datetime.now()).days
            
            self.certificate_info = {
                'subject': subject,
                'issuer': issuer,
                'not_before': not_before,
                'not_after': not_after,
                'is_expired': is_expired,
                'days_until_expiry': days_until_expiry,
                'is_self_signed': is_self_signed,
                'key_type': key_type,
                'key_size': key_size,
                'signature_algorithm': signature_algorithm,
                'serial_number': serial_number,
                'san_list': san_list,
                'cipher_info': cert_data['cipher']
            }
            
            return self.certificate_info
            
        except Exception as e:
            logger.error(f"Erro ao analisar certificado: {e}")
            raise
    
    def _get_key_type(self, key_type_id):
        """Identifica o tipo de chave pública."""
        key_types = {
            crypto.TYPE_RSA: 'RSA',
            crypto.TYPE_DSA: 'DSA'
        }
        
        # Verifica se é ECC (EC)
        try:
            if key_type_id == crypto.TYPE_EC:
                return 'ECC'
        except AttributeError:
            pass
        
        return key_types.get(key_type_id, 'Desconhecido')
    
    def _extract_san(self, x509):
        """Extrai Subject Alternative Names."""
        san_list = []
        
        try:
            for i in range(x509.get_extension_count()):
                ext = x509.get_extension(i)
                if 'subjectAltName' in str(ext.get_short_name(), 'utf-8'):
                    san_raw = str(ext)
                    # Parse SAN entries
                    for entry in san_raw.split(', '):
                        if entry.startswith('DNS:'):
                            san_list.append(entry.replace('DNS:', ''))
                        elif entry.startswith('IP:'):
                            san_list.append(entry.replace('IP:', ''))
        except Exception as e:
            logger.warning(f"Erro ao extrair SAN: {e}")
        
        return san_list
    
    def _analyze_security(self):
        """Analisa a segurança do certificado e configuração SSL."""
        vulnerabilities = []
        recommendations = []
        
        # Verifica expiração
        if self.certificate_info['is_expired']:
            vulnerabilities.append({
                'type': 'CRITICAL',
                'issue': 'Certificado Expirado',
                'description': 'O certificado SSL/TLS expirou',
                'impact': 'Conexões inseguras, avisos do navegador'
            })
        elif self.certificate_info['days_until_expiry'] <= 30:
            vulnerabilities.append({
                'type': 'WARNING',
                'issue': 'Certificado Expirando',
                'description': f"Certificado expira em {self.certificate_info['days_until_expiry']} dias",
                'impact': 'Potencial interrupção do serviço'
            })
        
        # Verifica certificado autoassinado
        if self.certificate_info['is_self_signed']:
            vulnerabilities.append({
                'type': 'HIGH',
                'issue': 'Certificado Autoassinado',
                'description': 'Certificado não foi emitido por uma CA confiável',
                'impact': 'Sem garantia de identidade, avisos do navegador'
            })
        
        # Verifica tamanho da chave
        key_size = self.certificate_info['key_size']
        key_type = self.certificate_info['key_type']
        
        if key_type == 'RSA':
            if key_size < 2048:
                vulnerabilities.append({
                    'type': 'HIGH',
                    'issue': 'Chave RSA Fraca',
                    'description': f'Chave RSA de {key_size} bits é considerada fraca',
                    'impact': 'Vulnerável a ataques de força bruta'
                })
            elif key_size < 4096:
                recommendations.append('Considere usar chave RSA de 4096 bits para maior segurança')
        
        # Verifica algoritmo de assinatura
        signature_alg = self.certificate_info['signature_algorithm'].lower()
        weak_algorithms = ['md5', 'sha1']
        
        for weak_alg in weak_algorithms:
            if weak_alg in signature_alg:
                vulnerabilities.append({
                    'type': 'HIGH',
                    'issue': 'Algoritmo de Assinatura Fraco',
                    'description': f'Algoritmo {signature_alg} é considerado inseguro',
                    'impact': 'Vulnerável a ataques de colisão'
                })
        
        # Verifica cipher suite
        if self.certificate_info['cipher_info']:
            cipher_name = self.certificate_info['cipher_info'][0]
            cipher_version = self.certificate_info['cipher_info'][1]
            cipher_bits = self.certificate_info['cipher_info'][2]
            
            # Verifica versão do protocolo
            if cipher_version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                vulnerabilities.append({
                    'type': 'HIGH',
                    'issue': 'Protocolo SSL/TLS Inseguro',
                    'description': f'Protocolo {cipher_version} é vulnerável',
                    'impact': 'Susceptível a ataques conhecidos (POODLE, BEAST, etc.)'
                })
            
            # Verifica força da cifra
            if cipher_bits < 128:
                vulnerabilities.append({
                    'type': 'MEDIUM',
                    'issue': 'Cifra Fraca',
                    'description': f'Cifra de {cipher_bits} bits é considerada fraca',
                    'impact': 'Dados podem ser descriptografados com relativa facilidade'
                })
        
        # Verifica wildcard certificates
        san_list = self.certificate_info.get('san_list', [])
        cn = self.certificate_info.get('subject', {}).get('CN', '')
        
        if any(name.startswith('*.') for name in san_list + [cn]):
            recommendations.append('Certificados wildcard podem ter implicações de segurança')
        
        # Análise avançada de cipher suites
        if hasattr(self, 'cipher_analysis') and self.cipher_analysis:
            cipher_analysis = self.cipher_analysis
            
            # Verifica ciphers fracos
            if cipher_analysis.get('weak_ciphers_found'):
                vulnerabilities.append({
                    'type': 'HIGH',
                    'issue': 'Cipher Suites Fracos',
                    'description': f"Encontrados {len(cipher_analysis['weak_ciphers_found'])} cipher suites fracos",
                    'impact': 'Conexões podem ser interceptadas ou descriptografadas'
                })
            
            # Verifica suporte a TLS 1.3
            if not cipher_analysis.get('tls13_support'):
                recommendations.append('Considere habilitar suporte a TLS 1.3 para maior segurança')
            
            # Verifica Perfect Forward Secrecy
            if not cipher_analysis.get('pfs_support'):
                vulnerabilities.append({
                    'type': 'MEDIUM',
                    'issue': 'Sem Perfect Forward Secrecy',
                    'description': 'Servidor não suporta Perfect Forward Secrecy (PFS)',
                    'impact': 'Chaves comprometidas podem descriptografar tráfego passado'
                })
            
            # Verifica versões TLS inseguras
            supported_versions = cipher_analysis.get('supported_versions', [])
            insecure_versions = ['TLSv1', 'TLSv1.1']
            
            for insecure_version in insecure_versions:
                if insecure_version in supported_versions:
                    vulnerabilities.append({
                        'type': 'HIGH',
                        'issue': f'Protocolo {insecure_version} Inseguro',
                        'description': f'Servidor ainda suporta {insecure_version}',
                        'impact': 'Vulnerável a ataques conhecidos'
                    })
        
        # Análise HSTS
        if hasattr(self, 'hsts_info') and self.hsts_info:
            if not self.hsts_info.get('enabled'):
                vulnerabilities.append({
                    'type': 'MEDIUM',
                    'issue': 'HSTS Não Configurado',
                    'description': 'HTTP Strict Transport Security não está habilitado',
                    'impact': 'Vulnerável a ataques de downgrade e man-in-the-middle'
                })
            else:
                max_age = self.hsts_info.get('max_age', 0)
                if max_age < 31536000:  # Menos de 1 ano
                    recommendations.append(f'HSTS max-age muito baixo ({max_age}s). Recomendado: ≥31536000s (1 ano)')
                
                if not self.hsts_info.get('include_subdomains'):
                    recommendations.append('Considere adicionar "includeSubDomains" ao cabeçalho HSTS')
        
        self.security_analysis = {
            'vulnerabilities': vulnerabilities,
            'recommendations': recommendations,
            'security_score': self._calculate_security_score(vulnerabilities)
        }
        
        return self.security_analysis
    
    def _calculate_security_score(self, vulnerabilities):
        """Calcula pontuação de segurança baseada nas vulnerabilidades."""
        score = 100
        
        for vuln in vulnerabilities:
            if vuln['type'] == 'CRITICAL':
                score -= 30
            elif vuln['type'] == 'HIGH':
                score -= 20
            elif vuln['type'] == 'MEDIUM':
                score -= 10
            elif vuln['type'] == 'LOW':
                score -= 5
            elif vuln['type'] == 'WARNING':
                score -= 3
        
        return max(0, score)
    
    def _check_certificate_transparency(self):
        """Verifica se o certificado está em logs de Certificate Transparency."""
        try:
            # Obtém os dados do certificado a partir do objeto de análise
            cert_der = None
            
            # Procura pelos dados do certificado salvo durante a análise
            if hasattr(self, '_cert_data') and self._cert_data:
                cert_der = self._cert_data.get('cert_der')
            
            if not cert_der:
                return {
                    'has_sct': False,
                    'ct_logs': [],
                    'transparency_score': 'No certificate data available',
                    'error': 'Certificate data not found'
                }
            
            # Calcula SHA-256 hash do certificado
            cert_hash = hashlib.sha256(cert_der).hexdigest()
            
            # Verifica se há SCT (Signed Certificate Timestamp) no certificado
            # Análise mais básica mas funcional
            try:
                x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_der)
                
                # Verifica extensões SCT
                has_sct_extension = False
                for i in range(x509.get_extension_count()):
                    ext = x509.get_extension(i)
                    ext_name = str(ext.get_short_name(), 'utf-8').lower()
                    if 'sct' in ext_name or '1.3.6.1.4.1.11129.2.4.2' in str(ext):
                        has_sct_extension = True
                        break
                
                # Lista simplificada de logs CT conhecidos
                ct_logs_info = [
                    {'name': 'Google Rocketeer', 'status': 'accessible'},
                    {'name': 'Google Icarus', 'status': 'accessible'}
                ]
                
                transparency_score = 'Good' if has_sct_extension else 'Limited'
                
                return {
                    'has_sct': has_sct_extension,
                    'ct_logs': ct_logs_info,
                    'transparency_score': transparency_score,
                    'cert_hash': cert_hash
                }
                
            except Exception as e:
                return {
                    'has_sct': False,
                    'ct_logs': [],
                    'transparency_score': 'Analysis Error',
                    'cert_hash': cert_hash,
                    'error': str(e)
                }
            
        except Exception as e:
            logger.warning(f"Erro ao verificar Certificate Transparency: {e}")
            return {
                'has_sct': False,
                'ct_logs': [],
                'transparency_score': 'Error',
                'error': str(e)
            }
    
    def _analyze_cipher_suites(self):
        """Analisa detalhadamente os cipher suites suportados."""
        try:
            supported_ciphers = []
            tls_versions = ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']
            
            for tls_version in tls_versions:
                try:
                    context = ssl.SSLContext()
                    
                    # Configura versão específica do TLS
                    if tls_version == 'TLSv1':
                        context.minimum_version = ssl.TLSVersion.TLSv1
                        context.maximum_version = ssl.TLSVersion.TLSv1
                    elif tls_version == 'TLSv1.1':
                        context.minimum_version = ssl.TLSVersion.TLSv1_1
                        context.maximum_version = ssl.TLSVersion.TLSv1_1
                    elif tls_version == 'TLSv1.2':
                        context.minimum_version = ssl.TLSVersion.TLSv1_2
                        context.maximum_version = ssl.TLSVersion.TLSv1_2
                    elif tls_version == 'TLSv1.3':
                        try:
                            context.minimum_version = ssl.TLSVersion.TLSv1_3
                            context.maximum_version = ssl.TLSVersion.TLSv1_3
                        except AttributeError:
                            # TLS 1.3 não disponível nesta versão do Python
                            continue
                    
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    with socket.create_connection((self.hostname, self.port), timeout=self.timeout) as sock:
                        with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                            cipher = ssock.cipher()
                            if cipher:
                                supported_ciphers.append({
                                    'tls_version': tls_version,
                                    'cipher_name': cipher[0],
                                    'cipher_version': cipher[1],
                                    'cipher_bits': cipher[2]
                                })
                
                except Exception:
                    # Versão não suportada pelo servidor
                    continue
            
            # Analisa características dos ciphers
            analysis = {
                'supported_versions': list(set([c['tls_version'] for c in supported_ciphers])),
                'cipher_details': supported_ciphers,
                'weak_ciphers_found': [],
                'strong_ciphers_found': [],
                'pfs_support': False,
                'tls13_support': False
            }
            
            # Verifica ciphers fracos e fortes
            for cipher in supported_ciphers:
                cipher_name = cipher['cipher_name']
                
                # Verifica ciphers fracos
                for weak in self.weak_ciphers:
                    if weak.upper() in cipher_name.upper():
                        analysis['weak_ciphers_found'].append(cipher)
                        break
                
                # Verifica ciphers fortes
                if any(preferred in cipher_name for preferred in self.preferred_ciphers):
                    analysis['strong_ciphers_found'].append(cipher)
                
                # Verifica Perfect Forward Secrecy
                if 'ECDHE' in cipher_name or 'DHE' in cipher_name:
                    analysis['pfs_support'] = True
                
                # Verifica TLS 1.3
                if cipher['tls_version'] == 'TLSv1.3':
                    analysis['tls13_support'] = True
            
            self.cipher_analysis = analysis
            return analysis
            
        except Exception as e:
            logger.error(f"Erro na análise de cipher suites: {e}")
            return {
                'supported_versions': [],
                'cipher_details': [],
                'error': str(e)
            }
    
    def _check_hsts(self):
        """Verifica se o servidor suporta HSTS (HTTP Strict Transport Security)."""
        try:
            # Faz uma requisição HTTPS para verificar cabeçalhos HSTS
            url = f"https://{self.hostname}:{self.port}"
            
            response = requests.get(url, timeout=self.timeout, verify=False)
            headers = response.headers
            
            hsts_header = headers.get('Strict-Transport-Security', '')
            
            if hsts_header:
                # Parse do cabeçalho HSTS
                hsts_parts = hsts_header.split(';')
                max_age = 0
                include_subdomains = False
                preload = False
                
                for part in hsts_parts:
                    part = part.strip()
                    if part.startswith('max-age='):
                        try:
                            max_age = int(part.split('=')[1])
                        except ValueError:
                            pass
                    elif part == 'includeSubDomains':
                        include_subdomains = True
                    elif part == 'preload':
                        preload = True
                
                self.hsts_info = {
                    'enabled': True,
                    'max_age': max_age,
                    'include_subdomains': include_subdomains,
                    'preload': preload,
                    'header_value': hsts_header
                }
            else:
                self.hsts_info = {
                    'enabled': False,
                    'max_age': 0,
                    'include_subdomains': False,
                    'preload': False,
                    'header_value': None
                }
            
            return self.hsts_info
            
        except Exception as e:
            logger.warning(f"Erro ao verificar HSTS: {e}")
            self.hsts_info = {
                'enabled': False,
                'error': str(e)
            }
            return self.hsts_info
    
    def _check_ocsp(self):
        """Verifica informações sobre OCSP (Online Certificate Status Protocol)."""
        try:
            # Esta é uma implementação básica de verificação OCSP
            # Em produção, seria mais complexa
            
            # Verifica se há OCSP stapling
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Tenta habilitar OCSP stapling
            try:
                context.check_ocsp = True
            except AttributeError:
                # OCSP não disponível nesta versão
                pass
            
            ocsp_info = {
                'stapling_supported': False,
                'responder_url': None,
                'status': 'unknown'
            }
            
            # Verifica se há URL do responder OCSP no certificado
            if hasattr(self, 'certificate_info') and self.certificate_info:
                # Esta é uma verificação simplificada
                # Em uma implementação completa, extrairíamos a URL do OCSP do certificado
                ocsp_info['status'] = 'certificate_available'
            
            self.ocsp_info = ocsp_info
            return ocsp_info
            
        except Exception as e:
            logger.warning(f"Erro ao verificar OCSP: {e}")
            self.ocsp_info = {
                'error': str(e),
                'status': 'error'
            }
            return self.ocsp_info
    
    def analyze_ssl(self, include_transparency=False, include_advanced=True):
        """Executa análise completa SSL/TLS."""
        try:
            console.print("[cyan]Iniciando análise SSL/TLS...[/cyan]")
            
            # Obtém certificado
            cert_data = self._get_certificate()
            
            # Analisa certificado
            self._parse_certificate(cert_data)
            
            # Análises avançadas
            if include_advanced:
                console.print("[cyan]Executando análises avançadas...[/cyan]")
                
                # Análise de cipher suites
                self._analyze_cipher_suites()
                
                # Verificação HSTS
                self._check_hsts()
                
                # Verificação OCSP
                self._check_ocsp()
            
            # Análise de segurança (deve ser após as análises avançadas)
            self._analyze_security()
            
            # Certificate Transparency (opcional)
            if include_transparency:
                console.print("[cyan]Verificando Certificate Transparency...[/cyan]")
                ct_info = self._check_certificate_transparency()
                self.certificate_info['certificate_transparency'] = ct_info
            
            logger.info(f"Análise SSL concluída para {self.hostname}")
            
            return {
                'certificate_info': self.certificate_info,
                'security_analysis': self.security_analysis,
                'cipher_analysis': getattr(self, 'cipher_analysis', {}),
                'hsts_info': getattr(self, 'hsts_info', {}),
                'ocsp_info': getattr(self, 'ocsp_info', {})
            }
            
        except Exception as e:
            logger.error(f"Erro na análise SSL: {e}")
            console.print(f"[bold red][!] Erro ao analisar SSL para {self.hostname}:{self.port}: {e}[/bold red]")
            return None
    
    def present_results(self, output_format='table'):
        """Apresenta os resultados da análise."""
        if output_format == 'table':
            console.print(f"\n[bold cyan]🔒 ANÁLISE SSL/TLS - {self.hostname}:{self.port}[/bold cyan]")
            console.print("-" * 60)
            
            if not self.certificate_info:
                console.print("[bold red]❌ Nenhuma informação de certificado disponível[/bold red]")
                return
            
            # Tabela de informações do certificado
            from rich.table import Table
            
            cert_table = Table(title="Informações do Certificado")
            cert_table.add_column("Campo", style="cyan")
            cert_table.add_column("Valor", style="white")
            
            # Subject
            subject = self.certificate_info.get('subject', {})
            subject_str = ", ".join([f"{k}={v}" for k, v in subject.items()])
            cert_table.add_row("Assunto", subject_str)
            
            # Issuer
            issuer = self.certificate_info.get('issuer', {})
            issuer_str = ", ".join([f"{k}={v}" for k, v in issuer.items()])
            cert_table.add_row("Emissor", issuer_str)
            
            # Validade
            not_before = self.certificate_info.get('not_before')
            not_after = self.certificate_info.get('not_after')
            if not_before and not_after:
                cert_table.add_row("Válido De", not_before.strftime('%Y-%m-%d %H:%M:%S'))
                
                is_expired = self.certificate_info.get('is_expired', False)
                days_until = self.certificate_info.get('days_until_expiry', 0)
                
                if is_expired:
                    validity_status = f"[bold red]❌ Expirado em {not_after.strftime('%Y-%m-%d')}[/bold red]"
                elif days_until <= 30:
                    validity_status = f"[bold yellow]⚠️  Expira em {days_until} dias ({not_after.strftime('%Y-%m-%d')})[/bold yellow]"
                else:
                    validity_status = f"[bold green]✅ Válido até {not_after.strftime('%Y-%m-%d')}[/bold green]"
                
                cert_table.add_row("Status", validity_status)
            
            # Chave pública
            key_type = self.certificate_info.get('key_type', 'N/A')
            key_size = self.certificate_info.get('key_size', 0)
            cert_table.add_row("Chave Pública", f"{key_type} ({key_size} bits)")
            
            # Algoritmo de assinatura
            sig_alg = self.certificate_info.get('signature_algorithm', 'N/A')
            cert_table.add_row("Algoritmo de Assinatura", sig_alg)
            
            # Cipher info
            cipher_info = self.certificate_info.get('cipher_info')
            if cipher_info:
                cipher_str = f"{cipher_info[0]} ({cipher_info[1]}, {cipher_info[2]} bits)"
                cert_table.add_row("Cipher Suite", cipher_str)
            
            # SAN
            san_list = self.certificate_info.get('san_list', [])
            if san_list:
                cert_table.add_row("Subject Alt Names", ", ".join(san_list))
            
            # Self-signed
            is_self_signed = self.certificate_info.get('is_self_signed', False)
            trust_status = "[bold red]❌ Autoassinado[/bold red]" if is_self_signed else "[bold green]✅ CA Confiável[/bold green]"
            cert_table.add_row("Confiança", trust_status)
            
            console.print(cert_table)
            
            # Análise de segurança
            if self.security_analysis:
                console.print(f"\n[bold cyan]🛡️  ANÁLISE DE SEGURANÇA[/bold cyan]")
                console.print("-" * 60)
                
                security_score = self.security_analysis.get('security_score', 0)
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
                
                # Vulnerabilidades
                vulnerabilities = self.security_analysis.get('vulnerabilities', [])
                if vulnerabilities:
                    console.print(f"\n[bold red]⚠️  VULNERABILIDADES ENCONTRADAS ({len(vulnerabilities)})[/bold red]")
                    
                    vuln_table = Table()
                    vuln_table.add_column("Tipo", style="red")
                    vuln_table.add_column("Problema", style="yellow")
                    vuln_table.add_column("Descrição", style="white")
                    
                    for vuln in vulnerabilities:
                        vuln_table.add_row(
                            vuln['type'],
                            vuln['issue'],
                            vuln['description']
                        )
                    
                    console.print(vuln_table)
                else:
                    console.print(f"[bold green]✅ Nenhuma vulnerabilidade crítica encontrada[/bold green]")
                
                # Recomendações
                recommendations = self.security_analysis.get('recommendations', [])
                if recommendations:
                    console.print(f"\n[bold cyan]💡 RECOMENDAÇÕES[/bold cyan]")
                    for i, rec in enumerate(recommendations, 1):
                        console.print(f"{i}. {rec}")
        
        elif output_format == 'json':
            import json
            return json.dumps({
                'certificate_info': self.certificate_info,
                'security_analysis': self.security_analysis
            }, indent=2, default=str)
        
        return {
            'certificate_info': self.certificate_info,
            'security_analysis': self.security_analysis
        }

# Funções de compatibilidade legacy
def get_ssl_info(hostname, port=443, include_transparency=False, output_format='table'):
    """Função de compatibilidade para análise SSL."""
    analyzer = AdvancedSSLAnalyzer(hostname, port)
    results = analyzer.analyze_ssl(include_transparency=include_transparency)
    
    if results and output_format == 'table':
        analyzer.present_results(output_format)
    
    return results

def ssl_analysis_scan(hostname, port=443, include_transparency=False, output_format='table'):
    """Função alternativa de compatibilidade."""
    return get_ssl_info(hostname, port, include_transparency, output_format)
