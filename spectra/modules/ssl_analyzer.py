# -*- coding: utf-8 -*-
"""
Módulo de Análise SSL/TLS
Analisa certificados SSL/TLS e configurações de segurança
"""

import ssl
import socket
import json
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
        # Implementação básica - pode ser expandida
        try:
            # Esta é uma verificação simplificada
            # Em produção, você faria uma consulta real aos logs CT
            has_sct = False  # Simplified check
            
            return {
                'has_sct': has_sct,
                'ct_logs': [],
                'transparency_score': 'Unknown'
            }
        except Exception as e:
            logger.warning(f"Erro ao verificar Certificate Transparency: {e}")
            return {
                'has_sct': False,
                'ct_logs': [],
                'transparency_score': 'Error'
            }
    
    def analyze_ssl(self, include_transparency=False):
        """Executa análise completa SSL/TLS."""
        try:
            # Obtém certificado
            cert_data = self._get_certificate()
            
            # Analisa certificado
            self._parse_certificate(cert_data)
            
            # Análise de segurança
            self._analyze_security()
            
            # Certificate Transparency (opcional)
            if include_transparency:
                ct_info = self._check_certificate_transparency()
                self.certificate_info['certificate_transparency'] = ct_info
            
            logger.info(f"Análise SSL concluída para {self.hostname}")
            
            return {
                'certificate_info': self.certificate_info,
                'security_analysis': self.security_analysis
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
