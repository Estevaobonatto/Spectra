# -*- coding: utf-8 -*-
"""
CVE Integrator Module
Módulo para integração com bases de dados de vulnerabilidades (CVE).
"""

import requests
import json
import re
import time
from datetime import datetime
from typing import List, Dict, Any, Optional
from urllib.parse import quote

from ..core.logger import get_logger
from ..utils.network import create_session


class CVEIntegrator:
    """Integrador para consulta e enriquecimento com dados de CVE."""

    def __init__(self):
        self.session = create_session()
        self.logger = get_logger(__name__)
        self.cache = {}  # Cache para evitar consultas repetidas
        
        # APIs disponíveis para consulta CVE
        self.apis = {
            'nvd': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
            'circl': 'https://cve.circl.lu/api/cve',
            'cve_details': 'https://www.cvedetails.com/json-feed.php'
        }

    def search_cve_by_keyword(self, keyword: str, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Busca CVEs por palavra-chave.
        
        Args:
            keyword: Palavra-chave para busca (ex: 'SQL injection', 'XSS', 'command injection')
            limit: Número máximo de resultados
            
        Returns:
            Lista de CVEs encontrados
        """
        try:
            # Usar API do NVD (National Vulnerability Database)
            url = f"{self.apis['nvd']}"
            params = {
                'keywordSearch': keyword,
                'resultsPerPage': limit,
                'startIndex': 0
            }
            
            response = self.session.get(url, params=params, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            cves = []
            
            if 'vulnerabilities' in data:
                for vuln in data['vulnerabilities']:
                    cve_data = vuln.get('cve', {})
                    cve_info = self._parse_nvd_cve(cve_data)
                    if cve_info:
                        cves.append(cve_info)
            
            self.logger.info(f"Encontrados {len(cves)} CVEs para '{keyword}'")
            return cves
            
        except Exception as e:
            self.logger.warning(f"Erro ao buscar CVEs por palavra-chave '{keyword}': {e}")
            return []

    def get_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Obtém detalhes específicos de um CVE.
        
        Args:
            cve_id: ID do CVE (ex: 'CVE-2023-1234')
            
        Returns:
            Detalhes do CVE ou None se não encontrado
        """
        if cve_id in self.cache:
            return self.cache[cve_id]
            
        try:
            # Tentar múltiplas APIs para obter informações completas
            cve_details = None
            
            # 1. Tentar API do NVD
            cve_details = self._get_from_nvd(cve_id)
            
            # 2. Se não encontrar, tentar CIRCL
            if not cve_details:
                cve_details = self._get_from_circl(cve_id)
            
            if cve_details:
                self.cache[cve_id] = cve_details
                
            return cve_details
            
        except Exception as e:
            self.logger.warning(f"Erro ao obter detalhes do CVE {cve_id}: {e}")
            return None

    def _get_from_nvd(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Obtém CVE da API do NVD."""
        try:
            url = f"{self.apis['nvd']}"
            params = {'cveId': cve_id}
            
            response = self.session.get(url, params=params, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            
            if 'vulnerabilities' in data and data['vulnerabilities']:
                cve_data = data['vulnerabilities'][0].get('cve', {})
                return self._parse_nvd_cve(cve_data)
                
        except Exception as e:
            self.logger.debug(f"Erro ao consultar NVD para {cve_id}: {e}")
            
        return None

    def _get_from_circl(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Obtém CVE da API do CIRCL."""
        try:
            url = f"{self.apis['circl']}/{cve_id}"
            
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            return self._parse_circl_cve(data)
            
        except Exception as e:
            self.logger.debug(f"Erro ao consultar CIRCL para {cve_id}: {e}")
            
        return None

    def _parse_nvd_cve(self, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse dos dados de CVE do NVD."""
        try:
            # Extrair informações básicas
            cve_id = cve_data.get('id', '')
            published = cve_data.get('published', '')
            modified = cve_data.get('lastModified', '')
            
            # Extrair descrição
            descriptions = cve_data.get('descriptions', [])
            description = ''
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            
            # Extrair CVSS scores
            metrics = cve_data.get('metrics', {})
            cvss_v3 = None
            cvss_v2 = None
            
            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                cvss_v3 = metrics['cvssMetricV31'][0].get('cvssData', {})
            elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                cvss_v3 = metrics['cvssMetricV30'][0].get('cvssData', {})
                
            if 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                cvss_v2 = metrics['cvssMetricV2'][0].get('cvssData', {})
            
            # Extrair weaknesses (CWE)
            weaknesses = []
            for weakness in cve_data.get('weaknesses', []):
                for desc in weakness.get('description', []):
                    if desc.get('lang') == 'en':
                        weaknesses.append(desc.get('value', ''))
            
            # Extrair referências
            references = []
            for ref in cve_data.get('references', []):
                references.append({
                    'url': ref.get('url', ''),
                    'source': ref.get('source', ''),
                    'tags': ref.get('tags', [])
                })
            
            return {
                'id': cve_id,
                'description': description,
                'published': published,
                'modified': modified,
                'cvss_v3': cvss_v3,
                'cvss_v2': cvss_v2,
                'weaknesses': weaknesses,
                'references': references,
                'source': 'NVD'
            }
            
        except Exception as e:
            self.logger.warning(f"Erro ao fazer parse do CVE do NVD: {e}")
            return {}

    def _parse_circl_cve(self, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse dos dados de CVE do CIRCL."""
        try:
            return {
                'id': cve_data.get('id', ''),
                'description': cve_data.get('summary', ''),
                'published': cve_data.get('Published', ''),
                'modified': cve_data.get('Modified', ''),
                'cvss': cve_data.get('cvss', ''),
                'cwe': cve_data.get('cwe', ''),
                'references': cve_data.get('references', []),
                'source': 'CIRCL'
            }
            
        except Exception as e:
            self.logger.warning(f"Erro ao fazer parse do CVE do CIRCL: {e}")
            return {}

    def enrich_vulnerability_with_cve(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enriquece uma vulnerabilidade encontrada com dados de CVE relevantes.
        
        Args:
            vulnerability: Dicionário com dados da vulnerabilidade
            
        Returns:
            Vulnerabilidade enriquecida com dados de CVE
        """
        # Mapear tipos de vulnerabilidade para termos de busca CVE
        vuln_type_mapping = {
            'SQL Injection': ['sql injection', 'sqli'],
            'XSS': ['cross-site scripting', 'xss'],
            'Command Injection': ['command injection', 'code injection'],
            'LFI': ['local file inclusion', 'directory traversal'],
            'RFI': ['remote file inclusion'],
            'SSRF': ['server-side request forgery', 'ssrf'],
            'Path Traversal': ['directory traversal', 'path traversal'],
            'XXE': ['xml external entity', 'xxe'],
            'CSRF': ['cross-site request forgery', 'csrf'],
            'Authentication Bypass': ['authentication bypass', 'auth bypass'],
            'Authorization': ['privilege escalation', 'access control']
        }
        
        vuln_type = vulnerability.get('Tipo', '')
        search_terms = vuln_type_mapping.get(vuln_type, [vuln_type.lower()])
        
        related_cves = []
        
        # Buscar CVEs relacionados
        for term in search_terms:
            if term:
                cves = self.search_cve_by_keyword(term, limit=3)
                related_cves.extend(cves)
                time.sleep(0.5)  # Rate limiting
        
        # Remover duplicatas
        unique_cves = []
        seen_ids = set()
        for cve in related_cves:
            if cve.get('id') not in seen_ids:
                unique_cves.append(cve)
                seen_ids.add(cve.get('id'))
        
        # Adicionar informações de CVE à vulnerabilidade
        enriched_vuln = vulnerability.copy()
        enriched_vuln['related_cves'] = unique_cves[:5]  # Limitar a 5 CVEs mais relevantes
        enriched_vuln['cve_count'] = len(unique_cves)
        
        # Calcular severity baseada nos CVEs relacionados
        if unique_cves:
            max_severity = self._calculate_max_severity(unique_cves)
            enriched_vuln['cve_max_severity'] = max_severity
            
            # Adicionar recomendações baseadas em CVEs
            enriched_vuln['cve_recommendations'] = self._generate_cve_recommendations(unique_cves)
        
        return enriched_vuln

    def _calculate_max_severity(self, cves: List[Dict[str, Any]]) -> str:
        """Calcula a severidade máxima baseada nos CVEs."""
        max_score = 0.0
        
        for cve in cves:
            score = 0.0
            
            # Tentar CVSS v3 primeiro
            if cve.get('cvss_v3') and 'baseScore' in cve['cvss_v3']:
                score = float(cve['cvss_v3']['baseScore'])
            # Fallback para CVSS v2
            elif cve.get('cvss_v2') and 'baseScore' in cve['cvss_v2']:
                score = float(cve['cvss_v2']['baseScore'])
            # Fallback para CVSS simples
            elif cve.get('cvss'):
                try:
                    score = float(cve['cvss'])
                except:
                    pass
            
            max_score = max(max_score, score)
        
        # Mapear score para severity
        if max_score >= 9.0:
            return 'CRITICAL'
        elif max_score >= 7.0:
            return 'HIGH'
        elif max_score >= 4.0:
            return 'MEDIUM'
        else:
            return 'LOW'

    def _generate_cve_recommendations(self, cves: List[Dict[str, Any]]) -> List[str]:
        """Gera recomendações baseadas nos CVEs relacionados."""
        recommendations = set()
        
        for cve in cves:
            # Analisar CWEs para gerar recomendações específicas
            weaknesses = cve.get('weaknesses', [])
            
            for weakness in weaknesses:
                if 'CWE-79' in weakness:  # XSS
                    recommendations.add("Implementar validação e sanitização de entrada adequada")
                    recommendations.add("Usar Content Security Policy (CSP)")
                elif 'CWE-89' in weakness:  # SQL Injection
                    recommendations.add("Usar prepared statements/parameterized queries")
                    recommendations.add("Implementar validação rigorosa de entrada")
                elif 'CWE-78' in weakness:  # Command Injection
                    recommendations.add("Evitar execução de comandos do sistema com entrada do usuário")
                    recommendations.add("Usar whitelist de comandos permitidos")
                elif 'CWE-22' in weakness:  # Path Traversal
                    recommendations.add("Validar e sanitizar caminhos de arquivo")
                    recommendations.add("Usar caminhos absolutos e canônicos")
                elif 'CWE-918' in weakness:  # SSRF
                    recommendations.add("Implementar whitelist de URLs permitidas")
                    recommendations.add("Validar e filtrar URLs de entrada")
        
        # Recomendações gerais se não houver específicas
        if not recommendations:
            recommendations.add("Atualizar para versão mais recente do software")
            recommendations.add("Implementar controles de segurança adequados")
            recommendations.add("Realizar testes de segurança regulares")
        
        return list(recommendations)

    def get_trending_vulnerabilities(self, days: int = 30) -> List[Dict[str, Any]]:
        """
        Obtém vulnerabilidades em tendência nos últimos N dias.
        
        Args:
            days: Número de dias para buscar vulnerabilidades recentes
            
        Returns:
            Lista de vulnerabilidades recentes
        """
        try:
            # Buscar CVEs publicados recentemente
            from datetime import datetime, timedelta
            
            end_date = datetime.now()
            start_date = end_date - timedelta(days=days)
            
            url = f"{self.apis['nvd']}"
            params = {
                'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
                'pubEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
                'resultsPerPage': 20,
                'startIndex': 0
            }
            
            response = self.session.get(url, params=params, timeout=15)
            response.raise_for_status()
            
            data = response.json()
            trending_cves = []
            
            if 'vulnerabilities' in data:
                for vuln in data['vulnerabilities']:
                    cve_data = vuln.get('cve', {})
                    cve_info = self._parse_nvd_cve(cve_data)
                    if cve_info:
                        trending_cves.append(cve_info)
            
            self.logger.info(f"Encontradas {len(trending_cves)} vulnerabilidades dos últimos {days} dias")
            return trending_cves
            
        except Exception as e:
            self.logger.warning(f"Erro ao buscar vulnerabilidades em tendência: {e}")
            return []


def integrate_cve_data(scan_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Função utilitária para integrar dados de CVE aos resultados de scan.
    
    Args:
        scan_results: Lista de vulnerabilidades encontradas no scan
        
    Returns:
        Lista de vulnerabilidades enriquecidas com dados de CVE
    """
    integrator = CVEIntegrator()
    enriched_results = []
    
    for vulnerability in scan_results:
        try:
            enriched_vuln = integrator.enrich_vulnerability_with_cve(vulnerability)
            enriched_results.append(enriched_vuln)
            time.sleep(0.1)  # Rate limiting para não sobrecarregar APIs
        except Exception as e:
            # Se falhar o enriquecimento, manter vulnerabilidade original
            enriched_results.append(vulnerability)
            continue
    
    return enriched_results
