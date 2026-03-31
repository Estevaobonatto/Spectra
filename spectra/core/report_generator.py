# -*- coding: utf-8 -*-
"""
Report Generator Module
Módulo para geração de relatórios em diferentes formatos (JSON, XML, HTML, PDF).
"""

import html
import json
import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom
from datetime import datetime
from pathlib import Path
import os
from typing import List, Dict, Any, Optional

from ..core.logger import get_logger
from .config import Config

_config = Config()
_VERSION = f"Spectra v{_config.version}"

# Aliases de severidade normalizados para pt-BR/en — múltiplos módulos usam variantes diferentes
_CRITICAL_ALIASES = {'crítico', 'crítica', 'critico', 'critica', 'critical'}
_HIGH_ALIASES = {'alto', 'alta', 'high'}
_MEDIUM_ALIASES = {'médio', 'média', 'medio', 'media', 'medium'}
_LOW_ALIASES = {'baixo', 'baixa', 'low'}


def _normalize_risk(value: str) -> str:
    """Normaliza uma string de risco para o padrão pt-BR usado no relatório."""
    v = value.strip().lower()
    if v in _CRITICAL_ALIASES:
        return 'Crítico'
    if v in _HIGH_ALIASES:
        return 'Alto'
    if v in _MEDIUM_ALIASES:
        return 'Médio'
    if v in _LOW_ALIASES:
        return 'Baixo'
    return value  # mantém original se não reconhecido


class ReportGenerator:
    """Gerador de relatórios avançado em múltiplos formatos."""

    def __init__(self, scan_results: List[Dict[str, Any]], target_url: str, scan_type: str):
        self.scan_results = scan_results
        self.target_url = target_url
        self.scan_type = scan_type
        self.timestamp = datetime.now()
        self.logger = get_logger(__name__)
        
        # Estatísticas calculadas
        self.stats = self._calculate_comprehensive_statistics()

    def _calculate_comprehensive_statistics(self) -> Dict[str, Any]:
        """Calcula estatísticas abrangentes dos resultados."""
        if not self.scan_results:
            return {
                "total_vulnerabilities": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "risk_score": 0.0,
                "compliance_status": "COMPLIANT"
            }
        
        total = len(self.scan_results)
        critical = len([v for v in self.scan_results if v.get('Risco', '').strip().lower() in _CRITICAL_ALIASES])
        high = len([v for v in self.scan_results if v.get('Risco', '').strip().lower() in _HIGH_ALIASES])
        medium = len([v for v in self.scan_results if v.get('Risco', '').strip().lower() in _MEDIUM_ALIASES])
        low = len([v for v in self.scan_results if v.get('Risco', '').strip().lower() in _LOW_ALIASES])
        
        # Cálculo de score de risco (0-100)
        risk_score = (critical * 10 + high * 7 + medium * 4 + low * 1) / max(total, 1)
        risk_score = min(risk_score * 10, 100.0)
        
        # Status de compliance
        if critical > 0 or high > 3:
            compliance = "NON-COMPLIANT"
        elif high > 0 or medium > 5:
            compliance = "PARTIALLY COMPLIANT"
        else:
            compliance = "COMPLIANT"
        
        return {
            "total_vulnerabilities": total,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "risk_score": round(risk_score, 2),
            "compliance_status": compliance
        }

    def generate_json_report(self, output_file: str = None) -> str:
        """Gera relatório em formato JSON."""
        if not output_file:
            output_file = f"spectra_report_{self.scan_type}_{self.timestamp.strftime('%Y%m%d_%H%M%S')}.json"

        # Estrutura do relatório JSON
        report_data = {
            "scan_info": {
                "target_url": self.target_url,
                "scan_type": self.scan_type,
                "timestamp": self.timestamp.isoformat(),
                "total_vulnerabilities": len(self.scan_results),
                "scanner_version": _VERSION,
                "duration": getattr(self, 'scan_duration', 'N/A')
            },
            "summary": {
                "risk_distribution": self._calculate_risk_distribution(),
                "vulnerability_types": self._calculate_vulnerability_types(),
                "confidence_levels": self._calculate_confidence_levels()
            },
            "vulnerabilities": self.scan_results,
            "recommendations": self._generate_recommendations(),
            "metadata": {
                "report_format": "JSON",
                "generated_by": "Spectra Security Scanner",
                "report_id": f"SPECTRA-{self.timestamp.strftime('%Y%m%d%H%M%S')}"
            }
        }

        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)
            
            self.logger.info(f"Relatório JSON gerado: {output_file}")
            return output_file
        except Exception as e:
            self.logger.error(f"Erro ao gerar relatório JSON: {e}")
            raise

    def generate_xml_report(self, output_file: str = None) -> str:
        """Gera relatório em formato XML."""
        if not output_file:
            output_file = f"spectra_report_{self.scan_type}_{self.timestamp.strftime('%Y%m%d_%H%M%S')}.xml"

        # Criar elemento raiz
        root = ET.Element("SpectraSecurityReport")
        root.set("version", "1.0.0")
        root.set("generated", self.timestamp.isoformat())

        # Informações do scan
        scan_info = ET.SubElement(root, "ScanInfo")
        ET.SubElement(scan_info, "TargetURL").text = self.target_url
        ET.SubElement(scan_info, "ScanType").text = self.scan_type
        ET.SubElement(scan_info, "Timestamp").text = self.timestamp.isoformat()
        ET.SubElement(scan_info, "TotalVulnerabilities").text = str(len(self.scan_results))
        ET.SubElement(scan_info, "ScannerVersion").text = _VERSION

        # Resumo
        summary = ET.SubElement(root, "Summary")
        
        # Distribuição de riscos
        risk_dist = ET.SubElement(summary, "RiskDistribution")
        for risk, count in self._calculate_risk_distribution().items():
            risk_elem = ET.SubElement(risk_dist, "Risk")
            risk_elem.set("level", risk)
            risk_elem.text = str(count)

        # Tipos de vulnerabilidades
        vuln_types = ET.SubElement(summary, "VulnerabilityTypes")
        for vuln_type, count in self._calculate_vulnerability_types().items():
            type_elem = ET.SubElement(vuln_types, "Type")
            type_elem.set("name", vuln_type)
            type_elem.text = str(count)

        # Vulnerabilidades
        vulnerabilities = ET.SubElement(root, "Vulnerabilities")
        for i, vuln in enumerate(self.scan_results):
            vuln_elem = ET.SubElement(vulnerabilities, "Vulnerability")
            vuln_elem.set("id", str(i + 1))
            
            for key, value in vuln.items():
                if isinstance(value, (str, int, float)):
                    elem = ET.SubElement(vuln_elem, key.replace(' ', '_'))
                    elem.text = str(value)
                elif isinstance(value, dict):
                    dict_elem = ET.SubElement(vuln_elem, key.replace(' ', '_'))
                    for sub_key, sub_value in value.items():
                        sub_elem = ET.SubElement(dict_elem, sub_key.replace(' ', '_'))
                        sub_elem.text = str(sub_value)

        # Recomendações
        recommendations = ET.SubElement(root, "Recommendations")
        for category, recs in self._generate_recommendations().items():
            cat_elem = ET.SubElement(recommendations, "Category")
            cat_elem.set("name", category)
            for rec in recs:
                rec_elem = ET.SubElement(cat_elem, "Recommendation")
                rec_elem.text = rec

        try:
            # Formatação do XML
            self._indent_xml(root)
            tree = ET.ElementTree(root)
            tree.write(output_file, encoding='utf-8', xml_declaration=True)
            
            self.logger.info(f"Relatório XML gerado: {output_file}")
            return output_file
        except Exception as e:
            self.logger.error(f"Erro ao gerar relatório XML: {e}")
            raise

    def generate_html_report(self, output_file: str = None) -> str:
        """Gera relatório em formato HTML."""
        if not output_file:
            output_file = f"spectra_report_{self.scan_type}_{self.timestamp.strftime('%Y%m%d_%H%M%S')}.html"

        risk_dist = self._calculate_risk_distribution()
        vuln_types = self._calculate_vulnerability_types()
        
        html_content = f"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Relatório de Segurança - Spectra</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
        }}
        .header p {{
            margin: 10px 0 0 0;
            opacity: 0.9;
            font-size: 1.1em;
        }}
        .content {{
            padding: 30px;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }}
        .summary-card h3 {{
            margin: 0 0 10px 0;
            color: #667eea;
            font-size: 1.2em;
        }}
        .risk-critical {{ background-color: #dc3545; color: white; }}
        .risk-alto {{ background-color: #fd7e14; color: white; }}
        .risk-medio {{ background-color: #ffc107; color: black; }}
        .risk-baixo {{ background-color: #28a745; color: white; }}
        .vuln-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        .vuln-table th, .vuln-table td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }}
        .vuln-table th {{
            background-color: #667eea;
            color: white;
            font-weight: 600;
        }}
        .vuln-table tr:hover {{
            background-color: #f8f9fa;
        }}
        .risk-badge {{
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .recommendations {{
            background: #e7f3ff;
            padding: 20px;
            border-radius: 8px;
            margin-top: 30px;
            border-left: 4px solid #007bff;
        }}
        .recommendations h3 {{
            color: #007bff;
            margin-top: 0;
        }}
        .recommendations ul {{
            padding-left: 20px;
        }}
        .recommendations li {{
            margin-bottom: 8px;
        }}
        .footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #6c757d;
            border-top: 1px solid #dee2e6;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Relatório de Segurança</h1>
            <p>Gerado por {html.escape(_VERSION)}</p>
            <p>Alvo: {html.escape(self.target_url)} | Tipo: {html.escape(self.scan_type)} | Data: {self.timestamp.strftime('%d/%m/%Y %H:%M:%S')}</p>
        </div>
        
        <div class="content">
            <div class="summary">
                <div class="summary-card">
                    <h3>📊 Total de Vulnerabilidades</h3>
                    <div style="font-size: 2em; font-weight: bold;">{len(self.scan_results)}</div>
                </div>
                <div class="summary-card">
                    <h3>🔴 Críticas</h3>
                    <div style="font-size: 2em; font-weight: bold; color: #dc3545;">{risk_dist.get('Crítico', 0)}</div>
                </div>
                <div class="summary-card">
                    <h3>🟠 Altas</h3>
                    <div style="font-size: 2em; font-weight: bold; color: #fd7e14;">{risk_dist.get('Alto', 0)}</div>
                </div>
                <div class="summary-card">
                    <h3>🟡 Médias</h3>
                    <div style="font-size: 2em; font-weight: bold; color: #ffc107;">{risk_dist.get('Médio', 0)}</div>
                </div>
            </div>

            <h2>🔍 Vulnerabilidades Detectadas</h2>
            <table class="vuln-table">
                <thead>
                    <tr>
                        <th>Risco</th>
                        <th>Tipo</th>
                        <th>Detalhe</th>
                        <th>Recomendação</th>
                    </tr>
                </thead>
                <tbody>
        """

        # Adicionar vulnerabilidades à tabela
        for vuln in self.scan_results:
            raw_risk = _normalize_risk(vuln.get('Risco', ''))
            risk_class = f"risk-{raw_risk.lower()}"
            safe_risk = html.escape(raw_risk or 'N/A')
            safe_tipo = html.escape(str(vuln.get('Tipo', 'N/A')))
            safe_detalhe = html.escape(str(vuln.get('Detalhe', 'N/A')))
            safe_rec = html.escape(str(vuln.get('Recomendação', 'N/A')))
            html_content += f"""
                    <tr>
                        <td><span class="risk-badge {risk_class}">{safe_risk}</span></td>
                        <td>{safe_tipo}</td>
                        <td>{safe_detalhe}</td>
                        <td>{safe_rec}</td>
                    </tr>
            """

        html_content += """
                </tbody>
            </table>

            <div class="recommendations">
                <h3>💡 Recomendações de Segurança</h3>
        """

        # Adicionar recomendações
        recommendations = self._generate_recommendations()
        for category, recs in recommendations.items():
            html_content += f"<h4>{category}</h4><ul>"
            for rec in recs:
                html_content += f"<li>{rec}</li>"
            html_content += "</ul>"

        html_content += f"""
            </div>
        </div>
        
        <div class="footer">
            <p>Relatório gerado em {self.timestamp.strftime('%d/%m/%Y às %H:%M:%S')} | 
            ID do Relatório: SPECTRA-{self.timestamp.strftime('%Y%m%d%H%M%S')}</p>
        </div>
    </div>
</body>
</html>
        """

        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.logger.info(f"Relatório HTML gerado: {output_file}")
            return output_file
        except Exception as e:
            self.logger.error(f"Erro ao gerar relatório HTML: {e}")
            raise

    def _calculate_risk_distribution(self) -> Dict[str, int]:
        """Calcula a distribuição de riscos."""
        distribution = {"Crítico": 0, "Alto": 0, "Médio": 0, "Baixo": 0}
        for vuln in self.scan_results:
            risk = vuln.get('Risco', 'Baixo')
            if risk in distribution:
                distribution[risk] += 1
        return distribution

    def _calculate_vulnerability_types(self) -> Dict[str, int]:
        """Calcula a distribuição de tipos de vulnerabilidades."""
        types = {}
        for vuln in self.scan_results:
            vuln_type = vuln.get('Tipo', 'Unknown')
            types[vuln_type] = types.get(vuln_type, 0) + 1
        return types

    def _calculate_confidence_levels(self) -> Dict[str, int]:
        """Calcula a distribuição de níveis de confiança."""
        confidence = {"High": 0, "Medium": 0, "Low": 0}
        for vuln in self.scan_results:
            conf = vuln.get('Confidence', 'Medium')
            if conf in confidence:
                confidence[conf] += 1
        return confidence

    def _generate_recommendations(self) -> Dict[str, List[str]]:
        """Gera recomendações baseadas nos resultados."""
        recommendations = {
            "Ações Imediatas": [
                "Revisar e corrigir vulnerabilidades de risco crítico e alto",
                "Implementar validação de entrada em todos os parâmetros",
                "Atualizar bibliotecas e frameworks para versões mais recentes",
                "Configurar Web Application Firewall (WAF)"
            ],
            "Melhorias de Segurança": [
                "Implementar Content Security Policy (CSP)",
                "Configurar headers de segurança HTTP",
                "Estabelecer processo de code review",
                "Implementar testes de segurança automatizados",
                "Configurar monitoramento de segurança em tempo real"
            ],
            "Boas Práticas": [
                "Princípio do menor privilégio",
                "Segregação de ambientes (dev/test/prod)",
                "Backup regular dos dados",
                "Documentação de configurações de segurança",
                "Treinamento de segurança para desenvolvedores"
            ]
        }
        return recommendations

    def _indent_xml(self, elem, level=0):
        """Formata XML com indentação."""
        i = "\n" + level * "  "
        if len(elem):
            if not elem.text or not elem.text.strip():
                elem.text = i + "  "
            if not elem.tail or not elem.tail.strip():
                elem.tail = i
            for child in elem:
                self._indent_xml(child, level + 1)
            if not child.tail or not child.tail.strip():
                child.tail = i
        else:
            if level and (not elem.tail or not elem.tail.strip()):
                elem.tail = i

    def generate_all_formats(self, base_filename: str = None) -> Dict[str, str]:
        """Gera relatórios em todos os formatos disponíveis."""
        if not base_filename:
            base_filename = f"spectra_report_{self.scan_type}_{self.timestamp.strftime('%Y%m%d_%H%M%S')}"
        
        generated_files = {}
        
        try:
            generated_files['json'] = self.generate_json_report(f"{base_filename}.json")
            generated_files['xml'] = self.generate_xml_report(f"{base_filename}.xml")
            generated_files['html'] = self.generate_html_report(f"{base_filename}.html")
            
            self.logger.info(f"Todos os formatos de relatório gerados com base: {base_filename}")
            return generated_files
        except Exception as e:
            self.logger.error(f"Erro ao gerar relatórios: {e}")
            raise


def generate_report(scan_results: List[Dict[str, Any]], target_url: str, scan_type: str, 
                   output_format: str = 'json', output_file: str = None) -> str:
    """
    Função utilitária para gerar relatórios.
    
    Args:
        scan_results: Lista de vulnerabilidades encontradas
        target_url: URL alvo do scan
        scan_type: Tipo de scan realizado
        output_format: Formato do relatório ('json', 'xml', 'html', 'all')
        output_file: Nome do arquivo de saída (opcional)
    
    Returns:
        str: Caminho do arquivo gerado ou dicionário com todos os caminhos se format='all'
    """
    generator = ReportGenerator(scan_results, target_url, scan_type)
    
    if output_format.lower() == 'json':
        return generator.generate_json_report(output_file)
    elif output_format.lower() == 'xml':
        return generator.generate_xml_report(output_file)
    elif output_format.lower() == 'html':
        return generator.generate_html_report(output_file)
    elif output_format.lower() == 'all':
        return generator.generate_all_formats(output_file)
    else:
        raise ValueError(f"Formato não suportado: {output_format}")
