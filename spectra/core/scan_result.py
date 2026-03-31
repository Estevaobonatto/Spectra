# -*- coding: utf-8 -*-
"""
Tipos centrais partilhados por todos os módulos de scan.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional, TypedDict


class SeverityLevel(str, Enum):
    """Níveis de severidade padronizados (CVSS-alinhado)."""
    CRITICAL = "Crítico"
    HIGH = "Alto"
    MEDIUM = "Médio"
    LOW = "Baixo"
    INFO = "Informativo"

    @classmethod
    def from_cvss(cls, score: float) -> "SeverityLevel":
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.INFO

    @classmethod
    def from_string(cls, value: str) -> "SeverityLevel":
        mapping = {
            "crítico": cls.CRITICAL,
            "critical": cls.CRITICAL,
            "alto": cls.HIGH,
            "high": cls.HIGH,
            "médio": cls.MEDIUM,
            "medio": cls.MEDIUM,
            "medium": cls.MEDIUM,
            "baixo": cls.LOW,
            "low": cls.LOW,
            "informativo": cls.INFO,
            "info": cls.INFO,
        }
        return mapping.get(value.lower(), cls.INFO)


class ScanResult(TypedDict, total=False):
    """Estrutura canônica de um achado de scan."""

    # Obrigatórios
    severity: str          # valor de SeverityLevel
    vuln_type: str         # ex: "SQL Injection", "XSS"
    url: str
    parameter: str
    method: str            # GET / POST / Headers / ...

    # Evidência
    payload: str
    evidence: str          # trecho da resposta que confirma o achado
    detection_method: str  # "pattern", "timing", "oast", "status_code"
    response_time: float   # segundos
    status_code: int
    content_length: int

    # Enriquecimento
    recommendation: str
    cwe: str               # ex: "CWE-89"
    cve_ids: List[str]
    confidence: str        # "High" / "Medium" / "Low"

    # OAST
    oast_interaction: Optional[str]
    blind_verified: bool

    # Metadados
    raw: Dict[str, Any]    # dados extras específicos do módulo


def make_finding(
    severity: SeverityLevel,
    vuln_type: str,
    url: str,
    parameter: str,
    method: str = "GET",
    **kwargs: Any,
) -> ScanResult:
    """Cria um ScanResult com os campos obrigatórios preenchidos."""
    result: ScanResult = {
        "severity": severity.value,
        "vuln_type": vuln_type,
        "url": url,
        "parameter": parameter,
        "method": method.upper(),
        "confidence": kwargs.pop("confidence", "Medium"),
    }
    result.update(kwargs)  # type: ignore[typeddict-item]
    return result
