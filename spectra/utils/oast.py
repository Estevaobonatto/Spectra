# -*- coding: utf-8 -*-
"""
OASTClient — Out-of-Band Application Security Testing

Implementa integração com o protocolo Interactsh
(https://github.com/projectdiscovery/interactsh) para detecção
de vulnerabilidades blind (SSRF blind, Blind XSS, OOB Command Injection, XXE blind).

Uso:
    client = OASTClient()
    host = client.generate_host()          # ex: abc123.oast.fun
    # ... dispara payload com host ...
    interactions = client.poll()           # verifica callbacks
"""

from __future__ import annotations

import hashlib
import os
import secrets
import threading
import time
import uuid
from typing import Dict, List, Optional
from urllib.parse import urljoin

try:
    import requests as _requests

    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

from ..core.logger import get_logger

logger = get_logger(__name__)


# Chave pública do servidor padrão de interactsh — usada apenas para o cliente REST
_DEFAULT_SERVER = os.environ.get("SPECTRA_OAST_SERVER", "https://oast.fun")
_FALLBACK_SERVERS = [
    "https://oast.live",
    "https://oast.site",
    "https://oast.online",
    "https://oast.fun",
]


class OASTInteraction(Dict):
    """Representa um callback OAST recebido."""

    @property
    def protocol(self) -> str:
        return self.get("protocol", "unknown")

    @property
    def remote_addr(self) -> str:
        return self.get("remote-address", "")

    @property
    def raw_request(self) -> str:
        return self.get("raw-request", "")


class OASTClient:
    """
    Cliente OAST com suporte ao protocolo Interactsh.

    Se nenhum servidor estiver disponível, entra em modo *manual*:
    o utilizador deve verificar as interações no painel do servidor.
    """

    def __init__(
        self,
        server: Optional[str] = None,
        timeout: int = 10,
        poll_interval: int = 5,
    ) -> None:
        self._server = (server or _DEFAULT_SERVER).rstrip("/")
        self._timeout = timeout
        self._poll_interval = poll_interval
        self._correlation_id: Optional[str] = None
        self._secret_key: Optional[str] = None
        self._payload_host: Optional[str] = None
        self._interactions: List[OASTInteraction] = []
        self._lock = threading.Lock()
        self._available: Optional[bool] = None  # None = não testado ainda
        self._manual_mode = False

        if not _HAS_REQUESTS:
            logger.warning("requests não disponível — OASTClient em modo manual")
            self._manual_mode = True

    # ------------------------------------------------------------------
    # Inicialização
    # ------------------------------------------------------------------

    def _try_server(self, server: str) -> bool:
        """Tenta registrar no servidor e retorna True se bem-sucedido."""
        try:
            import requests

            correlation_id = secrets.token_hex(16)
            secret_key = secrets.token_hex(32)
            resp = requests.post(
                f"{server}/register",
                json={"correlation-id": correlation_id, "secret-key": secret_key},
                timeout=self._timeout,
                verify=False,
            )
            if resp.status_code == 200:
                data = resp.json()
                self._correlation_id = correlation_id
                self._secret_key = secret_key
                domain = data.get("domain", "")
                if domain:
                    self._payload_host = f"{correlation_id}.{domain}"
                    self._server = server
                    return True
        except Exception as exc:
            logger.debug(f"OAST server {server} indisponível: {exc}")
        return False

    def _ensure_registered(self) -> bool:
        """Garante registro em algum servidor, tentando fallbacks."""
        if self._available is True:
            return True
        if self._manual_mode:
            return False

        # Tenta servidor primário
        if self._try_server(self._server):
            self._available = True
            return True

        # Tenta fallbacks
        for fb in _FALLBACK_SERVERS:
            if fb != self._server and self._try_server(fb):
                self._available = True
                return True

        logger.warning(
            "Nenhum servidor OAST disponível — interações blind não serão verificadas automaticamente. "
            "Configure SPECTRA_OAST_SERVER ou use um collaborator Burp Suite manualmente."
        )
        self._available = False
        self._manual_mode = True
        return False

    # ------------------------------------------------------------------
    # API pública
    # ------------------------------------------------------------------

    def generate_host(self, label: str = "") -> str:
        """
        Retorna um hostname OAST único para embutir em payloads.

        Em modo manual retorna um hostname fictício estilo Burp Collaborator
        que o utilizador deve configurar manualmente.
        """
        if self._ensure_registered() and self._payload_host:
            unique_id = secrets.token_hex(4)
            prefix = f"{label}-{unique_id}" if label else unique_id
            return f"{prefix}.{self._payload_host}"

        # Modo manual: gera identificador único para rastreamento
        unique = secrets.token_hex(8)
        tag = f"{label}-{unique}" if label else unique
        logger.info(
            f"[OAST manual] Use o host '{tag}.oast.example.com' no payload "
            "e verifique interações no seu servidor OAST/Collaborator."
        )
        return f"{tag}.oast.example.com"

    def poll(self) -> List[OASTInteraction]:
        """
        Consulta o servidor por novas interações.

        Returns:
            Lista de OASTInteraction recebidas desde o último poll.
        """
        if not self._ensure_registered():
            return []

        try:
            import requests

            resp = requests.get(
                f"{self._server}/poll",
                params={
                    "id": self._correlation_id,
                    "secret": self._secret_key,
                },
                timeout=self._timeout,
                verify=False,
            )
            if resp.status_code == 200:
                data = resp.json()
                items = data.get("data", [])
                interactions = [OASTInteraction(i) for i in items]
                with self._lock:
                    self._interactions.extend(interactions)
                return interactions
        except Exception as exc:
            logger.debug(f"Erro ao fazer poll OAST: {exc}")
        return []

    def wait_for_interaction(
        self, timeout: int = 30, expected_label: str = ""
    ) -> Optional[OASTInteraction]:
        """
        Aguarda por uma interação OAST por até `timeout` segundos.

        Args:
            timeout: Tempo máximo de espera em segundos.
            expected_label: Se fornecido, filtra por interações que contenham
                            este label no campo de requisição.

        Returns:
            Primeira interação correspondente ou None.
        """
        if not self._ensure_registered():
            return None

        deadline = time.time() + timeout
        while time.time() < deadline:
            interactions = self.poll()
            for interaction in interactions:
                if not expected_label or expected_label in interaction.raw_request:
                    return interaction
            time.sleep(self._poll_interval)
        return None

    def get_all_interactions(self) -> List[OASTInteraction]:
        """Retorna todas as interações coletadas até agora."""
        with self._lock:
            return list(self._interactions)

    @property
    def is_available(self) -> bool:
        """True se o servidor OAST está disponível."""
        return self._ensure_registered()

    def __repr__(self) -> str:
        status = "disponível" if self._available else "manual"
        host = self._payload_host or "N/A"
        return f"OASTClient(server={self._server!r}, host={host!r}, status={status})"
