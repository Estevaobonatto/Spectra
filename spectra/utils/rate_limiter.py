# -*- coding: utf-8 -*-
"""
AdaptiveRateLimiter — controle de taxa adaptativo para módulos de scan.

Usa asyncio.Semaphore para controle de concorrência e backoff exponencial
quando o alvo retorna 429 / 503.

Uso síncrono:
    limiter = AdaptiveRateLimiter(requests_per_second=10)
    with limiter:
        response = session.get(url)

Uso com decorator:
    @with_retry(max_retries=3, backoff_factor=0.5)
    def fetch(url):
        return requests.get(url, timeout=10)
"""

from __future__ import annotations

import functools
import time
import threading
from typing import Callable, Optional, TypeVar

from ..core.logger import get_logger

logger = get_logger(__name__)

F = TypeVar("F", bound=Callable)


class AdaptiveRateLimiter:
    """
    Rate limiter síncrono com janela deslizante e backoff adaptativo.

    Aumenta automaticamente o delay quando detecta respostas 429/503,
    e reduz gradualmente quando o alvo responde normalmente.
    """

    def __init__(
        self,
        requests_per_second: float = 10.0,
        burst: int = 5,
        min_delay: float = 0.0,
        max_delay: float = 30.0,
    ) -> None:
        self._rps = requests_per_second
        self._burst = burst
        self._min_delay = min_delay
        self._max_delay = max_delay
        self._base_interval = 1.0 / requests_per_second if requests_per_second > 0 else 0
        self._current_delay = self._base_interval
        self._last_request_time = 0.0
        self._lock = threading.Lock()
        self._consecutive_429 = 0
        self._consecutive_ok = 0

    # ------------------------------------------------------------------
    # Context manager (uso síncrono)
    # ------------------------------------------------------------------

    def __enter__(self) -> "AdaptiveRateLimiter":
        self._wait()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def _wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_request_time
            wait_time = self._current_delay - elapsed
            if wait_time > 0:
                time.sleep(wait_time)
            self._last_request_time = time.monotonic()

    # ------------------------------------------------------------------
    # Feedback de resposta
    # ------------------------------------------------------------------

    def notify_response(self, status_code: int) -> None:
        """
        Informa o resultado de uma requisição para ajustar o rate.

        Args:
            status_code: Código HTTP da resposta.
        """
        with self._lock:
            if status_code in (429, 503):
                self._consecutive_429 += 1
                self._consecutive_ok = 0
                # Duplica o delay até max_delay
                self._current_delay = min(
                    self._current_delay * 2 + 0.5, self._max_delay
                )
                logger.debug(
                    f"RateLimiter: {status_code} recebido — delay aumentado para "
                    f"{self._current_delay:.2f}s"
                )
            else:
                self._consecutive_ok += 1
                if self._consecutive_429 > 0:
                    self._consecutive_429 = 0
                # Reduz gradualmente após 10 respostas OK consecutivas
                if self._consecutive_ok >= 10:
                    self._consecutive_ok = 0
                    self._current_delay = max(
                        self._current_delay * 0.8, self._base_interval
                    )
                    logger.debug(
                        f"RateLimiter: delay reduzido para {self._current_delay:.2f}s"
                    )

    @property
    def current_delay(self) -> float:
        return self._current_delay

    def reset(self) -> None:
        """Reseta o limiter para o estado inicial."""
        with self._lock:
            self._current_delay = self._base_interval
            self._consecutive_429 = 0
            self._consecutive_ok = 0


# ------------------------------------------------------------------
# Decorator with_retry
# ------------------------------------------------------------------

class _RetryableError(Exception):
    """Sinal interno para retry."""

    def __init__(self, cause: Exception) -> None:
        self.cause = cause


def with_retry(
    max_retries: int = 3,
    backoff_factor: float = 0.5,
    retryable_exceptions: tuple = (Exception,),
    retryable_status_codes: tuple = (429, 500, 502, 503, 504),
) -> Callable[[F], F]:
    """
    Decorator que adiciona retry com backoff exponencial.

    Args:
        max_retries: Número máximo de tentativas adicionais.
        backoff_factor: Multiplica o tempo de espera a cada tentativa.
        retryable_exceptions: Exceções que disparam retry.
        retryable_status_codes: Status codes que disparam retry
            (se a função retorna um objecto com .status_code).

    Exemplo:
        @with_retry(max_retries=3, backoff_factor=0.5)
        def fetch(url):
            return requests.get(url, timeout=10)
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_exc: Optional[Exception] = None
            for attempt in range(max_retries + 1):
                try:
                    result = func(*args, **kwargs)
                    # Verifica status code se disponível
                    status = getattr(result, "status_code", None)
                    if status is not None and status in retryable_status_codes:
                        wait = backoff_factor * (2 ** attempt)
                        logger.debug(
                            f"Retry #{attempt + 1} após status {status} "
                            f"em {func.__name__} (aguardando {wait:.1f}s)"
                        )
                        time.sleep(wait)
                        continue
                    return result
                except retryable_exceptions as exc:
                    last_exc = exc
                    if attempt < max_retries:
                        wait = backoff_factor * (2 ** attempt)
                        logger.debug(
                            f"Retry #{attempt + 1} após exceção em {func.__name__}: "
                            f"{exc} (aguardando {wait:.1f}s)"
                        )
                        time.sleep(wait)
            if last_exc:
                raise last_exc
            return None  # type: ignore[return-value]

        return wrapper  # type: ignore[return-value]

    return decorator
