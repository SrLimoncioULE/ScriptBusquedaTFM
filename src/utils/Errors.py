# utils/Errors.py
from typing import Optional, Any, Dict

class ProviderError(Exception):
    """
    Error base para proveedores (APIs).
    Acepta:
      - ProviderError(provider, message, *, code=None, context=None)
      - ProviderError(provider=..., message=..., code=..., context=...)
      - ProviderError(message)  # retro-compat: provider='unknown'
    """
    def __init__(
        self,
        provider_or_message: Optional[str] = None,
        message: Optional[str] = None,
        *,
        code: Optional[int] = None,
        context: Optional[Dict[str, Any]] = None,
        provider: Optional[str] = None,   # <-- alias compatible
    ):
        # Normaliza proveedor y mensaje según cómo nos llamen
        if message is None:
            # Forma antigua: un solo string → es el mensaje
            prov = provider if provider is not None else "unknown"
            msg  = str(provider_or_message) if provider_or_message is not None else ""
        else:
            # Forma moderna: provider + message (posicional o keyword)
            prov = provider if provider is not None else (
                str(provider_or_message) if provider_or_message is not None else "unknown"
            )
            msg = str(message)

        self.provider: str = str(prov)
        self.message: str = msg
        self.code: Optional[int] = code
        self.context: Dict[str, Any] = context or {}

        super().__init__(f"[{self.provider}] {self.message}")

    def __str__(self) -> str:
        return f"[{self.provider}] {self.message}"

class ProviderRateLimitError(ProviderError):
    """Cuota/rate limit excedido (429/limit diario/etc.)."""
    pass

class ProviderBlockedError(ProviderError):
    """Bloqueo temporal/HTML WAF/anti-bot o redirect raro."""
    pass

class NetworkError(ProviderError):
    """Errores de red persistentes/timeouts."""
    pass

class SaveAndExitSignal(ProviderError):
    """Usa esto si implementas un botón 'parar y guardar'."""
    pass

class ProviderBadQueryError(ProviderError):
    pass