"""Shared SlowAPI limiter with a compatible no-op fallback."""

import logging

logger = logging.getLogger("sagedral_ml.api.rate_limit")


class _NoopLimiter:
    def limit(self, _rule):
        def decorator(function):
            return function

        return decorator


try:
    from slowapi import Limiter
    from slowapi.util import get_remote_address

    limiter = Limiter(key_func=get_remote_address)
    RATE_LIMITING_AVAILABLE = True
except Exception:
    limiter = _NoopLimiter()
    RATE_LIMITING_AVAILABLE = False
    logger.warning("slowapi tidak tersedia; API rate limiting dinonaktifkan.")

