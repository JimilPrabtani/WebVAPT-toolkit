"""
api/limiter.py
──────────────
Shared slowapi Limiter instance.
Importing from a single module prevents duplicate limiter creation
and ensures the same state is shared between main.py and routes.py.
"""

try:
    from slowapi import Limiter
    from slowapi.util import get_remote_address

    limiter = Limiter(key_func=get_remote_address)
    RATE_LIMITING_AVAILABLE = True

except ImportError:
    limiter = None
    RATE_LIMITING_AVAILABLE = False
