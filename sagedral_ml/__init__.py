"""
SAGEDRAL-ML — Smart Adaptive Guardian for Enhanced Detection, Response, and Adaptive Learning - ML
"""

__version__ = "1.0.0"
__author__ = "Hercio Moreira"


def _apply_scapy_wsl_patch():
    """
    Bulletproof Scapy WSL compatibility patch.
    1. Sets conf.ipv6_enabled = False in Scapy config to bypass IPv6 route sync at startup.
    2. Safely wraps read_routes6 / read_routes to catch KeyError: 'scope' on WSL environments.
    """
    try:
        import scapy.config
        scapy.config.conf.ipv6_enabled = False
    except Exception:
        pass

    try:
        import sys
        import scapy.arch.linux.rtnetlink as _rtnetlink

        def _make_safe(fn):
            def _safe_fn(*args, **kwargs):
                try:
                    return fn(*args, **kwargs)
                except Exception:
                    return []
            _safe_fn._is_patched = True
            return _safe_fn

        for fn_name in ("read_routes", "read_routes6"):
            orig = getattr(_rtnetlink, fn_name, None)
            if orig is not None and not getattr(orig, "_is_patched", False):
                setattr(_rtnetlink, fn_name, _make_safe(orig))

        for mod_name in ("scapy.arch", "scapy.arch.linux", "scapy.route6"):
            if mod_name in sys.modules:
                mod = sys.modules[mod_name]
                for fn_name in ("read_routes", "read_routes6"):
                    orig = getattr(mod, fn_name, None)
                    if orig is not None and not getattr(orig, "_is_patched", False):
                        setattr(mod, fn_name, _make_safe(orig))
    except Exception:
        pass


_apply_scapy_wsl_patch()
