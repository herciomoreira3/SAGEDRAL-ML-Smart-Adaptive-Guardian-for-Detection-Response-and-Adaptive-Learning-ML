[INFO] Creating directories...
[INFO] Initializing nftables sagedral table...
[INFO] Installing systemd service...
[WARN] System is not booted with systemd as PID 1 (WSL environment detected).
[WARN] Service file created at /etc/systemd/system/sagedral-ml.service
[INFO] To start SAGEDRAL-ML manually in WSL, run: sudo sagedral-ml start

================================================
  SAGEDRAL-ML installation completed!
================================================
Start service: systemctl start sagedral-ml
Web Dashboard: http://localhost:8000
(.venv) root@DESKTOP-KDF8R5K:~/sagedral-ml# sagedral-ml status
Traceback (most recent call last):
  File "/root/sagedral-ml/.venv/bin/sagedral-ml", line 3, in <module>
    from sagedral_ml.cli import main
  File "/root/sagedral-ml/sagedral_ml/cli.py", line 9, in <module>
    import requests
ModuleNotFoundError: No module named 'requests'
(.venv) root@DESKTOP-KDF8R5K:~/sagedral-ml# sudo sagedral-ml start
ERROR: Loading module scapy.layers.dcerpc
Traceback (most recent call last):
  File "/usr/local/lib/python3.10/dist-packages/scapy/main.py", line 312, in _load
    mod = importlib.import_module(module)
  File "/usr/lib/python3.10/importlib/__init__.py", line 126, in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
  File "<frozen importlib._bootstrap>", line 1050, in _gcd_import
  File "<frozen importlib._bootstrap>", line 1027, in _find_and_load
  File "<frozen importlib._bootstrap>", line 1006, in _find_and_load_unlocked
  File "<frozen importlib._bootstrap>", line 688, in _load_unlocked
  File "<frozen importlib._bootstrap_external>", line 883, in exec_module
  File "<frozen importlib._bootstrap>", line 241, in _call_with_frames_removed
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/dcerpc.py", line 38, in <module>
    from scapy.layers.dns import DNSStrField
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/dns.py", line 68, in <module>
    from scapy.layers.inet import IP, DestIPField, IPField, UDP, TCP
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/inet.py", line 2556, in <module>
    import scapy.layers.inet6
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/inet6.py", line 110, in <module>
    import scapy.route6  # noqa: F401
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 333, in <module>
    conf.route6 = Route6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 47, in __init__
    self.resync()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 64, in resync
    self.routes = read_routes6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 972, in read_routes6
    cset = scapy.utils6.construct_source_candidate_set(prefix, plen, devaddrs)
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in construct_source_candidate_set
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in <listcomp>
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 78, in <genexpr>
    cset = (x for x in laddr if x[1] == IPV6_ADDR_LINKLOCAL)
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 971, in <genexpr>
    devaddrs = ((x["address"], x["scope"], iface) for x in lifaddr.get(index, []))
KeyError: 'scope'
ERROR: Loading module scapy.layers.dhcp
Traceback (most recent call last):
  File "/usr/local/lib/python3.10/dist-packages/scapy/main.py", line 312, in _load
    mod = importlib.import_module(module)
  File "/usr/lib/python3.10/importlib/__init__.py", line 126, in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
  File "<frozen importlib._bootstrap>", line 1050, in _gcd_import
  File "<frozen importlib._bootstrap>", line 1027, in _find_and_load
  File "<frozen importlib._bootstrap>", line 1006, in _find_and_load_unlocked
  File "<frozen importlib._bootstrap>", line 688, in _load_unlocked
  File "<frozen importlib._bootstrap_external>", line 883, in exec_module
  File "<frozen importlib._bootstrap>", line 241, in _call_with_frames_removed
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/dhcp.py", line 44, in <module>
    from scapy.layers.inet import UDP, IP
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/inet.py", line 2556, in <module>
    import scapy.layers.inet6
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/inet6.py", line 110, in <module>
    import scapy.route6  # noqa: F401
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 333, in <module>
    conf.route6 = Route6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 47, in __init__
    self.resync()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 64, in resync
    self.routes = read_routes6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 972, in read_routes6
    cset = scapy.utils6.construct_source_candidate_set(prefix, plen, devaddrs)
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in construct_source_candidate_set
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in <listcomp>
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 78, in <genexpr>
    cset = (x for x in laddr if x[1] == IPV6_ADDR_LINKLOCAL)
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 971, in <genexpr>
    devaddrs = ((x["address"], x["scope"], iface) for x in lifaddr.get(index, []))
KeyError: 'scope'
ERROR: Loading module scapy.layers.dhcp6
Traceback (most recent call last):
  File "/usr/local/lib/python3.10/dist-packages/scapy/main.py", line 312, in _load
    mod = importlib.import_module(module)
  File "/usr/lib/python3.10/importlib/__init__.py", line 126, in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
  File "<frozen importlib._bootstrap>", line 1050, in _gcd_import
  File "<frozen importlib._bootstrap>", line 1027, in _find_and_load
  File "<frozen importlib._bootstrap>", line 1006, in _find_and_load_unlocked
  File "<frozen importlib._bootstrap>", line 688, in _load_unlocked
  File "<frozen importlib._bootstrap_external>", line 883, in exec_module
  File "<frozen importlib._bootstrap>", line 241, in _call_with_frames_removed
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/dhcp6.py", line 29, in <module>
    from scapy.layers.dns import DNSStrField
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/dns.py", line 68, in <module>
    from scapy.layers.inet import IP, DestIPField, IPField, UDP, TCP
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/inet.py", line 2556, in <module>
    import scapy.layers.inet6
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/inet6.py", line 110, in <module>
    import scapy.route6  # noqa: F401
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 333, in <module>
    conf.route6 = Route6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 47, in __init__
    self.resync()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 64, in resync
    self.routes = read_routes6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 972, in read_routes6
    cset = scapy.utils6.construct_source_candidate_set(prefix, plen, devaddrs)
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in construct_source_candidate_set
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in <listcomp>
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 78, in <genexpr>
    cset = (x for x in laddr if x[1] == IPV6_ADDR_LINKLOCAL)
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 971, in <genexpr>
    devaddrs = ((x["address"], x["scope"], iface) for x in lifaddr.get(index, []))
KeyError: 'scope'
ERROR: Loading module scapy.layers.dns
Traceback (most recent call last):
  File "/usr/local/lib/python3.10/dist-packages/scapy/main.py", line 312, in _load
    mod = importlib.import_module(module)
  File "/usr/lib/python3.10/importlib/__init__.py", line 126, in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
  File "<frozen importlib._bootstrap>", line 1050, in _gcd_import
  File "<frozen importlib._bootstrap>", line 1027, in _find_and_load
  File "<frozen importlib._bootstrap>", line 1006, in _find_and_load_unlocked
  File "<frozen importlib._bootstrap>", line 688, in _load_unlocked
  File "<frozen importlib._bootstrap_external>", line 883, in exec_module
  File "<frozen importlib._bootstrap>", line 241, in _call_with_frames_removed
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/dns.py", line 68, in <module>
    from scapy.layers.inet import IP, DestIPField, IPField, UDP, TCP
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/inet.py", line 2556, in <module>
    import scapy.layers.inet6
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/inet6.py", line 110, in <module>
    import scapy.route6  # noqa: F401
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 333, in <module>
    conf.route6 = Route6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 47, in __init__
    self.resync()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 64, in resync
    self.routes = read_routes6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 972, in read_routes6
    cset = scapy.utils6.construct_source_candidate_set(prefix, plen, devaddrs)
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in construct_source_candidate_set
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in <listcomp>
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 78, in <genexpr>
    cset = (x for x in laddr if x[1] == IPV6_ADDR_LINKLOCAL)
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 971, in <genexpr>
    devaddrs = ((x["address"], x["scope"], iface) for x in lifaddr.get(index, []))
KeyError: 'scope'
ERROR: Loading module scapy.layers.dot11
Traceback (most recent call last):
  File "/usr/local/lib/python3.10/dist-packages/scapy/main.py", line 312, in _load
    mod = importlib.import_module(module)
  File "/usr/lib/python3.10/importlib/__init__.py", line 126, in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
  File "<frozen importlib._bootstrap>", line 1050, in _gcd_import
  File "<frozen importlib._bootstrap>", line 1027, in _find_and_load
  File "<frozen importlib._bootstrap>", line 1006, in _find_and_load_unlocked
  File "<frozen importlib._bootstrap>", line 688, in _load_unlocked
  File "<frozen importlib._bootstrap_external>", line 883, in exec_module
  File "<frozen importlib._bootstrap>", line 241, in _call_with_frames_removed
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/dot11.py", line 58, in <module>
    from scapy.layers.inet import IP, TCP
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/inet.py", line 2556, in <module>
    import scapy.layers.inet6
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/inet6.py", line 110, in <module>
    import scapy.route6  # noqa: F401
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 333, in <module>
    conf.route6 = Route6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 47, in __init__
    self.resync()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 64, in resync
    self.routes = read_routes6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 972, in read_routes6
    cset = scapy.utils6.construct_source_candidate_set(prefix, plen, devaddrs)
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in construct_source_candidate_set
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in <listcomp>
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 78, in <genexpr>
    cset = (x for x in laddr if x[1] == IPV6_ADDR_LINKLOCAL)
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 971, in <genexpr>
    devaddrs = ((x["address"], x["scope"], iface) for x in lifaddr.get(index, []))
KeyError: 'scope'
ERROR: Loading module scapy.layers.gprs
Traceback (most recent call last):
  File "/usr/local/lib/python3.10/dist-packages/scapy/main.py", line 312, in _load
    mod = importlib.import_module(module)
  File "/usr/lib/python3.10/importlib/__init__.py", line 126, in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
  File "<frozen importlib._bootstrap>", line 1050, in _gcd_import
  File "<frozen importlib._bootstrap>", line 1027, in _find_and_load
  File "<frozen importlib._bootstrap>", line 1006, in _find_and_load_unlocked
  File "<frozen importlib._bootstrap>", line 688, in _load_unlocked
  File "<frozen importlib._bootstrap_external>", line 883, in exec_module
  File "<frozen importlib._bootstrap>", line 241, in _call_with_frames_removed
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/gprs.py", line 12, in <module>
    from scapy.layers.inet import IP
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/inet.py", line 2556, in <module>
    import scapy.layers.inet6
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/inet6.py", line 110, in <module>
    import scapy.route6  # noqa: F401
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 333, in <module>
    conf.route6 = Route6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 47, in __init__
    self.resync()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 64, in resync
    self.routes = read_routes6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 972, in read_routes6
    cset = scapy.utils6.construct_source_candidate_set(prefix, plen, devaddrs)
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in construct_source_candidate_set
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in <listcomp>
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 78, in <genexpr>
    cset = (x for x in laddr if x[1] == IPV6_ADDR_LINKLOCAL)
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 971, in <genexpr>
    devaddrs = ((x["address"], x["scope"], iface) for x in lifaddr.get(index, []))
KeyError: 'scope'
ERROR: Loading module scapy.layers.hsrp
Traceback (most recent call last):
  File "/usr/local/lib/python3.10/dist-packages/scapy/main.py", line 312, in _load
    mod = importlib.import_module(module)
  File "/usr/lib/python3.10/importlib/__init__.py", line 126, in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
  File "<frozen importlib._bootstrap>", line 1050, in _gcd_import
  File "<frozen importlib._bootstrap>", line 1027, in _find_and_load
  File "<frozen importlib._bootstrap>", line 1006, in _find_and_load_unlocked
  File "<frozen importlib._bootstrap>", line 688, in _load_unlocked
  File "<frozen importlib._bootstrap_external>", line 883, in exec_module
  File "<frozen importlib._bootstrap>", line 241, in _call_with_frames_removed
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/hsrp.py", line 19, in <module>
    from scapy.layers.inet import DestIPField, UDP
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/inet.py", line 2556, in <module>
    import scapy.layers.inet6
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/inet6.py", line 110, in <module>
    import scapy.route6  # noqa: F401
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 333, in <module>
    conf.route6 = Route6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 47, in __init__
    self.resync()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 64, in resync
    self.routes = read_routes6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 972, in read_routes6
    cset = scapy.utils6.construct_source_candidate_set(prefix, plen, devaddrs)
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in construct_source_candidate_set
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in <listcomp>
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 78, in <genexpr>
    cset = (x for x in laddr if x[1] == IPV6_ADDR_LINKLOCAL)
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 971, in <genexpr>
    devaddrs = ((x["address"], x["scope"], iface) for x in lifaddr.get(index, []))
KeyError: 'scope'
ERROR: Loading module scapy.layers.inet
Traceback (most recent call last):
  File "/usr/local/lib/python3.10/dist-packages/scapy/main.py", line 312, in _load
    mod = importlib.import_module(module)
  File "/usr/lib/python3.10/importlib/__init__.py", line 126, in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
  File "<frozen importlib._bootstrap>", line 1050, in _gcd_import
  File "<frozen importlib._bootstrap>", line 1027, in _find_and_load
  File "<frozen importlib._bootstrap>", line 1006, in _find_and_load_unlocked
  File "<frozen importlib._bootstrap>", line 688, in _load_unlocked
  File "<frozen importlib._bootstrap_external>", line 883, in exec_module
  File "<frozen importlib._bootstrap>", line 241, in _call_with_frames_removed
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/inet.py", line 2556, in <module>
    import scapy.layers.inet6
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/inet6.py", line 110, in <module>
    import scapy.route6  # noqa: F401
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 333, in <module>
    conf.route6 = Route6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 47, in __init__
    self.resync()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 64, in resync
    self.routes = read_routes6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 972, in read_routes6
    cset = scapy.utils6.construct_source_candidate_set(prefix, plen, devaddrs)
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in construct_source_candidate_set
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in <listcomp>
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 78, in <genexpr>
    cset = (x for x in laddr if x[1] == IPV6_ADDR_LINKLOCAL)
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 971, in <genexpr>
    devaddrs = ((x["address"], x["scope"], iface) for x in lifaddr.get(index, []))
KeyError: 'scope'
ERROR: Loading module scapy.layers.inet6
Traceback (most recent call last):
  File "/usr/local/lib/python3.10/dist-packages/scapy/main.py", line 312, in _load
    mod = importlib.import_module(module)
  File "/usr/lib/python3.10/importlib/__init__.py", line 126, in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
  File "<frozen importlib._bootstrap>", line 1050, in _gcd_import
  File "<frozen importlib._bootstrap>", line 1027, in _find_and_load
  File "<frozen importlib._bootstrap>", line 1006, in _find_and_load_unlocked
  File "<frozen importlib._bootstrap>", line 688, in _load_unlocked
  File "<frozen importlib._bootstrap_external>", line 883, in exec_module
  File "<frozen importlib._bootstrap>", line 241, in _call_with_frames_removed
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/inet6.py", line 110, in <module>
    import scapy.route6  # noqa: F401
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 333, in <module>
    conf.route6 = Route6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 47, in __init__
    self.resync()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 64, in resync
    self.routes = read_routes6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 972, in read_routes6
    cset = scapy.utils6.construct_source_candidate_set(prefix, plen, devaddrs)
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in construct_source_candidate_set
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in <listcomp>
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 78, in <genexpr>
    cset = (x for x in laddr if x[1] == IPV6_ADDR_LINKLOCAL)
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 971, in <genexpr>
    devaddrs = ((x["address"], x["scope"], iface) for x in lifaddr.get(index, []))
KeyError: 'scope'
ERROR: Loading module scapy.layers.ipsec
Traceback (most recent call last):
  File "/usr/local/lib/python3.10/dist-packages/scapy/main.py", line 312, in _load
    mod = importlib.import_module(module)
  File "/usr/lib/python3.10/importlib/__init__.py", line 126, in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
  File "<frozen importlib._bootstrap>", line 1050, in _gcd_import
  File "<frozen importlib._bootstrap>", line 1027, in _find_and_load
  File "<frozen importlib._bootstrap>", line 1006, in _find_and_load_unlocked
  File "<frozen importlib._bootstrap>", line 688, in _load_unlocked
  File "<frozen importlib._bootstrap_external>", line 883, in exec_module
  File "<frozen importlib._bootstrap>", line 241, in _call_with_frames_removed
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/ipsec.py", line 66, in <module>
    from scapy.layers.inet6 import IPv6, IPv6ExtHdrHopByHop, IPv6ExtHdrDestOpt, \
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/inet6.py", line 110, in <module>
    import scapy.route6  # noqa: F401
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 333, in <module>
    conf.route6 = Route6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 47, in __init__
    self.resync()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 64, in resync
    self.routes = read_routes6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 972, in read_routes6
    cset = scapy.utils6.construct_source_candidate_set(prefix, plen, devaddrs)
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in construct_source_candidate_set
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in <listcomp>
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 78, in <genexpr>
    cset = (x for x in laddr if x[1] == IPV6_ADDR_LINKLOCAL)
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 971, in <genexpr>
    devaddrs = ((x["address"], x["scope"], iface) for x in lifaddr.get(index, []))
KeyError: 'scope'
ERROR: Loading module scapy.layers.isakmp
Traceback (most recent call last):
  File "/usr/local/lib/python3.10/dist-packages/scapy/main.py", line 312, in _load
    mod = importlib.import_module(module)
  File "/usr/lib/python3.10/importlib/__init__.py", line 126, in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
  File "<frozen importlib._bootstrap>", line 1050, in _gcd_import
  File "<frozen importlib._bootstrap>", line 1027, in _find_and_load
  File "<frozen importlib._bootstrap>", line 1006, in _find_and_load_unlocked
  File "<frozen importlib._bootstrap>", line 688, in _load_unlocked
  File "<frozen importlib._bootstrap_external>", line 883, in exec_module
  File "<frozen importlib._bootstrap>", line 241, in _call_with_frames_removed
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/isakmp.py", line 36, in <module>
    from scapy.layers.ipsec import NON_ESP
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/ipsec.py", line 66, in <module>
    from scapy.layers.inet6 import IPv6, IPv6ExtHdrHopByHop, IPv6ExtHdrDestOpt, \
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/inet6.py", line 110, in <module>
    import scapy.route6  # noqa: F401
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 333, in <module>
    conf.route6 = Route6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 47, in __init__
    self.resync()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 64, in resync
    self.routes = read_routes6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 972, in read_routes6
    cset = scapy.utils6.construct_source_candidate_set(prefix, plen, devaddrs)
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in construct_source_candidate_set
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in <listcomp>
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 78, in <genexpr>
    cset = (x for x in laddr if x[1] == IPV6_ADDR_LINKLOCAL)
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 971, in <genexpr>
    devaddrs = ((x["address"], x["scope"], iface) for x in lifaddr.get(index, []))
KeyError: 'scope'
ERROR: Loading module scapy.layers.kerberos
Traceback (most recent call last):
  File "/usr/local/lib/python3.10/dist-packages/scapy/main.py", line 312, in _load
    mod = importlib.import_module(module)
  File "/usr/lib/python3.10/importlib/__init__.py", line 126, in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
  File "<frozen importlib._bootstrap>", line 1050, in _gcd_import
  File "<frozen importlib._bootstrap>", line 1027, in _find_and_load
  File "<frozen importlib._bootstrap>", line 1006, in _find_and_load_unlocked
  File "<frozen importlib._bootstrap>", line 688, in _load_unlocked
  File "<frozen importlib._bootstrap_external>", line 883, in exec_module
  File "<frozen importlib._bootstrap>", line 241, in _call_with_frames_removed
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/kerberos.py", line 148, in <module>
    from scapy.layers.smb import _NV_VERSION
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/smb.py", line 54, in <module>
    from scapy.layers.dns import (
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/dns.py", line 69, in <module>
    from scapy.layers.inet6 import IPv6
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/inet6.py", line 110, in <module>
    import scapy.route6  # noqa: F401
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 333, in <module>
    conf.route6 = Route6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 47, in __init__
    self.resync()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 64, in resync
    self.routes = read_routes6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 972, in read_routes6
    cset = scapy.utils6.construct_source_candidate_set(prefix, plen, devaddrs)
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in construct_source_candidate_set
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in <listcomp>
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 78, in <genexpr>
    cset = (x for x in laddr if x[1] == IPV6_ADDR_LINKLOCAL)
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 971, in <genexpr>
    devaddrs = ((x["address"], x["scope"], iface) for x in lifaddr.get(index, []))
KeyError: 'scope'
ERROR: Loading module scapy.layers.l2tp
Traceback (most recent call last):
  File "/usr/local/lib/python3.10/dist-packages/scapy/main.py", line 312, in _load
    mod = importlib.import_module(module)
  File "/usr/lib/python3.10/importlib/__init__.py", line 126, in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
  File "<frozen importlib._bootstrap>", line 1050, in _gcd_import
  File "<frozen importlib._bootstrap>", line 1027, in _find_and_load
  File "<frozen importlib._bootstrap>", line 1006, in _find_and_load_unlocked
  File "<frozen importlib._bootstrap>", line 688, in _load_unlocked
  File "<frozen importlib._bootstrap_external>", line 883, in exec_module
  File "<frozen importlib._bootstrap>", line 241, in _call_with_frames_removed
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/l2tp.py", line 18, in <module>
    from scapy.layers.ppp import PPP
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/ppp.py", line 21, in <module>
    from scapy.layers.inet6 import IPv6
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/inet6.py", line 110, in <module>
    import scapy.route6  # noqa: F401
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 333, in <module>
    conf.route6 = Route6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 47, in __init__
    self.resync()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 64, in resync
    self.routes = read_routes6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 972, in read_routes6
    cset = scapy.utils6.construct_source_candidate_set(prefix, plen, devaddrs)
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in construct_source_candidate_set
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in <listcomp>
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 78, in <genexpr>
    cset = (x for x in laddr if x[1] == IPV6_ADDR_LINKLOCAL)
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 971, in <genexpr>
    devaddrs = ((x["address"], x["scope"], iface) for x in lifaddr.get(index, []))
KeyError: 'scope'
ERROR: Loading module scapy.layers.ldap
Traceback (most recent call last):
  File "/usr/local/lib/python3.10/dist-packages/scapy/main.py", line 312, in _load
    mod = importlib.import_module(module)
  File "/usr/lib/python3.10/importlib/__init__.py", line 126, in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
  File "<frozen importlib._bootstrap>", line 1050, in _gcd_import
  File "<frozen importlib._bootstrap>", line 1027, in _find_and_load
  File "<frozen importlib._bootstrap>", line 1006, in _find_and_load_unlocked
  File "<frozen importlib._bootstrap>", line 688, in _load_unlocked
  File "<frozen importlib._bootstrap_external>", line 883, in exec_module
  File "<frozen importlib._bootstrap>", line 241, in _call_with_frames_removed
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/ldap.py", line 83, in <module>
    from scapy.layers.dns import dns_resolve
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/dns.py", line 69, in <module>
    from scapy.layers.inet6 import IPv6
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/inet6.py", line 110, in <module>
    import scapy.route6  # noqa: F401
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 333, in <module>
    conf.route6 = Route6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 47, in __init__
    self.resync()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 64, in resync
    self.routes = read_routes6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 972, in read_routes6
    cset = scapy.utils6.construct_source_candidate_set(prefix, plen, devaddrs)
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in construct_source_candidate_set
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in <listcomp>
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 78, in <genexpr>
    cset = (x for x in laddr if x[1] == IPV6_ADDR_LINKLOCAL)
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 971, in <genexpr>
    devaddrs = ((x["address"], x["scope"], iface) for x in lifaddr.get(index, []))
KeyError: 'scope'
ERROR: Loading module scapy.layers.llmnr
Traceback (most recent call last):
  File "/usr/local/lib/python3.10/dist-packages/scapy/main.py", line 312, in _load
    mod = importlib.import_module(module)
  File "/usr/lib/python3.10/importlib/__init__.py", line 126, in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
  File "<frozen importlib._bootstrap>", line 1050, in _gcd_import
  File "<frozen importlib._bootstrap>", line 1027, in _find_and_load
  File "<frozen importlib._bootstrap>", line 1006, in _find_and_load_unlocked
  File "<frozen importlib._bootstrap>", line 688, in _load_unlocked
  File "<frozen importlib._bootstrap_external>", line 883, in exec_module
  File "<frozen importlib._bootstrap>", line 241, in _call_with_frames_removed
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/llmnr.py", line 27, in <module>
    from scapy.layers.dns import (
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/dns.py", line 69, in <module>
    from scapy.layers.inet6 import IPv6
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/inet6.py", line 110, in <module>
    import scapy.route6  # noqa: F401
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 333, in <module>
    conf.route6 = Route6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 47, in __init__
    self.resync()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 64, in resync
    self.routes = read_routes6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 972, in read_routes6
    cset = scapy.utils6.construct_source_candidate_set(prefix, plen, devaddrs)
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in construct_source_candidate_set
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in <listcomp>
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 78, in <genexpr>
    cset = (x for x in laddr if x[1] == IPV6_ADDR_LINKLOCAL)
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 971, in <genexpr>
    devaddrs = ((x["address"], x["scope"], iface) for x in lifaddr.get(index, []))
KeyError: 'scope'
ERROR: Loading module scapy.layers.lltd
Traceback (most recent call last):
  File "/usr/local/lib/python3.10/dist-packages/scapy/main.py", line 312, in _load
    mod = importlib.import_module(module)
  File "/usr/lib/python3.10/importlib/__init__.py", line 126, in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
  File "<frozen importlib._bootstrap>", line 1050, in _gcd_import
  File "<frozen importlib._bootstrap>", line 1027, in _find_and_load
  File "<frozen importlib._bootstrap>", line 1006, in _find_and_load_unlocked
  File "<frozen importlib._bootstrap>", line 688, in _load_unlocked
  File "<frozen importlib._bootstrap_external>", line 883, in exec_module
  File "<frozen importlib._bootstrap>", line 241, in _call_with_frames_removed
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/lltd.py", line 22, in <module>
    from scapy.layers.inet6 import IP6Field
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/inet6.py", line 110, in <module>
    import scapy.route6  # noqa: F401
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 333, in <module>
    conf.route6 = Route6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 47, in __init__
    self.resync()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 64, in resync
    self.routes = read_routes6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 972, in read_routes6
    cset = scapy.utils6.construct_source_candidate_set(prefix, plen, devaddrs)
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in construct_source_candidate_set
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in <listcomp>
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 78, in <genexpr>
    cset = (x for x in laddr if x[1] == IPV6_ADDR_LINKLOCAL)
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 971, in <genexpr>
    devaddrs = ((x["address"], x["scope"], iface) for x in lifaddr.get(index, []))
KeyError: 'scope'
ERROR: Loading module scapy.layers.msrpce.rpcclient
Traceback (most recent call last):
  File "/usr/local/lib/python3.10/dist-packages/scapy/main.py", line 312, in _load
    mod = importlib.import_module(module)
  File "/usr/lib/python3.10/importlib/__init__.py", line 126, in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
  File "<frozen importlib._bootstrap>", line 1050, in _gcd_import
  File "<frozen importlib._bootstrap>", line 1027, in _find_and_load
  File "<frozen importlib._bootstrap>", line 1006, in _find_and_load_unlocked
  File "<frozen importlib._bootstrap>", line 688, in _load_unlocked
  File "<frozen importlib._bootstrap_external>", line 883, in exec_module
  File "<frozen importlib._bootstrap>", line 241, in _call_with_frames_removed
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/msrpce/rpcclient.py", line 16, in <module>
    from scapy.layers.dcerpc import (
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/dcerpc.py", line 38, in <module>
    from scapy.layers.dns import DNSStrField
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/dns.py", line 69, in <module>
    from scapy.layers.inet6 import IPv6
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/inet6.py", line 110, in <module>
    import scapy.route6  # noqa: F401
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 333, in <module>
    conf.route6 = Route6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 47, in __init__
    self.resync()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 64, in resync
    self.routes = read_routes6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 972, in read_routes6
    cset = scapy.utils6.construct_source_candidate_set(prefix, plen, devaddrs)
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in construct_source_candidate_set
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in <listcomp>
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 78, in <genexpr>
    cset = (x for x in laddr if x[1] == IPV6_ADDR_LINKLOCAL)
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 971, in <genexpr>
    devaddrs = ((x["address"], x["scope"], iface) for x in lifaddr.get(index, []))
KeyError: 'scope'
ERROR: Loading module scapy.layers.msrpce.rpcserver
Traceback (most recent call last):
  File "/usr/local/lib/python3.10/dist-packages/scapy/main.py", line 312, in _load
    mod = importlib.import_module(module)
  File "/usr/lib/python3.10/importlib/__init__.py", line 126, in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
  File "<frozen importlib._bootstrap>", line 1050, in _gcd_import
  File "<frozen importlib._bootstrap>", line 1027, in _find_and_load
  File "<frozen importlib._bootstrap>", line 1006, in _find_and_load_unlocked
  File "<frozen importlib._bootstrap>", line 688, in _load_unlocked
  File "<frozen importlib._bootstrap_external>", line 883, in exec_module
  File "<frozen importlib._bootstrap>", line 241, in _call_with_frames_removed
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/msrpce/rpcserver.py", line 19, in <module>
    from scapy.layers.dcerpc import (
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/dcerpc.py", line 38, in <module>
    from scapy.layers.dns import DNSStrField
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/dns.py", line 69, in <module>
    from scapy.layers.inet6 import IPv6
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/inet6.py", line 110, in <module>
    import scapy.route6  # noqa: F401
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 333, in <module>
    conf.route6 = Route6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 47, in __init__
    self.resync()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 64, in resync
    self.routes = read_routes6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 972, in read_routes6
    cset = scapy.utils6.construct_source_candidate_set(prefix, plen, devaddrs)
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in construct_source_candidate_set
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in <listcomp>
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 78, in <genexpr>
    cset = (x for x in laddr if x[1] == IPV6_ADDR_LINKLOCAL)
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 971, in <genexpr>
    devaddrs = ((x["address"], x["scope"], iface) for x in lifaddr.get(index, []))
KeyError: 'scope'
ERROR: Loading module scapy.layers.netflow
Traceback (most recent call last):
  File "/usr/local/lib/python3.10/dist-packages/scapy/main.py", line 312, in _load
    mod = importlib.import_module(module)
  File "/usr/lib/python3.10/importlib/__init__.py", line 126, in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
  File "<frozen importlib._bootstrap>", line 1050, in _gcd_import
  File "<frozen importlib._bootstrap>", line 1027, in _find_and_load
  File "<frozen importlib._bootstrap>", line 1006, in _find_and_load_unlocked
  File "<frozen importlib._bootstrap>", line 688, in _load_unlocked
  File "<frozen importlib._bootstrap_external>", line 883, in exec_module
  File "<frozen importlib._bootstrap>", line 241, in _call_with_frames_removed
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/netflow.py", line 72, in <module>
    from scapy.layers.inet6 import IP6Field
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/inet6.py", line 110, in <module>
    import scapy.route6  # noqa: F401
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 333, in <module>
    conf.route6 = Route6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 47, in __init__
    self.resync()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 64, in resync
    self.routes = read_routes6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 972, in read_routes6
    cset = scapy.utils6.construct_source_candidate_set(prefix, plen, devaddrs)
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in construct_source_candidate_set
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in <listcomp>
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 78, in <genexpr>
    cset = (x for x in laddr if x[1] == IPV6_ADDR_LINKLOCAL)
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 971, in <genexpr>
    devaddrs = ((x["address"], x["scope"], iface) for x in lifaddr.get(index, []))
KeyError: 'scope'
ERROR: Loading module scapy.layers.ppp
Traceback (most recent call last):
  File "/usr/local/lib/python3.10/dist-packages/scapy/main.py", line 312, in _load
    mod = importlib.import_module(module)
  File "/usr/lib/python3.10/importlib/__init__.py", line 126, in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
  File "<frozen importlib._bootstrap>", line 1050, in _gcd_import
  File "<frozen importlib._bootstrap>", line 1027, in _find_and_load
  File "<frozen importlib._bootstrap>", line 1006, in _find_and_load_unlocked
  File "<frozen importlib._bootstrap>", line 688, in _load_unlocked
  File "<frozen importlib._bootstrap_external>", line 883, in exec_module
  File "<frozen importlib._bootstrap>", line 241, in _call_with_frames_removed
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/ppp.py", line 21, in <module>
    from scapy.layers.inet6 import IPv6
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/inet6.py", line 110, in <module>
    import scapy.route6  # noqa: F401
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 333, in <module>
    conf.route6 = Route6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 47, in __init__
    self.resync()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 64, in resync
    self.routes = read_routes6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 972, in read_routes6
    cset = scapy.utils6.construct_source_candidate_set(prefix, plen, devaddrs)
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in construct_source_candidate_set
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in <listcomp>
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 78, in <genexpr>
    cset = (x for x in laddr if x[1] == IPV6_ADDR_LINKLOCAL)
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 971, in <genexpr>
    devaddrs = ((x["address"], x["scope"], iface) for x in lifaddr.get(index, []))
KeyError: 'scope'
ERROR: Loading module scapy.layers.sctp
Traceback (most recent call last):
  File "/usr/local/lib/python3.10/dist-packages/scapy/main.py", line 312, in _load
    mod = importlib.import_module(module)
  File "/usr/lib/python3.10/importlib/__init__.py", line 126, in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
  File "<frozen importlib._bootstrap>", line 1050, in _gcd_import
  File "<frozen importlib._bootstrap>", line 1027, in _find_and_load
  File "<frozen importlib._bootstrap>", line 1006, in _find_and_load_unlocked
  File "<frozen importlib._bootstrap>", line 688, in _load_unlocked
  File "<frozen importlib._bootstrap_external>", line 883, in exec_module
  File "<frozen importlib._bootstrap>", line 241, in _call_with_frames_removed
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/sctp.py", line 39, in <module>
    from scapy.layers.inet6 import IP6Field, IPv6, IPerror6
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/inet6.py", line 110, in <module>
    import scapy.route6  # noqa: F401
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 333, in <module>
    conf.route6 = Route6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 47, in __init__
    self.resync()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 64, in resync
    self.routes = read_routes6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 972, in read_routes6
    cset = scapy.utils6.construct_source_candidate_set(prefix, plen, devaddrs)
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in construct_source_candidate_set
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in <listcomp>
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 78, in <genexpr>
    cset = (x for x in laddr if x[1] == IPV6_ADDR_LINKLOCAL)
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 971, in <genexpr>
    devaddrs = ((x["address"], x["scope"], iface) for x in lifaddr.get(index, []))
KeyError: 'scope'
ERROR: Loading module scapy.layers.sixlowpan
Traceback (most recent call last):
  File "/usr/local/lib/python3.10/dist-packages/scapy/main.py", line 312, in _load
    mod = importlib.import_module(module)
  File "/usr/lib/python3.10/importlib/__init__.py", line 126, in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
  File "<frozen importlib._bootstrap>", line 1050, in _gcd_import
  File "<frozen importlib._bootstrap>", line 1027, in _find_and_load
  File "<frozen importlib._bootstrap>", line 1006, in _find_and_load_unlocked
  File "<frozen importlib._bootstrap>", line 688, in _load_unlocked
  File "<frozen importlib._bootstrap_external>", line 883, in exec_module
  File "<frozen importlib._bootstrap>", line 241, in _call_with_frames_removed
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/sixlowpan.py", line 77, in <module>
    from scapy.layers.inet6 import (
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/inet6.py", line 110, in <module>
    import scapy.route6  # noqa: F401
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 333, in <module>
    conf.route6 = Route6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 47, in __init__
    self.resync()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 64, in resync
    self.routes = read_routes6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 972, in read_routes6
    cset = scapy.utils6.construct_source_candidate_set(prefix, plen, devaddrs)
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in construct_source_candidate_set
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in <listcomp>
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 78, in <genexpr>
    cset = (x for x in laddr if x[1] == IPV6_ADDR_LINKLOCAL)
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 971, in <genexpr>
    devaddrs = ((x["address"], x["scope"], iface) for x in lifaddr.get(index, []))
KeyError: 'scope'
ERROR: Loading module scapy.layers.smb
Traceback (most recent call last):
  File "/usr/local/lib/python3.10/dist-packages/scapy/main.py", line 312, in _load
    mod = importlib.import_module(module)
  File "/usr/lib/python3.10/importlib/__init__.py", line 126, in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
  File "<frozen importlib._bootstrap>", line 1050, in _gcd_import
  File "<frozen importlib._bootstrap>", line 1027, in _find_and_load
  File "<frozen importlib._bootstrap>", line 1006, in _find_and_load_unlocked
  File "<frozen importlib._bootstrap>", line 688, in _load_unlocked
  File "<frozen importlib._bootstrap_external>", line 883, in exec_module
  File "<frozen importlib._bootstrap>", line 241, in _call_with_frames_removed
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/smb.py", line 54, in <module>
    from scapy.layers.dns import (
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/dns.py", line 69, in <module>
    from scapy.layers.inet6 import IPv6
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/inet6.py", line 110, in <module>
    import scapy.route6  # noqa: F401
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 333, in <module>
    conf.route6 = Route6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 47, in __init__
    self.resync()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 64, in resync
    self.routes = read_routes6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 972, in read_routes6
    cset = scapy.utils6.construct_source_candidate_set(prefix, plen, devaddrs)
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in construct_source_candidate_set
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in <listcomp>
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 78, in <genexpr>
    cset = (x for x in laddr if x[1] == IPV6_ADDR_LINKLOCAL)
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 971, in <genexpr>
    devaddrs = ((x["address"], x["scope"], iface) for x in lifaddr.get(index, []))
KeyError: 'scope'
ERROR: Loading module scapy.layers.smbclient
Traceback (most recent call last):
  File "/usr/local/lib/python3.10/dist-packages/scapy/main.py", line 312, in _load
    mod = importlib.import_module(module)
  File "/usr/lib/python3.10/importlib/__init__.py", line 126, in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
  File "<frozen importlib._bootstrap>", line 1050, in _gcd_import
  File "<frozen importlib._bootstrap>", line 1027, in _find_and_load
  File "<frozen importlib._bootstrap>", line 1006, in _find_and_load_unlocked
  File "<frozen importlib._bootstrap>", line 688, in _load_unlocked
  File "<frozen importlib._bootstrap_external>", line 883, in exec_module
  File "<frozen importlib._bootstrap>", line 241, in _call_with_frames_removed
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/smbclient.py", line 34, in <module>
    from scapy.layers.dcerpc import NDRUnion, find_dcerpc_interface
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/dcerpc.py", line 38, in <module>
    from scapy.layers.dns import DNSStrField
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/dns.py", line 69, in <module>
    from scapy.layers.inet6 import IPv6
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/inet6.py", line 110, in <module>
    import scapy.route6  # noqa: F401
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 333, in <module>
    conf.route6 = Route6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 47, in __init__
    self.resync()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 64, in resync
    self.routes = read_routes6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 972, in read_routes6
    cset = scapy.utils6.construct_source_candidate_set(prefix, plen, devaddrs)
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in construct_source_candidate_set
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in <listcomp>
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 78, in <genexpr>
    cset = (x for x in laddr if x[1] == IPV6_ADDR_LINKLOCAL)
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 971, in <genexpr>
    devaddrs = ((x["address"], x["scope"], iface) for x in lifaddr.get(index, []))
KeyError: 'scope'
ERROR: Loading module scapy.layers.smbserver
Traceback (most recent call last):
  File "/usr/local/lib/python3.10/dist-packages/scapy/main.py", line 312, in _load
    mod = importlib.import_module(module)
  File "/usr/lib/python3.10/importlib/__init__.py", line 126, in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
  File "<frozen importlib._bootstrap>", line 1050, in _gcd_import
  File "<frozen importlib._bootstrap>", line 1027, in _find_and_load
  File "<frozen importlib._bootstrap>", line 1006, in _find_and_load_unlocked
  File "<frozen importlib._bootstrap>", line 688, in _load_unlocked
  File "<frozen importlib._bootstrap_external>", line 883, in exec_module
  File "<frozen importlib._bootstrap>", line 241, in _call_with_frames_removed
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/smbserver.py", line 33, in <module>
    from scapy.layers.dcerpc import (
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/dcerpc.py", line 38, in <module>
    from scapy.layers.dns import DNSStrField
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/dns.py", line 69, in <module>
    from scapy.layers.inet6 import IPv6
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/inet6.py", line 110, in <module>
    import scapy.route6  # noqa: F401
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 333, in <module>
    conf.route6 = Route6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 47, in __init__
    self.resync()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 64, in resync
    self.routes = read_routes6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 972, in read_routes6
    cset = scapy.utils6.construct_source_candidate_set(prefix, plen, devaddrs)
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in construct_source_candidate_set
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in <listcomp>
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 78, in <genexpr>
    cset = (x for x in laddr if x[1] == IPV6_ADDR_LINKLOCAL)
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 971, in <genexpr>
    devaddrs = ((x["address"], x["scope"], iface) for x in lifaddr.get(index, []))
KeyError: 'scope'
ERROR: Loading module scapy.layers.spnego
Traceback (most recent call last):
  File "/usr/local/lib/python3.10/dist-packages/scapy/main.py", line 312, in _load
    mod = importlib.import_module(module)
  File "/usr/lib/python3.10/importlib/__init__.py", line 126, in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
  File "<frozen importlib._bootstrap>", line 1050, in _gcd_import
  File "<frozen importlib._bootstrap>", line 1027, in _find_and_load
  File "<frozen importlib._bootstrap>", line 1006, in _find_and_load_unlocked
  File "<frozen importlib._bootstrap>", line 688, in _load_unlocked
  File "<frozen importlib._bootstrap_external>", line 883, in exec_module
  File "<frozen importlib._bootstrap>", line 241, in _call_with_frames_removed
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/spnego.py", line 84, in <module>
    from scapy.layers.kerberos import (
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/kerberos.py", line 148, in <module>
    from scapy.layers.smb import _NV_VERSION
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/smb.py", line 54, in <module>
    from scapy.layers.dns import (
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/dns.py", line 69, in <module>
    from scapy.layers.inet6 import IPv6
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/inet6.py", line 110, in <module>
    import scapy.route6  # noqa: F401
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 333, in <module>
    conf.route6 = Route6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 47, in __init__
    self.resync()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 64, in resync
    self.routes = read_routes6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 972, in read_routes6
    cset = scapy.utils6.construct_source_candidate_set(prefix, plen, devaddrs)
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in construct_source_candidate_set
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in <listcomp>
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 78, in <genexpr>
    cset = (x for x in laddr if x[1] == IPV6_ADDR_LINKLOCAL)
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 971, in <genexpr>
    devaddrs = ((x["address"], x["scope"], iface) for x in lifaddr.get(index, []))
KeyError: 'scope'
ERROR: Loading module scapy.layers.vrrp
Traceback (most recent call last):
  File "/usr/local/lib/python3.10/dist-packages/scapy/main.py", line 312, in _load
    mod = importlib.import_module(module)
  File "/usr/lib/python3.10/importlib/__init__.py", line 126, in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
  File "<frozen importlib._bootstrap>", line 1050, in _gcd_import
  File "<frozen importlib._bootstrap>", line 1027, in _find_and_load
  File "<frozen importlib._bootstrap>", line 1006, in _find_and_load_unlocked
  File "<frozen importlib._bootstrap>", line 688, in _load_unlocked
  File "<frozen importlib._bootstrap_external>", line 883, in exec_module
  File "<frozen importlib._bootstrap>", line 241, in _call_with_frames_removed
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/vrrp.py", line 16, in <module>
    from scapy.layers.inet6 import IPv6, in6_chksum
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/inet6.py", line 110, in <module>
    import scapy.route6  # noqa: F401
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 333, in <module>
    conf.route6 = Route6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 47, in __init__
    self.resync()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 64, in resync
    self.routes = read_routes6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 972, in read_routes6
    cset = scapy.utils6.construct_source_candidate_set(prefix, plen, devaddrs)
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in construct_source_candidate_set
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in <listcomp>
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 78, in <genexpr>
    cset = (x for x in laddr if x[1] == IPV6_ADDR_LINKLOCAL)
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 971, in <genexpr>
    devaddrs = ((x["address"], x["scope"], iface) for x in lifaddr.get(index, []))
KeyError: 'scope'
ERROR: Loading module scapy.layers.vxlan
Traceback (most recent call last):
  File "/usr/local/lib/python3.10/dist-packages/scapy/main.py", line 312, in _load
    mod = importlib.import_module(module)
  File "/usr/lib/python3.10/importlib/__init__.py", line 126, in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
  File "<frozen importlib._bootstrap>", line 1050, in _gcd_import
  File "<frozen importlib._bootstrap>", line 1027, in _find_and_load
  File "<frozen importlib._bootstrap>", line 1006, in _find_and_load_unlocked
  File "<frozen importlib._bootstrap>", line 688, in _load_unlocked
  File "<frozen importlib._bootstrap_external>", line 883, in exec_module
  File "<frozen importlib._bootstrap>", line 241, in _call_with_frames_removed
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/vxlan.py", line 21, in <module>
    from scapy.layers.inet6 import IPv6
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/inet6.py", line 110, in <module>
    import scapy.route6  # noqa: F401
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 333, in <module>
    conf.route6 = Route6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 47, in __init__
    self.resync()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 64, in resync
    self.routes = read_routes6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 972, in read_routes6
    cset = scapy.utils6.construct_source_candidate_set(prefix, plen, devaddrs)
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in construct_source_candidate_set
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in <listcomp>
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 78, in <genexpr>
    cset = (x for x in laddr if x[1] == IPV6_ADDR_LINKLOCAL)
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 971, in <genexpr>
    devaddrs = ((x["address"], x["scope"], iface) for x in lifaddr.get(index, []))
KeyError: 'scope'
ERROR: Loading module scapy.layers.tuntap
Traceback (most recent call last):
  File "/usr/local/lib/python3.10/dist-packages/scapy/main.py", line 312, in _load
    mod = importlib.import_module(module)
  File "/usr/lib/python3.10/importlib/__init__.py", line 126, in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
  File "<frozen importlib._bootstrap>", line 1050, in _gcd_import
  File "<frozen importlib._bootstrap>", line 1027, in _find_and_load
  File "<frozen importlib._bootstrap>", line 1006, in _find_and_load_unlocked
  File "<frozen importlib._bootstrap>", line 688, in _load_unlocked
  File "<frozen importlib._bootstrap_external>", line 883, in exec_module
  File "<frozen importlib._bootstrap>", line 241, in _call_with_frames_removed
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/tuntap.py", line 32, in <module>
    from scapy.layers.inet6 import IPv6, IPv46
  File "/usr/local/lib/python3.10/dist-packages/scapy/layers/inet6.py", line 110, in <module>
    import scapy.route6  # noqa: F401
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 333, in <module>
    conf.route6 = Route6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 47, in __init__
    self.resync()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 64, in resync
    self.routes = read_routes6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 972, in read_routes6
    cset = scapy.utils6.construct_source_candidate_set(prefix, plen, devaddrs)
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in construct_source_candidate_set
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in <listcomp>
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 78, in <genexpr>
    cset = (x for x in laddr if x[1] == IPV6_ADDR_LINKLOCAL)
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 971, in <genexpr>
    devaddrs = ((x["address"], x["scope"], iface) for x in lifaddr.get(index, []))
KeyError: 'scope'
Traceback (most recent call last):
  File "/usr/local/bin/sagedral-ml", line 8, in <module>
    sys.exit(main())
  File "/usr/local/lib/python3.10/dist-packages/click/core.py", line 1569, in __call__
    return self.main(*args, **kwargs)
  File "/usr/local/lib/python3.10/dist-packages/click/core.py", line 1490, in main
    rv = self.invoke(ctx)
  File "/usr/local/lib/python3.10/dist-packages/click/core.py", line 1970, in invoke
    return _process_result(sub_ctx.command.invoke(sub_ctx))
  File "/usr/local/lib/python3.10/dist-packages/click/core.py", line 1353, in invoke
    return ctx.invoke(self.callback, **ctx.params)
  File "/usr/local/lib/python3.10/dist-packages/click/core.py", line 907, in invoke
    return callback(*args, **kwargs)
  File "/usr/local/lib/python3.10/dist-packages/sagedral_ml/cli.py", line 32, in start
    from sagedral_ml.main import run_app
  File "/usr/local/lib/python3.10/dist-packages/sagedral_ml/main.py", line 17, in <module>
    from sagedral_ml.capture.sniffer import PacketCapture
  File "/usr/local/lib/python3.10/dist-packages/sagedral_ml/capture/sniffer.py", line 9, in <module>
    from scapy.all import AsyncSniffer, conf
  File "/usr/local/lib/python3.10/dist-packages/scapy/all.py", line 51, in <module>
    from scapy.route6 import *  # noqa: F401
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 333, in <module>
    conf.route6 = Route6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 47, in __init__
    self.resync()
  File "/usr/local/lib/python3.10/dist-packages/scapy/route6.py", line 64, in resync
    self.routes = read_routes6()
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 972, in read_routes6
    cset = scapy.utils6.construct_source_candidate_set(prefix, plen, devaddrs)
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in construct_source_candidate_set
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 94, in <listcomp>
    addrs = [x[0] for x in cset]
  File "/usr/local/lib/python3.10/dist-packages/scapy/utils6.py", line 78, in <genexpr>
    cset = (x for x in laddr if x[1] == IPV6_ADDR_LINKLOCAL)
  File "/usr/local/lib/python3.10/dist-packages/scapy/arch/linux/rtnetlink.py", line 971, in <genexpr>
    devaddrs = ((x["address"], x["scope"], iface) for x in lifaddr.get(index, []))
KeyError: 'scope'