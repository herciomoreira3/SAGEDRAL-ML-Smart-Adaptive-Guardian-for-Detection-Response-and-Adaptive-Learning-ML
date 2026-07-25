"""
IPSModule for executing Linux network firewall blocking actions (nftables / iptables).
Strictly validates IP addresses and enforces Whitelist Protection.
"""

import ipaddress
import logging
import re
import shutil
import subprocess
from typing import Dict, List, Optional, Set

logger = logging.getLogger("sagedral_ml.ips.response")

HARDCODED_WHITELIST: Set[str] = {"127.0.0.1", "::1"}


def get_local_ip_addresses() -> Set[str]:
    """Enumerate all local IPv4/IPv6 addresses assigned to ANY interface on the
    running host (lo, eth0 NAT, eth1 bridged, wifi0, docker0, etc.) and return
    as a set of validated IP strings.

    Purpose: prevents SAGEDRAL-ML from auto-blocking its OWN host IP addresses
    when the user accidentally points capture.interface to an internal/NAT
    interface and sees legitimate self-traffic (ssh, dashboard HTTP, apt)
    classified as anomaly DDoS.
    """
    found: Set[str] = set()
    try:
        res = subprocess.run(
            ["ip", "-o", "addr", "show"],
            capture_output=True, text=True, timeout=3,
        )
    except Exception as e:
        logger.debug(f"Could not list local IPs: {e}")
        return found
    ipv4_re = re.compile(r"\binet\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})")
    ipv6_re = re.compile(r"\binet6\s+([0-9a-fA-F:]+)")
    for line in res.stdout.splitlines():
        for m in ipv4_re.finditer(line):
            try:
                found.add(str(ipaddress.IPv4Address(m.group(1))))
            except ValueError:
                pass
        for m in ipv6_re.finditer(line):
            tok = m.group(1).split("/", 1)[0]
            try:
                found.add(str(ipaddress.IPv6Address(tok)))
            except ValueError:
                pass
    return found


def validate_ip(ip: str) -> str:
    """
    Validate and sanitize IP address string.
    Raises ValueError if IP is invalid.
    """
    if not ip or not isinstance(ip, str):
        raise ValueError("IP address must be a non-empty string.")

    cleaned = ip.strip()
    try:
        parsed = ipaddress.ip_address(cleaned)
        return str(parsed)
    except ValueError:
        raise ValueError(f"Invalid IP address format: '{ip}'")


def validate_ip_or_network(value: str) -> str:
    """Validate either a single IP address or a CIDR network and return canonical string."""
    if not value or not isinstance(value, str):
        raise ValueError("IP address or CIDR network must be a non-empty string.")

    cleaned = value.strip()
    try:
        if "/" in cleaned:
            return str(ipaddress.ip_network(cleaned, strict=False))
        return str(ipaddress.ip_address(cleaned))
    except ValueError:
        raise ValueError(f"Invalid IP/CIDR format: '{value}'")


def calculate_escalated_duration(base_duration_seconds: Optional[int], strike_count: int) -> Optional[int]:
    """Return strike-based block duration. None/0 means permanent."""
    if base_duration_seconds is None or base_duration_seconds <= 0:
        return None
    if strike_count <= 1:
        multiplier = 1
    elif strike_count == 2:
        multiplier = 4
    elif strike_count == 3:
        multiplier = 24
    elif strike_count == 4:
        multiplier = 168
    else:
        return None
    return int(base_duration_seconds * multiplier)


def get_default_gateway() -> Optional[str]:
    """Detect default route gateway IP address from system route table."""
    try:
        res = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=3)
        match = re.search(r"default via (\S+)", res.stdout)
        if match:
            return validate_ip(match.group(1))
    except Exception as e:
        logger.debug(f"Could not detect default gateway: {e}")
    return None


class IPSModule:
    """
    Intrusion Prevention System response manager.
    Executes packet drop / IP block rules on Linux host.
    """

    def __init__(
        self,
        enabled: bool = True,
        preferred_backend: str = "nftables",
        whitelist: Optional[List[str]] = None,
        auto_unblock_after: int = 3600,
    ):
        self.enabled = enabled
        self.preferred_backend = preferred_backend.lower()
        self.auto_unblock_after = auto_unblock_after
        self.whitelist_single_ips: Set[ipaddress._BaseAddress] = set()
        self.whitelist_subnets: List[ipaddress._BaseNetwork] = []
        self._parse_whitelist_entries(whitelist or [])
        self.gateway_ip: Optional[str] = get_default_gateway()
        self.local_ips: Set[str] = get_local_ip_addresses()
        self.ip_offense_history: Dict[str, int] = {}

        self.backend = self._determine_backend()

        if self.enabled and self.backend == "nftables":
            self.setup_nftables_table()

    def _parse_whitelist_entries(self, entries: List[str]) -> None:
        for entry in entries:
            if not entry or not isinstance(entry, str):
                continue
            cleaned = entry.strip()
            try:
                if "/" in cleaned:
                    network = ipaddress.ip_network(cleaned, strict=False)
                    self.whitelist_subnets.append(network)
                else:
                    addr = ipaddress.ip_address(cleaned)
                    self.whitelist_single_ips.add(addr)
            except ValueError:
                logger.warning(f"Skipping invalid whitelist entry: '{entry}'")

    def _determine_backend(self) -> str:
        if self.preferred_backend == "nftables" and shutil.which("nft"):
            return "nftables"
        elif shutil.which("iptables"):
            return "iptables"
        elif shutil.which("nft"):
            return "nftables"
        else:
            logger.warning("Neither nftables nor iptables found in PATH. IPS actions will be logged only.")
            return "mock"

    def is_whitelisted(self, ip: str) -> bool:
        try:
            clean_ip_str = validate_ip(ip)
            parsed_ip = ipaddress.ip_address(clean_ip_str)
        except ValueError:
            return True

        if clean_ip_str in HARDCODED_WHITELIST:
            return True
        if parsed_ip in self.whitelist_single_ips:
            return True
        for subnet in self.whitelist_subnets:
            if parsed_ip in subnet:
                return True
        if self.gateway_ip and clean_ip_str == self.gateway_ip:
            return True
        if clean_ip_str in self.local_ips:
            return True
        return False

    def add_to_whitelist(self, entry: str) -> bool:
        cleaned = (entry or "").strip()
        if not cleaned:
            return False
        try:
            if "/" in cleaned:
                network = ipaddress.ip_network(cleaned, strict=False)
                self.whitelist_subnets.append(network)
            else:
                addr = ipaddress.ip_address(cleaned)
                self.whitelist_single_ips.add(addr)
            return True
        except ValueError:
            return False

    def remove_from_whitelist(self, entry: str) -> bool:
        cleaned = (entry or "").strip()
        if not cleaned:
            return False
        try:
            if "/" in cleaned:
                network = ipaddress.ip_network(cleaned, strict=False)
                if network in self.whitelist_subnets:
                    self.whitelist_subnets.remove(network)
                    return True
            else:
                addr = ipaddress.ip_address(cleaned)
                if addr in self.whitelist_single_ips:
                    self.whitelist_single_ips.remove(addr)
                    return True
        except ValueError:
            pass
        return False

    def is_entry_whitelisted(self, entry: str) -> bool:
        """Validate a single IP or CIDR and check if it overlaps the protected whitelist."""
        try:
            if "/" in (entry or ""):
                network = ipaddress.ip_network(entry.strip(), strict=False)
                if any(ip in network for ip in self.whitelist_single_ips):
                    return True
                return any(network.overlaps(existing) for existing in self.whitelist_subnets)
            return self.is_whitelisted(entry)
        except ValueError:
            return True

    def strike_count_get(self, ip: str) -> int:
        try:
            clean_ip = validate_ip(ip)
        except ValueError:
            return 0
        return self.ip_offense_history.get(clean_ip, 0)

    def strike_count_incr(self, ip: str) -> int:
        try:
            clean_ip = validate_ip(ip)
        except ValueError:
            return 0
        self.ip_offense_history[clean_ip] = self.ip_offense_history.get(clean_ip, 0) + 1
        return self.ip_offense_history[clean_ip]

    async def reconcile_from_db(self, db_session) -> None:
        try:
            from sagedral_ml.database import crud
            active_blocked = await crud.get_active_blocked_ips(db_session)
            logger.info(f"Reconciling {len(active_blocked)} active blocked IPs from database...")
            success = 0
            skipped_whitelisted = 0
            failed = 0
            for entry in active_blocked:
                try:
                    ip_str = entry.ip if hasattr(entry, "ip") else str(entry)
                    if self.is_whitelisted(ip_str):
                        logger.warning(f"Reconcile skip: IP {ip_str} is whitelisted")
                        skipped_whitelisted += 1
                        continue
                    result = self.block_ip(ip_str)
                    if result:
                        success += 1
                    else:
                        failed += 1
                except Exception as e:
                    logger.error(f"Reconcile error processing IP entry: {e}")
                    failed += 1
            logger.info(
                f"IPS reconcile complete: success={success}, skipped_whitelisted={skipped_whitelisted}, failed={failed}"
            )
        except Exception as e:
            logger.error(f"Failed to reconcile IPS from database: {e}")

    def setup_nftables_table(self) -> bool:
        """Initialize sagedral nftables table and blocklist set."""
        if self.backend != "nftables":
            return False

        cmds = [
            ["nft", "add", "table", "inet", "sagedral"],
            ["nft", "add", "set", "inet", "sagedral", "blocklist", "{ type ipv4_addr; }"],
            ["nft", "add", "chain", "inet", "sagedral", "input", "{ type filter hook input priority 0; }"],
            ["nft", "add", "rule", "inet", "sagedral", "input", "ip", "saddr", "@blocklist", "drop"],
            ["nft", "add", "chain", "inet", "sagedral", "output", "{ type filter hook output priority 0; }"],
            ["nft", "add", "rule", "inet", "sagedral", "output", "ip", "daddr", "@blocklist", "drop"],
        ]

        for cmd in cmds:
            try:
                subprocess.run(cmd, capture_output=True, check=False, timeout=5)
            except Exception as e:
                logger.debug(f"nftables setup command '{' '.join(cmd)}' note: {e}")
        logger.info("nftables table 'inet sagedral' initialized.")
        return True

    def block_ip(self, ip: str) -> bool:
        """Block specified IP address in firewall."""
        if not self.enabled:
            logger.info(f"IPS disabled: skipping block for IP {ip}")
            return False

        try:
            clean_ip = validate_ip(ip)
        except ValueError as e:
            logger.error(f"Cannot block invalid IP: {e}")
            return False

        if self.is_whitelisted(clean_ip):
            logger.warning(f"IP {clean_ip} is whitelisted! Block action aborted.")
            return False

        if self.backend == "nftables":
            cmd = ["nft", "add", "element", "inet", "sagedral", "blocklist", f"{{ {clean_ip} }}"]
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                if res.returncode == 0:
                    logger.info(f"Successfully blocked IP {clean_ip} via nftables.")
                    return True
                else:
                    logger.error(f"nftables block error: {res.stderr}")
            except Exception as e:
                logger.error(f"Failed to execute nftables command: {e}")
            return False

        elif self.backend == "iptables":
            try:
                c1 = ["iptables", "-I", "INPUT", "-s", clean_ip, "-j", "DROP"]
                c2 = ["iptables", "-I", "OUTPUT", "-d", clean_ip, "-j", "DROP"]
                subprocess.run(c1, capture_output=True, timeout=5)
                subprocess.run(c2, capture_output=True, timeout=5)
                logger.info(f"Successfully blocked IP {clean_ip} via iptables.")
                return True
            except Exception as e:
                logger.error(f"Failed to execute iptables command: {e}")
            return False

        else:
            logger.info(f"[MOCK IPS] Blocked IP {clean_ip}")
            return True

    def unblock_ip(self, ip: str) -> bool:
        """Unblock specified IP address in firewall."""
        try:
            clean_ip = validate_ip(ip)
        except ValueError as e:
            logger.error(f"Cannot unblock invalid IP: {e}")
            return False

        if self.backend == "nftables":
            cmd = ["nft", "delete", "element", "inet", "sagedral", "blocklist", f"{{ {clean_ip} }}"]
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                if res.returncode == 0:
                    logger.info(f"Successfully unblocked IP {clean_ip} via nftables.")
                    return True
            except Exception as e:
                logger.error(f"Failed to execute nftables unblock: {e}")
            return False

        elif self.backend == "iptables":
            try:
                c1 = ["iptables", "-D", "INPUT", "-s", clean_ip, "-j", "DROP"]
                c2 = ["iptables", "-D", "OUTPUT", "-d", clean_ip, "-j", "DROP"]
                subprocess.run(c1, capture_output=True, timeout=5)
                subprocess.run(c2, capture_output=True, timeout=5)
                logger.info(f"Successfully unblocked IP {clean_ip} via iptables.")
                return True
            except Exception as e:
                logger.error(f"Failed to execute iptables unblock: {e}")
            return False

        else:
            logger.info(f"[MOCK IPS] Unblocked IP {clean_ip}")
            return True
