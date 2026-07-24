"""
IPSModule for executing Linux network firewall blocking actions (nftables / iptables).
Strictly validates IP addresses and enforces Whitelist Protection.
"""

import ipaddress
import logging
import re
import shutil
import subprocess
from typing import List, Optional, Set

logger = logging.getLogger("sagedral_ml.ips.response")

HARDCODED_WHITELIST: Set[str] = {"127.0.0.1", "::1"}


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
        self.custom_whitelist: Set[str] = set(whitelist or [])
        self.gateway_ip: Optional[str] = get_default_gateway()

        self.backend = self._determine_backend()

        if self.enabled and self.backend == "nftables":
            self.setup_nftables_table()

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
            clean_ip = validate_ip(ip)
        except ValueError:
            return True

        if clean_ip in HARDCODED_WHITELIST:
            return True
        if clean_ip in self.custom_whitelist:
            return True
        if self.gateway_ip and clean_ip == self.gateway_ip:
            return True
        return False

    def add_to_whitelist(self, ip: str) -> bool:
        try:
            clean_ip = validate_ip(ip)
            self.custom_whitelist.add(clean_ip)
            return True
        except ValueError:
            return False

    def remove_from_whitelist(self, ip: str) -> bool:
        try:
            clean_ip = validate_ip(ip)
            if clean_ip in self.custom_whitelist:
                self.custom_whitelist.remove(clean_ip)
                return True
        except ValueError:
            pass
        return False

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
