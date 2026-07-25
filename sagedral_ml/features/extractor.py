"""
FlowAggregator class for converting raw packet streams into complete FlowRecords.
"""

import queue
import time
import threading
import logging
from typing import Dict, Tuple, Optional
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet

from sagedral_ml.features.models import FlowRecord

logger = logging.getLogger("sagedral_ml.features.extractor")


class FlowAggregator:
    """
    Aggregates packet streams into 5-tuple FlowRecord objects.
    """

    def __init__(self, flow_queue: queue.Queue, config: Optional[Dict] = None):
        self.flow_queue = flow_queue
        config = config or {}
        self.flow_timeout: float = float(config.get("flow_timeout", 60))
        self.max_packets_per_flow: int = int(config.get("max_packets_per_flow", 1000))
        self.max_active_flows: int = int(config.get("max_active_flows", 50000))
        self.active_flows: Dict[Tuple[str, str, int, int, int], FlowRecord] = {}
        self._lock = threading.Lock()

    def _extract_packet_info(self, packet) -> Optional[Dict]:
        """Extract IP, port, protocol, flags, and size from Scapy packet or dict."""
        if isinstance(packet, dict):
            return packet

        if not hasattr(packet, "haslayer"):
            return None

        is_ipv6 = packet.haslayer(IPv6)
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            protocol = int(ip_layer.proto)
            header_len = int(ip_layer.ihl * 4) if hasattr(ip_layer, "ihl") else 20
        elif is_ipv6:
            ip_layer = packet[IPv6]
            protocol = int(getattr(ip_layer, "nh", 0))
            header_len = 40
        else:
            return None

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        pkt_len = len(packet)
        timestamp = float(getattr(packet, "time", time.time()))

        src_port = 0
        dst_port = 0
        flags = {}

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            src_port = int(tcp_layer.sport)
            dst_port = int(tcp_layer.dport)
            header_len += int(tcp_layer.dataofs * 4) if hasattr(tcp_layer, "dataofs") else 20
            tcp_flags = str(tcp_layer.flags)
            flags = {
                "SYN": "S" in tcp_flags,
                "FIN": "F" in tcp_flags,
                "RST": "R" in tcp_flags,
                "PSH": "P" in tcp_flags,
                "ACK": "A" in tcp_flags,
                "URG": "U" in tcp_flags,
            }
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            src_port = int(udp_layer.sport)
            dst_port = int(udp_layer.dport)
            header_len += 8
        elif packet.haslayer(ICMP):
            header_len += 8

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "pkt_len": pkt_len,
            "header_len": header_len,
            "flags": flags,
            "timestamp": timestamp,
        }

    def process_packet(self, packet) -> None:
        """Process incoming packet and update or complete flows."""
        info = self._extract_packet_info(packet)
        if not info:
            return

        src_ip = info["src_ip"]
        dst_ip = info["dst_ip"]
        src_port = info["src_port"]
        dst_port = info["dst_port"]
        protocol = info["protocol"]
        timestamp = info["timestamp"]
        flags = info["flags"]

        fwd_key = (src_ip, dst_ip, src_port, dst_port, protocol)
        bwd_key = (dst_ip, src_ip, dst_port, src_port, protocol)

        with self._lock:
            if fwd_key not in self.active_flows and bwd_key not in self.active_flows:
                self._evict_oldest_flows_if_needed()

            if fwd_key in self.active_flows:
                flow = self.active_flows[fwd_key]
                flow.add_packet(info["pkt_len"], info["header_len"], flags, is_forward=True, timestamp=timestamp)
                target_key = fwd_key
            elif bwd_key in self.active_flows:
                flow = self.active_flows[bwd_key]
                flow.add_packet(info["pkt_len"], info["header_len"], flags, is_forward=False, timestamp=timestamp)
                target_key = bwd_key
            else:
                flow = FlowRecord(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    start_time=timestamp,
                    end_time=timestamp,
                )
                flow.add_packet(info["pkt_len"], info["header_len"], flags, is_forward=True, timestamp=timestamp)
                self.active_flows[fwd_key] = flow
                target_key = fwd_key

            # Completion check (TCP FIN/RST, or max packets)
            is_complete = False
            if flags.get("FIN") or flags.get("RST"):
                is_complete = True
            elif (flow.total_fwd_packets + flow.total_bwd_packets) >= self.max_packets_per_flow:
                is_complete = True

            if is_complete:
                completed_flow = self.active_flows.pop(target_key)
                try:
                    self.flow_queue.put_nowait(completed_flow)
                except queue.Full:
                    logger.warning("flow_queue is full, completed flow dropped.")

    def _evict_oldest_flows_if_needed(self) -> None:
        """Evict oldest flows when active flow cardinality exceeds safety cap."""
        if self.max_active_flows <= 0:
            return
        if len(self.active_flows) < self.max_active_flows:
            return

        evict_count = max(1, int(self.max_active_flows * 0.10))
        sorted_keys = sorted(
            self.active_flows.keys(),
            key=lambda k: self.active_flows[k].end_time,
        )
        for old_key in sorted_keys[:evict_count]:
            old_flow = self.active_flows.pop(old_key)
            try:
                self.flow_queue.put_nowait(old_flow)
            except queue.Full:
                logger.warning("flow_queue is full, evicted flow dropped.")
                break

    def cleanup_timeouts(self, now: Optional[float] = None) -> None:
        """Scan active flows and complete any flow exceeding timeout."""
        current_time = now if now is not None else time.time()
        expired_keys = []

        with self._lock:
            for key, flow in self.active_flows.items():
                if (current_time - flow.end_time) >= self.flow_timeout:
                    expired_keys.append(key)

            for key in expired_keys:
                flow = self.active_flows.pop(key)
                try:
                    self.flow_queue.put_nowait(flow)
                except queue.Full:
                    logger.warning("flow_queue full during timeout cleanup.")
