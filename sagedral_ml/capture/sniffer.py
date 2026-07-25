"""
PacketCapture class for non-blocking real-time packet sniffing using Scapy.
"""

import sagedral_ml
import queue
import threading
import logging
import time
from typing import Optional
from scapy.all import AsyncSniffer, conf

logger = logging.getLogger("sagedral_ml.capture.sniffer")


class PacketCapture:
    """
    Real-time network packet sniffer using Scapy AsyncSniffer.
    Pushes captured packets into a thread-safe queue.
    """

    def __init__(
        self,
        interface: str,
        packet_queue: queue.Queue,
        bpf_filter: str = "",
        promiscuous: bool = True,
    ):
        self.interface = interface
        self.packet_queue = packet_queue
        self.bpf_filter = bpf_filter
        self.promiscuous = promiscuous
        self._sniffer: Optional[AsyncSniffer] = None
        self._running = threading.Event()
        self.packets_received_total = 0
        self.packets_dropped_queue_full = 0
        self.started_at: Optional[float] = None
        self.last_packet_at: Optional[float] = None
        self.interface_status = "down"

    def _packet_handler(self, packet) -> None:
        """Callback invoked by Scapy for every captured packet."""
        try:
            self.packet_queue.put_nowait(packet)
            self.packets_received_total += 1
            self.last_packet_at = time.time()
            self.interface_status = "up"
        except queue.Full:
            self.packets_dropped_queue_full += 1
            logger.warning("packet_queue is full, captured packet dropped.")

    def start(self) -> None:
        """Start async packet capture."""
        if self._running.is_set():
            logger.warning("PacketCapture is already running.")
            return

        conf.promisc = self.promiscuous
        try:
            self._sniffer = AsyncSniffer(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self._packet_handler,
                store=False,  # Critical: Do not store packets in memory
            )
            self._sniffer.start()
            self._running.set()
            self.started_at = time.time()
            self.interface_status = "up"
            logger.info(f"PacketCapture started on interface '{self.interface}' (promiscuous={self.promiscuous}).")
        except Exception as e:
            logger.error(f"Failed to start PacketCapture on interface {self.interface}: {e}")
            raise

    def stop(self) -> None:
        """Gracefully stop packet capture."""
        if self._sniffer and self._running.is_set():
            try:
                self._sniffer.stop()
            except Exception as e:
                logger.error(f"Error stopping sniffer: {e}")
            self._running.clear()
            self.interface_status = "down"
            logger.info("PacketCapture stopped.")

    @property
    def is_running(self) -> bool:
        return self._running.is_set()

    def get_stats(self) -> dict:
        """Return capture health/statistics for API health checks and watchdogs."""
        now = time.time()
        received = int(self.packets_received_total)
        dropped = int(self.packets_dropped_queue_full)
        total = max(received + dropped, 1)
        return {
            "interface": self.interface or "auto",
            "status": self.interface_status,
            "is_running": self.is_running,
            "uptime_sec": int(now - self.started_at) if self.started_at else 0,
            "packets_received": received,
            "packets_dropped_queue_full": dropped,
            "drop_rate_pct": (100.0 * dropped / total),
            "last_packet_seen_sec_ago": (now - self.last_packet_at) if self.last_packet_at else None,
        }
