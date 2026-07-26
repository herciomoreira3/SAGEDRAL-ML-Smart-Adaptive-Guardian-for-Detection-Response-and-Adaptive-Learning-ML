"""
PacketCapture class for non-blocking real-time packet sniffing using Scapy.
"""

import sagedral_ml
import os
import queue
import threading
import logging
import time
import platform
import mmap
import select
import socket
import struct
import ctypes
import subprocess
from abc import ABC, abstractmethod
from typing import Optional
from scapy.all import AsyncSniffer, Ether, conf

logger = logging.getLogger("sagedral_ml.capture.sniffer")


class BasePacketCapture(ABC):
    """Stable capture backend contract used by the orchestrator."""

    @abstractmethod
    def start(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def stop(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def get_stats(self) -> dict:
        raise NotImplementedError


class PacketCapture(BasePacketCapture):
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
        backend: str = "scapy",
    ):
        self.interface = interface
        self.packet_queue = packet_queue
        self.bpf_filter = bpf_filter
        self.promiscuous = promiscuous
        self.backend = str(backend or "scapy").lower()
        if self.backend not in ("scapy", "libpcap", "af_packet"):
            raise ValueError("Unsupported capture backend: %s" % self.backend)
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
        if self.backend == "libpcap":
            try:
                conf.use_pcap = True
            except Exception as exc:
                raise RuntimeError("libpcap backend unavailable: %s" % exc)
        elif self.backend == "af_packet" and platform.system().lower() != "linux":
            raise RuntimeError("af_packet capture backend is only available on Linux")
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
            "backend": self.backend,
            "status": self.interface_status,
            "is_running": self.is_running,
            "uptime_sec": int(now - self.started_at) if self.started_at else 0,
            "packets_received": received,
            "packets_dropped_queue_full": dropped,
            "drop_rate_pct": (100.0 * dropped / total),
            "last_packet_seen_sec_ago": (now - self.last_packet_at) if self.last_packet_at else None,
        }


class ScapyPacketCapture(PacketCapture):
    def __init__(self, *args, **kwargs):
        kwargs["backend"] = "scapy"
        super().__init__(*args, **kwargs)


class LibpcapPacketCapture(PacketCapture):
    def __init__(self, *args, **kwargs):
        kwargs["backend"] = "libpcap"
        super().__init__(*args, **kwargs)


class AFPacketCapture(PacketCapture):
    """Linux TPACKET_V2 PACKET_RX_RING capture backend.

    Frames are read from a kernel/userspace mmap ring and only decoded to a
    Scapy packet at the boundary required by the existing feature extractor.
    """

    SOL_PACKET = 263
    PACKET_RX_RING = 5
    PACKET_STATISTICS = 6
    PACKET_VERSION = 10
    TPACKET_V2 = 1
    TP_STATUS_KERNEL = 0
    TP_STATUS_USER = 1
    ETH_P_ALL = 0x0003
    SO_ATTACH_FILTER = 26

    def __init__(self, *args, **kwargs):
        kwargs["backend"] = "af_packet"
        super().__init__(*args, **kwargs)
        self._socket = None
        self._ring = None
        self._reader_thread = None
        self._frame_size = 2048
        self._frame_count = 0
        self._ring_stop = threading.Event()
        self._kernel_packets = 0
        self._kernel_drops = 0

    def start(self) -> None:
        if platform.system().lower() != "linux":
            raise RuntimeError("af_packet capture backend is only available on Linux")
        if self._running.is_set():
            return

        block_size = 1 << 20
        block_count = 8
        self._frame_count = (block_size // self._frame_size) * block_count
        request_data = struct.pack(
            "IIII",
            block_size,
            block_count,
            self._frame_size,
            self._frame_count,
        )
        raw_socket = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.htons(self.ETH_P_ALL),
        )
        try:
            if self.bpf_filter:
                self._attach_bpf_filter(raw_socket, self.bpf_filter)
            raw_socket.setsockopt(
                self.SOL_PACKET,
                self.PACKET_VERSION,
                struct.pack("I", self.TPACKET_V2),
            )
            raw_socket.setsockopt(
                self.SOL_PACKET,
                self.PACKET_RX_RING,
                request_data,
            )
            raw_socket.bind((self.interface, 0))
            ring = mmap.mmap(
                raw_socket.fileno(),
                block_size * block_count,
                flags=mmap.MAP_SHARED,
                prot=mmap.PROT_READ | mmap.PROT_WRITE,
            )
        except Exception:
            raw_socket.close()
            raise

        self._socket = raw_socket
        self._ring = ring
        self._ring_stop.clear()
        self._running.set()
        self.started_at = time.time()
        self.interface_status = "up"
        self._reader_thread = threading.Thread(
            target=self._ring_reader,
            daemon=True,
            name="sagedral-af-packet",
        )
        self._reader_thread.start()
        logger.info(
            "AF_PACKET PACKET_RX_RING started on %s (%d frames).",
            self.interface,
            self._frame_count,
        )

    @classmethod
    def _attach_bpf_filter(cls, raw_socket, expression: str) -> None:
        """Compile a tcpdump expression and attach classic BPF to the socket."""
        try:
            result = subprocess.run(
                ["tcpdump", "-ddd", expression],
                capture_output=True,
                text=True,
                timeout=5,
                check=True,
            )
            lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            count = int(lines[0])
            instructions = lines[1:]
            if count <= 0 or len(instructions) != count:
                raise RuntimeError("tcpdump returned an invalid BPF program")

            class SockFilter(ctypes.Structure):
                _fields_ = [
                    ("code", ctypes.c_ushort),
                    ("jt", ctypes.c_ubyte),
                    ("jf", ctypes.c_ubyte),
                    ("k", ctypes.c_uint32),
                ]

            program_array = (SockFilter * count)()
            for index, instruction in enumerate(instructions):
                code, jump_true, jump_false, constant = (
                    int(value) for value in instruction.split()
                )
                program_array[index] = SockFilter(
                    code, jump_true, jump_false, constant
                )

            class SockFprog(ctypes.Structure):
                _fields_ = [
                    ("length", ctypes.c_ushort),
                    ("filters", ctypes.POINTER(SockFilter)),
                ]

            program = SockFprog(count, program_array)
            libc = ctypes.CDLL(None, use_errno=True)
            result_code = libc.setsockopt(
                raw_socket.fileno(),
                socket.SOL_SOCKET,
                cls.SO_ATTACH_FILTER,
                ctypes.byref(program),
                ctypes.sizeof(program),
            )
            if result_code != 0:
                errno_value = ctypes.get_errno()
                raise OSError(errno_value, os.strerror(errno_value))
        except Exception as exc:
            raise RuntimeError(
                "Could not compile/attach AF_PACKET BPF filter: %s" % exc
            )

    def _ring_reader(self) -> None:
        frame_index = 0
        while not self._ring_stop.is_set():
            ring = self._ring
            raw_socket = self._socket
            if ring is None or raw_socket is None:
                break
            frame_offset = frame_index * self._frame_size
            status_value = struct.unpack_from("I", ring, frame_offset)[0]
            if not (status_value & self.TP_STATUS_USER):
                try:
                    select.select([raw_socket], [], [], 0.25)
                except (OSError, ValueError):
                    break
                continue
            try:
                snap_len = struct.unpack_from("I", ring, frame_offset + 8)[0]
                mac_offset = struct.unpack_from("H", ring, frame_offset + 12)[0]
                seconds = struct.unpack_from("I", ring, frame_offset + 16)[0]
                nanoseconds = struct.unpack_from("I", ring, frame_offset + 20)[0]
                start = frame_offset + mac_offset
                end = min(start + snap_len, frame_offset + self._frame_size)
                if 0 < snap_len and start < end:
                    packet = Ether(bytes(ring[start:end]))
                    packet.time = float(seconds) + (float(nanoseconds) / 1e9)
                    self._packet_handler(packet)
            except Exception as exc:
                logger.debug("AF_PACKET frame decode failed: %s", exc)
            finally:
                struct.pack_into(
                    "I", ring, frame_offset, self.TP_STATUS_KERNEL
                )
                frame_index = (frame_index + 1) % self._frame_count

    def _read_kernel_statistics(self) -> None:
        if self._socket is None:
            return
        try:
            raw = self._socket.getsockopt(
                self.SOL_PACKET, self.PACKET_STATISTICS, 8
            )
            packets, drops = struct.unpack("II", raw)
            self._kernel_packets += int(packets)
            self._kernel_drops += int(drops)
        except OSError:
            pass

    def get_stats(self) -> dict:
        self._read_kernel_statistics()
        stats = super().get_stats()
        stats["kernel_packets"] = self._kernel_packets
        stats["kernel_drops"] = self._kernel_drops
        total = max(self._kernel_packets, 1)
        stats["kernel_drop_rate_pct"] = (
            100.0 * self._kernel_drops / total
        )
        return stats

    def stop(self) -> None:
        self._ring_stop.set()
        self._running.clear()
        if self._reader_thread is not None:
            self._reader_thread.join(timeout=2)
        self._read_kernel_statistics()
        if self._ring is not None:
            try:
                self._ring.close()
            except Exception:
                pass
            self._ring = None
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None
        self.interface_status = "down"


def create_packet_capture(
    backend: str,
    interface: str,
    packet_queue: queue.Queue,
    bpf_filter: str = "",
    promiscuous: bool = True,
) -> BasePacketCapture:
    backend_name = str(backend or "scapy").lower()
    backend_class = {
        "scapy": ScapyPacketCapture,
        "libpcap": LibpcapPacketCapture,
        "af_packet": AFPacketCapture,
    }.get(backend_name)
    if backend_class is None:
        raise ValueError("Unknown capture backend: %s" % backend_name)
    return backend_class(
        interface=interface,
        packet_queue=packet_queue,
        bpf_filter=bpf_filter,
        promiscuous=promiscuous,
    )
