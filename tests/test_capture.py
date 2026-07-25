"""
Basic unit tests for PacketCapture statistics tracking.
"""

import queue
import time
from unittest.mock import patch

from sagedral_ml.capture.sniffer import PacketCapture


def test_packet_capture_stats_initial_state():
    pq = queue.Queue(maxsize=2)
    capture = PacketCapture(interface="lo", packet_queue=pq, bpf_filter="", promiscuous=False)
    stats = capture.get_stats()
    assert stats["interface"] == "lo"
    assert stats["packets_received"] == 0
    assert stats["packets_dropped_queue_full"] == 0
    assert stats["is_running"] is False


def test_packet_handler_increments_counters():
    pq = queue.Queue(maxsize=10)
    capture = PacketCapture(interface="lo", packet_queue=pq)
    fake_packet = b"fake-packet-bytes"

    capture._packet_handler(fake_packet)
    stats = capture.get_stats()
    assert stats["packets_received"] == 1
    assert stats["status"] == "up"
    assert stats["last_packet_seen_sec_ago"] is not None


def test_packet_handler_tracks_queue_full_drops():
    pq = queue.Queue(maxsize=1)
    capture = PacketCapture(interface="lo", packet_queue=pq)
    capture._packet_handler(b"first")
    capture._packet_handler(b"second-should-drop")

    stats = capture.get_stats()
    assert stats["packets_received"] == 1
    assert stats["packets_dropped_queue_full"] == 1
    assert stats["drop_rate_pct"] > 0.0


def test_get_stats_uptime_after_manual_start_timestamp():
    pq = queue.Queue(maxsize=5)
    capture = PacketCapture(interface="lo", packet_queue=pq)
    capture.started_at = time.time() - 5
    capture.interface_status = "up"
    stats = capture.get_stats()
    assert stats["uptime_sec"] >= 5
