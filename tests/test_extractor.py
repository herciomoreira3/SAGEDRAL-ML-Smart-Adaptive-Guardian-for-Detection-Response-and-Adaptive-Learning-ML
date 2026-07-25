"""
Basic unit tests for FlowAggregator and FlowRecord feature extraction.
"""

import queue
import time

from sagedral_ml.features.extractor import FlowAggregator
from sagedral_ml.features.models import FlowRecord, RunningStat


def test_running_stat_mean_std():
    stat = RunningStat()
    for value in (10.0, 20.0, 30.0):
        stat.update(value)
    assert stat.n == 3
    assert abs(stat.mean - 20.0) < 1e-6
    assert stat.std >= 0.0


def test_flow_record_feature_vector_has_28_keys():
    flow = FlowRecord(
        src_ip="192.168.1.10",
        dst_ip="8.8.8.8",
        src_port=12345,
        dst_port=443,
        protocol=6,
    )
    flow.add_packet(100, 20, {"SYN": True, "ACK": False}, is_forward=True, timestamp=time.time())
    flow.add_packet(80, 20, {"SYN": False, "ACK": True}, is_forward=False, timestamp=time.time() + 0.1)

    features = flow.to_feature_vector()
    assert len(features) == 28
    assert features["total_fwd_packets"] == 1
    assert features["total_bwd_packets"] == 1
    assert features["syn_flag_count"] == 1


def test_flow_aggregator_processes_dict_packet():
    flow_q = queue.Queue()
    aggregator = FlowAggregator(flow_q, {"flow_timeout": 60, "max_active_flows": 100})
    now = time.time()

    aggregator.process_packet({
        "src_ip": "10.0.0.5",
        "dst_ip": "10.0.0.1",
        "src_port": 40000,
        "dst_port": 80,
        "protocol": 6,
        "pkt_len": 64,
        "header_len": 40,
        "flags": {"SYN": True},
        "timestamp": now,
    })
    aggregator.process_packet({
        "src_ip": "10.0.0.5",
        "dst_ip": "10.0.0.1",
        "src_port": 40000,
        "dst_port": 80,
        "protocol": 6,
        "pkt_len": 52,
        "header_len": 40,
        "flags": {"FIN": True},
        "timestamp": now + 0.05,
    })

    assert not flow_q.empty()
    completed = flow_q.get_nowait()
    assert isinstance(completed, FlowRecord)
    assert completed.src_ip == "10.0.0.5"
