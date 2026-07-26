"""Offline PCAP precision/recall regression gate.

Ground-truth JSON may map either a source IP or a canonical flow key
``src|dst|sport|dport|protocol`` to a boolean attack label.
"""

import argparse
import json
import queue
import tempfile
import time
from pathlib import Path
from typing import Dict, List

from scapy.all import Ether, IP, TCP, PcapReader, wrpcap

from sagedral_ml.detection.decision_engine import DecisionEngine
from sagedral_ml.detection.ml_engine import MLEngine
from sagedral_ml.detection.signature_engine import SignatureEngine
from sagedral_ml.features.extractor import FlowAggregator


def _flow_key(flow) -> str:
    return "%s|%s|%s|%s|%s" % (
        flow.src_ip,
        flow.dst_ip,
        flow.src_port,
        flow.dst_port,
        flow.protocol,
    )


def evaluate_pcap(
    pcap_path: str,
    truth: Dict[str, bool],
    model_dir: str,
) -> Dict[str, float]:
    completed = queue.Queue()
    aggregator = FlowAggregator(
        completed,
        {
            "flow_timeout": 60,
            "max_packets_per_flow": 10000,
            "max_active_flows": 50000,
        },
    )
    last_timestamp = time.time()
    with PcapReader(pcap_path) as reader:
        for packet in reader:
            last_timestamp = float(getattr(packet, "time", last_timestamp))
            aggregator.process_packet(packet)
    aggregator.cleanup_timeouts(now=last_timestamp + 61)

    signature = SignatureEngine()
    ml_engine = MLEngine(model_dir=model_dir)
    decision = DecisionEngine(dedup_window=0)
    true_positive = 0
    false_positive = 0
    false_negative = 0
    true_negative = 0
    evaluated = 0
    while not completed.empty():
        flow = completed.get_nowait()
        vector = flow.to_feature_vector()
        vector["src_ip"] = flow.src_ip
        sig_result = signature.evaluate(vector)
        ml_result = ml_engine.predict(vector)
        result = decision.decide(
            sig_result,
            ml_result,
            src_ip=flow.src_ip,
            now=last_timestamp,
        )
        expected = bool(truth.get(_flow_key(flow), truth.get(flow.src_ip, False)))
        predicted = bool(result.is_threat)
        evaluated += 1
        if expected and predicted:
            true_positive += 1
        elif expected:
            false_negative += 1
        elif predicted:
            false_positive += 1
        else:
            true_negative += 1

    precision = true_positive / max(true_positive + false_positive, 1)
    recall = true_positive / max(true_positive + false_negative, 1)
    return {
        "evaluated_flows": evaluated,
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "true_negative": true_negative,
        "precision": precision,
        "recall": recall,
    }


def create_self_test_dataset(directory: str):
    """Create a deterministic, tiny labeled PCAP for the CI smoke gate."""
    packets: List = []
    base_time = 1700000000.0

    normal_syn = (
        Ether()
        / IP(src="192.0.2.10", dst="192.0.2.20")
        / TCP(sport=41000, dport=443, flags="S")
    )
    normal_reply = (
        Ether()
        / IP(src="192.0.2.20", dst="192.0.2.10")
        / TCP(sport=443, dport=41000, flags="SA")
    )
    normal_fin = (
        Ether()
        / IP(src="192.0.2.10", dst="192.0.2.20")
        / TCP(sport=41000, dport=443, flags="FA")
    )
    for index, packet in enumerate((normal_syn, normal_reply, normal_fin)):
        packet.time = base_time + (index * 0.1)
        packets.append(packet)

    for index in range(120):
        attack = (
            Ether()
            / IP(src="198.51.100.66", dst="192.0.2.20")
            / TCP(sport=42000, dport=443, flags="S")
        )
        attack.time = base_time + 1.0 + (index * 0.005)
        packets.append(attack)
    attack_fin = (
        Ether()
        / IP(src="198.51.100.66", dst="192.0.2.20")
        / TCP(sport=42000, dport=443, flags="F")
    )
    attack_fin.time = base_time + 1.7
    packets.append(attack_fin)

    pcap_path = str(Path(directory) / "regression.pcap")
    wrpcap(pcap_path, packets)
    return pcap_path, {
        "192.0.2.10": False,
        "198.51.100.66": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap")
    parser.add_argument("--ground-truth")
    parser.add_argument("--model-dir")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--minimum-precision", type=float, default=0.70)
    parser.add_argument("--minimum-recall", type=float, default=0.85)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="sagedral-pcap-regression-") as tmp:
        if args.self_test:
            pcap_path, truth = create_self_test_dataset(tmp)
        else:
            if not args.pcap or not args.ground_truth:
                parser.error("--pcap and --ground-truth are required without --self-test")
            pcap_path = args.pcap
            with open(args.ground_truth, "r", encoding="utf-8") as handle:
                truth = json.load(handle)
        model_dir = args.model_dir or str(Path(tmp) / "models")
        result = evaluate_pcap(pcap_path, truth, model_dir)
        print(json.dumps(result, indent=2, sort_keys=True))
        if (
            result["precision"] < args.minimum_precision
            or result["recall"] < args.minimum_recall
        ):
            raise SystemExit(1)


if __name__ == "__main__":
    main()
