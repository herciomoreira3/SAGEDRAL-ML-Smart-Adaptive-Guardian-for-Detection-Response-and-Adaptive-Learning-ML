"""
FlowRecord dataclass representing a single aggregated 5-tuple network flow.
Generates 28 statistical numerical features for LightGBM and Signature detection engines.
"""

import time
from dataclasses import dataclass, field
from typing import Dict, List, Any
import numpy as np


@dataclass
class FlowRecord:
    """
    Representation of a 5-tuple network flow and its accumulated statistics.
    """
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int  # 6=TCP, 17=UDP, 1=ICMP

    start_time: float = field(default_factory=time.time)
    end_time: float = field(default_factory=time.time)
    last_fwd_time: float = 0.0
    last_bwd_time: float = 0.0

    total_fwd_packets: int = 0
    total_bwd_packets: int = 0
    total_fwd_bytes: int = 0
    total_bwd_bytes: int = 0

    fwd_packet_lengths: List[int] = field(default_factory=list)
    bwd_packet_lengths: List[int] = field(default_factory=list)
    fwd_iat_list: List[float] = field(default_factory=list)
    bwd_iat_list: List[float] = field(default_factory=list)

    syn_flag_count: int = 0
    fin_flag_count: int = 0
    rst_flag_count: int = 0
    psh_flag_count: int = 0
    ack_flag_count: int = 0
    urg_flag_count: int = 0

    fwd_header_len: int = 0
    bwd_header_len: int = 0

    def add_packet(self, pkt_len: int, header_len: int, flags: Dict[str, bool], is_forward: bool, timestamp: float):
        self.end_time = timestamp

        if is_forward:
            self.total_fwd_packets += 1
            self.total_fwd_bytes += pkt_len
            self.fwd_packet_lengths.append(pkt_len)
            self.fwd_header_len += header_len

            if self.last_fwd_time > 0.0:
                iat = max(timestamp - self.last_fwd_time, 0.0)
                self.fwd_iat_list.append(iat)
            self.last_fwd_time = timestamp
        else:
            self.total_bwd_packets += 1
            self.total_bwd_bytes += pkt_len
            self.bwd_packet_lengths.append(pkt_len)
            self.bwd_header_len += header_len

            if self.last_bwd_time > 0.0:
                iat = max(timestamp - self.last_bwd_time, 0.0)
                self.bwd_iat_list.append(iat)
            self.last_bwd_time = timestamp

        if flags:
            if flags.get("SYN"): self.syn_flag_count += 1
            if flags.get("FIN"): self.fin_flag_count += 1
            if flags.get("RST"): self.rst_flag_count += 1
            if flags.get("PSH"): self.psh_flag_count += 1
            if flags.get("ACK"): self.ack_flag_count += 1
            if flags.get("URG"): self.urg_flag_count += 1

    def to_feature_vector(self) -> Dict[str, Any]:
        """
        Convert FlowRecord to a dictionary of 28 numeric features.
        Matches exact schema required by Signature Engine and LightGBM model.
        """
        duration = max(self.end_time - self.start_time, 1e-6)

        fwd_lens = self.fwd_packet_lengths if self.fwd_packet_lengths else [0]
        bwd_lens = self.bwd_packet_lengths if self.bwd_packet_lengths else [0]
        fwd_iats = self.fwd_iat_list if self.fwd_iat_list else [0.0]
        bwd_iats = self.bwd_iat_list if self.bwd_iat_list else [0.0]

        total_bytes = self.total_fwd_bytes + self.total_bwd_bytes
        total_pkts = self.total_fwd_packets + self.total_bwd_packets

        fwd_len_mean = float(np.mean(fwd_lens))
        fwd_len_std = float(np.std(fwd_lens)) if len(fwd_lens) > 1 else 0.0

        bwd_len_mean = float(np.mean(bwd_lens))
        bwd_len_std = float(np.std(bwd_lens)) if len(bwd_lens) > 1 else 0.0

        fwd_iat_mean = float(np.mean(fwd_iats))
        fwd_iat_std = float(np.std(fwd_iats)) if len(fwd_iats) > 1 else 0.0

        bwd_iat_mean = float(np.mean(bwd_iats))
        bwd_iat_std = float(np.std(bwd_iats)) if len(bwd_iats) > 1 else 0.0

        down_up_ratio = float(self.total_bwd_bytes) / float(max(self.total_fwd_bytes, 1))

        return {
            "duration": float(duration),
            "total_fwd_packets": int(self.total_fwd_packets),
            "total_bwd_packets": int(self.total_bwd_packets),
            "total_fwd_bytes": int(self.total_fwd_bytes),
            "total_bwd_bytes": int(self.total_bwd_bytes),
            "fwd_packet_len_mean": fwd_len_mean,
            "fwd_packet_len_std": fwd_len_std,
            "bwd_packet_len_mean": bwd_len_mean,
            "bwd_packet_len_std": bwd_len_std,
            "flow_bytes_per_sec": float(total_bytes) / duration,
            "flow_packets_per_sec": float(total_pkts) / duration,
            "fwd_iat_mean": fwd_iat_mean,
            "fwd_iat_std": fwd_iat_std,
            "bwd_iat_mean": bwd_iat_mean,
            "bwd_iat_std": bwd_iat_std,
            "psh_flag_count": int(self.psh_flag_count),
            "urg_flag_count": int(self.urg_flag_count),
            "syn_flag_count": int(self.syn_flag_count),
            "fin_flag_count": int(self.fin_flag_count),
            "rst_flag_count": int(self.rst_flag_count),
            "ack_flag_count": int(self.ack_flag_count),
            "avg_fwd_segment_size": fwd_len_mean,
            "avg_bwd_segment_size": bwd_len_mean,
            "fwd_header_len": int(self.fwd_header_len),
            "bwd_header_len": int(self.bwd_header_len),
            "down_up_ratio": down_up_ratio,
            "protocol": int(self.protocol),
            "dst_port": int(self.dst_port),
        }
