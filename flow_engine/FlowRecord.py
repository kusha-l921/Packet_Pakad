from __future__ import annotations

from collections import defaultdict, deque
from typing import Any
import numpy as np


class FlowRecord:
    """Maintains packet arrival history and extracts 25 statistical features for a bidirectional flow.

    Tracks timestamps, wire sizes, and packet directions in a bounded sliding window FIFO queue.
    """

    def __init__(
        self,
        initiator_ip: str,
        window_size: int = 200,
        stride: int = 25,
    ) -> None:
        self.initiator_ip = initiator_ip
        self.window_size = window_size
        self.stride = stride

        self.timestamps: deque[float] = deque(maxlen=window_size)
        self.sizes: deque[float] = deque(maxlen=window_size)
        self.is_forward: deque[bool] = deque(maxlen=window_size)
        self.packets_since_last_predict: int = 0
        self.last_seen: float = 0.0

    @property
    def packet_count(self) -> int:
        """Current number of packets buffered in the sliding window."""
        return len(self.timestamps)

    def update(self, meta: dict[str, Any]) -> bool:
        """Append a packet record to the sliding window.

        Returns True if the sliding window is full and stride interval has been reached.
        """
        ts = float(meta.get("timestamp", 0.0))
        size = float(meta.get("wire_bytes", 0))
        src = str(meta.get("src_ip", ""))

        self.timestamps.append(ts)
        self.sizes.append(size)
        self.is_forward.append(src == self.initiator_ip)
        self.packets_since_last_predict += 1
        self.last_seen = ts

        # Only trigger inference when window is full AND stride is reached
        if len(self.timestamps) == self.window_size and self.packets_since_last_predict >= self.stride:
            self.packets_since_last_predict = 0
            return True
        return False

    def is_idle(self, current_time: float, timeout_seconds: float = 5.0) -> bool:
        """Check whether the flow has been inactive past the timeout with pending packets."""
        return (
            (current_time - self.last_seen) > timeout_seconds
            and self.packets_since_last_predict > 0
        )

    def extract_features(self) -> dict[str, float] | None:
        """Extract 25 statistical flow metrics from the current packet sliding window.

        Returns None if fewer than 2 packets are buffered.
        """
        n = len(self.timestamps)
        if n < 2:
            return None

        times = np.array(self.timestamps, dtype=np.float64)
        sizes = np.array(self.sizes, dtype=np.float64)
        dirs = np.array(self.is_forward, dtype=bool)

        fwd_sizes = sizes[dirs]
        bwd_sizes = sizes[~dirs]

        n_fwd = int(len(fwd_sizes))
        n_bwd = int(len(bwd_sizes))

        tot_bytes = float(np.sum(sizes))
        fwd_bytes = float(np.sum(fwd_sizes)) if n_fwd > 0 else 0.0
        bwd_bytes = float(np.sum(bwd_sizes)) if n_bwd > 0 else 0.0

        duration = float(times[-1] - times[0])
        effective_duration = duration if duration > 1e-6 else 1e-6

        iats = np.diff(times)
        mean_iat = float(np.mean(iats)) if len(iats) > 0 else 0.0
        min_iat = float(np.min(iats)) if len(iats) > 0 else 0.0
        max_iat = float(np.max(iats)) if len(iats) > 0 else 0.0
        std_iat = float(np.std(iats)) if len(iats) > 1 else 0.0

        sec_bins: dict[int, int] = defaultdict(int)
        for t in times:
            sec_bins[int(t)] += 1
        max_pkts_1s = float(max(sec_bins.values())) if sec_bins else 1.0

        feature_dict: dict[str, float] = {
            "total_packets": float(n),
            "forward_packets": float(n_fwd),
            "backward_packets": float(n_bwd),
            "total_bytes": tot_bytes,
            "forward_bytes": fwd_bytes,
            "backward_bytes": bwd_bytes,
            "minimum_packet_size": float(np.min(sizes)),
            "maximum_packet_size": float(np.max(sizes)),
            "mean_packet_size": float(np.mean(sizes)),
            "standard_deviation_packet_size": float(np.std(sizes)),
            "median_packet_size": float(np.median(sizes)),
            "forward_mean_packet_size": float(np.mean(fwd_sizes)) if n_fwd > 0 else 0.0,
            "backward_mean_packet_size": float(np.mean(bwd_sizes)) if n_bwd > 0 else 0.0,
            "flow_duration_seconds": duration,
            "packets_per_second": n / effective_duration,
            "bytes_per_second": tot_bytes / effective_duration,
            "mean_inter_arrival_time": mean_iat,
            "minimum_inter_arrival_time": min_iat,
            "maximum_inter_arrival_time": max_iat,
            "standard_deviation_inter_arrival_time": std_iat,
            "forward_packet_ratio": n_fwd / n,
            "backward_packet_ratio": n_bwd / n,
            "forward_byte_ratio": (fwd_bytes / tot_bytes) if tot_bytes > 0 else 0.0,
            "backward_byte_ratio": (bwd_bytes / tot_bytes) if tot_bytes > 0 else 0.0,
            "maximum_packets_in_one_second": max_pkts_1s,
        }

        return feature_dict