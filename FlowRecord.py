import numpy as np
from collections import defaultdict, deque


class FlowRecord:
    def __init__(self, initiator_ip, window_size=200, stride=25):
        self.initiator_ip = initiator_ip
        self.window_size = window_size
        self.stride = stride
        
        self.timestamps = deque(maxlen=window_size)
        self.sizes = deque(maxlen=window_size)
        self.is_forward = deque(maxlen=window_size)
        self.packets_since_last_predict = 0
        self.last_seen = 0.0

    def update(self, meta):
        self.timestamps.append(meta["timestamp"])
        self.sizes.append(meta["wire_bytes"])
        self.is_forward.append(meta["src_ip"] == self.initiator_ip)
        self.packets_since_last_predict += 1
        self.last_seen = meta["timestamp"]

        # Only trigger inference when window is full AND stride is reached
        if len(self.timestamps) == self.window_size and self.packets_since_last_predict >= self.stride:
            self.packets_since_last_predict = 0
            return True
        return False

    def is_idle(self, current_time, timeout_seconds=5.0):
        """Trigger 2: Time-based check for inactive/paused flows."""
        return (
            (current_time - self.last_seen) > timeout_seconds
            and self.packets_since_last_predict > 0
        )

    def extract_features(self):
        n = len(self.timestamps)
        if n < 2:
            return None

        times = np.array(self.timestamps, dtype=np.float64)
        sizes = np.array(self.sizes, dtype=np.float64)
        dirs = np.array(self.is_forward, dtype=bool)

        fwd_sizes = sizes[dirs]
        bwd_sizes = sizes[~dirs]

        n_fwd = len(fwd_sizes)
        n_bwd = len(bwd_sizes)

        tot_bytes = float(np.sum(sizes))
        fwd_bytes = float(np.sum(fwd_sizes)) if n_fwd > 0 else 0.0
        bwd_bytes = float(np.sum(bwd_sizes)) if n_bwd > 0 else 0.0

        duration = float(times[-1] - times[0])
        effective_duration = duration if duration > 1e-6 else 1e-6

        iats = np.diff(times)
        mean_iat = float(np.mean(iats))
        min_iat = float(np.min(iats))
        max_iat = float(np.max(iats))
        std_iat = float(np.std(iats)) if len(iats) > 1 else 0.0

        sec_bins = defaultdict(int)
        for t in times:
            sec_bins[int(t)] += 1
        max_pkts_1s = max(sec_bins.values()) if sec_bins else 1

        feature_dict = {
            "total_packets": n,
            "forward_packets": n_fwd,
            "backward_packets": n_bwd,
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