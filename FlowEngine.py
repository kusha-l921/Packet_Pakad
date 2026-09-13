from FlowRecord import FlowRecord

IDLE_TIMEOUT = 5.0
MIN_PACKETS = 10

active_flows = {}


def process_packet(model, esp_meta, window_size=200, stride=25):
  if not esp_meta:
    return

  current_time = esp_meta["timestamp"]
  flow_key = tuple(sorted([esp_meta["src_ip"], esp_meta["dst_ip"]]))

  if flow_key not in active_flows:
    active_flows[flow_key] = FlowRecord(
        initiator_ip=esp_meta["src_ip"], window_size=window_size, stride=stride
    )

  flow = active_flows[flow_key]

  if flow.update(esp_meta):
    features = flow.extract_features()
    if features:
      prediction = model.predict([list(features.values())])[0]
      print(f"[FLOW {flow_key}] Verdict: {prediction}")

  expired = []
  for key, record in active_flows.items():
    if record.is_idle(current_time, timeout_seconds=IDLE_TIMEOUT):
      if len(record.timestamps) >= MIN_PACKETS:
        features = record.extract_features()
        if features:
          prediction = model.predict([list(features.values())])[0]
          print(f"[TIMEOUT TRIGGER] Inactive Flow {key} -> {prediction}")
      record.packets_since_last_predict = 0
      expired.append(key)

  for key in expired:
    del active_flows[key]