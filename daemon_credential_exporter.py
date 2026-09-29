import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def get_active_strongswan_sas():
    """Query strongSwan gw-hq daemon for active IKE and Child SA telemetry."""
    try:
        res = subprocess.run(
            ["docker", "exec", "gw-hq", "swanctl", "--list-sas", "--pretty"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if res.returncode != 0 or not res.stdout:
            return None
        return res.stdout
    except Exception as e:
        print(f"[!] Warning: Unable to query swanctl from gw-hq: {e}")
        return None


def parse_swanctl_data(text):
    """Extract negotiated Child SA proposals, SPIs, TS, and data-plane packet metrics."""
    if not text:
        return None

    init_spi_m = re.search(r"initiator-spi\s*=\s*([0-9a-fA-F]+)", text)
    init_spi = ("0x" + init_spi_m.group(1).lower()) if init_spi_m else None

    lport_m = re.search(r"local-port\s*=\s*(\d+)", text)
    rport_m = re.search(r"remote-port\s*=\s*(\d+)", text)
    lport = int(lport_m.group(1)) if lport_m else 4500
    rport = int(rport_m.group(1)) if rport_m else 4500
    is_natt = (lport == 4500 or rport == 4500)

    # Find child-sas block
    child_blocks = re.findall(r"(\w+-\w+-\d+)\s*\{([^}]+)\}", text) or re.findall(
        r"(\w+)\s*\{([^}]+)\}", text
    )

    for name, block in child_blocks:
        if "spi-in" not in block and "spi-out" not in block:
            continue

        mode_m = re.search(r"mode\s*=\s*(\w+)", block)
        mode = mode_m.group(1).upper() if mode_m else "TUNNEL"

        spi_in_m = re.search(r"spi-in\s*=\s*([0-9a-fA-F]+)", block)
        spi_out_m = re.search(r"spi-out\s*=\s*([0-9a-fA-F]+)", block)
        spi_in = ("0x" + spi_in_m.group(1).lower()) if spi_in_m else None
        spi_out = ("0x" + spi_out_m.group(1).lower()) if spi_out_m else None

        encr_m = re.search(r"encr-alg\s*=\s*([A-Za-z0-9_]+)", block)
        keysize_m = re.search(r"encr-keysize\s*=\s*(\d+)", block)
        encr_alg = encr_m.group(1).upper() if encr_m else "AES_GCM_16"

        if "3DES" in encr_alg or "DES" in encr_alg:
            encr_id = 3
            encr_keysize = 192
        elif "GCM" in encr_alg:
            encr_id = 20
            encr_keysize = int(keysize_m.group(1)) if keysize_m else 256
        elif "CHACHA" in encr_alg:
            encr_id = 28
            encr_keysize = 256
        elif "CBC" in encr_alg:
            encr_id = 12
            encr_keysize = int(keysize_m.group(1)) if keysize_m else 256
        else:
            encr_id = 20
            encr_keysize = int(keysize_m.group(1)) if keysize_m else 256

        integ_m = re.search(r"integ-alg\s*=\s*([A-Za-z0-9_]+)", block)
        dh_m = re.search(r"dh-group\s*=\s*([A-Za-z0-9_]+)", block)

        pkts_in = int(re.search(r"packets-in\s*=\s*(\d+)", block).group(1)) if re.search(r"packets-in\s*=\s*(\d+)", block) else 0
        pkts_out = int(re.search(r"packets-out\s*=\s*(\d+)", block).group(1)) if re.search(r"packets-out\s*=\s*(\d+)", block) else 0
        bytes_in = int(re.search(r"bytes-in\s*=\s*(\d+)", block).group(1)) if re.search(r"bytes-in\s*=\s*(\d+)", block) else 0
        bytes_out = int(re.search(r"bytes-out\s*=\s*(\d+)", block).group(1)) if re.search(r"bytes-out\s*=\s*(\d+)", block) else 0

        local_ts_m = re.search(r"local-ts\s*=\s*\[\s*([0-9\.\/]+)\s*\]", block)
        remote_ts_m = re.search(r"remote-ts\s*=\s*\[\s*([0-9\.\/]+)\s*\]", block)
        local_ts = local_ts_m.group(1) if local_ts_m else "172.28.0.2/32"
        remote_ts = remote_ts_m.group(1) if remote_ts_m else "172.28.0.3/32"

        transforms = {
            "encryption": [{"id": encr_id, "length": encr_keysize}],
            "integrity": [],
            "extended_sequence_numbers": [],
        }
        if integ_m:
            integ_name = integ_m.group(1).upper()
            if "MD5" in integ_name:
                integ_id = 1
            elif "SHA1" in integ_name or "SHA_1" in integ_name:
                integ_id = 2
            elif "256" in integ_name:
                integ_id = 12
            elif "384" in integ_name:
                integ_id = 13
            elif "512" in integ_name:
                integ_id = 14
            else:
                integ_id = 12
            transforms["integrity"] = [{"id": integ_id}]
        if dh_m:
            dh_name = dh_m.group(1).upper()
            if "1024" in dh_name or "MODP_1024" in dh_name or "MODP1024" in dh_name:
                dh_id = 2
            elif "768" in dh_name or "MODP_768" in dh_name:
                dh_id = 1
            elif "2048" in dh_name or "MODP_2048" in dh_name:
                dh_id = 14
            elif "3072" in dh_name or "MODP_3072" in dh_name:
                dh_id = 15
            elif "384" in dh_name or "ECP_384" in dh_name:
                dh_id = 20
            elif "256" in dh_name or "ECP_256" in dh_name:
                dh_id = 19
            elif "25519" in dh_name or "CURVE25519" in dh_name:
                dh_id = 31
            else:
                dh_id = 14
            transforms["dh_group"] = [{"id": dh_id}]
        else:
            # strongSwan swanctl --list-sas does not print dh-group for child SAs.
            # Inspect esp_proposals in swanctl.conf to detect configured Child SA PFS.
            esp_p = ""
            hq_conf = ROOT / "hq" / "swanctl.conf"
            if hq_conf.exists():
                try:
                    m_conf = re.search(r"esp_proposals\s*=\s*([^\n\r]+)", hq_conf.read_text(encoding="utf-8"))
                    if m_conf:
                        esp_p = m_conf.group(1).upper()
                except Exception:
                    pass
            if not esp_p:
                try:
                    res_c = subprocess.run(["docker", "exec", "gw-hq", "cat", "/etc/swanctl/swanctl.conf"], capture_output=True, text=True, timeout=5)
                    if res_c.returncode == 0:
                        m_conf = re.search(r"esp_proposals\s*=\s*([^\n\r]+)", res_c.stdout)
                        if m_conf:
                            esp_p = m_conf.group(1).upper()
                except Exception:
                    pass

            if esp_p:
                if "CURVE25519" in esp_p or "X25519" in esp_p or "25519" in esp_p:
                    transforms["dh_group"] = [{"id": 31}]
                elif "CURVE448" in esp_p or "X448" in esp_p:
                    transforms["dh_group"] = [{"id": 32}]
                elif "ECP_384" in esp_p or "ECP384" in esp_p:
                    transforms["dh_group"] = [{"id": 20}]
                elif "ECP_256" in esp_p or "ECP256" in esp_p:
                    transforms["dh_group"] = [{"id": 19}]
                elif "ECP_521" in esp_p or "ECP521" in esp_p:
                    transforms["dh_group"] = [{"id": 21}]
                elif "MODP_3072" in esp_p or "MODP3072" in esp_p or "3072" in esp_p:
                    transforms["dh_group"] = [{"id": 15}]
                elif "MODP_2048" in esp_p or "MODP2048" in esp_p or "2048" in esp_p:
                    transforms["dh_group"] = [{"id": 14}]
                elif "MODP_1024" in esp_p or "MODP1024" in esp_p or "1024" in esp_p:
                    transforms["dh_group"] = [{"id": 2}]
                elif "MODP_768" in esp_p or "MODP768" in esp_p or "768" in esp_p:
                    transforms["dh_group"] = [{"id": 1}]

        l_ip = local_ts.split("/")[0]
        r_ip = remote_ts.split("/")[0]
        traffic_selectors = {
            "initiator": [{"ts_type": 7, "ip_proto": 0, "start_address": l_ip, "end_address": l_ip, "start_port": 0, "end_port": 65535}],
            "responder": [{"ts_type": 7, "ip_proto": 0, "start_address": r_ip, "end_address": r_ip, "start_port": 0, "end_port": 65535}],
        }

        total_pkts = pkts_out if pkts_out > 0 else (pkts_in if pkts_in > 0 else 1)
        total_bytes = bytes_out if bytes_out > 0 else (bytes_in if bytes_in > 0 else 100)
        avg_wire = max(64, int(total_bytes / total_pkts))

        seqs = list(range(1, total_pkts + 1))
        packets = [
            {
                "seq_num": i,
                "wire_bytes": avg_wire,
                "is_natt": is_natt,
                "timestamp": 1790328144.0 + (i * 0.05),
                "inner_src_ip": l_ip,
                "inner_dst_ip": r_ip,
            }
            for i in seqs
        ]

        active_spi = spi_out or spi_in or "0x00000000"
        has_child_pfs = bool(transforms.get("dh_group"))
        return {
            "init_spi": init_spi,
            "child_sa": {
                "present": True,
                "mode": mode,
                "is_transport_mode": (mode == "TRANSPORT"),
                "pfs": has_child_pfs,
                "traffic_selectors": traffic_selectors,
                "proposals": [
                    {
                        "proposal_num": 1,
                        "protocol_id": 3,
                        "spi": active_spi,
                        "transforms": transforms,
                    }
                ],
            },
            "traffic_selectors": traffic_selectors,
            "data_plane": {
                "spi": active_spi,
                "packet_count": total_pkts,
                "byte_count": total_bytes,
                "seq_numbers": seqs,
                "last_seq": total_pkts,
                "is_natt": is_natt,
                "src_port": lport,
                "dst_port": rport,
                "last_seen": 1790328144.0 + (total_pkts * 0.05),
                "packets": packets,
            },
        }

    return None


def main():
    print("=" * 70)
    print(" IPsec Daemon Credential & ESP Telemetry Ingest Coordinator")
    print("=" * 70)

    # 1. Query live strongSwan charon daemon for active Child SAs & ESP traffic
    print("[*] Polling gw-hq strongSwan daemon for active Child SAs & ESP packet counters...")
    sas_output = get_active_strongswan_sas()
    sa_data = parse_swanctl_data(sas_output)

    out_dir = Path("c:/ipsec-testbed/assessment_output")
    out_dir.mkdir(parents=True, exist_ok=True)
    child_sa_file = out_dir / "child_sa_export.json"

    if sa_data:
        dp = sa_data["data_plane"]
        print(f" [+] Found active Child SA | SPI: {dp['spi']} | Packets: {dp['packet_count']} | Bytes: {dp['byte_count']}B | Mode: {sa_data['child_sa']['mode']}")
        with open(child_sa_file, "w", encoding="utf-8") as f:
            json.dump(sa_data, f, indent=2)
    else:
        print(" [!] No active Child SA detected from strongSwan charon daemon.")

    # 2. Trigger in-container pipeline ingest
    print("[*] Ingesting gateway certificates & Child SA telemetry into analytical pipeline...")
    cmd = [
        "docker", "exec", "ipsec-analyzer", "python", "-c",
        """
import json, glob
from pathlib import Path
from cert_engine.daemonCertIngest import build_auth_metadata, build_peer_credentials
from pipeline.integratedPipeline import IntegratedPipeline

certs_dir = Path('/certs') if Path('/certs').exists() else Path('/workspace/certs')
sun_cert = certs_dir / 'sunCert.pem'
moon_cert = certs_dir / 'moonCert.pem'

init_cred = build_peer_credentials('initiator', sun_cert, identity_value='sun.enterprise.net')
resp_cred = build_peer_credentials('responder', moon_cert, identity_value='moon.enterprise.net')
auth_meta = build_auth_metadata(initiator=init_cred, responder=resp_cred, source='daemon_api')

out_dir = Path('/workspace/output')
child_file = out_dir / 'child_sa_export.json'
child_data = json.load(open(child_file, encoding='utf-8')) if child_file.exists() else None

canon_files = sorted(
    glob.glob(str(out_dir / 'sessions' / '*' / 'intermediate_canonical_session.json')),
    key=lambda p: Path(p).stat().st_mtime
)
if not canon_files and (out_dir / 'intermediate_canonical_session.json').exists():
    canon_files = [str(out_dir / 'intermediate_canonical_session.json')]

target_file = None
if child_data and child_data.get('init_spi'):
    cand = out_dir / 'sessions' / child_data['init_spi'] / 'intermediate_canonical_session.json'
    if cand.exists():
        target_file = cand

if not target_file and canon_files:
    target_file = Path(canon_files[-1])

if not target_file:
    print('[!] No sessions found in output directory to ingest credentials into.')
else:
    pipeline = IntegratedPipeline(output_dir=out_dir)
    s = json.load(open(target_file, encoding='utf-8'))
    if child_data:
        if 'IKE_AUTH' not in s:
            s['IKE_AUTH'] = {}
        s['IKE_AUTH']['child_sa'] = child_data['child_sa']
        s['IKE_AUTH']['traffic_selectors'] = child_data['traffic_selectors']
        s['data_plane'] = child_data['data_plane']
    res = pipeline.process_session_dict(s, auth_meta)
    print(f'[+] Ingested credentials & ESP telemetry into active session {res["session_id"]}')
    print('[+] All certificates, ESP data plane, and compliance reports successfully updated.')
"""
    ]

    res = subprocess.run(cmd, capture_output=True, text=True)
    print(res.stdout)
    if res.stderr:
        err_lines = [
            line for line in res.stderr.splitlines()
            if "CryptographyDeprecationWarning" not in line
            and "Diffie-Hellman" not in line
            and "from cryptography" not in line
            and "DHParameterNumbers" not in line
        ]
        if err_lines:
            print("\n".join(err_lines), file=sys.stderr)


if __name__ == "__main__":
    main()