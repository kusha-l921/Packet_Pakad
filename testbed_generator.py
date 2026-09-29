"""IPsec Testbed Configuration & Traffic Generator.

Interactive CLI session to configure IPsec tunnels (HQ <-> Branch),
initiate strongSwan Child SAs, inject synthetic traffic, and export telemetry.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent
CAPTURES_DIR = ROOT / "captures"
ASSESSMENT_DIR = ROOT / "assessment_output"
EXPORTER_PATH = ROOT / "daemon_credential_exporter.py"

HQ_IP = "172.28.0.2"
BRANCH_IP = "172.28.0.3"
CONTAINERS = ("gw-hq", "gw-branch", "ipsec-analyzer")

MODES = ["tunnel", "transport"]

IKE_OPTIONS = [
    {
        "label": "PQC-Hybrid: AES-256-GCM + SHA384 + ECP-384 + ML-KEM-768",
        "short": "ML-KEM-768 | AES-256-GCM | ECP-384",
        "ike": "aes256gcm16-prfsha384-ecp384-ke1_mlkem768,aes256gcm16-prfsha384-ecp384",
        "tag": "PQC",
    },
    {
        "label": "PQC-Hybrid: AES-256-GCM + SHA384 + ECP-384 + ML-KEM-1024",
        "short": "ML-KEM-1024 | AES-256-GCM | ECP-384",
        "ike": "aes256gcm16-prfsha384-ecp384-ke1_mlkem1024,aes256gcm16-prfsha384-ecp384",
        "tag": "PQC",
    },
    {
        "label": "PQC-Hybrid: AES-256-GCM + SHA256 + Curve25519 + ML-KEM-768",
        "short": "ML-KEM-768 | AES-256-GCM | X25519",
        "ike": "aes256gcm16-prfsha256-curve25519-ke1_mlkem768,aes256gcm16-prfsha256-curve25519",
        "tag": "PQC",
    },
    {
        "label": "PQC-Hybrid: AES-128-GCM + SHA256 + Curve25519 + ML-KEM-512",
        "short": "ML-KEM-512 | AES-128-GCM | X25519",
        "ike": "aes128gcm16-prfsha256-curve25519-ke1_mlkem512,aes128gcm16-prfsha256-curve25519",
        "tag": "PQC",
    },
    {
        "label": "PQC-Hybrid: AES-256-GCM + SHA384 + ECP-384 + FrodoKEM-976",
        "short": "FrodoKEM-976 | AES-256-GCM | ECP-384",
        "ike": "aes256gcm16-prfsha384-ecp384-ke1_frodokem976shake,aes256gcm16-prfsha384-ecp384",
        "tag": "PQC",
    },
    {
        "label": "Classical: AES-256-GCM + PRF-SHA384 + ECP-384 (RFC 8247)",
        "short": "AES-256-GCM | SHA384 | ECP-384",
        "ike": "aes256gcm16-prfsha384-ecp384",
        "tag": "CLASSICAL",
    },
    {
        "label": "Classical: AES-128-GCM + PRF-SHA256 + ECP-256",
        "short": "AES-128-GCM | SHA256 | ECP-256",
        "ike": "aes128gcm16-prfsha256-ecp256",
        "tag": "CLASSICAL",
    },
    {
        "label": "Classical: AES-256-GCM + PRF-SHA256 + Curve25519",
        "short": "AES-256-GCM | SHA256 | X25519",
        "ike": "aes256gcm16-prfsha256-curve25519",
        "tag": "CLASSICAL",
    },
    {
        "label": "Classical: AES-256-CBC + SHA384 + MODP-3072",
        "short": "AES-256-CBC | SHA384 | MODP-3072",
        "ike": "aes256-sha384-modp3072",
        "tag": "CBC",
    },
    {
        "label": "Classical: AES-256-CBC + SHA256 + MODP-2048",
        "short": "AES-256-CBC | SHA256 | MODP-2048",
        "ike": "aes256-sha256-modp2048",
        "tag": "CBC",
    },
    {
        "label": "Broken: 3DES-CBC + HMAC-MD5 + MODP-1024 (RFC 8247 Prohibited)",
        "short": "3DES-CBC | MD5 | MODP-1024",
        "ike": "3des-md5-modp1024",
        "tag": "BROKEN",
    },
]

ESP_OPTIONS = [
    {"label": "AES-256-GCM (No PFS)", "esp": "aes256gcm16"},
    {"label": "AES-128-GCM (No PFS)", "esp": "aes128gcm16"},
    {"label": "AES-256-GCM + ECP-384 (PFS)", "esp": "aes256gcm16-ecp384"},
    {"label": "AES-256-GCM + Curve25519 (PFS)", "esp": "aes256gcm16-curve25519"},
    {"label": "AES-256-CBC + HMAC-SHA256 (No PFS)", "esp": "aes256-sha256"},
    {"label": "3DES-CBC + HMAC-MD5 (Broken / RFC Prohibited)", "esp": "3des-md5"},
]

TRAFFIC_OPTIONS = [
    "ICMP (Ping)",
    "VoIP (UDP 5004)",
    "Video-streaming (UDP 8000)",
    "Web-browsing (TCP 80)",
    "All Traffic Types",
]


def run_cmd(args, timeout=120, cwd=None):
    if isinstance(args, str):
        res = subprocess.run(
            args,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd or ROOT,
        )
    else:
        res = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd or ROOT,
        )
    return ((res.stdout or "") + (res.stderr or "")).strip()


def run_stream(args, on_line=None, timeout=600, cwd=None):
    proc = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        cwd=cwd or ROOT,
    )
    lines = []
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            text = line.rstrip()
            lines.append(text)
            if on_line:
                on_line(text)
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        raise
    return proc.returncode or 0, "\n".join(lines)


def docker_exec(container, *cmd, timeout=60):
    return run_cmd(["docker", "exec", container, *cmd], timeout=timeout)


def write_swanctl_conf(node, mode, proposals, esp_prop, child_count=1):
    is_hq = node == "hq"
    local_ip = HQ_IP if is_hq else BRANCH_IP
    remote_ip = BRANCH_IP if is_hq else HQ_IP
    local_id = "sun.enterprise.net" if is_hq else "moon.enterprise.net"
    remote_id = "moon.enterprise.net" if is_hq else "sun.enterprise.net"
    local_cert = "sunCert.pem" if is_hq else "moonCert.pem"
    remote_cert = "moonCert.pem" if is_hq else "sunCert.pem"

    children_blocks = []
    # Primary corporate traffic SA
    children_blocks.append(f"""            corp-traffic-sa {{
                esp_proposals = {esp_prop}
                mode = {mode}
                local_ts = {local_ip}/32
                remote_ts = {remote_ip}/32
                rekey_time = 3600
                start_action = none
            }}""")

    if child_count >= 2:
        children_blocks.append(f"""            voice-traffic-sa {{
                esp_proposals = {esp_prop}
                mode = {mode}
                local_ts = {local_ip}/32[udp]
                remote_ts = {remote_ip}/32[udp]
                rekey_time = 3600
                start_action = none
            }}""")

    if child_count >= 3:
        children_blocks.append(f"""            mgmt-traffic-sa {{
                esp_proposals = {esp_prop}
                mode = {mode}
                local_ts = {local_ip}/32[icmp]
                remote_ts = {remote_ip}/32[icmp]
                rekey_time = 3600
                start_action = none
            }}""")

    children_str = "\n".join(children_blocks)

    conf = f"""connections {{
    enterprise-vpn {{
        version = 2
        local_addrs  = {local_ip}
        remote_addrs = {remote_ip}
        proposals = {proposals}

        local {{
            auth = pubkey
            certs = {local_cert}
            id = {local_id}
        }}
        remote {{
            auth = pubkey
            certs = {remote_cert}
            id = {remote_id}
        }}

        children {{
{children_str}
        }}
    }}
}}
"""
    dest = ROOT / node
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "swanctl.conf").write_text(conf, encoding="utf-8")


def container_states():
    states = {
        name: {"running": False, "health": "n/a", "label": "DOWN"} for name in CONTAINERS
    }
    try:
        out = run_cmd(
            ["docker", "ps", "-a", "--format", "{{.Names}}\t{{.Status}}"],
            timeout=6,
        )
    except Exception:
        return states
    for line in out.splitlines():
        if "\t" not in line:
            continue
        name, status = line.split("\t", 1)
        if name not in states:
            continue
        low = status.lower()
        running = low.startswith("up")
        health = "n/a"
        if "(healthy)" in low:
            health = "healthy"
        elif "(unhealthy)" in low:
            health = "unhealthy"
        elif "(health: starting)" in low:
            health = "starting"
        states[name] = {
            "running": running,
            "health": health,
            "label": "UP" if running else "DOWN",
        }
    return states


def daemon_ready(container):
    try:
        res = subprocess.run(
            ["docker", "exec", container, "swanctl", "--stats"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return res.returncode == 0
    except Exception:
        return False


def wait_daemons(on_line=None, attempts=30):
    for name in ("gw-hq", "gw-branch"):
        for _ in range(attempts):
            if daemon_ready(name):
                if on_line:
                    on_line(f"{name} charon is ready")
                break
            time.sleep(1)
        else:
            return False, f"{name} failed to initialize"
    return True, "daemons ready"


def compose_up(on_line=None):
    CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
    code, _ = run_stream(["docker", "compose", "up", "-d"], on_line=on_line)
    if code != 0:
        return False, "docker compose up failed"
    ok, msg = wait_daemons(on_line=on_line)
    if not ok:
        return False, msg
    for name in ("gw-hq", "gw-branch"):
        out = docker_exec(name, "swanctl", "--load-all")
        if on_line:
            on_line(f"{name} load-all: {out or 'ok'}")
    return True, "lab is up"


def compose_down(on_line=None):
    code, _ = run_stream(["docker", "compose", "down"], on_line=on_line)
    return code == 0, "lab stopped" if code == 0 else "compose down failed"


def parse_list_sas(text):
    if not text or "No IKE" in text:
        return {"established": False, "raw": text or "", "ike": None, "child": None}
    ike_name = None
    m_name = re.search(r"^(\S+):\s+#\d+", text, re.M)
    if m_name:
        ike_name = m_name.group(1)

    def grab(pattern, default="n/a"):
        m = re.search(pattern, text, re.I)
        return m.group(1) if m else default

    established = "ESTABLISHED" in text
    installed = "INSTALLED" in text
    mode_m = re.search(r"INSTALLED,\s*(\w+)", text)
    in_m = re.search(r"in\s+([0-9a-fA-F]+),\s+([\d.]+[KMG]?)\s+bytes,\s+(\d+)\s+packets", text)
    out_m = re.search(r"out\s+([0-9a-fA-F]+),\s+([\d.]+[KMG]?)\s+bytes,\s+(\d+)\s+packets", text)
    alg_m = re.search(r"^\s+((?:AES_|CHACHA|PRF_|ECP_|CURVE|ML_|MODP_|SHA).+)$", text, re.M)
    child_alg_m = re.search(r"ESP:([A-Z0-9_/-]+)", text)
    return {
        "established": established,
        "installed": installed,
        "raw": text,
        "ike": {
            "name": ike_name or "enterprise-vpn",
            "state": "ESTABLISHED" if established else "DOWN",
            "initiator_spi": grab(r"initiator.?spi[:\s]+([0-9a-fA-Fx]+)"),
            "responder_spi": grab(r"responder.?spi[:\s]+([0-9a-fA-Fx]+)"),
            "encr": alg_m.group(1).strip() if alg_m else "n/a",
        },
        "child": {
            "state": "INSTALLED" if installed else "ABSENT",
            "mode": mode_m.group(1) if mode_m else grab(r"mode:\s+(\w+)"),
            "spi_in": in_m.group(1) if in_m else "n/a",
            "spi_out": out_m.group(1) if out_m else "n/a",
            "bytes_in": in_m.group(2) if in_m else "0",
            "bytes_out": out_m.group(2) if out_m else "0",
            "pkts_in": in_m.group(3) if in_m else "0",
            "pkts_out": out_m.group(3) if out_m else "0",
            "esp": child_alg_m.group(1) if child_alg_m else "n/a",
        },
    }


def list_sas():
    try:
        states = container_states()
        if not states.get("gw-hq", {}).get("running"):
            return {"established": False, "raw": "", "ike": None, "child": None}
        text = docker_exec("gw-hq", "swanctl", "--list-sas", timeout=8)
    except Exception as exc:
        return {"established": False, "raw": str(exc), "ike": None, "child": None}
    return parse_list_sas(text)


def deploy_and_initiate(mode, ike_opt, esp_opt, on_line=None):
    write_swanctl_conf("hq", mode, ike_opt["ike"], esp_opt["esp"])
    write_swanctl_conf("branch", mode, ike_opt["ike"], esp_opt["esp"])
    if on_line:
        on_line(f"wrote swanctl.conf  mode={mode}  ike={ike_opt['ike']}  esp={esp_opt['esp']}")
    docker_exec("gw-hq", "swanctl", "--terminate", "--ike", "enterprise-vpn")
    time.sleep(1)
    docker_exec("gw-branch", "swanctl", "--load-all")
    docker_exec("gw-hq", "swanctl", "--load-all")
    if on_line:
        on_line("initiating Child SA corp-traffic-sa ...")
    init_res = docker_exec("gw-hq", "swanctl", "--initiate", "--child", "corp-traffic-sa", timeout=90)
    if on_line and init_res:
        on_line(init_res)
    sas = list_sas()
    ok = bool(sas.get("installed") or (sas.get("raw") and "INSTALLED" in sas["raw"]))
    return ok, sas


def inject_traffic(traffic_type, target_ip=BRANCH_IP, on_line=None):
    if on_line:
        on_line(f"injecting {traffic_type}")
    if traffic_type in ("ICMP (Ping)", "All Traffic Types"):
        out = docker_exec("gw-hq", "ping", "-c", "3", "-W", "1", target_ip, timeout=10)
        if on_line:
            last = out.splitlines()[-2:] if out else []
            on_line(" ".join(last) or "ping complete")
    py = "python3"
    if traffic_type in ("VoIP (UDP 5004)", "All Traffic Types"):
        docker_exec(
            "gw-hq",
            py,
            "-c",
            (
                "import socket,time\n"
                "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n"
                f"addr=('{target_ip}',5004)\n"
                "payload=b'RTP_VOIP_SAMPLE'*5\n"
                "for _ in range(10):\n"
                "    s.sendto(payload, addr)\n"
                "    time.sleep(0.005)\n"
            ),
            timeout=10,
        )
        if on_line:
            on_line("sent 10 VoIP UDP datagrams to :5004")
    if traffic_type in ("Video-streaming (UDP 8000)", "All Traffic Types"):
        docker_exec(
            "gw-hq",
            py,
            "-c",
            (
                "import socket\n"
                "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n"
                f"[s.sendto(b'V'*1300,('{target_ip}',8000)) for _ in range(15)]"
            ),
            timeout=10,
        )
        if on_line:
            on_line("sent 15 video UDP frames to :8000")
    if traffic_type in ("Web-browsing (TCP 80)", "All Traffic Types"):
        docker_exec(
            "gw-hq",
            py,
            "-c",
            (
                "import socket\n"
                "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n"
                "s.settimeout(0.1)\n"
                f"[s.connect_ex(('{target_ip}',80)) for _ in range(3)]"
            ),
            timeout=5,
        )
        if on_line:
            on_line("attempted 3 TCP connects to :80")


def run_exporter(on_line=None):
    if not EXPORTER_PATH.exists():
        return False, "daemon_credential_exporter.py missing"
    if on_line:
        on_line("running credential exporter ...")
    res = subprocess.run(
        [sys.executable, str(EXPORTER_PATH)],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=180,
    )
    out = (res.stdout or "").strip()
    err = (res.stderr or "").strip()
    if on_line:
        for line in (out + ("\n" + err if err else "")).splitlines():
            if (
                "CryptographyDeprecationWarning" in line
                or "Diffie-Hellman" in line
                or "from cryptography" in line
                or "DHParameterNumbers" in line
            ):
                continue
            on_line(line)
    return res.returncode == 0, out


def load_json(name):
    path = ASSESSMENT_DIR / name
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def latest_session_id():
    sessions = ASSESSMENT_DIR / "sessions"
    if not sessions.exists():
        data = load_json("unified_rag_payload.json")
        return (data or {}).get("session_id")
    dirs = [p for p in sessions.iterdir() if p.is_dir()]
    if not dirs:
        return None
    newest = max(dirs, key=lambda p: p.stat().st_mtime)
    return newest.name


def load_reports():
    return {
        "rfc": load_json("rfc_compliance_report.json"),
        "crypto": load_json("crypto_vector_posture.json"),
        "certs": load_json("certificate_health_report.json"),
        "child": load_json("child_sa_export.json"),
        "rag": load_json("unified_rag_payload.json"),
        "session_id": latest_session_id(),
    }


def prompt_menu(title, options):
    print(f"\n--- {title} ---")
    for idx, opt in enumerate(options, 1):
        label = opt["label"] if isinstance(opt, dict) else opt
        print(f" [{idx:2d}] {label}")
    while True:
        choice = input("Select an option (number): ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(options):
            return options[int(choice) - 1]
        print("Invalid choice. Try again.")


def run_cli_session():
    os.makedirs(CAPTURES_DIR, exist_ok=True)
    selected_mode = prompt_menu("Select IPsec Operating Mode", MODES)
    selected_ike = prompt_menu("Select IKE Proposal Suite", IKE_OPTIONS)
    selected_esp = prompt_menu("Select ESP Child SA Proposal", ESP_OPTIONS)
    selected_traffic = prompt_menu("Select Traffic Pattern", TRAFFIC_OPTIONS)
    print("\n" + "=" * 70)
    print(f"[*] Deploying Configuration: {selected_ike['label']}")
    print(f"    Mode:   {selected_mode.upper()}")
    print(f"    IKE:    {selected_ike['ike']}")
    print(f"    ESP:    {selected_esp['esp']}")
    print("=" * 70)
    ok, sas = deploy_and_initiate(selected_mode, selected_ike, selected_esp, on_line=print)
    print(sas.get("raw") or "")
    if not ok:
        print("\n[!] Handshake failed to establish Child SA.")
        return
    time.sleep(1)
    inject_traffic(selected_traffic, on_line=print)
    run_exporter(on_line=print)
    print("\n[+] Cycle completed. All vectors, ESP data plane, and certs updated.")


def main():

    print(r"""                                                                          
╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴
                                                                                    
   ╷ ╷╭┬╮╭╮ ╭─╮╭─╴╷  ╷  ╭─╮   ╭─╴╭─╮╭─╮╭─╮╭─╮╭─╮╭─╮╶┬╴╷╭─╮╭╮╷                       
   │ ││││├┴╮├┬╯├╴ │  │  ├─┤   │  │ │├┬╯├─╯│ │├┬╯├─┤ │ ││ ││╰┤                       
   ╰─╯╵ ╵╰─╯╵╰╴╰─╴╰─╴╰─╴╵ ╵   ╰─╴╰─╯╵╰╴╵  ╰─╯╵╰╴╵ ╵ ╵ ╵╰─╯╵ ╵                       
                                                                                    
╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴╶─╴
""")




    try:
        run_cli_session()
    except (KeyboardInterrupt, EOFError):
        print("\n\n[!] Session exited.")
        sys.exit(0)


if __name__ == "__main__":
    main()
