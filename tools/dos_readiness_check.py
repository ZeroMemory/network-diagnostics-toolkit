import argparse
import datetime as dt
import json
import re
import shlex
import sys
from pathlib import Path
from probe_options import output_state, validate_report_paths, write_reports


import paramiko


SYSCTL_KEYS = [
    "net.ipv4.tcp_syncookies",
    "net.ipv4.tcp_max_syn_backlog",
    "net.ipv4.tcp_synack_retries",
    "net.ipv4.tcp_fin_timeout",
    "net.ipv4.tcp_tw_reuse",
    "net.ipv4.icmp_echo_ignore_broadcasts",
    "net.ipv4.icmp_ignore_bogus_error_responses",
    "net.ipv4.conf.all.rp_filter",
    "net.ipv4.conf.default.rp_filter",
    "net.netfilter.nf_conntrack_max",
    "net.netfilter.nf_conntrack_tcp_timeout_established",
]


def read_secret(path: Path, label: str) -> str:
    text = path.read_text(encoding="utf-8-sig")
    match = re.search(rf"^{re.escape(label)}: (.+)$", text, re.M)
    if not match:
        raise RuntimeError(f"Missing '{label}' in {path}")
    return match.group(1).strip()


def run_ssh(host: str, key_path: Path, sudo_password: str, username: str, known_hosts: Path, port: int = 22) -> tuple[int, str, str]:
    sysctl_keys = " ".join(shlex.quote(key) for key in SYSCTL_KEYS)
    script = f"""
set -o pipefail
printf '== time ==\\n'
date -Iseconds || true
printf '\\n== services ==\\n'
for s in ssh ufw fail2ban wg-quick@wg0; do printf '%-18s %s\\n' "$s" "$(systemctl is-active "$s" 2>/dev/null || true)"; done
printf '\\n== ufw status ==\\n'
ufw status verbose || true
printf '\\n== wireguard ==\\n'
wg show wg0 || true
printf '\\n== listening sockets ==\\n'
ss -lntup || true
printf '\\n== sysctl dos-related ==\\n'
for key in {sysctl_keys}; do sysctl "$key" 2>/dev/null || printf '%s = unavailable\\n' "$key"; done
printf '\\n== conntrack ==\\n'
COUNT="$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || true)"
MAX="$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || true)"
printf 'count=%s max=%s\\n' "$COUNT" "$MAX"
printf '\\n== nstat sample ==\\n'
nstat -az 2>/dev/null | grep -Ei 'TcpExtSyncookies|ListenOverflows|ListenDrops|TCPReqQFull|IpExtInNoRoutes|IpExtInTruncatedPkts|IpExtInCsumErrors|IcmpInErrors' || true
printf '\\n== routes ==\\n'
ip route || true
printf '\\n== rules ==\\n'
ip rule || true
printf '\\n== recent kernel risk markers ==\\n'
journalctl -k --since '24 hours ago' -o short-iso --no-pager -q | grep -Ei 'UFW BLOCK|SYN|flood|conntrack|nf_conntrack|martian|fragment|overrun|drop' | tail -200 || true
"""
    key = paramiko.Ed25519Key.from_private_key_file(str(key_path))
    client = paramiko.SSHClient()
    try:
        client.load_host_keys(str(known_hosts))
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.connect(host, port=port, username=username, pkey=key, look_for_keys=False, allow_agent=False, timeout=10, banner_timeout=10, auth_timeout=10)
        cmd = "sudo -S -p \"\" bash -lc " + shlex.quote(script)
        stdin, stdout, stderr = client.exec_command(cmd, timeout=180)
        stdin.write(sudo_password + "\n")
        stdin.flush()
        stdin.channel.shutdown_write()
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        rc = stdout.channel.recv_exit_status()
    finally:
        client.close()
    return rc, out, err


def value_for(raw: str, key: str) -> str | None:
    match = re.search(rf"^{re.escape(key)}\s*=\s*(.+)$", raw, re.M)
    return match.group(1).strip() if match else None


def section(raw: str, name: str) -> str:
    match = re.search(rf"^== {re.escape(name)} ==\n(.*?)(?=^== |\Z)", raw, re.M | re.S)
    return match.group(1).strip() if match else ""


def parse_collection(raw: str) -> tuple[int, str, str]:
    match = re.match(r"^RC=(-?\d+)\r?\n", raw)
    rc = int(match.group(1)) if match else 0
    body = raw[match.end():] if match else raw
    stdout, separator, stderr = body.partition("\nSTDERR:\n")
    return rc, stdout, stderr if separator else ""


def analyse(raw: str) -> list[str]:
    findings: list[str] = []
    rc, raw, stderr = parse_collection(raw)
    if rc != 0 or stderr.strip():
        return [f"UNKNOWN: collection failed or produced stderr (RC={rc}); readiness cannot be assessed."]

    if "Status: active" in raw and "Default: deny (incoming)" in raw:
        findings.append("OK: UFW is active and default incoming policy is deny.")
    else:
        findings.append("REVIEW: UFW is not clearly active with default deny incoming.")

    if value_for(raw, "net.ipv4.tcp_syncookies") == "1":
        findings.append("OK: TCP SYN cookies are enabled.")
    else:
        findings.append("REVIEW: TCP SYN cookies are not clearly enabled.")

    if value_for(raw, "net.ipv4.icmp_echo_ignore_broadcasts") == "1":
        findings.append("OK: broadcast ICMP echo replies are disabled.")
    else:
        findings.append("REVIEW: broadcast ICMP echo replies are not clearly disabled.")

    conntrack = section(raw, "conntrack")
    match = re.search(r"count=(\d+)\s+max=(\d+)", conntrack)
    if match:
        count = int(match.group(1))
        max_count = int(match.group(2))
        ratio = count / max_count if max_count else None
        if ratio is None:
            findings.append("UNKNOWN: conntrack maximum is zero; usage cannot be assessed.")
        elif ratio < 0.7:
            findings.append(f"OK: conntrack usage is low ({count}/{max_count}).")
        else:
            findings.append(f"REVIEW: conntrack usage is high ({count}/{max_count}).")
    else:
        findings.append("UNKNOWN: conntrack usage was not available.")

    sockets = section(raw, "listening sockets")
    watched_ports = {
        "22": "SSH",
        "5000": "application service",
        "7890": "Mihomo proxy",
        "9091": "Mihomo UI/API",
        "1053": "Mihomo DNS",
    }
    listening = [name for port, name in watched_ports.items() if re.search(rf"[:.]{port}\s", sockets)]
    if listening:
        findings.append("INFO: sensitive services are listening locally: " + ", ".join(listening) + ". Keep them limited by UFW/router/WireGuard.")

    markers = section(raw, "recent kernel risk markers")
    marker_lines = [line for line in markers.splitlines() if re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", line)]
    unavailable = re.search(r"permission denied|failed|unavailable|not found|not permitted|no journal files|not opened", markers, re.I)
    severe = [line for line in marker_lines if re.search(r"conntrack|nf_conntrack|flood|overrun", line, re.I)]
    if severe:
        findings.append(f"REVIEW: kernel logs contain {len(severe)} possible overload markers in the last 24h.")
    elif marker_lines and not unavailable:
        findings.append("OK: no obvious conntrack/flood/overrun markers in kernel logs from the last 24h.")
    else:
        findings.append("UNKNOWN: no kernel risk-marker data; empty output does not establish healthy logs.")

    findings.append("LIMIT: this check does not generate DoS traffic. Volumetric DDoS must be mitigated by ISP/upstream filtering, CDN, or DDoS-protected hosting.")
    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host")
    parser.add_argument("--username")
    parser.add_argument("--known-hosts")
    parser.add_argument("--ssh-port", type=int, default=22)
    parser.add_argument("--credential-file")
    parser.add_argument("--input-log", help="Analyse a saved log without connecting to a host")
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args()
    if not args.input_log and not all((args.host, args.username, args.known_hosts, args.credential_file)):
        parser.error("host, username, known-hosts and credential-file are required for SSH collection")
    if not 1 <= args.ssh_port <= 65535:
        parser.error("SSH port must be 1..65535")

    out_dir = Path(args.out_dir)
    if args.input_log:
        inputs = [Path(args.input_log)]
    else:
        cred = Path(args.credential_file)
        ubuntu_password = read_secret(cred, "Ubuntu new password")
        key_path = Path(read_secret(cred, "SSH private key"))
        inputs = [cred, key_path, Path(args.known_hosts)]
    outputs = [out_dir / name for name in ("ubuntu-dos-readiness.txt", "dos-readiness.json", "summary.txt")]
    try:
        validate_report_paths(inputs, outputs)
        baselines = {output: output_state(output) for output in outputs}
    except (OSError, RuntimeError, ValueError) as exc:
        parser.error(str(exc))
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.input_log:
        rc, stdout, stderr = parse_collection(inputs[0].read_text(encoding="utf-8-sig"))
    else:
        rc, stdout, stderr = run_ssh(args.host, key_path, ubuntu_password, args.username, Path(args.known_hosts), args.ssh_port)
    raw = f"RC={rc}\n\n{stdout}\n\nSTDERR:\n{stderr}\n"
    findings = analyse(raw)
    data = {
        "collected_at": dt.datetime.now().isoformat(timespec="seconds"),
        "host": args.host,
        "ssh_rc": rc,
        "input_log": args.input_log,
        "findings": findings,
    }
    summary = [
        "DoS/DDoS readiness summary",
        "==========================",
        f"Collected at: {data['collected_at']}",
        f"Host: {args.host}",
        "",
        "Findings:",
    ]
    summary.extend(f"  - {item}" for item in findings)
    summary.extend(
        [
            "",
            "Files:",
            "  ubuntu-dos-readiness.txt",
            "  dos-readiness.json",
        ]
    )
    text = "\n".join(summary) + "\n"
    try:
        write_reports(inputs, dict(zip(outputs, (raw, json.dumps(data, ensure_ascii=False, indent=2), text))), baselines)
    except (OSError, RuntimeError, ValueError) as exc:
        parser.error(str(exc))
    print(text)
    return 0 if rc == 0 else rc


if __name__ == "__main__":
    raise SystemExit(main())
