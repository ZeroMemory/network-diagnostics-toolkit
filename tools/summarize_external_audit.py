import argparse
import csv
import json
from pathlib import Path
from urllib.parse import urlparse
from web_exposure_probe import SAFE_PATHS, DEEPER_PATHS


EXPECTED_CLOSED_TCP = {
    22: "SSH must not be exposed to the internet",
    80: "router or web service",
    443: "router or web service",
    2375: "Docker API without TLS",
    2376: "Docker API",
    3000: "development web app or Grafana",
    5000: "application service",
    5432: "PostgreSQL",
    6379: "Redis",
    6443: "Kubernetes API",
    7890: "Mihomo proxy",
    8080: "alternative or admin HTTP",
    8443: "alternative or admin HTTPS",
    9000: "MinIO, ClickHouse, or development service",
    9001: "MinIO admin console",
    9090: "Cockpit",
    9091: "Mihomo UI/API",
    9200: "Elasticsearch",
    1053: "Mihomo DNS",
    10250: "Kubernetes kubelet",
    27017: "MongoDB",
    4330: "PCP pmlogger",
    44321: "PCP pmcd",
    51820: "WireGuard is expected on UDP, not TCP",
}


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def validate_observations(root: Path) -> None:
    def require(condition, label):
        if not condition:
            raise ValueError(label)

    def valid_port(value):
        return type(value) is int and 1 <= value <= 65535

    meta = read_json(root / "00-metadata.json")
    require(isinstance(meta.get("target"), str) and meta["target"], "metadata target missing")
    require(meta.get("mode") in ("safe", "deeper") and isinstance(meta.get("started_at"), str), "metadata run fields missing")
    tcp = meta.get("tested_tcp_ports")
    require(isinstance(tcp, list) and tcp and all(valid_port(p) for p in tcp) and len(set(tcp)) == len(tcp), "tested TCP scope missing or invalid")
    udp_text = meta.get("tested_udp_ports")
    require(isinstance(udp_text, str) and udp_text, "tested UDP scope missing")
    udp = [int(p) for p in udp_text.split(",")]
    require(all(valid_port(p) for p in udp) and len(set(udp)) == len(udp) and valid_port(meta.get("dns_port")), "UDP/DNS scope invalid")
    stages = meta.get("stage_exit_codes")
    expected_stages = ("http_probe.py", "tls_probe.py", "web_exposure_probe.py", "udp_probe.py", "dns_recursion_probe.py")
    require(isinstance(stages, dict) and all(type(stages.get(name)) is int for name in expected_stages), "probe stage status missing")
    with (root / "01-tcp-connect-sweep.csv").open(encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    require(len(rows) == len(tcp) and {int(row["port"]) for row in rows} == set(tcp), "TCP rows do not cover declared scope")
    require(all(row.get("state") in ("open", "closed_or_filtered") for row in rows), "TCP row state missing")
    for filename, web in (("04-http-probe.json", False), ("04b-web-exposure.json", True)):
        rows = read_json(root / filename)
        expected_paths = (DEEPER_PATHS if meta["mode"] == "deeper" else SAFE_PATHS) if web else ["/"]
        expected = {(p, scheme, path) for p in tcp for scheme in ("http", "https") for path in expected_paths}
        seen = set()
        for row in rows:
            require(type(row.get("ok")) is bool and row.get("scheme") in ("http", "https") and row.get("port") in tcp, filename + " transport fields missing")
            parsed = urlparse(row.get("url", "")) if not web else None
            if parsed:
                require(parsed.hostname == meta["target"] and parsed.port == row["port"] and parsed.scheme == row["scheme"], "HTTP URL differs from run target")
            path = row.get("path") if web else parsed.path
            key = (row["port"], row["scheme"], path)
            require(key in expected and key not in seen, filename + " unexpected or repeated scope")
            seen.add(key)
            if row["ok"]:
                require(type(row.get("status")) is int and 100 <= row["status"] <= 599 and isinstance(row.get("headers"), dict), filename + " response fields missing")
                if web:
                    require(isinstance(row.get("sensitive_markers"), list), "web marker data missing")
            else:
                require(isinstance(row.get("error"), str) and row["error"], filename + " error evidence missing")
        require(seen == expected, filename + " does not cover declared scope")
    rows = read_json(root / "05-tls-probe.json")
    require(len(rows) == len(tcp) and {row.get("port") for row in rows} == set(tcp), "TLS scope incomplete")
    for row in rows:
        require(row.get("host") == meta["target"] and type(row.get("ok")) is bool, "TLS transport fields missing")
        if row["ok"]:
            require(all(isinstance(row.get(k), str) and row[k] for k in ("tls_version", "cert_subject", "cert_issuer", "cert_not_before", "cert_not_after", "cert_sha256")) and type(row.get("certificate_verified")) is bool, "TLS certificate fields missing")
        else:
            require(isinstance(row.get("error"), str) and row["error"], "TLS error evidence missing")
    rows = read_json(root / "06-udp-probe.json")
    require(len(rows) == len(udp) and {row.get("port") for row in rows} == set(udp), "UDP scope incomplete")
    for row in rows:
        require(row.get("host") == meta["target"] and row.get("state") in ("responded", "open_or_filtered", "error"), "UDP transport fields missing")
        if row["state"] == "responded":
            require(type(row.get("response_len")) is int and row["response_len"] >= 0 and row.get("response_from") == f"{meta['target']}:{row['port']}", "UDP response evidence missing")
        else:
            require(bool(row.get("error") or row.get("note")), "UDP failure evidence missing")
    dns = read_json(root / "07-dns-recursion.json")
    require(dns.get("host") == meta["target"] and dns.get("port") == meta["dns_port"] and isinstance(dns.get("qname"), str) and type(dns.get("responded")) is bool, "DNS transport fields missing")
    if dns["responded"]:
        require(all(type(dns.get(k)) is bool for k in ("recursion_available", "recursion_observed")) and all(type(dns.get(k)) is int for k in ("bytes", "answer_count", "a_answer_count", "rcode")), "DNS response evidence missing")
    else:
        require(bool(dns.get("error") or dns.get("note")), "DNS failure evidence missing")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--result-dir", required=True)
    parser.add_argument("--expected-udp", default="51820")
    args = parser.parse_args()
    root = Path(args.result_dir)

    required = ["00-metadata.json", "01-tcp-connect-sweep.csv", "04-http-probe.json", "05-tls-probe.json", "04b-web-exposure.json", "06-udp-probe.json", "07-dns-recursion.json"]
    missing = [name for name in required if not (root / name).is_file()]
    problems = list(missing)
    print("Network observation summary")
    print("===========================")
    if missing:
        print("INCOMPLETE: missing " + ", ".join(missing))
        return 2
    for name in required:
        if not name.endswith(".json") or not (root / name).is_file():
            continue
        try:
            data = read_json(root / name)
            if name in ("00-metadata.json", "07-dns-recursion.json"):
                if not isinstance(data, dict) or not data:
                    raise ValueError("expected a nonempty object")
            elif not isinstance(data, list) or not data or not all(isinstance(item, dict) for item in data):
                raise ValueError("expected a nonempty observation array")
        except (OSError, ValueError) as exc:
            print(f"INCOMPLETE: {name}: {type(exc).__name__}")
            return 2
    try:
        validate_observations(root)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print("INCOMPLETE: " + str(exc))
        return 2
    meta_path = root / "00-metadata.json"
    if meta_path.exists():
        meta = read_json(meta_path)
        print(f"Target: {meta.get('target')}")
        print(f"Mode: {meta.get('mode', 'safe')}")
        print(f"Source public IP: {meta.get('local_public_ip')}")
        print(f"Started: {meta.get('started_at')}")
    print()

    tcp_path = root / "01-tcp-connect-sweep.csv"
    open_tcp = []
    tcp_count = 0
    if tcp_path.exists():
        with tcp_path.open("r", encoding="utf-8-sig", newline="") as f:
            for row in csv.DictReader(f):
                tcp_count += 1
                if row.get("state") not in ("open", "closed_or_filtered"):
                    problems.append("TCP row with unknown state")
                if row.get("state") == "open":
                    open_tcp.append(int(row["port"]))
        if not tcp_count:
            problems.append("TCP sweep contains no observations")
    print(f"Open TCP ports: {', '.join(map(str, open_tcp)) if open_tcp else 'none'}")
    if open_tcp:
        print("TCP findings:")
        for port in open_tcp:
            reason = EXPECTED_CLOSED_TCP.get(port, "unexpected public TCP service")
            print(f"  - TCP/{port}: REVIEW ({reason})")
    elif tcp_count:
        print(f"TCP observation: no accepted connections across {tcp_count} tested ports; closed and filtered are not distinguished.")
    else:
        print("TCP observation: UNKNOWN, no sweep data.")

    udp_path = root / "06-udp-probe.json"
    if udp_path.exists():
        udp = read_json(udp_path)
        responded = [item for item in udp if item.get("state") == "responded"]
        print()
        print("UDP responses:")
        if responded:
            for item in responded:
                print(f"  - UDP/{item['port']} responded from {item.get('response_from')} ({item.get('response_len')} bytes)")
        else:
            print("  none; UDP silence is expected for filtered ports and for WireGuard without a valid handshake")

    http_path = root / "04-http-probe.json"
    if http_path.exists():
        http = read_json(http_path)
        ok = [item for item in http if item.get("ok")]
        print()
        print("HTTP(S) responses:")
        if ok:
            for item in ok:
                server = item.get("headers", {}).get("Server", "")
                print(f"  - {item['url']} -> {item.get('status')} {item.get('reason')} Server={server}")
        else:
            print("  none")

    exposure_path = root / "04b-web-exposure.json"
    if exposure_path.exists():
        exposure = read_json(exposure_path)
        interesting = [
            item
            for item in exposure
            if item.get("ok")
            and item.get("status") in (200, 401, 403)
            and item.get("path") not in ("/", "/robots.txt", "/sitemap.xml")
        ]
        sensitive = [item for item in interesting if item.get("sensitive_markers")]
        print()
        print("Web exposure checks:")
        if interesting:
            for item in interesting[:30]:
                markers = ",".join(item.get("sensitive_markers") or [])
                suffix = f" markers={markers}" if markers else ""
                print(f"  - {item['scheme']}://target:{item['port']}{item['path']} -> {item.get('status')}{suffix}")
            if len(interesting) > 30:
                print(f"  - ...and {len(interesting) - 30} more; see 04b-web-exposure.json")
        else:
            print("  none")
        if sensitive:
            print("  REVIEW: sensitive markers appeared in sampled responses.")

    dns_path = root / "07-dns-recursion.json"
    if dns_path.exists():
        dns = read_json(dns_path)
        print()
        print("Public DNS recursion:")
        if dns.get("responded"):
            recursion = "yes" if dns.get("recursion_available") else "no"
            print(f"  UDP/{dns['port']} responded from {dns.get('response_from')}; recursion_available={recursion}")
            if dns.get("recursion_observed"):
                print("  REVIEW: recursive answer observed; investigate public resolver exposure.")
            elif dns.get("recursion_available"):
                print("  REVIEW: resolver advertises recursion; this alone does not prove a recursive answer.")
        else:
            print("  no validated response; silence is inconclusive")
            if dns.get("error"):
                problems.append("DNS probe returned an error")

    tls_path = root / "05-tls-probe.json"
    if tls_path.exists():
        tls = read_json(tls_path)
        print()
        print(f"TLS connections: {sum(bool(item.get('ok')) for item in tls)}; certificate trust is not validated by this inspection probe.")

    if meta_path.exists():
        failed = [name for name, code in meta.get("stage_exit_codes", {}).items() if code != 0]
        problems.extend("failed stage " + name for name in failed)
        if meta.get("nmap") == "missing":
            problems.append("Nmap was requested but is not installed")

    print()
    print(f"Expected UDP ports supplied by operator: {args.expected_udp}")
    print("These observations cover only tested ports and paths; they do not certify overall server security.")
    if problems:
        print("INCOMPLETE: " + "; ".join(problems))
        return 2
    print("Collection complete for the recorded test scope. Review reachable services and correlate with internal logs.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
