import argparse
import socket
import time
from probe_options import ipv4, ports, parse_probe_args, write_probe


PAYLOADS = {
    53: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01",
    123: b"\x1b" + b"\0" * 47,
    51820: b"\0" * 32,
}


def probe_udp(host: str, port: int, timeout: float = 2.0) -> dict:
    payload = PAYLOADS.get(port, b"\0")
    result = {"host": host, "port": port, "state": "open_or_filtered", "response_len": 0}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    started = time.perf_counter()
    try:
        sock.connect((host, port))
        sock.send(payload)
        data = sock.recv(2048)
        result.update(
            {
                "state": "responded",
                "response_len": len(data),
                "response_from": f"{host}:{port}",
                "ms": round((time.perf_counter() - started) * 1000, 2),
            }
        )
    except socket.timeout:
        result["note"] = "No UDP response. This is normal for filtered ports and also normal for WireGuard without a valid handshake."
    except Exception as exc:
        result["state"] = "error"
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        sock.close()
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True, type=ipv4)
    parser.add_argument("--ports", required=True, type=ports)
    args = parse_probe_args(parser)

    results = [probe_udp(args.target, port) for port in args.ports]
    write_probe(parser, args, results)
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
