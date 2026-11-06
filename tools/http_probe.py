import argparse
import http.client
import socket
import ssl
from urllib.parse import urlparse
from probe_options import ipv4, ports, parse_probe_args, write_probe


def probe_url(url: str, timeout: float = 4.0) -> dict:
    parsed = urlparse(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    result = {"url": url, "scheme": parsed.scheme, "port": port, "ok": False}
    conn = None
    try:
        if parsed.scheme == "https":
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(parsed.hostname, port, timeout=timeout, context=context)
        else:
            conn = http.client.HTTPConnection(parsed.hostname, port, timeout=timeout)
        conn.request("GET", "/", headers={"User-Agent": "private-audit/1.0", "Accept": "*/*"})
        resp = conn.getresponse()
        body = resp.read(512)
        result.update(
            {
                "ok": True,
                "status": resp.status,
                "reason": resp.reason,
                "headers": dict(resp.getheaders()),
                "body_prefix": body.decode("utf-8", "replace"),
            }
        )
    except (socket.timeout, TimeoutError) as exc:
        result["error"] = f"timeout: {exc}"
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if conn:
            conn.close()
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True, type=ipv4)
    parser.add_argument("--ports", required=True, type=ports)
    args = parse_probe_args(parser)

    results = []
    for port in args.ports:
        for scheme in ("http", "https"):
            results.append(probe_url(f"{scheme}://{args.target}:{port}/"))

    write_probe(parser, args, results)
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
