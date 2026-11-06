import argparse
import http.client
import socket
import ssl
from probe_options import ipv4, ports, parse_probe_args, write_probe


SAFE_PATHS = [
    "/",
    "/robots.txt",
    "/sitemap.xml",
    "/.env",
    "/.git/HEAD",
    "/.svn/entries",
    "/backup.zip",
    "/backup.tar.gz",
    "/db.sql",
    "/dump.sql",
    "/config.php",
    "/config.json",
    "/server-status",
    "/phpinfo.php",
    "/admin",
    "/login",
    "/debug",
    "/metrics",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/api",
]

DEEPER_PATHS = SAFE_PATHS + [
    "/.DS_Store",
    "/.well-known/security.txt",
    "/wp-login.php",
    "/wp-admin/",
    "/xmlrpc.php",
    "/phpmyadmin/",
    "/pma/",
    "/adminer.php",
    "/manager/html",
    "/cgi-bin/",
    "/console",
    "/swagger",
    "/swagger-ui/",
    "/openapi.json",
    "/graphql",
    "/prometheus",
    "/grafana/",
    "/minio/",
]


SENSITIVE_MARKERS = [
    "DB_PASSWORD",
    "SECRET_KEY",
    "AWS_SECRET",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "[core]",
    "phpinfo()",
    "Index of /",
]


def request(host: str, port: int, scheme: str, path: str, timeout: float = 3.0) -> dict:
    result = {"scheme": scheme, "port": port, "path": path, "ok": False}
    conn = None
    try:
        if scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request("GET", path, headers={"User-Agent": "private-audit/1.0", "Accept": "*/*"})
        resp = conn.getresponse()
        body = resp.read(2048)
        text = body.decode("utf-8", "replace")
        markers = [marker for marker in SENSITIVE_MARKERS if marker.lower() in text.lower()]
        result.update(
            {
                "ok": True,
                "status": resp.status,
                "reason": resp.reason,
                "headers": dict(resp.getheaders()),
                "body_len_sampled": len(body),
                "sensitive_markers": markers,
                "body_prefix": text[:500],
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
    parser.add_argument("--mode", choices=["safe", "deeper"], default="safe")
    args = parse_probe_args(parser)

    paths = DEEPER_PATHS if args.mode == "deeper" else SAFE_PATHS
    results = []
    for port in args.ports:
        for scheme in ("http", "https"):
            for path in paths:
                results.append(request(args.target, port, scheme, path))

    write_probe(parser, args, results)
    findings = [r for r in results if r.get("ok") and r.get("status") in (200, 401, 403) and r.get("path") != "/"]
    print(f"wrote {args.out}; interesting web responses={len(findings)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
