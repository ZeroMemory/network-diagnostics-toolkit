import argparse
import socket
import ssl
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from probe_options import ipv4, ports, parse_probe_args, write_probe


def probe_tls(host: str, port: int, timeout: float = 4.0) -> dict:
    result = {"host": host, "port": port, "ok": False}
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as ssock:
                # CERT_NONE returns {} for the decoded dictionary. Inspect the actual DER bytes.
                cert = x509.load_der_x509_certificate(ssock.getpeercert(binary_form=True))
                result.update(
                    {
                        "ok": True,
                        "tls_version": ssock.version(),
                        "cipher": ssock.cipher(),
                        "cert_subject": cert.subject.rfc4514_string(),
                        "cert_issuer": cert.issuer.rfc4514_string(),
                        "cert_not_before": cert.not_valid_before_utc.isoformat(),
                        "cert_not_after": cert.not_valid_after_utc.isoformat(),
                        "cert_sha256": cert.fingerprint(hashes.SHA256()).hex(),
                        "certificate_verified": False,
                    }
                )
    except (socket.timeout, TimeoutError) as exc:
        result["error"] = f"timeout: {exc}"
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True, type=ipv4)
    parser.add_argument("--ports", required=True, type=ports)
    args = parse_probe_args(parser)

    results = [probe_tls(args.target, port) for port in args.ports]
    write_probe(parser, args, results)
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
