import argparse
import socket
import time
import secrets
from probe_options import ipv4, port, parse_probe_args, write_probe


def name_end(data: bytes, cursor: int) -> int:
    visited = set()
    encoded_end = None
    expanded_size = 1
    while True:
        if cursor in visited or cursor >= len(data):
            raise ValueError("DNS name is truncated or has a compression cycle")
        visited.add(cursor)
        size = data[cursor]
        cursor += 1
        if size & 0xC0 == 0xC0:
            if cursor >= len(data):
                raise ValueError("Truncated DNS name pointer")
            target = (size & 0x3F) << 8 | data[cursor]
            if encoded_end is None:
                encoded_end = cursor + 1
            cursor = target
            continue
        if size & 0xC0 or cursor + size > len(data):
            raise ValueError("Invalid DNS name label")
        if size == 0:
            return encoded_end if encoded_end is not None else cursor
        expanded_size += size + 1
        if expanded_size > 255:
            raise ValueError("Expanded DNS name exceeds 255 bytes")
        cursor += size


def validate_records(data: bytes, cursor: int) -> int:
    answers = int.from_bytes(data[6:8], "big")
    count = answers + sum(int.from_bytes(data[offset:offset + 2], "big") for offset in (8, 10))
    a_answers = 0
    for index in range(count):
        cursor = name_end(data, cursor)
        if cursor + 10 > len(data):
            raise ValueError("Truncated DNS resource record")
        record_type = int.from_bytes(data[cursor:cursor + 2], "big")
        record_class = int.from_bytes(data[cursor + 2:cursor + 4], "big")
        size = int.from_bytes(data[cursor + 8:cursor + 10], "big")
        body_start = cursor + 10
        body_end = body_start + size
        if body_end > len(data):
            raise ValueError("Truncated DNS resource data")
        if record_class == 1 and ((record_type == 1 and size != 4) or (record_type == 28 and size != 16)):
            raise ValueError("DNS address resource data has an invalid length")
        if record_type in (2, 5, 12) and name_end(data, body_start) != body_end:
            raise ValueError("DNS name resource data has an invalid length")
        if index < answers and record_type == 1 and record_class == 1:
            a_answers += 1
        cursor = body_end
    if cursor != len(data):
        raise ValueError("Unaccounted bytes after DNS records")
    return a_answers


def query(host: str, qname: str = "example.com", timeout: float = 3.0, port: int = 53) -> dict:
    labels = b"".join(bytes([len(part)]) + part.encode() for part in qname.split("."))
    transaction = secrets.token_bytes(2)
    payload = transaction + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + labels + b"\x00\x00\x01\x00\x01"
    result = {"host": host, "port": port, "qname": qname, "responded": False}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    started = time.perf_counter()
    try:
        sock.connect((host, port))
        sock.send(payload)
        data = sock.recv(2048)
        if len(data) < 12 or data[:2] != transaction:
            raise ValueError("Invalid DNS header or mismatched transaction ID")
        flags = int.from_bytes(data[2:4], "big")
        if not flags & 0x8000 or flags & 0x0200:
            raise ValueError("DNS packet is not a complete response")
        if int.from_bytes(data[4:6], "big") != 1 or data[12:len(payload)] != payload[12:]:
            raise ValueError("DNS response question does not match query")
        a_answers = validate_records(data, len(payload))
        result.update(
            {
                "responded": True,
                "response_from": f"{host}:{port}",
                "bytes": len(data),
                "ms": round((time.perf_counter() - started) * 1000, 2),
                "recursion_available": bool(flags & 0x0080),
                "answer_count": int.from_bytes(data[6:8], "big"),
                "a_answer_count": a_answers,
                "recursion_observed": bool(flags & 0x0080) and not bool(flags & 0x0400) and (flags & 15) == 0 and a_answers > 0,
                "rcode": flags & 0x000F,
            }
        )
    except socket.timeout:
        result["note"] = "No public DNS response."
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        sock.close()
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True, type=ipv4)
    parser.add_argument("--port", type=port, default=53)
    args = parse_probe_args(parser)
    result = query(args.target, port=args.port)
    write_probe(parser, args, result)
    print(f"wrote {args.out}; responded={result.get('responded')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
