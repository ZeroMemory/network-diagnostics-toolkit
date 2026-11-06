import argparse
import base64
import datetime as dt
import hashlib
import hmac
import json
import random
import re
import shlex
import sys
import time
from http.cookiejar import Cookie, CookieJar
from pathlib import Path
from probe_options import output_state, validate_report_paths, write_reports
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPCookieProcessor, HTTPRedirectHandler, ProxyHandler, Request, build_opener


import paramiko


def router_origin(value: str, *, base_url: bool = True) -> tuple:
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password or (base_url and (parsed.query or parsed.fragment)):
        raise ValueError("Router URL must be explicit HTTP(S) without credentials, query or fragment")
    port = parsed.port
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Router port must be between 1 and 65535")
    return parsed.scheme, parsed.hostname.lower(), port if port is not None else (443 if parsed.scheme == "https" else 80)


class RouterRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if router_origin(req.full_url, base_url=False) != router_origin(newurl, base_url=False):
            raise HTTPError(req.full_url, code, "Router redirect outside the selected origin is refused", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def router_opener(jar: CookieJar):
    return build_opener(HTTPCookieProcessor(jar), ProxyHandler({}), RouterRedirectHandler())


def read_secret(path: Path, label: str) -> str:
    text = path.read_text(encoding="utf-8-sig")
    match = re.search(rf"^{re.escape(label)}: (.+)$", text, re.M)
    if not match:
        raise RuntimeError(f"Missing '{label}' in {path}")
    return match.group(1).strip()


def run_ssh(host: str, key_path: Path, sudo_password: str, since_minutes: int, username: str, known_hosts: Path, port: int = 22) -> str:
    script = f"""
set -o pipefail
SINCE='{since_minutes} minutes ago'
printf '== time ==\\n'
date -Iseconds || true
printf '\\n== services ==\\n'
for s in ssh ufw fail2ban wg-quick@wg0; do printf '%-16s %s\\n' "$s" "$(systemctl is-active "$s" 2>/dev/null || true)"; done
printf '\\n== sshd effective ==\\n'
sshd -T | grep -Ei '^(pubkeyauthentication|passwordauthentication|kbdinteractiveauthentication|permitrootlogin) ' || true
printf '\\n== wg ==\\n'
wg show wg0 || true
printf '\\n== ufw status ==\\n'
ufw status verbose || true
printf '\\n== ufw blocks ==\\n'
journalctl -k --since "$SINCE" -o short-iso --no-pager -q | grep 'UFW BLOCK' || true
printf '\\n== ssh logs ==\\n'
journalctl _COMM=sshd --since "$SINCE" -o short-iso --no-pager -q | grep -Ei 'Accepted|Failed|Invalid|Connection closed|Connection reset|Unable to negotiate|Bad protocol|error|maximum|preauth' || true
printf '\\n== fail2ban ==\\n'
fail2ban-client status sshd || true
printf '\\n== high priority warnings ==\\n'
journalctl -p warning..alert --since "$SINCE" -o short-iso --no-pager -q | tail -120 || true
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
    if rc:
        raise RuntimeError(f"Remote log collection failed with exit code {rc}")
    return f"RC={rc}\n\n{out}\n\nSTDERR:\n{err}\n"


def request(opener, base: str, path: str, data=None, accept="application/json, text/javascript, */*; q=0.01"):
    headers = {
        "User-Agent": "Mozilla/5.0 private-audit/1.0",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "identity",
        "Connection": "close",
        "X-Requested-With": "XMLHttpRequest",
        "Accept": accept,
    }
    body = None
    if data is not None:
        body = urlencode(data).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8"
    with opener.open(Request(base + path, data=body, headers=headers), timeout=10) as response:
        return response.status, response.read().decode("utf-8", "replace")


def router_login(router_password: str, base: str, username: str):
    router_origin(base)
    parsed = urlsplit(base)
    base = base.rstrip("/") + "/"
    jar = CookieJar()
    opener = router_opener(jar)
    _, html = request(opener, base, "login.html", accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
    csrf = re.search(r"csrf_token\s*=\s*'([^']+)'", html).group(1)
    _, text = request(opener, base, f"data/user_lang.json?_={int(time.time()*1000)}&csrf_token={csrf}")
    enc = re.search(r'"encryption_key"\s*:\s*"([^"]+)"', text).group(1)
    hash1 = hmac.new(b"$1$SERCOMM$", router_password.encode(), hashlib.sha256).hexdigest()
    hash2 = hmac.new(enc.encode(), hash1.encode(), hashlib.sha256).hexdigest()
    jar.set_cookie(
        Cookie(
            version=0,
            name="login_uid",
            value=str(random.random()),
            port=None,
            port_specified=False,
            domain=parsed.hostname,
            domain_specified=False,
            domain_initial_dot=False,
            path="/",
            path_specified=True,
            secure=False,
            expires=None,
            discard=True,
            comment=None,
            comment_url=None,
            rest={},
            rfc2109=False,
        )
    )
    _, body = request(opener, base, f"data/login.json?_={int(time.time()*1000)}&csrf_token={csrf}", {"LoginName": username, "LoginPWD": hash2})
    if body.strip().strip('"') != "1":
        raise RuntimeError("Router login failed")
    return opener, base, csrf


def collect_router(router_password: str, since_minutes: int, base: str, username: str):
    opener, base, csrf = router_login(router_password, base, username)
    _, body = request(opener, base, f"data/statussupporteventlog.json?_={int(time.time()*1000)}&lang=en&csrf_token={csrf}")
    events = json.loads(body)
    cutoff = dt.datetime.now() - dt.timedelta(minutes=since_minutes)
    recent = []
    for event in events:
        try:
            event_dt = dt.datetime.strptime(event["date"] + " " + event["time"], "%Y-%m-%d %H:%M:%S")
        except Exception:
            continue
        if event_dt >= cutoff:
            recent.append(event)
    return {"all_events": events, "recent_events": recent}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--since-minutes", type=int, default=60)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--credential-file", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--known-hosts", required=True)
    parser.add_argument("--ssh-port", type=int, default=22)
    parser.add_argument("--router-url")
    parser.add_argument("--router-username")
    parser.add_argument("--skip-router", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.since_minutes <= 1440 or not 1 <= args.ssh_port <= 65535:
        parser.error("since-minutes must be 1..1440 and SSH port must be 1..65535")
    if not args.skip_router and (not args.router_url or not args.router_username):
        parser.error("router-url and router-username are required, or use skip-router")
    if not args.skip_router:
        try:
            router_origin(args.router_url)
        except ValueError as exc:
            parser.error(str(exc))

    out_dir = Path(args.out_dir)
    cred = Path(args.credential_file)
    ubuntu_password = read_secret(cred, "Ubuntu new password")
    key_path = Path(read_secret(cred, "SSH private key"))
    inputs = [cred, key_path, Path(args.known_hosts)]
    outputs = [out_dir / name for name in ("ubuntu-security.txt", "router-eventlog-all.json", "router-eventlog-recent.json", "summary.txt")]
    try:
        validate_report_paths(inputs, outputs)
        baselines = {output: output_state(output) for output in outputs}
    except (OSError, RuntimeError, ValueError) as exc:
        parser.error(str(exc))
    out_dir.mkdir(parents=True, exist_ok=True)

    ubuntu = run_ssh(args.host, key_path, ubuntu_password, args.since_minutes, args.username, Path(args.known_hosts), args.ssh_port)
    router = {"all_events": [], "recent_events": []}
    if not args.skip_router:
        router = collect_router(read_secret(cred, "Router new password"), args.since_minutes, args.router_url, args.router_username)

    summary = [
        "Internal post-audit log collection",
        "==================================",
        f"Collected at: {dt.datetime.now().isoformat(timespec='seconds')}",
        f"Window: last {args.since_minutes} minutes",
        f"Router recent events: {len(router['recent_events'])}",
        f"Router collection: {'skipped by operator' if args.skip_router else 'completed'}",
        "",
        "Files:",
        "  ubuntu-security.txt",
        "  router-eventlog-all.json",
        "  router-eventlog-recent.json",
    ]
    text = "\n".join(summary)
    contents = (
        ubuntu,
        json.dumps(router["all_events"], ensure_ascii=False, indent=2),
        json.dumps(router["recent_events"], ensure_ascii=False, indent=2),
        text + "\n",
    )
    try:
        write_reports(inputs, dict(zip(outputs, contents)), baselines)
    except (OSError, RuntimeError, ValueError) as exc:
        parser.error(str(exc))
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
