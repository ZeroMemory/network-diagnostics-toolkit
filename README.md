# Network Diagnostics Toolkit

Check which services on a Linux server are reachable from the internet. Run the external checks from another network, then collect server and router logs to investigate the results.

The summary compares exposed services with a VPN-server profile. The expected UDP port defaults to WireGuard's 51820.

## Setup

Requires Windows PowerShell 5.1+, Python 3.12 and the pinned dependencies. Nmap is optional. SSH collection uses Linux tools including `sudo`, journalctl, UFW, WireGuard and sysctl; router collection supports compatible Sercomm firmware.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r .\requirements.txt
```

Run commands from the repository root.

## Check external exposure

Use an internet connection outside the server's LAN.

```powershell
$serverIp = Read-Host 'Server public IPv4 address'
.\run_external_audit.ps1 -Target $serverIp -SkipNmap -PythonExe .\.venv\Scripts\python.exe
```

The runner checks TCP/UDP ports, HTTP responses and exposed web paths, presented TLS certificates and DNS recursion. Results are saved under `network-results` as CSV, JSON, logs and a text summary.

Use `-Mode deeper`, `-Ports`, `-UdpPorts` and `-ExpectedOpenUdp` to select the scope. Remove `-SkipNmap` to include an installed Nmap. `-ResolveSourceIp` additionally queries ipify for the connection's public address.

Standalone probes accept `--out` for a new result path and `--overwrite` to replace an existing report.

## Collect internal logs

Connect from the server's trusted LAN or VPN. The collector reads Linux SSH, firewall, Fail2Ban and WireGuard status and logs. A compatible Sercomm router can also supply event logs. Compare these files with the external observations.

Verify the SSH host fingerprint and add it to a `known_hosts` file. Use a credential text file with these exact labels, replacing the example values:

```text
Ubuntu new password: YOUR_SUDO_PASSWORD
SSH private key: PATH_TO_YOUR_ED25519_KEY
Router new password: YOUR_ROUTER_PASSWORD
```

Add the router line when collecting router logs.

```powershell
$server = Read-Host 'SSH server address'
$user = Read-Host 'SSH username'
$knownHosts = Read-Host 'Path to the verified known_hosts file'
$credentials = Read-Host 'Path to the credential file'
.\collect_post_audit_logs.ps1 -HostAddress $server -Username $user -KnownHosts $knownHosts -CredentialFile $credentials -SkipRouter -PythonExe .\.venv\Scripts\python.exe
```

For router logs, replace `-SkipRouter` with `-RouterUrl` and `-RouterUsername`. Use `-SshPort` and `-SinceMinutes` to set the SSH port and collection window.

## Inspect protection settings

`dos_readiness_check.ps1` reads firewall settings, selected kernel parameters, conntrack usage, listeners and overload markers. It accepts `-HostAddress`, `-Username`, `-KnownHosts` and `-CredentialFile` for SSH collection, or `-InputLog` for an existing readiness log. It writes `summary.txt` and `dos-readiness.json` under `network-results`.
