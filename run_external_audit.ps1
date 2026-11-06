param(
    [Parameter(Mandatory=$true)][string]$Target,
    [ValidateSet('safe','deeper')][string]$Mode='safe',
    [string]$ExpectedOpenUdp='51820',
    [string]$ResultsRoot='.\network-results',
    [string]$PythonExe='python',
    [string]$Ports,
    [string]$UdpPorts,
    [ValidateRange(1,65535)][int]$DnsPort=53,
    [switch]$SkipNmap,
    [switch]$ResolveSourceIp,
    [switch]$LocalTest
)
$ErrorActionPreference='Stop'
$parsed=$null
if ($Target -notmatch '^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$' -or -not [Net.IPAddress]::TryParse($Target,[ref]$parsed) -or $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $parsed.ToString() -ne $Target) { throw 'Target must be one canonical dotted-quad IPv4 address.' }
$bytes=$parsed.GetAddressBytes(); $a=$bytes[0]; $b=$bytes[1]
if ($LocalTest) {
    if ($a -ne 127 -or -not $Ports -or -not $UdpPorts -or -not $SkipNmap -or $ResolveSourceIp) {
        throw 'LocalTest requires loopback, explicit Ports/UdpPorts, SkipNmap, and no source-IP lookup.'
    }
} elseif ($a -eq 0 -or $a -eq 10 -or $a -eq 127 -or $a -ge 224 -or ($a -eq 169 -and $b -eq 254) -or ($a -eq 172 -and $b -ge 16 -and $b -le 31) -or ($a -eq 192 -and $b -eq 168) -or ($a -eq 100 -and $b -ge 64 -and $b -le 127) -or ($a -eq 192 -and $b -eq 0 -and $bytes[2] -eq 2) -or ($a -eq 198 -and $b -eq 51 -and $bytes[2] -eq 100) -or ($a -eq 203 -and $b -eq 0 -and $bytes[2] -eq 113) -or ($a -eq 198 -and ($b -eq 18 -or $b -eq 19))) {
    throw 'Target must be a public IPv4; LocalTest is reserved for bounded loopback scenarios.'
}
function Parse-Ports([string]$Value) {
    $list=@($Value.Split(',')|ForEach-Object {
        $n=0; if(-not [int]::TryParse($_.Trim(),[ref]$n) -or $n -lt 1 -or $n -gt 65535){throw 'Ports must be a nonempty comma-separated list of 1..65535.'}; $n
    }|Sort-Object -Unique)
    if(-not $list.Count){throw 'At least one port is required.'}; return $list
}
if(-not $Ports){
    $Ports='1,7,9,13,17,19,20,21,22,23,25,53,80,81,88,110,111,135,139,143,389,443,445,465,500,587,631,873,993,995,1194,1433,1521,1883,2049,2375,2376,3000,3306,3389,4330,5000,5432,5555,5672,5900,6379,6443,7547,8000,8080,8123,8443,8883,8888,9000,9001,9090,9091,9200,9300,10250,11211,15672,27017,26257,44321,51820'
    if($Mode -eq 'deeper'){$Ports+=',26,37,49,69,79,82,83,84,85,89,90,99,109,113,119,161,162,179,199,264,427,444,548,554,563,593,636,646,990,1025,1026,1027,1028,1029,1080,1723,2082,2083,2086,2087,2222,2483,2484,3128,4443,4567,4711,4848,5060,5061,5601,5984,6000,7001,7002,7070,7443,7777,8008,8069,8081,8082,8086,8088,8090,8096,8181,8222,8333,8500,8834,8848,9002,9042,9092,9100,9443,9999,10000,27018,27019,28017,50000,50070'}
}
if(-not $UdpPorts){$UdpPorts=if($Mode -eq 'deeper'){'53,67,68,69,123,137,138,161,162,500,1194,1701,1900,4500,5060,51820,5353,11211'}else{'53,123,500,4500,51820,1194'}}
$tcpPorts=@(Parse-Ports $Ports); $udpPortsString=(Parse-Ports $UdpPorts)-join ','
$python=(Get-Command $PythonExe -ErrorAction Stop).Source
$stamp=(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[Guid]::NewGuid().ToString('N').Substring(0,8)
$resultDir=Join-Path $ResultsRoot "external-$Target-$stamp"
New-Item -ItemType Directory -Path $resultDir | Out-Null
$meta=[ordered]@{started_at=(Get-Date).ToString('o');target=$Target;mode=$Mode;local_test=[bool]$LocalTest;tested_tcp_ports=$tcpPorts;tested_udp_ports=$udpPortsString;dns_port=$DnsPort;expected_open_udp=$ExpectedOpenUdp;local_public_ip='not_requested';stage_exit_codes=[ordered]@{};nmap='not_run'}
if($ResolveSourceIp){try{$meta.local_public_ip=Invoke-RestMethod -TimeoutSec 8 -Uri 'https://api.ipify.org'}catch{$meta.local_public_ip='unavailable'}}
function Save-Metadata {$meta|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $resultDir '00-metadata.json') -Encoding utf8}
function Invoke-Probe([string]$Script,[string[]]$Arguments){
    $saved=$ErrorActionPreference;$ErrorActionPreference='Continue'
    $out=@(& $python -B (Join-Path $PSScriptRoot "tools\$Script") @Arguments 2>&1|ForEach-Object {[string]$_})
    $code=$LASTEXITCODE;$ErrorActionPreference=$saved
    $meta.stage_exit_codes[$Script]=$code
    $out|Set-Content -LiteralPath (Join-Path $resultDir ($Script+'.log')) -Encoding utf8
    Save-Metadata
    if($code -ne 0){throw "$Script failed with exit code $code; see its log."}
}
Save-Metadata
$tcpRows=foreach($port in $tcpPorts){
    $client=New-Object Net.Sockets.TcpClient;$watch=[Diagnostics.Stopwatch]::StartNew();$handle=$null
    try{
        $async=$client.BeginConnect($Target,$port,$null,$null);$handle=$async.AsyncWaitHandle
        if($handle.WaitOne(900) -and $client.Connected){$client.EndConnect($async);[pscustomobject]@{port=$port;state='open';ms=$watch.ElapsedMilliseconds}}
        else{[pscustomobject]@{port=$port;state='closed_or_filtered';ms=$watch.ElapsedMilliseconds}}
    }catch{[pscustomobject]@{port=$port;state='closed_or_filtered';ms=$watch.ElapsedMilliseconds}}
    finally{$watch.Stop();if($handle){$handle.Dispose()};$client.Close()}
}
$tcpRows|Export-Csv -NoTypeInformation -Encoding utf8 -LiteralPath (Join-Path $resultDir '01-tcp-connect-sweep.csv')
if(-not $SkipNmap){
    $nmap=Get-Command nmap -ErrorAction SilentlyContinue
    if($nmap){
        $saved=$ErrorActionPreference;$ErrorActionPreference='Continue'
        & $nmap.Source -Pn -n -sT --top-ports 1000 --version-light --reason --max-rate 20 --host-timeout 5m -oA (Join-Path $resultDir '02-nmap-top1000') $Target 2>&1|Out-File (Join-Path $resultDir '02-nmap-top1000.txt')
        $meta.stage_exit_codes['nmap-top1000']=$LASTEXITCODE
        $scripts=if($Mode -eq 'deeper'){'safe,banner,http-title,http-headers,http-server-header,http-methods,http-robots.txt,http-security-headers,http-auth-finder,ssl-cert,ssl-enum-ciphers'}else{'default,safe,banner,http-title,http-headers,ssl-cert,ssl-enum-ciphers'}
        & $nmap.Source -Pn -n -sT -sV --version-light --max-rate 20 --host-timeout 5m --script $scripts -p ($tcpPorts -join ',') -oA (Join-Path $resultDir '03-nmap-focused') $Target 2>&1|Out-File (Join-Path $resultDir '03-nmap-focused.txt')
        $meta.stage_exit_codes['nmap-focused']=$LASTEXITCODE
        $meta.nmap=if($meta.stage_exit_codes['nmap-top1000'] -eq 0 -and $meta.stage_exit_codes['nmap-focused'] -eq 0){'completed'}else{'failed'}
        $ErrorActionPreference=$saved
    }else{$meta.nmap='missing'}
}else{$meta.nmap='skipped_by_operator'}
$httpPorts=$tcpPorts -join ','
Invoke-Probe 'http_probe.py' @('--target',$Target,'--ports',$httpPorts,'--out',(Join-Path $resultDir '04-http-probe.json'))
Invoke-Probe 'tls_probe.py' @('--target',$Target,'--ports',$httpPorts,'--out',(Join-Path $resultDir '05-tls-probe.json'))
Invoke-Probe 'web_exposure_probe.py' @('--target',$Target,'--ports',$httpPorts,'--mode',$Mode,'--out',(Join-Path $resultDir '04b-web-exposure.json'))
Invoke-Probe 'udp_probe.py' @('--target',$Target,'--ports',$udpPortsString,'--out',(Join-Path $resultDir '06-udp-probe.json'))
Invoke-Probe 'dns_recursion_probe.py' @('--target',$Target,'--port',[string]$DnsPort,'--out',(Join-Path $resultDir '07-dns-recursion.json'))
$meta.completed_at=(Get-Date).ToString('o');Save-Metadata
$saved=$ErrorActionPreference;$ErrorActionPreference='Continue'
$summary=@(& $python -B (Join-Path $PSScriptRoot 'tools\summarize_external_audit.py') --result-dir $resultDir --expected-udp $ExpectedOpenUdp 2>&1|ForEach-Object {[string]$_});$code=$LASTEXITCODE;$ErrorActionPreference=$saved
$summary|Set-Content -LiteralPath (Join-Path $resultDir '99-summary.txt') -Encoding utf8
$summary|Write-Output
Write-Output "Result directory: $resultDir"
exit $code
