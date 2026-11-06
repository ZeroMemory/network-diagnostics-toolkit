param(
    [Parameter(Mandatory=$true)][string]$HostAddress,
    [Parameter(Mandatory=$true)][string]$Username,
    [Parameter(Mandatory=$true)][string]$KnownHosts,
    [Parameter(Mandatory=$true)][string]$CredentialFile,
    [ValidateRange(1,1440)][int]$SinceMinutes=60,
    [ValidateRange(1,65535)][int]$SshPort=22,
    [string]$RouterUrl,
    [string]$RouterUsername,
    [switch]$SkipRouter,
    [string]$ResultsRoot='.\network-results',
    [string]$PythonExe='python'
)
$ErrorActionPreference='Stop'
$python=(Get-Command $PythonExe -ErrorAction Stop).Source
$resultDir=Join-Path $ResultsRoot ('internal-logs-'+[Guid]::NewGuid().ToString('N'))
$arguments=@('--host',$HostAddress,'--username',$Username,'--known-hosts',$KnownHosts,'--credential-file',$CredentialFile,'--since-minutes',[string]$SinceMinutes,'--ssh-port',[string]$SshPort,'--out-dir',$resultDir)
if($SkipRouter){$arguments+='--skip-router'}else{$arguments+=@('--router-url',$RouterUrl,'--router-username',$RouterUsername)}
& $python -B (Join-Path $PSScriptRoot 'tools\collect_internal_logs.py') @arguments
if($LASTEXITCODE -ne 0){throw "Internal log collection failed with exit code $LASTEXITCODE."}
Write-Output "Internal logs saved to: $resultDir"
