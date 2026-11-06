param(
    [string]$HostAddress,[string]$Username,[string]$KnownHosts,[string]$CredentialFile,
    [ValidateRange(1,65535)][int]$SshPort=22,
    [string]$InputLog,
    [string]$ResultsRoot='.\network-results',
    [string]$PythonExe='python'
)
$ErrorActionPreference='Stop'
$python=(Get-Command $PythonExe -ErrorAction Stop).Source
$resultDir=Join-Path $ResultsRoot ('dos-readiness-'+[Guid]::NewGuid().ToString('N'))
$arguments=@('--out-dir',$resultDir)
if($InputLog){$arguments+=@('--input-log',$InputLog)}
else{
    if(-not ($HostAddress -and $Username -and $KnownHosts -and $CredentialFile)){throw 'HostAddress, Username, KnownHosts and CredentialFile are required unless InputLog is supplied.'}
    $arguments+=@('--host',$HostAddress,'--username',$Username,'--known-hosts',$KnownHosts,'--credential-file',$CredentialFile,'--ssh-port',[string]$SshPort)
}
& $python -B (Join-Path $PSScriptRoot 'tools\dos_readiness_check.py') @arguments
if($LASTEXITCODE -ne 0){throw "Readiness collection failed with exit code $LASTEXITCODE."}
Write-Output "Readiness results: $resultDir"
