# Diagnose the current connection without changing strategy, service or network settings.
param([string[]]$Url=@(),[ValidateRange(1,30)][int]$TimeoutSec=8)
. (Join-Path $PSScriptRoot 'lib.ps1')
. (Join-Path $PSScriptRoot 'webprobe.ps1')
. (Join-Path $PSScriptRoot 'connectionprobe.ps1')
$ErrorActionPreference='Stop'
try {
    $targets=$null
    if($Url.Count){$targets=@();$number=0;foreach($address in $Url){$number++;$targets+=@([pscustomobject]@{Group='Custom';Name=('url'+$number);Url=(Assert-WebProbeUrl $address)})}}
    Invoke-ConnectionDiagnostic -Targets $targets -TimeoutSec $TimeoutSec|Out-Null
}catch{Write-Color $_.Exception.Message Yellow;exit 1}
