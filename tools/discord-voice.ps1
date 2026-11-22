param([ValidateRange(1,120)][int]$DurationSec=30,[string]$StunHost='stun.cloudflare.com',[ValidateRange(1,65535)][int]$StunPort=3478,[ValidateSet('Unknown','Both','OnlyReceive','OnlySend','None')][string]$Audio='Unknown',[switch]$ControlOnly)
. (Join-Path $PSScriptRoot 'lib.ps1')
. (Join-Path $PSScriptRoot 'webprobe.ps1')
. (Join-Path $PSScriptRoot 'connectionprobe.ps1')
. (Join-Path $PSScriptRoot 'voiceprobe.ps1')
$ErrorActionPreference='Stop'
try{Invoke-DiscordVoiceDiagnostic -DurationSec $DurationSec -StunHost $StunHost -StunPort $StunPort -Audio $Audio -ControlOnly:$ControlOnly|Out-Null}catch{Write-Color $_.Exception.Message Yellow;exit 1}
