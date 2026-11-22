# Voice evidence is observational. Synthetic ETW metadata, no traffic capture.
param([string]$Pkg=(Split-Path -Parent (Split-Path -Parent $PSScriptRoot)))
if(Test-Path (Join-Path $Pkg '.git')){throw 'Run on a package copy.'}
$ErrorActionPreference='Stop'
. (Join-Path $Pkg 'tools/lib.ps1')
$module=Join-Path $Pkg 'tools/voiceprobe.ps1';$fails=0
function Check($Name,$Ok){if($Ok){Write-Host ('ok '+$Name)}else{$script:fails++;Write-Host ('FAIL '+$Name)}}
Check 'dedicated voice diagnostic module exists' (Test-Path $module)
if(-not (Test-Path $module)){exit 1}
. $module
$now=[datetime]::UtcNow
$identities=@([pscustomobject]@{Id=123;Name='Discord';StartedUtc=$now.AddMinutes(-1);ObservedUntilUtc=$now.AddSeconds(10)})
$local=@{'10.0.0.2'=$true;'::1'=$true}
function Event($Id,$Owner,$Destination,$Source,$Dport,$Sport,$Time=$now){
    [pscustomobject]@{Id=$Id;TimeCreated=$Time;Properties=@([pscustomobject]@{Value=$Owner},[pscustomobject]@{Value=80},[pscustomobject]@{Value=$Destination},[pscustomobject]@{Value=$Source},[pscustomobject]@{Value=(Swap16 $Dport)},[pscustomobject]@{Value=(Swap16 $Sport)})}
}
$out=Convert-DiscordVoiceEvent (Event 42 123 '203.0.113.9' '10.0.0.2' 50000 54321) $identities $local
$in=Convert-DiscordVoiceEvent (Event 43 123 '10.0.0.2' '203.0.113.9' 54321 50000) $identities $local
Check 'UDP send and receive map to the same application flow' ($out.Direction -eq 'Out' -and $in.Direction -eq 'In' -and $out.Address -eq $in.Address -and $out.Port -eq 50000 -and $in.LocalPort -eq 54321)
Check 'another PID is not attributed to Discord' ($null -eq (Convert-DiscordVoiceEvent (Event 42 124 '203.0.113.9' '10.0.0.2' 50000 54321) $identities $local))
Check 'reused PID outside its observed lifetime is rejected' ($null -eq (Convert-DiscordVoiceEvent (Event 42 123 '203.0.113.9' '10.0.0.2' 50000 54321 $now.AddSeconds(30)) $identities $local))
Check 'TCP and ambiguous local direction do not become voice UDP' ($null -eq (Convert-DiscordVoiceEvent (Event 10 123 '203.0.113.9' '10.0.0.2' 50000 54321) $identities $local) -and $null -eq (Convert-DiscordVoiceEvent (Event 42 123 '203.0.113.9' '192.0.2.2' 50000 54321) $identities $local))
$flows=@(Get-DiscordVoiceFlows @($out,$in,$out))
Check 'flow counters preserve both directions and configured port coverage' ($flows.Count -eq 1 -and $flows[0].Out -eq 2 -and $flows[0].In -eq 1 -and $flows[0].VoicePortConfigured -and $flows[0].ProfileHit -eq 'NotObserved')
$first=$out|Select-Object *;$second=$in|Select-Object *
$first|Add-Member -NotePropertyName ProcessStartedUtc -NotePropertyValue $now.AddMinutes(-1).ToString('o') -Force
$second|Add-Member -NotePropertyName ProcessStartedUtc -NotePropertyValue $now.ToString('o') -Force
$reused=@(Get-DiscordVoiceFlows @($first,$second))
Check 'two lifetimes sharing a PID and socket cannot synthesize two-way flow' ($reused.Count -eq 2 -and -not @($reused|Where-Object{$_.Out -gt 0 -and $_.In -gt 0}).Count)
$split=[pscustomobject]@{Status='Completed';Truncated=$false;Flows=@([pscustomobject]@{Out=1;In=0},[pscustomobject]@{Out=0;In=1})}
Check 'opposite directions in different flows are not outbound-only or a two-way flow' ((Get-DiscordVoiceAssessment $split @() 'Unknown' 'ObservedStable').Traffic -eq 'SeparateDirectionsObserved')
$capture=[pscustomobject]@{Status='Completed';Truncated=$false;Flows=$flows}
$control=@([pscustomobject]@{State='OK';ResponseValidated=$true})
$assessment=Get-DiscordVoiceAssessment $capture $control 'Unknown' 'ObservedStable'
Check 'bidirectional UDP and STUN do not confirm audio' ($assessment.Traffic -eq 'BidirectionalUdpObserved' -and $assessment.Audio -eq 'NotProvided' -and $assessment.Outcome -eq 'NeedsAudioCheck' -and $assessment.Cause -eq 'NotEstablished')
$audio=Get-DiscordVoiceAssessment $capture $control 'Both' 'ObservedStable'
Check 'two-way audio remains explicitly user-reported evidence' ($audio.Audio -eq 'UserReportedBoth' -and $audio.Outcome -eq 'UserReportedBoth')
$noControl=Get-DiscordVoiceAssessment $capture @([pscustomobject]@{State='UNKNOWN';ResponseValidated=$false;Reason='Timeout'}) 'Unknown' 'ObservedStable'
Check 'control timeout is not a no-UDP or ISP-block verdict' ($noControl.Control -eq 'NoResponseObserved' -and $noControl.Cause -eq 'NotEstablished')
$capture.Truncated=$true
Check 'truncated capture retains uncertainty' ((Get-DiscordVoiceAssessment $capture $control 'Unknown' 'ObservedStable').Traffic -eq 'CaptureUnknown')
Check 'changed context cannot accept a current strategy result' ((Get-DiscordVoiceAssessment $capture $control 'Both' 'Changed').Outcome -eq 'ContextChanged')
$capture.Status='Unavailable';$capture.Flows=@()
Check 'unavailable capture is not measured silence' ((Get-DiscordVoiceAssessment $capture $control 'Unknown' 'Unknown').Traffic -eq 'CaptureUnknown')
if($fails){exit 1}
Write-Host 'Voice evidence passed.'
