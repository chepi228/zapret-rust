# Voice capture lifecycle and reports with fake trace backend. No real ETW or external traffic.
param([string]$Pkg=(Split-Path -Parent (Split-Path -Parent $PSScriptRoot)))
if(Test-Path (Join-Path $Pkg '.git')){throw 'Run on a package copy.'}
$ErrorActionPreference='Stop'
. (Join-Path $Pkg 'tools/lib.ps1')
. (Join-Path $Pkg 'tools/webprobe.ps1')
. (Join-Path $Pkg 'tools/connectionprobe.ps1')
. (Join-Path $Pkg 'tools/voiceprobe.ps1')
$fails=0
function Check($Name,$Ok){if($Ok){Write-Host ('ok '+$Name)}else{$script:fails++;Write-Host ('FAIL '+$Name)}}
$exists=$null -ne (Get-Command Invoke-DiscordVoiceDiagnostic -ErrorAction SilentlyContinue)
Check 'voice capture/report orchestration exists' $exists
if(-not $exists){exit 1}
$Script:Runtime=Join-Path $Script:Runtime ('voicerun-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($Script:Runtime)
$script:mode='normal';$script:starts=@();$script:stops=@();$script:queries=@();$script:contexts=0;$script:guardStarts=0;$script:activeTrace=$false;$script:processReads=0;$script:identityStart=[datetime]::UtcNow.AddMinutes(-1)
function Test-Admin{return $true}
function Get-WebVerificationContext {[pscustomobject]@{Known=$true;Network=[pscustomobject]@{Known=$true;Key=('A'*64);ObservedUtc=[datetime]::UtcNow.ToString('o')};Processes=@('42|123');SettingsHash=('B'*64)}}
function Get-DiscordVoiceProcesses {$script:processReads++;if($script:mode -ne 'missing' -and ($script:mode -ne 'stale' -or $script:processReads -eq 1)){[pscustomobject]@{Id=123;Name='Discord';StartedUtc=$script:identityStart;ObservedUtc=[datetime]::UtcNow}}}
function Get-DiscordVoiceLocalAddresses {return @{'10.0.0.2'=$true}}
function Start-DiscordVoiceTrace($Session,$Path){$script:starts+=@($Session);if($script:mode -eq 'startfail'){throw 'fixture start failure'};$script:activeTrace=$true;$script:tracePath=$Path;[IO.File]::WriteAllText($Path,'fixture');return [pscustomobject]@{Ok=$true;Error=''}}
function Stop-DiscordVoiceTrace($Session){$script:stops+=@($Session);if($script:mode -eq 'stopretry' -and $script:stops.Count -eq $script:retryBase+1){return [pscustomobject]@{Ok=$false;Error='transient fixture stop failure'}};$script:activeTrace=$false;return [pscustomobject]@{Ok=$true;Error=''}}
function Get-DiscordVoiceTraceState($Session){$script:queries+=@($Session);[pscustomobject]@{Known=$true;Exists=$script:activeTrace;LogPath=$(if($script:mode -eq 'foreign'){'C:\another-trace.etl'}elseif($script:activeTrace){$script:tracePath}else{''});EventsLost=0;Error=''}}
function Start-DiscordVoiceGuard($Session,$Path,$DurationSec){$script:guardStarts++;[pscustomobject]@{Fixture=$true}}
function Complete-DiscordVoiceGuard($Guard){[pscustomobject]@{Ok=$true;Error=''}}
function Read-DiscordVoiceTrace($Path,$Identities,$Local){
    if($script:mode -eq 'queryfail'){return [pscustomobject]@{Events=@();Truncated=$false;Error='fixture query failure'}}
    if($script:mode -eq 'stale'){$script:staleIdentities=@($Identities);return [pscustomobject]@{Events=@();Truncated=$false;Error=''}}
    $time=[datetime]::UtcNow.ToString('o')
    [pscustomobject]@{Events=@([pscustomobject]@{ProcessId=123;ProcessName='Discord';ProcessStartedUtc=$script:identityStart.ToString('o');Address='203.0.113.9';Port=50000;LocalAddress='10.0.0.2';LocalPort=50001;Direction='Out';Bytes=80;ObservedUtc=$time},[pscustomobject]@{ProcessId=123;ProcessName='Discord';ProcessStartedUtc=$script:identityStart.ToString('o');Address='203.0.113.9';Port=50000;LocalAddress='10.0.0.2';LocalPort=50001;Direction='In';Bytes=80;ObservedUtc=$time});Truncated=$false;Error=''}
}
function Invoke-VoiceStunControl($HostName,$Port){return [pscustomobject]@{State='OK';Reason='BindingResponse';ResponseValidated=$true;Address='127.0.0.1';Port=$Port;ElapsedMs=1}}
$run=Invoke-DiscordVoiceDiagnostic -DurationSec 1 -Quiet
Check 'successful capture is closed and reports metadata without audio claim' ($run.Capture.Status -eq 'Completed' -and $run.Assessment.Audio -eq 'NotProvided' -and $run.Assessment.Traffic -eq 'BidirectionalUdpObserved' -and $script:starts.Count -eq 1 -and $script:stops[0] -eq $script:starts[0])
Check 'trace name is unique and scoped to voice diagnostic' ($script:starts[0] -match '^zapretVoice-[a-f0-9]{32}$')
Check 'independent deadline guard starts before capture' ($script:guardStarts -eq 1)
$last=[IO.File]::ReadAllText((Join-Path $Script:Runtime 'voice-check-last.json'))|ConvertFrom-Json
Check 'voice JSON points to its immutable text report' ($last.RunId -eq $run.RunId -and [IO.File]::Exists($last.TextFile))
$oldText=[IO.File]::ReadAllText($run.TextFile)
$annotated=New-DiscordVoiceAudioReport $run 'Both'
Check 'audio report is a new artifact with explicit user evidence' ($annotated.RunId -ne $run.RunId -and $annotated.CaptureRunId -eq $run.RunId -and $annotated.Assessment.Audio -eq 'UserReportedBoth' -and [IO.File]::ReadAllText($run.TextFile) -ceq $oldText)
$script:mode='startfail';$before=$script:queries.Count
$failed=Invoke-DiscordVoiceDiagnostic -DurationSec 1 -Quiet
Check 'trace startup failure queries owned cleanup and stays unknown' ($failed.Capture.Status -eq 'Failed' -and $failed.Assessment.Traffic -eq 'CaptureUnknown' -and $script:queries.Count -eq $before+1 -and $script:queries[-1] -ceq $failed.Capture.Session)
$script:mode='queryfail'
$query=Invoke-DiscordVoiceDiagnostic -DurationSec 1 -Quiet
Check 'query failure is not empty observed traffic' ($query.Capture.Status -eq 'Failed' -and $query.Assessment.Traffic -eq 'CaptureUnknown')
$script:mode='stale';$script:processReads=0;$script:staleIdentities=@('not-read')
$stale=Invoke-DiscordVoiceDiagnostic -DurationSec 1 -Quiet
Check 'pre-start Discord snapshot cannot extend through trace startup' ($script:staleIdentities.Count -eq 0 -and $stale.Capture.Identities.Count -eq 0)
$script:mode='stopretry';$script:retryBase=$script:stops.Count
$retry=Invoke-DiscordVoiceDiagnostic -DurationSec 1 -Quiet
Check 'transient stop failure is retried for the exact owned session' ($script:stops.Count -eq $script:retryBase+2 -and $script:stops[-1] -ceq $retry.Capture.Session -and $script:stops[-2] -ceq $retry.Capture.Session -and -not [IO.File]::Exists($retry.Capture.TracePath))
$script:mode='foreign';$script:activeTrace=$true;$before=$script:stops.Count
$foreign=Close-DiscordVoiceTrace $retry.Capture.Session $retry.Capture.TracePath
Check 'a session pointing to a different ETL cannot be stopped as owned' (-not $foreign.Ok -and $script:stops.Count -eq $before)
$script:activeTrace=$false
$script:mode='missing';$before=$script:starts.Count
$missing=Invoke-DiscordVoiceDiagnostic -DurationSec 1 -Quiet
Check 'missing Discord does not start a trace or infer voice failure' ($missing.Capture.Status -eq 'Unavailable' -and $script:starts.Count -eq $before -and $missing.Assessment.Cause -eq 'NotEstablished')
Check 'voice checks never write settings or strategy ranking' (-not (Test-Path (Join-Path $Script:Runtime 'settings.ini')) -and -not (Test-Path (Join-Path $Script:Runtime 'test-rank.txt')))
$controllerCode=@'
param($PackagePath,$OutputRoot,$GateFile,$Mode)
$ErrorActionPreference='Stop'
. (Join-Path $PackagePath 'tools/lib.ps1')
. (Join-Path $PackagePath 'tools/webprobe.ps1')
. (Join-Path $PackagePath 'tools/connectionprobe.ps1')
. (Join-Path $PackagePath 'tools/voiceprobe.ps1')
$Script:Runtime=$OutputRoot
function Get-WebVerificationContext {[pscustomobject]@{Known=$false;Network=[pscustomobject]@{Known=$false;Key='';ObservedUtc=[datetime]::UtcNow.ToString('o')};Processes=@();SettingsHash='fixture'}}
function Test-Admin{return $true}
function Get-DiscordVoiceProcesses {[pscustomobject]@{Id=123;Name='Discord';StartedUtc=[datetime]'2026-01-01';ObservedUtc=[datetime]::UtcNow}}
function Get-DiscordVoiceLocalAddresses {return @{'10.0.0.2'=$true}}
function Start-DiscordVoiceTrace($Session,$Path){[IO.File]::WriteAllText($GateFile,$Session);return [pscustomobject]@{Ok=$true;Error=''}}
function Stop-DiscordVoiceTrace($Session){[IO.File]::WriteAllText(($GateFile+'.stopped'),$Session);return [pscustomobject]@{Ok=$true;Error=''}}
function Get-DiscordVoiceTraceState($Session){[pscustomobject]@{Known=$true;Exists=(-not [IO.File]::Exists(($GateFile+'.stopped')));LogPath=$script:tracePath;EventsLost=0;Error=''}}
function Start-DiscordVoiceGuard($Session,$Path,$DurationSec){$script:tracePath=$Path;[pscustomobject]@{Fixture=$true}}
function Complete-DiscordVoiceGuard($Guard){[pscustomobject]@{Ok=$true;Error=''}}
function Read-DiscordVoiceTrace($Path,$Identities,$Local){return [pscustomobject]@{Events=@();Truncated=$false;Error=''}}
if($Mode -eq 'capture'){
    function Invoke-VoiceStunControl($HostName,$Port){[pscustomobject]@{State='OK';Reason='BindingResponse';ResponseValidated=$true;Address='127.0.0.1';Port=$Port;ElapsedMs=1}}
}else{
    function Get-ConnectionDnsCommand($HostName,$OutputFile){
        $encoded=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($GateFile))
        $code='$gate=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('''+$encoded+'''));[IO.File]::WriteAllText($gate,[string]$PID);Start-Sleep -Seconds 30'
        return [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
    }
}
Invoke-DiscordVoiceDiagnostic -DurationSec 120 -StunHost fixture.invalid -Quiet
'@
foreach($mode in @('capture','dns')){
    $outputRoot=Join-Path $Script:Runtime ('interrupt-'+$mode);[void][IO.Directory]::CreateDirectory($outputRoot);$gate=Join-Path $outputRoot 'ready'
    $controller=[PowerShell]::Create()
    try{
        [void]$controller.AddScript($controllerCode).AddArgument($Pkg).AddArgument($outputRoot).AddArgument($gate).AddArgument($mode);$pending=$controller.BeginInvoke()
        $timer=[Diagnostics.Stopwatch]::StartNew()
        while(-not [IO.File]::Exists($gate) -and -not $pending.IsCompleted -and $timer.ElapsedMilliseconds -lt 10000){Start-Sleep -Milliseconds 20}
        if(-not [IO.File]::Exists($gate)){throw ('Voice interruption fixture did not start: '+($controller.Streams.Error -join ' '))}
        Start-Sleep -Milliseconds 80;$owned=[IO.File]::ReadAllText($gate);$controller.Stop();try{[void]$controller.EndInvoke($pending)}catch{}
        if(-not [IO.File]::Exists((Join-Path $outputRoot 'voice-check-last.json'))){throw ('No partial voice report: '+($controller.Streams.Error -join ' '))}
        $partial=[IO.File]::ReadAllText((Join-Path $outputRoot 'voice-check-last.json'))|ConvertFrom-Json
        Check ($mode+' interruption publishes incomplete evidence') ($partial.Completion -eq 'Interrupted' -and $partial.Assessment.Traffic -eq 'CaptureUnknown')
        if($mode -eq 'capture'){
            Check 'capture interruption closes only its owned trace' ([IO.File]::ReadAllText(($gate+'.stopped')) -ceq $owned -and $partial.Capture.Status -eq 'Interrupted')
        }else{
            Check 'DNS interruption preserves the started control observation' ($partial.ControlDns.WorkerId -eq [int]$owned -and $partial.ControlDns.Reason -eq 'Cancelled')
            $gone=$false;try{[Diagnostics.Process]::GetProcessById([int]$owned).Dispose()}catch{$gone=$true}
            Check 'voice cancellation leaves no owned DNS worker' $gone
        }
    }finally{$controller.Dispose()}
}
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Pkg 'tools/menu.ps1'),[ref]$null,[ref]$null)
foreach($fn in $ast.FindAll({$args[0] -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){. ([scriptblock]::Create($fn.Extent.Text))}
$script:menuInputs=New-Object System.Collections.Generic.Queue[string];$script:menuInputs.Enqueue('13');$script:menuInputs.Enqueue('0');$script:actions=@()
function Read-Host($Prompt){$script:menuInputs.Dequeue()}
function Show-Header($Screen){}
function Write-BoxRow($Text,$Color){}
function Write-MenuItem($Key,$Text){}
function Write-BoxSep($Title){}
function Write-BoxBottom{}
function Invoke-MenuAction($Action){$script:actions+=@($Action)}
$Script:LetterKeys=@{};Show-ToolsMenu
Check 'Tools13 dispatches the voice diagnostic' ($script:actions.Count -eq 1 -and $script:actions[0] -eq 'voicecheck')
$manifest=[IO.File]::ReadAllLines((Join-Path $Pkg 'dev/package-files.txt'))
Check 'voice runtime and entry point are in the package manifest' ($manifest -contains 'tools/voiceprobe.ps1' -and $manifest -contains 'tools/voiceprobe.cs' -and $manifest -contains 'tools/discord-voice.ps1')
if($fails){exit 1}
Write-Host 'Voice lifecycle/reporting passed.'
