# Independent watchdog with an owned child and a fake trace backend. No ETW capture.
param([string]$Pkg=(Split-Path -Parent (Split-Path -Parent $PSScriptRoot)))
if(Test-Path (Join-Path $Pkg '.git')){throw 'Run on a package copy.'}
$ErrorActionPreference='Stop'
. (Join-Path $Pkg 'tools/lib.ps1')
. (Join-Path $Pkg 'tools/voiceprobe.ps1')
$fails=0
function Check($Name,$Ok){if($Ok){Write-Host ('ok '+$Name)}else{$script:fails++;Write-Host ('FAIL '+$Name)}}
$worker=Join-Path $Pkg 'tools/voiceguard.ps1'
Check 'independent bounded ETW owner exists' ([IO.File]::Exists($worker))
if(-not [IO.File]::Exists($worker)){exit 1}
Initialize-VoiceProbeRuntime
$session='zapretVoice-'+[guid]::NewGuid().ToString('N');$query=[ZapretVoice.TraceSession]::Query($session)
Check 'native query of a random absent session returns a bounded status' ($query.Code -in @(4201,5) -and ($query.Known -eq ($query.Code -eq 4201)))
$outputRoot=Join-Path $Script:Runtime ('voiceguardtest-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($outputRoot)
$module=Join-Path $Pkg 'tools/voiceprobe.ps1';$saved=[IO.File]::ReadAllBytes($module)
$stub=@'
function Initialize-VoiceProbeRuntime{}
function Close-DiscordVoiceTrace($Session,$Path){
    [IO.File]::AppendAllText(($Path+'.closed'),$Session+"`n")
    return [pscustomobject]@{Ok=$true;Error='';EventsLost=0}
}
'@
function TraceFile {
    $path=Join-Path $outputRoot ('voice-20261110-000000-'+[guid]::NewGuid().ToString('N')+'.etl')
    [IO.File]::WriteAllText($path,'temporary system metadata fixture');return $path
}
function Start-Worker($Path,$Parent,[int]$Seconds,[long]$Ticks=0){
    if(-not $Ticks){$Ticks=$Parent.StartTime.ToUniversalTime().Ticks}
    $arguments=@('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$worker,'-Session',$session,'-TracePath',$Path,'-ParentId',[string]$Parent.Id,'-ParentStartedTicks',[string]$Ticks,'-MaxSeconds',[string]$Seconds)
    $info=New-Object Diagnostics.ProcessStartInfo;$info.FileName=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe';$info.Arguments=ConvertTo-WinCmdLine $arguments;$info.UseShellExecute=$false;$info.CreateNoWindow=$true
    return [Diagnostics.Process]::Start($info)
}
function Wait-Ready($Process,$Path){
    $timer=[Diagnostics.Stopwatch]::StartNew()
    while(-not [IO.File]::Exists(($Path+'.guard.ready')) -and -not $Process.HasExited -and $timer.ElapsedMilliseconds -lt 10000){Start-Sleep -Milliseconds 20}
    return [IO.File]::Exists(($Path+'.guard.ready'))
}
$self=[Diagnostics.Process]::GetCurrentProcess();$child=$null;$parent=$null
try{
    [IO.File]::WriteAllText($module,$stub,(New-Object Text.UTF8Encoding($true)))
    $path=TraceFile;$guard=Start-DiscordVoiceGuard $session $path 1
    Check 'normal controller gets a ready independently running process' (-not $guard.Process.HasExited)
    $done=Complete-DiscordVoiceGuard $guard
    Check 'explicit handoff closes exact session and removes temporary ETL' ($done.Ok -and -not [IO.File]::Exists($path) -and [IO.File]::ReadAllText(($path+'.closed')).Trim() -ceq $session)
    $path=TraceFile;$child=Start-Worker $path $self 1
    Check 'deadline fixture becomes ready' (Wait-Ready $child $path)
    Check 'independent deadline terminates collector cleanup without controller signal' ($child.WaitForExit(6000) -and -not [IO.File]::Exists($path) -and [IO.File]::Exists(($path+'.guard.done')))
    $child.Dispose();$child=$null
    $info=New-Object Diagnostics.ProcessStartInfo;$info.FileName=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe';$info.Arguments='-NoProfile -NonInteractive -Command "Start-Sleep -Seconds 30"';$info.UseShellExecute=$false;$info.CreateNoWindow=$true
    $parent=[Diagnostics.Process]::Start($info);$path=TraceFile;$child=Start-Worker $path $parent 4
    Check 'parent-exit fixture becomes ready' (Wait-Ready $child $path)
    $parent.Kill();[void]$parent.WaitForExit(2000)
    Check 'dead parent still leaves an independently bounded cleanup owner' ($child.WaitForExit(7000) -and -not [IO.File]::Exists($path) -and [IO.File]::Exists(($path+'.closed')))
    $child.Dispose();$child=$null;$parent.Dispose();$parent=$null
    $path=TraceFile;$child=Start-Worker $path $self 1 ($self.StartTime.ToUniversalTime().Ticks+1)
    Check 'reused parent PID cannot authorize the watchdog' ($child.WaitForExit(6000) -and -not [IO.File]::Exists(($path+'.guard.ready')) -and -not [IO.File]::Exists(($path+'.closed')))
}finally{
    [IO.File]::WriteAllBytes($module,$saved)
    if($child){if(-not $child.HasExited){$child.Kill();[void]$child.WaitForExit(2000)};$child.Dispose()}
    if($parent){if(-not $parent.HasExited){$parent.Kill();[void]$parent.WaitForExit(2000)};$parent.Dispose()}
    $self.Dispose()
}
$path=TraceFile
function Get-WinEvent {param($Path,[switch]$Oldest,$FilterXPath,$MaxEvents,$ErrorAction);return @()}
$identities=@(1..65|ForEach-Object{[pscustomobject]@{Id=$_;Name='Discord';StartedUtc=[datetime]'2026-01-01';ObservedUntilUtc=[datetime]::UtcNow}})
$limited=Read-DiscordVoiceTrace $path $identities @{}
Check 'PID filter truncation cannot look like complete measured silence' ($limited.Truncated -and -not $limited.Error)
if($fails){exit 1}
Write-Host 'Voice independent owner passed.'
