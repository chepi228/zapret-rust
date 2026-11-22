# Independent bounded owner for one diagnostic ETW session. No bypass control.
param([ValidatePattern('^zapretVoice-[a-f0-9]{32}$')][string]$Session,[string]$TracePath,[int]$ParentId,[long]$ParentStartedTicks,[ValidateRange(1,145)][int]$MaxSeconds)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'lib.ps1')
. (Join-Path $PSScriptRoot 'voiceprobe.ps1')
$trace=[IO.Path]::GetFullPath($TracePath);$runtimeRoot=[IO.Path]::GetFullPath($Script:Runtime).TrimEnd('\')+'\'
if(-not $trace.StartsWith($runtimeRoot,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($trace) -notmatch '^voice-\d{8}-\d{6}-[a-f0-9]{32}\.etl$'){throw 'Invalid owned voice trace path.'}
$signal=$trace+'.guard';$parent=$null;$ready=$false;$cleanup=[pscustomobject]@{Ok=$false;Error='Guard did not start.'}
try{
    Initialize-VoiceProbeRuntime
    $parent=[Diagnostics.Process]::GetProcessById($ParentId)
    if($parent.StartTime.ToUniversalTime().Ticks -ne $ParentStartedTicks){throw 'Parent process identity changed.'}
    [IO.File]::WriteAllText(($signal+'.ready'),'');$ready=$true
    $clock=[Diagnostics.Stopwatch]::StartNew()
    while($clock.Elapsed.TotalSeconds -lt $MaxSeconds -and -not [IO.File]::Exists(($signal+'.stop')) -and -not $parent.HasExited){Start-Sleep -Milliseconds 100}
    # An already launched logman may finish after its parent dies. Cover its bounded startup window.
    if($parent.HasExited -and -not [IO.File]::Exists(($signal+'.stop'))){
        while($clock.Elapsed.TotalSeconds -lt [math]::Min(12,$MaxSeconds)){Start-Sleep -Milliseconds 100}
    }
}catch{$cleanup.Error=$_.Exception.Message}
finally{
    if($ready){
        try{
            $cleanup=Close-DiscordVoiceTrace $Session $trace
            if($cleanup.Ok -and [IO.File]::Exists($trace)){[IO.File]::Delete($trace)}
        }catch{$cleanup=[pscustomobject]@{Ok=$false;Error=$_.Exception.Message}}
    }
    if($parent){$parent.Dispose()}
    foreach($suffix in @('.ready','.stop')){if([IO.File]::Exists(($signal+$suffix))){[IO.File]::Delete(($signal+$suffix))}}
    [IO.File]::WriteAllText(($signal+'.done'),(ConvertTo-Json -InputObject $cleanup -Compress),(New-Object Text.UTF8Encoding($false)))
}
