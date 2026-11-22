# Current-connection orchestration and normal menu entry. No external network.
param([string]$Pkg=(Split-Path -Parent (Split-Path -Parent $PSScriptRoot)))
if(Test-Path (Join-Path $Pkg '.git')){throw 'Run on a package copy.'}
$ErrorActionPreference='Stop'
. (Join-Path $Pkg 'tools/lib.ps1')
. (Join-Path $Pkg 'tools/webprobe.ps1')
. (Join-Path $Pkg 'tools/connectionprobe.ps1')
$fails=0
function Check($Name,$Ok){if($Ok){Write-Host ('ok '+$Name)}else{$script:fails++;Write-Host ('FAIL '+$Name)}}
$exists=$null -ne (Get-Command Invoke-ConnectionDiagnostic -ErrorAction SilentlyContinue)
Check 'staged connection orchestration exists' $exists
if(-not $exists){exit 1}
$Script:Runtime=Join-Path $Script:Runtime ('connectionrun-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($Script:Runtime)
$script:mode='healthy';$script:probeCount=0;$script:closed=0;$script:dnsCount=0;$script:contextChanged=$false;$script:contexts=0
function Get-WebVerificationContext {
    $script:contexts++
    [pscustomobject]@{Known=$true;Network=[pscustomobject]@{Known=$true;Key=$(if($script:contextChanged -and $script:contexts%2 -eq 0){'B'*64}else{'A'*64});ObservedUtc=[datetime]::UtcNow.ToString('o')};Processes=@('123|456');SettingsHash=('C'*64)}
}
function Resolve-ConnectionTarget($Target,$DeadlineTicks){
    $script:dnsCount++
    if($script:mode -eq 'dnsfail'){return [pscustomobject]@{State='FAIL';Reason='ResolveFailed';Addresses=@();Error='fixture';ElapsedMs=1;WorkerId=0}}
    [pscustomobject]@{State='OK';Reason='Resolved';Addresses=@('127.0.0.1','::1');Error='';ElapsedMs=1;WorkerId=0}
}
function Start-ConnectionAddressProbe($Uri,$Address,$TimeoutMs){
    $script:probeCount++
    if($script:mode -eq 'startfail' -and $script:probeCount -eq 1){throw 'fixture launch failure'}
    $bad=$script:mode -eq 'mixed' -and $Address -eq '::1'
    $row=[pscustomobject]@{Address=$Address;Family=$(if($Address -eq '::1'){'IPv6'}else{'IPv4'});Stage=$(if($bad){'Tls'}else{'Complete'});State=$(if($bad){'FAIL'}else{'OK'});Reason=$(if($bad){'Certificate'}else{'Completed'});StatusCode=$(if($bad){0}else{200});Error='';ElapsedMs=10;TcpSucceeded=$true;TlsSucceeded=(-not $bad);HeadersComplete=(-not $bad);CertificateErrors=$(if($bad){'RemoteCertificateChainErrors'}else{'None'});TlsProtocol='Tls12';ReceivedBytes=64;HeaderBytes=64;Validation='System';RevocationCheck=$false;Evidence='Headers'}
    $completion=[pscustomobject]@{IsCompleted=($script:mode -ne 'budget');Value=$row}
    $completion|Add-Member ScriptMethod GetAwaiter {return $this}
    $completion|Add-Member ScriptMethod GetResult {return $this.Value}
    $probe=[pscustomobject]@{Completion=$completion}
    $probe|Add-Member ScriptMethod Cancel {$this.Completion.Value.State='UNKNOWN';$this.Completion.Value.Reason='Cancelled';$this.Completion.IsCompleted=$true}
    $probe|Add-Member ScriptMethod Expire {$this.Completion.Value.State='FAIL';$this.Completion.Value.Stage='Http';$this.Completion.Value.StatusCode=0;$this.Completion.Value.Reason='Timeout';$this.Completion.IsCompleted=$true}
    $probe|Add-Member ScriptMethod Dispose {$script:closed++}
    return $probe
}
$targets=@([pscustomobject]@{Group='YouTube';Name='web';Url='https://example.invalid/'},[pscustomobject]@{Group='Clean';Name='bing';Url='https://control.invalid/'})
$run=Invoke-ConnectionDiagnostic -Targets $targets -Quiet
Check 'normal run probes both families twice for each target' ($script:probeCount -eq 8 -and $script:closed -eq 8 -and $run.Targets.Count -eq 2 -and $run.Targets[0].Rows.Count -eq 4)
Check 'control target and observed connection stability are recorded' ($run.ControlState -eq 'ReachedHttp' -and $run.ConnectionState -eq 'ObservedStable')
$saved=[IO.File]::ReadAllText($run.JsonFile)|ConvertFrom-Json
$last=[IO.File]::ReadAllText((Join-Path $Script:Runtime 'connection-check-last.json'))|ConvertFrom-Json
Check 'last JSON references the same immutable text report' ($last.RunId -eq $run.RunId -and $last.TextFile -eq $run.TextFile -and [IO.File]::Exists($last.TextFile))
Check 'report identifies diagnostic backend and header evidence' ($saved.Client -like '*Schannel*' -and $saved.Evidence -eq 'Headers' -and $saved.SourceHash -match '^[0-9A-F]{64}$')
Check 'diagnostic leaves settings and ranking untouched' (-not (Test-Path (Join-Path $Script:Runtime 'settings.ini')) -and -not (Test-Path (Join-Path $Script:Runtime 'test-rank.txt')))
$script:mode='mixed';$mixed=Invoke-ConnectionDiagnostic -Targets @($targets[0]) -Quiet
Check 'IPv4 success and IPv6 certificate failure stay separate in persisted rows' ($mixed.Targets[0].Assessment.Consistency -eq 'Mixed' -and @($mixed.Targets[0].Rows|Where-Object{$_.Reason -eq 'Certificate'}).Count -eq 2)
$script:mode='dnsfail';$script:dnsCount=0;$before=$script:probeCount
$dns=Invoke-ConnectionDiagnostic -Targets @($targets[0]) -Quiet
Check 'failed DNS is repeated without inventing address probes' ($script:dnsCount -eq 2 -and $script:probeCount -eq $before -and $dns.Targets[0].Assessment.Stage -eq 'Dns')
$script:mode='budget';$timer=[Diagnostics.Stopwatch]::StartNew()
$limited=Invoke-ConnectionDiagnostic -Targets @($targets[0]) -TimeoutSec 1 -Quiet
Check 'target budget records not-started retries and remains incomplete' ($timer.ElapsedMilliseconds -lt 3000 -and $limited.Targets[0].Rows.Count -eq 4 -and @($limited.Targets[0].Rows|Where-Object{$_.State -eq 'NOT_RUN'}).Count -eq 2 -and $limited.Targets[0].Assessment.Consistency -eq 'Incomplete')
$script:mode='startfail';$script:probeCount=0
$failed=Invoke-ConnectionDiagnostic -Targets @($targets[0]) -Quiet
Check 'one probe controller failure preserves all remaining planned observations' ($failed.Targets[0].Rows.Count -eq 4 -and @($failed.Targets[0].Rows|Where-Object{$_.Reason -eq 'ControllerError'}).Count -eq 1)
$script:mode='healthy';$script:contextChanged=$true
$changed=Invoke-ConnectionDiagnostic -Targets @($targets[0]) -Quiet
Check 'network changes are marked instead of hidden by successful probes' ($changed.ConnectionState -eq 'Changed')

$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Pkg 'tools/menu.ps1'),[ref]$null,[ref]$null)
foreach($fn in $ast.FindAll({$args[0] -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){. ([scriptblock]::Create($fn.Extent.Text))}
$script:menuInputs=New-Object System.Collections.Generic.Queue[string];$script:menuInputs.Enqueue('12');$script:menuInputs.Enqueue('0');$script:actions=@()
function Read-Host($Prompt){$script:menuInputs.Dequeue()}
function Show-Header($Screen){}
function Write-BoxRow($Text,$Color){}
function Write-MenuItem($Key,$Text){}
function Write-BoxSep($Title){}
function Write-BoxBottom{}
function Invoke-MenuAction($Action){$script:actions+=@($Action)}
$Script:LetterKeys=@{};Show-ToolsMenu
Check 'Tools12 dispatches the normal staged diagnostic action' ($script:actions.Count -eq 1 -and $script:actions[0] -eq 'connectioncheck')
$manifest=[IO.File]::ReadAllLines((Join-Path $Pkg 'dev/package-files.txt'))
Check 'release includes controller, native client source and standalone entry' ($manifest -contains 'tools/connectionprobe.ps1' -and $manifest -contains 'tools/connectionprobe.cs' -and $manifest -contains 'tools/connection-check.ps1')
Check 'frozen input catalog includes the native diagnostic source' (@(Get-ScoreInputFiles) -contains 'tools/connectionprobe.cs')
if($fails){exit 1}
Write-Host 'Connection diagnostic entry and reporting passed.'
