# Normal entry points and persisted advisory evidence, with unavailable clients and local stubs.
param([string]$Pkg=(Split-Path -Parent (Split-Path -Parent $PSScriptRoot)))
if(Test-Path (Join-Path $Pkg '.git')){throw 'Run on a package copy.'}
$ErrorActionPreference='Stop'
. (Join-Path $Pkg 'tools/lib.ps1')
. (Join-Path $Pkg 'tools/webprobe.ps1')
$fails=0
function Check($Name,$Ok){if($Ok){Write-Host ('ok '+$Name)}else{$script:fails++;Write-Host ('FAIL '+$Name)}}
$exists=$null -ne (Get-Command Invoke-WebVerification -ErrorAction SilentlyContinue)
Check 'web verification orchestrator exists' $exists
if(-not $exists){exit 1}
$Script:Runtime=Join-Path $Script:Runtime ('webchecktest-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($Script:Runtime)
$caps=[pscustomobject]@{CurlPath='';Curl=(Convert-WebCurlCapabilities '');BrowserPath='';BrowserVersion=''}
$script:contextCalls=0;$script:contextChanged=$false;$script:contextKnown=$true
function Get-WebVerificationContext {
    $script:contextCalls++
    return [pscustomobject]@{Known=$script:contextKnown;Network=[pscustomobject]@{Known=$script:contextKnown;Key=$(if($script:contextChanged -and $script:contextCalls%2 -eq 0){'B'*64}else{'A'*64});ObservedUtc=[datetime]::UtcNow.ToString('o')};Processes=@('123|456');SettingsHash=('C'*64)}
}
$target=[pscustomobject]@{Group='YouTube';Name='web';Url='https://example.test/'}
$result=Invoke-WebVerification @($target) -Capabilities $caps -Quiet
Check 'unavailable clients do not become network failures' ($result.Rows.Count -eq 4 -and @($result.Rows|Where-Object{$_.State -ne 'UNAVAILABLE'}).Count -eq 0)
Check 'explicit protocol evidence cannot be inferred from a missing client' ($result.Quic -eq 'Unconfirmed' -and @($result.Rows|Where-Object{$_.ProtocolConfirmed}).Count -eq 0)
Check 'diagnostic records stable observed connection context' ($result.ConnectionState -eq 'ObservedStable' -and $result.Mode -eq 'Advisory')
$saved=[IO.File]::ReadAllText($result.JsonFile)|ConvertFrom-Json
Check 'JSON preserves per-client evidence with schema and run identity' ($saved.Schema -eq 1 -and $saved.RunId -eq $result.RunId -and $saved.Rows.Count -eq 4 -and $saved.ProxyMode -eq 'Direct')
$text=[IO.File]::ReadAllText($result.TextFile)
Check 'text explains unavailable support and scope' ($text.Contains('HTTP/3') -and $text.Contains('недоступна') -and $text.Contains('основного документа') -and $text.Contains('заголовков'))
Check 'standalone diagnostic leaves strategy settings and ranks untouched' (-not (Test-Path (Join-Path $Script:Runtime 'settings.ini')) -and -not (Test-Path (Join-Path $Script:Runtime 'test-rank.txt')))
$script:contextChanged=$true
$changed=Invoke-WebVerification @($target) -Capabilities $caps -Quiet
Check 'changed connection is explicit even with completed client probes' ($changed.ConnectionState -eq 'Changed')
$script:contextChanged=$false;$script:contextKnown=$false
$unknown=Invoke-WebVerification @($target) -Capabilities $caps -Quiet
Check 'unknown connection context stays unknown' ($unknown.ConnectionState -eq 'Unknown')
$script:contextKnown=$true

# Exercise the report pipeline with actual row shapes from the clients.
function Invoke-WebCurlProbe($Target,$Mode,$Capabilities,$TimeoutSec){Convert-WebProtocolResult $Target $Mode $(if($Mode -eq 'Http2'){'h2'}else{'h3'}) 403 $true 12 ''}
function Invoke-WebBrowserProbe($Target,$Mode,$BrowserPath,$TimeoutSec){
    $one=Convert-WebProtocolResult $Target $Mode 'h2' 200 $true 20 ''
    $two=Convert-WebProtocolResult $Target $Mode 'h2' 200 $false 8000 'Timeout';$two.Sample=2
    return @($one,$two)
}
$mixed=Invoke-WebVerification @($target) -Capabilities $caps -Quiet
$mixedSaved=[IO.File]::ReadAllText($mixed.JsonFile)|ConvertFrom-Json
Check 'mixed report preserves HTTP errors, incomplete visits and actual HTTP3' ($mixedSaved.Quic -eq 'Observed' -and @($mixedSaved.Rows|Where-Object{$_.State -eq 'HTTP_ERROR'}).Count -eq 2 -and @($mixedSaved.Rows|Where-Object{$_.State -eq 'FAIL' -and -not $_.Complete}).Count -eq 2)
function Invoke-WebCurlProbe($Target,$Mode,$Capabilities,$TimeoutSec){
    if($Mode -eq 'Http3'){throw (New-Object OperationCanceledException 'fixture cancellation')}
    return Convert-WebProtocolResult $Target $Mode 'h2' 200 $true 12 ''
}
$cancelled=$false
try{Invoke-WebVerification @($target) -Capabilities $caps -Quiet|Out-Null}catch{$cancelled=$true}
$partial=[IO.File]::ReadAllText((Join-Path $Script:Runtime 'web-check-last.json'))|ConvertFrom-Json
Check 'interrupted orchestration persists prior evidence and the cancelled pending probe' ($cancelled -and $partial.Rows.Count -eq 2 -and $partial.Rows[0].State -eq 'OK' -and $partial.Rows[1].Reason -eq 'Cancelled' -and $partial.Rows[1].State -eq 'UNKNOWN')

$standalone=Join-Path $Pkg 'tools/webcheck.ps1'
Check 'standalone entry exists in the user package' (Test-Path $standalone)
$manifest=[IO.File]::ReadAllLines((Join-Path $Pkg 'dev/package-files.txt'))
Check 'release manifest includes both web diagnostic scripts' ($manifest -contains 'tools/webprobe.ps1' -and $manifest -contains 'tools/webcheck.ps1')
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Pkg 'tools/menu.ps1'),[ref]$null,[ref]$null)
foreach($fn in $ast.FindAll({$args[0] -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){. ([scriptblock]::Create($fn.Extent.Text))}
$script:menuInputs=New-Object System.Collections.Generic.Queue[string];$script:menuInputs.Enqueue('11');$script:menuInputs.Enqueue('0');$script:actions=@()
function Read-Host($Prompt){return $script:menuInputs.Dequeue()}
function Show-Header($Screen){}
function Write-BoxRow($Text,$Color){}
function Write-MenuItem($Key,$Text){}
function Write-BoxSep($Title){}
function Write-BoxBottom{}
function Invoke-MenuAction($Action){$script:actions+=@($Action)}
$Script:LetterKeys=@{}
Show-ToolsMenu
Check 'tools menu dispatches web verification through its normal action' ($script:actions.Count -eq 1 -and $script:actions[0] -eq 'webcheck')
$testAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Pkg 'tools/test.ps1'),[ref]$null,[ref]$null)
Check 'automatic selector exposes optional extended verification' (@($testAst.ParamBlock.Parameters|Where-Object{$_.Name.VariablePath.UserPath -eq 'WebCheck'}).Count -eq 1)
Check 'default selection does not require the optional web check' ($testAst.ParamBlock.Parameters.Extent.Text -notmatch 'WebCheck\s*=\s*\$true')

# Run the actual post-selection statements with process-control stubs.
$restoreIf=$testAst.Find({$args[0] -is [Management.Automation.Language.IfStatementAst] -and $args[0].Extent.Text.StartsWith('if ($restoreRequired)')},$false)
$webIf=$testAst.Find({$args[0] -is [Management.Automation.Language.IfStatementAst] -and $args[0].Extent.Text.StartsWith('if ($WebCheck)')},$false)
$mainTry=@($testAst.EndBlock.Statements|Where-Object{$_ -is [Management.Automation.Language.TryStatementAst]})[-1]
Check 'advisory web verification runs after restoration finally and mutex release' ($webIf -and $mainTry.Finally.Extent.EndOffset -lt $webIf.Extent.StartOffset)
Check 'post-selection phase restores connection before optional verification' ($restoreIf -and $webIf -and $restoreIf.Extent.StartOffset -lt $webIf.Extent.StartOffset)
if($restoreIf -and $webIf){
    $phase=[scriptblock]::Create($restoreIf.Extent.Text+"`n"+$webIf.Extent.Text)
    $script:restoreOk=$true;$script:postEvents=@();$script:postSubject=''
    function Start-Bypass{$script:postEvents+=@('restore');return $script:restoreOk}
    function Invoke-WebVerification($Subject){$script:postEvents+=@('web');$script:postSubject=$Subject;return [pscustomobject]@{TextFile='fixture-web.txt'}}
    $restoreRequired=$true;$restored=$false;$WebCheck=$true;$report=New-Object System.Collections.Generic.List[string];$repFile=Join-Path $Script:Runtime 'post-selection.txt'
    . $phase
    Check 'optional web check observes restored current connection' (($script:postEvents -join ',') -eq 'restore,web' -and $script:postSubject -eq 'Текущее подключение после автоподбора.')
    $script:restoreOk=$false;$script:postEvents=@();$report.Clear()
    . $phase
    Check 'failed bypass restoration is stated in the web report subject' (($script:postEvents -join ',') -eq 'restore,web' -and $script:postSubject.Contains('не подтверждён'))
    $WebCheck=$false;$script:postEvents=@();$restoreRequired=$false
    . $phase
    Check 'default path starts no browser verification' ($script:postEvents.Count -eq 0)
    $script:restoreAnswers=New-Object System.Collections.Generic.Queue[bool]
    function Start-Bypass{$script:postEvents+=@('restore');return $script:restoreAnswers.Dequeue()}
    function Get-OurProcesses{return @()}
    function Exit-BypassControl{$script:postEvents+=@('release')}
    $inside=$webIf.Extent.StartOffset -lt $mainTry.Finally.Extent.StartOffset
    $sequence='try {'+$restoreIf.Extent.Text+$(if($inside){"`n"+$webIf.Extent.Text})+'} finally '+$mainTry.Finally.Extent.Text+$(if(-not $inside){"`n"+$webIf.Extent.Text})
    $wholePhase=[scriptblock]::Create($sequence)
    $script:restoreAnswers.Enqueue($false);$script:restoreAnswers.Enqueue($true)
    $script:postEvents=@();$report.Clear();$restoreRequired=$true;$wasRunning=$true;$restored=$false;$WebCheck=$true;$p=$null;$Script:TestRunSnapshot=$null
    . $wholePhase
    Check 'failed first restoration retries and releases control before web traffic' (($script:postEvents -join ',') -eq 'restore,restore,release,web')
    Check 'web report uses final successful restoration outcome' (-not $script:postSubject.Contains('не подтверждён'))
}
if($fails){exit 1}
Write-Host 'Web diagnostic reports and entry points passed.'
