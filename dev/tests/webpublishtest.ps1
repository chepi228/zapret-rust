# Deterministic concurrent publishers and failed alias updates. No external network or driver.
param([string]$Pkg=(Split-Path -Parent (Split-Path -Parent $PSScriptRoot)))
if(Test-Path (Join-Path $Pkg '.git')){throw 'Run on a package copy.'}
$ErrorActionPreference='Stop'
. (Join-Path $Pkg 'tools/lib.ps1')
. (Join-Path $Pkg 'tools/webprobe.ps1')
$fails=0
function Check($Name,$Ok){if($Ok){Write-Host ('ok '+$Name)}else{$script:fails++;Write-Host ('FAIL '+$Name)}}
function Same-Bytes([string]$Path,[byte[]]$Expected){return [IO.File]::Exists($Path) -and [Convert]::ToBase64String([IO.File]::ReadAllBytes($Path)) -ceq [Convert]::ToBase64String($Expected)}
$Script:Runtime=Join-Path $Script:Runtime ('web publication '+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($Script:Runtime)
$fixture=Join-Path $Script:Runtime 'writer.ps1'
$child=@'
param([string]$Pkg,[string]$OutputRoot,[string]$Tag)
$ErrorActionPreference='Stop'
. (Join-Path $Pkg 'tools/lib.ps1')
. (Join-Path $Pkg 'tools/webprobe.ps1')
$Script:Runtime=$OutputRoot;$script:contextCalls=0
function Get-WebVerificationContext {
    $script:contextCalls++
    if($Tag -eq 'B' -and $script:contextCalls -eq 2){[IO.File]::WriteAllText((Join-Path $OutputRoot 'B-ready'),'ready')}
    return [pscustomobject]@{Known=$false;Network=[pscustomobject]@{Known=$false;Key='';ObservedUtc=[datetime]::UtcNow.ToString('o')};Processes=@();SettingsHash='fixture'}
}
function Copy-Item {
    [CmdletBinding()]param([string]$LiteralPath,[string]$Destination,[switch]$Force)
    Microsoft.PowerShell.Management\Copy-Item @PSBoundParameters
    if($Tag -eq 'A' -and [IO.Path]::GetFileName($Destination) -like 'web-check-last*.json*'){
        [IO.File]::WriteAllText((Join-Path $OutputRoot 'A-ready'),'ready')
        $clock=[Diagnostics.Stopwatch]::StartNew()
        while(-not [IO.File]::Exists((Join-Path $OutputRoot 'release-A'))){
            if($clock.ElapsedMilliseconds -gt 10000){throw 'Parent did not release writer A.'}
            Start-Sleep -Milliseconds 20
        }
    }
}
$caps=[pscustomobject]@{CurlPath='';Curl=(Convert-WebCurlCapabilities '');BrowserPath='';BrowserVersion=''}
$target=[pscustomobject]@{Group='Fixture';Name=$Tag;Url='https://example.invalid/'}
$result=Invoke-WebVerification @($target) -Capabilities $caps -Subject ('writer '+$Tag) -Quiet
[IO.File]::WriteAllText((Join-Path $OutputRoot ($Tag+'-done')),$result.RunId)
'@
[IO.File]::WriteAllText($fixture,$child,(New-Object Text.UTF8Encoding($true)))
$children=New-Object System.Collections.Generic.List[object]
function Start-Writer([string]$Tag){
    $process=New-Object Diagnostics.Process
    $process.StartInfo=New-Object Diagnostics.ProcessStartInfo
    $process.StartInfo.FileName=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
    $process.StartInfo.Arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$fixture+'" -Pkg "'+$Pkg+'" -OutputRoot "'+$Script:Runtime+'" -Tag '+$Tag
    $process.StartInfo.UseShellExecute=$false;$process.StartInfo.CreateNoWindow=$true
    $process.StartInfo.RedirectStandardOutput=$true;$process.StartInfo.RedirectStandardError=$true
    if(-not $process.Start()){throw 'Writer did not start.'}
    $state=[pscustomobject]@{Process=$process;Output=$process.StandardOutput.ReadToEndAsync();Error=$process.StandardError.ReadToEndAsync()}
    $children.Add($state);return $state
}
function Wait-WriterSignal([string]$Name,$State){
    $clock=[Diagnostics.Stopwatch]::StartNew()
    while(-not [IO.File]::Exists((Join-Path $Script:Runtime $Name))){
        if($State.Process.HasExited){throw ($Name+' writer exited: '+$State.Error.GetAwaiter().GetResult())}
        if($clock.ElapsedMilliseconds -gt 10000){throw ('No writer signal '+$Name)}
        Start-Sleep -Milliseconds 20
    }
}
try {
    $a=Start-Writer 'A';Wait-WriterSignal 'A-ready' $a
    $b=Start-Writer 'B';Wait-WriterSignal 'B-ready' $b
    # With no publication lock, B finishes while A is paused between the two alias writes.
    # With the lock, B is pending until A is released. Both paths must end with one coherent pair.
    [void]$b.Process.WaitForExit(1200)
    [IO.File]::WriteAllText((Join-Path $Script:Runtime 'release-A'),'release')
    foreach($state in $children){
        if(-not $state.Process.WaitForExit(10000)){throw 'Writer exceeded its bound.'}
        if($state.Process.ExitCode -ne 0){throw $state.Error.GetAwaiter().GetResult()}
    }
    $json=Join-Path $Script:Runtime 'web-check-last.json';$text=Join-Path $Script:Runtime 'web-check-last.txt'
    $last=[IO.File]::ReadAllText($json)|ConvertFrom-Json
    Check 'two concurrent real entry points leave JSON and text from the same run' ([IO.File]::ReadAllText($text) -ceq [IO.File]::ReadAllText($last.TextFile))
    Check 'the pending second writer publishes its own latest result' ($last.RunId -ceq [IO.File]::ReadAllText((Join-Path $Script:Runtime 'B-done')))
    Check 'concurrent publishers retain both immutable report pairs' (@(Get-ChildItem -LiteralPath $Script:Runtime -File -Filter 'web-check-*.json'|Where-Object{$_.Name -ne 'web-check-last.json'}).Count -eq 2 -and [IO.File]::Exists((Join-Path $Script:Runtime 'A-done')) -and [IO.File]::Exists((Join-Path $Script:Runtime 'B-done')))
    if(-not (Get-Command Publish-WebVerificationReports -ErrorAction SilentlyContinue)){exit 1}
    $beforeJson=[IO.File]::ReadAllBytes($json);$beforeText=[IO.File]::ReadAllBytes($text)
    $firstId=[IO.File]::ReadAllText((Join-Path $Script:Runtime 'A-done'))
    $source=[IO.File]::ReadAllText((Join-Path $Script:Runtime ('web-check-'+$firstId+'.json')))|ConvertFrom-Json
    Check 'rollback fixture uses different old and new run contents' ($source.RunId -cne $last.RunId)
    $lease=[IO.File]::Open((Join-Path $Script:Runtime 'web-check-last.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    $clock=[Diagnostics.Stopwatch]::StartNew();$blocked=$false
    try{try{Publish-WebVerificationReports $source.JsonFile $source.TextFile -WaitMs 150}catch{$blocked=$true}}finally{$lease.Dispose()}
    Check 'publication waiting has a bound and preserves the previous pair' ($blocked -and $clock.ElapsedMilliseconds -lt 2000 -and (Same-Bytes $json $beforeJson) -and (Same-Bytes $text $beforeText))
    $failed=$false
    try{Publish-WebVerificationReports $source.JsonFile (Join-Path $Script:Runtime 'missing-text.txt')}catch{$failed=$true}
    Check 'failed staging preserves both previous aliases' ($failed -and (Same-Bytes $json $beforeJson) -and (Same-Bytes $text $beforeText))

    # Text is published before the JSON pointer. Denying JSON replacement exercises rollback.
    $reader=[IO.File]::Open($json,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $failed=$false
    try{try{Publish-WebVerificationReports $source.JsonFile $source.TextFile}catch{$failed=$true;Write-Host ('Expected publication failure '+$_.Exception.Message)}}finally{$reader.Dispose()}
    Check 'failed second replacement restores the preceding complete pair' ($failed -and (Same-Bytes $json $beforeJson) -and (Same-Bytes $text $beforeText))
    Publish-WebVerificationReports $source.JsonFile $source.TextFile
    Check 'failure releases the publication lease for the next writer' ((Same-Bytes $json ([IO.File]::ReadAllBytes($source.JsonFile))) -and (Same-Bytes $text ([IO.File]::ReadAllBytes($source.TextFile))))
    $leftovers=@(Get-ChildItem -LiteralPath $Script:Runtime -File|Where-Object{$_.Name -like 'web-check-last.*.tmp' -or $_.Name -like 'web-check-last.*.bak'})
    if($leftovers.Count){Write-Host ('Publication leftovers '+(($leftovers|ForEach-Object{$_.Name}) -join ', '))}
    Check 'successful publication leaves no owned staging or backup files' ($leftovers.Count -eq 0)

    $oldRuntime=$Script:Runtime;$Script:Runtime=Join-Path $oldRuntime 'partial previous pair';[void][IO.Directory]::CreateDirectory($Script:Runtime)
    $json=Join-Path $Script:Runtime 'web-check-last.json';$text=Join-Path $Script:Runtime 'web-check-last.txt'
    [IO.File]::WriteAllBytes($json,$beforeJson)
    $reader=[IO.File]::Open($json,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$failed=$false
    try{try{Publish-WebVerificationReports $source.JsonFile $source.TextFile}catch{$failed=$true}}finally{$reader.Dispose()}
    Check 'rollback restores the absence of an originally missing text alias' ($failed -and (Same-Bytes $json $beforeJson) -and -not [IO.File]::Exists($text))
    Publish-WebVerificationReports $source.JsonFile $source.TextFile
    Check 'publication recovers a previously incomplete alias pair' ([IO.File]::ReadAllText($text) -ceq [IO.File]::ReadAllText($source.TextFile))
} finally {
    foreach($state in $children){try{if(-not $state.Process.HasExited){$state.Process.Kill();$state.Process.WaitForExit()}}finally{$state.Process.Dispose()}}
}
if($fails){exit 1}
Write-Host 'Web report publication passed.'
