# Family planning and replay on recorded local rows. No traffic or real engine.
param([string]$Pkg=(Split-Path -Parent (Split-Path -Parent $PSScriptRoot)))
if (Test-Path (Join-Path $Pkg '.git')) { throw 'Run on a package copy.' }
$ErrorActionPreference='Stop'
. (Join-Path $Pkg 'tools/lib.ps1')
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Pkg 'tools/test.ps1'),[ref]$null,[ref]$null)
foreach ($fn in $ast.FindAll({$args[0] -is [Management.Automation.Language.FunctionDefinitionAst]},$false)) { . ([scriptblock]::Create($fn.Extent.Text)) }
$fails=0
function Check($Name,$Ok) { if ($Ok) { Write-Host ('ok '+$Name) } else { Write-Host ('FAIL '+$Name);$script:fails++ } }
if (-not (Get-Command Get-StrategySearchFamily -ErrorAction SilentlyContinue)) { throw 'FAIL family search planner is missing' }
$bundled=@(Get-TestStrategies)
$bundledRequired=@(Get-RequiredTestStrategyIds (Get-Settings) (Get-TestRank) $bundled)
$bundledPlan=New-FamilySearchPlan $bundled $bundledRequired
Write-Host ('bundled fresh pool='+$bundled.Count+' families='+@($bundledPlan.FamilyById.Values | Sort-Object -Unique).Count+' initial='+$bundledPlan.Initial.Count+' deferred='+$bundledPlan.Deferred.Count)
Check 'bundled TCP variants form reusable families' (@($bundledPlan.FamilyById.Values | Sort-Object -Unique).Count -lt $bundled.Count)
Check 'bundled quick pool leaves candidates for its second stage' ($bundledPlan.Deferred.Count -gt 0)
Check 'different fake SNI values share one bundled family' ((Get-StrategySearchFamily (Get-Strategy '50')) -eq (Get-StrategySearchFamily (Get-Strategy '60')))
$warmBundled=@($bundled | Where-Object {$Script:RotationPref -contains $_.Id -or $Script:QuickExtra -contains $_.Id})
$warmPlan=New-FamilySearchPlan $warmBundled @((Get-Settings).alt)
Write-Host ('bundled warm pool='+$warmBundled.Count+' initial='+$warmPlan.Initial.Count+' deferred='+$warmPlan.Deferred.Count)
Check 'bundled warm pool can start with fewer strategy launches' ($warmPlan.Initial.Count -lt $warmBundled.Count)
function Strategy($Id,$Method='multisplit',$Position=1) {
    [pscustomobject]@{Id=[string]$Id;Name=('fixture '+$Id);Since='';Missing=@();MatchL3=@{};Sections=@{general=@('--out-range=-d10','--payload=tls_client_hello',('--lua-desync='+$Method+':pos='+$Position+':fool=badseq:repeats=4'))}}
}
$a=Strategy 1;$b=Strategy 2 'multisplit' 9
Check 'parameter variants share a family' ((Get-StrategySearchFamily $a) -eq (Get-StrategySearchFamily $b))
Check 'different methods have different families' ((Get-StrategySearchFamily $a) -ne (Get-StrategySearchFamily (Strategy 3 'multidisorder')))
$b.MatchL3.general='ipv4'
Check 'L3 restriction changes the family' ((Get-StrategySearchFamily $a) -ne (Get-StrategySearchFamily $b))
$b=Strategy 2;$b.Sections.general[1]='--payload=http_req'
Check 'payload selection changes the family' ((Get-StrategySearchFamily $a) -ne (Get-StrategySearchFamily $b))
$b=Strategy 2;$b.Sections.general[2]=$b.Sections.general[2].Replace('fool=badseq','fool=badsum')
Check 'fooling class changes the family' ((Get-StrategySearchFamily $a) -ne (Get-StrategySearchFamily $b))
$b=Strategy 2;$b.Sections.general+='--filter-l7=tls'
Check 'custom native directives remain part of the family' ((Get-StrategySearchFamily $a) -ne (Get-StrategySearchFamily $b))
$tlsFirst=Strategy 1;$httpFirst=Strategy 2
$tlsFirst.Sections.general=@('--payload=tls_client_hello','--lua-desync=fake:blob=tls_google','--payload=http_req','--lua-desync=multisplit:pos=1')
$httpFirst.Sections.general=@('--payload=tls_client_hello','--lua-desync=multisplit:pos=1','--payload=http_req','--lua-desync=fake:blob=tls_google')
Check 'methods stay attached to their payload scope in a family key' ((Get-StrategySearchFamily $tlsFirst) -ne (Get-StrategySearchFamily $httpFirst))
$tlsFirst.Sections.general=@('--payload=tls_client_hello','--lua-desync=fake:blob=tls_google','--lua-desync=multisplit:pos=1')
$httpFirst.Sections.general=@('--payload=tls_client_hello','--lua-desync=multisplit:pos=1','--lua-desync=fake:blob=tls_google')
Check 'different action order remains a different family' ((Get-StrategySearchFamily $tlsFirst) -ne (Get-StrategySearchFamily $httpFirst))
$pool=@(1..5 | ForEach-Object {Strategy $_ 'multisplit' $_})+@(6..10 | ForEach-Object {Strategy $_ 'multidisorder' $_})+@(11..15 | ForEach-Object {Strategy $_ 'fake' $_})
$order=New-TestMeasurementOrder $pool 1 42 -FamilySearch -RequiredIds @('1','2')
$plan=$order.Rounds[0].FamilySearch
Check 'initial stage contains every family and required primary companions' ($plan.Initial.Count -eq 4 -and @($plan.Initial.Id | Where-Object {$_ -in @('1','2')}).Count -eq 2 -and @($plan.Initial | ForEach-Object {$plan.FamilyById[$_.Id]} | Sort-Object -Unique).Count -eq 3)
Check 'every candidate is preserved once across initial and deferred stages' ((@($order.Rounds[0].Strategies.Id | Sort-Object -Unique).Count -eq 15) -and $plan.Initial.Count+$plan.Deferred.Count -eq 15)
$same=New-TestMeasurementOrder $pool 1 42 -FamilySearch -RequiredIds @('1','2')
Check 'seed reproduces family plan without mutating input' (($order|ConvertTo-Json -Depth 12 -Compress) -ceq ($same|ConvertTo-Json -Depth 12 -Compress) -and ($pool.Id -join ',') -eq (1..15 -join ','))
$paired=New-TestMeasurementOrder $pool 2 42 -FamilySearch -RequiredIds @('1','2')
$reverse=@($paired.Rounds[0].Strategies.Id);[array]::Reverse($reverse)
Check 'multiple rounds retain every candidate and exact reverse pairing' (-not (Get-ProbeField $paired.Rounds[0] 'FamilySearch') -and ($reverse -join ',') -ceq ($paired.Rounds[1].Strategies.Id -join ',') -and $paired.Rounds[0].Strategies.Count -eq 15)
$targets=@([pscustomobject]@{Group='YouTube';Name='video';Url='https://video.example/'},[pscustomobject]@{Group='Discord';Name='gateway';Url='https://gateway.example/'},[pscustomobject]@{Group='Clean';Name='clean';Url='https://clean.example/'})
function Rows($State='OK') {
    foreach ($t in $targets) { [pscustomobject]@{Group=$t.Group;Name=$t.Name;Url=$t.Url;State=$State;TlsMs=100;Flaky=$false;Tries=1;Code='200';Exit=0;Up=0;Down=100;ConnMs=50} }
}
$baseline=@(Rows)
Check 'all targets and healthy controls confirm coverage' (Test-SearchCandidateRows $targets @(Rows) $baseline 500)
foreach ($problem in @('missing','duplicate','unknown','cancelled','flaky','slow','missing-timing','infinite-timing','bad-baseline')) {
    $rows=@(Rows);$base=@(Rows)
    switch ($problem) {
        'missing' {$rows=@($rows[0],$rows[2])}
        'duplicate' {$rows=@($rows[0],$rows[0],$rows[2])}
        'unknown' {$rows[0].State='NA'}
        'cancelled' {$rows[0].State='CANCELLED'}
        'flaky' {$rows[0].Flaky=$true}
        'slow' {$rows[2].TlsMs=601}
        'missing-timing' {$rows[2].TlsMs=$null}
        'infinite-timing' {$rows[2].TlsMs=[double]::PositiveInfinity}
        'bad-baseline' {$base[2].State='FAIL'}
    }
    Check ($problem+' prevents a shortened search') (-not (Test-SearchCandidateRows $targets $rows $base 500))
}
$table=@{'0'=$baseline}
foreach ($s in $plan.Initial) {$table[$s.Id]=@(Rows)}
$next=Get-FamilySearchContinuation $plan $table $targets 500
Check 'fully covered initial stage refines at most two siblings' ($next.Reason -eq 'CoverageConfirmed' -and $next.Strategies.Count -le 2 -and $next.SkippedIds.Count -gt 0)
Check 'refinement and explicit skips account for every deferred candidate' ($next.Strategies.Count+$next.SkippedIds.Count -eq $plan.Deferred.Count)
$shortened=$plan.Initial.Count+$next.Strategies.Count
Check ('recorded perfect matrix preserves coverage using '+$shortened+'/15 launches') ($shortened -lt 15 -and @(Rows | Where-Object {$_.State -ne 'OK'}).Count -eq 0)
# The first representative fails a target that only a deferred sibling can open.
$table=@{'0'=$baseline}
foreach ($s in $plan.Initial) {$rows=@(Rows);$rows[0].State='FAIL';$table[$s.Id]=$rows}
$next=Get-FamilySearchContinuation $plan $table $targets 500
Check 'failed representatives keep every deferred sibling eligible' ($next.Reason -eq 'CoverageIncomplete' -and $next.Strategies.Count -eq $plan.Deferred.Count -and $next.SkippedIds.Count -eq 0)
$table[$next.Strategies[-1].Id]=@(Rows)
Check 'exhaustive continuation can recover unique coverage in the last sibling' (Test-SearchCandidateRows $targets $table[$next.Strategies[-1].Id] $baseline 500)
$table=@{'0'=$baseline}
foreach ($s in $plan.Initial) {$table[$s.Id]=@(Rows)}
$table.Remove($plan.Initial[-1].Id)
$next=Get-FamilySearchContinuation $plan $table $targets 500
Check 'failed mandatory startup cannot shorten the continuation' ($next.Reason -eq 'CoverageIncomplete' -and $next.Strategies.Count -eq $plan.Deferred.Count)
$table[$plan.Initial[-1].Id]=@(Rows);$table[$plan.Initial[-1].Id][0].State='NA'
$next=Get-FamilySearchContinuation $plan $table $targets 500
Check 'one unknown initial candidate prevents shortening despite another perfect candidate' ($next.Reason -eq 'CoverageIncomplete' -and $next.Strategies.Count -eq $plan.Deferred.Count)
foreach ($problem in @('missing','zero','infinite','slow')) {
    $table=@{'0'=$baseline};foreach ($s in $plan.Initial) {$table[$s.Id]=@(Rows)}
    $control=$table[$plan.Initial[-1].Id][2]
    switch ($problem) {'missing' {$control.TlsMs=$null};'zero' {$control.TlsMs=0};'infinite' {$control.TlsMs=[double]::PositiveInfinity};'slow' {$control.TlsMs=601}}
    $next=Get-FamilySearchContinuation $plan $table $targets 500
    Check ($problem+' timing of another initial control prevents shortening') ($next.Reason -eq 'CoverageIncomplete' -and $next.SkippedIds.Count -eq 0)
}
$first=@(Rows);$first[0].State='FAIL'
$unknown=@(Rows);$unknown[0].State='NA';$unknown[0].Exit=6
$merged=@(Merge-Retry $first @($unknown[0]))
$table=@{'0'=$baseline};foreach ($s in $plan.Initial) {$table[$s.Id]=@(Rows)}
$table[$plan.Initial[-1].Id]=$merged
$next=Get-FamilySearchContinuation $plan $table $targets 500
Check 'merged repeated rows require original-attempt eligibility before shortening' ($next.Reason -eq 'CoverageIncomplete' -and $next.SkippedIds.Count -eq 0)
$first=@(Rows);$first[0].State='FAIL';$repeat=@(Rows)[0];$repeat.State='FAIL'
Check 'matching known failed attempts remain eligible without changing their score' (Test-SearchProbeAttempts $targets $first @($targets[0]) @($repeat) @{clean=100} 500)
Check 'missing retry row prevents shortening' (-not (Test-SearchProbeAttempts $targets $first @($targets[0]) @() @{clean=100} 500))
Check 'duplicate retry rows prevent shortening' (-not (Test-SearchProbeAttempts $targets $first @($targets[0]) @($repeat,$repeat) @{clean=100} 500))
$repeat.State='NA'
Check 'unknown retry cannot be hidden by a known first failure' (-not (Test-SearchProbeAttempts $targets $first @($targets[0]) @($repeat) @{clean=100} 500))
$first=@(Rows);$first[2].TlsMs=900;$repeat=@(Rows)[2];$repeat.State='FAIL'
Check 'slow first control and failed retry remain unsuitable for shortening' (-not (Test-SearchProbeAttempts $targets $first @($targets[2]) @($repeat) @{clean=100} 500))
# Exercise the actual measurement loop, including failed startup at the stage boundary.
$loop=$ast.Find({param($n) $n -is [Management.Automation.Language.ForEachStatementAst] -and $n.Extent.Text.StartsWith('foreach ($roundPlan in $measurementOrder.Rounds)')},$true)
if (-not $loop) { throw 'FAIL actual measurement loop is missing' }
$Parallel=16;$TimeoutSec=5;$RetryMax=16;$HopelessRuns=3;$HarmSlowMs=500;$Rounds=1
$GroupNames=[ordered]@{YouTube='YouTube';Discord='Discord';Clean='Clean'}
$settings=@{alt='1'};$testLifetimeMs=120000;$postFile=''
$scoreFingerprints=@{};foreach ($s in $pool) {$scoreFingerprints[$s.Id]='C'*64}
$script:fakeProcess=$null;$script:case='';$script:startedIds=@();$script:measuredIds=@();$script:initialIds=@();$script:failedId=''
function Start-TestInstance($Settings,$Alt,$LifetimeMs) {
    $script:startedIds+=$Alt
    if ($script:case -eq 'startup' -and $Alt -eq $script:failedId) { return $null }
    $script:fakeProcess=[pscustomobject]@{Id=123456;HasExited=$false}
    $script:fakeProcess | Add-Member ScriptMethod WaitForExit {return $this.HasExited}
    return $script:fakeProcess
}
function Stop-Process {param($Id,[switch]$Force,$ErrorAction);if ($Id -ne 123456) {throw 'Fixture refuses a real PID'};$script:fakeProcess.HasExited=$true}
function Start-Sleep { }
function Invoke-CurlBatch($Targets,$PostFile,$Width=0,[long]$DeadlineTicks=0,$RequiredProcess=$null) {
    $id=[string]$metadata.StrategyId
    if ($id -ne '0') {$script:measuredIds+=$id}
    foreach ($row in @(Rows)) {
        if ($script:case -eq 'incomplete' -and $script:initialIds -contains $id -and $row.Group -eq 'YouTube') {$row.State='FAIL'}
        if ($script:case -eq 'retryunknown' -and $id -eq $script:failedId -and $row.Group -eq 'YouTube') {
            $row.State=if (@($script:measuredIds | Where-Object {$_ -eq $id}).Count -eq 1) {'FAIL'} else {'NA'}
            if ($row.State -eq 'NA') {$row.Exit=6}
        }
        if (@($Targets | Where-Object {$_.Name -eq $row.Name}).Count) {$row}
    }
}
foreach ($case in @('perfect','incomplete','retryunknown','startup','full')) {
    $script:case=$case;$script:startedIds=@();$script:measuredIds=@()
    $measurementOrder=New-TestMeasurementOrder $pool 1 42 -FamilySearch:($case -ne 'full') -RequiredIds @('1','2')
    $script:initialIds=@($plan.Initial.Id);$script:failedId=$plan.Initial[-1].Id
    $table=@{};$failRuns=@{};$everOk=@{};$p=$null
    $measurementId=[guid]::NewGuid().ToString('N')
    $journalFile=Join-Path $Script:Runtime ('family-'+$measurementId+'.jsonl')
    $metadata=@{RunId=$measurementId;Seed=42;Sequence=0;Round=0;Stage='baseline';StrategyId='0';StrategyHash='';NetworkKey=('A'*64);InputsHash=('B'*64)}
    $report=New-Object 'Collections.Generic.List[string]'
    . ([scriptblock]::Create($loop.Extent.Text))
    $actual=@($script:measuredIds | Select-Object -Unique)
    if ($case -eq 'perfect') {
        Check 'actual entry loop shortens a covered search and records no invented rows' ($actual.Count -lt 15 -and $table.Count -eq $actual.Count+1 -and $actual -contains '1' -and $actual -contains '2')
    } elseif ($case -eq 'startup') {
        Check 'failed last initial startup still measures every deferred candidate' (@($plan.Deferred.Id | Where-Object {$actual -notcontains $_}).Count -eq 0 -and $actual.Count -eq 14)
    } else {
        Check ($case+' actual entry loop measures the entire candidate pool') ($actual.Count -eq 15)
    }
    $searchFile=Join-Path $Script:Runtime ('test-search-'+$measurementId+'.json')
    if ($case -ne 'full') {
        $record=if (Test-Path -LiteralPath $searchFile) {Get-Content -LiteralPath $searchFile -Raw | ConvertFrom-Json} else {$null}
        Check ($case+' execution records the continuation and explicit skips') ($null -ne $record -and @($record.ContinuationIds).Count+@($record.SkippedIds).Count -eq $plan.Deferred.Count)
        if ($case -eq 'retryunknown') { Check 'execution records that original attempts rejected shortening' ((Get-ProbeField $record.ProbeEligibility $script:failedId) -eq $false -and $record.Reason -eq 'CoverageIncomplete') }
    }
}
if ($fails) { exit 1 }
