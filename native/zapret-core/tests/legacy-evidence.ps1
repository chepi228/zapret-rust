param([Parameter(Mandatory=$true)][string]$Root,[Parameter(Mandatory=$true)][string]$Out)
$ErrorActionPreference='Stop'
. (Join-Path $Root 'tools/selection.ps1')
. (Join-Path $Root 'tools/processmetrics.ps1')
. (Join-Path $Root 'tools/comparison.ps1')
$targets=@([pscustomobject]@{Group='Clean';Name='fixture';Url='https://example.invalid/'},[pscustomobject]@{Group='YouTube';Name='fixture';Url='https://video.invalid/'})
$cases=New-Object 'Collections.Generic.List[object]'
function Plan([int]$Seed=42,[switch]$Resources){New-FinalistPlan '12' '53' ('C'*64) ('D'*64) $targets ('A'*64) ('B'*64) $Seed 4 ('1'*32) -MeasureResources:$Resources}
function Rows($Plan,[double]$Gain=40){
    foreach($slot in $Plan.Slots){
        foreach($target in $Plan.Targets){
            $t=($slot.Index-1)*1000+100
            $tls=100+($t*0.01)
            if($slot.Kind -eq 'Compare' -and $slot.Arm -eq 'B'){$tls-=$Gain}
            [pscustomobject]@{Schema=1;RunId=$Plan.RunId;Seed=$Plan.Seed;Stage='comparison';ComparisonSlot=$slot.Index;ComparisonBlock=$slot.Block;ComparisonKind=$slot.Kind;ComparisonArm=$slot.Arm;StrategyId=$slot.StrategyId;StrategyHash=$slot.StrategyHash;CapturedNetworkKey=$Plan.CapturedNetworkKey;CapturedInputsHash=$Plan.CapturedInputsHash;TargetKey=$target.Key;Group=$target.Group;Name=$target.Name;Attempt=1;State='OK';TlsMs=$tls;StartedMs=$t;ObservedMs=($t+10)}
        }
        if($Plan.Protocol -eq 'finalists-v2'){
            foreach($phase in @('Ready','Warm','End')){
                $offset=@{Ready=0;Warm=50;End=950}[$phase]
                [pscustomobject]@{Schema=1;ResourceSchema=1;RunId=$Plan.RunId;Seed=$Plan.Seed;Stage='comparison-resource';ComparisonSlot=$slot.Index;ComparisonBlock=$slot.Block;ComparisonKind=$slot.Kind;ComparisonArm=$slot.Arm;StrategyId=$slot.StrategyId;StrategyHash=$slot.StrategyHash;CapturedNetworkKey=$Plan.CapturedNetworkKey;CapturedInputsHash=$Plan.CapturedInputsHash;ResourcePhase=$phase;ResourceStatus='Ready';ResourceReason='';ProcessId=(1000+$slot.Index);ProcessStartKey=('638000000000000000');ObservedMs=(($slot.Index-1)*1000+$offset);ReadDurationMs=0.25;CpuTotalMs=($offset/10);PrivateBytes=(32000000+$offset);WorkingSetBytes=16000000;OsPeakWorkingSetBytes=17000000}
            }
        }
    }
}
function Add-Case($Name,$Plan,$Rows,[switch]$Incomplete){
    $all=@($Rows)
    if(-not $Incomplete){$all+=New-FinalistCompletion $Plan $all}
    $cases.Add([pscustomobject]@{Name=$Name;Plan=$Plan;Rows=$all;Expected=(Get-FinalistAssessment $Plan $all)})
}
foreach($seed in @(0,42,2147483647)){$plan=Plan $seed;Add-Case ('seed-'+$seed) $plan @(Rows $plan)}
$plan=Plan
Add-Case 'equal' $plan @(Rows $plan 0)
Add-Case 'regressed' $plan @(Rows $plan -40)
Add-Case 'not-finalized' $plan @(Rows $plan) -Incomplete
$rows=@(Rows $plan);$rows[0].State='FAIL';$rows[0].TlsMs=0
Add-Case 'loss' $plan $rows
$rows=@(Rows $plan);$rows+=$rows[0].PSObject.Copy()
Add-Case 'duplicate' $plan $rows
$rows=@(Rows $plan);$rows[0].CapturedNetworkKey='E'*64
Add-Case 'mixed-context' $plan $rows
$rows=@(Rows $plan);$rows+=New-FinalistCompletion $plan $rows;$rows[0].TlsMs=1
Add-Case 'tampered-completion' $plan $rows -Incomplete
$numbers=@(0.0,-0.0,1e-6,1e-5,1e-4,1e15,1e16,1e17,1.2345678901234567,[double]::Epsilon,1e100,1.7976931348623157e308)
$rows=@(Rows $plan)
for($i=0;$i -lt $rows.Count;$i++){$rows[$i]|Add-Member NoteProperty DnsMs $numbers[$i%$numbers.Count]}
Add-Case 'canonical-floating-point' $plan $rows
$plan=Plan -Resources
Add-Case 'resources-ready' $plan @(Rows $plan)
$rows=@(Rows $plan);$rows|Where-Object{$_.Stage -eq 'comparison-resource' -and $_.ComparisonSlot -eq 5}|ForEach-Object{$_.ResourceStatus='Unavailable';$_.CpuTotalMs=$null}
Add-Case 'resources-partial' $plan $rows
$rows=@(Rows $plan);($rows|Where-Object{$_.Stage -eq 'comparison-resource'}|Select-Object -First 1).ProcessStartKey='639000000000000000'
Add-Case 'resources-reused' $plan $rows
$rows=@(Rows $plan);($rows|Where-Object{$_.Stage -eq 'comparison-resource'}|Select-Object -First 1).ObservedMs=900
Add-Case 'resources-clock' $plan $rows
$numbers=@(0.0,-0.0,1e-6,1e-5,1e-4,1e15,1e16,1e17,1.2345678901234567,[double]::Epsilon,1e100,1.7976931348623157e308)
$spellings=@($numbers|ForEach-Object{[pscustomobject]@{Value=$_;Text=$_.ToString('R',[Globalization.CultureInfo]::InvariantCulture)}})
[IO.File]::WriteAllText($Out,([pscustomobject]@{Cases=@($cases.ToArray());Numbers=$spellings}|ConvertTo-Json -Depth 28 -Compress),(New-Object Text.UTF8Encoding($false)))
