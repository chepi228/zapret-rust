# Measurement evidence helpers. No processes, network requests or settings writes on import.
function Get-ProbeTransferState([string]$Code,[Nullable[int]]$Exit,[double]$Up,[double]$Down,[bool]$Post,[bool]$TargetReached=$false) {
    if ($null -eq $Exit) { return 'FAIL' }
    if ($Exit -eq 6) { return 'NA' }
    if ($TargetReached -and $Exit -in @(0,23,28) -and $Code -match '^[1-9][0-9]{2}$') { return 'OK' }
    if ($Exit -eq 0 -and $Code -match '^[1-9][0-9]{2}$') { return 'OK' }
    if ($Exit -eq 28 -and ($Down -gt 0 -or ($Post -and $Up -gt 0))) { return 'FREEZE' }
    return 'FAIL'
}
function Get-TcpUnavailableText([string[]]$Names) {
    return ('TCP-подключение к проверенному IPv4 не удалось для '+($Names -join ', ')+'. Возможные причины включают фильтрацию, сбой маршрута и недоступность выбранного адреса. Точная причина не установлена.')
}
function Get-PrimaryDecisionText($Choice,[hashtable]$Averages,[string]$CurrentName,[double]$Margin,[switch]$ReportOnly,[switch]$KeepPrimary) {
    if ($ReportOnly) { return ('Решение по основной: '+$CurrentName+' сохраняется — режим отчёта.') }
    if ($KeepPrimary) { return ('Решение по основной: '+$CurrentName+' сохраняется; рейтинг и круги автосмены обновляются после итоговой проверки.') }
    $top=$Choice.Top;$mean=Format-Points $Averages[$top.Id].Avg;$runs=$Averages[$top.Id].Runs
    if ($Choice.Current -and $top.Id -eq $Choice.Current.Id) {
        return ('Решение по основной: '+$CurrentName+' сохраняется — она лидирует по среднему баллу '+$mean+'; совместимых прогонов: '+$runs+'.')
    }
    if ($Choice.Noise) {
        $current=Format-Points $Averages[$Choice.Current.Id].Avg
        $gap=Format-Points ($Averages[$top.Id].Avg-$Averages[$Choice.Current.Id].Avg)
        return ('Решение по основной: '+$CurrentName+' сохраняется. По среднему впереди '+$top.Name+' ('+$mean+'), у основной '+$current+'; преимущество '+$gap+' меньше порога смены '+(Format-Points $Margin)+'.')
    }
    $line='Решение по основной: по среднему предлагается '+$top.Name+' ('+$mean+'; совместимых прогонов: '+$runs+'). Применение возможно после итоговой проверки рабочего режима.'
    if (-not $Choice.Current) { $line+=' Текущая основная в этом прогоне не проверялась.' }
    return $line
}
function Get-PrimaryResultText([string]$PrimaryName,[string]$CandidateName,[ValidateSet('Applied','Kept','Rejected','ReportOnly','QualityRejected')][string]$Status,[string]$Details='') {
    $head='Основная после теста: '+$PrimaryName+'. '
    switch ($Status) {
        'Applied' { return ($head+'Применена после итоговой проверки рабочего режима.') }
        'Kept' { return ($head+'Сохранена; итоговая комбинация подтверждена в рабочем режиме.') }
        'Rejected' { return ($head+'Итоговая комбинация с «'+$CandidateName+'» отклонена, смена не применена. Прежние настройки и рейтинг сохранены. '+$Details) }
        'ReportOnly' { return ($head+'Сохранена — режим отчёта.') }
        'QualityRejected' { return ($head+'Сохранена: результаты измерений отклонены. '+$Details) }
    }
}
function Get-StrategySearchFamily($Strategy) {
    $sections=Get-ProbeField $Strategy 'Sections'
    if ($sections -isnot [Collections.IDictionary] -or -not $sections.Count) { return ('custom-'+$Strategy.Id) }
    $l3=Get-ProbeField $Strategy 'MatchL3'
    $parts=@('family-tcp-v1')
    foreach ($section in @('general','google','discord_media','ipset_tcp')) {
        $actual=if ($sections.ContainsKey($section)) {$section} else {'general'}
        $family=if ($l3 -and $l3.ContainsKey($actual)) { $l3[$actual] } else { 'any' }
        $parts+=($section+'@'+$family)
        $lastAction=$null
        foreach ($line in @($sections[$actual])) {
            $value=[string]$line
            if ($value.StartsWith('--lua-desync=')) {
                $value=[regex]::Replace($value,':(pos|repeats|blob|host|seqovl|seqovl_pattern)=[^:]+',':$1=*')
                $value=[regex]::Replace($value,'(?<=[=,])sni=[^,:]+','sni=*')
                if ($value -cne $lastAction) { $parts+=$value }
                $lastAction=$value
            } else { $parts+=$value;$lastAction=$null }
        }
    }
    $sha=[Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($parts -join "`n")))).Replace('-','') } finally { $sha.Dispose() }
}
function New-FamilySearchPlan($Strategies,[string[]]$RequiredIds=@()) {
    $all=@($Strategies);$byId=@{};$families=@{}
    foreach ($strategy in $all) {
        $id=[string]$strategy.Id
        if ($id -notmatch '^\d+$' -or $byId.ContainsKey($id)) { throw 'Некорректный или повторный ID стратегии в плане.' }
        $byId[$id]=$strategy;$families[$id]=Get-StrategySearchFamily $strategy
    }
    foreach ($id in $RequiredIds) { if (-not $byId.ContainsKey($id)) { throw ('Обязательная стратегия отсутствует в плане '+$id) } }
    $preferred=@($RequiredIds | ForEach-Object { $byId[$_] })+$all
    $representatives=@{}
    foreach ($strategy in $preferred) {
        $family=$families[$strategy.Id]
        if (-not $representatives.ContainsKey($family)) { $representatives[$family]=$strategy }
    }
    $initial=New-Object 'Collections.Generic.List[object]';$included=@{}
    foreach ($strategy in $all) {
        $representative=$representatives[$families[$strategy.Id]]
        if (-not $included.ContainsKey($representative.Id)) { $initial.Add($representative);$included[$representative.Id]=$true }
    }
    foreach ($id in $RequiredIds) { if (-not $included.ContainsKey($id)) { $initial.Add($byId[$id]);$included[$id]=$true } }
    return [pscustomobject]@{Policy='family-v1';Initial=@($initial.ToArray());Deferred=@($all | Where-Object {-not $included.ContainsKey($_.Id)});FamilyById=$families;RequiredIds=@($RequiredIds)}
}
function Get-SearchRowsByKey($Targets,$Rows) {
    $targets=@($Targets);$rows=@($Rows)
    if (-not $targets.Count -or $rows.Count -ne $targets.Count) { return $null }
    $keys=@{};$map=@{}
    foreach ($target in $targets) {
        $key=Get-ProbeKey $target
        if (-not $key -or $keys.ContainsKey($key)) { return $null }
        $keys[$key]=$true
    }
    foreach ($row in $rows) {
        $key=Get-ProbeKey $row
        if (-not $key -or -not $keys.ContainsKey($key) -or $map.ContainsKey($key) -or (Get-ProbeField $row 'State') -notin @('OK','FAIL','FREEZE') -or (Get-ProbeField $row 'Flaky')) { return $null }
        $map[$key]=$row
    }
    return $map
}
function Test-SearchControlRows([hashtable]$Actual,[hashtable]$Baseline,[int]$HarmSlowMs=500) {
    if (-not $Actual -or -not $Baseline) { return $false }
    $controls=@($Actual.Values | Where-Object {$_.Group -eq 'Clean'})
    foreach ($row in $controls) {
        $base=$Baseline[(Get-ProbeKey $row)]
        if (-not $base -or $base.State -ne 'OK' -or $row.State -ne 'OK') { return $false }
        $before=Get-ProbeMetric $base 'TlsMs';$after=Get-ProbeMetric $row 'TlsMs'
        if ($null -eq $before -or $null -eq $after -or $before -le 0 -or $after -le 0 -or $after -gt $before+$HarmSlowMs) { return $false }
    }
    return ($controls.Count -gt 0)
}
function Test-SearchCandidateRows($Targets,$Actual,$Baseline,[int]$HarmSlowMs=500) {
    $actualMap=Get-SearchRowsByKey $Targets $Actual
    $baselineMap=Get-SearchRowsByKey $Targets $Baseline
    if (-not (Test-SearchControlRows $actualMap $baselineMap $HarmSlowMs)) { return $false }
    return (@($Actual | Where-Object {$_.State -ne 'OK'}).Count -eq 0 -and @($Targets | Where-Object {$_.Group -ne 'Clean'}).Count -gt 0)
}
function Test-SearchProbeAttempts($Targets,$First,$RetryTargets,$Retry,[hashtable]$CleanBaseline,[int]$HarmSlowMs=500) {
    $firstMap=Get-SearchRowsByKey $Targets $First
    if (-not $firstMap) { return $false }
    $retryMap=@{}
    if (@($RetryTargets).Count) {
        $retryMap=Get-SearchRowsByKey $RetryTargets $Retry
        if (-not $retryMap) { return $false }
        foreach ($key in $retryMap.Keys) {
            if (-not $firstMap.ContainsKey($key) -or $firstMap[$key].State -ne $retryMap[$key].State) { return $false }
        }
    } elseif (@($Retry).Count) { return $false }
    foreach ($row in @($First)+@($Retry)) {
        if ($row.Group -ne 'Clean') { continue }
        $ms=Get-ProbeMetric $row 'TlsMs'
        if ($row.State -ne 'OK' -or $null -eq $ms -or $ms -le 0) { return $false }
        if ($CleanBaseline -and $CleanBaseline.ContainsKey($row.Name) -and $ms -gt $CleanBaseline[$row.Name]+$HarmSlowMs) { return $false }
    }
    return $true
}
function Get-FamilySearchContinuation($Plan,[hashtable]$Table,$Targets,[int]$HarmSlowMs=500,[hashtable]$ProbeEligibility=$null) {
    $measured=@();$ordinal=0
    $baseline=if ($Table.ContainsKey('0')) { $Table['0'] } else { @() }
    $baselineMap=Get-SearchRowsByKey $Targets $baseline
    $complete=[bool]$baselineMap
    if ($null -ne $ProbeEligibility) {
        if (-not $ProbeEligibility.ContainsKey('0') -or $ProbeEligibility['0'] -ne $true) { $complete=$false }
    } elseif (@($baseline | Where-Object {(Get-ProbeMetric $_ 'Tries') -gt 1}).Count) { $complete=$false }
    foreach ($strategy in $Plan.Initial) {
        $ordinal++
        if (-not $Table.ContainsKey($strategy.Id)) { $complete=$false;continue }
        $rows=@($Table[$strategy.Id])
        $rowMap=Get-SearchRowsByKey $Targets $rows
        if (-not $rowMap) { $complete=$false;continue }
        if (-not (Test-SearchControlRows $rowMap $baselineMap $HarmSlowMs)) { $complete=$false }
        if ($null -ne $ProbeEligibility) {
            if (-not $ProbeEligibility.ContainsKey($strategy.Id) -or $ProbeEligibility[$strategy.Id] -ne $true) { $complete=$false }
        } elseif (@($rows | Where-Object {(Get-ProbeMetric $_ 'Tries') -gt 1}).Count) { $complete=$false }
        $successes=@($rows | Where-Object {$_.Group -ne 'Clean' -and $_.State -eq 'OK'}).Count
        $measured+=[pscustomobject]@{Id=$strategy.Id;Family=$Plan.FamilyById[$strategy.Id];Successes=$successes;Ordinal=$ordinal;Perfect=(Test-SearchCandidateRows $Targets $rows $baseline $HarmSlowMs)}
    }
    $ordered=@($measured | Sort-Object @{Expression={$_.Perfect};Descending=$true},@{Expression={$_.Successes};Descending=$true},Ordinal)
    $winner=@($ordered | Where-Object {$_.Perfect} | Select-Object -First 1)
    $reason='CoverageIncomplete';$skipped=@()
    if ($complete -and $winner.Count) {
        $reason='CoverageConfirmed'
        $chosen=@($Plan.Deferred | Where-Object {$Plan.FamilyById[$_.Id] -eq $winner[0].Family} | Select-Object -First 2)
        $chosenIds=@($chosen | ForEach-Object {$_.Id})
        $skipped=@($Plan.Deferred | Where-Object {$chosenIds -notcontains $_.Id} | ForEach-Object {$_.Id})
    } else {
        $familyOrder=@{}
        foreach ($entry in $ordered) { if (-not $familyOrder.ContainsKey($entry.Family)) { $familyOrder[$entry.Family]=$familyOrder.Count } }
        $deferredIds=@($Plan.Deferred | ForEach-Object {[string]$_.Id})
        $chosen=@($Plan.Deferred | Sort-Object @{Expression={if ($familyOrder.ContainsKey($Plan.FamilyById[$_.Id])) {$familyOrder[$Plan.FamilyById[$_.Id]]} else {[int]::MaxValue}}},@{Expression={[array]::IndexOf($deferredIds,[string]$_.Id)}})
    }
    return [pscustomobject]@{Reason=$reason;Strategies=$chosen;SkippedIds=$skipped}
}
function New-TestMeasurementOrder($Strategies, [ValidateRange(1,10)][int]$Rounds, [ValidateRange(0,2147483647)][int]$Seed,[switch]$FamilySearch,[string[]]$RequiredIds=@()) {
    $all=@($Strategies)
    if (-not $all.Count) { throw 'Нет стратегий для измерения.' }
    $random=New-Object System.Random($Seed)
    $items=New-Object 'System.Collections.Generic.List[object]'
    for ($round=1; $round -le $Rounds; $round+=2) {
        $shuffled=@($all | ForEach-Object { $_ })
        for ($i=$shuffled.Count-1; $i -gt 0; $i--) {
            $j=$random.Next($i+1);$temporary=$shuffled[$i];$shuffled[$i]=$shuffled[$j];$shuffled[$j]=$temporary
        }
        $roundPlan=[pscustomobject]@{Number=$round;Strategies=@($shuffled)}
        if ($FamilySearch -and $Rounds -eq 1) {
            $plan=New-FamilySearchPlan $shuffled $RequiredIds
            $roundPlan.Strategies=@($plan.Initial)+@($plan.Deferred)
            $roundPlan | Add-Member NoteProperty FamilySearch $plan
        }
        $items.Add($roundPlan)
        if ($round -lt $Rounds) {
            $reverse=@($shuffled | ForEach-Object { $_ });[array]::Reverse($reverse)
            $items.Add([pscustomobject]@{Number=($round+1);Strategies=@($reverse)})
        }
    }
    return [pscustomobject]@{Schema=1;Seed=$Seed;Rounds=@($items.ToArray())}
}
function Get-ProbeField($Row,[string]$Name) {
    if ($null -eq $Row) { return $null }
    $property=$Row.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
}
function Get-ProbeMetric($Row,[string]$Name) {
    $raw=Get-ProbeField $Row $Name
    if ($null -eq $raw) { return $null }
    $value=0.0
    if (-not [double]::TryParse([string]$raw,[Globalization.NumberStyles]::Float,[Globalization.CultureInfo]::InvariantCulture,[ref]$value) -or [double]::IsNaN($value) -or [double]::IsInfinity($value)) { return $null }
    return $value
}
function Get-ProbeKey($Row) {
    $parts=@(foreach ($name in @('Group','Name','Url')) { Get-ProbeField $Row $name })
    if ($parts.Count -ne 3 -or @($parts | Where-Object { -not $_ }).Count) { return '' }
    $sha=[Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($parts -join "`n")))).Replace('-','') } finally { $sha.Dispose() }
}
function Get-ControlTargets($Targets) {
    $clean=@($Targets | Where-Object { $_.Group -eq 'Clean' })
    $ordered=@()
    foreach ($name in @('bing','github','pypi','aws','steam')) { $ordered+=@($clean | Where-Object { $_.Name -eq $name }) }
    $ordered+=@($clean | Where-Object { $ordered -notcontains $_ })
    $hosts=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $out=@()
    foreach ($target in $ordered) {
        $uri=$null
        if (-not [uri]::TryCreate($target.Url,[UriKind]::Absolute,[ref]$uri) -or $uri.Scheme -ne 'https' -or -not $hosts.Add($uri.DnsSafeHost)) { continue }
        $out+=$target
        if ($out.Count -eq 5) { break }
    }
    return $out
}
function Get-ControlAssessment($Targets,$Before,$After) {
    $Targets=@(Get-ControlTargets $Targets)
    $maps=@()
    foreach ($rows in @(@{Rows=@($Before)},@{Rows=@($After)})) {
        $map=New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
        foreach ($row in $rows.Rows) {
            $key=Get-ProbeKey $row
            if (-not $key) { continue }
            if (-not $map.ContainsKey($key)) { $map.Add($key,(New-Object 'System.Collections.Generic.List[object]')) }
            $map[$key].Add($row)
        }
        $maps+=,$map
    }
    $matched=0;$availability=@();$up=@();$down=@();$uncertain=@()
    foreach ($target in $Targets) {
        $key=Get-ProbeKey $target
        $b=@(if ($key -and $maps[0].ContainsKey($key)) { $maps[0][$key] })
        $a=@(if ($key -and $maps[1].ContainsKey($key)) { $maps[1][$key] })
        $complete=$true
        foreach ($window in @(@{Rows=$b},@{Rows=$a})) {
            if ($window.Rows.Count -ne 2 -or (@($window.Rows | ForEach-Object { Get-ProbeMetric $_ 'Attempt' } | Sort-Object -Unique) -join ',') -ne '1,2') { $complete=$false }
        }
        if (-not $complete) { $uncertain+=$target.Name;continue }
        $bok=@($b | Where-Object { (Get-ProbeField $_ 'State') -eq 'OK' }).Count
        $aok=@($a | Where-Object { (Get-ProbeField $_ 'State') -eq 'OK' }).Count
        $bknown=@($b | Where-Object { (Get-ProbeField $_ 'State') -in @('OK','FAIL','FREEZE') }).Count
        $aknown=@($a | Where-Object { (Get-ProbeField $_ 'State') -in @('OK','FAIL','FREEZE') }).Count
        if ($bknown -eq 2 -and $aknown -eq 2 -and (($bok -eq 2 -and $aok -eq 0) -or ($bok -eq 0 -and $aok -eq 2))) { $availability+=$target.Name;continue }
        $bt=@($b | ForEach-Object { Get-ProbeMetric $_ 'TlsMs' } | Where-Object { $null -ne $_ -and $_ -gt 0 })
        $at=@($a | ForEach-Object { Get-ProbeMetric $_ 'TlsMs' } | Where-Object { $null -ne $_ -and $_ -gt 0 })
        if ($bok -ne 2 -or $aok -ne 2 -or $bt.Count -ne 2 -or $at.Count -ne 2) { $uncertain+=$target.Name;continue }
        $matched++
        $threshold=[math]::Max(250,0.5*[math]::Min(($bt[0]+$bt[1])/2,($at[0]+$at[1])/2))
        if ([math]::Min($at[0],$at[1])-[math]::Max($bt[0],$bt[1]) -gt $threshold) { $up+=$target.Name }
        if ([math]::Min($bt[0],$bt[1])-[math]::Max($at[0],$at[1]) -gt $threshold) { $down+=$target.Name }
    }
    $reasons=@()
    if ($availability.Count) { $reasons+='availability-changed' }
    if ($up.Count -ge 3 -or $down.Count -ge 3) { $reasons+='latency-shift' }
    if ($matched -lt 3) { $reasons+='insufficient-control' }
    $status=if ($availability.Count -or $up.Count -ge 3 -or $down.Count -ge 3) { 'Changed' } elseif ($matched -lt 3) { 'Unknown' } else { 'Stable' }
    return [pscustomobject]@{Schema=1;Status=$status;CanApply=($status -eq 'Stable');MatchedTargets=$matched;AvailabilityChanged=@($availability);ShiftedUp=@($up);ShiftedDown=@($down);UncertainTargets=@($uncertain);Reasons=@($reasons)}
}
function Write-ProbeJournal([string]$Path,[hashtable]$Metadata,$Rows,[ValidateRange(1,2)][int]$Attempt,[long]$MaxBytes=67108864) {
    if (-not @($Rows).Count) { return }
    $Metadata.Sequence=1+[int]$Metadata['Sequence']
    $lines=New-Object Text.StringBuilder
    $captured=[datetime]::UtcNow.ToString('o')
    foreach ($row in $Rows) {
        $entry=[ordered]@{Schema=1;RunId=$Metadata['RunId'];Seed=$Metadata['Seed'];Sequence=$Metadata.Sequence;Round=$Metadata['Round'];Stage=$Metadata['Stage'];StrategyId=$Metadata['StrategyId'];StrategyHash=$Metadata['StrategyHash'];CapturedNetworkKey=$Metadata['NetworkKey'];CapturedInputsHash=$Metadata['InputsHash'];Attempt=$Attempt;CapturedUtc=$captured
            Group=(Get-ProbeField $row 'Group');Name=(Get-ProbeField $row 'Name');TargetKey=(Get-ProbeKey $row);State=(Get-ProbeField $row 'State');Code=(Get-ProbeField $row 'Code');Exit=(Get-ProbeMetric $row 'Exit');Up=(Get-ProbeMetric $row 'Up');Down=(Get-ProbeMetric $row 'Down')
            ConnMs=(Get-ProbeMetric $row 'ConnMs');TlsMs=(Get-ProbeMetric $row 'TlsMs');DnsMs=(Get-ProbeMetric $row 'DnsMs');FirstByteMs=(Get-ProbeMetric $row 'FirstByteMs');TotalMs=(Get-ProbeMetric $row 'TotalMs');StartedUtc=(Get-ProbeField $row 'StartedUtc');ObservedUtc=(Get-ProbeField $row 'ObservedUtc');ControlUncontaminated=$Metadata['ControlUncontaminated']
            BodyBytes=(Get-ProbeMetric $row 'BodyBytes');BodyLimit=(Get-ProbeMetric $row 'BodyLimit');TargetReached=(Get-ProbeField $row 'TargetReached');BodyComplete=(Get-ProbeField $row 'BodyComplete');Termination=(Get-ProbeField $row 'Termination')
            StartedMs=(Get-ProbeMetric $row 'StartedMs');ObservedMs=(Get-ProbeMetric $row 'ObservedMs');ComparisonSlot=$Metadata['ComparisonSlot'];ComparisonBlock=$Metadata['ComparisonBlock'];ComparisonKind=$Metadata['ComparisonKind'];ComparisonArm=$Metadata['ComparisonArm']}
        [void]$lines.AppendLine(($entry | ConvertTo-Json -Compress))
    }
    $text=$lines.ToString()
    $size=if (Test-Path -LiteralPath $Path) { (Get-Item -LiteralPath $Path -ErrorAction Stop).Length } else { 0 }
    if ($MaxBytes -le 0 -or $size+[Text.Encoding]::UTF8.GetByteCount($text) -gt $MaxBytes) { throw 'Лимит журнала измерений превышен; результаты не применены.' }
    [IO.File]::AppendAllText($Path,$text,(New-Object Text.UTF8Encoding($false)))
}
