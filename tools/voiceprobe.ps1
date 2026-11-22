# Discord voice evidence. Importing this module starts no capture or network probes.
function Initialize-VoiceProbeRuntime {
    if('ZapretVoice.Probe' -as [type]){return}
    $file=Join-Path $PSScriptRoot 'voiceprobe.cs';$source=[IO.File]::ReadAllText($file);$hash=(Get-FileHash -LiteralPath $file -Algorithm SHA256 -ErrorAction Stop).Hash
    Add-Type -Language CSharp -TypeDefinition $source.Replace('__SOURCE_HASH__',$hash) -ErrorAction Stop
}
function Convert-DiscordVoiceEvent($Event,$Identities,[hashtable]$Local) {
    try {
        if($Event.Id -notin @(42,43,58,59) -or $Event.Properties.Count -lt 6 -or $null -eq $Event.TimeCreated){return $null}
        $owner=[int]$Event.Properties[0].Value;$time=([datetime]$Event.TimeCreated).ToUniversalTime();$size=[long]$Event.Properties[1].Value
        $matched=@($Identities|Where-Object{$_.Id -eq $owner -and $_.Name -in @('Discord','DiscordCanary','DiscordPTB') -and $time -ge ([datetime]$_.StartedUtc).ToUniversalTime() -and $time -le ([datetime]$_.ObservedUntilUtc).ToUniversalTime()})
        if(-not $matched.Count -or $size -lt 0 -or $size -gt 65535){return $null}
        $destination=Convert-EtwAddr $Event.Properties[2].Value;$source=Convert-EtwAddr $Event.Properties[3].Value
        $dip=$null;$sip=$null
        if(-not [Net.IPAddress]::TryParse($destination,[ref]$dip) -or -not [Net.IPAddress]::TryParse($source,[ref]$sip)){return $null}
        $destination=$dip.ToString() -replace '%.*$','';$source=$sip.ToString() -replace '%.*$',''
        $dp=[int]$Event.Properties[4].Value;$sp=[int]$Event.Properties[5].Value
        if($dp -lt 0 -or $dp -gt 65535 -or $sp -lt 0 -or $sp -gt 65535){return $null}
        if($Event.Id -in @(42,58) -and $Local.ContainsKey($source) -and -not $Local.ContainsKey($destination)){$address=$destination;$port=Swap16 $dp;$localAddress=$source;$localPort=Swap16 $sp;$direction='Out'}
        elseif($Event.Id -in @(43,59) -and $Local.ContainsKey($destination) -and -not $Local.ContainsKey($source)){$address=$source;$port=Swap16 $sp;$localAddress=$destination;$localPort=Swap16 $dp;$direction='In'}
        else{return $null}
        if($port -lt 1 -or $localPort -lt 1){return $null}
        return [pscustomobject]@{ProcessId=$owner;ProcessName=$matched[0].Name;ProcessStartedUtc=([datetime]$matched[0].StartedUtc).ToUniversalTime().ToString('o');Address=$address;Port=$port;LocalAddress=$localAddress;LocalPort=$localPort;Direction=$direction;Bytes=$size;ObservedUtc=$time.ToString('o')}
    }catch{return $null}
}
function Get-DiscordVoiceFlows($Events) {
    $flows=[ordered]@{}
    foreach($event in $Events){
        $key=@($event.ProcessId,$event.ProcessStartedUtc,$event.Address,$event.Port,$event.LocalAddress,$event.LocalPort) -join '|'
        if(-not $flows.Contains($key)){
            if($flows.Count -ge 128){continue}
            $configured=($event.Port -ge 19294 -and $event.Port -le 19344) -or ($event.Port -ge 50000 -and $event.Port -le 50100)
            $flows[$key]=[pscustomobject]@{ProcessId=$event.ProcessId;ProcessName=$event.ProcessName;ProcessStartedUtc=$event.ProcessStartedUtc;Address=$event.Address;Port=$event.Port;LocalAddress=$event.LocalAddress;LocalPort=$event.LocalPort;Out=0;In=0;BytesOut=0L;BytesIn=0L;FirstUtc=$event.ObservedUtc;LastUtc=$event.ObservedUtc;VoicePortConfigured=$configured;ProfileHit='NotObserved'}
        }
        $flow=$flows[$key]
        if($event.Direction -eq 'Out'){$flow.Out++;$flow.BytesOut+=$event.Bytes}else{$flow.In++;$flow.BytesIn+=$event.Bytes}
        if($event.ObservedUtc -lt $flow.FirstUtc){$flow.FirstUtc=$event.ObservedUtc};if($event.ObservedUtc -gt $flow.LastUtc){$flow.LastUtc=$event.ObservedUtc}
    }
    return @($flows.Values)
}
function Get-DiscordVoiceAssessment($Capture,$Control,[ValidateSet('Unknown','Both','OnlyReceive','OnlySend','None')][string]$Audio,[string]$Context) {
    $traffic='CaptureUnknown'
    if($Capture.Status -eq 'Completed' -and -not $Capture.Truncated){
        if(@($Capture.Flows|Where-Object{$_.Out -gt 0 -and $_.In -gt 0}).Count){$traffic='BidirectionalUdpObserved'}
        elseif(@($Capture.Flows|Where-Object{$_.Out -gt 0}).Count -and @($Capture.Flows|Where-Object{$_.In -gt 0}).Count){$traffic='SeparateDirectionsObserved'}
        elseif(@($Capture.Flows|Where-Object{$_.Out -gt 0}).Count){$traffic='OutboundOnly'}
        elseif(@($Capture.Flows|Where-Object{$_.In -gt 0}).Count){$traffic='InboundOnly'}else{$traffic='NoUdpObserved'}
    }
    $controlState=if(@($Control|Where-Object{$_.ResponseValidated}).Count){'StunResponseObserved'}elseif(@($Control).Count){'NoResponseObserved'}else{'Unknown'}
    $audioState=if($Audio -eq 'Both'){'UserReportedBoth'}elseif($Audio -eq 'Unknown'){'NotProvided'}else{'UserReportedIssue'}
    $outcome=if($Context -eq 'Changed'){'ContextChanged'}elseif($Audio -eq 'Both'){'UserReportedBoth'}elseif($Audio -ne 'Unknown'){'UserReportedIssue'}elseif($traffic -eq 'BidirectionalUdpObserved' -or $controlState -eq 'StunResponseObserved'){'NeedsAudioCheck'}else{'InsufficientEvidence'}
    return [pscustomobject]@{Traffic=$traffic;Control=$controlState;Audio=$audioState;Outcome=$outcome;Cause='NotEstablished';ProfileHit='NotObserved'}
}
function Get-DiscordVoiceProcesses {
    $observed=[datetime]::UtcNow
    foreach($process in @(Get-Process -Name Discord,DiscordCanary,DiscordPTB -ErrorAction SilentlyContinue)){
        try{$started=$process.StartTime.ToUniversalTime();if($started -le $observed){[pscustomobject]@{Id=[int]$process.Id;Name=$process.ProcessName;StartedUtc=$started;ObservedUtc=$observed}}}catch{}finally{$process.Dispose()}
    }
}
function Get-DiscordVoiceLocalAddresses {
    $local=@{};foreach($address in @(Get-NetIPAddress -ErrorAction SilentlyContinue)){$ip=$null;if([Net.IPAddress]::TryParse($address.IPAddress,[ref]$ip)){$local[($ip.ToString() -replace '%.*$','')]=$true}}
    return $local
}
function Start-DiscordVoiceTrace([string]$Session,[string]$Path) {
    $arguments=@('start',$Session,'-p','Microsoft-Windows-Kernel-Network','0xffffffffffffffff','0xff','-o',$Path,'-f','bincirc','-bs','64','-nb','2','16','-max','32','-ets')
    $native=Invoke-Native 'logman.exe' (ConvertTo-WinCmdLine $arguments) $Script:Runtime 8
    return [pscustomobject]@{Ok=($native.ExitCode -eq 0 -and -not $native.TimedOut);Error=$native.Output}
}
function Stop-DiscordVoiceTrace([string]$Session) {
    $native=Invoke-Native 'logman.exe' (ConvertTo-WinCmdLine @('stop',$Session,'-ets')) $Script:Runtime 8
    return [pscustomobject]@{Ok=($native.ExitCode -eq 0 -and -not $native.TimedOut);Error=$native.Output}
}
function Get-DiscordVoiceTraceState([string]$Session) {
    Initialize-VoiceProbeRuntime
    return [ZapretVoice.TraceSession]::Query($Session)
}
function Close-DiscordVoiceTrace([string]$Session,[string]$Path) {
    if($Session -notmatch '^zapretVoice-[a-f0-9]{32}$'){throw 'Некорректное имя собственного сеанса ETW.'}
    $errorText='';$lost=0L
    for($attempt=0;$attempt -lt 3;$attempt++){
        try{
            $state=Get-DiscordVoiceTraceState $Session;$lost=[math]::Max($lost,[long]$state.EventsLost)
            if($state.Known -and -not $state.Exists){return [pscustomobject]@{Ok=$true;Error='';EventsLost=$lost}}
            if($state.Known -and $state.Exists -and [IO.Path]::GetFullPath($state.LogPath) -ine [IO.Path]::GetFullPath($Path)){return [pscustomobject]@{Ok=$false;Error='Имя сеанса указывает на другой журнал; остановка запрещена.';EventsLost=$lost}}
            $stop=Stop-DiscordVoiceTrace $Session
            $state=Get-DiscordVoiceTraceState $Session;$lost=[math]::Max($lost,[long]$state.EventsLost)
            if($state.Known -and -not $state.Exists){return [pscustomobject]@{Ok=$true;Error='';EventsLost=$lost}}
            $errorText=if($stop.Error){$stop.Error}elseif($state.Error){$state.Error}else{'Сеанс ETW ещё активен.'}
        }catch{$errorText=$_.Exception.Message}
        if($attempt -lt 2){Start-Sleep -Milliseconds 100}
    }
    return [pscustomobject]@{Ok=$false;Error=$errorText;EventsLost=$lost}
}
function Start-DiscordVoiceGuard([string]$Session,[string]$Path,[int]$DurationSec) {
    $process=$null;$self=[Diagnostics.Process]::GetCurrentProcess()
    $guard=[pscustomobject]@{Process=$null;SignalBase=($Path+'.guard')}
    $arguments=@('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',(Join-Path $PSScriptRoot 'voiceguard.ps1'),'-Session',$Session,'-TracePath',$Path,'-ParentId',[string]$PID,'-ParentStartedTicks',[string]$self.StartTime.ToUniversalTime().Ticks,'-MaxSeconds',[string]($DurationSec+12))
    try{
        $info=New-Object Diagnostics.ProcessStartInfo
        $info.FileName=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe';$info.Arguments=ConvertTo-WinCmdLine $arguments;$info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.WindowStyle='Hidden'
        $process=[Diagnostics.Process]::Start($info);$guard.Process=$process
        $timer=[Diagnostics.Stopwatch]::StartNew()
        while(-not [IO.File]::Exists(($guard.SignalBase+'.ready')) -and -not $process.HasExited -and $timer.ElapsedMilliseconds -lt 10000){Start-Sleep -Milliseconds 20}
        if(-not [IO.File]::Exists(($guard.SignalBase+'.ready'))){throw 'Не удалось подготовить независимое ограничение сеанса ETW.'}
        return $guard
    }finally{
        $self.Dispose()
        if($process -and -not [IO.File]::Exists(($guard.SignalBase+'.ready'))){[IO.File]::WriteAllText(($guard.SignalBase+'.stop'),'');$process.Dispose()}
    }
}
function Complete-DiscordVoiceGuard($Guard) {
    try{
        [IO.File]::WriteAllText(($Guard.SignalBase+'.stop'),'')
        if(-not $Guard.Process.WaitForExit(5000)){return [pscustomobject]@{Ok=$false;Error='Независимая очистка ETW ещё выполняется.'}}
        $done=$Guard.SignalBase+'.done'
        if(-not [IO.File]::Exists($done)){return [pscustomobject]@{Ok=$false;Error='Нет подтверждения независимой очистки ETW.'}}
        try{return ([IO.File]::ReadAllText($done)|ConvertFrom-Json)}finally{[IO.File]::Delete($done)}
    }finally{$Guard.Process.Dispose()}
}
function Read-DiscordVoiceTrace([string]$Path,$Identities,[hashtable]$Local) {
    $result=[pscustomobject]@{Events=@();Truncated=$false;Error=''}
    try {
        if(-not [IO.File]::Exists($Path)){throw 'Нет файла журнала ETW.'}
        $allIds=@($Identities|ForEach-Object{[int]$_.Id}|Select-Object -Unique)
        $ids=@($allIds|Select-Object -First 64)
        $result.Truncated=$allIds.Count -gt 64
        if(-not $ids.Count){return $result}
        $pidFilter=(@($ids|ForEach-Object{"Data[@Name='PID']="+$_}) -join ' or ')
        $query="*[System[(EventID=42 or EventID=43 or EventID=58 or EventID=59)] and EventData[$pidFilter]]"
        $events=@()
        try{$events=@(Get-WinEvent -Path $Path -Oldest -FilterXPath $query -MaxEvents 20001 -ErrorAction Stop)}catch{if($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound'){throw}}
        $result.Truncated=$result.Truncated -or $events.Count -gt 20000 -or (Get-Item -LiteralPath $Path).Length -ge 32MB
        foreach($event in @($events|Select-Object -First 20000)){
            $decoded=Convert-DiscordVoiceEvent $event $Identities $Local
            if($null -ne $decoded){$result.Events+=@($decoded)}else{$result.Truncated=$true}
        }
        if(@($result.Events|ForEach-Object{@($_.ProcessId,$_.ProcessStartedUtc,$_.Address,$_.Port,$_.LocalAddress,$_.LocalPort) -join '|'}|Select-Object -Unique).Count -gt 128){$result.Truncated=$true}
    }catch{$result.Error=$_.Exception.Message}
    return $result
}
function Invoke-VoiceStunControl([string]$HostName,[int]$Port,$Observations=$null,$DnsObservation=$null) {
    $hostText=if($HostName.Contains(':')){'['+$HostName.Trim('[',']')+']'}else{$HostName}
    $uri=$null
    if(-not [Uri]::TryCreate(('https://'+$hostText+'/'),[UriKind]::Absolute,[ref]$uri) -or $uri.UserInfo -or $uri.AbsolutePath -ne '/' -or $uri.Query -or $uri.Fragment){throw 'Некорректное имя контрольного STUN-сервера.'}
    $target=[pscustomobject]@{Url=$uri.AbsoluteUri}
    $dns=Resolve-ConnectionTarget $target ([Diagnostics.Stopwatch]::GetTimestamp()+[long](2*[Diagnostics.Stopwatch]::Frequency)) $DnsObservation
    if($dns.State -ne 'OK'){return [pscustomobject]@{State='UNKNOWN';Reason=('Dns'+$dns.Reason);ResponseValidated=$false;Address='';Port=$Port;ElapsedMs=$dns.ElapsedMs;Error=$dns.Error}}
    $address=@(Select-ConnectionAddresses $dns.Addresses|Select-Object -First 1)[0]
    for($attempt=1;$attempt -le 2;$attempt++){
        $probe=$null;$completed=$null
        $row=[pscustomobject]@{Attempt=$attempt;State='UNKNOWN';Reason='Cancelled';ResponseValidated=$false;Address=$address;Port=$Port;ElapsedMs=0;Error=''}
        if($null -ne $Observations){$Observations.Add($row)}
        try{$probe=New-Object ZapretVoice.Probe($address,$Port,1200);$completed=$probe.Completion.GetAwaiter().GetResult()}
        catch{$row.Reason='ControllerError';$row.Error=$_.Exception.Message}
        finally{
            if($probe){
                try{if($null -eq $completed){$probe.Cancel();if($probe.Completion.Wait(500)){$completed=$probe.Completion.Result}}}finally{$probe.Dispose()}
            }
            if($null -ne $completed){foreach($property in $completed.PSObject.Properties){$row|Add-Member -NotePropertyName $property.Name -NotePropertyValue $property.Value -Force}}
        }
        $row
    }
}
function Format-DiscordVoiceReport($Result) {
    $captureText=switch($Result.Capture.Status){'Completed'{'завершён'};'Running'{'идёт наблюдение'};'Interrupted'{'прерван'};'Failed'{'ошибка наблюдения'};default{'недоступен'}}
    $reasonText=switch($Result.Capture.Reason){'AdministratorRequired'{'нужен запуск от администратора'};'DiscordNotRunning'{'Discord не запущен'};'ControlOnly'{'выбран только контрольный STUN'};'ObservedWindow'{'выполнено заданное окно'};'Cancelled'{'отмена'};'StopFailed'{'не удалось подтвердить остановку собственного ETW-сеанса'};'QueryFailed'{'не удалось прочитать события'};'CaptureError'{'сбой при наблюдении'};default{'наблюдение не начато'}}
    $trafficText=switch($Result.Assessment.Traffic){'BidirectionalUdpObserved'{'наблюдались пакеты в обе стороны одного потока'};'SeparateDirectionsObserved'{'наблюдались отправка и приём в разных потоках; двусторонность одного потока не подтверждена'};'OutboundOnly'{'наблюдались только исходящие пакеты'};'InboundOnly'{'наблюдались только входящие пакеты'};'NoUdpObserved'{'в окне наблюдения события не найдены'};default{'недостаточно данных'}}
    $controlText=switch($Result.Assessment.Control){'StunResponseObserved'{'получен проверенный ответ'};'NoResponseObserved'{'проверенный ответ не получен'};default{'недостаточно данных'}}
    $audioText=switch($Result.AudioObservation){'Both'{'пользователь подтвердил звук в обе стороны'};'OnlyReceive'{'пользователь слышал собеседника, обратного звука не было'};'OnlySend'{'собеседник слышал пользователя, обратного звука не было'};'None'{'пользователь сообщил об отсутствии звука в обе стороны'};default{'пользователь не проверял'}}
    $contextText=switch($Result.ConnectionState){'ObservedStable'{'наблюдаемых изменений нет'};'Changed'{'изменился во время проверки'};default{'не определён'}}
    'zapret — диагностика Discord Voice'
    $(if($Result.Completion -eq 'Completed'){'Наблюдение завершено.'}else{'Наблюдение прервано. Данные неполные.'})
    'Захват — '+$captureText+', '+$reasonText
    'UDP Discord — '+$trafficText
    'Контрольный STUN — '+$controlText
    'Двусторонний звук — '+$audioText
    'Контекст подключения — '+$contextText
    'Показаны наблюдаемые события ETW. Их количество не является измерением потерь UDP или качества голоса.'
    'Контрольный STUN использует отдельный сокет. Его ответ не подтверждает голосовой путь Discord.'
    foreach($flow in $Result.Capture.Flows){
        $flow.ProcessName+' PID '+$flow.ProcessId+', UDP '+$flow.Address+':'+$flow.Port+', локальный порт '+$flow.LocalPort+', исходящих '+$flow.Out+', входящих '+$flow.In
        '  Порт соответствует настройке голосового профиля — '+$(if($flow.VoicePortConfigured){'да'}else{'нет'})+'. Фактическое срабатывание профиля — не наблюдалось.'
    }
    if($Result.Capture.Error){'Ошибка наблюдения — '+($Result.Capture.Error -replace '[\r\n]+',' ')}
    if($Result.Capture.Truncated){'Окно ETW неполное или достигнут предел. Отсутствие событий не доказывает отсутствие трафика.'}
    foreach($row in $Result.Control){'STUN '+$row.Address+':'+$row.Port+' — '+$row.Reason+', '+([math]::Round($row.ElapsedMs,1))+' мс'}
    'Причина возможного сбоя не установлена автоматически. Двусторонний звук подтверждается отдельно пользователем.'
    'JSON '+$Result.JsonFile
}
function Save-DiscordVoiceReport($Result) {
    $json=(ConvertTo-Json -InputObject $Result -Depth 12)+"`r`n"
    Write-TextNoBom $Result.JsonFile $json
    Write-TextNoBom $Result.TextFile ((@(Format-DiscordVoiceReport $Result) -join "`r`n")+"`r`n")
    $last=Join-Path $Script:Runtime 'voice-check-last.json';$temporary=$last+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
    try{Write-TextNoBom $temporary $json;if([IO.File]::Exists($last)){[IO.File]::Replace($temporary,$last,[NullString]::Value)}else{try{[IO.File]::Move($temporary,$last)}catch [IO.IOException]{if(-not [IO.File]::Exists($last)){throw};[IO.File]::Replace($temporary,$last,[NullString]::Value)}}}finally{if([IO.File]::Exists($temporary)){[IO.File]::Delete($temporary)}}
}
function Invoke-DiscordVoiceDiagnostic([ValidateRange(1,120)][int]$DurationSec=30,[string]$StunHost='stun.cloudflare.com',[ValidateRange(1,65535)][int]$StunPort=3478,[ValidateSet('Unknown','Both','OnlyReceive','OnlySend','None')][string]$Audio='Unknown',[switch]$ControlOnly,[switch]$Quiet) {
    Initialize-WebProbeRuntime;Initialize-VoiceProbeRuntime
    [void][IO.Directory]::CreateDirectory($Script:Runtime)
    $runId=(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N')
    $capture=[pscustomobject]@{Status='Unavailable';Reason='NotStarted';Error='';Truncated=$false;Identities=@();Flows=@();Session=('zapretVoice-'+[guid]::NewGuid().ToString('N'));TracePath=(Join-Path $Script:Runtime ('voice-'+$runId+'.etl'));DurationSec=$DurationSec;Coverage='EtwObservedEvents'}
    $result=[pscustomobject]@{Schema=1;Kind='DiscordVoice';RunId=$runId;CaptureRunId=$runId;StartedUtc=[datetime]::UtcNow.ToString('o');FinishedUtc='';Completion='Interrupted';AudioObservation=$Audio;AudioReportedUtc=$(if($Audio -eq 'Unknown'){''}else{[datetime]::UtcNow.ToString('o')});SourceHash=[ZapretVoice.Probe]::SourceHash;ContextBefore=(Get-WebVerificationContext);ContextAfter=$null;ConnectionState='Unknown';Capture=$capture;Control=@();Assessment=$null;JsonFile=(Join-Path $Script:Runtime ('voice-check-'+$runId+'.json'));TextFile=(Join-Path $Script:Runtime ('voice-check-'+$runId+'.txt'))}
    $result.Control=New-Object 'Collections.Generic.List[object]'
    $result|Add-Member -NotePropertyName ControlDns -NotePropertyValue (New-ConnectionDnsObservation)
    $attempted=$false;$traceStarted=$false;$stopped=$false;$guard=$null;$identities=[ordered]@{}
    try {
        if(-not $Quiet){Write-Color 'Проверка контрольного UDP/STUN...' Cyan}
        $result.Control=@(Invoke-VoiceStunControl $StunHost $StunPort $result.Control $result.ControlDns)
        $processes=@(Get-DiscordVoiceProcesses)
        if($ControlOnly){$capture.Reason='ControlOnly'}
        elseif(-not (Test-Admin)){$capture.Reason='AdministratorRequired'}
        elseif(-not $processes.Count){$capture.Reason='DiscordNotRunning'}
        else {
            $local=Get-DiscordVoiceLocalAddresses
            $guard=Start-DiscordVoiceGuard $capture.Session $capture.TracePath $DurationSec
            $attempted=$true
            $started=Start-DiscordVoiceTrace $capture.Session $capture.TracePath
            if(-not $started.Ok){throw ('ETW start: '+$started.Error)}
            $traceStarted=$true;$capture.Status='Running';$capture.Reason='Observing'
            $processes=@(Get-DiscordVoiceProcesses)
            if(-not $Quiet){Write-Color ('Наблюдаю UDP Discord '+$DurationSec+' сек. Говорите и слушайте собеседника.') Cyan}
            $timer=[Diagnostics.Stopwatch]::StartNew();$lastProgress=0
            do {
                foreach($process in $processes){
                    $key=[string]$process.Id+'|'+([datetime]$process.StartedUtc).Ticks
                    if(-not $identities.Contains($key)){
                        if($identities.Count -ge 128){$capture.Truncated=$true;continue}
                        $identities[$key]=[pscustomobject]@{Id=$process.Id;Name=$process.Name;StartedUtc=$process.StartedUtc;ObservedUntilUtc=$process.ObservedUtc}
                    }else{$identities[$key].ObservedUntilUtc=$process.ObservedUtc}
                }
                if(-not $Quiet -and $timer.Elapsed.TotalSeconds-$lastProgress -ge 10){$lastProgress=[int]$timer.Elapsed.TotalSeconds;Write-Color ('Наблюдение '+$lastProgress+'/'+$DurationSec+' сек.') Gray}
                Start-Sleep -Milliseconds ([int][math]::Min(200,[math]::Max(1,$DurationSec*1000-$timer.ElapsedMilliseconds)))
                $processes=@(Get-DiscordVoiceProcesses)
            }while($timer.Elapsed.TotalSeconds -lt $DurationSec)
            foreach($process in $processes){$key=[string]$process.Id+'|'+([datetime]$process.StartedUtc).Ticks;if($identities.Contains($key)){$identities[$key].ObservedUntilUtc=$process.ObservedUtc}}
            $capture.Status='Completed';$capture.Reason='ObservedWindow'
        }
        $result.Completion='Completed'
    }catch{$capture.Status='Failed';$capture.Reason='CaptureError';$capture.Error=$_.Exception.Message}
    finally {
        if($attempted){
            try{$stop=Close-DiscordVoiceTrace $capture.Session $capture.TracePath;$stopped=$stop.Ok;if($stop.EventsLost -gt 0){$capture.Truncated=$true};if(-not $stop.Ok){$capture.Status='Failed';$capture.Reason='StopFailed';$capture.Error=$stop.Error}}catch{$capture.Status='Failed';$capture.Reason='StopFailed';$capture.Error=$_.Exception.Message}
        }
        if($capture.Status -eq 'Running'){$capture.Status='Interrupted';$capture.Reason='Cancelled'}
        $capture.Identities=@($identities.Values)
        if($traceStarted -and $stopped){
            $decoded=Read-DiscordVoiceTrace $capture.TracePath $capture.Identities $local
            $capture.Flows=@(Get-DiscordVoiceFlows $decoded.Events);$capture.Truncated=$capture.Truncated -or $decoded.Truncated
            if($decoded.Error){$capture.Status='Failed';$capture.Reason='QueryFailed';$capture.Error=$decoded.Error}
        }
        if($stopped -and [IO.File]::Exists($capture.TracePath)){[IO.File]::Delete($capture.TracePath)}
        if($guard){
            try{$cleanup=Complete-DiscordVoiceGuard $guard;if(-not $cleanup.Ok){$capture.Status='Failed';$capture.Reason='StopFailed';$capture.Error=$cleanup.Error}}catch{$capture.Status='Failed';$capture.Reason='StopFailed';$capture.Error=$_.Exception.Message}
        }
        if($result.Control -is [Collections.Generic.List[object]]){$result.Control=$result.Control.ToArray()}
        $result.ContextAfter=Get-WebVerificationContext
        if($result.ContextBefore.Known -and $result.ContextAfter.Known){$result.ConnectionState=if((Test-NetworkObservation $result.ContextBefore.Network $result.ContextAfter.Network) -and ($result.ContextBefore.Processes -join ',') -ceq ($result.ContextAfter.Processes -join ',') -and $result.ContextBefore.SettingsHash -ceq $result.ContextAfter.SettingsHash){'ObservedStable'}else{'Changed'}}
        $result.Assessment=Get-DiscordVoiceAssessment $capture $result.Control $Audio $result.ConnectionState;$result.FinishedUtc=[datetime]::UtcNow.ToString('o');Save-DiscordVoiceReport $result
    }
    if(-not $Quiet){foreach($line in @(Format-DiscordVoiceReport $result)){Write-Color $line Gray};Write-Color ('Отчёт '+$result.TextFile) Cyan}
    return $result
}
function New-DiscordVoiceAudioReport($CaptureReport,[ValidateSet('Both','OnlyReceive','OnlySend','None')][string]$Audio) {
    $report=$CaptureReport|ConvertTo-Json -Depth 12|ConvertFrom-Json
    $report.RunId=(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N');$report.CaptureRunId=$CaptureReport.CaptureRunId
    $report.JsonFile=Join-Path $Script:Runtime ('voice-check-'+$report.RunId+'.json');$report.TextFile=Join-Path $Script:Runtime ('voice-check-'+$report.RunId+'.txt')
    $report.AudioObservation=$Audio;$report.AudioReportedUtc=[datetime]::UtcNow.ToString('o');$report.Assessment=Get-DiscordVoiceAssessment $report.Capture $report.Control $Audio $report.ConnectionState
    Save-DiscordVoiceReport $report;return $report
}
