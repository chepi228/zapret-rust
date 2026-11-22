# Observational connection diagnostics. No network activity or settings writes on import.
function Select-ConnectionAddresses([string[]]$Addresses) {
    $v4=New-Object System.Collections.Generic.List[string];$v6=New-Object System.Collections.Generic.List[string];$seen=@{};$first=''
    foreach($text in $Addresses){
        $ip=$null;if(-not [Net.IPAddress]::TryParse($text,[ref]$ip)){continue}
        $canonical=$ip.ToString();if($seen.ContainsKey($canonical)){continue};$seen[$canonical]=$true
        $family=if($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork){'4'}elseif($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6){'6'}else{continue}
        if(-not $first){$first=$family}
        if($family -eq '4' -and $v4.Count -lt 2){$v4.Add($canonical)}elseif($family -eq '6' -and $v6.Count -lt 2){$v6.Add($canonical)}
    }
    for($i=0;$i -lt 2;$i++){foreach($family in $(if($first -eq '6'){@('6','4')}else{@('4','6')})){if($family -eq '4' -and $v4.Count -gt $i){$v4[$i]}elseif($family -eq '6' -and $v6.Count -gt $i){$v6[$i]}}}
}
function Get-ConnectionAssessment($DnsAttempts,[string[]]$Addresses,$Rows,[int]$Attempts=2) {
    $dns=@($DnsAttempts);$rows=@($Rows);$reachable=@($rows|Where-Object{$_.Address -in $Addresses -and $_.State -in @('OK','HTTP_ERROR') -and $_.Stage -eq 'Complete' -and $_.StatusCode -ge 200 -and $_.StatusCode -le 599 -and $_.HeadersComplete}).Count -gt 0
    $answer=[pscustomobject]@{Stage='Unknown';Reason='Unknown';Consistency='Unknown';ReachableHttp=$reachable;Observations=$rows.Count}
    if(-not @($dns|Where-Object{$_.State -eq 'OK'}).Count){
        $answer.Stage='Dns'
        if($dns.Count -ge 2 -and @($dns|Where-Object{$_.State -ne 'FAIL'}).Count -eq 0 -and @($dns.Reason|Select-Object -Unique).Count -eq 1){$answer.Consistency='Repeated';$answer.Reason=$dns[0].Reason}
        return $answer
    }
    $keys=@{};$valid=$Addresses.Count -gt 0 -and $rows.Count -eq $Addresses.Count*$Attempts
    foreach($row in $rows){
        $key=$row.Address+'|'+$row.Attempt
        if($Addresses -notcontains $row.Address -or $row.Attempt -lt 1 -or $row.Attempt -gt $Attempts -or $keys.ContainsKey($key) -or $row.State -notin @('OK','HTTP_ERROR','FAIL')){$valid=$false}
        if($row.State -in @('OK','HTTP_ERROR') -and ($row.Stage -ne 'Complete' -or $row.StatusCode -lt 200 -or $row.StatusCode -gt 599 -or -not $row.HeadersComplete)){$valid=$false}
        $keys[$key]=$true
    }
    if(-not $valid){$answer.Consistency='Incomplete';return $answer}
    if(@($rows|Where-Object{$_.State -notin @('OK','HTTP_ERROR')}).Count -eq 0){$answer.Stage='Complete';$answer.Reason='ReachedHttp';$answer.Consistency='Repeated'}
    elseif(@($rows|Where-Object{$_.State -ne 'FAIL'}).Count -eq 0 -and @($rows.Stage|Select-Object -Unique).Count -eq 1 -and @($rows.Reason|Select-Object -Unique).Count -eq 1){$answer.Stage=$rows[0].Stage;$answer.Reason=$rows[0].Reason;$answer.Consistency='Repeated'}
    else{$answer.Consistency='Mixed'}
    if(@($dns|Where-Object{$_.State -ne 'OK'}).Count){$answer.Consistency='Mixed';$answer.Stage='Unknown';$answer.Reason='DnsRecovered'}
    return $answer
}
function Initialize-ConnectionProbeRuntime {
    if('ZapretConnection.Probe' -as [type]){return}
    $path=Join-Path $PSScriptRoot 'connectionprobe.cs';$source=[IO.File]::ReadAllText($path);$hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash
    Add-Type -Language CSharp -TypeDefinition $source.Replace('__SOURCE_HASH__',$hash) -ErrorAction Stop
}
function Get-ConnectionDnsCommand([string]$HostName,[string]$OutputFile) {
    $hostData=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($HostName));$pathData=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($OutputFile))
    $prefix='$name=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('''+$hostData+'''))'+"`n"+'$output=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('''+$pathData+'''))'+"`n"
    $body=@'
$ErrorActionPreference='Stop'
try {
    $ips=@([Net.Dns]::GetHostAddresses($name)|Select-Object -First 64|ForEach-Object{$_.ToString()})
    $value=@{State='OK';Reason='Resolved';Addresses=$ips;Error=''}
}catch{$value=@{State='FAIL';Reason='ResolveFailed';Addresses=@();Error=$_.Exception.GetBaseException().Message}}
[IO.File]::WriteAllText(($output+'.tmp'),(ConvertTo-Json -InputObject $value -Compress),(New-Object Text.UTF8Encoding($false)))
[IO.File]::Move(($output+'.tmp'),$output)
'@
    return [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($prefix+$body))
}
function New-ConnectionDnsObservation {
    return [pscustomobject]@{State='UNKNOWN';Reason='Cancelled';Addresses=@();Error='';ElapsedMs=0;WorkerId=0;Resolver='Windows system resolver in owned process'}
}
function Resolve-ConnectionTarget($Target,[long]$DeadlineTicks,$Observation=$null) {
    $uri=[Uri]$Target.Url;$literal=$null;$clock=[Diagnostics.Stopwatch]::StartNew();$owner=$null
    $result=if($null -eq $Observation){New-ConnectionDnsObservation}else{$Observation}
    if([Net.IPAddress]::TryParse($uri.DnsSafeHost,[ref]$literal)){$result.State='OK';$result.Reason='AddressLiteral';$result.Addresses=@($literal.ToString());return $result}
    $file=Join-Path $Script:Runtime ('connection-dns-'+[guid]::NewGuid().ToString('N')+'.json')
    try {
        if([Diagnostics.Stopwatch]::GetTimestamp() -ge $DeadlineTicks){$result.Reason='Timeout';return $result}
        Initialize-WebProbeRuntime
        $command=Get-ConnectionDnsCommand $uri.DnsSafeHost $file
        $powershell=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
        $owner=[ZapretWeb.BrowserProcess]::Start($powershell,[string[]]@('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand',$command));$result.WorkerId=$owner.Id
        while(-not $owner.Exited){
            if([Diagnostics.Stopwatch]::GetTimestamp() -ge $DeadlineTicks){$result.Reason='Timeout';return $result}
            Start-Sleep -Milliseconds 20
        }
        if(-not [IO.File]::Exists($file) -or (Get-Item -LiteralPath $file).Length -gt 65536){throw 'DNS worker returned no bounded result.'}
        $decoded=[IO.File]::ReadAllText($file)|ConvertFrom-Json -ErrorAction Stop
        if($decoded.State -notin @('OK','FAIL') -or -not $decoded.PSObject.Properties['Addresses']){throw 'Invalid DNS worker result.'}
        $addresses=@();foreach($text in @($decoded.Addresses)){$ip=$null;if(-not [Net.IPAddress]::TryParse([string]$text,[ref]$ip)){throw 'Invalid resolver address.'};$addresses+=@($ip.ToString())}
        $result.State=$decoded.State;$result.Reason=$decoded.Reason;$result.Error=$decoded.Error;$result.Addresses=@($addresses|Select-Object -Unique)
        if($result.State -eq 'OK' -and -not $result.Addresses.Count){$result.State='FAIL';$result.Reason='NoAddresses'}
        return $result
    } catch {$result.Reason='ControllerError';$result.Error=$_.Exception.Message;return $result}
    finally {if($owner){$owner.Dispose()};foreach($path in @($file,($file+'.tmp'))){if([IO.File]::Exists($path)){[IO.File]::Delete($path)}};$result.ElapsedMs=[math]::Round($clock.Elapsed.TotalMilliseconds,1)}
}
function Start-ConnectionAddressProbe([Uri]$Uri,[string]$Address,[int]$TimeoutMs) {
    return [ZapretConnection.Probe]::Start($Uri.IdnHost,$Address,$Uri.Port,$Uri.PathAndQuery,$TimeoutMs)
}
function New-ConnectionUnknownRow([string]$Address,[int]$Attempt,[string]$Reason,[string]$State='UNKNOWN') {
    return [pscustomobject]@{Address=$Address;Family=$(if($Address.Contains(':')){'IPv6'}else{'IPv4'});Attempt=$Attempt;Stage='Unknown';State=$State;Reason=$Reason;StatusCode=0;Error='';ElapsedMs=0;TcpSucceeded=$false;TlsSucceeded=$false;HeadersComplete=$false;CertificateObserved=$false;CertificateErrors='NotObserved';TlsProtocol='';ReceivedBytes=0;HeaderBytes=0;Validation='System';RevocationCheck=$false;Evidence='Headers'}
}
function Format-ConnectionDiagnostic($Result) {
    'zapret — этапы подключения DNS → TCP → TLS → HTTP'
    'Проверено текущее подключение. Начало '+$Result.StartedUtc
    $(if($Result.Completion -eq 'Completed'){'Прогон завершён.'}else{'Прогон прерван. Сохранены полученные данные и незапущенные цели.'})
    'Клиент .NET/Schannel, HTTP/1.1 HEAD. Проверяются имя и цепочка доверия сертификата. Проверка отзыва не выполняется.'
    'Читаются только заголовки ответа, до 32768 байт. Перенаправления сохраняются как HTTP-ответ без перехода к другому адресу.'
    'Прокси приложения не используется. Системные маршруты и VPN/TUN влияют на подключение.'
    $context=switch($Result.ConnectionState){'ObservedStable'{'сохранены'};'Changed'{'изменились во время проверки'};default{'не установлены'}}
    'Наблюдаемые параметры подключения — '+$context
    'Контрольный сайт — '+$(if($Result.ControlState -eq 'ReachedHttp'){'HTTP-доступ подтверждён'}else{'HTTP-доступ не подтверждён'})
    foreach($target in $Result.Targets){
        '';($target.Group+'.'+$target.Name+' — '+$target.Url)
        'Выполнение — '+$(switch($target.Execution){'Completed'{'завершено'};'Interrupted'{'прервано'};default{'не запускалось'}})
        foreach($dns in $target.DnsAttempts){'DNS — '+$dns.State+', '+$dns.Reason+', '+$dns.ElapsedMs+' мс. Адреса '+(@($dns.Addresses) -join ', ');if($dns.Error){'  '+($dns.Error -replace '[\r\n]+',' ')}}
        $assessment=$target.Assessment
        $consistency=switch($assessment.Consistency){'Repeated'{'повторное наблюдение'};'Mixed'{'результаты расходятся'};'Incomplete'{'проверка неполная'};default{'данных недостаточно'}}
        'Итог — '+$consistency+'. Этап '+$assessment.Stage+', сигнал '+$assessment.Reason
        foreach($row in $target.Rows){
            $reason=switch($row.Reason){'Certificate'{'ошибка сертификата'};'Timeout'{'истекло время ожидания'};'Cancelled'{'проба прервана'};'BudgetExhausted'{'бюджет времени исчерпан'};'ControllerError'{'пробу не удалось выполнить'};'ConnectionRefused'{'подключение отклонено'};'HeaderLimit'{'превышен лимит заголовков'};'TruncatedHeaders'{'заголовки получены не полностью'};'MalformedHttp'{'некорректный HTTP-ответ'};'HttpStatus'{'HTTP-ошибка сайта'};'Completed'{'HTTP-ответ получен'};default{$row.Reason}}
            $row.Address+' '+$row.Family+', попытка '+$row.Attempt+' — '+$row.Stage+', '+$reason+', HTTP '+$row.StatusCode+', '+([math]::Round($row.ElapsedMs,1))+' мс'
            if($row.Error){'  '+($row.Error -replace '[\r\n]+',' ')}
        }
    }
    ''
    'Эти наблюдения не устанавливают блокировку провайдером. Доступность HTTP-заголовков не измеряет видео, голос или игровой пинг.'
    'JSON '+$Result.JsonFile
}
function Save-ConnectionDiagnostic($Result) {
    $json=(ConvertTo-Json -InputObject $Result -Depth 12)+"`r`n"
    Write-TextNoBom $Result.JsonFile $json
    Write-TextNoBom $Result.TextFile ((@(Format-ConnectionDiagnostic $Result) -join "`r`n")+"`r`n")
    $last=Join-Path $Script:Runtime 'connection-check-last.json';$temporary=$last+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
    try {
        Write-TextNoBom $temporary $json
        if([IO.File]::Exists($last)){[IO.File]::Replace($temporary,$last,[NullString]::Value)}else{
            try{[IO.File]::Move($temporary,$last)}catch [IO.IOException]{if(-not [IO.File]::Exists($last)){throw};[IO.File]::Replace($temporary,$last,[NullString]::Value)}
        }
    }finally{if([IO.File]::Exists($temporary)){[IO.File]::Delete($temporary)}}
}
function Invoke-ConnectionDiagnostic($Targets=$null,[ValidateRange(1,30)][int]$TimeoutSec=8,[switch]$Quiet) {
    if($null -eq $Targets){$Targets=@(Read-WebVerificationTargets)};$Targets=@($Targets)
    if($Targets.Count -lt 1 -or $Targets.Count -gt 6){throw 'Нужно от одного до шести HTTPS-адресов.'}
    foreach($target in $Targets){$url=Assert-WebProbeUrl $target.Url;if(([Uri]$url).Scheme -ne 'https'){throw 'Для проверки TLS нужен HTTPS-адрес.'}}
    Initialize-WebProbeRuntime;Initialize-ConnectionProbeRuntime
    [void][IO.Directory]::CreateDirectory($Script:Runtime)
    $runId=(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N')
    $result=[pscustomobject]@{Schema=1;Kind='ConnectionStages';RunId=$runId;StartedUtc=[datetime]::UtcNow.ToString('o');FinishedUtc='';Completion='Interrupted';RequestedTargets=$Targets.Count;Client='.NET SslStream/Schannel';SourceHash=[ZapretConnection.Probe]::SourceHash;Evidence='Headers';HeaderLimit=32768;ProxyMode='Direct';TimeoutSec=$TimeoutSec;Attempts=2;ContextBefore=(Get-WebVerificationContext);ContextAfter=$null;ConnectionState='Unknown';ControlState='Unknown';Targets=@();JsonFile=(Join-Path $Script:Runtime ('connection-check-'+$runId+'.json'));TextFile=(Join-Path $Script:Runtime ('connection-check-'+$runId+'.txt'))}
    foreach($target in $Targets){$result.Targets+=@([pscustomobject]@{Group=$target.Group;Name=$target.Name;Url=$target.Url;Execution='NOT_RUN';DnsAttempts=@();SelectedAddresses=@();Rows=@();Assessment=$null})}
    try {
        foreach($state in $result.Targets){
            $state.Execution='RUNNING'
            if(-not $Quiet){Write-Color ('Этапы подключения — '+$state.Group+'.'+$state.Name) Cyan}
            $deadline=[Diagnostics.Stopwatch]::GetTimestamp()+[long]($TimeoutSec*[Diagnostics.Stopwatch]::Frequency)
            for($attempt=1;$attempt -le 2;$attempt++){
                $dnsDeadline=[math]::Min($deadline,([Diagnostics.Stopwatch]::GetTimestamp()+[long](1.5*[Diagnostics.Stopwatch]::Frequency)))
                $observation=New-ConnectionDnsObservation;$state.DnsAttempts+=@($observation);$index=$state.DnsAttempts.Count-1
                $dns=Resolve-ConnectionTarget $state $dnsDeadline $observation;$state.DnsAttempts[$index]=$dns
                if($dns.State -eq 'OK'){$state.SelectedAddresses=@(Select-ConnectionAddresses $dns.Addresses);break}
                if([Diagnostics.Stopwatch]::GetTimestamp() -ge $deadline){break}
            }
            $uri=[Uri]$state.Url
            for($attempt=1;$attempt -le 2;$attempt++){
                $handles=New-Object System.Collections.Generic.List[object]
                try {
                    foreach($address in $state.SelectedAddresses){
                        $remaining=[math]::Floor(($deadline-[Diagnostics.Stopwatch]::GetTimestamp())*1000.0/[Diagnostics.Stopwatch]::Frequency)
                        if($remaining -le 0){$state.Rows+=@(New-ConnectionUnknownRow $address $attempt 'BudgetExhausted' 'NOT_RUN');continue}
                        try{$probe=Start-ConnectionAddressProbe $uri $address ([int][math]::Min(3000,$remaining));$handles.Add([pscustomobject]@{Probe=$probe;Address=$address;Attempt=$attempt})}
                        catch{$row=New-ConnectionUnknownRow $address $attempt 'ControllerError';$row.Error=$_.Exception.Message;$state.Rows+=@($row)}
                    }
                    while(@($handles|Where-Object{-not $_.Probe.Completion.IsCompleted}).Count){
                        if([Diagnostics.Stopwatch]::GetTimestamp() -ge $deadline){foreach($entry in $handles){if(-not $entry.Probe.Completion.IsCompleted){$entry.Probe.Expire()}}}
                        Start-Sleep -Milliseconds 20
                    }
                } finally {
                    foreach($entry in $handles){
                        try {
                            if(-not $entry.Probe.Completion.IsCompleted){$entry.Probe.Cancel()}
                            try{$row=$entry.Probe.Completion.GetAwaiter().GetResult();$row|Add-Member -NotePropertyName Attempt -NotePropertyValue $entry.Attempt -Force}
                            catch{$row=New-ConnectionUnknownRow $entry.Address $entry.Attempt 'ControllerError';$row.Error=$_.Exception.Message}
                            $state.Rows+=@($row)
                        }finally{$entry.Probe.Dispose()}
                    }
                }
            }
            $state.Assessment=Get-ConnectionAssessment $state.DnsAttempts $state.SelectedAddresses $state.Rows
            $state.Execution='Completed'
        }
        $result.Completion='Completed'
    } finally {
        foreach($state in $result.Targets){
            if($state.Execution -eq 'RUNNING'){$state.Execution='Interrupted'}
            foreach($address in $state.SelectedAddresses){for($attempt=1;$attempt -le 2;$attempt++){if(-not @($state.Rows|Where-Object{$_.Address -eq $address -and $_.Attempt -eq $attempt}).Count){$state.Rows+=@(New-ConnectionUnknownRow $address $attempt 'Cancelled')}}}
            $state.Assessment=Get-ConnectionAssessment $state.DnsAttempts $state.SelectedAddresses $state.Rows
            if($state.Execution -eq 'NOT_RUN'){$state.Assessment.Stage='Unknown';$state.Assessment.Reason='NotStarted';$state.Assessment.Consistency='Incomplete'}
        }
        $controls=@($result.Targets|Where-Object{$_.Group -eq 'Clean'})
        if($controls.Count -and @($controls|Where-Object{$_.Assessment.Stage -ne 'Complete' -or $_.Assessment.Consistency -ne 'Repeated'}).Count -eq 0){$result.ControlState='ReachedHttp'}
        $result.ContextAfter=Get-WebVerificationContext
        if($result.ContextBefore.Known -and $result.ContextAfter.Known){$result.ConnectionState=if((Test-NetworkObservation $result.ContextBefore.Network $result.ContextAfter.Network) -and ($result.ContextBefore.Processes -join ',') -ceq ($result.ContextAfter.Processes -join ',') -and $result.ContextBefore.SettingsHash -ceq $result.ContextAfter.SettingsHash){'ObservedStable'}else{'Changed'}}
        $result.FinishedUtc=[datetime]::UtcNow.ToString('o');Save-ConnectionDiagnostic $result
    }
    if(-not $Quiet){foreach($line in @(Format-ConnectionDiagnostic $result)){Write-Color $line Gray};Write-Color ('Отчёт '+$result.TextFile) Cyan}
    return $result
}
