# Real curl with bounded loopback bodies. No external traffic or driver.
param([string]$Pkg=(Split-Path -Parent (Split-Path -Parent $PSScriptRoot)))
if (Test-Path (Join-Path $Pkg '.git')) { throw 'Run on a package copy.' }
$ErrorActionPreference='Stop'
. (Join-Path $Pkg 'tools/lib.ps1')
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Pkg 'tools/test.ps1'),[ref]$null,[ref]$null)
foreach ($fn in $ast.FindAll({$args[0] -is [Management.Automation.Language.FunctionDefinitionAst]},$false)) { . ([scriptblock]::Create($fn.Extent.Text)) }
$fails=0;$Parallel=1;$TimeoutSec=2
function Check($Name,$Ok) { if ($Ok) { Write-Host ('ok '+$Name) } else { Write-Host ('FAIL '+$Name);$script:fails++ } }
foreach ($mode in @('large','chunked','short','post','exact','cancel','exactcancel')) {
    $ready=Join-Path $Script:Runtime ('curl-limit-'+[guid]::NewGuid().ToString('N'))
    $job=Start-Job -ArgumentList $ready,$mode -ScriptBlock {
        param($Ready,$Mode)
        $ErrorActionPreference='Stop';$client=$null
        $listener=New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback,0)
        try {
            $listener.Start();[IO.File]::WriteAllText(($Ready+'.tmp'),[string]$listener.LocalEndpoint.Port);[IO.File]::Move(($Ready+'.tmp'),$Ready)
            $pending=$listener.AcceptTcpClientAsync();if (-not $pending.Wait(10000)) { throw 'No loopback request' }
            $client=$pending.Result;$stream=$client.GetStream();$stream.ReadTimeout=4000;$stream.WriteTimeout=4000
            $reader=New-Object IO.StreamReader($stream,[Text.Encoding]::ASCII,$false,1024,$true)
            for ($i=0;$i -lt 100;$i++) { $line=$reader.ReadLine();if (-not $line) { break } }
            if ($Mode -eq 'post') {
                $interim=[Text.Encoding]::ASCII.GetBytes("HTTP/1.1 100 Continue`r`n`r`n");$stream.Write($interim,0,$interim.Length);$stream.Flush()
                $upload=New-Object char[] 65536;$received=$reader.ReadBlock($upload,0,$upload.Length)
                if ($received -ne 65536) { throw 'Fixture did not receive the complete POST' }
            }
            $chunked=$Mode -eq 'chunked';$length=if ($Mode -eq 'short') {128} else {2097152}
            $sizeHeader=if ($chunked) {'Transfer-Encoding: chunked'} else {'Content-Length: '+$length}
            $header=[Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`n"+$sizeHeader+"`r`nConnection: close`r`n`r`n")
            $stream.Write($header,0,$header.Length)
            $body=New-Object byte[] 8192
            if ($Mode -eq 'cancel') { $stream.Write($body,0,$body.Length);$stream.Flush();Start-Sleep -Seconds 5;return }
            if ($Mode -in @('exact','exactcancel')) { $sample=New-Object byte[] 65536;$stream.Write($sample,0,$sample.Length);$stream.Flush();Start-Sleep -Seconds 3;return }
            try {
                for ($sent=0;$sent -lt $length;$sent+=$count) {
                    $count=[math]::Min($body.Length,$length-$sent)
                    if ($chunked) { $prefix=[Text.Encoding]::ASCII.GetBytes($count.ToString('X')+"`r`n");$stream.Write($prefix,0,$prefix.Length) }
                    $stream.Write($body,0,$count)
                    if ($chunked) { $stream.WriteByte(13);$stream.WriteByte(10) }
                    $stream.Flush();Start-Sleep -Milliseconds 2
                }
                if ($chunked) { $end=[Text.Encoding]::ASCII.GetBytes("0`r`n`r`n");$stream.Write($end,0,$end.Length) }
            } catch [IO.IOException] { }
        } finally { if ($client) { $client.Dispose() };$listener.Stop() }
    }
    try {
        for ($i=0;$i -lt 100 -and -not (Test-Path $ready) -and $job.State -notin @('Completed','Failed','Stopped');$i++) { Start-Sleep -Milliseconds 50 }
        if (-not (Test-Path $ready)) { Receive-Job $job;throw 'Fixture did not start' }
        $target=[pscustomobject]@{Group='DPI';Name=$mode;Url=('http://127.0.0.1:'+([IO.File]::ReadAllText($ready))+'/');Post=($mode -eq 'post')}
        $postFile=$ready+'.post'
        if ($target.Post) { [IO.File]::WriteAllBytes($postFile,(New-Object byte[] 65536)) }
        if ($mode -in @('cancel','exactcancel')) {
            $failure=$null;$TimeoutSec=10
            $deadline=[Diagnostics.Stopwatch]::GetTimestamp()+[long][Diagnostics.Stopwatch]::Frequency
            try { Invoke-CurlBatch @($target) '' 1 -DeadlineTicks $deadline | Out-Null } catch { $failure=$_ }
            $cancelled=@(if ($failure) { $failure.Exception.Data['Rows'] })
            $expectedBytes=if ($mode -eq 'exactcancel') {65536} else {8192}
            Check ($mode+' preserves observed body bytes and its termination cause') ($failure -and $cancelled.Count -eq 1 -and $cancelled[0].State -eq 'CANCELLED' -and (Get-ProbeField $cancelled[0] 'BodyBytes') -eq $expectedBytes -and (Get-ProbeField $cancelled[0] 'Termination') -eq 'Cancelled')
            if ($mode -eq 'exactcancel') { Check 'batch deadline keeps target-volume evidence without accepting the cancelled attempt' ((Get-ProbeField $cancelled[0] 'TargetReached') -eq $true -and $cancelled[0].State -eq 'CANCELLED') }
            $TimeoutSec=2
            continue
        }
        if ($mode -eq 'exact') { $TimeoutSec=1 }
        $rows=@(Invoke-CurlBatch @($target) $postFile 1);$row=$rows[0];$TimeoutSec=2
        $bodyBytes=Get-ProbeField $row 'BodyBytes';$complete=Get-ProbeField $row 'BodyComplete'
        $termination=Get-ProbeField $row 'Termination';$reached=Get-ProbeField $row 'TargetReached'
        if ($mode -eq 'exact') {
            Check 'exact target followed by a stall preserves the real curl timeout' ($row.State -eq 'OK' -and $row.Exit -eq 28 -and $reached -eq $true -and $complete -eq $false -and $termination -eq 'Timeout' -and $bodyBytes -eq 65536)
        } elseif ($mode -eq 'short') {
            Check 'short complete response remains complete' ($row.State -eq 'OK' -and $complete -eq $true -and $termination -eq 'Complete' -and $bodyBytes -eq 128 -and -not $reached)
        } else {
            Check ($mode+' body reader stops at 64 KiB even when Range is ignored') ($bodyBytes -eq 65536 -and $row.Down -lt 262144)
            Check ($mode+' target volume is successful with incomplete body recorded') ($row.State -eq 'OK' -and $reached -eq $true -and $complete -eq $false -and $termination -eq 'BodyLimit')
            Check ($mode+' original curl phase measurements survive the body limit') ($row.Code -eq '200' -and $null -ne $row.DnsMs -and $null -ne $row.TotalMs)
            if ($target.Post) { Check 'body limit preserves the full POST upload measurement' ($row.Up -eq 65536) }
        }
        $done=Wait-Job $job -Timeout 5
        if (-not $done -or $job.State -ne 'Completed') { Receive-Job $job;throw 'Fixture did not finish' }
    } finally {
        Stop-Job $job -ErrorAction SilentlyContinue;Remove-Job $job -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $ready,($ready+'.post') -Force -ErrorAction SilentlyContinue
    }
}
Check 'uncorroborated write error remains failure' ((Get-ProbeTransferState '200' 23 0 100 $false) -eq 'FAIL')
Check 'reached body limit cannot hide a TLS error' ((Get-ProbeTransferState '200' 35 0 65536 $false $true) -eq 'FAIL')
if (Get-Command Initialize-CurlBodySink -ErrorAction SilentlyContinue) {
    Initialize-CurlBodySink
    Add-Type -Language CSharp -TypeDefinition @'
namespace PipeCloseFixture {
    public static class Writer {
        public static System.Threading.Tasks.Task CloseAfter(System.IDisposable writer,int delayMs) {
            return System.Threading.Tasks.Task.Delay(delayMs).ContinueWith(task=>writer.Dispose());
        }
    }
}
'@ -ErrorAction Stop
    $sink=New-Object Zapret.Diagnostics.CurlBodySink -ArgumentList 65536
    $client=New-Object IO.Pipes.NamedPipeClientStream('.',($sink.PipePath -split '\\')[-1],[IO.Pipes.PipeDirection]::Out)
    $client.Connect(1000);$client.WriteByte(42)
    $closing=[PipeCloseFixture.Writer]::CloseAfter($client,150);$completed=$true
    try{$sink.Complete()}catch{$completed=$false;Write-Host ('Occupied completion pipe '+$_.Exception.Message+' HResult='+$_.Exception.GetBaseException().HResult)}
    finally{$closing.GetAwaiter().GetResult();$sink.Dispose()}
    Check 'occupied body pipe during asynchronous drain does not fail optional completion connection' ($completed -and $sink.BytesRead -eq 1)
    $lost=0
    for ($i=0;$i -lt 100;$i++) {
        $sink=New-Object Zapret.Diagnostics.CurlBodySink -ArgumentList 65536
        $pipeName=($sink.PipePath -split '\\')[-1]
        $client=New-Object IO.Pipes.NamedPipeClientStream('.',$pipeName,[IO.Pipes.PipeDirection]::Out)
        try { $client.Connect(1000);$client.WriteByte(42) } finally { $client.Dispose() }
        $sink.Complete()
        if ($sink.BytesRead -ne 1) { $lost++ }
    }
    Check ('immediate writer close drains every short body; lost='+$lost) ($lost -eq 0)
    $sink=New-Object Zapret.Diagnostics.CurlBodySink -ArgumentList 65536
    $reader=$sink.GetType().GetField('reader',[Reflection.BindingFlags]'Instance,NonPublic').GetValue($sink)
    $sink.Dispose()
    Check 'disposing an unopened body pipe releases its asynchronous reader' ($reader.Wait(1500))
    $sink=New-Object Zapret.Diagnostics.CurlBodySink -ArgumentList 65536
    $pipePath=$sink.PipePath
    $sink.Complete()
    Check 'failed request before output opens completes body collection without waiting for a writer' ($sink.BytesRead -eq 0 -and -not $sink.LimitReached)
    $missing=$false
    try { $client=New-Object IO.Pipes.NamedPipeClientStream('.',($pipePath -split '\\')[-1],[IO.Pipes.PipeDirection]::Out);$client.Connect(100) }
    catch [TimeoutException] { $missing=$true }
    finally { if ($client) { $client.Dispose() } }
    Check 'completed request leaves no connectable body pipe' $missing
}
if ($fails) { exit 1 }
