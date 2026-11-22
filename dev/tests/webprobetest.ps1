# Offline protocol evidence and real loopback clients. No driver or external network.
param([string]$Pkg=(Split-Path -Parent (Split-Path -Parent $PSScriptRoot)))
if(Test-Path (Join-Path $Pkg '.git')){throw 'Run on a package copy.'}
$ErrorActionPreference='Stop'
. (Join-Path $Pkg 'tools/lib.ps1')
$module=Join-Path $Pkg 'tools/webprobe.ps1'
$fails=0
function Check($Name,$Ok){if($Ok){Write-Host ('ok '+$Name)}else{$script:fails++;Write-Host ('FAIL '+$Name)}}
Check 'extended protocol module exists' (Test-Path $module)
if(-not (Test-Path $module)){exit 1}
. $module

$caps=Convert-WebCurlCapabilities "curl 8.22.0 (Windows)`nProtocols: http https`nFeatures: alt-svc HTTP2 HTTP3 SSL"
Check 'capability parser recognizes exact feature tokens' ($caps.Available -and $caps.Http2 -and $caps.Http3)
$limited=Convert-WebCurlCapabilities "curl 8.22.0 (Windows)`nProtocols: http https`nFeatures: alt-svc SSL"
Check 'HTTPS and alt-svc do not imply HTTP2 or HTTP3' ($limited.Available -and -not $limited.Http2 -and -not $limited.Http3)
Check 'unknown capability output stays unavailable' (-not (Convert-WebCurlCapabilities 'not curl').Available)
$plain=Convert-WebCurlCapabilities "curl 8.22.0 (Windows)`nProtocols: http`nFeatures: HTTP2 HTTP3"
Check 'a curl build without HTTPS cannot provide these protocol probes' (-not $plain.Http2 -and -not $plain.Http3)
$target=[pscustomobject]@{Group='YouTube';Name='web';Url='https://example.test/'}
$ok=Convert-WebProtocolResult $target 'Http2' '2' 200 $true 12 ''
Check 'observed HTTP2 confirms requested protocol' ($ok.State -eq 'OK' -and $ok.ProtocolConfirmed -and $ok.Complete)
$fallback=Convert-WebProtocolResult $target 'Http2' '1.1' 200 $true 13 ''
Check 'HTTP1 fallback is not HTTP2 success' ($fallback.State -eq 'UNKNOWN' -and -not $fallback.ProtocolConfirmed -and $fallback.Reason -eq 'ProtocolMismatch')
$h3Fallback=Convert-WebProtocolResult $target 'Http3' 'h2' 200 $true 12 ''
Check 'TCP success is not QUIC success' ($h3Fallback.State -eq 'UNKNOWN' -and -not $h3Fallback.QuicConfirmed)
$h3=Convert-WebProtocolResult $target 'Http3' 'h3' 200 $true 13 ''
Check 'observed HTTP3 confirms QUIC' ($h3.State -eq 'OK' -and $h3.QuicConfirmed -and $h3.ProtocolConfirmed)
$denied=Convert-WebProtocolResult $target 'Http2' 'h2' 403 $true 12 ''
Check 'HTTP application error retains negotiated protocol evidence' ($denied.State -eq 'HTTP_ERROR' -and $denied.ProtocolConfirmed -and $denied.StatusCode -eq 403)
$partial=Convert-WebProtocolResult $target 'BrowserAuto' 'h2' 200 $false 24 'Timeout'
Check 'headers do not prove completed browser transfer' ($partial.State -eq 'FAIL' -and -not $partial.Complete -and $partial.Reason -eq 'Timeout')
$tcp=Convert-WebProtocolResult $target 'BrowserTcp' 'h3' 200 $true 12 ''
Check 'unexpected QUIC in disabled mode is contradictory evidence' ($tcp.State -eq 'UNKNOWN' -and $tcp.Reason -eq 'ProtocolMismatch')
$missing=Convert-WebProtocolResult $target 'Http3' '' 0 $false 0 'Unavailable'
Check 'missing support has a separate unavailable outcome' ($missing.State -eq 'UNAVAILABLE' -and -not $missing.ProtocolConfirmed)
$broken=Convert-WebProtocolResult $target 'BrowserAuto' '' 0 $false 0 'ControllerError'
Check 'browser controller error stays unknown' ($broken.State -eq 'UNKNOWN')

$inputTargets=@($target,[pscustomobject]@{Group='Discord';Name='main';Url='https://discord.test/'},[pscustomobject]@{Group='Clean';Name='bing';Url='https://clean.test/'},[pscustomobject]@{Group='DPI';Name='post';Url='https://post.test/';Post=$true})
$chosen=@(Get-WebCheckTargets $inputTargets)
Check 'defaults select web targets and a clean control without POST uploads' ($chosen.Count -eq 3 -and @($chosen|Where-Object{$_.Group -eq 'DPI'}).Count -eq 0)

# Feed actual CDP event shape. Only the final main-frame document can complete the row.
$nav=@{FrameId='main';LoaderId='loader';RequestId='';Url='';Protocol='';StatusCode=0;Complete=$false;Failure='';Done=$false}
function Event($Method,$Params){return [pscustomobject]@{method=$Method;params=[pscustomobject]$Params}}
Update-WebNavigation $nav (Event 'Network.requestWillBeSent' @{frameId='main';loaderId='loader';type='Document';requestId='req';request=[pscustomobject]@{url='https://example.test/'}})
Update-WebNavigation $nav (Event 'Network.responseReceived' @{frameId='child';type='Document';requestId='child';response=[pscustomobject]@{url='https://child.test/';status=200;protocol='h3'}})
Update-WebNavigation $nav (Event 'Network.loadingFinished' @{requestId='child'})
Check 'successful subframe does not complete main navigation' (-not $nav.Complete -and $nav.StatusCode -eq 0)
Update-WebNavigation $nav (Event 'Network.responseReceived' @{frameId='main';type='Document';requestId='req';response=[pscustomobject]@{url='https://example.test/';status=302;protocol='h2'}})
Update-WebNavigation $nav (Event 'Network.requestWillBeSent' @{frameId='main';loaderId='loader';type='Document';requestId='req';request=[pscustomobject]@{url='https://example.test/final'}})
Update-WebNavigation $nav (Event 'Network.loadingFinished' @{requestId='req'})
Check 'redirect headers cannot stand in for final document' (-not $nav.Complete -and $nav.StatusCode -eq 0)
Update-WebNavigation $nav (Event 'Network.responseReceived' @{frameId='main';type='Document';requestId='req';response=[pscustomobject]@{url='https://example.test/final';status=200;protocol='h2'}})
Update-WebNavigation $nav (Event 'Network.loadingFinished' @{requestId='req';encodedDataLength=1234})
Check 'main document completion retains final URL and protocol' ($nav.Complete -and $nav.Done -and $nav.Url -eq 'https://example.test/final' -and $nav.Protocol -eq 'h2')
Check 'completed main document retains browser-reported encoded byte count' ($nav.EncodedBytes -eq 1234)
Update-WebNavigation $nav (Event 'Network.requestWillBeSent' @{frameId='main';loaderId='other';type='Document';requestId='late';request=[pscustomobject]@{url='https://other.test/'}})
Check 'another loader cannot replace completed requested navigation' ($nav.RequestId -eq 'req')

# Exercise the actual curl probe path with captured subprocess arguments.
$script:curlArguments=@();$script:curlAnswer=[pscustomobject]@{Exit=0;Output='200|1.1|https://example.test/final';Error=''}
function Invoke-WebCurlCommand($Path,$Arguments,$TimeoutMs){$script:curlArguments=$Arguments;return $script:curlAnswer}
$clientCaps=[pscustomobject]@{CurlPath='fixture-curl.exe';Curl=$caps}
$strict=Invoke-WebCurlProbe $target Http3 $clientCaps
Check 'HTTP3 subprocess forbids TCP fallback and checks certificates' ($script:curlArguments -contains '--http3-only' -and $script:curlArguments -notcontains '--http3' -and $script:curlArguments -notcontains '--insecure' -and $script:curlArguments -contains '--head' -and $script:curlArguments[0] -eq '--disable')
Check 'actual probe retains negotiated fallback as unknown with final URL' ($strict.State -eq 'UNKNOWN' -and $strict.FinalUrl -eq 'https://example.test/final')
$script:curlAnswer=[pscustomobject]@{Exit=60;Output='000|0|https://example.test/';Error='untrusted certificate'}
$cert=Invoke-WebCurlProbe $target Http2 $clientCaps
Check 'certificate validation failure is retained as a failed request' ($cert.State -eq 'FAIL' -and $cert.Reason -eq 'RequestFailed' -and $cert.Error -eq 'untrusted certificate')
$script:curlAnswer=[pscustomobject]@{Exit=4;Output='';Error='feature unavailable'}
$unsupported=Invoke-WebCurlProbe $target Http3 $clientCaps
Check 'runtime unsupported feature is not a network failure' ($unsupported.State -eq 'UNAVAILABLE')
$before=$script:curlArguments
$unavailableCaps=[pscustomobject]@{CurlPath='';Curl=$limited}
$absent=Invoke-WebCurlProbe $target Http3 $unavailableCaps
Check 'unavailable protocol does not launch a request' ($absent.State -eq 'UNAVAILABLE' -and [object]::ReferenceEquals($before,$script:curlArguments))
$probeAst=${function:Invoke-WebBrowserProbe}.Ast
$navigateError=$probeAst.Find({$args[0] -is [Management.Automation.Language.IfStatementAst] -and $args[0].Extent.Text.StartsWith("if(`$started.PSObject.Properties['errorText'])")},$true)
$nativeFailure=$probeAst.Find({$args[0] -is [Management.Automation.Language.AssignmentStatementAst] -and $args[0].Extent.Text.StartsWith('$failure=if($navigation.Failure)')},$true)
foreach($nativeError in @('net::ERR_TIMED_OUT','net::ERR_CONNECTION_TIMED_OUT','net::ERR_CERT_AUTHORITY_INVALID')){
    $expected=if($nativeError -match 'TIMED_OUT'){'Timeout'}else{'RequestFailed'}
    $started=[pscustomobject]@{errorText=$nativeError};$clock=[Diagnostics.Stopwatch]::StartNew();$rows=New-Object System.Collections.Generic.List[object];$Mode='BrowserAuto'
    . ([scriptblock]::Create('foreach($sample in @(1)) {'+$navigateError.Extent.Text+'}'))
    Check ('Page.navigate classifies '+$nativeError) ($rows.Count -eq 1 -and $rows[0].Reason -eq $expected -and $rows[0].Error -eq $nativeError)
    $navigation=@{FrameId='main';LoaderId='loader';RequestId='req';Url=$target.Url;Protocol='';StatusCode=0;Complete=$false;Failure='';Done=$false}
    Update-WebNavigation $navigation (Event 'Network.loadingFailed' @{requestId='req';errorText=$nativeError})
    . ([scriptblock]::Create($nativeFailure.Extent.Text))
    Check ('Network.loadingFailed classifies '+$nativeError) ($navigation.Done -and $failure -eq $expected)
}
# PowerShell's exception string includes the invariant nested type name.
$reasonCode=$probeAst.Find({$args[0] -is [Management.Automation.Language.AssignmentStatementAst] -and $args[0].Extent.Text.StartsWith('$reason=if($cancelled)')},$true)
$cancelled=$false;$navigating=$true
try{throw (New-Object Threading.Tasks.TaskCanceledException 'Операция прервана по истечении срока.')}catch{
    . ([scriptblock]::Create($reasonCode.Extent.Text))
    Check 'localized task cancellation already retains the timeout classification' ($reason -eq 'Timeout')
}

$waitAvailable=$null -ne (Get-Command Wait-WebBrowserEndpoint -ErrorAction SilentlyContinue)
Check 'browser endpoint waits for readable complete publication' $waitAvailable
if($waitAvailable){
    Add-Type -Language CSharp -TypeDefinition @'
namespace WebEndpointFixture {
    public sealed class Publisher : System.IDisposable {
        readonly System.Threading.CancellationTokenSource stop=new System.Threading.CancellationTokenSource();
        readonly System.IO.FileStream locked;
        readonly System.Threading.Tasks.Task task;
        public Publisher(string path,bool partial,int delay){
            if(partial)System.IO.File.WriteAllText(path,"12345\n");
            else locked=new System.IO.FileStream(path,System.IO.FileMode.Create,System.IO.FileAccess.Write,System.IO.FileShare.None);
            task=System.Threading.Tasks.Task.Run(()=>{
                try{
                    if(stop.Token.WaitHandle.WaitOne(delay))return;
                    if(partial)System.IO.File.AppendAllText(path,"/devtools/browser/fixture-123\n");
                    else {byte[] data=System.Text.Encoding.UTF8.GetBytes("12345\n/devtools/browser/fixture-123\n");locked.Write(data,0,data.Length);}
                }catch(System.ObjectDisposedException){}finally{if(locked!=null)locked.Dispose();}
            });
        }
        public void Dispose(){stop.Cancel();task.Wait();if(locked!=null)locked.Dispose();stop.Dispose();}
    }
}
'@ -ErrorAction Stop
    $directory=Join-Path $Script:Runtime ('web-endpoint-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($directory)
    $portFile=Join-Path $directory 'DevToolsActivePort';$owner=[pscustomobject]@{Exited=$false}
    foreach($partial in @($false,$true)){
        $publisher=New-Object WebEndpointFixture.Publisher($portFile,$partial,200)
        try{
            $deadline=[Diagnostics.Stopwatch]::GetTimestamp()+[long](2*[Diagnostics.Stopwatch]::Frequency)
            $endpoint=Wait-WebBrowserEndpoint $portFile $owner $deadline
            Check ($(if($partial){'partial endpoint publication'}else{'exclusive writer sharing violation'})+' waits for the real endpoint') ($endpoint -ceq 'ws://127.0.0.1:12345/devtools/browser/fixture-123')
        }finally{$publisher.Dispose();[IO.File]::Delete($portFile)}
    }
    $publisher=New-Object WebEndpointFixture.Publisher($portFile,$false,10000)
    try{
        $clock=[Diagnostics.Stopwatch]::StartNew();$timedOut=$false
        $deadline=[Diagnostics.Stopwatch]::GetTimestamp()+[long]([Diagnostics.Stopwatch]::Frequency/5)
        try{Wait-WebBrowserEndpoint $portFile $owner $deadline|Out-Null}catch{$timedOut=$_.Exception.GetBaseException() -is [TimeoutException]}
        Check 'locked endpoint still obeys the original startup deadline' ($timedOut -and $clock.ElapsedMilliseconds -lt 1500)
    }finally{$publisher.Dispose();[IO.File]::Delete($portFile)}
    $exited=$false
    try{Wait-WebBrowserEndpoint $portFile ([pscustomobject]@{Exited=$true}) ([Diagnostics.Stopwatch]::GetTimestamp()+[Diagnostics.Stopwatch]::Frequency)|Out-Null}catch{$exited=$_.Exception.Message.Contains('Browser exited')}
    Check 'browser exit stops endpoint waiting immediately' $exited
    [IO.Directory]::Delete($directory)
}
if($fails){exit 1}
Write-Host 'Web protocol evidence passed.'
