# Installed browser and curl, only against an owned loopback fixture. No WinDivert.
param([string]$Pkg=(Split-Path -Parent (Split-Path -Parent $PSScriptRoot)))
if(Test-Path (Join-Path $Pkg '.git')){throw 'Run on a package copy.'}
$ErrorActionPreference='Stop'
. (Join-Path $Pkg 'tools/lib.ps1')
. (Join-Path $Pkg 'tools/webprobe.ps1')
$fails=0
function Check($Name,$Ok){if($Ok){Write-Host ('ok '+$Name)}else{$script:fails++;Write-Host ('FAIL '+$Name)}}
Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
namespace WebProbeFixture {
    public sealed class Server : IDisposable {
        readonly TcpListener listener=new TcpListener(IPAddress.Loopback,0);
        readonly CancellationTokenSource stopped=new CancellationTokenSource();
        public int Port {get;private set;}
        public int HeadRequests, BrowserRequests, RecoveryRequests;
        public Server(){listener.Start();Port=((IPEndPoint)listener.LocalEndpoint).Port;Task.Run((Action)Accept);}
        void Accept(){while(!stopped.IsCancellationRequested){try{TcpClient client=listener.AcceptTcpClient();Task.Run(()=>Serve(client));}catch(SocketException){break;}catch(ObjectDisposedException){break;}}}
        void Serve(TcpClient client){using(client){try{
            var stream=client.GetStream();stream.ReadTimeout=2500;stream.WriteTimeout=2500;
            var reader=new StreamReader(stream,Encoding.ASCII,false,1024,true);string request=reader.ReadLine();if(request==null)return;
            string path=request.Split(' ')[1];bool head=request.StartsWith("HEAD ");if(head)Interlocked.Increment(ref HeadRequests);
            for(int i=0;i<100;i++){string line=reader.ReadLine();if(string.IsNullOrEmpty(line))break;if(line.StartsWith("User-Agent:") && line.Contains("HeadlessChrome"))Interlocked.Increment(ref BrowserRequests);}
            if(path=="/hang"){stopped.Token.WaitHandle.WaitOne(10000);return;}
            if(path=="/recover" && Interlocked.Increment(ref RecoveryRequests)==1){stopped.Token.WaitHandle.WaitOne(10000);return;}
            string body="<html><title>loopback</title>ok</html>";
            if(path=="/iframe")body="<html><iframe src='/denied'></iframe>main</html>";
            int code=path=="/denied"?403:path=="/redirect"?302:200;
            bool partial=path=="/abort" || path=="/stall";
            int length=partial?4096:Encoding.UTF8.GetByteCount(body);
            byte[] header=Encoding.ASCII.GetBytes("HTTP/1.1 "+code+" Fixture\r\nContent-Type: text/html\r\nContent-Length: "+length+"\r\n"+(path=="/redirect"?"Location: /final\r\n":"")+"Connection: close\r\n\r\n");
            stream.Write(header,0,header.Length);
            if(!head){byte[] bytes=Encoding.UTF8.GetBytes(body);stream.Write(bytes,0,bytes.Length);}stream.Flush();
            if(path=="/stall")stopped.Token.WaitHandle.WaitOne(10000);
        }catch(IOException){}catch(SocketException){}catch(ObjectDisposedException){}}}
        public void Dispose(){stopped.Cancel();listener.Stop();}
    }
}
'@ -ErrorAction Stop
$server=New-Object WebProbeFixture.Server
$profilesBefore=@(Get-ChildItem -LiteralPath ([IO.Path]::GetTempPath()) -Directory -Filter 'zapret-web-*'|ForEach-Object{$_.FullName})
try {
    $caps=Get-WebProbeCapabilities
    Check 'local curl detection compiles runtime and records its feature support' ($caps.Curl.Available -and $caps.CurlPath)
    $base='http://127.0.0.1:'+$server.Port
    $answer=Invoke-WebCurlCommand $caps.CurlPath @('--disable','--silent','--noproxy','*','--head','--max-time','2','--output','NUL','--write-out','%{http_code}|%{http_version}','--url',($base+'/final')) 3000
    Check 'real curl HEAD obtains status and actual protocol without a body' ($answer.Exit -eq 0 -and $answer.Output -eq '200|1.1' -and $server.HeadRequests -eq 1)
    if(-not $caps.BrowserPath){Write-Host 'SKIP browser fixtures: Edge/Chrome is not installed.'}
    else {
        foreach($case in @('final','redirect','denied','iframe','abort','stall','hang')){
            $target=[pscustomobject]@{Group='Fixture';Name=$case;Url=($base+'/'+$case)}
            $rows=@(Invoke-WebBrowserProbe $target BrowserTcp $caps.BrowserPath -TimeoutSec 5 -Visits 1)
            $row=$rows[0]
            Write-Host ($case+' '+($row|ConvertTo-Json -Compress))
            $expected=if($case -eq 'denied'){'HTTP_ERROR'}elseif($case -in @('abort','stall','hang')){'FAIL'}else{'OK'}
            Check ($case+' has the expected observed outcome') ($rows.Count -eq 1 -and $row.State -eq $expected)
            Check ($case+' cleans the owned browser profile') $row.CleanupComplete
            if($row.Complete){Check ($case+' retains browser-reported request bytes') ($row.EncodedBytes -gt 0)}
            if($case -eq 'redirect'){Check 'redirect records only the final document URL' ($row.FinalUrl -eq ($base+'/final') -and $row.Complete -and $row.StatusCode -eq 200)}
            if($case -in @('abort','stall','hang')){Check ($case+' preserves incomplete body evidence') (-not $row.Complete)}
            if($case -eq 'hang'){Check 'navigation deadline before headers is reported as a request timeout' ($row.Reason -eq 'Timeout')}
        }
        $target=[pscustomobject]@{Group='Fixture';Name='repeat';Url=($base+'/final')}
        $rows=@(Invoke-WebBrowserProbe $target BrowserAuto $caps.BrowserPath -TimeoutSec 5)
        Check 'automatic browser mode retains both visits and actual non-QUIC protocol' ($rows.Count -eq 2 -and @($rows|Where-Object{$_.State -eq 'OK' -and $_.ObservedProtocol -eq 'http/1.1' -and -not $_.QuicConfirmed}).Count -eq 2 -and $rows[0].Sample -eq 1 -and $rows[1].Sample -eq 2)
        $target=[pscustomobject]@{Group='Fixture';Name='recover';Url=($base+'/recover')}
        $recovered=@(Invoke-WebBrowserProbe $target BrowserAuto $caps.BrowserPath -TimeoutSec 5)
        Check 'first navigation timeout does not discard the planned second visit' ($recovered.Count -eq 2 -and $recovered[0].Reason -eq 'Timeout' -and $recovered[1].State -eq 'OK' -and $recovered[1].Sample -eq 2)
        if($recovered.Count -eq 2){Check 'recovery reports its new browser session explicitly' $recovered[1].SessionRestarted}
        Check 'fixture received a real headless browser user agent' ($server.BrowserRequests -ge 8)
        $deadline=[Diagnostics.Stopwatch]::GetTimestamp()+[long](2*[Diagnostics.Stopwatch]::Frequency)
        $target=[pscustomobject]@{Group='Fixture';Name='cancel';Url=($base+'/hang')}
        $cancelled=@(Invoke-WebBrowserProbe $target BrowserTcp $caps.BrowserPath -TimeoutSec 10 -Visits 1 -DeadlineTicks $deadline)
        Check 'deadline cancellation remains unknown and cleans owned processes' ($cancelled.Count -eq 1 -and $cancelled[0].State -eq 'UNKNOWN' -and $cancelled[0].Reason -eq 'Cancelled' -and $cancelled[0].CleanupComplete)
    }
    $target=[pscustomobject]@{Group='Fixture';Name='startup';Url=($base+'/final')}
    $wrongBrowser=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
    $startup=@(Invoke-WebBrowserProbe $target BrowserAuto $wrongBrowser -TimeoutSec 2 -Visits 1)
    Check 'browser startup failure stays unknown and cleans its private profile' ($startup.Count -eq 1 -and $startup[0].State -eq 'UNKNOWN' -and $startup[0].Reason -eq 'ControllerError' -and $startup[0].CleanupComplete)
    if($caps.BrowserPath){
        $cliLog=Join-Path $Script:Runtime 'web-cli-fixture.log'
        $ps=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
        & $ps -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Pkg 'tools/webcheck.ps1') -Url ($base+'/final') -TimeoutSec 5 *> $cliLog
        $cliExit=$LASTEXITCODE
        $saved=[IO.File]::ReadAllText((Join-Path $Script:Runtime 'web-check-last.json'))|ConvertFrom-Json
        Check 'standalone script runs real loopback clients and persists the result' ($cliExit -eq 0 -and $saved.Rows.Count -eq 6 -and @($saved.Rows|Where-Object{$_.Mode -like 'Browser*' -and $_.State -eq 'OK'}).Count -eq 4)
    }
    $profilesAfter=@(Get-ChildItem -LiteralPath ([IO.Path]::GetTempPath()) -Directory -Filter 'zapret-web-*'|ForEach-Object{$_.FullName})
    Check 'real clients leave no added temporary browser profiles' (@($profilesAfter|Where-Object{$profilesBefore -notcontains $_}).Count -eq 0)
    $owned=@(Get-CimInstance Win32_Process -Filter "Name='msedge.exe' OR Name='chrome.exe'"|Where-Object{$_.CommandLine -match 'user-data-dir=.*zapret-web-'})
    Check 'no diagnostic browser descendants remain running' ($owned.Count -eq 0)
} finally {$server.Dispose()}
if($fails){exit 1}
Write-Host 'Web loopback clients passed.'
