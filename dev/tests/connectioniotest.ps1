# Actual loopback TCP/TLS/HTTP and owned DNS workers. No certificate-store changes.
param([string]$Pkg=(Split-Path -Parent (Split-Path -Parent $PSScriptRoot)))
if(Test-Path (Join-Path $Pkg '.git')){throw 'Run on a package copy.'}
$ErrorActionPreference='Stop'
. (Join-Path $Pkg 'tools/lib.ps1')
. (Join-Path $Pkg 'tools/webprobe.ps1')
. (Join-Path $Pkg 'tools/connectionprobe.ps1')
$fails=0
function Check($Name,$Ok){if($Ok){Write-Host ('ok '+$Name)}else{$script:fails++;Write-Host ('FAIL '+$Name)}}
$fixture=@'
namespace ConnectionFixture {
    public sealed class Server : System.IDisposable {
        readonly System.Net.Sockets.TcpListener listener;
        readonly System.Threading.CancellationTokenSource stopped=new System.Threading.CancellationTokenSource();
        readonly System.Collections.Concurrent.ConcurrentBag<System.Net.Sockets.TcpClient> clients=new System.Collections.Concurrent.ConcurrentBag<System.Net.Sockets.TcpClient>();
        readonly string mode;
        readonly System.Security.Cryptography.X509Certificates.X509Certificate2 certificate;
        public int Port {get;private set;}
        public string Authority="", Method="";
        public string Thumbprint {get{return certificate.Thumbprint;}}
        public Server(string mode,bool ipv6) {
            this.mode=mode;
            using(var key=System.Security.Cryptography.RSA.Create(2048)){
                var request=new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=localhost",key,System.Security.Cryptography.HashAlgorithmName.SHA256,System.Security.Cryptography.RSASignaturePadding.Pkcs1);
                var names=new System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder();names.AddDnsName("localhost");request.CertificateExtensions.Add(names.Build());
                using(var original=request.CreateSelfSigned(System.DateTimeOffset.UtcNow.AddHours(-1),System.DateTimeOffset.UtcNow.AddDays(1)))
                    certificate=new System.Security.Cryptography.X509Certificates.X509Certificate2(original.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pfx),"",System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.UserKeySet|System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.Exportable);
            }
            listener=new System.Net.Sockets.TcpListener(ipv6?System.Net.IPAddress.IPv6Loopback:System.Net.IPAddress.Loopback,0);listener.Start();Port=((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
            System.Threading.Tasks.Task.Run((System.Action)Accept);
        }
        void Accept(){while(!stopped.IsCancellationRequested){try{var client=listener.AcceptTcpClient();clients.Add(client);System.Threading.Tasks.Task.Run(()=>Serve(client));}catch(System.Net.Sockets.SocketException){break;}catch(System.ObjectDisposedException){break;}}}
        void Serve(System.Net.Sockets.TcpClient client){using(client){try{
            if(mode=="tlsstall"){stopped.Token.WaitHandle.WaitOne(10000);return;}
            using(var tls=new System.Net.Security.SslStream(client.GetStream(),false)){
                tls.ReadTimeout=3000;tls.WriteTimeout=3000;tls.AuthenticateAsServer(certificate,false,System.Security.Authentication.SslProtocols.Tls12,false);
                var reader=new System.IO.StreamReader(tls,System.Text.Encoding.ASCII,false,1024,true);string line=reader.ReadLine();if(line==null)return;Method=line.Split(' ')[0];
                for(int i=0;i<100;i++){line=reader.ReadLine();if(string.IsNullOrEmpty(line))break;if(line.StartsWith("Host: "))Authority=line.Substring(6);}
                if(mode=="httpstall"){stopped.Token.WaitHandle.WaitOne(10000);return;}
                string response="HTTP/1.1 200 OK\r\nContent-Length: 2000000\r\nConnection: close\r\n\r\n";
                if(mode=="denied")response="HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
                if(mode=="interim")response="HTTP/1.1 103 Early Hints\r\nLink: </asset>\r\n\r\n"+response;
                if(mode=="malformed")response="not HTTP\r\n\r\n";
                if(mode=="badstatus")response="HTTP/1.1 200 OK\0bad\r\n\r\n";
                if(mode=="boundary"){
                    string prefix="HTTP/1.1 103 Early Hints\r\nX-Pad: ";string final="HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
                    response=prefix+new string('x',32768-prefix.Length-4-final.Length)+"\r\n\r\n"+final;
                }
                if(mode=="badheader")response="HTTP/1.1 200 OK\r\nInvalid header without colon\r\n\r\n";
                if(mode=="upgrade")response="HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n";
                if(mode=="truncated")response="HTTP/1.1 200 OK\r\nX-Partial: true\r\n";
                if(mode=="oversized")response="HTTP/1.1 200 OK\r\nX-Large: "+new string('x',40000)+"\r\n\r\n";
                byte[] bytes=System.Text.Encoding.ASCII.GetBytes(response);tls.Write(bytes,0,bytes.Length);tls.Flush();
                if(mode=="body"){byte[] body=new byte[8192];for(int i=0;i<256;i++)tls.Write(body,0,body.Length);}
            }
        }catch(System.IO.IOException){}catch(System.Net.Sockets.SocketException){}catch(System.ObjectDisposedException){}catch(System.Security.Authentication.AuthenticationException){}}}
        public ZapretConnection.Probe Start(string host,string address,int timeout) {
            string expected=Thumbprint;
            return ZapretConnection.Probe.StartFixture(host,address,Port,"/",timeout,(sender,cert,chain,errors)=>cert!=null && cert.GetCertHashString()==expected && (errors & ~System.Net.Security.SslPolicyErrors.RemoteCertificateChainErrors)==0);
        }
        public void Dispose(){stopped.Cancel();listener.Stop();foreach(var client in clients)client.Close();certificate.Dispose();}
    }
}
'@
$path=Join-Path $Pkg 'tools/connectionprobe.cs';$source=[IO.File]::ReadAllText($path).Replace('__SOURCE_HASH__',(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash)
Add-Type -Language CSharp -TypeDefinition ($source+"`n"+$fixture) -ErrorAction Stop
Initialize-ConnectionProbeRuntime
foreach($mode in @('normal','denied','interim','boundary','body','malformed','badstatus','badheader','upgrade','truncated','oversized','tlsstall','httpstall')){
    $server=New-Object ConnectionFixture.Server($mode,$false);$probe=$null
    try{
        $probe=$server.Start('localhost','127.0.0.1',1200);$row=$probe.Completion.GetAwaiter().GetResult()
        $expected=if($mode -in @('normal','interim','boundary','body')){'OK'}elseif($mode -eq 'denied'){'HTTP_ERROR'}else{'FAIL'}
        Write-Host ($mode+' '+($row|ConvertTo-Json -Compress))
        Check ($mode+' actual outcome') ($row.State -eq $expected)
        if($mode -eq 'normal'){Check 'successful TLS records the certificate callback observation' ($row.CertificateObserved -and $row.CertificateErrors -ne 'NotObserved')}
        if($mode -eq 'tlsstall'){Check 'stalled TLS does not claim certificate validation occurred' (-not $row.CertificateObserved -and $row.CertificateErrors -eq 'NotObserved')}
        if($expected -in @('OK','HTTP_ERROR')){Check ($mode+' confirms TLS and bounded response headers') ($row.TcpSucceeded -and $row.TlsSucceeded -and $row.HeadersComplete -and $row.ReceivedBytes -le 32768 -and $row.Validation -eq 'FixturePin')}
        if($mode -eq 'normal'){Check 'original hostname is used in HTTP authority and HEAD method' ($server.Authority -eq ('localhost:'+$server.Port) -and $server.Method -eq 'HEAD')}
        if($mode -eq 'tlsstall'){Check 'TLS timeout retains a completed TCP stage' ($row.Stage -eq 'Tls' -and $row.Reason -eq 'Timeout' -and $row.TcpSucceeded -and -not $row.TlsSucceeded)}
        if($mode -eq 'httpstall'){Check 'HTTP timeout retains completed TLS evidence' ($row.Stage -eq 'Http' -and $row.Reason -eq 'Timeout' -and $row.TlsSucceeded -and -not $row.HeadersComplete)}
        if($mode -eq 'oversized'){Check 'header byte budget is enforced' ($row.Reason -eq 'HeaderLimit' -and $row.ReceivedBytes -eq 32768)}
        if($mode -eq 'truncated'){Check 'EOF without final headers is incomplete' ($row.Reason -eq 'TruncatedHeaders' -and -not $row.HeadersComplete)}
        if($mode -eq 'boundary'){Check 'buffered final headers at the exact inclusive limit complete successfully' ($row.HeadersComplete -and $row.HeaderBytes -eq 32768)}
    }finally{if($probe){$probe.Dispose()};$server.Dispose()}
}
$server=New-Object ConnectionFixture.Server('normal',$false)
try{
    $probe=[ZapretConnection.Probe]::Start('localhost','127.0.0.1',$server.Port,'/',2000)
    try{$untrusted=$probe.Completion.GetAwaiter().GetResult()}finally{$probe.Dispose()}
    Check 'production validation rejects an untrusted certificate' ($untrusted.Stage -eq 'Tls' -and $untrusted.Reason -eq 'Certificate' -and -not $untrusted.TlsSucceeded -and $untrusted.Validation -eq 'System')
    Check 'rejected certificate still records observed validation errors' ($untrusted.CertificateObserved -and $untrusted.CertificateErrors -ne 'NotObserved' -and $untrusted.CertificateErrors -ne 'None')
    $probe=$server.Start('wrong.invalid','127.0.0.1',2000)
    try{$wrong=$probe.Completion.GetAwaiter().GetResult()}finally{$probe.Dispose()}
    Check 'selected IP does not replace original TLS hostname validation' ($wrong.Reason -eq 'Certificate' -and $wrong.CertificateErrors.Contains('RemoteCertificateNameMismatch'))
    $cliLog=Join-Path $Script:Runtime 'connection-cli.log'
    $powershell=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
    & $powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $Pkg 'tools/connection-check.ps1') -Url ('https://127.0.0.1:'+$server.Port+'/') -TimeoutSec 5 *> $cliLog
    $cliExit=$LASTEXITCODE;$cli=[IO.File]::ReadAllText((Join-Path $Script:Runtime 'connection-check-last.json'))|ConvertFrom-Json
    Check 'real standalone CLI saves untrusted TLS evidence without claiming connectivity' ($cliExit -eq 0 -and $cli.Targets.Count -eq 1 -and $cli.Targets[0].Rows.Count -eq 2 -and $cli.Targets[0].Assessment.Stage -eq 'Tls' -and -not $cli.Targets[0].Assessment.ReachableHttp)
}finally{$server.Dispose()}
$listener=New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback,0);$listener.Start();$closedPort=$listener.LocalEndpoint.Port;$listener.Stop()
$probe=[ZapretConnection.Probe]::Start('localhost','127.0.0.1',$closedPort,'/',3000)
try{$refused=$probe.Completion.GetAwaiter().GetResult()}finally{$probe.Dispose()}
Write-Host ('refused '+($refused|ConvertTo-Json -Compress))
Check 'TCP refusal never becomes TLS failure' ($refused.Stage -eq 'Tcp' -and $refused.Reason -eq 'ConnectionRefused' -and -not $refused.TcpSucceeded)
Check 'unobserved certificate validation has an explicit marker' (-not $refused.CertificateObserved -and $refused.CertificateErrors -eq 'NotObserved')
$server=New-Object ConnectionFixture.Server('httpstall',$false)
try{
    $probe=$server.Start('localhost','127.0.0.1',10000);Start-Sleep -Milliseconds 200;$probe.Cancel()
    try{$cancel=$probe.Completion.GetAwaiter().GetResult()}finally{$probe.Dispose()}
    Check 'explicit cancellation remains unknown and bounded' ($cancel.State -eq 'UNKNOWN' -and $cancel.Reason -eq 'Cancelled' -and $cancel.ElapsedMs -lt 2500)
}finally{$server.Dispose()}
if([Net.Sockets.Socket]::OSSupportsIPv6){
    $server=New-Object ConnectionFixture.Server('normal',$true)
    try{$probe=$server.Start('localhost','::1',2000);try{$six=$probe.Completion.GetAwaiter().GetResult()}finally{$probe.Dispose()};Check 'actual IPv6 loopback uses the same staged client' ($six.State -eq 'OK' -and $six.Family -eq 'IPv6')}finally{$server.Dispose()}
}else{Write-Host 'SKIP IPv6 fixture: OS has no IPv6 support.'}
Check 'all owned address probes finished' ([ZapretConnection.Probe]::Active -eq 0)

Initialize-WebProbeRuntime
$target=[pscustomobject]@{Group='Fixture';Name='dns';Url='https://localhost/'}
$dns=Resolve-ConnectionTarget $target ([Diagnostics.Stopwatch]::GetTimestamp()+[long](4*[Diagnostics.Stopwatch]::Frequency))
Check 'actual system DNS worker resolves localhost' ($dns.State -eq 'OK' -and $dns.Addresses.Count -gt 0 -and $dns.WorkerId -gt 0)
$gone=$false;try{[Diagnostics.Process]::GetProcessById($dns.WorkerId).Dispose()}catch{$gone=$true}
Check 'completed resolver worker is no longer running' $gone
$original=${function:Get-ConnectionDnsCommand}
function Get-ConnectionDnsCommand($HostName,$OutputFile){[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Start-Sleep -Seconds 30'))}
try{$timed=Resolve-ConnectionTarget $target ([Diagnostics.Stopwatch]::GetTimestamp()+[long]([Diagnostics.Stopwatch]::Frequency/2))}finally{${function:Get-ConnectionDnsCommand}=$original}
$gone=$false;try{[Diagnostics.Process]::GetProcessById($timed.WorkerId).Dispose()}catch{$gone=$true}
Check 'resolver deadline kills its owned worker and remains unknown' ($timed.State -eq 'UNKNOWN' -and $timed.Reason -eq 'Timeout' -and $timed.WorkerId -gt 0 -and $gone -and $timed.ElapsedMs -lt 2500)
Check 'DNS result and staging files are cleaned' (@(Get-ChildItem -LiteralPath $Script:Runtime -File -Filter 'connection-dns-*').Count -eq 0)
$oldRuntime=$Script:Runtime;$Script:Runtime=Join-Path $oldRuntime "O’Neil";[void][IO.Directory]::CreateDirectory($Script:Runtime)
try{$quoted=Resolve-ConnectionTarget $target ([Diagnostics.Stopwatch]::GetTimestamp()+[long](4*[Diagnostics.Stopwatch]::Frequency))}finally{$Script:Runtime=$oldRuntime}
Check 'real DNS worker accepts a legal installation path containing a typographic quote' ($quoted.State -eq 'OK' -and $quoted.Addresses.Count -gt 0)

# Stop a real controller runspace after its owned DNS worker starts.
$interruptedRoot=Join-Path $Script:Runtime 'interrupted';[void][IO.Directory]::CreateDirectory($interruptedRoot);$gate=Join-Path $interruptedRoot 'worker-ready'
$controller=[PowerShell]::Create()
$controllerCode=@'
param($PackagePath,$OutputRoot,$GateFile)
$ErrorActionPreference='Stop'
. (Join-Path $PackagePath 'tools/lib.ps1')
. (Join-Path $PackagePath 'tools/webprobe.ps1')
. (Join-Path $PackagePath 'tools/connectionprobe.ps1')
$Script:Runtime=$OutputRoot
function Get-WebVerificationContext {[pscustomobject]@{Known=$false;Network=[pscustomobject]@{Known=$false;Key='';ObservedUtc=[datetime]::UtcNow.ToString('o')};Processes=@();SettingsHash='fixture'}}
function Get-ConnectionDnsCommand($HostName,$OutputFile){
    $encodedGate=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($GateFile))
    $code='$gate=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('''+$encodedGate+'''));[IO.File]::WriteAllText($gate,[string]$PID);Start-Sleep -Seconds 30'
    [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
}
$targets=@([pscustomobject]@{Group='Fixture';Name='first';Url='https://localhost/'},[pscustomobject]@{Group='Fixture';Name='second';Url='https://localhost/'})
Invoke-ConnectionDiagnostic -Targets $targets -TimeoutSec 20 -Quiet
'@
try{
    [void]$controller.AddScript($controllerCode).AddArgument($Pkg).AddArgument($interruptedRoot).AddArgument($gate);$pending=$controller.BeginInvoke()
    $timer=[Diagnostics.Stopwatch]::StartNew()
    while(-not [IO.File]::Exists($gate) -and -not $pending.IsCompleted -and $timer.ElapsedMilliseconds -lt 10000){Start-Sleep -Milliseconds 20}
    if(-not [IO.File]::Exists($gate)){throw ('Controller fixture did not start DNS: '+($controller.Streams.Error -join ' '))}
    $workerId=[int][IO.File]::ReadAllText($gate);$controller.Stop();try{[void]$controller.EndInvoke($pending)}catch{}
    $partial=[IO.File]::ReadAllText((Join-Path $interruptedRoot 'connection-check-last.json'))|ConvertFrom-Json
    $partialText=[IO.File]::ReadAllText($partial.TextFile)
    Check 'interruption preserves the complete requested target plan' ($partial.Completion -eq 'Interrupted' -and $partial.Targets.Count -eq 2)
    Check 'interruption preserves its started DNS observation as cancelled' ($partial.Targets[0].DnsAttempts.Count -eq 1 -and $partial.Targets[0].DnsAttempts[0].Reason -eq 'Cancelled' -and $partial.Targets[0].DnsAttempts[0].WorkerId -eq $workerId)
    if($partial.Targets.Count -eq 2){Check 'unstarted targets are explicitly not run' ($partial.Targets[1].Execution -eq 'NOT_RUN')}
    Check 'interrupted text report declares incomplete execution' ($partialText.Contains('прерван'))
    $gone=$false;try{[Diagnostics.Process]::GetProcessById($workerId).Dispose()}catch{$gone=$true}
    Check 'runspace cancellation leaves no owned DNS worker' $gone
}finally{$controller.Dispose()}
if($fails){exit 1}
Write-Host 'Real staged connection clients passed.'
