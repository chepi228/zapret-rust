# Optional web diagnostics. Importing this module starts no processes or network requests.
function Convert-WebCurlCapabilities([string]$VersionText) {
    $available=$VersionText -match '(?m)^curl [0-9]+\.'
    $https=$false;if($VersionText -match '(?m)^Protocols:\s*(.+)$'){$https=@($matches[1].Trim() -split '\s+') -contains 'https'}
    $available=$available -and $https
    $features=@();if($VersionText -match '(?m)^Features:\s*(.+)$'){$features=@($matches[1].Trim() -split '\s+')}
    return [pscustomobject]@{Available=$available;Http2=($available -and $features -contains 'HTTP2');Http3=($available -and $features -contains 'HTTP3');Version=($VersionText -split '\r?\n')[0]}
}
function Convert-WebProtocolResult($Target,[string]$Mode,[string]$Protocol,[int]$StatusCode,[bool]$Complete,[double]$ElapsedMs,[string]$Failure) {
    $observed=switch -Regex ($Protocol.ToLowerInvariant()) {'^(?:http/)?1\.0$'{'http/1.0';break};'^(?:http/)?1\.1$'{'http/1.1';break};'^(?:h2|2(?:\.0)?|http/2)$'{'h2';break};'^(?:h3|3(?:\.0)?|http/3)$'{'h3';break};default{$Protocol}}
    $protocolOk=switch($Mode){'Http2'{$observed -eq 'h2'};'Http3'{$observed -eq 'h3'};'BrowserTcp'{$observed -in @('http/1.0','http/1.1','h2')};default{$observed -in @('http/1.0','http/1.1','h2','h3')}}
    $confirmed=$StatusCode -ge 100 -and $StatusCode -le 599 -and $protocolOk
    $state='UNKNOWN';$reason=$Failure
    if($Failure -eq 'Unavailable'){$state='UNAVAILABLE'}
    elseif($Failure -in @('ControllerError','Cancelled','UnsupportedScheme')){$state='UNKNOWN'}
    elseif($Failure){$state='FAIL'}
    elseif(-not $Complete -or $StatusCode -lt 100 -or $StatusCode -gt 599){$reason='Incomplete'}
    elseif(-not $protocolOk){$reason='ProtocolMismatch'}
    elseif($StatusCode -ge 400){$state='HTTP_ERROR';$reason='HttpStatus'}
    elseif($StatusCode -ge 200){$state='OK';$reason='Completed'}
    else{$reason='Incomplete'}
    return [pscustomobject]@{Group=$Target.Group;Name=$Target.Name;Url=$Target.Url;FinalUrl=$Target.Url;Mode=$Mode;ObservedProtocol=$observed;StatusCode=$StatusCode;Complete=$Complete;ProtocolConfirmed=[bool]$confirmed;QuicConfirmed=($confirmed -and $observed -eq 'h3');State=$state;Reason=$reason;Error='';ElapsedMs=[math]::Round($ElapsedMs,1);Sample=1;EncodedBytes=$null;SessionRestarted=$false;Evidence=$(if($Mode -in @('Http2','Http3')){'Headers'}else{'MainDocument'})}
}
function Get-WebCheckTargets($Targets) {
    foreach($key in @('YouTube.web','Discord.main','Clean.bing')) {
        $match=@($Targets|Where-Object{($_.Group+'.'+$_.Name) -eq $key})
        if($match.Count){$match[0]}
    }
}
function Read-WebVerificationTargets {
    $targets=@()
    foreach($line in [IO.File]::ReadAllLines((Get-PkgPath 'tools/targets.txt'))){
        if($line.Trim() -match '^([A-Za-z0-9]+)\.([A-Za-z0-9_]+)\s*=\s*(https?://\S+)$'){$targets+=@([pscustomobject]@{Group=$matches[1];Name=$matches[2];Url=$matches[3]})}
    }
    return @(Get-WebCheckTargets $targets)
}
function Assert-WebProbeUrl([string]$Url) {
    $uri=$null
    if($Url.Length -gt 2048 -or -not [Uri]::TryCreate($Url,[UriKind]::Absolute,[ref]$uri) -or $uri.UserInfo -or ($uri.Scheme -ne 'https' -and -not ($uri.Scheme -eq 'http' -and $uri.IsLoopback))){throw 'Нужен HTTPS-адрес без имени пользователя и пароля.'}
    return $uri.AbsoluteUri
}
function Initialize-WebProbeRuntime {
    if('ZapretWeb.BrowserProcess' -as [type]){return}
    Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Net.WebSockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace ZapretWeb {
    public sealed class BrowserProcess : IDisposable {
        [StructLayout(LayoutKind.Sequential)] struct BasicLimits {
            public long ProcessTime, JobTime;
            public uint Flags;
            public UIntPtr MinWorkingSet, MaxWorkingSet;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint Priority, Scheduling;
        }
        [StructLayout(LayoutKind.Sequential)] struct IoCounters { public ulong ReadOperations, WriteOperations, OtherOperations, ReadBytes, WriteBytes, OtherBytes; }
        [StructLayout(LayoutKind.Sequential)] struct ExtendedLimits {
            public BasicLimits Basic;
            public IoCounters Io;
            public UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
        }
        [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct StartupInfo {
            public uint Size;
            public string Reserved, Desktop, Title;
            public uint X, Y, XSize, YSize, XCountChars, YCountChars, FillAttribute, Flags;
            public ushort ShowWindow, ReservedSize;
            public IntPtr ReservedData, StdInput, StdOutput, StdError;
        }
        [StructLayout(LayoutKind.Sequential)] struct ProcessInfo { public IntPtr Process, Thread; public uint ProcessId, ThreadId; }
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateJobObject(IntPtr security,string name);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job,int kind,ref ExtendedLimits info,uint length);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcess(string executable,StringBuilder command,IntPtr processSecurity,IntPtr threadSecurity,bool inherit,uint flags,IntPtr environment,string directory,ref StartupInfo startup,out ProcessInfo process);
        [DllImport("kernel32.dll",SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
        [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr handle,uint timeout);
        [DllImport("kernel32.dll")] static extern bool TerminateProcess(IntPtr process,uint code);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
        IntPtr job, process;
        public uint Id {get;private set;}
        public bool Exited {get{return process==IntPtr.Zero || WaitForSingleObject(process,0)==0;}}
        BrowserProcess(){}
        public static string Quote(string value) {
            StringBuilder quoted=new StringBuilder("\"");int slashes=0;
            foreach(char c in value) {
                if(c=='\\'){slashes++;continue;}
                if(c=='"'){quoted.Append('\\',slashes*2+1).Append(c);slashes=0;continue;}
                quoted.Append('\\',slashes).Append(c);slashes=0;
            }
            return quoted.Append('\\',slashes*2).Append('"').ToString();
        }
        public static BrowserProcess Start(string executable,string[] arguments) {
            BrowserProcess owner=new BrowserProcess();ProcessInfo child=new ProcessInfo();bool resumed=false;
            try {
                owner.job=CreateJobObject(IntPtr.Zero,null);
                if(owner.job==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
                ExtendedLimits limits=new ExtendedLimits();limits.Basic.Flags=0x2000; // KILL_ON_JOB_CLOSE
                if(!SetInformationJobObject(owner.job,9,ref limits,(uint)Marshal.SizeOf(typeof(ExtendedLimits))))throw new Win32Exception(Marshal.GetLastWin32Error());
                StringBuilder command=new StringBuilder(Quote(executable));foreach(string argument in arguments)command.Append(' ').Append(Quote(argument));
                StartupInfo startup=new StartupInfo();startup.Size=(uint)Marshal.SizeOf(typeof(StartupInfo));startup.Flags=1;startup.ShowWindow=0;
                // Own the entire tree before the first browser instruction can spawn a child.
                if(!CreateProcess(executable,command,IntPtr.Zero,IntPtr.Zero,false,0x08000004,IntPtr.Zero,Path.GetDirectoryName(executable),ref startup,out child))throw new Win32Exception(Marshal.GetLastWin32Error());
                owner.process=child.Process;owner.Id=child.ProcessId;
                if(!AssignProcessToJobObject(owner.job,child.Process))throw new Win32Exception(Marshal.GetLastWin32Error());
                if(ResumeThread(child.Thread)==0xffffffff)throw new Win32Exception(Marshal.GetLastWin32Error());
                resumed=true;return owner;
            } catch {if(child.Process!=IntPtr.Zero && !resumed)TerminateProcess(child.Process,1);owner.Dispose();throw;}
            finally {if(child.Thread!=IntPtr.Zero)CloseHandle(child.Thread);}
        }
        public void Dispose(){
            IntPtr ownedJob=Interlocked.Exchange(ref job,IntPtr.Zero);if(ownedJob!=IntPtr.Zero)CloseHandle(ownedJob);
            IntPtr ownedProcess=Interlocked.Exchange(ref process,IntPtr.Zero);if(ownedProcess!=IntPtr.Zero){WaitForSingleObject(ownedProcess,2000);CloseHandle(ownedProcess);}
            GC.SuppressFinalize(this);
        }
        ~BrowserProcess(){Dispose();}
    }
    public sealed class DevToolsSocket : IDisposable {
        readonly ClientWebSocket socket=new ClientWebSocket();
        public void Connect(string url,int timeoutMs){using(var cancel=new CancellationTokenSource(timeoutMs)){socket.ConnectAsync(new Uri(url),cancel.Token).GetAwaiter().GetResult();}}
        public void Send(string json,int timeoutMs){
            byte[] data=Encoding.UTF8.GetBytes(json);
            using(var cancel=new CancellationTokenSource(timeoutMs)){socket.SendAsync(new ArraySegment<byte>(data),WebSocketMessageType.Text,true,cancel.Token).GetAwaiter().GetResult();}
        }
        public string Receive(int timeoutMs){
            byte[] buffer=new byte[8192];
            using(var cancel=new CancellationTokenSource(timeoutMs))using(var output=new MemoryStream()){
                while(true){
                    var frame=socket.ReceiveAsync(new ArraySegment<byte>(buffer),cancel.Token).GetAwaiter().GetResult();
                    if(frame.MessageType!=WebSocketMessageType.Text)throw new IOException("DevTools connection closed or sent a non-text message.");
                    if(output.Length+frame.Count>1048576)throw new IOException("DevTools message exceeded 1 MiB.");
                    output.Write(buffer,0,frame.Count);
                    if(frame.EndOfMessage)return Encoding.UTF8.GetString(output.ToArray());
                }
            }
        }
        public void Dispose(){socket.Abort();socket.Dispose();}
    }
}
'@ -ErrorAction Stop
}
function Invoke-WebCurlCommand([string]$Path,[string[]]$Arguments,[int]$TimeoutMs) {
    Initialize-WebProbeRuntime
    $process=New-Object Diagnostics.Process
    $process.StartInfo=New-Object Diagnostics.ProcessStartInfo
    $process.StartInfo.FileName=$Path;$process.StartInfo.Arguments=(@($Arguments|ForEach-Object{[ZapretWeb.BrowserProcess]::Quote($_)}) -join ' ')
    $process.StartInfo.UseShellExecute=$false;$process.StartInfo.CreateNoWindow=$true
    $process.StartInfo.RedirectStandardOutput=$true;$process.StartInfo.RedirectStandardError=$true
    try {
        if(-not $process.Start()){throw 'curl did not start'}
        $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
        if(-not $process.WaitForExit($TimeoutMs)){$process.Kill();$process.WaitForExit();return [pscustomobject]@{Exit=28;Output='';Error='Timeout'}}
        return [pscustomobject]@{Exit=$process.ExitCode;Output=$stdout.GetAwaiter().GetResult();Error=$stderr.GetAwaiter().GetResult()}
    } finally {try{if(-not $process.HasExited){$process.Kill()}}catch{};$process.Dispose()}
}
function Get-WebProbeCapabilities {
    $curlPath='';$curl=Convert-WebCurlCapabilities ''
    try{$command=Get-Command curl.exe -CommandType Application -ErrorAction Stop|Select-Object -First 1;$curlPath=$command.Source;$version=Invoke-WebCurlCommand $curlPath @('--disable','--version') 3000;if($version.Exit -eq 0){$curl=Convert-WebCurlCapabilities $version.Output}}catch{}
    $browserPath='';$browserVersion=''
    foreach($path in @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe","$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe","$env:LOCALAPPDATA\Microsoft\Edge\Application\msedge.exe","$env:ProgramFiles\Google\Chrome\Application\chrome.exe","${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe","$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe")){
        if(Test-Path -LiteralPath $path -PathType Leaf){$browserPath=$path;$browserVersion=(Get-Item -LiteralPath $path).VersionInfo.ProductVersion;break}
    }
    return [pscustomobject]@{CurlPath=$curlPath;Curl=$curl;BrowserPath=$browserPath;BrowserVersion=$browserVersion}
}
function Invoke-WebCurlProbe($Target,[ValidateSet('Http2','Http3')][string]$Mode,$Capabilities,[ValidateRange(1,30)][int]$TimeoutSec=8) {
    $url=Assert-WebProbeUrl $Target.Url
    $supported=if($Mode -eq 'Http2'){$Capabilities.Curl.Http2}else{$Capabilities.Curl.Http3}
    if(-not $Capabilities.CurlPath -or -not $supported){return Convert-WebProtocolResult $Target $Mode '' 0 $false 0 'Unavailable'}
    if(([Uri]$url).Scheme -ne 'https'){return Convert-WebProtocolResult $Target $Mode '' 0 $false 0 'UnsupportedScheme'}
    $option=if($Mode -eq 'Http2'){'--http2'}else{'--http3-only'}
    $clock=[Diagnostics.Stopwatch]::StartNew()
    try {
        $answer=Invoke-WebCurlCommand $Capabilities.CurlPath @('--disable','--silent','--show-error','--noproxy','*',$option,'--head','--location','--max-redirs','5','--proto','=https','--proto-redir','=https','--connect-timeout',[string]$TimeoutSec,'--max-time',[string]$TimeoutSec,'--output','NUL','--write-out','%{http_code}|%{http_version}|%{url_effective}','--url',$url) ($TimeoutSec*1000+1000)
        $code=0;$protocol='';$finalUrl=$url
        if($answer.Output.Trim() -match '^([0-9]{3})\|([^|]*)\|(.+)$'){$code=[int]$matches[1];$protocol=$matches[2];$finalUrl=$matches[3]}
        $failure=if($answer.Exit -eq 0){''}elseif($answer.Exit -in @(2,4)){'Unavailable'}elseif($answer.Exit -eq 28){'Timeout'}else{'RequestFailed'}
        $row=Convert-WebProtocolResult $Target $Mode $protocol $code ($answer.Exit -eq 0) $clock.Elapsed.TotalMilliseconds $failure
        $row.FinalUrl=$finalUrl;$row.Error=([string]$answer.Error).Trim();if($row.Error.Length -gt 1024){$row.Error=$row.Error.Substring(0,1024)}
        return $row
    } catch {$row=Convert-WebProtocolResult $Target $Mode '' 0 $false $clock.Elapsed.TotalMilliseconds 'ControllerError';$row.Error=$_.Exception.Message;return $row}
}
function Get-WebRemainingMs([long]$Deadline) {
    $remaining=[math]::Ceiling(($Deadline-[Diagnostics.Stopwatch]::GetTimestamp())*1000.0/[Diagnostics.Stopwatch]::Frequency)
    if($remaining -le 0){throw (New-Object TimeoutException 'Web probe deadline expired.')}
    return [int][math]::Min(30000,$remaining)
}
function Invoke-WebDevToolsCommand([hashtable]$Connection,[string]$Method,[hashtable]$Parameters,[long]$Deadline) {
    $Connection.Sequence++
    $command=@{id=$Connection.Sequence;method=$Method;params=$Parameters}
    if($Connection.Session){$command.sessionId=$Connection.Session}
    $Connection.Socket.Send((ConvertTo-Json -InputObject $command -Depth 8 -Compress),(Get-WebRemainingMs $Deadline))
    while($true) {
        $message=$Connection.Socket.Receive((Get-WebRemainingMs $Deadline))|ConvertFrom-Json -ErrorAction Stop
        if($message.PSObject.Properties['id'] -and $message.id -eq $Connection.Sequence){
            if($message.PSObject.Properties['error']){throw ('DevTools rejected '+$Method)}
            return $message.result
        }
        if($message.PSObject.Properties['method']){
            if($Connection.Events.Count -ge 2048){throw 'DevTools event queue exceeded its limit.'}
            $Connection.Events.Enqueue($message)
        }
    }
}
function Update-WebNavigation([hashtable]$Navigation,$Event) {
    if(-not $Event.PSObject.Properties['method'] -or -not $Event.PSObject.Properties['params']){return}
    $p=$Event.params
    if($Event.method -eq 'Network.requestWillBeSent' -and $p.type -eq 'Document' -and $p.frameId -eq $Navigation.FrameId -and $p.loaderId -eq $Navigation.LoaderId){
        $Navigation.RequestId=$p.requestId;$Navigation.Url=$p.request.url;$Navigation.Protocol='';$Navigation.StatusCode=0;$Navigation.Complete=$false;$Navigation.Done=$false;$Navigation.Failure='';$Navigation.EncodedBytes=$null
    }elseif($Event.method -eq 'Network.responseReceived' -and $p.type -eq 'Document' -and $p.frameId -eq $Navigation.FrameId -and $p.requestId -eq $Navigation.RequestId){
        $Navigation.Url=$p.response.url;$Navigation.Protocol=$p.response.protocol;$Navigation.StatusCode=[int]$p.response.status
    }elseif($Event.method -eq 'Network.loadingFinished' -and $p.requestId -eq $Navigation.RequestId -and $Navigation.StatusCode -ge 100){
        $Navigation.Complete=$true;$Navigation.Done=$true
        if($p.PSObject.Properties['encodedDataLength'] -and $p.encodedDataLength -ge 0){$Navigation.EncodedBytes=[long]$p.encodedDataLength}
    }elseif($Event.method -eq 'Network.loadingFailed' -and $p.requestId -eq $Navigation.RequestId){
        $Navigation.Failure=$p.errorText;$Navigation.Done=$true
    }
}
function Get-WebBrowserRequestFailure([string]$ErrorText) {
    if($ErrorText -in @('net::ERR_TIMED_OUT','net::ERR_CONNECTION_TIMED_OUT')){return 'Timeout'}
    return 'RequestFailed'
}
function Remove-WebBrowserProfile([string]$Path) {
    $absolute=[IO.Path]::GetFullPath($Path);$temp=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
    if([IO.Path]::GetDirectoryName($absolute) -cne $temp -or [IO.Path]::GetFileName($absolute) -cnotmatch '^zapret-web-[a-f0-9]{32}$'){throw 'Unsafe browser profile cleanup path.'}
    if(-not [IO.Directory]::Exists($absolute)){return $true}
    for($attempt=0;$attempt -lt 20;$attempt++){
        try{
            $pending=New-Object System.Collections.Generic.Queue[string];$pending.Enqueue($absolute)
            while($pending.Count){
                $directory=$pending.Dequeue()
                if((Get-Item -LiteralPath $directory -Force -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Unexpected reparse point in browser profile.'}
                foreach($item in @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop)){
                    if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Unexpected reparse point in browser profile.'}
                    if($item.PSIsContainer){$pending.Enqueue($item.FullName)}
                }
            }
            Remove-Item -LiteralPath $absolute -Recurse -Force -ErrorAction Stop
            return $true
        }catch{if($attempt -eq 19){return $false};Start-Sleep -Milliseconds 50}
    }
}
function Wait-WebBrowserEndpoint([string]$PortFile,$Owner,[long]$Deadline) {
    while($true){
        Get-WebRemainingMs $Deadline|Out-Null
        if($Owner.Exited){throw 'Browser exited before remote debugging was available.'}
        if([IO.File]::Exists($PortFile)){
            try{
                $lines=@([IO.File]::ReadAllLines($PortFile));$port=0
                if($lines.Count -ge 2 -and [int]::TryParse($lines[0],[ref]$port) -and $port -ge 1 -and $port -le 65535 -and $lines[1] -cmatch '^/devtools/browser/[a-zA-Z0-9-]+$'){
                    return ('ws://127.0.0.1:'+$port+$lines[1])
                }
            }catch [IO.IOException]{
                # Chromium can expose the file before closing its exclusive writer.
                $code=$_.Exception.GetBaseException().HResult -band 0xffff
                if($code -notin @(2,3,32,33)){throw}
            }
        }
        Start-Sleep -Milliseconds 40
    }
}
function Invoke-WebBrowserProbe($Target,[ValidateSet('BrowserAuto','BrowserTcp')][string]$Mode,[string]$BrowserPath,[ValidateRange(1,30)][int]$TimeoutSec=8,[ValidateRange(1,2)][int]$Visits=2,[long]$DeadlineTicks=0) {
    $url=Assert-WebProbeUrl $Target.Url
    if(-not $BrowserPath -or -not (Test-Path -LiteralPath $BrowserPath -PathType Leaf)){return Convert-WebProtocolResult $Target $Mode '' 0 $false 0 'Unavailable'}
    $profile=Join-Path ([IO.Path]::GetTempPath()) ('zapret-web-'+[guid]::NewGuid().ToString('N'))
    $owner=$null;$socket=$null;$rows=New-Object System.Collections.Generic.List[object];$navigation=$null;$navigating=$false;$sample=1;$cleaned=$false
    $clock=[Diagnostics.Stopwatch]::StartNew();$startupDeadline=[Diagnostics.Stopwatch]::GetTimestamp()+[long]($TimeoutSec*[Diagnostics.Stopwatch]::Frequency)
    if($DeadlineTicks -gt 0){$startupDeadline=[math]::Min($startupDeadline,$DeadlineTicks)}
    try {
        Initialize-WebProbeRuntime
        [void][IO.Directory]::CreateDirectory($profile)
        $arguments=@('--headless=new','--no-first-run','--no-default-browser-check','--disable-extensions','--disable-sync','--disable-background-networking','--disable-component-update','--no-proxy-server','--remote-debugging-address=127.0.0.1','--remote-debugging-port=0',('--user-data-dir='+$profile),'about:blank')
        if($Mode -eq 'BrowserTcp'){$arguments+=@('--disable-quic')}
        $owner=[ZapretWeb.BrowserProcess]::Start($BrowserPath,[string[]]$arguments)
        $portFile=Join-Path $profile 'DevToolsActivePort'
        $endpoint=Wait-WebBrowserEndpoint $portFile $owner $startupDeadline
        $socket=New-Object ZapretWeb.DevToolsSocket;$socket.Connect($endpoint,(Get-WebRemainingMs $startupDeadline))
        $connection=@{Socket=$socket;Sequence=0;Session='';Events=(New-Object System.Collections.Generic.Queue[object])}
        $created=Invoke-WebDevToolsCommand $connection 'Target.createTarget' @{url='about:blank'} $startupDeadline
        $attached=Invoke-WebDevToolsCommand $connection 'Target.attachToTarget' @{targetId=$created.targetId;flatten=$true} $startupDeadline
        $connection.Session=$attached.sessionId
        Invoke-WebDevToolsCommand $connection 'Page.enable' @{} $startupDeadline|Out-Null
        Invoke-WebDevToolsCommand $connection 'Network.enable' @{} $startupDeadline|Out-Null
        Invoke-WebDevToolsCommand $connection 'Network.setCacheDisabled' @{cacheDisabled=$true} $startupDeadline|Out-Null
        Invoke-WebDevToolsCommand $connection 'Network.setBypassServiceWorker' @{bypass=$true} $startupDeadline|Out-Null
        for($sample=1;$sample -le $Visits;$sample++) {
            $connection.Events.Clear();$navigation=$null;$clock.Restart()
            $deadline=[Diagnostics.Stopwatch]::GetTimestamp()+[long]($TimeoutSec*[Diagnostics.Stopwatch]::Frequency)
            if($DeadlineTicks -gt 0){$deadline=[math]::Min($deadline,$DeadlineTicks)}
            $navigating=$true
            $started=Invoke-WebDevToolsCommand $connection 'Page.navigate' @{url=$url} $deadline
            if($started.PSObject.Properties['errorText']){
                $row=Convert-WebProtocolResult $Target $Mode '' 0 $false $clock.Elapsed.TotalMilliseconds (Get-WebBrowserRequestFailure $started.errorText);$row.Error=$started.errorText;$row.Sample=$sample;$rows.Add($row);continue
            }
            if(-not $started.PSObject.Properties['loaderId']){throw 'Browser did not provide a navigation loader.'}
            $navigation=@{FrameId=$started.frameId;LoaderId=$started.loaderId;RequestId='';Url=$url;Protocol='';StatusCode=0;Complete=$false;Done=$false;Failure=''}
            while(-not $navigation.Done){
                if($connection.Events.Count){$event=$connection.Events.Dequeue()}else{$event=$socket.Receive((Get-WebRemainingMs $deadline))|ConvertFrom-Json -ErrorAction Stop}
                if($event.PSObject.Properties['sessionId'] -and $event.sessionId -ne $connection.Session){continue}
                Update-WebNavigation $navigation $event
            }
            $failure=if($navigation.Failure){Get-WebBrowserRequestFailure $navigation.Failure}else{''}
            $row=Convert-WebProtocolResult $Target $Mode $navigation.Protocol $navigation.StatusCode $navigation.Complete $clock.Elapsed.TotalMilliseconds $failure
            $row.FinalUrl=$navigation.Url;$row.Error=$navigation.Failure;$row.Sample=$sample;$row.EncodedBytes=$navigation.EncodedBytes;$rows.Add($row)
        }
    } catch {
        $cancelled=$DeadlineTicks -gt 0 -and [Diagnostics.Stopwatch]::GetTimestamp() -ge $DeadlineTicks
        $reason=if($cancelled){'Cancelled'}elseif($navigating -and (([string]$_.Exception) -match 'deadline|canceled|cancelled|timed out')){'Timeout'}else{'ControllerError'}
        $protocol='';$code=0;$finalUrl=$url
        if($navigation){$protocol=$navigation.Protocol;$code=$navigation.StatusCode;$finalUrl=$navigation.Url}
        $row=Convert-WebProtocolResult $Target $Mode $protocol $code $false $clock.Elapsed.TotalMilliseconds $reason
        $row.FinalUrl=$finalUrl;$row.Sample=$sample;$row.Error=$_.Exception.Message;$rows.Add($row)
    } finally {
        if($socket){$socket.Dispose()}
        if($owner){$owner.Dispose()}
        $cleaned=Remove-WebBrowserProfile $profile
    }
    foreach($row in $rows){$row|Add-Member -NotePropertyName CleanupComplete -NotePropertyValue $cleaned}
    # A receive timeout aborts ClientWebSocket. Give the remaining visit a fresh owned session.
    if($Visits -eq 2 -and $rows.Count -eq 1 -and $rows[0].Reason -in @('Timeout','ControllerError') -and ($DeadlineTicks -eq 0 -or [Diagnostics.Stopwatch]::GetTimestamp() -lt $DeadlineTicks)){
        foreach($retry in @(Invoke-WebBrowserProbe $Target $Mode $BrowserPath $TimeoutSec -Visits 1 -DeadlineTicks $DeadlineTicks)){
            $retry.Sample=2;$retry.SessionRestarted=$true;$rows.Add($retry)
        }
    }
    return $rows.ToArray()
}
function Get-WebVerificationContext {
    $network=Get-NetworkObservation
    try {
        $processes=@(Get-OurProcesses|Sort-Object Id|ForEach-Object{[string]$_.Id+'|'+[string]$_.StartTime.Ticks})
        $settingsPath=Get-PkgPath 'runtime/settings.ini'
        $settingsHash=if(Test-Path -LiteralPath $settingsPath){(Get-FileHash -LiteralPath $settingsPath -Algorithm SHA256 -ErrorAction Stop).Hash}else{'Absent'}
        return [pscustomobject]@{Known=$network.Known;Network=$network;Processes=$processes;SettingsHash=$settingsHash}
    }catch{return [pscustomobject]@{Known=$false;Network=$network;Processes=@();SettingsHash='Unknown'}}
}
function Format-WebVerificationReport($Result) {
    'zapret — проверка браузера и HTTP-протоколов'
    $Result.Subject
    'Начало '+$Result.StartedUtc
    $context=switch($Result.ConnectionState){'ObservedStable'{'наблюдаемые параметры сохранены'};'Changed'{'изменился за время проверки'};default{'не установлен'}}
    'Контекст подключения — '+$context
    'Проверка использует прямое подключение без прокси приложения. VPN/TUN и системные маршруты продолжают влиять на трафик.'
    'HTTP/2 и HTTP/3 проверяются запросом заголовков curl. Браузер проверяет завершение основного документа с обычной проверкой сертификата.'
    'В браузере используются временный профиль, автоматический выбор протокола и отдельный режим с выключенным QUIC. Вторая загрузка выполняется без HTTP-кэша после первого посещения.'
    'Этот результат не измеряет воспроизведение видео, голос Discord или задержку игры. Отдельный сбой не устанавливает причину недоступности.'
    if($Result.Capabilities.BrowserPath){'Браузер '+[IO.Path]::GetFileName($Result.Capabilities.BrowserPath)+' '+$Result.Capabilities.BrowserVersion}
    foreach($row in $Result.Rows){
        $label=switch($row.Mode){'Http2'{'HTTP/2 curl'};'Http3'{'HTTP/3 curl'};'BrowserAuto'{'Браузер автоматически'};'BrowserTcp'{'Браузер без QUIC'}}
        $state=switch($row.State){'OK'{'выполнено'};'HTTP_ERROR'{'HTTP-ошибка сайта'};'UNAVAILABLE'{'проверка недоступна'};'FAIL'{'запрос не завершён'};default{'результат неопределён'}}
        $reason=switch($row.Reason){'Unavailable'{'нет поддержки клиента'};'ProtocolMismatch'{'запрошенный протокол не подтверждён'};'Timeout'{'истекло время ожидания'};'ControllerError'{'ошибка запуска или управления проверкой'};'Cancelled'{'проверка прервана'};'Incomplete'{'недостаточно данных о завершении'};'UnsupportedScheme'{'для протокольной проверки нужен HTTPS'};'Completed'{'запрос завершён'};'HttpStatus'{'сайт вернул HTTP-ошибку'};'RequestFailed'{'ошибка запроса'};default{$row.Reason}}
        $protocol=if($row.ObservedProtocol){$row.ObservedProtocol}else{'не установлен'}
        $http=if($row.StatusCode){[string]$row.StatusCode}else{'не получен'}
        $label+' — '+$row.Group+'.'+$row.Name+', попытка '+$row.Sample+' — '+$state+'. Протокол '+$protocol+', HTTP '+$http+', '+$row.ElapsedMs+' мс. '+$reason
        if($row.FinalUrl -ne $row.Url){'  Итоговый адрес '+$row.FinalUrl}
        if($null -ne $row.EncodedBytes){'  Браузер сообщил '+$row.EncodedBytes+' байт для основного запроса.'}
        if($row.SessionRestarted){'  После сбоя создана новая временная сессия браузера.'}
        if($row.Error){'  '+($row.Error -replace '[\r\n]+',' ')}
        if($row.PSObject.Properties['CleanupComplete'] -and -not $row.CleanupComplete){'  Временный профиль браузера не удалось полностью удалить.'}
    }
    if($Result.Quic -eq 'Observed'){'HTTP/3 наблюдался в ответе. Успешность HTTP-запроса указана отдельно для каждой попытки.'}else{'HTTP/3 не подтверждён этими пробами. Это не устанавливает блокировку QUIC.'}
    'JSON '+$Result.JsonFile
}
function Publish-WebVerificationReports([string]$JsonFile,[string]$TextFile,[ValidateRange(100,10000)][int]$WaitMs=5000) {
    $lease=$null;$files=@();$keepBackups=$false
    $clock=[Diagnostics.Stopwatch]::StartNew()
    try {
        # A file lease also coordinates different PowerShell processes and Windows sessions.
        # Keep the lock file in place so every writer locks the same file identity.
        $lock=Join-Path $Script:Runtime 'web-check-last.lock'
        while($null -eq $lease){
            try{$lease=[IO.File]::Open($lock,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)}
            catch [IO.IOException]{
                if($clock.ElapsedMilliseconds -ge $WaitMs){throw 'Истекло время ожидания публикации последних отчётов. Именные отчёты сохранены.'}
                Start-Sleep -Milliseconds 25
            }
        }
        $generation=[guid]::NewGuid().ToString('N')
        foreach($kind in @('json','txt')){
            $target=Join-Path $Script:Runtime ('web-check-last.'+$kind)
            $files+=@([pscustomobject]@{Source=$(if($kind -eq 'json'){$JsonFile}else{$TextFile});Target=$target;Stage=(Join-Path $Script:Runtime ('web-check-last.'+$generation+'.'+$kind+'.tmp'));Backup=(Join-Path $Script:Runtime ('web-check-last.'+$generation+'.'+$kind+'.bak'));Existed=[IO.File]::Exists($target);Published=$false})
        }
        try {
            foreach($file in $files){Copy-Item -LiteralPath $file.Source -Destination $file.Stage -Force -ErrorAction Stop}
            # The JSON pointer references immutable per-run files. Publish it after the text alias.
            foreach($file in @($files[1],$files[0])){
                if($file.Existed){[IO.File]::Replace($file.Stage,$file.Target,$file.Backup)}else{[IO.File]::Move($file.Stage,$file.Target)}
                $file.Published=$true
            }
        } catch {
            $failure=$_;$rollbackErrors=New-Object System.Collections.Generic.List[string]
            foreach($file in $files){
                if(-not $file.Published){continue}
                try {
                    if($file.Existed){[IO.File]::Replace($file.Backup,$file.Target,[NullString]::Value)}else{[IO.File]::Delete($file.Target)}
                } catch {$keepBackups=$true;$rollbackErrors.Add($_.Exception.Message)}
            }
            if($rollbackErrors.Count){throw ('Не удалось вернуть предыдущие последние отчёты. Сохранены резервные файлы в '+$Script:Runtime+'. '+($rollbackErrors -join ' '))}
            throw $failure
        }
    } finally {
        try {
            foreach($file in $files){
                if([IO.File]::Exists($file.Stage)){[IO.File]::Delete($file.Stage)}
                if(-not $keepBackups -and [IO.File]::Exists($file.Backup)){[IO.File]::Delete($file.Backup)}
            }
        } finally {if($null -ne $lease){$lease.Dispose()}}
    }
}
function Invoke-WebVerification($Targets=$null,$Capabilities=$null,[ValidateRange(1,30)][int]$TimeoutSec=8,[string]$Subject='Текущее подключение',[switch]$Quiet) {
    if($null -eq $Targets){$Targets=@(Read-WebVerificationTargets)}
    $Targets=@($Targets)
    if($Targets.Count -lt 1 -or $Targets.Count -gt 6){throw 'Для проверки нужно от одного до шести адресов.'}
    foreach($target in $Targets){Assert-WebProbeUrl $target.Url|Out-Null}
    if($null -eq $Capabilities){$Capabilities=Get-WebProbeCapabilities}
    [void][IO.Directory]::CreateDirectory($Script:Runtime)
    $runId=(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8)
    $result=[pscustomobject]@{Schema=1;Kind='WebVerification';Mode='Advisory';RunId=$runId;Subject=$Subject;StartedUtc=[datetime]::UtcNow.ToString('o');FinishedUtc='';ProxyMode='Direct';Capabilities=$Capabilities;ContextBefore=(Get-WebVerificationContext);ContextAfter=$null;ConnectionState='Unknown';Quic='Unconfirmed';Rows=@();JsonFile=(Join-Path $Script:Runtime ('web-check-'+$runId+'.json'));TextFile=(Join-Path $Script:Runtime ('web-check-'+$runId+'.txt'))}
    $rows=New-Object System.Collections.Generic.List[object];$pending=$null
    try {
        foreach($target in $Targets){
            if(-not $Quiet){Write-Color ('Проверка браузера и протоколов — '+$target.Group+'.'+$target.Name) Cyan}
            foreach($mode in @('Http2','Http3','BrowserAuto','BrowserTcp')){
                $pending=[pscustomobject]@{Target=$target;Mode=$mode}
                if($mode -in @('Http2','Http3')){$observations=@(Invoke-WebCurlProbe $target $mode $Capabilities $TimeoutSec)}else{$observations=@(Invoke-WebBrowserProbe $target $mode $Capabilities.BrowserPath $TimeoutSec)}
                foreach($row in $observations){$rows.Add($row)}
                $pending=$null
            }
        }
    } finally {
        if($pending){$rows.Add((Convert-WebProtocolResult $pending.Target $pending.Mode '' 0 $false 0 'Cancelled'))}
        $result.ContextAfter=Get-WebVerificationContext
        if($result.ContextBefore.Known -and $result.ContextAfter.Known){
            $sameNetwork=Test-NetworkObservation $result.ContextBefore.Network $result.ContextAfter.Network
            $sameProcesses=($result.ContextBefore.Processes -join ',') -ceq ($result.ContextAfter.Processes -join ',')
            $sameSettings=$result.ContextBefore.SettingsHash -ceq $result.ContextAfter.SettingsHash
            $result.ConnectionState=if($sameNetwork -and $sameProcesses -and $sameSettings){'ObservedStable'}else{'Changed'}
        }
        $result.Rows=@($rows.ToArray());$result.FinishedUtc=[datetime]::UtcNow.ToString('o')
        if(@($result.Rows|Where-Object{$_.QuicConfirmed}).Count){$result.Quic='Observed'}
        Write-TextNoBom $result.JsonFile ((ConvertTo-Json -InputObject $result -Depth 9)+"`r`n")
        $text=@(Format-WebVerificationReport $result)
        Write-TextNoBom $result.TextFile (($text -join "`r`n")+"`r`n")
        Publish-WebVerificationReports $result.JsonFile $result.TextFile
    }
    if(-not $Quiet){foreach($line in $text){Write-Color $line Gray};Write-Color ('Отчёт '+$result.TextFile) Cyan}
    return $result
}
