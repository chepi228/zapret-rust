# RFC8489 control probes against an owned loopback UDP fixture only.
param([string]$Pkg=(Split-Path -Parent (Split-Path -Parent $PSScriptRoot)))
if(Test-Path (Join-Path $Pkg '.git')){throw 'Run on a package copy.'}
$ErrorActionPreference='Stop'
. (Join-Path $Pkg 'tools/lib.ps1')
. (Join-Path $Pkg 'tools/voiceprobe.ps1')
$fails=0
function Check($Name,$Ok){if($Ok){Write-Host ('ok '+$Name)}else{$script:fails++;Write-Host ('FAIL '+$Name)}}
Initialize-VoiceProbeRuntime
$tx=[byte[]](1..12);$request=[ZapretVoice.Stun]::Request($tx)
Check 'binding request uses cookie and 96-bit transaction ID' ($request.Length -eq 20 -and $request[1] -eq 1 -and $request[4] -eq 0x21 -and $request[7] -eq 0x42 -and $request[19] -eq 12)
function Response([byte[]]$Transaction){
    [byte[]]$data=New-Object byte[] 32;$data[0]=1;$data[1]=1;$data[3]=12;$data[4]=0x21;$data[5]=0x12;$data[6]=0xa4;$data[7]=0x42;[Array]::Copy($Transaction,0,$data,8,12)
    $data[21]=0x20;$data[23]=8;$data[25]=1;$data[26]=0x33;$data[27]=0x44;$data[28]=0x21;$data[29]=0x12;$data[30]=0xa4;$data[31]=0x43
    return ,$data
}
$valid=Response $tx;$parsed=[ZapretVoice.Stun]::Parse($valid,$tx)
Check 'binding success requires a valid mapped-address attribute' ($parsed.Valid -and $parsed.Success -and $parsed.Mapped)
$bad=$valid.Clone();$bad[8]=99
Check 'wrong transaction cannot become UDP success' (-not [ZapretVoice.Stun]::Parse($bad,$tx).Valid)
$bad=$valid.Clone();$bad[4]=0
Check 'wrong magic cookie is rejected' (-not [ZapretVoice.Stun]::Parse($bad,$tx).Valid)
$bad=$valid.Clone();$bad[23]=20
Check 'attribute overrun is rejected' (-not [ZapretVoice.Stun]::Parse($bad,$tx).Valid)
Check 'bare success header without mandatory address is rejected' (-not [ZapretVoice.Stun]::Parse([byte[]]$valid[0..19],$tx).Valid)
$fingerprint=[Convert]::FromBase64String('AQEAFCESpEIBAgMEBQYHCAkKCwwAIAAIAAEzRCESpEOAKAAEA/yZhA==')
Check 'independently computed CRC32 fingerprint is accepted' ([ZapretVoice.Stun]::Parse($fingerprint,$tx).Valid)
$bad=$fingerprint.Clone();$bad[39]=$bad[39] -bxor 1
Check 'corrupt fingerprint cannot become UDP success' (-not [ZapretVoice.Stun]::Parse($bad,$tx).Valid)
$bad=[byte[]]($valid+[byte[]](0x40,1,0,0));$bad[3]=16
Check 'unknown comprehension-required attribute invalidates the response' (-not [ZapretVoice.Stun]::Parse($bad,$tx).Valid)
$optional=[byte[]]($valid+[byte[]](0xc0,1,0,0));$optional[3]=16
Check 'unknown comprehension-optional attribute is ignored' ([ZapretVoice.Stun]::Parse($optional,$tx).Valid)
$bad=[byte[]]($valid+[byte[]](0,8,0,0));$bad[3]=16
Check 'unsupported malformed MESSAGE-INTEGRITY cannot become success' (-not [ZapretVoice.Stun]::Parse($bad,$tx).Valid)
Add-Type -Language CSharp -TypeDefinition @'
namespace VoiceFixture {
    public sealed class Server : System.IDisposable {
        readonly System.Net.Sockets.UdpClient udp=new System.Net.Sockets.UdpClient(new System.Net.IPEndPoint(System.Net.IPAddress.Loopback,0));
        readonly string mode;
        public int Port {get{return ((System.Net.IPEndPoint)udp.Client.LocalEndPoint).Port;}}
        public Server(string mode){this.mode=mode;System.Threading.Tasks.Task.Run((System.Action)Run);}
        void Run(){try{
            var remote=new System.Net.IPEndPoint(System.Net.IPAddress.Any,0);byte[] request=udp.Receive(ref remote);if(mode=="silence")return;
            byte[] response=new byte[32];response[0]=1;response[1]=1;response[3]=12;System.Buffer.BlockCopy(request,4,response,4,16);
            response[21]=0x20;response[23]=8;response[25]=1;response[26]=0x33;response[27]=0x44;response[28]=0x21;response[29]=0x12;response[30]=0xa4;response[31]=0x43;
            if(mode=="wrong"){response[8]^=1;udp.Send(response,response.Length,remote);return;}
            if(mode=="noise"){byte[] wrong=(byte[])response.Clone();wrong[8]^=1;udp.Send(wrong,wrong.Length,remote);}
            if(mode=="flood"){response[8]^=1;for(int i=0;i<10;i++)udp.Send(response,response.Length,remote);return;}
            udp.Send(response,response.Length,remote);
        }catch(System.Net.Sockets.SocketException){}catch(System.ObjectDisposedException){}}
        public void Dispose(){udp.Close();}
    }
}
'@ -ErrorAction Stop
foreach($mode in @('normal','noise','wrong','flood','silence','cancel')){
    $server=New-Object VoiceFixture.Server($(if($mode -eq 'cancel'){'silence'}else{$mode}));$probe=$null
    try{
        $probe=New-Object ZapretVoice.Probe('127.0.0.1',$server.Port,600)
        if($mode -eq 'cancel'){Start-Sleep -Milliseconds 50;$probe.Cancel()}
        $row=$probe.Completion.GetAwaiter().GetResult()
        $success=$mode -in @('normal','noise')
        Check ($mode+' actual UDP outcome') ($row.ResponseValidated -eq $success -and $row.ElapsedMs -lt 2000)
        if($mode -eq 'noise'){Check 'mismatched datagram is ignored before matching response' ($row.Rejected -eq 1 -and $row.State -eq 'OK')}
        if($mode -eq 'flood'){Check 'malformed response processing has a datagram cap' ($row.Datagrams -eq 8 -and $row.Reason -eq 'MalformedResponses')}
        if($mode -eq 'cancel'){Check 'cancellation is explicit' ($row.Reason -eq 'Cancelled' -and $row.State -eq 'UNKNOWN')}
    }finally{if($probe){$probe.Dispose()};$server.Dispose()}
}
$server=New-Object VoiceFixture.Server('normal')
try{
    $ps=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe';$log=Join-Path $Script:Runtime 'voice-cli.log'
    & $ps -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $Pkg 'tools/discord-voice.ps1') -ControlOnly -StunHost 127.0.0.1 -StunPort $server.Port -DurationSec 1 *> $log
    $code=$LASTEXITCODE;$saved=[IO.File]::ReadAllText((Join-Path $Script:Runtime 'voice-check-last.json'))|ConvertFrom-Json
    Check 'normal CLI control-only mode persists actual loopback evidence without capture' ($code -eq 0 -and $saved.Capture.Reason -eq 'ControlOnly' -and @($saved.Control|Where-Object{$_.ResponseValidated}).Count -ge 1 -and $saved.Assessment.Audio -eq 'NotProvided')
}finally{$server.Dispose()}
if($fails){exit 1}
Write-Host 'Voice STUN loopback passed.'
