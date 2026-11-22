using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace ZapretVoice {
    public sealed class TraceStatus { public bool Known, Exists; public string LogPath="",Error=""; public long EventsLost; public uint Code; }
    public static class TraceSession {
        [StructLayout(LayoutKind.Sequential)] struct Wnode { public uint BufferSize,ProviderId;public ulong HistoricalContext;public long TimeStamp;public Guid Guid;public uint ClientContext,Flags; }
        [StructLayout(LayoutKind.Sequential)] struct Properties {
            public Wnode Wnode;
            public uint BufferSize,MinimumBuffers,MaximumBuffers,MaximumFileSize,LogFileMode,FlushTimer,EnableFlags;
            public int AgeLimit;
            public uint NumberOfBuffers,FreeBuffers,EventsLost,BuffersWritten,LogBuffersLost,RealTimeBuffersLost;
            public IntPtr LoggerThreadId;
            public uint LogFileNameOffset,LoggerNameOffset;
        }
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] static extern uint ControlTraceW(ulong handle,string name,IntPtr properties,uint command);
        public static TraceStatus Query(string session) {
            if(session==null || !System.Text.RegularExpressions.Regex.IsMatch(session,"^zapretVoice-[a-f0-9]{32}$"))throw new ArgumentException("Invalid owned ETW session.");
            var result=new TraceStatus();int size=Marshal.SizeOf(typeof(Properties)),capacity=size+8192;IntPtr memory=Marshal.AllocHGlobal(capacity);
            try {
                Marshal.Copy(new byte[capacity],0,memory,capacity);
                var value=new Properties{Wnode=new Wnode{BufferSize=(uint)capacity},LoggerNameOffset=(uint)size,LogFileNameOffset=(uint)(size+2048)};
                Marshal.StructureToPtr(value,memory,false);result.Code=ControlTraceW(0,session,memory,0);
                if(result.Code==4201){result.Known=true;return result;}
                if(result.Code!=0){result.Error="ControlTrace query code "+result.Code;return result;}
                value=(Properties)Marshal.PtrToStructure(memory,typeof(Properties));result.Known=true;result.Exists=true;
                result.EventsLost=(long)value.EventsLost+value.LogBuffersLost+value.RealTimeBuffersLost;
                if(value.LogFileNameOffset>=(uint)size && value.LogFileNameOffset<(uint)(capacity-2)){
                    int offset=(int)value.LogFileNameOffset;string path=Marshal.PtrToStringUni(IntPtr.Add(memory,offset),(capacity-offset)/2);int end=path.IndexOf('\0');result.LogPath=end>=0?path.Substring(0,end):"";
                }
            } finally {Marshal.FreeHGlobal(memory);}
            return result;
        }
    }
    public sealed class Parsed { public bool Valid, Success, Mapped; public string Reason="MalformedResponse"; }
    public static class Stun {
        static int Word(byte[] data,int at){return (data[at]<<8)|data[at+1];}
        static uint Fingerprint(byte[] data,int length){
            uint crc=0xffffffff;
            for(int i=0;i<length;i++){crc^=data[i];for(int bit=0;bit<8;bit++)crc=(crc>>1)^((crc&1)!=0?0xedb88320u:0u);}
            return (~crc)^0x5354554eu;
        }
        public static byte[] Request(byte[] transaction) {
            if(transaction==null || transaction.Length!=12)throw new ArgumentException("STUN transaction must be 12 bytes.");
            byte[] packet=new byte[20];packet[1]=1;packet[4]=0x21;packet[5]=0x12;packet[6]=0xa4;packet[7]=0x42;Buffer.BlockCopy(transaction,0,packet,8,12);return packet;
        }
        public static Parsed Parse(byte[] data,byte[] transaction) {
            var result=new Parsed();
            if(data==null || data.Length<20 || data.Length>2048 || transaction==null || transaction.Length!=12 || (data[0]&0xc0)!=0 || data[4]!=0x21 || data[5]!=0x12 || data[6]!=0xa4 || data[7]!=0x42)return result;
            int length=Word(data,2);if(length%4!=0 || length+20!=data.Length)return result;
            for(int i=0;i<12;i++)if(data[8+i]!=transaction[i]){result.Reason="TransactionMismatch";return result;}
            int type=Word(data,0);if(type!=0x0101 && type!=0x0111)return result;
            bool error=false;
            for(int at=20;at<data.Length;){
                if(at+4>data.Length)return result;int kind=Word(data,at),size=Word(data,at+2);at+=4;
                if(at+size>data.Length)return result;
                if(kind==0x0020){
                    if(size<4 || data[at]!=0 || !((data[at+1]==1 && size==8)||(data[at+1]==2 && size==20)))return result;
                    result.Mapped=true;
                }
                if(kind==0x0009){if(size<4 || data[at]!=0 || data[at+1]!=0 || data[at+2]<3 || data[at+2]>6 || data[at+3]>99)return result;error=true;}
                // This unauthenticated Binding usage accepts no unknown required extensions.
                if(kind<0x8000 && kind!=0x0020 && kind!=0x0009)return result;
                if(kind==0x8028){
                    if(size!=4 || at+4!=data.Length)return result;
                    uint expected=Fingerprint(data,at-4),actual=((uint)data[at]<<24)|((uint)data[at+1]<<16)|((uint)data[at+2]<<8)|data[at+3];
                    if(actual!=expected)return result;
                }
                at+=(size+3)&~3;if(at>data.Length)return result;
            }
            if(type==0x0101 && result.Mapped){result.Valid=true;result.Success=true;result.Reason="BindingResponse";}
            else if(type==0x0111 && error){result.Valid=true;result.Reason="ErrorResponse";}
            return result;
        }
    }
    public sealed class Result {
        public string Address, State="UNKNOWN",Reason="ControllerError",Error="";
        public int Port,SentBytes,ReceivedBytes,Datagrams,Rejected;
        public bool ResponseValidated, MappedAddressPresent;
        public double ElapsedMs;
        public string Evidence="StunControl",SourceHash=Probe.SourceHash;
    }
    public sealed class Probe : IDisposable {
        public const string SourceHash="__SOURCE_HASH__";
        readonly UdpClient client;
        readonly CancellationTokenSource stop=new CancellationTokenSource();
        readonly CancellationToken token;
        readonly IPEndPoint endpoint;
        int cancelled;
        public Task<Result> Completion {get;private set;}
        public Probe(string address,int port,int timeoutMs) {
            IPAddress ip;if(!IPAddress.TryParse(address,out ip) || port<1 || port>65535 || timeoutMs<1 || timeoutMs>5000)throw new ArgumentException("Invalid STUN control endpoint.");
            endpoint=new IPEndPoint(ip,port);client=new UdpClient(ip.AddressFamily);
            try{client.Connect(endpoint);token=stop.Token;stop.CancelAfter(timeoutMs);Completion=Run();}
            catch{client.Close();stop.Dispose();throw;}
        }
        static void Observe(Task task){task.ContinueWith(t=>GC.KeepAlive(t.Exception),CancellationToken.None,TaskContinuationOptions.OnlyOnFaulted|TaskContinuationOptions.ExecuteSynchronously,TaskScheduler.Default);}
        async Task<Result> Run() {
            var result=new Result{Address=endpoint.Address.ToString(),Port=endpoint.Port};var clock=Stopwatch.StartNew();
            byte[] transaction=new byte[12];using(var random=RandomNumberGenerator.Create())random.GetBytes(transaction);
            byte[] request=Stun.Request(transaction);
            using(token.Register(()=>client.Close())) {
                try {
                    result.SentBytes=await client.SendAsync(request,request.Length).ConfigureAwait(false);
                    while(result.Datagrams<8) {
                        var receive=client.ReceiveAsync();var interrupted=new TaskCompletionSource<bool>();
                        using(token.Register(()=>interrupted.TrySetResult(true))){if(await Task.WhenAny(receive,interrupted.Task).ConfigureAwait(false)!=receive){Observe(receive);throw new OperationCanceledException(token);}}
                        var datagram=await receive.ConfigureAwait(false);result.Datagrams++;result.ReceivedBytes+=datagram.Buffer.Length;
                        if(!datagram.RemoteEndPoint.Equals(endpoint)){result.Rejected++;continue;}
                        var parsed=Stun.Parse(datagram.Buffer,transaction);
                        if(!parsed.Valid){result.Rejected++;continue;}
                        result.ResponseValidated=true;result.MappedAddressPresent=parsed.Mapped;result.State=parsed.Success?"OK":"ERROR_RESPONSE";result.Reason=parsed.Reason;break;
                    }
                    if(!result.ResponseValidated)result.Reason="MalformedResponses";
                } catch(Exception error) {
                    if(token.IsCancellationRequested)result.Reason=Volatile.Read(ref cancelled)!=0?"Cancelled":"Timeout";
                    else result.Reason="SocketError";
                    result.Error=error.GetBaseException().Message;
                } finally {client.Close();result.ElapsedMs=clock.Elapsed.TotalMilliseconds;}
            }
            stop.Dispose();return result;
        }
        public void Cancel(){Interlocked.Exchange(ref cancelled,1);try{stop.Cancel();}catch(ObjectDisposedException){}}
        public void Dispose(){Cancel();client.Close();}
    }
}
