using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace ZapretConnection {
    public sealed class Result {
        public string Address, Family, Stage="Tcp", State="UNKNOWN", Reason="ControllerError", Error="";
        public bool TcpSucceeded, TlsSucceeded, HeadersComplete, CertificateObserved;
        public int StatusCode, ReceivedBytes, HeaderBytes;
        public string CertificateErrors="NotObserved", TlsProtocol="", HttpVersion="", Validation="System";
        public bool RevocationCheck=false;
        public double? TcpMs, TlsMs, HttpMs;
        public double ElapsedMs;
        public string Evidence="Headers", Client=".NET SslStream/Schannel", SourceHash=Probe.SourceHash;
    }
    public sealed class Probe : IDisposable {
        public const string SourceHash="__SOURCE_HASH__";
        public const int HeaderLimit=32768;
        static int active;
        readonly TcpClient client;
        readonly CancellationTokenSource stop=new CancellationTokenSource();
        readonly CancellationToken token;
        readonly string host, path;
        readonly int port;
        readonly IPAddress address;
        readonly RemoteCertificateValidationCallback fixtureValidator;
        readonly string validation;
        int cancelled, certificateErrors, certificateObserved;
        public static int Active {get{return Volatile.Read(ref active);}}
        public Task<Result> Completion {get;private set;}
        Probe(string hostname,string ip,int targetPort,string resource,int timeoutMs,RemoteCertificateValidationCallback validator) {
            if(string.IsNullOrEmpty(hostname) || hostname.IndexOfAny(new[]{'\r','\n'})>=0 || !IPAddress.TryParse(ip,out address) || targetPort<1 || targetPort>65535 || string.IsNullOrEmpty(resource) || !resource.StartsWith("/") || resource.IndexOfAny(new[]{'\r','\n'})>=0 || timeoutMs<1 || timeoutMs>30000)throw new ArgumentException("Invalid connection probe input.");
            host=hostname;path=resource;port=targetPort;fixtureValidator=validator;validation=validator==null?"System":"FixturePin";
            client=new TcpClient(address.AddressFamily);token=stop.Token;stop.CancelAfter(timeoutMs);
            Completion=RunAsync();
        }
        public static Probe Start(string hostname,string ip,int port,string path,int timeoutMs){return new Probe(hostname,ip,port,path,timeoutMs,null);}
        // Only a fixture compiled into this same assembly can supply private test trust.
        internal static Probe StartFixture(string hostname,string ip,int port,string path,int timeoutMs,RemoteCertificateValidationCallback validator){return new Probe(hostname,ip,port,path,timeoutMs,validator);}
        static void ObserveFault(Task operation){operation.ContinueWith(t=>GC.KeepAlive(t.Exception),CancellationToken.None,TaskContinuationOptions.OnlyOnFaulted|TaskContinuationOptions.ExecuteSynchronously,TaskScheduler.Default);}
        async Task AwaitOperation(Task operation) {
            var interrupted=new TaskCompletionSource<bool>();
            using(token.Register(()=>interrupted.TrySetResult(true))) {
                if(await Task.WhenAny(operation,interrupted.Task).ConfigureAwait(false)!=operation) {
                    ObserveFault(operation);
                    throw new OperationCanceledException(token);
                }
                await operation.ConfigureAwait(false);
            }
        }
        bool Validate(object sender,X509Certificate certificate,X509Chain chain,SslPolicyErrors errors) {
            Interlocked.Exchange(ref certificateErrors,(int)errors);
            Interlocked.Exchange(ref certificateObserved,1);
            return fixtureValidator==null?errors==SslPolicyErrors.None:fixtureValidator(sender,certificate,chain,errors);
        }
        async Task<Result> RunAsync() {
            Interlocked.Increment(ref active);
            var result=new Result{Address=address.ToString(),Family=address.AddressFamily==AddressFamily.InterNetwork?"IPv4":"IPv6",Validation=validation};
            var total=Stopwatch.StartNew();var phase=Stopwatch.StartNew();SslStream tls=null;
            using(token.Register(()=>client.Close())) {
                try {
                    await AwaitOperation(client.ConnectAsync(address,port)).ConfigureAwait(false);
                    result.TcpSucceeded=true;result.TcpMs=phase.Elapsed.TotalMilliseconds;
                    result.Stage="Tls";phase.Restart();
                    tls=new SslStream(client.GetStream(),false,Validate);
                    await AwaitOperation(tls.AuthenticateAsClientAsync(host,null,SslProtocols.None,false)).ConfigureAwait(false);
                    result.TlsSucceeded=true;result.TlsMs=phase.Elapsed.TotalMilliseconds;result.TlsProtocol=tls.SslProtocol.ToString();
                    result.Stage="Http";phase.Restart();
                    string authority=host.IndexOf(':')>=0?"["+host+"]":host;
                    if(port!=443)authority+=":"+port;
                    byte[] request=Encoding.ASCII.GetBytes("HEAD "+path+" HTTP/1.1\r\nHost: "+authority+"\r\nConnection: close\r\nUser-Agent: zapret-connection-diagnostic/1\r\nAccept: */*\r\n\r\n");
                    await AwaitOperation(tls.WriteAsync(request,0,request.Length)).ConfigureAwait(false);
                    await AwaitOperation(tls.FlushAsync()).ConfigureAwait(false);
                    byte[] bytes=new byte[HeaderLimit];int used=0,begin=0,scan=0;
                    while(true) {
                        int end=-1;
                        for(int i=scan;i+3<used;i++)if(bytes[i]==13 && bytes[i+1]==10 && bytes[i+2]==13 && bytes[i+3]==10){end=i+4;break;}
                        if(end>=0) {
                            string header=Encoding.ASCII.GetString(bytes,begin,end-begin);int newline=header.IndexOf("\r\n",StringComparison.Ordinal);
                            var status=Regex.Match(newline<0?"":header.Substring(0,newline),@"\AHTTP/(1\.[01]) ([1-5][0-9]{2})(?:[ \t][\t \x21-\x7e\x80-\xff]*)?\z");
                            if(!status.Success){result.Reason="MalformedHttp";result.State="FAIL";break;}
                            bool validFields=true;
                            string[] fields=header.Split(new[]{"\r\n"},StringSplitOptions.None);
                            for(int i=1;i<fields.Length;i++)if(fields[i].Length>0 && !Regex.IsMatch(fields[i],@"\A[!#$%&'*+\-.^_`|~0-9A-Za-z]+:[\t \x21-\x7e\x80-\xff]*\z")){validFields=false;break;}
                            if(!validFields){result.Reason="MalformedHttp";result.State="FAIL";break;}
                            int code=int.Parse(status.Groups[2].Value,System.Globalization.CultureInfo.InvariantCulture);
                            if(code>=100 && code<200) {
                                if(code==101){result.Reason="UnsupportedUpgrade";result.State="FAIL";break;}
                                begin=end;scan=begin;
                                continue;
                            }
                            result.StatusCode=code;result.HttpVersion=status.Groups[1].Value;result.HeaderBytes=end;result.HeadersComplete=true;
                            result.Stage="Complete";result.State=code>=400?"HTTP_ERROR":"OK";result.Reason=code>=400?"HttpStatus":"Completed";break;
                        }
                        if(used==HeaderLimit){result.Reason="HeaderLimit";result.State="FAIL";break;}
                        scan=Math.Max(begin,used-3);
                        var read=tls.ReadAsync(bytes,used,Math.Min(2048,HeaderLimit-used));
                        await AwaitOperation(read).ConfigureAwait(false);int count=read.GetAwaiter().GetResult();
                        if(count==0){result.Reason="TruncatedHeaders";result.State="FAIL";break;}
                        used+=count;result.ReceivedBytes=used;
                    }
                    result.HttpMs=phase.Elapsed.TotalMilliseconds;
                } catch(Exception error) {
                    result.State="FAIL";
                    if(token.IsCancellationRequested){result.Reason=Volatile.Read(ref cancelled)!=0?"Cancelled":"Timeout";if(result.Reason=="Cancelled")result.State="UNKNOWN";}
                    else if(result.Stage=="Tls")result.Reason=Volatile.Read(ref certificateErrors)!=0?"Certificate":"Handshake";
                    else if(result.Stage=="Tcp") {
                        Exception cause=error;while(cause.InnerException!=null)cause=cause.InnerException;
                        var socket=cause as SocketException;result.Reason=socket==null?"ConnectError":socket.SocketErrorCode.ToString();
                    } else result.Reason="ReadError";
                    result.Error=error.GetBaseException().Message;
                    if(result.Error.Length>1024)result.Error=result.Error.Substring(0,1024);
                    if(result.Stage=="Tcp")result.TcpMs=phase.Elapsed.TotalMilliseconds;
                    else if(result.Stage=="Tls")result.TlsMs=phase.Elapsed.TotalMilliseconds;
                    else if(result.Stage=="Http")result.HttpMs=phase.Elapsed.TotalMilliseconds;
                } finally {
                    result.CertificateObserved=Volatile.Read(ref certificateObserved)!=0;
                    result.CertificateErrors=result.CertificateObserved?((SslPolicyErrors)Volatile.Read(ref certificateErrors)).ToString():"NotObserved";
                    if(tls!=null)tls.Dispose();client.Close();
                    result.ElapsedMs=total.Elapsed.TotalMilliseconds;Interlocked.Decrement(ref active);
                }
            }
            stop.Dispose();return result;
        }
        public void Cancel(){Interlocked.Exchange(ref cancelled,1);try{stop.Cancel();}catch(ObjectDisposedException){}}
        public void Expire(){try{stop.Cancel();}catch(ObjectDisposedException){}}
        public void Dispose(){Cancel();client.Close();}
    }
}
