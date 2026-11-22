/* MIT. Compare complete pinned TLS diagnostics, including deferred wire reads. */
#include "params.h"
#include "protocol.h"
#include "helpers.h"
#include <stdarg.h>
#include <limits.h>
#undef main
struct params_s params;
static char output[16384],observations[1024];static size_t used,observed;
static unsigned mode,mutations,cases,guarded;static uint8_t *next_version;
#define CHECK(v) do{if(!(v)){fprintf(stderr,"FAIL TLS diagnostics case=%u mode=%u line=%d %s\n",cases,mode,__LINE__,#v);exit(1);}}while(0)
int DLOG(const char *format,...)
{
    va_list args;va_start(args,format);int n=vsnprintf(output+used,sizeof(output)-used,format,args);va_end(args);
    CHECK(n>=0 && (size_t)n<sizeof(output)-used);used+=n;
    if(mode==1 && strstr(format,"record layer")){params.debug=false;++mutations;}
    if(mode==2 && next_version && strstr(format,"supported versions ext : %s")){
        next_version[0]=3;next_version[1]=1;next_version=NULL;++mutations;
    }
    return n;
}
int DLOG_ERR(const char *format,...){(void)format;CHECK(false);return 0;}

void hexdump_limited_dlog(const uint8_t *data, size_t length, size_t limit)
{
    (void)data;
    (void)length;
    (void)limit;
    CHECK(false);
}

bool __real_IsTLSHandshakeServerHello(const uint8_t *, size_t, bool);
bool __real_TLSFindExtInHandshake(const uint8_t *, size_t, uint16_t, const uint8_t **, size_t *, bool);

bool __wrap_IsTLSHandshakeServerHello(const uint8_t *data, size_t length, bool partial)
{
    CHECK(partial);int n=snprintf(observations+observed,sizeof(observations)-observed,"S:%zu;",length);CHECK(n>0);observed+=n;
    return __real_IsTLSHandshakeServerHello(data, length, partial);
}
bool __wrap_TLSFindExtInHandshake(const uint8_t *data, size_t length, uint16_t kind,
    const uint8_t **extension, size_t *extension_length, bool partial)
{
    CHECK(!partial);int n=snprintf(observations+observed,sizeof(observations)-observed,"E:%u:%zu;",kind,length);CHECK(n>0);observed+=n;
    bool found=__real_TLSFindExtInHandshake(data, length, kind, extension, extension_length, partial);
    if(mode==2 && kind==43 && found && data[0]==1 && extension && *extension_length>=5 && (*extension)[0]>=4)
        next_version=(uint8_t *)*extension+3;
    return found;
}
#define IsTLSHandshakeServerHello __wrap_IsTLSHandshakeServerHello
#define TLSFindExtInHandshake __wrap_TLSFindExtInHandshake
#define TLSDebugHandshake reference_handshake
#define TLSDebug reference_record
#include "tls_debug_reference.inc"
#undef TLSDebugHandshake
#undef TLSDebug
#undef IsTLSHandshakeServerHello
#undef TLSFindExtInHandshake
#include "tls_debug_policy_windows.inc"
static size_t hello(uint8_t *wire,bool server,unsigned mask,unsigned versions,unsigned alpn)
{
    memset(wire,0xa5,512);wire[0]=server?2:1;wire[4]=3;wire[5]=3;
    memset(wire+6,0,32);wire[38]=0;size_t at=39;
    if(!server){wire[at++]=0;wire[at++]=2;wire[at++]=0x13;wire[at++]=1;wire[at++]=1;wire[at++]=0;}
    else{wire[at++]=0x13;wire[at++]=1;wire[at++]=0;}
    size_t extensions=at;at+=2;
    if(mask&1){wire[at++]=0;wire[at++]=43;wire[at++]=0;wire[at++]=versions;
        for(unsigned i=0;i<versions;++i)wire[at++]=(i==0&&!server)?(uint8_t)(versions-1):(i&1?3:4);}
    if(mask&2){wire[at++]=0;wire[at++]=16;wire[at++]=0;size_t size_at=at++,start=at;
        wire[at++]=0;size_t declared=at++;
        unsigned width=alpn==0?0:alpn==1?2:alpn==2?31:alpn==3?32:alpn==4?40:3;
        wire[at++]=width;for(unsigned i=0;i<width;++i)wire[at++]=alpn==5&&i==1?0:(uint8_t)('a'+i%26);
        wire[at++]=1;wire[at++]='x';wire[declared]=alpn==6?255:(uint8_t)(at-start-2);wire[size_at]=(uint8_t)(at-start);}
    if(mask&4){wire[at++]=0xfe;wire[at++]=0x0d;wire[at++]=0;wire[at++]=0;}
    size_t ext=at-extensions-2;wire[extensions]=(uint8_t)(ext>>8);wire[extensions+1]=(uint8_t)ext;
    size_t length=at-4;wire[1]=(uint8_t)(length>>16);wire[2]=(uint8_t)(length>>8);wire[3]=(uint8_t)length;
    return at;
}
static void compare(const uint8_t *input,size_t length,bool record,bool debug)
{
    uint8_t left[512],right[512];char logs[sizeof(output)],calls_before[sizeof(observations)];
    CHECK(length<=sizeof(left));memcpy(left,input,sizeof(left));memcpy(right,input,sizeof(right));
    for(unsigned side=0;side<2;++side){
        params.debug=debug;used=observed=0;output[0]=observations[0]=0;next_version=NULL;
        const uint8_t *data=side?right:left;
        if(record){if(side)TLSDebug(data,length);else reference_record(data,length);}
        else{if(side)TLSDebugHandshake(data,length);else reference_handshake(data,length);}
        if(!side){strcpy(logs,output);strcpy(calls_before,observations);}else{
            CHECK(!strcmp(logs,output) && !strcmp(calls_before,observations));CHECK(!memcmp(left,right,sizeof(left)));
        }
    }
    ++cases;
}
static void guarded_inputs(void)
{
    uint8_t *memory=VirtualAlloc(NULL,8192,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);CHECK(memory);DWORD old;
    CHECK(VirtualProtect(memory+4096,4096,PAGE_NOACCESS,&old));
    params.debug=false;reference_handshake(memory+4096,SIZE_MAX);TLSDebugHandshake(memory+4096,SIZE_MAX);
    reference_record(memory+4096,SIZE_MAX);TLSDebug(memory+4096,SIZE_MAX);guarded+=4;
    for(size_t length=0;length<=12;++length){
        uint8_t *p=memory+4096-length;memset(p,0,length);params.debug=true;
        reference_handshake(p,length);TLSDebugHandshake(p,length);reference_record(p,length);TLSDebug(p,length);guarded+=4;
    }
    CHECK(VirtualFree(memory,0,MEM_RELEASE));
}
int main(void)
{
    uint8_t wire[512],record[512];
    for(mode=0;mode<3;++mode)for(unsigned server=0;server<2;++server)for(unsigned mask=0;mask<8;++mask)
    for(unsigned version=0;version<=10;++version)for(unsigned alpn=0;alpn<7;++alpn){
        size_t length=hello(wire,server,mask,version,alpn);
        for(unsigned debug=0;debug<2;++debug){
            compare(wire,length,false,debug);compare(wire,length/2,false,debug);
            memset(record,0xa5,sizeof(record));record[0]=22;record[1]=3;record[2]=1;record[3]=(uint8_t)(length>>8);record[4]=(uint8_t)length;
            memcpy(record+5,wire,length);compare(record,length+5,true,debug);
            record[4]=1;compare(record,length+5,true,debug);
        }
    }
    mode=0;guarded_inputs();CHECK(mutations && guarded);
    printf("PASS tls_debug cases=%u guarded=%u mutations=%u complete_diagnostics=1 deferred_reads=1 native_observation_order=1\n",cases,guarded,mutations);return 0;
}
