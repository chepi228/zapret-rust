/* MIT. Full old/new native packet callback, including late WinDivert observations. */
#include "params.h"
#include "nfqws.h"
#include "engine_loop_windows.h"
#include <stdarg.h>
#include <limits.h>
#undef main
static WINDIVERT_ADDRESS *observed_address;static bool mutate;
static char log_text[2048],ifin_text[44],ifout_text[44];static unsigned calls,cases;static uint32_t initial_mark;
#define CHECK(v) do{if(!(v)){fprintf(stderr,"FAIL native packet case=%u line=%d %s\n",cases,__LINE__,#v);exit(1);}}while(0)
int DLOG(const char *format,...)
{
    size_t used=strlen(log_text);va_list args;va_start(args,format);int n=vsnprintf(log_text+used,sizeof(log_text)-used,format,args);va_end(args);CHECK(n>=0 && (size_t)n<sizeof(log_text)-used);
    if(mutate && strstr(format,"packet: id=")){
        observed_address->Outbound=!observed_address->Outbound;
        observed_address->Impostor=!observed_address->Impostor;
        observed_address->Network.IfIdx=UINT32_MAX;observed_address->Network.SubIfIdx=0;
    }
    return n;
}
int DLOG_ERR(const char *format,...){(void)format;CHECK(false);return 0;}
static uint8_t processPacketData(uint32_t *mark,const char *ifin,const char *ifout,const uint8_t *packet,size_t length,uint8_t *changed,size_t *changed_length)
{
    CHECK(packet && length==8 && changed && *changed_length==16);initial_mark=*mark;*mark=0xdead;
    strcpy(ifin_text,ifin);strcpy(ifout_text,ifout);++calls;memcpy(changed,packet,length);changed[0]^=0xff;*changed_length=length;return VERDICT_MODIFY|VERDICT_PRESERVE_NEXT;
}

/* The linked Windows object uses this packet callback. All driver and VM
 * callbacks below are unreachable in this offline projection test. */
struct params_s params;
uint32_t w_win32_error;
__typeof__(bQuit) bQuit;
uint8_t zapret_native_capture_process(const void *,uint32_t,uint32_t,const uint8_t *,size_t,uint8_t *,size_t *);
uint8_t dpi_desync_packet(uint32_t mark,const char *in,const char *out,const uint8_t *data,size_t size,uint8_t *modified,size_t *length)
{return processPacketData(&mark,in,out,data,size,modified,length);}
void catch_signals(void){abort();}
bool logical_net_filter_match(void){abort();}
bool loop_quitting(void){abort();}
void loop_sleep_ms(uint64_t delay){abort();}
void loop_prepare(void){abort();}
void rawsend_cleanup(void){abort();}
void NoInterceptLoop(void){abort();}
void loop_report(uint32_t event,uint32_t id,size_t length,size_t other){abort();}
bool windivert_init(const char *filter){abort();}
bool win_sandbox(void){abort();}
bool win_dark_init(const struct str_list_head *wlan,bool invert_wlan,const struct str_list_head *net,bool invert_net){abort();}
bool windivert_send(const uint8_t *data,size_t size,const WINDIVERT_ADDRESS *address){abort();}
uint32_t zapret_capture_receive(void *addresses,uint8_t *packet,zapret_capture_batch *batch,uint64_t *deadline){abort();}
bool lua_init(void){abort();}
int DLOG_CONDUP(const char *format,...){abort();}
#define loop_process reference_process
#include "capture_packet_reference.inc"
#undef loop_process
#include "capture_packet_policy_windows.inc"
int main(void)
{
    uint32_t indices[]={0,1,10,999,UINT32_MAX};uint8_t packet[8]={1,2,3,4,5,6,7,8};
    for(unsigned i=0;i<5;++i)for(unsigned j=0;j<5;++j)for(unsigned out=0;out<2;++out)
    for(unsigned impostor=0;impostor<2;++impostor)for(unsigned mutation=0;mutation<2;++mutation){
        char before_log[2048],before_in[44],before_out[44];uint8_t before_bytes[16],before_verdict=99;size_t before_length=0;unsigned before_calls=99;
        uint8_t (*const process[])(const void *,uint32_t,uint32_t,const uint8_t *,size_t,uint8_t *,size_t *)={
            reference_process,loop_process,zapret_native_capture_process,
        };
        for(unsigned side=0;side<sizeof(process)/sizeof(*process);++side){
            WINDIVERT_ADDRESS addresses[3]={0};WINDIVERT_ADDRESS *wa=&addresses[1];wa->Outbound=out;wa->Impostor=impostor;wa->IPv6=i&1;wa->IPChecksum=j&1;wa->TCPChecksum=out^impostor;wa->UDPChecksum=mutation;wa->Network.IfIdx=indices[i];wa->Network.SubIfIdx=indices[j];
            observed_address=wa;mutate=mutation;calls=0;initial_mark=99;log_text[0]=ifin_text[0]=ifout_text[0]=0;
            uint8_t changed[16];memset(changed,0xa5,sizeof(changed));size_t length=sizeof(changed);
            uint8_t verdict=process[side](addresses,1,123,packet,sizeof(packet),changed,&length);
            if(calls){CHECK(initial_mark==0 && ((!*ifin_text)!=(!*ifout_text)));}
            if(!side){strcpy(before_log,log_text);strcpy(before_in,ifin_text);strcpy(before_out,ifout_text);memcpy(before_bytes,changed,sizeof(changed));before_verdict=verdict;before_length=length;before_calls=calls;}
            else CHECK(!strcmp(before_log,log_text) && !strcmp(before_in,ifin_text) && !strcmp(before_out,ifout_text) && !memcmp(before_bytes,changed,sizeof(changed)) && before_verdict==verdict && before_length==length && before_calls==calls);
        }++cases;
    }
    printf("PASS capture_packet cases=%u full_callback=1 max_interface_values=1 late_native_observations=1 rust_win64=1\n",cases);return 0;
}
