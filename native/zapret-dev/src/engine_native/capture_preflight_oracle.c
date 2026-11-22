/* MIT. Original capture preflight and real C adapter with private backend faults. */
#include "params.h"
#include <setjmp.h>
#include <stdarg.h>
#undef main
enum{WF_TCP_IN,WF_UDP_IN,WF_TCP_OUT,WF_UDP_OUT,WF_ICMP_IN,WF_ICMP_OUT,WF_IPP_IN,WF_IPP_OUT,WF_RAW,WF_RAWF_PART,WF_RAWF_FILTER,GLOBAL_SSID_FILTER,GLOBAL_SSID_FILTER_NEG,GLOBAL_NLM_FILTER,GLOBAL_NLM_FILTER_NEG,WF_RAWF,WF_COUNT};
static unsigned cases,boundaries,atomic_repairs,mutex_repairs,allocation_faults,real_cycles,real_collisions,dry_repairs;
#define CHECK(value) do{if(!(value)){fprintf(stderr,"FAIL capture prepare cases=%u boundaries=%u line=%d: %s\n",cases,boundaries,__LINE__,#value);exit(1);}}while(0)
struct state{struct params_s fields;char output[65536],resized[65536],raw[65536],clauses[12][512],saved[65536],name[64];struct str_list part;char save[256];unsigned hashes[16],fault,trace[16],used;bool cleaned,shrunk,real;HANDLE mutex;};
static struct state left,right,bridge;static struct state *active;static jmp_buf legacy_jump;static int legacy_exit;
#define params (active->fields)
static void trace(unsigned event){CHECK(active->used<16);active->trace[active->used++]=event;}
static HANDLE real_create(const char *name){char local[128];CHECK(!strncmp(name,"Global\\",7));snprintf(local,sizeof(local),"Local\\zapret-private-%lu-%s",GetCurrentProcessId(),name+7);return CreateMutexA(NULL,TRUE,local);}
static BOOL real_close(HANDLE handle){return CloseHandle(handle);}
#define cleanup_windivert_portfilters model_cleanup
#define realloc model_resize
#define CreateMutexA model_create
#define CloseHandle model_close
#define save_file model_save_file
#define zapret_engine_save_file model_save
#define wf_error model_error
#define DLOG model_log
#define DLOG_ERR model_log
static void cleanup_windivert_portfilters(struct params_s *fields){CHECK(fields==&params);trace(5);active->cleaned=true;}
static void *realloc(void *data,size_t size){trace(6);CHECK(data==active->output && size>0 && size<=65536);if(active->fault==2)return NULL;memcpy(active->resized,data,size);active->shrunk=true;return active->resized;}
static HANDLE CreateMutexA(SECURITY_ATTRIBUTES *attributes,BOOL owner,const char *name){trace(3);CHECK(!attributes && owner && strlen(name)<sizeof(active->name));strcpy(active->name,name);if(active->real)return real_create(name);SetLastError(active->fault==4?ERROR_ACCESS_DENIED:active->fault==5?ERROR_ALREADY_EXISTS:active->fault==6?0:active->fault==7?ERROR_ACCESS_DENIED:0);return active->fault==4 || active->fault==6?NULL:(HANDLE)(uintptr_t)0x1111;}
static BOOL CloseHandle(HANDLE handle){trace(4);CHECK(handle);return active->real?real_close(handle):TRUE;}
static uint32_t zapret_engine_save_file(const char *path,const uint8_t *data,size_t size){trace(1);CHECK(!strcmp(path,"export") && size<sizeof(active->saved));memcpy(active->saved,data,size);active->saved[size]=0;return active->fault==3?ERROR_WRITE_FAULT:0;}
static bool save_file(const char *path,const void *data,size_t size){return zapret_engine_save_file(path,data,size)==0;}
static void wf_error(unsigned error){(void)error;}
static int model_log(const char *format,...){if(!strncmp(format,"windivert filter size:",22))trace(0);else if(!strncmp(format,"windivert filter: raw filter saved",33))trace(2);return 0;}
static unsigned hash_jen(const void *data,unsigned length){extern uint32_t zapret_cli_capture_hash(const void *,uint32_t);return zapret_cli_capture_hash(data,length);}
static void exit_clean(int code){legacy_exit=code;longjmp(legacy_jump,1);}
#include "windivert_filter_windows.inc"
static bool legacy(unsigned flags)
{
    unsigned IfIdx=12,SubIfIdx=34;bool wf_ipv4=true,wf_ipv6=flags&128,wf_filter_lan=flags&128,wf_filter_loopback=flags&128,wf_tcp_empty=flags&128,bDupCheck=flags&4;
    char *wf_save_file=active->save;unsigned hash_wf[16];memcpy(hash_wf,active->hashes,sizeof(hash_wf));
    legacy_exit=-1;if(setjmp(legacy_jump))return legacy_exit==0;
#include "capture_preflight_reference.inc"
    active->mutex=hMutexArg;return true;
exiterr:active->mutex=hMutexArg;return false;
}
#include "capture_preflight_windows.inc"
static const zapret_capture_prepare_ops ops={realloc,native_capture_release_clauses,zapret_engine_save_file,native_capture_create_mutex,native_capture_close_mutex,native_capture_prepare_report};
static zapret_capture_prepare_target target_for(unsigned flags)
{
    zapret_capture_prepare_target value={&params.windivert_filter,active->save,active->hashes,&active->mutex,
        {params.wf_pf_tcp_src_out,params.wf_pf_tcp_dst_out,params.wf_pf_tcp_src_in,params.wf_pf_tcp_dst_in,params.wf_pf_udp_src_in,params.wf_pf_udp_dst_in,params.wf_pf_udp_src_out,params.wf_pf_udp_dst_out,params.wf_icf_out,params.wf_icf_in,params.wf_ipf_out,params.wf_ipf_in},
        params.wf_raw_filter,LIST_FIRST(&params.wf_raw_part),65536,12,34,true,flags&128,flags&128,flags&128,flags&128,params.intercept,params.server,flags&4,flags&256};return value;
}
static void initial(struct state *value,unsigned flags,unsigned fault)
{
    memset(value,0,sizeof(*value));value->fault=fault;value->fields.intercept=flags&1;value->fields.server=flags&2;
    value->fields.windivert_filter=value->output;value->fields.wf_raw_filter=value->raw;
    char **slots[]={&value->fields.wf_pf_tcp_src_out,&value->fields.wf_pf_tcp_dst_out,&value->fields.wf_pf_tcp_src_in,&value->fields.wf_pf_tcp_dst_in,&value->fields.wf_pf_udp_src_in,&value->fields.wf_pf_udp_dst_in,&value->fields.wf_pf_udp_src_out,&value->fields.wf_pf_udp_dst_out,&value->fields.wf_icf_out,&value->fields.wf_icf_in,&value->fields.wf_ipf_out,&value->fields.wf_ipf_in};
    const char *clauses[]={"(tcp.SrcPort==80)","(tcp.DstPort==80)","(tcp.SrcPort==443)","(tcp.DstPort==443)","(udp.SrcPort==53)","(udp.DstPort==53)","(udp.SrcPort==443)","(udp.DstPort==443)","(icmp.Type==0)","(icmp.Type==8)","(ip.Protocol==6)","(ip.Protocol==17)"};
    for(unsigned i=0;i<12;++i){*slots[i]=value->clauses[i];if(flags&16)strcpy(value->clauses[i],clauses[i]);}
    if(flags&8)strcpy(value->output,"ip and tcp");if(flags&32){value->part.str="udp.DstPort==123";value->fields.wf_raw_part.lh_first=&value->part;}
    if(flags&64)strcpy(value->save,"export");if(fault==1)memset(value->raw,'x',sizeof(value->raw)-1);
    for(unsigned i=0;i<16;++i)value->hashes[i]=i*73+3;
}
static bool same(const struct state *a,const struct state *b){return !strcmp(a->fields.windivert_filter,b->fields.windivert_filter) && !strcmp(a->saved,b->saved) && !strcmp(a->name,b->name) && a->cleaned==b->cleaned && a->shrunk==b->shrunk && a->mutex==b->mutex && a->used==b->used && !memcmp(a->trace,b->trace,a->used*sizeof(unsigned));}
static void compare(unsigned flags,unsigned fault)
{
    initial(&left,flags,fault);initial(&right,flags,fault);initial(&bridge,flags,fault);
    active=&left;bool expected=legacy(flags);active=&right;zapret_capture_prepare_target target=target_for(flags);zapret_capture_prepare_result result=zapret_capture_prepare(&target,&ops);
    active=&bridge;zapret_capture_prepare_result adapted=native_capture_prepare(12,34,true,flags&128,flags&128,flags&128,flags&128,flags&4,flags&256,bridge.save,bridge.hashes,&bridge.mutex);
    CHECK(result.status==adapted.status && result.error==adapted.error && same(&right,&bridge));
    if((flags&256) && (flags&4) && (flags&1) && !(flags&64) && result.status==0){
        CHECK(expected==(fault!=5) && !right.mutex && !*right.name && left.used==right.used+1+(fault==5) && left.trace[right.used]==3 && !memcmp(left.trace,right.trace,right.used*sizeof(unsigned)));
        CHECK(!strcmp(left.fields.windivert_filter,right.fields.windivert_filter) && left.cleaned==right.cleaned && left.shrunk==right.shrunk && !strcmp(left.saved,right.saved));++dry_repairs;++cases;return;
    }
    if(result.status==7){CHECK(expected && (fault==4 || fault==6) && !right.mutex && result.error==(fault==4?ERROR_ACCESS_DENIED:ERROR_GEN_FAILURE));++mutex_repairs;}
    else CHECK(expected==(result.status==0 || result.status==8));
    if(result.status==3){CHECK(!*right.fields.windivert_filter && left.cleaned && right.cleaned && left.used==right.used && !memcmp(left.trace,right.trace,left.used*sizeof(unsigned)));++atomic_repairs;}
    else CHECK(same(&left,&right));++cases;
}
#ifndef PREFLIGHT_INTEGRATED_CHECK
void zapret_fixture_fail_after(intptr_t);
#endif
static void boundary_checks(void)
{
    initial(&right,17,0);active=&right;zapret_capture_prepare_target target=target_for(17);_Alignas(8)unsigned char storage[256]={0};
#define REJECT(call) do{CHECK((call).status==1 && !right.used);++boundaries;}while(0)
    REJECT(zapret_capture_prepare(NULL,&ops));REJECT(zapret_capture_prepare(&target,NULL));REJECT(zapret_capture_prepare((const zapret_capture_prepare_target *)(storage+1),&ops));REJECT(zapret_capture_prepare(&target,(const zapret_capture_prepare_ops *)(storage+1)));
    target.output=(void *)(storage+1);REJECT(zapret_capture_prepare(&target,&ops));target=target_for(17);target.mutex=(void *)(storage+1);REJECT(zapret_capture_prepare(&target,&ops));target=target_for(17);target.capacity=SIZE_MAX;REJECT(zapret_capture_prepare(&target,&ops));
    target=target_for(17);target.save=NULL;REJECT(zapret_capture_prepare(&target,&ops));target=target_for(17);zapret_capture_prepare_ops missing=ops;missing.create=NULL;REJECT(zapret_capture_prepare(&target,&missing));
    target=target_for(17);right.mutex=(HANDLE)(uintptr_t)0x7777;REJECT(zapret_capture_prepare(&target,&ops));right.mutex=NULL;
    target=target_for(21);target.hashes=(void *)(storage+1);REJECT(zapret_capture_prepare(&target,&ops));target=target_for(17);target.output=NULL;REJECT(zapret_capture_prepare(&target,&ops));target=target_for(17);target.sources[1]=NULL;REJECT(zapret_capture_prepare(&target,&ops));
#undef REJECT
    void *guard=VirtualAlloc(NULL,4096,MEM_RESERVE|MEM_COMMIT,PAGE_NOACCESS);CHECK(guard);strcpy(right.output,"tcp");target=target_for(277);target.hashes=guard;CHECK(!zapret_capture_prepare(&target,&ops).status && right.used==1 && right.trace[0]==0 && !right.mutex && !*right.name);CHECK(VirtualFree(guard,0,MEM_RELEASE));++boundaries;
#ifndef PREFLIGHT_INTEGRATED_CHECK
    const unsigned variants[]={17,21,49,53};for(unsigned i=0;i<4;++i){unsigned flags=variants[i];initial(&right,flags,0);active=&right;target=target_for(flags);zapret_fixture_fail_after(0);zapret_capture_prepare_result result=zapret_capture_prepare(&target,&ops);zapret_fixture_fail_after(-1);CHECK(result.status==4 && !right.used && !right.mutex && !*right.output);++allocation_faults;}
#endif
}
static DWORD WINAPI foreign_wait(void *pointer){return WaitForSingleObject(pointer,0);}
static void real_mutex_checks(void)
{
    DWORD before,after;CHECK(GetProcessHandleCount(GetCurrentProcess(),&before));
    for(unsigned cycle=0;cycle<32;++cycle){initial(&right,13,0);active=&right;right.real=true;right.hashes[0]=GetCurrentProcessId()+cycle*99991;zapret_capture_prepare_target target=target_for(13);zapret_capture_prepare_result result=zapret_capture_prepare(&target,&ops);CHECK(!result.status && right.mutex);
        HANDLE owned=right.mutex;right.mutex=NULL;result=zapret_capture_prepare(&target,&ops);CHECK(result.status==6 && !right.mutex);
        HANDLE thread=CreateThread(NULL,0,foreign_wait,owned,0,NULL);CHECK(thread);CHECK(WaitForSingleObject(thread,5000)==WAIT_OBJECT_0);DWORD code;CHECK(GetExitCodeThread(thread,&code) && code==WAIT_TIMEOUT);CHECK(real_close(thread));
        CHECK(ReleaseMutex(owned));CHECK(real_close(owned));++real_cycles;
    }
    initial(&right,13,0);active=&right;right.real=true;right.hashes[0]=GetCurrentProcessId()^0x1234abcd;char local[128];snprintf(local,sizeof(local),"Local\\zapret-private-%lu-winws2_arg_%u",GetCurrentProcessId(),hash_jen(right.hashes,sizeof(right.hashes)));
    HANDLE event=CreateEventA(NULL,FALSE,FALSE,local);CHECK(event);zapret_capture_prepare_target target=target_for(13);zapret_capture_prepare_result result=zapret_capture_prepare(&target,&ops);CHECK(result.status==7 && result.error==ERROR_INVALID_HANDLE && !right.mutex && WaitForSingleObject(event,0)==WAIT_TIMEOUT);CHECK(real_close(event));++real_collisions;
    CHECK(GetProcessHandleCount(GetCurrentProcess(),&after) && before==after);
}
int main(void)
{
    for(unsigned repeat=0;repeat<4;++repeat)for(unsigned flags=0;flags<512;++flags)for(unsigned fault=0;fault<8;++fault)compare(flags,fault);
    boundary_checks();real_mutex_checks();printf("PASS capture_preflight blocks=1 cases=%u atomic_repairs=%u mutex_error_repairs=%u dry_mutex_repairs=%u boundaries=%u allocation_faults=%u real_private_cycles=%u foreign_wait_checks=%u real_namespace_collisions=%u handle_counts_preserved=1 c_bridge=1\n",cases,atomic_repairs,mutex_repairs,dry_repairs,boundaries,allocation_faults,real_cycles,real_cycles,real_collisions);return 0;
}
