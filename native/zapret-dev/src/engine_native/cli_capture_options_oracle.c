/* MIT. Original Windows cases and controlled backend operations, without live capture. */
#include <windows.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include "uthash.h"
#undef main
#define WINDIVERT_MAX 65536
#define WINDIVERT_PORTFILTER_MAX 4096
enum{IDX_WF_IFACE,IDX_WF_L3,IDX_WF_TCP_IN,IDX_WF_TCP_OUT,IDX_WF_UDP_IN,IDX_WF_UDP_OUT,IDX_WF_ICMP_IN,IDX_WF_ICMP_OUT,IDX_WF_IPP_IN,IDX_WF_IPP_OUT,IDX_WF_RAW,IDX_WF_RAW_PART,IDX_WF_RAW_FILTER,IDX_WF_TCP_EMPTY,IDX_WF_FILTER_LAN,IDX_WF_FILTER_LOOPBACK,IDX_WF_SAVE,IDX_WF_DUP_CHECK,IDX_SSID_FILTER,IDX_SSID_FILTER_NEG,IDX_NLM_FILTER,IDX_NLM_FILTER_NEG,IDX_NLM_LIST};
enum{WF_TCP_IN,WF_UDP_IN,WF_TCP_OUT,WF_UDP_OUT,WF_ICMP_IN,WF_ICMP_OUT,WF_IPP_IN,WF_IPP_OUT,WF_RAW,WF_RAWF_PART,WF_RAWF_FILTER,GLOBAL_SSID_FILTER,GLOBAL_SSID_FILTER_NEG,GLOBAL_NLM_FILTER,GLOBAL_NLM_FILTER_NEG,WF_RAWF,WF_COUNT};
static unsigned cases,boundaries,repairs,empty_repairs,oversize_repairs,hash_cases,allocation_faults,sequences;
#define CHECK(value) do{if(!(value)){fprintf(stderr,"FAIL capture options cases=%u boundaries=%u line=%d: %s\n",cases,boundaries,__LINE__,#value);exit(1);}}while(0)
struct head{unsigned count;char text[65536];};
struct model_params{char wf_pf_tcp_src_in[4096],wf_pf_tcp_dst_in[4096],wf_pf_tcp_src_out[4096],wf_pf_tcp_dst_out[4096],wf_pf_udp_src_in[4096],wf_pf_udp_dst_in[4096],wf_pf_udp_src_out[4096],wf_pf_udp_dst_out[4096],wf_icf_in[4096],wf_icf_out[4096],wf_ipf_in[4096],wf_ipf_out[4096],windivert_filter[65536],wf_raw_filter[65536];struct head wf_raw_part,ssid_filter,nlm_filter;bool ssid_filter_neg,nlm_filter_neg;};
struct state{struct model_params fields;char save[256];bool ipv4,ipv6,lan,loopback,empty,duplicate;unsigned index,sub,hashes[16],trace[16],used,fault,rendered;};
static struct state left,right,bridge,prior;static struct state *active;static jmp_buf legacy_jump;static int legacy_status;static unsigned char legacy_allocation[65536];
#define params (active->fields)
#ifdef ZAPRET_CAPTURE_BINDING_DIRECT
#define strlist_add fixture_reference_strlist_add
#define parse_strlist fixture_reference_parse_strlist
#define nlm_list fixture_reference_nlm_list
#endif
static void trace(unsigned value){CHECK(active->used<16);active->trace[active->used++]=value;}
static unsigned hash_jen(const void *data,unsigned len){unsigned value;HASH_JEN(data,len,value);return value;}
#define zapret_filter_clauses mock_capture_render
static bool zapret_filter_clauses(const char *text,uint32_t kind,const char *protocol,const char *field,char *out,size_t cap)
{unsigned call=++active->rendered;trace(10+kind*2+(field && !strcmp(field,"DstPort")));CHECK(text && cap>=2);int size=snprintf(out,cap,"%u:%s:%s:%s",kind,protocol?protocol:"",field?field:"",text);return size>=0 && (size_t)size<cap && !((active->fault==1 && call==1) || (active->fault==2 && call==2));}
static bool wf_make_pf(const char *text,const char *protocol,const char *field,char *out,size_t cap){return zapret_filter_clauses(text,0,protocol,field,out,cap);}
static bool wf_make_icf(const char *text,char *out,size_t cap){return zapret_filter_clauses(text,1,NULL,NULL,out,cap);}
static bool wf_make_ipf(const char *text,char *out,size_t cap){return zapret_filter_clauses(text,2,NULL,NULL,out,cap);}
static bool wf_make_l3(const char *text,bool *v4,bool *v6){trace(20);if(active->fault==1)return false;if(strstr(text,"4"))*v4=true;if(strstr(text,"6"))*v6=true;return true;}
#define zapret_engine_load_file mock_capture_read
static uint32_t zapret_engine_load_file(const char *path,int64_t offset,void *out,size_t *size)
{trace(30);CHECK(path && offset==0);const char *content=!strcmp(path,"empty")?"":!strcmp(path,"binary")?"tcp\0x":"ip and tcp";size_t count=!strcmp(path,"large")?65536:!strcmp(path,"binary")?5:strlen(content);if(count>*size)count=*size;if(!strcmp(path,"large"))memset(out,'x',count);else memcpy(out,content,count);*size=count;return active->fault==3?ERROR_READ_FAULT:0;}
static void legacy_exit(int code){legacy_status=code;longjmp(legacy_jump,1);}
static void load_file_or_exit(const char *text,void *out,size_t *size){CHECK(text[0]=='@');if(zapret_engine_load_file(text+1,0,out,size))legacy_exit(1);}
static void *strlist_add(struct head *head,const char *text){trace(40);CHECK(head==&params.wf_raw_part);if(active->fault==4)return NULL;CHECK(strlen(text)<sizeof(head->text));strcpy(head->text,text);++head->count;return head;}
static bool parse_strlist(const char *text,struct head *head){trace(41);CHECK(head==&params.ssid_filter || head==&params.nlm_filter);CHECK(strlen(text)<sizeof(head->text));strcpy(head->text,text);++head->count;return active->fault!=4;}
typedef struct{void *target;bool *explicit;int64_t lower,upper;uint32_t scale,kind;bool *disable;}zapret_numeric_option;
#define zapret_cli_set_number mock_capture_number
static bool zapret_cli_set_number(const char *text,const zapret_numeric_option *option){trace(42);CHECK(option->lower==INT32_MIN && option->upper==INT32_MAX && option->scale==1 && !option->kind);if(active->fault==5)return false;*(bool *)option->target=!text || atoi(text)!=0;return true;}
static int engine_numeric_option(int index,const char *text,void *profile){(void)profile;bool *value=index==IDX_SSID_FILTER_NEG?&params.ssid_filter_neg:&params.nlm_filter_neg;zapret_numeric_option option={.target=value,.lower=INT32_MIN,.upper=INT32_MAX,.scale=1};return zapret_cli_set_number(text,&option)?1:-1;}
static bool nlm_list(bool all){trace(50+all);return active->fault!=5;}
static bool observe_diagnostic;
static char diagnostic[128];
static DWORD last_capture_error;
static int format_diagnostic(const char *format, va_list args)
{
    return observe_diagnostic ? vsnprintf(diagnostic, sizeof(diagnostic), format, args) : 0;
}
static int quiet(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int result = format_diagnostic(format, args);
    va_end(args);
    return result;
}
static int capture_perror(const char *label)
{
    if (!observe_diagnostic) return 0;
    CHECK(last_capture_error == ERROR_READ_FAULT);
    return snprintf(diagnostic, sizeof(diagnostic), "%s", label);
}
#define wf_error mock_capture_error
static void wf_error(DWORD error){last_capture_error=error;}
static void *legacy_malloc(size_t size){CHECK(size==65536);return legacy_allocation;}
static void legacy_free(void *pointer){CHECK(pointer==legacy_allocation);}
#define DLOG_ERR quiet
#define DLOG_PERROR capture_perror
#define malloc legacy_malloc
#define free legacy_free
#define exit_clean legacy_exit
static int legacy(int option_index,char *optarg)
{
    void *dp=NULL;static const struct{const char *name;}long_options[23]={{"fixture"}};
#define wf_save_file (active->save)
#define wf_ipv4 (active->ipv4)
#define wf_ipv6 (active->ipv6)
#define wf_filter_lan (active->lan)
#define wf_filter_loopback (active->loopback)
#define wf_tcp_empty (active->empty)
#define bDupCheck (active->duplicate)
#define IfIdx (active->index)
#define SubIfIdx (active->sub)
#define hash_wf (active->hashes)
    legacy_status=0;if(setjmp(legacy_jump))return legacy_status;
    switch(option_index){
#include "cli_capture_options_reference.inc"
        default:CHECK(false);
    }
#undef wf_save_file
#undef wf_ipv4
#undef wf_ipv6
#undef wf_filter_lan
#undef wf_filter_loopback
#undef wf_tcp_empty
#undef bDupCheck
#undef IfIdx
#undef SubIfIdx
#undef hash_wf
    return 0;
}
#undef malloc
#undef free
#undef exit_clean
#ifdef ZAPRET_CAPTURE_BINDING_DIRECT
#define engine_capture_option capture_c_binding
#else
#define capture_c_binding engine_capture_option
#endif
#include "cli_capture_options_windows.inc"
#undef DLOG_ERR
#undef DLOG_PERROR
static const zapret_capture_option_ops ops={zapret_filter_clauses,wf_make_l3,zapret_engine_load_file,native_capture_append,native_capture_strings,native_capture_number,nlm_list};
static zapret_capture_cli context(void){zapret_capture_cli value={active->save,256,&active->ipv4,&active->ipv6,&active->lan,&active->loopback,&active->empty,&active->duplicate,&active->index,&active->sub,active->hashes};return value;}
static zapret_capture_option_target target_for(unsigned kind)
{
    zapret_capture_option_target t={0};t.capacity=4096;
    switch(kind){case 0:t.first=&active->index;t.second=&active->sub;break;case 1:t.first=&active->ipv4;t.second=&active->ipv6;break;
    case 2:t.first=params.wf_pf_tcp_src_in;t.second=params.wf_pf_tcp_dst_in;t.hash=&active->hashes[WF_TCP_IN];break;
    case 3:t.first=params.wf_pf_tcp_src_out;t.second=params.wf_pf_tcp_dst_out;t.hash=&active->hashes[WF_TCP_OUT];break;
    case 4:t.first=params.wf_pf_udp_src_in;t.second=params.wf_pf_udp_dst_in;t.hash=&active->hashes[WF_UDP_IN];break;
    case 5:t.first=params.wf_pf_udp_src_out;t.second=params.wf_pf_udp_dst_out;t.hash=&active->hashes[WF_UDP_OUT];break;
    case 6:t.first=params.wf_icf_in;t.hash=&active->hashes[WF_ICMP_IN];break;case 7:t.first=params.wf_icf_out;t.hash=&active->hashes[WF_ICMP_OUT];break;
    case 8:t.first=params.wf_ipf_in;t.hash=&active->hashes[WF_IPP_IN];break;case 9:t.first=params.wf_ipf_out;t.hash=&active->hashes[WF_IPP_OUT];break;
    case 10:t.first=params.windivert_filter;t.capacity=65536;t.hash=&active->hashes[WF_RAWF];break;
    case 11:t.collection=&params.wf_raw_part;t.capacity=65536;t.hash=&active->hashes[WF_RAWF_PART];break;
    case 12:t.first=params.wf_raw_filter;t.capacity=65536;t.hash=&active->hashes[WF_RAWF_FILTER];t.secondary_hash=&active->hashes[WF_RAWF];break;
    case 13:t.first=&active->empty;break;case 14:t.first=&active->lan;break;case 15:t.first=&active->loopback;break;case 16:t.first=active->save;t.capacity=256;break;case 17:t.first=&active->duplicate;break;
    case 18:t.collection=&params.ssid_filter;t.hash=&active->hashes[GLOBAL_SSID_FILTER];break;case 19:t.first=&params.ssid_filter_neg;t.hash=&active->hashes[GLOBAL_SSID_FILTER_NEG];break;
    case 20:t.collection=&params.nlm_filter;t.hash=&active->hashes[GLOBAL_NLM_FILTER];break;case 21:t.first=&params.nlm_filter_neg;t.hash=&active->hashes[GLOBAL_NLM_FILTER_NEG];break;
    }return t;
}
static void initial(struct state *state,unsigned fault,bool initial_value)
{memset(state,0,sizeof(*state));state->fault=fault;state->index=123;state->sub=456;state->ipv4=initial_value;state->ipv6=!initial_value;state->lan=state->loopback=state->empty=state->duplicate=initial_value;for(unsigned i=0;i<16;++i)state->hashes[i]=100+i;strcpy(state->save,"old-save");strcpy(state->fields.windivert_filter,"old-raw");strcpy(state->fields.wf_raw_filter,"old-filter");}
static bool same_fields(const struct state *a,const struct state *b)
{
#define STRING(field) if(strcmp(a->fields.field,b->fields.field))return false
    STRING(wf_pf_tcp_src_in);STRING(wf_pf_tcp_dst_in);STRING(wf_pf_tcp_src_out);STRING(wf_pf_tcp_dst_out);STRING(wf_pf_udp_src_in);STRING(wf_pf_udp_dst_in);STRING(wf_pf_udp_src_out);STRING(wf_pf_udp_dst_out);STRING(wf_icf_in);STRING(wf_icf_out);STRING(wf_ipf_in);STRING(wf_ipf_out);STRING(windivert_filter);STRING(wf_raw_filter);
#undef STRING
    return !memcmp(&a->fields.wf_raw_part,&b->fields.wf_raw_part,sizeof(struct head)) && !memcmp(&a->fields.ssid_filter,&b->fields.ssid_filter,sizeof(struct head)) && !memcmp(&a->fields.nlm_filter,&b->fields.nlm_filter,sizeof(struct head)) && a->fields.ssid_filter_neg==b->fields.ssid_filter_neg && a->fields.nlm_filter_neg==b->fields.nlm_filter_neg && !strcmp(a->save,b->save) && a->ipv4==b->ipv4 && a->ipv6==b->ipv6 && a->lan==b->lan && a->loopback==b->loopback && a->empty==b->empty && a->duplicate==b->duplicate && a->index==b->index && a->sub==b->sub && !memcmp(a->hashes,b->hashes,sizeof(a->hashes));
}
static bool same(const struct state *a,const struct state *b){return same_fields(a,b) && a->used==b->used && !memcmp(a->trace,b->trace,a->used*sizeof(unsigned));}

#ifdef ZAPRET_CAPTURE_BINDING_DIRECT
#undef engine_capture_option
#undef strlist_add
#undef parse_strlist
#undef nlm_list
#undef wf_error
#include "native_cli_catalog_abi.h"

/* Match the live params pointer slots while keeping fixture-owned record storage. */
struct capture_params {
    unsigned char prefix[4288];
    void *ssid_filter, *nlm_filter;
    bool ssid_filter_neg, nlm_filter_neg;
    void *raw_part;
    char *raw;
    char *tcp_src_in, *tcp_dst_in, *udp_src_in, *udp_dst_in;
    char *tcp_src_out, *tcp_dst_out, *udp_src_out, *udp_dst_out;
    char *icmp_in, *icmp_out, *ipp_in, *ipp_out;
    char *raw_filter;
};
struct capture_params capture_storage __asm__("params");
_Static_assert(offsetof(struct capture_params, raw) == 4320 &&
    offsetof(struct capture_params, raw_filter) == 4424, "Fixture capture slots");

static struct state rust_bridge;
static int capture_indices[23];
int engine_capture_option(int, const char *, zapret_capture_cli *);

bool __wrap_zapret_filter_clauses(const char *text, uint32_t kind, const char *protocol,
    const char *field, char *out, size_t capacity)
{ return zapret_filter_clauses(text, kind, protocol, field, out, capacity); }

bool __wrap_zapret_filter_ip_versions(const char *text, bool *ipv4, bool *ipv6)
{ return wf_make_l3(text, ipv4, ipv6); }

uint32_t __wrap_zapret_engine_load_file(const char *path, int64_t offset, void *out, size_t *length)
{ return zapret_engine_load_file(path, offset, out, length); }

bool __wrap_zapret_cli_set_number(const char *text, const zapret_numeric_option *option)
{ return zapret_cli_set_number(text, option); }

bool strlist_add(void *head, const char *text)
{
    CHECK(head == &capture_storage.raw_part);
    return fixture_reference_strlist_add(&params.wf_raw_part, text) != NULL;
}

bool parse_strlist(char *text, void *head)
{
    CHECK(head == &capture_storage.ssid_filter || head == &capture_storage.nlm_filter);
    return fixture_reference_parse_strlist(text,
        head == &capture_storage.ssid_filter ? &params.ssid_filter : &params.nlm_filter);
}

bool nlm_list(bool all) { return fixture_reference_nlm_list(all); }
void __wrap_wf_error(DWORD error) { mock_capture_error(error); }
int DLOG_PERROR(const char *label) { return capture_perror(label); }
int DLOG_ERR(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int result = format_diagnostic(format, args);
    va_end(args);
    return result;
}

static void initialize_capture_indices(void)
{
    bool seen[23] = {0};
    for (size_t index = 0; index < zapret_native_cli_count(); ++index) {
        int kind = zapret_native_cli_kind((int)index, 4);
        if (kind < 0) continue;
        CHECK(kind < 23 && !seen[kind]);
        seen[kind] = true;
        capture_indices[kind] = (int)index;
    }
    for (size_t kind = 0; kind < 23; ++kind) CHECK(seen[kind]);
    CHECK(!engine_capture_option(-1, NULL, NULL));
}

static int capture_rust_binding(int kind, const char *text, zapret_capture_cli *context)
{
    capture_storage.ssid_filter_neg = params.ssid_filter_neg;
    capture_storage.nlm_filter_neg = params.nlm_filter_neg;
    capture_storage.raw = params.windivert_filter;
    capture_storage.tcp_src_in = params.wf_pf_tcp_src_in;
    capture_storage.tcp_dst_in = params.wf_pf_tcp_dst_in;
    capture_storage.tcp_src_out = params.wf_pf_tcp_src_out;
    capture_storage.tcp_dst_out = params.wf_pf_tcp_dst_out;
    capture_storage.udp_src_in = params.wf_pf_udp_src_in;
    capture_storage.udp_dst_in = params.wf_pf_udp_dst_in;
    capture_storage.udp_src_out = params.wf_pf_udp_src_out;
    capture_storage.udp_dst_out = params.wf_pf_udp_dst_out;
    capture_storage.icmp_in = params.wf_icf_in;
    capture_storage.icmp_out = params.wf_icf_out;
    capture_storage.ipp_in = params.wf_ipf_in;
    capture_storage.ipp_out = params.wf_ipf_out;
    capture_storage.raw_filter = params.wf_raw_filter;
    int status = engine_capture_option(capture_indices[kind], text, context);
    params.ssid_filter_neg = capture_storage.ssid_filter_neg;
    params.nlm_filter_neg = capture_storage.nlm_filter_neg;
    return status;
}

static unsigned private_paths;
static void compare_bindings(unsigned kind, const char *text, unsigned fault, bool flag, size_t capacity)
{
    initial(&bridge, fault, flag);
    initial(&rust_bridge, fault, flag);
    observe_diagnostic = true;
    last_capture_error = 0;
    memset(diagnostic, 0, sizeof(diagnostic));
    active = &bridge;
    zapret_capture_cli cli = context();
    cli.save_capacity = capacity;
    int expected = capture_c_binding(kind, text, &cli);
    char expected_log[sizeof(diagnostic)];
    memcpy(expected_log, diagnostic, sizeof(diagnostic));
    DWORD expected_error = last_capture_error;

    last_capture_error = 0;
    memset(diagnostic, 0, sizeof(diagnostic));
    active = &rust_bridge;
    cli = context();
    cli.save_capacity = capacity;
    CHECK(capture_rust_binding(kind, text, &cli) == expected);
    CHECK(!memcmp(&bridge, &rust_bridge, sizeof(bridge)));
    CHECK(last_capture_error == expected_error && !memcmp(diagnostic, expected_log, sizeof(diagnostic)));
    observe_diagnostic = false;
}

static void compare_private_paths(void)
{
    const char *paths[] = {"", "private.txt", ".\\fixture\\private-é.txt", "dir\\file-\xff.txt"};
    const size_t capacities[] = {0, 1, 16, 256};
    for (size_t i = 0; i < sizeof(paths) / sizeof(*paths); ++i)
        for (size_t j = 0; j < sizeof(capacities) / sizeof(*capacities); ++j) {
            compare_bindings(IDX_WF_SAVE, paths[i], 0, false, capacities[j]);
            ++private_paths;
        }
}
#define selected_capture_binding capture_rust_binding
#else
#define selected_capture_binding capture_c_binding
#endif

static void compare(unsigned kind,const char *text,unsigned fault,bool initial_value)
{
    initial(&left,fault,initial_value);initial(&right,fault,initial_value);initial(&bridge,fault,initial_value);initial(&prior,fault,initial_value);
    active=&left;int expected=legacy(kind,(char *)text);active=&right;zapret_capture_option_target target=target_for(kind);zapret_capture_option_result result=zapret_cli_capture_option(kind,text,&target,&ops);
    active=&bridge;zapret_capture_cli ctx=context();int adapted=capture_c_binding(kind,text,&ctx);CHECK(adapted==(result.status==8?2:result.status?-1:1) && same(&right,&bridge));
#ifdef ZAPRET_CAPTURE_BINDING_DIRECT
    compare_bindings(kind,text,fault,initial_value,256);
#endif
    if(kind==0 && text && strspn(text," \t\r\n\v\f")==strlen(text)){CHECK(expected==0 && result.status==2 && same_fields(&right,&prior));++empty_repairs;}
    else {CHECK(expected==((result.status==0 || result.status==8)?0:1));if(result.status && result.status!=8 && !same_fields(&left,&right)){
        CHECK((kind>=2 && kind<=12) || kind==18 || kind==20);CHECK(!memcmp(right.hashes,prior.hashes,sizeof(prior.hashes)));
        if(kind!=18 && kind!=20)CHECK(same_fields(&right,&prior));++repairs;
    }else CHECK(same_fields(&left,&right));CHECK(left.used==right.used && !memcmp(left.trace,right.trace,left.used*sizeof(unsigned)));}
    ++cases;
}
static void hash_checks(void)
{
    unsigned char data[8208];uint32_t random=123456;for(size_t i=0;i<sizeof(data);++i){random=random*1664525+1013904223;data[i]=(unsigned char)(random>>24);}
    for(unsigned offset=0;offset<8;++offset)for(unsigned size=0;size<=8192;++size){CHECK(zapret_cli_capture_hash(data+offset,size)==hash_jen(data+offset,size));++hash_cases;}
    unsigned char *guard=VirtualAlloc(NULL,8192,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);CHECK(guard);DWORD old;CHECK(VirtualProtect(guard+4096,4096,PAGE_NOACCESS,&old));memcpy(guard,data,4096);
    for(unsigned size=0;size<=4096;++size){CHECK(zapret_cli_capture_hash(guard+4096-size,size)==hash_jen(guard+4096-size,size));++hash_cases;}CHECK(VirtualFree(guard,0,MEM_RELEASE));
    CHECK(zapret_cli_capture_hash(NULL,0)==hash_jen(NULL,0));++hash_cases;
    static unsigned char large[65544];for(unsigned i=0;i<sizeof(large);++i)large[i]=(unsigned char)(i*73+23);
    const unsigned sizes[]={8193,16384,32768,65535,65536};for(unsigned offset=0;offset<8;++offset)for(unsigned i=0;i<5;++i){CHECK(zapret_cli_capture_hash(large+offset,sizes[i])==hash_jen(large+offset,sizes[i]));++hash_cases;}
}
#ifndef CAPTURE_INTEGRATED_CHECK
void zapret_fixture_fail_after(intptr_t);
#endif
static void boundary_checks(void)
{
    initial(&right,0,false);active=&right;zapret_capture_option_target target=target_for(0);_Alignas(8) unsigned char storage[80]={0};
#define REJECT(call) do{CHECK((call).status==1 && !right.used);++boundaries;}while(0)
    REJECT(zapret_cli_capture_option(0,"1",NULL,&ops));REJECT(zapret_cli_capture_option(0,"1",&target,NULL));REJECT(zapret_cli_capture_option(23,"1",&target,&ops));
    REJECT(zapret_cli_capture_option(0,NULL,&target,&ops));REJECT(zapret_cli_capture_option(0,"1",(const zapret_capture_option_target *)(storage+1),&ops));REJECT(zapret_cli_capture_option(0,"1",&target,(const zapret_capture_option_ops *)(storage+1)));
    target.first=storage+1;REJECT(zapret_cli_capture_option(0,"1",&target,&ops));target=target_for(2);target.hash=(uint32_t *)(storage+1);REJECT(zapret_cli_capture_option(2,"1",&target,&ops));
    target=target_for(2);target.capacity=SIZE_MAX;REJECT(zapret_cli_capture_option(2,"1",&target,&ops));target=target_for(10);target.capacity=0;REJECT(zapret_cli_capture_option(10,"1",&target,&ops));
    target=target_for(12);target.secondary_hash=NULL;REJECT(zapret_cli_capture_option(12,"1",&target,&ops));
    target=target_for(2);zapret_capture_option_ops missing={0};REJECT(zapret_cli_capture_option(2,"1",&target,&missing));target=target_for(11);REJECT(zapret_cli_capture_option(11,"1",&target,&missing));
#undef REJECT
    static char long_value[65537];memset(long_value,'x',65536);long_value[65536]=0;
    for(unsigned kind=10;kind<=16;++kind){if(kind!=10 && kind!=11 && kind!=12 && kind!=16)continue;target=target_for(kind);CHECK(zapret_cli_capture_option(kind,long_value,&target,&ops).status==5 && !right.used);++oversize_repairs;}
    for(unsigned kind=10;kind<=12;++kind){initial(&left,0,false);initial(&right,0,false);initial(&prior,0,false);active=&left;CHECK(!legacy(kind,"@large"));active=&right;target=target_for(kind);CHECK(zapret_cli_capture_option(kind,"@large",&target,&ops).status==5 && right.used==1 && same_fields(&right,&prior));++oversize_repairs;}
#ifndef CAPTURE_INTEGRATED_CHECK
    for(unsigned kind=2;kind<=12;++kind){initial(&right,0,false);active=&right;target=target_for(kind);zapret_fixture_fail_after(0);zapret_capture_option_result result=zapret_cli_capture_option(kind,"value",&target,&ops);zapret_fixture_fail_after(-1);CHECK(result.status==3 && !right.used);++allocation_faults;}
    for(unsigned kind=2;kind<=5;++kind){initial(&right,0,false);active=&right;target=target_for(kind);zapret_fixture_fail_after(1);zapret_capture_option_result result=zapret_cli_capture_option(kind,"value",&target,&ops);zapret_fixture_fail_after(-1);CHECK(result.status==3 && right.used==1 && right.hashes[0]==100 && !*right.fields.wf_pf_tcp_src_in);++allocation_faults;}
#endif
    for(unsigned kind=10;kind<=12;++kind){initial(&left,0,false);initial(&right,0,false);for(unsigned step=0;step<4;++step){left.used=right.used=0;active=&left;CHECK(!legacy(kind,step&1?"@file":"tcp"));active=&right;target=target_for(kind);CHECK(!zapret_cli_capture_option(kind,step&1?"@file":"tcp",&target,&ops).status && same_fields(&left,&right));}++sequences;}
}
int main(void)
{
#ifdef ZAPRET_CAPTURE_BINDING_DIRECT
    initialize_capture_indices();
#endif
    const char *text[]={NULL,"","0","1","1junk","12.34","5","ipv4,ipv6","@file","all","данные-é-中","raw-\xff"," \t","@empty","@binary"};
    for(unsigned repeat=0;repeat<2;++repeat)for(unsigned kind=0;kind<23;++kind)for(unsigned argument=0;argument<15;++argument)for(unsigned fault=0;fault<6;++fault)for(unsigned flag=0;flag<2;++flag){if(!text[argument] && kind!=13 && kind!=17 && kind!=19 && kind!=21 && kind!=22)continue;compare(kind,text[argument],fault,flag!=0);}
    initial(&bridge,3,false);
    active=&bridge;
    observe_diagnostic=true;
    last_capture_error=0;
    zapret_capture_cli cli=context();
    CHECK(selected_capture_binding(IDX_WF_RAW,"@file",&cli)==-1);
    CHECK(!strcmp(diagnostic,"read capture filter"));
    initial(&bridge,0,false);
    char long_path[257];
    memset(long_path,'x',sizeof(long_path)-1);
    long_path[sizeof(long_path)-1]=0;
    CHECK(selected_capture_binding(IDX_WF_SAVE,long_path,&cli)==-1);
    CHECK(!strcmp(diagnostic,"value for --wf-save is too long\n"));
    observe_diagnostic=false;
    hash_checks();boundary_checks();
#ifdef ZAPRET_CAPTURE_BINDING_DIRECT
    compare_private_paths();
    printf("PASS cli_capture_options functions=23 cases=%u atomic_repairs=%u empty_iface_repairs=%u oversized_repairs=%u hash_cases=%u boundaries=%u allocation_faults=%u sequences=%u diagnostic_cases=2 c_bridge=1 live_networks=0 rust_binding=1 private_paths=%u\n",cases,repairs,empty_repairs,oversize_repairs,hash_cases,boundaries,allocation_faults,sequences,private_paths);
#else
    printf("PASS cli_capture_options functions=23 cases=%u atomic_repairs=%u empty_iface_repairs=%u oversized_repairs=%u hash_cases=%u boundaries=%u allocation_faults=%u sequences=%u diagnostic_cases=2 c_bridge=1 live_networks=0\n",cases,repairs,empty_repairs,oversize_repairs,hash_cases,boundaries,allocation_faults,sequences);
#endif
    return 0;
}
