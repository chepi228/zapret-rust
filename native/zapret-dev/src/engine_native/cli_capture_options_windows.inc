/* MIT. Addresses and backend ABIs; all capture option decisions are Rust. */
#include "runtime_log_windows.h"

typedef struct{void *first,*second;size_t capacity;uint32_t *hash,*secondary_hash;void *collection;}zapret_capture_option_target;
typedef struct{
    bool (*render)(const char *,uint32_t,const char *,const char *,char *,size_t);
    bool (*versions)(const char *,bool *,bool *);
    uint32_t (*read)(const char *,int64_t,void *,size_t *);
    bool (*append)(void *,const char *),(*strings)(const char *,void *),(*number)(const char *,bool *),(*networks)(bool);
}zapret_capture_option_ops;
typedef struct{uint32_t status,error;}zapret_capture_option_result;
typedef struct{char *save;size_t save_capacity;bool *ipv4,*ipv6,*lan,*loopback,*empty,*duplicate;unsigned *index,*sub_index,*hashes;}zapret_capture_cli;
zapret_capture_option_result zapret_cli_capture_option(uint32_t,const char *,const zapret_capture_option_target *,const zapret_capture_option_ops *);
int zapret_cli_capture_report(zapret_capture_option_result,const char *,void (*)(DWORD),
    zapret_log_sink,int (*)(const char *));
uint32_t zapret_cli_capture_hash(const void *,uint32_t);
uint32_t zapret_engine_load_file(const char *,int64_t,void *,size_t *);
bool zapret_cli_set_boolean(const char *, bool *, bool (*)(const char *, const zapret_numeric_option *));
_Static_assert(sizeof(zapret_capture_option_target) == 6 * sizeof(void *) &&
    sizeof(zapret_capture_option_ops) == 7 * sizeof(void *) && sizeof(zapret_capture_option_result) == 8 &&
    sizeof(zapret_capture_cli) == 11 * sizeof(void *) &&
    WINDIVERT_MAX == 65536 && WINDIVERT_PORTFILTER_MAX == 4096 && WF_COUNT == 16, "Rust capture options ABI");
static bool native_capture_append(void *head,const char *text){return strlist_add(head,text);}
static bool native_capture_strings(const char *text,void *head){return parse_strlist((char *)text,head);}
static bool native_capture_number(const char *text,bool *value){return zapret_cli_set_boolean(text,value,zapret_cli_set_number);}
static int engine_capture_option(int index,const char *text,zapret_capture_cli *state)
{
    uint32_t kind;zapret_capture_option_target target={0};target.capacity=WINDIVERT_PORTFILTER_MAX;
    const char *name;
    switch(index){
        case IDX_WF_IFACE:kind=0;name="wf-iface";target.first=state->index;target.second=state->sub_index;break;
        case IDX_WF_L3:kind=1;name="wf-l3";target.first=state->ipv4;target.second=state->ipv6;break;
        case IDX_WF_TCP_IN:kind=2;name="wf-tcp-in";target.first=params.wf_pf_tcp_src_in;target.second=params.wf_pf_tcp_dst_in;target.hash=&state->hashes[WF_TCP_IN];break;
        case IDX_WF_TCP_OUT:kind=3;name="wf-tcp-out";target.first=params.wf_pf_tcp_src_out;target.second=params.wf_pf_tcp_dst_out;target.hash=&state->hashes[WF_TCP_OUT];break;
        case IDX_WF_UDP_IN:kind=4;name="wf-udp-in";target.first=params.wf_pf_udp_src_in;target.second=params.wf_pf_udp_dst_in;target.hash=&state->hashes[WF_UDP_IN];break;
        case IDX_WF_UDP_OUT:kind=5;name="wf-udp-out";target.first=params.wf_pf_udp_src_out;target.second=params.wf_pf_udp_dst_out;target.hash=&state->hashes[WF_UDP_OUT];break;
        case IDX_WF_ICMP_IN:kind=6;name="wf-icmp-in";target.first=params.wf_icf_in;target.hash=&state->hashes[WF_ICMP_IN];break;
        case IDX_WF_ICMP_OUT:kind=7;name="wf-icmp-out";target.first=params.wf_icf_out;target.hash=&state->hashes[WF_ICMP_OUT];break;
        case IDX_WF_IPP_IN:kind=8;name="wf-ipp-in";target.first=params.wf_ipf_in;target.hash=&state->hashes[WF_IPP_IN];break;
        case IDX_WF_IPP_OUT:kind=9;name="wf-ipp-out";target.first=params.wf_ipf_out;target.hash=&state->hashes[WF_IPP_OUT];break;
        case IDX_WF_RAW:kind=10;name="wf-raw";target.first=params.windivert_filter;target.capacity=WINDIVERT_MAX;target.hash=&state->hashes[WF_RAWF];break;
        case IDX_WF_RAW_PART:kind=11;name="wf-raw-part";target.capacity=WINDIVERT_MAX;target.collection=&params.wf_raw_part;target.hash=&state->hashes[WF_RAWF_PART];break;
        case IDX_WF_RAW_FILTER:kind=12;name="wf-raw-filter";target.first=params.wf_raw_filter;target.capacity=WINDIVERT_MAX;target.hash=&state->hashes[WF_RAWF_FILTER];target.secondary_hash=&state->hashes[WF_RAWF];break;
        case IDX_WF_TCP_EMPTY:kind=13;name="wf-tcp-empty";target.first=state->empty;break;
        case IDX_WF_FILTER_LAN:kind=14;name="wf-filter-lan";target.first=state->lan;break;
        case IDX_WF_FILTER_LOOPBACK:kind=15;name="wf-filter-loopback";target.first=state->loopback;break;
        case IDX_WF_SAVE:kind=16;name="wf-save";target.first=state->save;target.capacity=state->save_capacity;break;
        case IDX_WF_DUP_CHECK:kind=17;name="wf-dup-check";target.first=state->duplicate;break;
        case IDX_SSID_FILTER:kind=18;name="ssid-filter";target.collection=&params.ssid_filter;target.hash=&state->hashes[GLOBAL_SSID_FILTER];break;
        case IDX_SSID_FILTER_NEG:kind=19;name="ssid-filter-neg";target.first=&params.ssid_filter_neg;target.hash=&state->hashes[GLOBAL_SSID_FILTER_NEG];break;
        case IDX_NLM_FILTER:kind=20;name="nlm-filter";target.collection=&params.nlm_filter;target.hash=&state->hashes[GLOBAL_NLM_FILTER];break;
        case IDX_NLM_FILTER_NEG:kind=21;name="nlm-filter-neg";target.first=&params.nlm_filter_neg;target.hash=&state->hashes[GLOBAL_NLM_FILTER_NEG];break;
        case IDX_NLM_LIST:kind=22;name="nlm-list";break;
        default:return 0;
    }
    static const zapret_capture_option_ops ops={zapret_filter_clauses,wf_make_l3,zapret_engine_load_file,native_capture_append,native_capture_strings,native_capture_number,nlm_list};
    zapret_capture_option_result result=zapret_cli_capture_option(kind,text,&target,&ops);
    return zapret_cli_capture_report(result,name,wf_error,DLOG_ERR,DLOG_PERROR);
}
