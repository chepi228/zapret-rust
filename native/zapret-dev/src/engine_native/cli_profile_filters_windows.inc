/* MIT. Field addresses and parser ABI; Rust owns commit and context decisions. */
#include "runtime_log_windows.h"

typedef struct{void *value;bool *explicit,*extra;const uint64_t *payload;const struct packet_range *incoming,*outgoing;}zapret_profile_filter_target;
typedef struct {
    bool (*versions)(const char *,bool *,bool *);
    bool (*ports)(const char *,void *), (*icmp)(const char *,void *), (*ip_protocol)(const char *,void *);
    bool (*protocols)(const char *,uint64_t *), (*payloads)(const char *,uint64_t *);
    bool (*range)(const char *,struct packet_range *);
    struct func_list *(*append)(void *,const char *);
} zapret_profile_filter_ops;
uint32_t zapret_cli_profile_filter(uint32_t,const char *,const zapret_profile_filter_target *,const zapret_profile_filter_ops *);
int zapret_cli_profile_filter_report(uint32_t,uint32_t,const char *,zapret_log_sink);
_Static_assert(sizeof(zapret_profile_filter_target) == 6 * sizeof(void *) &&
    sizeof(zapret_profile_filter_ops) == 8 * sizeof(void *) && sizeof(struct packet_range) == 20 &&
    offsetof(struct func_list, payload_type) == 8 && offsetof(struct func_list, range_in) == 16 &&
    offsetof(struct func_list, range_out) == 36 && L7P_ALL == 0, "Rust profile filter ABI");
static bool native_profile_filter_ports(const char *text, void *value){return parse_pf_list(text,value);}
static bool native_profile_filter_icmp(const char *text, void *value){return parse_icf_list(text,value);}
static bool native_profile_filter_ip_protocol(const char *text, void *value){return parse_ipp_list(text,value);}
static struct func_list *native_profile_filter_append(void *head,const char *text){return parse_lua_call((char *)text,head);}
static const zapret_profile_filter_ops native_profile_filter_ops = {
    wf_make_l3, native_profile_filter_ports, native_profile_filter_icmp, native_profile_filter_ip_protocol,
    parse_l7_list, parse_l7p_list, packet_range_parse, native_profile_filter_append,
};
static int engine_profile_filter(int index,const char *text,struct desync_profile *profile,uint64_t *payload,struct packet_range *incoming,struct packet_range *outgoing)
{
    uint32_t kind;zapret_profile_filter_target target={0};
    switch(index){
        case IDX_FILTER_L3:kind=0;target.value=&profile->filter_ipv4;target.extra=&profile->filter_ipv6;target.explicit=&profile->b_filter_l3;break;
        case IDX_FILTER_TCP:kind=1;target.value=&profile->pf_tcp;break;
        case IDX_FILTER_UDP:kind=2;target.value=&profile->pf_udp;break;
        case IDX_FILTER_ICMP:kind=3;target.value=&profile->icf;break;
        case IDX_FILTER_IPP:kind=4;target.value=&profile->ipf;break;
        case IDX_FILTER_L7:kind=5;target.value=&profile->filter_l7;target.explicit=&profile->b_filter_l7;break;
        case IDX_PAYLOAD_DISABLE:kind=6;target.value=&params.payload_disable;break;
        case IDX_REASM_DISABLE:kind=7;target.value=&params.reasm_payload_disable;break;
        case IDX_PAYLOAD:kind=8;target.value=payload;break;
        case IDX_OUT_RANGE:kind=9;target.value=outgoing;break;
        case IDX_IN_RANGE:kind=10;target.value=incoming;break;
        case IDX_LUA_DESYNC:kind=11;target.value=&profile->lua_desync;target.payload=payload;target.incoming=incoming;target.outgoing=outgoing;break;
        default:return 0;
    }
    uint32_t status=zapret_cli_profile_filter(kind,text,&target,&native_profile_filter_ops);
    return zapret_cli_profile_filter_report(kind,status,text,DLOG_ERR);
}
