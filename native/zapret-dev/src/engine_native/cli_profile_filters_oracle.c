/* MIT. Compare original profile cases and the C bridge without a VM or network. */
#include <windows.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#undef main
static unsigned cases,boundaries,transactions,sequences;
#define CHECK(value) do{if(!(value)){fprintf(stderr,"FAIL profile filters cases=%u boundaries=%u line=%d: %s\n",cases,boundaries,__LINE__,#value);exit(1);}}while(0)
enum{IDX_FILTER_L3,IDX_FILTER_TCP,IDX_FILTER_UDP,IDX_FILTER_ICMP,IDX_FILTER_IPP,IDX_FILTER_L7,IDX_PAYLOAD_DISABLE,IDX_REASM_DISABLE,IDX_PAYLOAD,IDX_OUT_RANGE,IDX_IN_RANGE,IDX_LUA_DESYNC};
enum{L7P_ALL=0};
struct packet_pos{char mode;uint32_t pos;};
struct packet_range{struct packet_pos from,to;bool upper_cutoff;};
struct func_list{char *func;uint64_t payload_type;struct packet_range range_in,range_out;};
struct head{void *first;};
struct desync_profile{bool filter_ipv4,filter_ipv6,b_filter_l3,b_filter_l7;struct head pf_tcp,pf_udp,icf,ipf,lua_desync;uint64_t filter_l7;};
struct model_params{uint64_t payload_disable,reasm_payload_disable;};
struct state{struct desync_profile profile;struct model_params fields;uint64_t payload;struct packet_range incoming,outgoing;struct func_list rule;unsigned used,trace[8],fault;};
static struct state *active;static jmp_buf legacy_jump;
#define params (active->fields)
static void trace(unsigned item){CHECK(active->used<8);active->trace[active->used++]=item;}
static uint32_t hash(const char *text){uint32_t value=17;for(const unsigned char *p=(const unsigned char *)text;*p;++p)value=value*33+*p;return value;}
static bool writable(void){return active->fault!=1;}
static bool parse_versions(const char *text,bool *ipv4,bool *ipv6){trace(0);if(!writable())return false;uint32_t value=hash(text);if(value&1)*ipv4=true;if(value&2)*ipv6=true;return active->fault!=3;}
static bool wf_make_l3(const char *text,bool *ipv4,bool *ipv6){return parse_versions(text,ipv4,ipv6);}
static bool list(const char *text,struct head *head,unsigned kind){CHECK(text);trace(kind);if(!writable() || active->fault==3)return false;head->first=(void *)((uintptr_t)head->first+1);return true;}
static bool parse_pf_list(const char *text,struct head *head){CHECK(head==&active->profile.pf_tcp || head==&active->profile.pf_udp);return list(text,head,head==&active->profile.pf_tcp?1:2);}
static bool parse_icf_list(const char *text,struct head *head){CHECK(head==&active->profile.icf);return list(text,head,3);}
static bool parse_ipp_list(const char *text,struct head *head){CHECK(head==&active->profile.ipf);return list(text,head,4);}
static bool mask(const char *text,uint64_t *value,unsigned kind){trace(kind);if(!writable())return false;*value=((uint64_t)hash(text)<<32)|123;return active->fault!=3;}
static bool parse_l7_list(const char *text,uint64_t *value){return mask(text,value,5);}
static bool parse_l7p_list(const char *text,uint64_t *value){return mask(text,value,6);}
static bool packet_range_parse(const char *text,struct packet_range *range){trace(9);if(!writable())return false;uint32_t value=hash(text);*range=(struct packet_range){{'n',value},{'d',value+4},(value&1)!=0};return active->fault!=3;}
static struct func_list *parse_lua_call(char *text,struct head *head){CHECK(head==&active->profile.lua_desync);trace(11);if(active->fault==2)return NULL;active->rule.func=text;head->first=(void *)((uintptr_t)head->first+1);return &active->rule;}
static bool observe_diagnostic;
static char diagnostic[128];
static int quiet(const char *format,...)
{
    if (!observe_diagnostic) return 0;
    va_list args;
    va_start(args,format);
    int result=vsnprintf(diagnostic,sizeof(diagnostic),format,args);
    va_end(args);
    return result;
}
static void legacy_exit(int code){CHECK(code==1);longjmp(legacy_jump,1);}
#define DLOG_ERR quiet
static bool legacy(unsigned kind,char *optarg)
{
    struct desync_profile *dp=&active->profile;uint64_t payload_type=active->payload;
    struct packet_range range_in=active->incoming,range_out=active->outgoing;
#define exit_clean(code) do{active->payload=payload_type;active->incoming=range_in;active->outgoing=range_out;legacy_exit(code);}while(0)
    if(setjmp(legacy_jump))return false;
    switch(kind){
#include "cli_profile_filters_reference.inc"
        default:CHECK(false);
    }
#undef exit_clean
    active->payload=payload_type;active->incoming=range_in;active->outgoing=range_out;
    return true;
}
#include "cli_profile_filters_windows.inc"
#undef DLOG_ERR
#define ops native_profile_filter_ops
static zapret_profile_filter_target target_for(unsigned kind)
{
    struct desync_profile *dp=&active->profile;zapret_profile_filter_target target={0};
    switch(kind){case 0:target.value=&dp->filter_ipv4;target.extra=&dp->filter_ipv6;target.explicit=&dp->b_filter_l3;break;case 1:target.value=&dp->pf_tcp;break;case 2:target.value=&dp->pf_udp;break;case 3:target.value=&dp->icf;break;case 4:target.value=&dp->ipf;break;case 5:target.value=&dp->filter_l7;target.explicit=&dp->b_filter_l7;break;case 6:target.value=&params.payload_disable;break;case 7:target.value=&params.reasm_payload_disable;break;case 8:target.value=&active->payload;break;case 9:target.value=&active->outgoing;break;case 10:target.value=&active->incoming;break;case 11:target.value=&dp->lua_desync;target.payload=&active->payload;target.incoming=&active->incoming;target.outgoing=&active->outgoing;break;}
    return target;
}
static void initial(struct state *value,unsigned fault,bool explicit)
{
    memset(value,0,sizeof(*value));value->fault=fault;value->fields.payload_disable=111;value->fields.reasm_payload_disable=112;value->payload=113;value->profile.filter_l7=114;
    value->profile.b_filter_l3=value->profile.b_filter_l7=explicit;value->profile.filter_ipv4=explicit;value->profile.filter_ipv6=!explicit;
    value->incoming=(struct packet_range){{'x',1},{'a',2},true};value->outgoing=(struct packet_range){{'b',3},{'p',4},false};
}
static bool range_equal(const struct packet_range *a,const struct packet_range *b){return a->from.mode==b->from.mode && a->from.pos==b->from.pos && a->to.mode==b->to.mode && a->to.pos==b->to.pos && a->upper_cutoff==b->upper_cutoff;}
static bool same(const struct state *a,const struct state *b)
{return !memcmp(&a->profile,&b->profile,sizeof(a->profile)) && !memcmp(&a->fields,&b->fields,sizeof(a->fields)) && a->payload==b->payload && range_equal(&a->incoming,&b->incoming) && range_equal(&a->outgoing,&b->outgoing) && a->rule.func==b->rule.func && a->rule.payload_type==b->rule.payload_type && range_equal(&a->rule.range_in,&b->rule.range_in) && range_equal(&a->rule.range_out,&b->rule.range_out) && a->used==b->used && !memcmp(a->trace,b->trace,a->used*sizeof(unsigned));}
static void compare(unsigned kind,const char *text,unsigned fault,bool explicit)
{
    struct state a,b,c,prior;initial(&a,fault,explicit);initial(&b,fault,explicit);initial(&c,fault,explicit);initial(&prior,fault,explicit);
    active=&a;bool expected=legacy(kind,(char *)text);active=&b;zapret_profile_filter_target target=target_for(kind);unsigned result=zapret_cli_profile_filter(kind,text,&target,&ops);
    active=&c;int adapted=engine_profile_filter(kind,text,&c.profile,&c.payload,&c.incoming,&c.outgoing);CHECK((adapted==1)==!result && same(&b,&c));CHECK(expected==!result);
    if(fault==3 && text && (kind==0 || (kind>=5 && kind<=10))){CHECK(result==2 && b.used==1 && b.trace[0]==a.trace[0]);prior.used=b.used;memcpy(prior.trace,b.trace,sizeof(b.trace));CHECK(same(&b,&prior));++transactions;}
    else CHECK(same(&a,&b));
    ++cases;
}
static void boundary_checks(void)
{
    struct state value;initial(&value,0,false);active=&value;zapret_profile_filter_target target=target_for(0);_Alignas(8) unsigned char storage[80]={0};
    CHECK(zapret_cli_profile_filter(0,"x",NULL,&ops)==1 && !value.used);++boundaries;
    CHECK(zapret_cli_profile_filter(0,"x",&target,NULL)==1 && !value.used);++boundaries;
    CHECK(zapret_cli_profile_filter(12,"x",&target,&ops)==1 && !value.used);++boundaries;
    CHECK(zapret_cli_profile_filter(0,NULL,&target,&ops)==1 && !value.used);++boundaries;
    CHECK(zapret_cli_profile_filter(0,"x",(const zapret_profile_filter_target *)(storage+1),&ops)==1 && !value.used);++boundaries;
    CHECK(zapret_cli_profile_filter(0,"x",&target,(const zapret_profile_filter_ops *)(storage+1))==1 && !value.used);++boundaries;
    target.extra=NULL;CHECK(zapret_cli_profile_filter(0,"x",&target,&ops)==1 && !value.used);++boundaries;
    target=target_for(5);target.value=storage+1;CHECK(zapret_cli_profile_filter(5,"x",&target,&ops)==1 && !value.used);++boundaries;
    target=target_for(9);target.value=storage+1;CHECK(zapret_cli_profile_filter(9,"x",&target,&ops)==1 && !value.used);++boundaries;
    target=target_for(1);target.value=storage+1;CHECK(zapret_cli_profile_filter(1,"x",&target,&ops)==1 && !value.used);++boundaries;
    target=target_for(11);target.payload=(const uint64_t *)(storage+1);CHECK(zapret_cli_profile_filter(11,"x",&target,&ops)==1 && !value.used);++boundaries;
    target=target_for(11);target.incoming=NULL;CHECK(zapret_cli_profile_filter(11,"x",&target,&ops)==1 && !value.used);++boundaries;
    target=target_for(11);zapret_profile_filter_ops absent={0};CHECK(zapret_cli_profile_filter(11,"x",&target,&absent)==1 && !value.used);++boundaries;
    target=target_for(0);CHECK(zapret_cli_profile_filter(0,"x",&target,&absent)==1 && !value.used);++boundaries;
    CHECK(!engine_profile_filter(123,NULL,NULL,NULL,NULL,NULL) && !value.used);++boundaries;
}
static void sequence_checks(void)
{
    for(unsigned kind=0;kind<12;++kind){struct state a,b;initial(&a,0,false);initial(&b,0,false);for(unsigned step=0;step<4;++step){a.used=b.used=0;a.fault=b.fault=step==1?1:0;active=&a;bool expected=legacy(kind,"sequence");active=&b;zapret_profile_filter_target target=target_for(kind);unsigned result=zapret_cli_profile_filter(kind,"sequence",&target,&ops);CHECK(expected==!result && same(&a,&b));}++sequences;}
}
int main(void)
{
    const char *text[]={NULL,"","ipv4,ipv6","80,443","tls_client_hello","n1-n4","func:arg=value","данные-é-中","raw-\xff"};
    for(unsigned repeat=0;repeat<8;++repeat)for(unsigned kind=0;kind<12;++kind)for(unsigned argument=0;argument<9;++argument)for(unsigned fault=0;fault<4;++fault)for(unsigned flag=0;flag<2;++flag){if(!text[argument] && kind!=6 && kind!=7)continue;compare(kind,text[argument],fault,flag!=0);}
    struct state state;
    initial(&state,3,false);
    active=&state;
    observe_diagnostic=true;
    CHECK(engine_profile_filter(IDX_FILTER_TCP,"raw-\xff",&state.profile,
        &state.payload,&state.incoming,&state.outgoing)==-1);
    CHECK(!strcmp(diagnostic,"Invalid port filter : raw-\xff\n"));
    observe_diagnostic=false;
    boundary_checks();sequence_checks();printf("PASS cli_profile_filters functions=12 cases=%u defensive_transactions=%u boundaries=%u sequences=%u diagnostic_cases=1 c_bridge=1 rule_context=1\n",cases,transactions,boundaries,sequences);return 0;
}
