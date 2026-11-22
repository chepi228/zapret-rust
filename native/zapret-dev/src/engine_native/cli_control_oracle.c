/* MIT. C-only original control flow, real adapter and deterministic profile errors. */
#include <windows.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#undef main
static unsigned cases,boundaries,template_repairs,sequences;
#define CHECK(value) do{if(!(value)){fprintf(stderr,"FAIL CLI control cases=%u boundaries=%u line=%d: %s\n",cases,boundaries,__LINE__,#value);exit(1);}}while(0)
enum{IDX_NEW,IDX_SKIP,IDX_TEMPLATE,IDX_NAME,IDX_COOKIE,IDX_IMPORT,IDX_DRY_RUN,IDX_VERSION,IDX_COMMENT};
struct packet_pos{char mode;uint32_t pos;};struct packet_range{struct packet_pos from,to;bool upper_cutoff;};
#define PACKET_RANGE_NEVER (struct packet_range){{'x',0},{'x',0},false}
#define PACKET_RANGE_ALWAYS (struct packet_range){{'a',0},{'a',0},false}
struct desync_profile{const char *name,*cookie;};struct desync_profile_list{struct desync_profile dp;};struct zapret_list_file{unsigned id;};
typedef struct{struct desync_profile_list *current;bool skip,template;}native_profile_flow;
struct state{native_profile_flow flow;struct desync_profile_list entries[2],*entry;struct desync_profile *profile;struct zapret_list_file *host,*host_exclude,*ip,*ip_exclude;uint64_t payload;struct packet_range incoming,outgoing;bool dry;unsigned trace[8],used,fault;};
static struct state *active;static struct zapret_list_file cache_file;static jmp_buf legacy_jump;static int exit_code;
static void trace(unsigned event){CHECK(active->used<8);active->trace[active->used++]=event;}
static uint32_t native_profile_next(native_profile_flow *flow,const char *name){trace(10);CHECK(flow==&active->flow);if(active->fault)return active->fault;flow->current=&active->entries[1];flow->current->dp.name=name;flow->skip=flow->template=false;return 0;}
static uint32_t native_profile_label(struct desync_profile *profile,bool cookie,const char *name){trace(11+cookie);CHECK(profile==active->profile);if(active->fault)return active->fault;if(name){if(cookie)profile->cookie=name;else profile->name=name;}return 0;}
static uint32_t native_profile_import(const native_profile_flow *flow,const char *name){trace(13);CHECK(flow==&active->flow);if(active->fault)return active->fault;flow->current->dp.cookie=name;return 0;}
static void exit_clean(int code){exit_code=code;longjmp(legacy_jump,1);}
static void native_profile_exit(uint32_t status,const char *name){(void)name;if(status)exit_clean(1);}
static bool legacy(unsigned kind,const char *optarg)
{
    struct desync_profile_list *dpl=active->entry;struct desync_profile *dp=active->profile;
#define profile_flow (active->flow)
#define anon_hl (active->host)
#define anon_hl_exclude (active->host_exclude)
#define anon_ips (active->ip)
#define anon_ips_exclude (active->ip_exclude)
#define payload_type (active->payload)
#define range_in (active->incoming)
#define range_out (active->outgoing)
#define bDry (active->dry)
    exit_code=-1;if(setjmp(legacy_jump))return exit_code==0;
    switch(kind){
#include "cli_control_reference.inc"
        default:CHECK(false);
    }
    active->entry=dpl;active->profile=dp;
#undef profile_flow
#undef anon_hl
#undef anon_hl_exclude
#undef anon_ips
#undef anon_ips_exclude
#undef payload_type
#undef range_in
#undef range_out
#undef bDry
    return true;
}
#include "cli_control_windows.inc"
static const zapret_cli_control_ops ops={native_control_next,native_control_label,native_control_import};
static zapret_cli_control_target target_for(void){zapret_cli_control_target value={&active->flow,active->profile,&active->flow.skip,&active->flow.template,{(void **)&active->host,(void **)&active->host_exclude,(void **)&active->ip,(void **)&active->ip_exclude},&active->payload,&active->incoming,&active->outgoing,&active->dry};return value;}
static void initial(struct state *value,unsigned fault,unsigned flags)
{memset(value,0,sizeof(*value));value->fault=fault;value->entries[0].dp.name="previous";value->entries[0].dp.cookie="cookie";value->flow.current=value->entry=&value->entries[0];value->profile=&value->entry->dp;value->flow.skip=flags&1;value->flow.template=flags&2;value->dry=flags&4;value->host=value->host_exclude=value->ip=value->ip_exclude=&cache_file;value->payload=123;value->incoming=(struct packet_range){{'n',2},{'d',9},true};value->outgoing=(struct packet_range){{'b',3},{'p',5},false};}
static bool range_equal(const struct packet_range *a,const struct packet_range *b){return a->from.mode==b->from.mode && a->from.pos==b->from.pos && a->to.mode==b->to.mode && a->to.pos==b->to.pos && a->upper_cutoff==b->upper_cutoff;}
static bool same(const struct state *a,const struct state *b)
{return (a->flow.current==&a->entries[0])==(b->flow.current==&b->entries[0]) && a->flow.skip==b->flow.skip && a->flow.template==b->flow.template && a->entries[0].dp.name==b->entries[0].dp.name && a->entries[0].dp.cookie==b->entries[0].dp.cookie && a->entries[1].dp.name==b->entries[1].dp.name && a->entries[1].dp.cookie==b->entries[1].dp.cookie && a->host==b->host && a->host_exclude==b->host_exclude && a->ip==b->ip && a->ip_exclude==b->ip_exclude && a->payload==b->payload && range_equal(&a->incoming,&b->incoming) && range_equal(&a->outgoing,&b->outgoing) && a->dry==b->dry && a->used==b->used && !memcmp(a->trace,b->trace,a->used*sizeof(unsigned));}
static void compare(unsigned kind,const char *text,unsigned fault,unsigned flags)
{
    struct state a,b,c;initial(&a,fault,flags);initial(&b,fault,flags);initial(&c,fault,flags);
    active=&a;bool expected=legacy(kind,text);active=&b;zapret_cli_control_target target=target_for();unsigned result=zapret_cli_control(kind,text,&target,&ops);
    active=&c;int adapted=engine_control_option(kind,text,&c.flow,&c.entry,&c.profile,&c.host,&c.host_exclude,&c.ip,&c.ip_exclude,&c.payload,&c.incoming,&c.outgoing,&c.dry);
    CHECK(adapted==(result==8?2:result?-(int)result-1:1) && same(&b,&c) && (c.entry==c.flow.current) && c.profile==&c.entry->dp);
    CHECK(expected==(result==0 || result==8));if(kind==2 && fault && !(flags&2)){CHECK(a.flow.template && !b.flow.template);a.flow.template=false;++template_repairs;}CHECK(same(&a,&b));++cases;
}
static void boundary_checks(void)
{
    struct state value;initial(&value,0,0);active=&value;zapret_cli_control_target target=target_for();_Alignas(8) unsigned char storage[128]={0};
#define REJECT(call) do{CHECK((call)==6 && !value.used);++boundaries;}while(0)
    REJECT(zapret_cli_control(0,"x",NULL,&ops));REJECT(zapret_cli_control(0,"x",&target,NULL));REJECT(zapret_cli_control(9,"x",&target,&ops));
    REJECT(zapret_cli_control(0,"x",(const zapret_cli_control_target *)(storage+1),&ops));REJECT(zapret_cli_control(0,"x",&target,(const zapret_cli_control_ops *)(storage+1)));
    target.caches[2]=(void **)(storage+1);REJECT(zapret_cli_control(0,"x",&target,&ops));target=target_for();target.payload=(uint64_t *)(storage+1);REJECT(zapret_cli_control(0,"x",&target,&ops));
    target=target_for();target.outgoing=NULL;REJECT(zapret_cli_control(0,"x",&target,&ops));target=target_for();target.template=NULL;REJECT(zapret_cli_control(2,"x",&target,&ops));
    target=target_for();target.skip=NULL;REJECT(zapret_cli_control(1,"x",&target,&ops));target=target_for();target.dry=NULL;REJECT(zapret_cli_control(6,"x",&target,&ops));
    target=target_for();zapret_cli_control_ops missing={0};REJECT(zapret_cli_control(0,"x",&target,&missing));REJECT(zapret_cli_control(2,"x",&target,&missing));REJECT(zapret_cli_control(5,"x",&target,&missing));REJECT(zapret_cli_control(5,NULL,&target,&ops));
#undef REJECT
    CHECK(zapret_cli_control(7,NULL,&target,&missing)==8 && !value.used);++boundaries;CHECK(!zapret_cli_control(8,NULL,&target,&missing) && !value.used);++boundaries;
}
static void sequence_checks(void)
{
    for(unsigned fault=1;fault<=5;++fault){struct state value;initial(&value,fault,0);active=&value;zapret_cli_control_target target=target_for();CHECK(zapret_cli_control(0,"next",&target,&ops)==fault && value.host && value.payload==123);value.fault=0;CHECK(!zapret_cli_control(0,"next",&target,&ops) && !value.host && value.payload==0 && value.incoming.from.mode=='x' && value.outgoing.to.mode=='a');++sequences;}
}
int main(void)
{
    const char *text[]={NULL,"","name","known","missing","данные-é-中","bad-\xff","retry"};
    for(unsigned repeat=0;repeat<4;++repeat)for(unsigned kind=0;kind<9;++kind)for(unsigned argument=0;argument<8;++argument)for(unsigned fault=0;fault<=5;++fault)for(unsigned flags=0;flags<8;++flags){if(kind==5 && !text[argument])continue;compare(kind,text[argument],fault,flags);}
    boundary_checks();sequence_checks();printf("PASS cli_control functions=9 cases=%u template_error_repairs=%u boundaries=%u sequences=%u c_bridge=1 cache_reset=4\n",cases,template_repairs,boundaries,sequences);return 0;
}
