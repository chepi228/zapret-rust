/* MIT. Full entry parity plus observed failure/VM/C-longjmp paths. */
#include "conntrack_fixture.h"
#include <setjmp.h>
#define lua_createtable conntrack_core_create
#define luaL_ref conntrack_core_ref
#define luaL_unref conntrack_core_unref
#define boottime conntrack_core_time
#define fixture_clock_gettime conntrack_core_clock
#include "conntrack_lifecycle_core.inc"
#undef lua_createtable
#undef luaL_ref
#undef luaL_unref
#undef boottime
#undef fixture_clock_gettime
void reference_ConntrackPoolInit(t_conntrack *,time_t,uint32_t,uint32_t,uint32_t,uint32_t);
void reference_ConntrackClearHostname(t_ctrack *);
static bool observing;
static unsigned failure_kind,vm_fault,vm_boundary,extra_cases,base_ref;
static uint64_t native_trace;
static void *last_entry;
static jmp_buf native_failure;
static void observe(unsigned op,uint64_t value){if(observing)native_trace=(native_trace^op)*1099511628211ULL^value;}
static void vm_observe(unsigned op,int value){observe(op,value<0?(uint64_t)(int64_t)value:(unsigned)value-base_ref);if(observing&&++vm_boundary==vm_fault)longjmp(native_failure,1);}
void *conntrack_fixture_malloc(size_t size){observe(1,size);if(observing&&failure_kind==1)return NULL;return last_entry=malloc(size);}
void conntrack_fixture_free(void *p){observe(2,p==last_entry?1:p?2:0);if(p==last_entry)last_entry=NULL;free(p);}
int conntrack_fixture_insert(struct zapret_conntrack_index **slot,const t_conn *key,void *p){observe(3,key->l4proto);if(observing&&failure_kind==2)return 0;return zapret_conntrack_insert(slot,key,p);}
void lua_createtable(lua_State *L,int a,int b){vm_observe(4,-2);observe(5,(uintptr_t)L);conntrack_core_create(L,a,b);}
int luaL_ref(lua_State *L,int index){vm_observe(6,-2);observe(7,(uintptr_t)L);return conntrack_core_ref(L,index);}
void luaL_unref(lua_State *L,int index,int ref){vm_observe(8,ref);observe(9,(uintptr_t)L);conntrack_core_unref(L,index,ref);if(observing)params.L=(lua_State *)((uintptr_t)L+1);}
time_t boottime(void){observe(10,fake_time);return conntrack_core_time();}
int fixture_clock_gettime(clockid_t clock,struct timespec *out){observe(11,clock);return conntrack_core_clock(clock,out);}
typedef struct{uint64_t trace;uintptr_t value;unsigned status,allocated,freed,count;time_t purge;uint32_t limits[4];t_ctrack_positions positions;struct timespec start;int refs[2];bool hostname,hostname_ip;size_t queued,reassembly;} lifecycle_sample;
static t_conntrack *native_table;
static test_packet native_packet;
static t_ctrack *native_track;
static bool native_reverse;
static uintptr_t native_value;

static void prepare_teardown_after_fault(t_ctrack *track)
{
    int *ids[] = {&track->lua_state, &track->lua_instance_cutoff};
    for (unsigned i = 0; i < 2; ++i) {
        int ref = *ids[i];
        if (ref > 0 && (unsigned)ref <= next_ref && !refs[ref])
            *ids[i] = LUA_NOREF;
    }
}

static lifecycle_sample observe_entry(bool reference,unsigned entry)
{
    observing=false;last_entry=NULL;params.L=(lua_State *)(uintptr_t)1;base_ref=next_ref;fake_time=100;
    native_table=reference?reference_create(3,7,11,5,9):calloc(1,sizeof(*native_table));if(!reference)ConntrackPoolInit(native_table,3,7,11,5,9);
    make_packet(&native_packet,0,false,TH_SYN,100,0,0);native_track=NULL;native_reverse=false;
    if(entry!=0&&entry!=6){REQUIRE(reference?reference_feed(native_table,&native_packet.dis,&native_track,&native_reverse):ConntrackPoolFeed(native_table,&native_packet.dis,&native_track,&native_reverse));owned_buffers(native_track,reference);}
    if(entry==1){native_track->pos.state=2;make_packet(&native_packet,0,false,TH_SYN,500,0,2);}
    if(entry==4){fake_time=120;native_track->b_cutoff=true;}
    unsigned before_alloc=allocations,before_free=releases;native_value=native_trace=0;vm_boundary=0;observing=true;
    unsigned status=(unsigned)setjmp(native_failure);if(!status)switch(entry){
        case 0:case 1:native_value=reference?reference_feed(native_table,&native_packet.dis,&native_track,&native_reverse):ConntrackPoolFeed(native_table,&native_packet.dis,&native_track,&native_reverse);break;
        case 2:native_value=reference?reference_drop(native_table,&native_packet.dis):ConntrackPoolDrop(native_table,&native_packet.dis);break;
        case 3:if(reference)reference_destroy(native_table);else ConntrackPoolDestroy(native_table);break;
        case 4:if(reference)reference_purge(native_table);else ConntrackPoolPurge(native_table);break;
        case 5:native_value=reference?reference_search(native_table,&native_packet.dis,&native_track,&native_reverse):ConntrackPoolDoubleSearch(native_table,&native_packet.dis,&native_track,&native_reverse);break;
        case 6:if(reference)reference_ConntrackPoolInit(native_table,3,7,11,5,9);else ConntrackPoolInit(native_table,3,7,11,5,9);break;
        case 7:if(reference)reference_ConntrackClearHostname(native_track);else ConntrackClearHostname(native_track);break;
    }
    observing=false;lifecycle_sample s;memset(&s,0,sizeof(s));s.trace=native_trace;s.value=native_value;s.status=status;s.allocated=allocations-before_alloc;s.freed=releases-before_free;s.purge=native_table->t_last_purge;
    s.limits[0]=native_table->timeout_syn;s.limits[1]=native_table->timeout_established;s.limits[2]=native_table->timeout_fin;s.limits[3]=native_table->timeout_udp;
    uint64_t cursor=0;t_conntrack_pool *e;while((e=zapret_conntrack_after(native_table->pool,&cursor))){++s.count;s.positions=e->track.pos;s.start=e->track.t_start;s.refs[0]=e->track.lua_state<0?e->track.lua_state:e->track.lua_state-(int)base_ref;s.refs[1]=e->track.lua_instance_cutoff<0?e->track.lua_instance_cutoff:e->track.lua_instance_cutoff-(int)base_ref;s.hostname=e->track.hostname!=NULL;s.hostname_ip=e->track.hostname_is_ip;s.queued=rawpacket_queue_count(&e->track.delayed);s.reassembly=e->track.reasm_client.size;}
    /* A fault can interrupt ClearTrack after its first unref or detach an
       entry before its free. Repair already released references only after
       capturing the partial state, so fixture teardown can release the rest. */
    if (status) {
        cursor = 0;
        while ((e = zapret_conntrack_after(native_table->pool, &cursor)))
            prepare_teardown_after_fault(&e->track);
    }
    if(reference)reference_destroy(native_table);else ConntrackPoolDestroy(native_table);
    if(last_entry){t_conntrack_pool *e=last_entry;free(e->track.hostname);ReasmClear(&e->track.reasm_client);rawpacket_queue_destroy(&e->track.delayed);
        int ids[]={e->track.lua_state,e->track.lua_instance_cutoff};for(unsigned i=0;i<2;++i)if(ids[i]>0&&(unsigned)ids[i]<=next_ref&&refs[ids[i]])conntrack_core_unref(params.L,LUA_REGISTRYINDEX,ids[i]);free(e);last_entry=NULL;}
    free(native_table);return s;
}
#undef main
int main(void){int result=conntrack_lifecycle_core_main();REQUIRE(result==0);for(unsigned entry=0;entry<8;++entry)for(failure_kind=0;failure_kind<3;++failure_kind)for(vm_fault=0;vm_fault<8;++vm_fault){lifecycle_sample a=observe_entry(true,entry),b=observe_entry(false,entry);if(memcmp(&a,&b,sizeof(a))){fprintf(stderr,"lifecycle entry=%u failure=%u vm=%u trace=%llu/%llu status=%u/%u\n",entry,failure_kind,vm_fault,(unsigned long long)a.trace,(unsigned long long)b.trace,a.status,b.status);REQUIRE(0);}++extra_cases;}
    printf("PASS conntrack_lifecycle entries=8 fault_cases=%u full_native_vm_trace=1 c_longjmp=1\n",extra_cases);return 0;}
