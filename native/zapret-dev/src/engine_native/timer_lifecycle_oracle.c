/* MIT. Complete destroy/next/run comparison, callback mutations and C longjmp. */
#define TIMER_LIFECYCLE_ORACLE
#include "timer_lifecycle_fixture.h"
#include <setjmp.h>
#include <inttypes.h>
#undef main
timer_lifecycle_fixture_params timer_lifecycle_params;
void reference_TimerPoolDestroy(timer_pool **);
uint64_t reference_TimerPoolNext(const timer_pool *,bool *);
uint64_t reference_TimerPoolRun(timer_pool **,bool *,uint64_t);
static timer_pool *pool;
static bool dirty;
static uint64_t base,current,trace,returned;
static unsigned cases,entry,scenario,call_error,throw_at,boundaries,calls,depth,stack_length;
static int stack[64];
static jmp_buf failure;
#define CHECK(x) do{if(!(x)){fprintf(stderr,"FAIL timer_lifecycle case=%u line=%u: %s\n",cases,__LINE__,#x);exit(1);}}while(0)
static uint64_t token(uint64_t id){return id?id-base+1:0;}
static void event(unsigned kind,uint64_t value){trace=(trace^kind)*1099511628211ULL;trace=(trace^value)*1099511628211ULL;}
static void boundary(unsigned kind,uint64_t value){event(kind,value);if(++boundaries==throw_at)longjmp(failure,1);}
static void info(const zapret_timer_info *t){event(50,token(t->id));event(51,t->period);event(52,t->fires);event(53,(uint32_t)t->name_ref);event(54,(uint32_t)t->func_ref);event(55,(uint32_t)t->data_ref);event(56,t->oneshot);}
void timer_fixture_registry(void *L,int table,int ref){(void)L;boundary(1,(uint64_t)(uint32_t)table<<32|(uint32_t)ref);CHECK(stack_length<64);stack[stack_length++]=ref;}
const char *timer_fixture_string(void *L,int index){(void)L;boundary(2,(uint32_t)index);static char text[40];CHECK(index<0&&(unsigned)-index<=stack_length);snprintf(text,sizeof(text),"ref-%d",stack[stack_length+index]);return text;}
void timer_fixture_pop(void *L,int n){(void)L;boundary(3,n);CHECK(stack_length>=(unsigned)n);stack_length-=n;}
void timer_fixture_unref(void *L,int table,int ref){(void)L;boundary(4,(uint64_t)(uint32_t)table<<32|(uint32_t)ref);}
void timer_fixture_log(const char *format,...){char text[512];va_list ap;va_start(ap,format);int n=vsnprintf(text,sizeof(text),format,ap);va_end(ap);CHECK(n>=0&&(size_t)n<sizeof(text));uint64_t h=0;for(int i=0;i<n;++i)h=h*131+(unsigned char)text[i];boundary(5,h);}
void timer_fixture_error(void){boundary(6,0);CHECK(stack_length);--stack_length;}
uint64_t timer_fixture_now(void){event(7,100);return 100;}
int timer_fixture_after(const timer_pool *p,uint64_t after,zapret_timer_info *out){event(8,token(after));int r=zapret_timer_after(p,after,out);event(9,r);if(r)info(out);return r;}
int timer_fixture_remove(timer_pool **p,uint64_t id,zapret_timer_info *out){event(10,token(id));int r=zapret_timer_remove(p,id,out);event(11,r);if(r)info(out);return r;}
int timer_fixture_due(timer_pool *p,uint64_t after,uint64_t now,zapret_timer_info *out){event(12,token(after));event(13,now);int r=zapret_timer_due(p,after,now,out);event(14,r);if(r){current=out->id;info(out);}return r;}
int timer_fixture_finish(timer_pool **p,uint64_t id,uint64_t now,int ok,zapret_timer_info *out){event(15,token(id));event(16,now);event(17,ok);int r=zapret_timer_finish(p,id,now,ok,out);event(18,r);if(r)info(out);return r;}
uint64_t timer_fixture_next(const timer_pool *p){uint64_t value=zapret_timer_next(p);event(19,value);return value;}
int timer_fixture_call(void *L,int args,int results,int handler){(void)L;boundary(20,(uint64_t)args<<32|(uint32_t)results);event(21,handler);CHECK(stack_length>=3);stack_length-=3;
    if(!calls++&&scenario){zapret_timer_info old={0};dirty=true;event(22,scenario);
        if(scenario>=2)zapret_timer_remove(&pool,current,&old);
        if(scenario>=3){zapret_timer_info replacement={.period=0,.name_ref=31,.func_ref=32,.data_ref=33,.oneshot=1};CHECK(zapret_timer_set(&pool,"replacement",&replacement,100,&old)>=0);}}
    if(call_error){stack[stack_length++]=99;return 1;}return 0;
}
typedef struct{uint64_t trace,returned,fields[16][8];unsigned count,stack_length,boundaries,calls,status;bool dirty;} sample;
static sample run(bool reference,unsigned seeded,uint64_t now)
{
    pool=NULL;dirty=true;trace=returned=current=base=0;boundaries=calls=depth=stack_length=0;zapret_timer_info old;
    for(unsigned i=0;i<seeded;++i){char name[40];snprintf(name,sizeof(name),"seed-%u",i);zapret_timer_info t={.period=5+i,.name_ref=10+(int)i*3,.func_ref=11+(int)i*3,.data_ref=12+(int)i*3,.oneshot=i&1};CHECK(zapret_timer_set(&pool,name,&t,95,&old)>=0);if(!base){CHECK(zapret_timer_get(pool,name,&t));base=t.id;}}
    unsigned status=(unsigned)setjmp(failure);if(!status){switch(entry){case 1:if(reference)reference_TimerPoolDestroy(&pool);else TimerPoolDestroy(&pool);break;case 2:returned=reference?reference_TimerPoolNext(pool,&dirty):TimerPoolNext(pool,&dirty);break;case 3:returned=reference?reference_TimerPoolRun(&pool,&dirty,now):TimerPoolRun(&pool,&dirty,now);break;}}
    sample s;memset(&s,0,sizeof(s));s.trace=trace;s.returned=returned;s.stack_length=stack_length;s.boundaries=boundaries;s.calls=calls;s.status=status;s.dirty=dirty;
    uint64_t after=0;zapret_timer_info t;while(zapret_timer_after(pool,after,&t)){CHECK(s.count<16);uint64_t *v=s.fields[s.count++];v[0]=token(t.id);v[1]=t.period;v[2]=t.fires;v[3]=(uint32_t)t.name_ref;v[4]=(uint32_t)t.func_ref;v[5]=(uint32_t)t.data_ref;v[6]=t.oneshot;after=t.id;}
    while(zapret_timer_after(pool,0,&t))CHECK(zapret_timer_remove(&pool,t.id,&t));return s;
}
int main(void){const uint64_t times[]={0,99,100,UINT64_MAX};for(entry=1;entry<=3;++entry)for(unsigned seed=0;seed<3;++seed)for(scenario=0;scenario<4;++scenario)for(call_error=0;call_error<2;++call_error)for(throw_at=0;throw_at<18;++throw_at)for(unsigned n=0;n<4;++n){sample a=run(true,seed,times[n]),b=run(false,seed,times[n]);if(memcmp(&a,&b,sizeof(a))){fprintf(stderr,"entry=%u seed=%u scenario=%u error=%u boundary=%u now=%llu trace=%llu/%llu\n",entry,seed,scenario,call_error,throw_at,(unsigned long long)times[n],(unsigned long long)a.trace,(unsigned long long)b.trace);CHECK(0);}++cases;}
    printf("PASS timer_lifecycle entries=3 cases=%u full_vm_trace=1 callback_mutations=1 c_longjmp_boundaries=1\n",cases);return 0;}
