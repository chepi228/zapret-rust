/* MIT. Native startup ordering and owned default entries, without VM or file I/O. */
#include "params.h"
#include <setjmp.h>
#include <stdarg.h>
#undef main
static unsigned cases,boundaries,atomic_repairs,releases,retries;
#define CHECK(value) do{if(!(value)){fprintf(stderr,"FAIL startup validation cases=%u boundaries=%u line=%d: %s\n",cases,boundaries,__LINE__,#value);exit(1);}}while(0)
typedef struct{void *(*allocate)(size_t);void(*release)(void *);char *(*duplicate)(const char *);bool(*copy)(uint32_t,void *,const void *);void(*destroy)(uint32_t,void *),(*failures)(void *),(*report)(uint32_t);}fixture_profile_ops;
struct desync_profile_list *zapret_profile_add(struct desync_profile_list_head *,const fixture_profile_ops *);
void zapret_profile_list_destroy(struct desync_profile_list_head *,const fixture_profile_ops *);
bool zapret_profile_add_default(struct desync_profile_list_head *,const fixture_profile_ops *);
struct state{struct params_s fields;unsigned count,template_count,fault,live,trace[64],used;bool mutation;};
static struct state *active;static jmp_buf legacy_jump;static struct zapret_list_file automatic, changed_automatic;
#define params (active->fields)
static void trace(unsigned event){CHECK(active->used<64);active->trace[active->used++]=event;}
static void *allocate(size_t size){if(active->fault==2)return NULL;void *value=calloc(1,size);if(value)++active->live;return value;}
static void release(void *value){if(value){CHECK(active->live);--active->live;++releases;free(value);}}
static char *duplicate(const char *text){if(active->fault==1)return NULL;char *value=strdup(text);if(value)++active->live;return value;}
static bool copy(uint32_t kind,void *to,const void *from){(void)kind;(void)to;(void)from;return true;}
static void destroy(uint32_t kind,void *head){(void)kind;CHECK(!*(void **)head);}
static void failures(void *head){CHECK(!*(void **)head);}
static void report(uint32_t event){(void)event;}
static const fixture_profile_ops profile_ops={allocate,release,duplicate,copy,destroy,failures,report};
#define dp_list_add model_add
#define dp_list_destroy model_destroy
#define make_writable_dir model_writable
#define ensure_file_access model_label
#define filter_defaults model_defaults
#define LuaDesyncDebug model_debug
#define test_list_files model_lists
#define lua_test_init_script_files model_scripts
#define LoadAllHostLists model_hosts
#define LoadAllIpsets model_ips
#define HostlistsDebug model_hosts_debug
#define IpsetsDebug model_ips_debug
#define BlobDebug model_blobs_debug
#define DLOG model_log
#define DLOG_ERR model_log
#define DLOG_CONDUP model_log
#undef getenv
#define getenv model_env
static char *model_env(const char *name){CHECK(!strcmp(name,"WRITABLE"));return "fixture-writable";}
static int model_log(const char *format,...)
{
    if (!active->mutation) return 0;
    if (!strcmp(format, "adding low-priority default empty desync profile\n")) params.writable_dir_enable = true;
    if (strstr(format, "auto hostlist file may not be writable")) {
        va_list args;
        va_start(args, format);
        const char *path = va_arg(args, const char *);
        va_end(args);
        CHECK(path == changed_automatic.filename);
        trace(23);
    }
    return 0;
}
static struct desync_profile_list *dp_list_add(struct desync_profile_list_head *head){return zapret_profile_add(head,&profile_ops);}
static void dp_list_destroy(struct desync_profile_list_head *head){trace(600);zapret_profile_list_destroy(head,&profile_ops);}
static bool make_writable_dir(void){trace(10);if(active->mutation)params.debug_target=LOG_TARGET_FILE;return active->fault!=3;}
static bool ensure_file_access(const char *path)
{
    CHECK(path);
    trace(!strcmp(path,"debug")?20:!strcmp(path,"autolog")?21:22);
    if (active->mutation && path == automatic.filename) {
        LIST_FIRST(&params.desync_profiles)->dp.hostlist_auto = &changed_automatic;
        return false;
    }
    return active->fault!=4;
}
static bool filter_defaults(struct desync_profile *profile){trace(100+profile->n);if(active->fault==5)return false;profile->filter_ipv4=profile->filter_ipv6=true;return true;}
static void LuaDesyncDebug(const struct desync_profile *profile,const char *type){trace((!strcmp(type,"template")?300:200)+profile->n);}
static bool test_list_files(void){trace(400);return active->fault!=6;}
static bool lua_test_init_script_files(void){trace(401);return active->fault!=7;}
static bool LoadAllHostLists(void){trace(402);return active->fault!=8;}
static bool LoadAllIpsets(void){trace(403);return active->fault!=9;}
static void HostlistsDebug(void){trace(500);}
static void IpsetsDebug(void){trace(501);}
static void BlobDebug(void){trace(502);}
static void exit_clean(int code){CHECK(code==1);longjmp(legacy_jump,1);}
static bool legacy(void)
{
    struct desync_profile_list *dpl;struct desync_profile *dp;struct{unsigned count,template_count;}profile_flow={active->count,active->template_count};
    if(setjmp(legacy_jump))return false;
#define strdup duplicate
#include "startup_validation_reference.inc"
#undef strdup
    return true;
}
bool native_profile_add_default(struct desync_profile_list_head *head){return zapret_profile_add_default(head,&profile_ops);}
#include "startup_validation_windows.inc"

static zapret_startup_validation_target target_for(void){zapret_startup_validation_target value={&params.desync_profiles,&params.desync_templates,params.debug_logfile,params.hostlist_auto_debuglog,active->count,active->template_count,(const uint32_t *)&params.debug_target,&params.writable_dir_enable,&params.server};return value;}
static void initial(struct state *value,unsigned flags,unsigned user_count)
{
    memset(value,0,sizeof(*value));active=value;params.writable_dir_enable=flags&1;params.debug_target=flags&2?LOG_TARGET_FILE:LOG_TARGET_CONSOLE;strcpy(params.debug_logfile,"debug");if(flags&4)strcpy(params.hostlist_auto_debuglog,"autolog");params.server=flags&8;
    for(unsigned i=0;i<user_count;++i){struct desync_profile_list *entry=dp_list_add(&params.desync_profiles);CHECK(entry);entry->dp.n=i+1;entry->dp.name=duplicate("user");if(flags&16)entry->dp.hostlist_auto=&automatic;}
    active->count=user_count;active->template_count=flags&32?2:0;
    for(unsigned i=0;i<active->template_count;++i){struct desync_profile_list *entry=dp_list_add(&params.desync_templates);CHECK(entry);entry->dp.n=i+1;entry->dp.name=duplicate("template");}
}
static unsigned profile_count(const struct desync_profile_list_head *head){unsigned count=0;const struct desync_profile_list *entry;LIST_FOREACH(entry,head,next)++count;return count;}
static void same_profiles(const struct desync_profile_list_head *a,const struct desync_profile_list_head *b)
{
    const struct desync_profile_list *one=LIST_FIRST(a),*two=LIST_FIRST(b);
    while(one){CHECK(two && one->dp.n==two->dp.n && !!one->dp.name==!!two->dp.name && (!one->dp.name || !strcmp(one->dp.name,two->dp.name)) && one->dp.hostlist_auto==two->dp.hostlist_auto && one->dp.filter_ipv4==two->dp.filter_ipv4 && one->dp.filter_ipv6==two->dp.filter_ipv6);one=LIST_NEXT(one,next);two=LIST_NEXT(two,next);}CHECK(!two);
}
static void same(const struct state *a,const struct state *b){CHECK(a->used==b->used && !memcmp(a->trace,b->trace,a->used*sizeof(unsigned)));same_profiles(&a->fields.desync_profiles,&b->fields.desync_profiles);same_profiles(&a->fields.desync_templates,&b->fields.desync_templates);}
static void cleanup(struct state *state){active=state;state->fault=0;zapret_profile_list_destroy(&params.desync_profiles,&profile_ops);zapret_profile_list_destroy(&params.desync_templates,&profile_ops);CHECK(!state->live);}
static void compare(unsigned flags,unsigned user_count,unsigned fault)
{
    struct state a,b,c;initial(&a,flags,user_count);initial(&b,flags,user_count);initial(&c,flags,user_count);a.fault=b.fault=c.fault=fault;
    active=&a;bool expected=legacy();active=&b;zapret_startup_validation_target target=target_for();uint32_t result=zapret_profile_startup_validate(&target,&startup_validation_ops);active=&c;bool adapted=native_startup_validate(c.count,c.template_count);
    CHECK(expected==!result && adapted==!result);same(&b,&c);
    if(fault==1){CHECK(result==1 && a.used==0 && b.used==0 && profile_count(&a.fields.desync_profiles)==profile_count(&b.fields.desync_profiles)+1);same_profiles(&a.fields.desync_templates,&b.fields.desync_templates);++atomic_repairs;}
    else same(&a,&b);
    cleanup(&a);cleanup(&b);cleanup(&c);++cases;
}
static void boundary_checks(void)
{
    struct state value;initial(&value,0,0);active=&value;zapret_startup_validation_target target=target_for();_Alignas(8) unsigned char storage[128]={0};
#define REJECT(call) do{CHECK((call)==9 && !value.used && !value.live);++boundaries;}while(0)
    REJECT(zapret_profile_startup_validate(NULL,&startup_validation_ops));REJECT(zapret_profile_startup_validate(&target,NULL));REJECT(zapret_profile_startup_validate((const zapret_startup_validation_target *)(storage+1),&startup_validation_ops));REJECT(zapret_profile_startup_validate(&target,(const zapret_startup_validation_ops *)(storage+1)));
    target.profiles=(void *)(storage+1);REJECT(zapret_profile_startup_validate(&target,&startup_validation_ops));target=target_for();target.templates=NULL;REJECT(zapret_profile_startup_validate(&target,&startup_validation_ops));target=target_for();target.debug_file=NULL;REJECT(zapret_profile_startup_validate(&target,&startup_validation_ops));target=target_for();target.auto_log=NULL;REJECT(zapret_profile_startup_validate(&target,&startup_validation_ops));target=target_for();zapret_startup_validation_ops missing=startup_validation_ops;missing.checks[0]=NULL;REJECT(zapret_profile_startup_validate(&target,&missing));
#undef REJECT
    CHECK(!zapret_profile_add_default(NULL,&profile_ops) && !value.live);++boundaries;CHECK(!zapret_profile_add_default(&params.desync_profiles,NULL) && !value.live);++boundaries;
    for(unsigned fault=1;fault<=2;++fault){value.fault=fault;CHECK(!native_profile_add_default(&params.desync_profiles) && !LIST_FIRST(&params.desync_profiles) && !value.live);value.fault=0;CHECK(native_profile_add_default(&params.desync_profiles) && profile_count(&params.desync_profiles)==1);cleanup(&value);++retries;}
}
static void deferred_reads(void)
{
    struct state a, b;
    initial(&a, 16, 1);
    initial(&b, 16, 1);
    a.mutation = b.mutation = true;
    active = &a;
    CHECK(legacy());
    active = &b;
    CHECK(native_startup_validate(b.count, b.template_count));
    CHECK(a.used >= 4 && a.trace[0] == 10 && a.trace[1] == 20 && a.trace[2] == 22 && a.trace[3] == 23);
    same(&a, &b);
    cleanup(&a);
    cleanup(&b);
}
int main(void)
{
    automatic.filename="auto";
    changed_automatic.filename="changed after file access";
    for(unsigned repeat=0;repeat<4;++repeat)for(unsigned flags=0;flags<64;++flags)for(unsigned users=0;users<2;++users)for(unsigned fault=0;fault<10;++fault)compare(flags,users,fault);
    boundary_checks();deferred_reads();printf("PASS startup_validation blocks=1 cases=%u default_atomic_repairs=%u boundaries=%u retry=%u owned_releases=%u c_bridge=1 vm_calls=0 file_io=0 deferred_reads=1\n",cases,atomic_repairs,boundaries,retries,releases);return 0;
}
