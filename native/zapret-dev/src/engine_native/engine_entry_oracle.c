/* MIT. No live services, capture handles, VM or filesystem mutations. */
#include <iphlpapi.h>
#define native_profile_finish mock_profile_finish
#define cleanup_args mock_cleanup_args
#define cleanup_params mock_cleanup_params
#include "params.h"
#include "nfqws.h"
#include <setjmp.h>
#include <stdarg.h>
#include <limits.h>
#undef main
#undef close_std
#undef close_std_and_exit
#define close_std mock_close_std
#define close_std_and_exit mock_close_std_and_exit
struct params_s params;
#include "profile_flow_windows.h"
#include "engine_entry_capture_type.inc"
#include "engine_entry_abi.h"
enum {IDX_NEW=34,IDX_SSID_FILTER_NEG=73,IDX_NLM_FILTER_NEG=75,IDX_OTHER=2};
static const struct option long_options[76]={
    [IDX_NEW]={"new"},[IDX_SSID_FILTER_NEG]={"ssid-filter-neg"},[IDX_NLM_FILTER_NEG]={"nlm-filter-neg"},[IDX_OTHER]={"число"},
};
typedef struct{uint32_t status,error;}zapret_capture_prepare_result;
struct fixture {
    int returns[6],index,argc,run_result,returned,escaped;unsigned mutation,depth,used,nested;
    uint64_t events[96],payload;char log[2048],save[32],*text;char **argv;
    native_profile_flow flow;struct desync_profile_list entries[2],*entry;struct desync_profile *profile;
    struct zapret_list_file files[4],*anonymous[4];struct packet_range incoming,outgoing;
    bool dry,ipv4,ipv6,lan,loopback,empty,duplicate,validation,owned,jump;
    unsigned index_value,sub_index,hashes[16];uint32_t profile_status,capture_status,lifecycle_status;
    zapret_capture_cli capture;
};
static struct fixture left,right,*active;
static jmp_buf escape;
static bool native_side;
static unsigned route_cases,finish_cases,reentries,escape_cases,boundaries,guarded;
#define CHECK(v) do{if(!(v)){fprintf(stderr,"FAIL entry routes=%u finish=%u line=%d: %s\n",route_cases,finish_cases,__LINE__,#v);exit(1);}}while(0)
static void event(uint32_t kind,uint32_t value){CHECK(active->used<96);active->events[active->used++]=((uint64_t)kind<<32)|value;}
static int message(const char *format,va_list args)
{size_t used=strlen(active->log);int out=vsnprintf(active->log+used,sizeof(active->log)-used,format,args);CHECK(out>=0 && (size_t)out<sizeof(active->log)-used);return out;}
int DLOG(const char *format,...){va_list args;va_start(args,format);int out=message(format,args);va_end(args);return out;}
int DLOG_ERR(const char *format,...){va_list args;va_start(args,format);int out=message(format,args);va_end(args);return out;}
void cleanup_args(struct params_s *value){CHECK(value==&params && active->depth==0);event(21,active->argc);}
void cleanup_params(struct params_s *value){CHECK(value==&params && active->depth==0);event(27,0);}
void close_std(void){CHECK(active->depth==0);event(29,0);}
void close_std_and_exit(int code){close_std();event(31,(uint32_t)code);active->escaped=1;active->returned=code;longjmp(escape,1);}
static void exit_clean(int code){cleanup_params(&params);close_std_and_exit(code);}
#include "profile_flow_windows.inc"
static void nested_route(void);
static int stage(unsigned category)
{
    CHECK(category<6);++active->depth;event(category+1,active->profile->n);
    if(active->mutation&1){
        active->profile->n+=category+1;active->profile->name=category&1?"changed profile":"";
        active->payload=active->payload*3+category+1;active->incoming.from.pos+=category;active->outgoing.to.pos+=category;
        active->anonymous[category%4]=&active->files[(category+1)%4];active->flow.skip=!active->flow.skip;
        if(category==1){active->entry=&active->entries[1];active->profile=&active->entry->dp;active->ipv4=!active->ipv4;}
    }
    if((active->mutation&2) && category==1 && active->depth==1)nested_route();
    int result=active->returns[category];--active->depth;return result;
}
static void option_check(int index,const char *text,struct desync_profile *profile)
{CHECK(index==active->index && text==active->text && profile==active->profile);}
static int engine_numeric_option(int index,const char *text,struct desync_profile *profile){option_check(index,text,profile);return stage(0);}
static int engine_startup_option(int index,const char *text){option_check(index,text,active->profile);return stage(1);}
static int engine_list_option(int index,const char *text,struct desync_profile *profile,bool skip,
    struct zapret_list_file **a,struct zapret_list_file **b,struct zapret_list_file **c,struct zapret_list_file **d)
{option_check(index,text,profile);CHECK(skip==active->flow.skip && a==&active->anonymous[0] && b==&active->anonymous[1] && c==&active->anonymous[2] && d==&active->anonymous[3]);return stage(2);}
static int engine_profile_filter(int index,const char *text,struct desync_profile *profile,uint64_t *payload,struct packet_range *in,struct packet_range *out)
{option_check(index,text,profile);CHECK(payload==&active->payload && in==&active->incoming && out==&active->outgoing);return stage(3);}
static int engine_capture_option(int index,const char *text,zapret_capture_cli *capture)
{option_check(index,text,active->profile);CHECK(capture==&active->capture);return stage(4);}
static int engine_control_option(int index,const char *text,native_profile_flow *flow,struct desync_profile_list **entry,struct desync_profile **profile,
    struct zapret_list_file **a,struct zapret_list_file **b,struct zapret_list_file **c,struct zapret_list_file **d,uint64_t *payload,struct packet_range *in,struct packet_range *out,bool *dry)
{option_check(index,text,*profile);CHECK(flow==&active->flow && entry==&active->entry && profile==&active->profile && a==&active->anonymous[0] && b==&active->anonymous[1] && c==&active->anonymous[2] && d==&active->anonymous[3] && payload==&active->payload && in==&active->incoming && out==&active->outgoing && dry==&active->dry);return stage(5);}
uint32_t native_profile_finish(native_profile_flow *flow)
{CHECK(active->depth==0 && flow==&active->flow);event(20,flow->count);if(active->mutation){++flow->count;flow->template_count+=2;}return active->profile_status;}
static bool native_startup_validate(unsigned count,unsigned templates)
{CHECK(active->argc==0 && active->argv==NULL && count==active->flow.count && templates==active->flow.template_count);event(22,count);if(active->mutation)active->dry=!active->dry;return active->validation;}
static zapret_capture_prepare_result native_capture_prepare(unsigned index,unsigned sub_index,bool ipv4,bool ipv6,bool lan,bool loopback,bool empty,bool duplicate,bool dry,const char *save,const unsigned *hashes,HANDLE *mutex)
{CHECK(index==active->index_value && sub_index==active->sub_index && ipv4==active->ipv4 && ipv6==active->ipv6 && lan==active->lan && loopback==active->loopback && empty==active->empty && duplicate==active->duplicate && dry==active->dry && save==active->save && hashes==active->hashes && !*mutex);event(23,active->capture_status);if(active->owned)*mutex=(HANDLE)(uintptr_t)0x1234;return(zapret_capture_prepare_result){active->capture_status,87};}
static uint32_t native_lifecycle_prepare(bool dry){CHECK(dry==active->dry);event(24,active->lifecycle_status);return active->lifecycle_status;}
static int win_main(void)
{CHECK(active->depth==0);event(25,(uint32_t)active->run_result);if(active->jump){active->escaped=2;active->returned=123;longjmp(escape,2);}return active->run_result;}
static void native_lifecycle_release_mutex(HANDLE *mutex){CHECK(active->depth==0);event(28,*mutex!=NULL);*mutex=NULL;}
#ifdef ZAPRET_DIRECT_NATIVE_ENTRY
static const struct option *fixture_options(void) { return long_options; }
static uint32_t fixture_prepare(struct params_s *settings, bool dry)
{
    CHECK(settings==&params);
    return native_lifecycle_prepare(dry);
}
#define zapret_native_cli_options fixture_options
#define zapret_native_lifecycle_prepare fixture_prepare
#define zapret_native_lifecycle_release_mutex native_lifecycle_release_mutex
#include "engine_entry_rust.inc"
#undef zapret_native_lifecycle_release_mutex
#undef zapret_native_lifecycle_prepare
#undef zapret_native_cli_options
#else
#include "engine_entry_windows.inc"
#endif
static bool native_engine_option(native_engine_cli *state)
{
    zapret_engine_route route = zapret_engine_option_route(state,
        state->index == IDX_SSID_FILTER_NEG || state->index == IDX_NLM_FILTER_NEG,
        native_engine_option_category);
    return native_engine_apply_option_result(state, route);
}

static void reference_profile_exit(uint32_t status, const char *name)
{
    switch (status) {
        case 0: return;
        case 1: DLOG_ERR("desync_profile_add: out of memory\n"); break;
        case 2: DLOG_ERR("template '%s' already present\n", name); break;
        case 3: DLOG_ERR("template '%s' not found\n", name); break;
        case 4: DLOG_ERR("could not copy template\n"); break;
        default: DLOG_ERR("desync profile count out of range\n"); break;
    }
    exit_clean(1);
}

typedef struct{native_engine_cli cli;int *argc_pointer;char ***argv_pointer;}native_engine_reference;
#define native_profile_exit reference_profile_exit
#include "engine_entry_reference_aliases.inc"
#include "engine_entry_reference.inc"
#undef native_profile_exit
#undef option_index
#undef optarg
#undef dp
#undef dpl
#undef profile_flow
#undef anon_hl
#undef anon_hl_exclude
#undef anon_ips
#undef anon_ips_exclude
#undef payload_type
#undef range_in
#undef range_out
#undef bDry
#undef capture_cli
#undef IfIdx
#undef SubIfIdx
#undef wf_ipv4
#undef wf_ipv6
#undef wf_filter_lan
#undef wf_filter_loopback
#undef wf_tcp_empty
#undef bDupCheck
#undef wf_save_file
#undef hash_wf
#undef argc
#undef argv
static void prepare(struct fixture *value)
{
    value->used=value->nested=value->depth=0;value->returned=-999;value->escaped=0;value->log[0]=0;value->argc=3;value->argv=(char **)(void *)value->events;
    value->entry=&value->entries[0];value->profile=&value->entry->dp;value->entries[0].dp.n=11;value->entries[1].dp.n=17;
    value->entries[0].dp.name=value->entries[1].dp.name="profile";value->flow.count=2;value->flow.template_count=1;
    for(unsigned i=0;i<4;++i)value->anonymous[i]=&value->files[i];
    strcpy(value->save,"fixture-filter.txt");value->capture=(zapret_capture_cli){value->save,sizeof(value->save),&value->ipv4,&value->ipv6,&value->lan,&value->loopback,&value->empty,&value->duplicate,&value->index_value,&value->sub_index,value->hashes};
}
static native_engine_cli input(struct fixture *value)
{return(native_engine_cli){value->index,value->text,&value->flow,&value->entry,&value->profile,{&value->anonymous[0],&value->anonymous[1],&value->anonymous[2],&value->anonymous[3]},&value->payload,&value->incoming,&value->outgoing,&value->dry,&value->capture};}
static void nested_route(void)
{
    struct fixture child={.index=IDX_OTHER,.returns={0,0,0,0,1,0}};prepare(&child);struct fixture *parent=active;active=&child;
    native_engine_cli route=input(&child);CHECK((native_side?native_engine_option:reference_engine_option)(&route));CHECK(child.used==5);
    active=parent;++active->nested;++reentries;event(10,child.used);
}
static unsigned file_id(const struct fixture *value,const struct zapret_list_file *file)
{for(unsigned i=0;i<4;++i)if(file==&value->files[i])return i;CHECK(false);return 0;}
static void same(void)
{
    if(left.returned!=right.returned || left.escaped!=right.escaped || left.used!=right.used || memcmp(left.events,right.events,left.used*sizeof(*left.events)) || strcmp(left.log,right.log)){
        fprintf(stderr,"DETAIL returned=%d/%d escaped=%d/%d events=%u/%u oldlog=%s newlog=%s\n",left.returned,right.returned,left.escaped,right.escaped,left.used,right.used,left.log,right.log);CHECK(false);
    }
    CHECK(left.nested==right.nested && left.payload==right.payload && left.flow.skip==right.flow.skip && left.flow.count==right.flow.count && left.flow.template_count==right.flow.template_count);
    CHECK(left.profile->n==right.profile->n && !strcmp(left.profile->name,right.profile->name) && (left.profile==&left.entries[1].dp)==(right.profile==&right.entries[1].dp));
    CHECK(left.incoming.from.pos==right.incoming.from.pos && left.outgoing.to.pos==right.outgoing.to.pos && left.dry==right.dry && left.ipv4==right.ipv4);
    CHECK(left.argc==right.argc && (left.argv==NULL)==(right.argv==NULL));
    for(unsigned i=0;i<4;++i)CHECK(file_id(&left,left.anonymous[i])==file_id(&right,right.anonymous[i]));
}
static void execute(bool native,bool finish)
{
    struct fixture *value=native?&right:&left;prepare(value);active=value;native_side=native;
    if(!setjmp(escape)){
        if(finish)value->returned=(native?native_engine_finish:reference_engine_finish)(&value->flow,value->profile,&value->capture,&value->dry,&value->argc,&value->argv);
        else {native_engine_cli route=input(value);value->returned=(native?native_engine_option:reference_engine_option)(&route);}
    }
    CHECK(value->depth==0);
}
static int32_t minimum_result(void *context,uint32_t category){CHECK(context==&left);return category==5?INT32_MIN:0;}
static void boundaries_check(void)
{
    _Alignas(8) uint8_t bytes[32]={0};zapret_engine_finish flow={0};zapret_engine_finish_feedback feedback={0};
#define BOUND(v) do{CHECK(v);++boundaries;}while(0)
    BOUND(zapret_engine_option_route(NULL,false,minimum_result).action==ENTRY_INVALID);
    BOUND(zapret_engine_option_route(&left,false,NULL).action==ENTRY_INVALID);
    zapret_engine_route route=zapret_engine_option_route(&left,false,minimum_result);BOUND(route.action==ENTRY_CONTROL_ERROR && route.status==INT32_MAX);
    BOUND(zapret_engine_finish_step(NULL,&feedback)==FINISH_INVALID);
    BOUND(zapret_engine_finish_step(&flow,NULL)==FINISH_INVALID);
    BOUND(zapret_engine_finish_step((void *)(bytes+1),&feedback)==FINISH_INVALID);
    BOUND(zapret_engine_finish_step(&flow,(void *)(bytes+1))==FINISH_INVALID);
    flow.phase=UINT_MAX;BOUND(zapret_engine_finish_step(&flow,&feedback)==FINISH_INVALID && flow.phase==UINT_MAX);
    uint8_t *memory=VirtualAlloc(NULL,8192,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);CHECK(memory);DWORD previous;
    CHECK(VirtualProtect(memory+4096,4096,PAGE_NOACCESS,&previous));zapret_engine_finish_feedback *at=(void *)(memory+4096-sizeof(*at));*at=feedback;
    CHECK(VirtualProtect(memory,4096,PAGE_READONLY,&previous));
    for(unsigned phase=0;phase<=13;++phase){flow=(zapret_engine_finish){.phase=phase};BOUND(zapret_engine_finish_step(&flow,at)!=FINISH_INVALID);++guarded;}
    CHECK(VirtualFree(memory,0,MEM_RELEASE));
#undef BOUND
}

enum { SCAN_DRY=1, SCAN_NUMBER=2, SCAN_VERSION=4, SCAN_BLOB=17, SCAN_SSID=73 };
static const struct option scan_options[74] = {
    [SCAN_DRY] = {"dry-run", no_argument, NULL, 0},
    [SCAN_NUMBER] = {"intercept", optional_argument, NULL, 0},
    [SCAN_VERSION] = {"version", no_argument, NULL, 0},
    [SCAN_BLOB] = {"blob", required_argument, NULL, 0},
    [SCAN_SSID] = {"ssid-filter-neg", optional_argument, NULL, 0},
};
struct scan_fixture {
    int index;
    char *argument;
    bool dry, set_dry_from_log;
    unsigned reads[74], reports;
};
static struct scan_fixture *scanning;
static bool present_environment;
static char empty_environment[] = "";
static unsigned environment_reads;

static char *scan_environment(const char *name)
{
    CHECK(!strcmp(name, "POSIXLY_CORRECT"));
    ++environment_reads;
    return present_environment ? empty_environment : NULL;
}

static int32_t scan_category(void *context, uint32_t category)
{
    struct scan_fixture *scan = context;
    CHECK(scan->index >= 0 && scan->index < 74);
    ++scan->reads[scan->index];
    switch (scan->index) {
    case SCAN_DRY:
        if (category == 5) { scan->dry = true; return 1; }
        break;
    case SCAN_SSID:
        CHECK(category != 0 && !strcmp(scan->argument, "1"));
        return category == 4;
    case SCAN_VERSION:
        return category == 5 ? 2 : 0;
    case SCAN_NUMBER:
        CHECK(category == 0);
        return -1;
    }
    return 0;
}

static int scan_stderr(const char *format, ...)
{
    CHECK(!strcmp(format, "%s: %s -- %.*s\n") && !scanning->argument);
    ++scanning->reports;
    if (scanning->set_dry_from_log) scanning->dry = true;
    return 0;
}

static void check_argument_scan(void)
{
    struct scan_fixture scan = {0};
    scanning = &scan;
    const zapret_engine_scan_ops ops = {
        scan_options, sizeof(scan_options)/sizeof(*scan_options), &scan, scan_category,
        &scan.argument, &scan.index, scan_stderr, &scan.dry
    };
    char *argv[] = {"engine", "operand", "--dry-run", "--ssid-filter-neg=1", "--blob=one",
        "--blob=two", "--unknown", "--version"};
    size_t argc = sizeof(argv)/sizeof(*argv);
    zapret_engine_scan_cursor cursor = zapret_engine_scan_begin(scan_environment);
    CHECK(cursor.next == 1 && !cursor.stop_at_operand && environment_reads == 1);
    zapret_engine_scan_event event = zapret_engine_scan_arguments((int)argc, argv, &cursor, &ops);
    CHECK(cursor.next == 5 && event.route.action == ENTRY_LOAD_BLOB && !strcmp(scan.argument, "one"));
    CHECK(event.blob_maximum == 16384 && event.blob_reserve == 128 && scan.dry);
    CHECK(scan.reads[SCAN_DRY] == 6 && scan.reads[SCAN_SSID] == 4 && scan.reads[SCAN_BLOB] == 6);
    present_environment = 1;
    event = zapret_engine_scan_arguments((int)argc, argv, &cursor, &ops);
    CHECK(cursor.next == 6 && event.route.action == ENTRY_LOAD_BLOB && !strcmp(scan.argument, "two"));
    event = zapret_engine_scan_arguments((int)argc, argv, &cursor, &ops);
    CHECK(cursor.next == 7 && event.route.action == ENTRY_EXIT_ERROR && scan.reports == 1 && !scan.reads[SCAN_VERSION]);
    CHECK(environment_reads == 1);

    scan = (struct scan_fixture){0};
    cursor = zapret_engine_scan_begin(scan_environment);
    CHECK(cursor.next == 1 && cursor.stop_at_operand && environment_reads == 2);
    event = zapret_engine_scan_arguments((int)argc, argv, &cursor, &ops);
    CHECK(cursor.next == argc && event.route.action == ENTRY_PARSE_DONE && !scan.reads[SCAN_DRY]);

    char *stops[] = {"engine", "--unknown", "--version", "--intercept=bad", "--blob=late"};
    cursor = (zapret_engine_scan_cursor){ .next = 1 };
    event = zapret_engine_scan_arguments(5, stops, &cursor, &ops);
    CHECK(cursor.next == 2 && event.route.action == ENTRY_PARSE_HELP);
    scan.set_dry_from_log = true;
    cursor.next = 1;
    event = zapret_engine_scan_arguments(5, stops, &cursor, &ops);
    CHECK(cursor.next == 2 && event.route.action == ENTRY_EXIT_ERROR && !scan.reads[SCAN_VERSION]);
    event = zapret_engine_scan_arguments(5, stops, &cursor, &ops);
    CHECK(cursor.next == 3 && event.route.action == ENTRY_EXIT_SUCCESS && !scan.reads[SCAN_NUMBER]);
    event = zapret_engine_scan_arguments(5, stops, &cursor, &ops);
    CHECK(cursor.next == 4 && event.route.action == ENTRY_NUMERIC_ERROR && !scan.reads[SCAN_BLOB]);
}

#ifdef ZAPRET_DIRECT_NATIVE_ENTRY
static unsigned check_rust_bindings(void)
{
    const struct {
        const char *argument;
        unsigned index, category, calls, action;
        int result;
    } cases[] = {
        {"--intercept=bad", SCAN_NUMBER, 0, 1, ENTRY_NUMERIC_ERROR, -1},
        {"--version", SCAN_VERSION, 5, 6, ENTRY_EXIT_SUCCESS, 2},
        {"--blob=one", SCAN_BLOB, 5, 6, ENTRY_LOAD_BLOB, 0},
        {"--ssid-filter-neg=1", SCAN_SSID, 4, 4, ENTRY_PARSE_DONE, 1},
    };
    for (unsigned i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        char argument[40];
        strcpy(argument, cases[i].argument);
        char *argv[] = {"engine", argument};
        struct fixture test = {.index = cases[i].index};
        test.returns[cases[i].category] = cases[i].result;
        char *separator = strchr(argument, '=');
        test.text = separator ? separator + 1 : NULL;
        prepare(&test);
        active = &test;
        native_engine_cli cli = input(&test);
        zapret_engine_scan_cursor cursor = {.next = 1};
        zapret_engine_scan_event event = zapret_native_cli_scan(2, argv, &cursor, &cli,
            scan_options, sizeof(scan_options) / sizeof(*scan_options), DLOG_ERR);
        CHECK(event.route.action == cases[i].action && cursor.next == 2);
        CHECK(cli.index == test.index &&
            cli.text == (event.route.action == ENTRY_PARSE_DONE ? NULL : test.text) &&
            test.used == cases[i].calls);
        if (event.route.action == ENTRY_LOAD_BLOB)
            CHECK(event.blob_maximum == 16384 && event.blob_reserve == 128);
    }
    return sizeof(cases) / sizeof(*cases);
}

static unsigned run_blob_count, run_blob_fail;
static const char *run_second_blob;

static bool run_read_blob(const char *argument, size_t maximum, size_t reserve)
{
    CHECK(active->index==SCAN_BLOB && active->text==argument);
    CHECK(maximum==16384 && reserve==128);
    CHECK(!strcmp(argument,run_blob_count ? "two" : "one"));
    ++run_blob_count;
    active->text=(char *)run_second_blob;
    return run_blob_count!=run_blob_fail;
}

static unsigned check_argument_runs(void)
{
    const zapret_native_argument_ops ops = {
        scan_options, sizeof(scan_options)/sizeof(*scan_options), scan_environment,
        DLOG_ERR, run_read_blob,
    };
    struct argument_run {
        int index, count, numeric, control;
        char *first, *second;
        unsigned fail, reads, action;
        bool dry;
        int code;
    } cases[] = {
        {SCAN_BLOB,3,0,0,"--blob=one","--blob=two",0,2,NATIVE_ARGUMENT_DONE,false,0},
        {SCAN_BLOB,3,0,0,"--blob=one","--blob=two",1,1,NATIVE_ARGUMENT_EXIT,false,1},
        {0,2,0,0,"--unknown",NULL,0,0,NATIVE_ARGUMENT_HELP,false,0},
        {0,2,0,0,"--unknown",NULL,0,0,NATIVE_ARGUMENT_EXIT,true,1},
        {SCAN_VERSION,2,0,2,"--version",NULL,0,0,NATIVE_ARGUMENT_EXIT,false,0},
        {SCAN_NUMBER,2,-1,0,"--intercept=bad",NULL,0,0,NATIVE_ARGUMENT_EXIT,false,1},
    };
    present_environment=0;
    unsigned previous_reads=environment_reads;
    for(unsigned i=0;i<sizeof(cases)/sizeof(*cases);++i){
        const struct argument_run *fixture=&cases[i];
        struct fixture test={.index=fixture->index,.dry=fixture->dry};
        test.returns[0]=fixture->numeric;
        test.returns[5]=fixture->control;
        char *separator=strchr(fixture->first,'=');
        test.text=separator ? separator+1 : NULL;
        char *argv[]={"engine",fixture->first,fixture->second};
        prepare(&test);
        active=&test;
        run_blob_count=0;
        run_blob_fail=fixture->fail;
        run_second_blob=fixture->second ? strchr(fixture->second,'=')+1 : NULL;
        native_engine_cli cli=input(&test);
        zapret_native_argument_result result=zapret_native_cli_run(fixture->count,argv,&cli,&ops);
        CHECK(result.action==fixture->action && result.exit_code==fixture->code);
        CHECK(run_blob_count==fixture->reads && environment_reads==previous_reads+i+1);
        if(fixture->numeric<0)CHECK(strstr(test.log,"invalid numeric value"));
    }
    return sizeof(cases)/sizeof(*cases);
}
#endif

#ifdef ZAPRET_DIRECT_NATIVE_ENTRY
static void check_main_storage(void)
{
    zapret_engine_main_options options;
    zapret_engine_main_defaults(&options);
    unsigned hashes[16]={0};
    native_profile_flow flow={0};
    struct desync_profile_list item={0},*entry=&item;
    struct desync_profile *profile=&item.dp;
    zapret_capture_cli capture;
    native_engine_cli cli;
    memset(&capture,0xa5,sizeof(capture));
    memset(&cli,0xa5,sizeof(cli));
    zapret_native_main_bind(&options,hashes,&flow,&entry,&profile,&capture,&cli);
    CHECK(cli.index==0 && cli.text==NULL && cli.flow==&flow && cli.entry==&entry);
    CHECK(cli.profile==&profile && cli.payload==&options.payload &&
        cli.incoming==&options.incoming && cli.outgoing==&options.outgoing &&
        cli.dry==&options.dry && cli.capture==&capture);
    for(unsigned i=0;i<4;++i)CHECK(cli.anonymous[i]==&options.anonymous[i]);
    CHECK(capture.save==options.save && capture.save_capacity==sizeof(options.save));
    CHECK(capture.ipv4==&options.ipv4 && capture.ipv6==&options.ipv6 &&
        capture.lan==&options.lan && capture.loopback==&options.loopback &&
        capture.empty==&options.empty && capture.duplicate==&options.duplicate);
    CHECK(capture.index==&options.index && capture.sub_index==&options.sub_index &&
        capture.hashes==hashes);
    *cli.dry=true;
    *capture.index=17;
    capture.hashes[15]=23;
    CHECK(options.dry && options.index==17 && hashes[15]==23);
}
#endif

int main(void)
{
    const int options[3][4]={{-1,0,1,2},{-7,0,2,3},{-4,0,1,INT32_MAX}};
    const int indices[]={IDX_NEW,IDX_SSID_FILTER_NEG,IDX_NLM_FILTER_NEG,IDX_OTHER};
    for(unsigned bank=0;bank<3;++bank)for(unsigned encoded=0;encoded<4096;++encoded)for(unsigned index=0;index<4;++index)for(unsigned mutation=0;mutation<4;++mutation){
        memset(&left,0,sizeof(left));left.index=indices[index];left.mutation=mutation;left.text=encoded&1?NULL:"параметр";
        for(unsigned category=0;category<6;++category)left.returns[category]=options[bank][(encoded>>(category*2))&3];right=left;
        execute(false,false);execute(true,false);same();++route_cases;
    }
    const uint32_t profiles[]={0,1,2,6,UINT_MAX},capture[]={0,1,2,3,5,6,7,8,9,UINT_MAX},lifecycle[]={0,1,2,8,9,UINT_MAX};
    const int results[]={0,1,5,87,INT32_MAX,INT32_MIN,-1,-87};
    for(unsigned p=0;p<5;++p)for(unsigned validation=0;validation<2;++validation)for(unsigned c=0;c<10;++c)for(unsigned l=0;l<6;++l)for(unsigned r=0;r<8;++r)for(unsigned owned=0;owned<2;++owned)for(unsigned mutation=0;mutation<2;++mutation)for(unsigned jump=0;jump<2;++jump){
        memset(&left,0,sizeof(left));left.profile_status=profiles[p];left.validation=validation;left.capture_status=capture[c];left.lifecycle_status=lifecycle[l];left.run_result=results[r];left.owned=owned;left.mutation=mutation;left.jump=jump;
        left.ipv4=left.lan=true;left.index_value=17;left.sub_index=23;left.hashes[0]=0x12345678;right=left;
        execute(false,true);execute(true,true);same();if(left.escaped==2)++escape_cases;++finish_cases;
    }
    CHECK(reentries && escape_cases);boundaries_check();check_argument_scan();
    unsigned rust_cases = 0, argument_runs = 0;
#ifdef ZAPRET_DIRECT_NATIVE_ENTRY
    rust_cases = check_rust_bindings();
    check_main_storage();
    argument_runs = check_argument_runs();
#endif
    printf("PASS engine_entry categories=6 route_cases=%u finish_cases=%u reentries=%u c_unwind_cases=%u boundaries=%u guarded=%u scan_cases=8 rust_dispatch=%d rust_scan_cases=%u rust_main_storage=%d rust_argument_runs=%u mutable_profiles=1 early_exits=1 cleanup_order=1 exact_exit_codes=1 no_live_mutations=1\n",
        route_cases,finish_cases,reentries,escape_cases,boundaries,guarded,rust_cases!=0,rust_cases,rust_cases!=0,argument_runs);
    return 0;
}
