/* MIT. Pinned original cases, real C adapter and controlled backend failures. */
#include <windows.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#undef main
static unsigned cases,boundaries,read_repairs,close_repairs,sequences;
#define CHECK(value) do{if(!(value)){fprintf(stderr,"FAIL list options cases=%u boundaries=%u line=%d: %s\n",cases,boundaries,__LINE__,#value);exit(1);}}while(0)
enum {IDX_HOSTLIST,IDX_HOSTLIST_DOMAINS,IDX_HOSTLIST_EXCLUDE,IDX_HOSTLIST_EXCLUDE_DOMAINS,IDX_HOSTLIST_AUTO,IDX_IPSET,IDX_IPSET_IP,IDX_IPSET_EXCLUDE,IDX_IPSET_EXCLUDE_IP};
struct zapret_list_file{void *hostlist,*ipset;};
#define hostlist_file zapret_list_file
#define ipset_file zapret_list_file
struct desync_profile{struct hostlist_file *hostlist_auto;};
static struct hostlist_file hosts[2];static struct ipset_file ips[2];
struct state{struct desync_profile profile;struct hostlist_file *host,*host_exclude;struct ipset_file *ip,*ip_exclude;unsigned trace[16],used,fault;bool skipped;};
static struct state *active;static jmp_buf legacy_jump;
static void trace(unsigned item){CHECK(active->used<16);active->trace[active->used++]=item;}
static void *register_file(bool ip,void *profile,bool exclude,const char *text)
{CHECK(profile==&active->profile);trace(1u+ip*8u+exclude*4u+(text!=NULL)*2u);if(active->fault==1)return NULL;return ip?(void *)&ips[exclude]:(void *)&hosts[exclude];}
static struct hostlist_file *RegisterHostlist(struct desync_profile *profile,bool exclude,const char *text){return register_file(false,profile,exclude,text);}
static struct ipset_file *RegisterIpset(struct desync_profile *profile,bool exclude,const char *text){return register_file(true,profile,exclude,text);}
static bool parse_domain_list(const char *text,void **pool){CHECK(text && (pool==&hosts[0].hostlist || pool==&hosts[1].hostlist));trace(20u+(pool==&hosts[1].hostlist));return active->fault!=2;}
static bool parse_ip_list(const char *text,void **pool){CHECK(text && (pool==&ips[0].ipset || pool==&ips[1].ipset));trace(22u+(pool==&ips[1].ipset));return active->fault!=2;}
static FILE *mock_fopen(const char *path,const char *mode){CHECK(path && !strcmp(mode,"a+b"));trace(40);return active->fault==3?NULL:(FILE *)(uintptr_t)0x1111;}
static bool is_gzip(FILE *file){CHECK(file==(FILE *)(uintptr_t)0x1111);trace(41);return active->fault==4 || active->fault==7;}
static int mock_ferror(FILE *file){CHECK(file==(FILE *)(uintptr_t)0x1111);return active->fault==5 || active->fault==7;}
static int mock_fclose(FILE *file){CHECK(file==(FILE *)(uintptr_t)0x1111);trace(42);return active->fault>=6?EOF:0;}
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
static void exit_clean(int code){CHECK(code==1);longjmp(legacy_jump,1);}
#define DLOG_ERR quiet
#define fopen mock_fopen
#define fclose mock_fclose
#define ferror mock_ferror
static bool legacy(unsigned kind,const char *optarg)
{
    struct desync_profile *dp=&active->profile;struct{bool skip;}profile_flow={active->skipped};
    // Store directly in the model so a C-only longjmp preserves partial registration.
#define anon_hl (active->host)
#define anon_hl_exclude (active->host_exclude)
#define anon_ips (active->ip)
#define anon_ips_exclude (active->ip_exclude)
    if(setjmp(legacy_jump))return false;
    switch(kind){
#include "cli_list_options_reference.inc"
        default:CHECK(false);
    }
#undef anon_hl
#undef anon_hl_exclude
#undef anon_ips
#undef anon_ips_exclude
    return true;
}
#include "cli_list_options_windows.inc"
#undef DLOG_ERR
#undef fopen
#undef fclose
#undef ferror
#define ops native_list_option_ops
static zapret_list_option_target target_for(unsigned kind)
{void **cache=kind==1?(void **)&active->host:kind==3?(void **)&active->host_exclude:kind==6?(void **)&active->ip:kind==8?(void **)&active->ip_exclude:NULL;zapret_list_option_target target={&active->profile,cache,(void **)&active->profile.hostlist_auto,active->skipped};return target;}
static void initial(struct state *state,unsigned fault,bool skip,bool cached,bool automatic)
{memset(state,0,sizeof(*state));state->fault=fault;state->skipped=skip;if(cached){state->host=&hosts[0];state->host_exclude=&hosts[1];state->ip=&ips[0];state->ip_exclude=&ips[1];}if(automatic)state->profile.hostlist_auto=&hosts[0];}
static bool same(const struct state *a,const struct state *b)
{return a->profile.hostlist_auto==b->profile.hostlist_auto && a->host==b->host && a->host_exclude==b->host_exclude && a->ip==b->ip && a->ip_exclude==b->ip_exclude && a->used==b->used && !memcmp(a->trace,b->trace,a->used*sizeof(unsigned));}
static void compare(unsigned kind,const char *text,unsigned fault,bool skip,bool cached,bool automatic)
{
    struct state a,b,c;initial(&a,fault,skip,cached,automatic);initial(&b,fault,skip,cached,automatic);initial(&c,fault,skip,cached,automatic);
    active=&a;bool expected=legacy(kind,text);active=&b;zapret_list_option_target target=target_for(kind);unsigned result=zapret_cli_list_option(kind,text,&target,&ops);
    active=&c;int adapted=engine_list_option((int)kind,text,&c.profile,skip,&c.host,&c.host_exclude,&c.ip,&c.ip_exclude);CHECK((adapted==1)==!result && same(&b,&c));
    if(kind==4 && !skip && !automatic && (fault==5 || fault==6 || fault==7)){
        CHECK(result==(fault==6?9u:8u) && b.used==3 && b.trace[2]==42 && !b.profile.hostlist_auto);
        if(fault==7)CHECK(!expected && same(&a,&b));
        else {CHECK(expected && a.profile.hostlist_auto==&hosts[0] && a.used==4);if(fault==5)++read_repairs;else ++close_repairs;}
    }else CHECK(expected==!result && same(&a,&b));
    ++cases;
}
static uint32_t unknown_probe(const char *text){(void)text;return 99;}
static void boundary_checks(void)
{
    struct state state;initial(&state,0,false,false,false);active=&state;zapret_list_option_target target=target_for(1);
    CHECK(zapret_cli_list_option(1,"a",NULL,&ops)==1 && !state.used);++boundaries;
    CHECK(zapret_cli_list_option(1,"a",&target,NULL)==1 && !state.used);++boundaries;
    CHECK(zapret_cli_list_option(9,"a",&target,&ops)==1 && !state.used);++boundaries;
    CHECK(zapret_cli_list_option(1,NULL,&target,&ops)==1 && !state.used);++boundaries;
    _Alignas(8) unsigned char storage[64]={0};
    CHECK(zapret_cli_list_option(1,"a",(const zapret_list_option_target *)(storage+1),&ops)==1 && !state.used);++boundaries;
    CHECK(zapret_cli_list_option(1,"a",&target,(const zapret_list_option_ops *)(storage+1))==1 && !state.used);++boundaries;
    target.cached=(void **)(storage+1);CHECK(zapret_cli_list_option(1,"a",&target,&ops)==1 && !state.used);++boundaries;
    target=target_for(4);target.autolist=(void **)(storage+1);CHECK(zapret_cli_list_option(4,"a",&target,&ops)==1 && !state.used);++boundaries;
    target=target_for(4);zapret_list_option_ops other=ops;other.probe_auto=unknown_probe;CHECK(zapret_cli_list_option(4,"a",&target,&other)==1 && !state.used);++boundaries;
    target.profile=NULL;CHECK(zapret_cli_list_option(4,"a",&target,&ops)==1 && !state.used);++boundaries;
    void *guard=VirtualAlloc(NULL,4096,MEM_RESERVE|MEM_COMMIT,PAGE_NOACCESS);CHECK(guard);target.skip=true;target.cached=guard;target.autolist=guard;
    for(unsigned kind=0;kind<9;++kind)CHECK(!zapret_cli_list_option(kind,guard,&target,&ops) && !state.used);
    CHECK(VirtualFree(guard,0,MEM_RELEASE));++boundaries;
    CHECK(engine_list_option(123,NULL,NULL,true,NULL,NULL,NULL,NULL)==0 && !state.used);++boundaries;
}
static void sequence_checks(void)
{
    for(unsigned kind=1;kind<=8;++kind){if(kind!=1 && kind!=3 && kind!=6 && kind!=8)continue;struct state state;initial(&state,2,false,false,false);active=&state;zapret_list_option_target target=target_for(kind);
        CHECK(zapret_cli_list_option(kind,"first",&target,&ops)==4 && *target.cached && state.used==2);
        state.fault=0;CHECK(!zapret_cli_list_option(kind,"second",&target,&ops) && state.used==3);
        CHECK(!zapret_cli_list_option(kind,"third",&target,&ops) && state.used==4);++sequences;
    }
    struct state state;initial(&state,1,false,false,false);active=&state;zapret_list_option_target target=target_for(4);
    CHECK(zapret_cli_list_option(4,"auto",&target,&ops)==2 && !state.profile.hostlist_auto && state.used==4);
    state.fault=0;CHECK(!zapret_cli_list_option(4,"auto",&target,&ops) && state.used==8 && state.profile.hostlist_auto);
    CHECK(zapret_cli_list_option(4,"other",&target,&ops)==5 && state.used==8);++sequences;
}
int main(void)
{
    const char *text[]={"","list.txt","C:/path/data.txt","данные-é-中.txt","a,,b,a","0.0.0.0/0,::/0","x-\xff","example.org,*.example.org"};
    for(unsigned repeat=0;repeat<4;++repeat)for(unsigned kind=0;kind<9;++kind)for(unsigned argument=0;argument<8;++argument)for(unsigned fault=0;fault<8;++fault)for(unsigned flags=0;flags<8;++flags)compare(kind,text[argument],fault,flags&1,flags&2,flags&4);
    struct state state;
    initial(&state,7,false,false,false);
    active=&state;
    observe_diagnostic=true;
    CHECK(engine_list_option(IDX_HOSTLIST_AUTO,"list.txt",&state.profile,false,
        &state.host,&state.host_exclude,&state.ip,&state.ip_exclude)==-1);
    CHECK(!strcmp(diagnostic,"cannot read auto hostlist 'list.txt'\n"));
    CHECK(state.used==3 && state.trace[2]==42 && !state.profile.hostlist_auto);
    observe_diagnostic=false;
    boundary_checks();sequence_checks();printf("PASS cli_list_options functions=9 cases=%u read_error_repairs=%u close_error_repairs=%u boundaries=%u sequences=%u diagnostic_cases=1 c_bridge=1 skipped_io=0\n",cases,read_repairs,close_repairs,boundaries,sequences);return 0;
}
