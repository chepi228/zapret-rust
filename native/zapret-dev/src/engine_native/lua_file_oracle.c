/* MIT. Real protected LuaJIT entries with injected native boundaries and files. */
#include "params.h"
#include "engine_lua.h"
#include "gzip.h"
#include <luajit.h>
#include <stdarg.h>
#undef main
static unsigned cases,probes,errors,reentries,boundaries,fault_cases,vm_faults,native_cases,live;
#define CHECK(v) do{if(!(v)){fprintf(stderr,"FAIL Lua file cases=%u probes=%u line=%d: %s\n",cases,probes,__LINE__,#v);exit(1);}}while(0)
struct atom {int type;double number;size_t length;char bytes[512];};
struct sample {int outer,status,arity,errno_after;bool normal;unsigned nested;struct atom values[8];char message[12288],trace[4096];};
static struct sample *active;
static bool native_side,real_files,gzip_input;static unsigned open_mask,opened,allocation,fail_allocation,read_failure,depth;
static const char *body;static size_t body_size;static const char *input_name="file.lua";
static void *allocations[32];
static void record(const char *format,...){if(!active)return;size_t size=strlen(active->trace);va_list args;va_start(args,format);int count=vsnprintf(active->trace+size,sizeof(active->trace)-size,format,args);va_end(args);CHECK(count>=0 && (size_t)count<sizeof(active->trace)-size);}
static uint64_t hash(const char *value){uint64_t n=1469598103934665603ULL;for(;*value;++value)n=(n^(uint8_t)*value)*1099511628211ULL;return n;}
static void remember(void *data){if(!data)return;CHECK(live<32);allocations[live++]=data;}
static void *fixture_malloc(size_t size){record("alloc:%zu;",size);if(++allocation==fail_allocation){errno=ENOMEM;return NULL;}void *data=malloc(size?size:1);remember(data);return data;}
static void fixture_free(void *data){record("free:%u;",data!=NULL);if(data){unsigned n=0;while(n<live && allocations[n]!=data)++n;CHECK(n<live);allocations[n]=allocations[--live];}free(data);}
static FILE *fixture_open(const char *name,const char *mode){CHECK(!strcmp(mode,"rb"));record("open:%zu:%llx;",strlen(name),(unsigned long long)hash(name));++opened;if(real_files)return fopen(name,mode);if(opened<32 && (open_mask&(1u<<(opened-1))))return (FILE *)(uintptr_t)opened;errno=ENOENT;return NULL;}
static int fixture_close(FILE *file){record("close;");return real_files?fclose(file):0;}
bool zapret_engine_is_gzip(FILE *,const void *);
int zapret_engine_gzip_read(FILE *,char **,size_t *,size_t,const void *);
static bool fixture_probe(FILE *file){record("magic;");return real_files?zapret_engine_is_gzip(file,NULL):gzip_input;}
static int fixture_read(FILE *file,char **out,size_t *length,size_t extra){CHECK(extra==0);record("read;");*out=NULL;*length=0;if(real_files){int status=zapret_engine_gzip_read(file,out,length,extra,NULL);if(status==Z_STREAM_END)remember(*out);return status;}if(read_failure)return -(int)read_failure;*out=fixture_malloc(body_size?body_size:1);if(!*out)return Z_MEM_ERROR;memcpy(*out,body,body_size);*length=body_size;return Z_STREAM_END;}
static int fixture_loadfile(lua_State *L,const char *name){record("plain;");if(real_files)return luaL_loadfile(L,name);char chunk[PATH_MAX+1];snprintf(chunk,sizeof(chunk),"@%s",name);return luaL_loadbuffer(L,body,body_size,chunk);}
static int fixture_dofile(lua_State *L,const char *name){return fixture_loadfile(L,name)||lua_pcall(L,0,LUA_MULTRET,0);}
#define fopen fixture_open
#define fclose fixture_close
#define is_gzip fixture_probe
#define z_readfile fixture_read
#define malloc fixture_malloc
#define free fixture_free
#undef luaL_dofile
#define luaL_dofile fixture_dofile
#define lua_file_open_test reference_probe
#define luaL_doZfile reference_load
#include "lua_file_reference.inc"
#undef lua_file_open_test
#undef luaL_doZfile
#ifdef ZAPRET_LUA_FILE_DIRECT
#include "lj_frame.h"
#include "lj_err.h"
_Static_assert(LJ_ABI_WIN && LJ_GC64, "LuaJIT file guard needs the Win64 GC64 VM");
_Static_assert(offsetof(lua_State, cframe)==80, "LuaJIT state cframe offset");
_Static_assert(CFRAME_OFS_ERRF==84, "LuaJIT error handler offset");

static int raise_in_loadbuffer;
static int fixture_loadbuffer(lua_State *L,const char *data,size_t length,const char *name)
{
    if (raise_in_loadbuffer) {
        CHECK(live==1);
        record("loader_throw;");
        if (raise_in_loadbuffer == LUA_ERRMEM) lj_err_mem(L);
        lua_pushliteral(L,"fixture loader error");
        return lua_error(L);
    }
    return luaL_loadbuffer(L,data,length,name);
}
#define luaL_loadfile fixture_loadfile
#define luaL_loadbuffer fixture_loadbuffer
#include "windows_lua_file_vm_abi.h"
#undef luaL_loadbuffer
#undef luaL_loadfile
#define native_lua_file_ops zapret_lua_file_vm_native_ops.io
typedef struct {uint32_t phase;int32_t status;}zapret_lua_file_flow;
typedef struct {int32_t status;uint32_t found,gzip;}zapret_lua_file_feedback;
bool zapret_lua_file_probe(const char *,bool *,char *,size_t,const zapret_lua_file_ops *);
uint32_t zapret_lua_file_read(const char *,char **,size_t *,const zapret_lua_file_ops *);
uint32_t zapret_lua_file_step(zapret_lua_file_flow *,const zapret_lua_file_feedback *);
#define LUA_FILE_UNWIND "rust_c_unwind=1 escaped_unwind_release=1 exception_statuses=3 error_handler_order=1"
#else
#include "lua_file_windows.inc"
#define LUA_FILE_UNWIND "c_only_unwind=1"
#endif
#undef malloc
#undef free
#undef fopen
#undef fclose
#define fopen wf_fopen
struct allocator {bool armed;unsigned limit,attempts,rejected,live;};
static struct allocator *fault_allocator;
static void *vm_allocate(void *context,void *pointer,size_t previous,size_t next){struct allocator *state=context;if(!next){if(pointer){CHECK(state->live);--state->live;}free(pointer);return NULL;}if(state->armed && next>previous && state->attempts++>=state->limit){++state->rejected;return NULL;}bool fresh=!pointer;void *result=realloc(pointer,next);if(result && fresh)++state->live;return result;}
static int load(lua_State *L){active->status=native_side?luaL_doZfile(L,input_name):reference_load(L,input_name);active->normal=true;return lua_gettop(L);}
static int reenter(lua_State *L){CHECK(depth++==0);const char *saved=body;size_t saved_size=body_size;body="return 'inner',nil,17";body_size=strlen(body);int top=lua_gettop(L);int status=native_side?luaL_doZfile(L,"nested.lua"):reference_load(L,"nested.lua");record("nested:%d:%d;",status,lua_gettop(L)-top);++active->nested;lua_settop(L,top);body=saved;body_size=saved_size;--depth;return 0;}
static lua_State *new_vm(struct allocator *a){lua_State *L=a?lua_newstate(vm_allocate,a):luaL_newstate();CHECK(L);luaL_openlibs(L);luaJIT_setmode(L,0,LUAJIT_MODE_ENGINE|LUAJIT_MODE_OFF);lua_register(L,"REENTER",reenter);return L;}
static void execute(lua_State *L,bool rust,struct sample *sample){CHECK(!live);native_side=rust;opened=allocation=depth=0;active=sample;lua_settop(L,0);lua_pushcfunction(L,load);errno=EDOM;if(fault_allocator){fault_allocator->armed=true;fault_allocator->attempts=fault_allocator->rejected=0;}sample->outer=lua_pcall(L,0,LUA_MULTRET,0);if(fault_allocator)fault_allocator->armed=false;sample->errno_after=errno;sample->arity=lua_gettop(L);CHECK(sample->arity<=8);if(sample->outer || sample->status){const char *text=lua_tostring(L,-1);snprintf(sample->message,sizeof(sample->message),"%s",text?text:"");}else for(int i=0;i<sample->arity;++i){struct atom *atom=&sample->values[i];atom->type=lua_type(L,i+1);if(atom->type==LUA_TNUMBER)atom->number=lua_tonumber(L,i+1);else if(atom->type==LUA_TBOOLEAN)atom->number=lua_toboolean(L,i+1);else if(atom->type==LUA_TSTRING){const char *bytes=lua_tolstring(L,i+1,&atom->length);CHECK(atom->length<sizeof(atom->bytes));memcpy(atom->bytes,bytes,atom->length);}}CHECK(!live);active=NULL;lua_settop(L,0);}
static void compare(lua_State *L){struct sample a={0},b={0};execute(L,false,&a);execute(L,true,&b);if(memcmp(&a,&b,sizeof(a))){fprintf(stderr,"DETAIL mask=%u gzip=%u allocfail=%u readfail=%u file=%s real=%u oldouter=%d newouter=%d oldstatus=%d newstatus=%d oldarity=%d newarity=%d olderrno=%d newerrno=%d\noldmsg=%s\nnewmsg=%s\noldtrace=%s\nnewtrace=%s\n",open_mask,gzip_input,fail_allocation,read_failure,input_name,real_files,a.outer,b.outer,a.status,b.status,a.arity,b.arity,a.errno_after,b.errno_after,a.message,b.message,a.trace,b.trace);CHECK(false);}++cases;if(a.outer||a.status)++errors;reentries+=a.nested;if(real_files)++native_cases;}
static void probe_cases(void){char names[3][PATH_MAX+64];strcpy(names[0],"file.lua");memset(names[1],'a',sizeof(names[1])-1);names[1][sizeof(names[1])-1]=0;strcpy(names[2],"file.lua.gz");for(unsigned name=0;name<3;++name)for(open_mask=0;open_mask<8;++open_mask)for(unsigned magic=0;magic<2;++magic)for(fail_allocation=0;fail_allocation<3;++fail_allocation)for(unsigned optional=0;optional<4;++optional){gzip_input=magic;struct sample a={0},b={0};char left[PATH_MAX+16],right[PATH_MAX+16];memset(left,0xa5,sizeof(left));memset(right,0xa5,sizeof(right));bool ag=true,bg=true;opened=allocation=0;active=&a;bool ar=reference_probe(names[name],optional&1?&ag:NULL,optional&2?left:NULL);CHECK(!live);opened=allocation=0;active=&b;bool br=lua_file_open_test(names[name],optional&1?&bg:NULL,optional&2?right:NULL);CHECK(!live);CHECK(ar==br && ag==bg && !memcmp(left,right,sizeof(left)) && !strcmp(a.trace,b.trace));active=NULL;++probes;}}
static void native_files(lua_State *L){real_files=true;open_mask=~0u;fail_allocation=read_failure=0;const char *name="lua-file-\xd0\xb4\xd0\xb0\xd0\xbd\xd0\xbd\xd1\x8b\xd0\xb5-\xc3\xa9.lua";char gz[256];snprintf(gz,sizeof(gz),"%s.gz",name);const char *scripts[]={"return 1,'real',nil,true","error('native file failure')","local invalid = !","\xef\xbb\xbf#!/lua\nreturn 42",""};for(unsigned i=0;i<5;++i){body=scripts[i];body_size=strlen(body);FILE *file=fopen(name,"wb");CHECK(file);CHECK(fwrite(body,1,body_size,file)==body_size);CHECK(!fclose(file));input_name=name;compare(L);z_stream stream={0};uint8_t compressed[2048];CHECK(deflateInit2(&stream,6,Z_DEFLATED,31,8,Z_DEFAULT_STRATEGY)==Z_OK);stream.next_in=(Bytef *)body;stream.avail_in=(uInt)body_size;stream.next_out=compressed;stream.avail_out=sizeof(compressed);CHECK(deflate(&stream,Z_FINISH)==Z_STREAM_END);size_t size=sizeof(compressed)-stream.avail_out;CHECK(deflateEnd(&stream)==Z_OK);file=fopen(gz,"wb");CHECK(file);CHECK(fwrite(compressed,1,size,file)==size);CHECK(!fclose(file));compare(L);CHECK(!remove(name));input_name=name;compare(L);input_name=gz;compare(L);CHECK(!remove(gz));}real_files=false;input_name="file.lua";}
static void faults(void){const char *scripts[]={"return 1,'fault',nil,true","local invalid = !","error('file fault path')","local x={} for i=1,100 do x[i]=string.rep('x',100) end return #x"};open_mask=~0u;read_failure=fail_allocation=0;for(unsigned script=0;script<4;++script)for(unsigned magic=0;magic<2;++magic){body=scripts[script];body_size=strlen(body);gzip_input=magic;for(unsigned side=0;side<2;++side)for(unsigned limit=0;limit<128;++limit){struct allocator a={.limit=limit};lua_State *L=new_vm(&a);struct sample result={0};fault_allocator=&a;execute(L,side!=0,&result);fault_allocator=NULL;if(result.outer==LUA_ERRMEM || result.status==LUA_ERRMEM || (result.status && a.rejected)){CHECK(a.rejected);++vm_faults;}lua_close(L);CHECK(!a.live && !live);++fault_cases;}}CHECK(vm_faults>100);}
static void boundary_checks(void){const zapret_lua_file_ops *ops=&native_lua_file_ops;char path[8];memset(path,0xa5,sizeof(path));CHECK(!zapret_lua_file_probe(NULL,NULL,path,sizeof(path),ops));++boundaries;CHECK(!zapret_lua_file_probe("x",NULL,path,0,ops));++boundaries;CHECK(!zapret_lua_file_probe("x",NULL,NULL,1,ops));++boundaries;CHECK(!zapret_lua_file_probe("x",NULL,path,sizeof(path),NULL));++boundaries;CHECK(zapret_lua_file_read("x",NULL,NULL,ops)==3);++boundaries;CHECK(zapret_lua_file_step(NULL,NULL)==10);++boundaries;zapret_lua_file_flow flow={0};zapret_lua_file_feedback feedback={.found=2};CHECK(zapret_lua_file_step(&flow,&feedback)==10 && flow.phase==0);++boundaries;uint8_t *memory=VirtualAlloc(NULL,8192,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);CHECK(memory);DWORD old;CHECK(VirtualProtect(memory+4096,4096,PAGE_NOACCESS,&old));char *edge=(char *)memory+4096-8;memcpy(edge,"edge.gz",8);struct sample sample={0};active=&sample;open_mask=~0u;opened=allocation=0;fail_allocation=0;CHECK(zapret_lua_file_probe(edge,NULL,path,sizeof(path),ops));CHECK(!strcmp(path,"edge.gz"));active=NULL;CHECK(VirtualFree(memory,0,MEM_RELEASE));++boundaries;}
#ifdef ZAPRET_LUA_FILE_DIRECT
static unsigned handler_calls;
static bool handler_fails;

static int handle_loader_error(lua_State *L)
{
    CHECK(live==1 && lua_gettop(L)==1);
    CHECK(!strcmp(lua_tostring(L,1),"fixture loader error"));
    ++handler_calls;
    record("handle_error;");
    lua_pushliteral(L,"handler result");
    return handler_fails ? lua_error(L) : 1;
}

static void escaped_unwind(void)
{
    struct sample result={0};
    lua_State *L=new_vm(NULL);
    open_mask=7;
    gzip_input=true;
    fail_allocation=read_failure=0;
    body="return 'fixture'";
    body_size=strlen(body);
    raise_in_loadbuffer=LUA_ERRRUN;
    execute(L,true,&result);
    raise_in_loadbuffer=false;
    CHECK(result.outer==LUA_ERRRUN && !result.normal && result.arity==1);
    CHECK(!strcmp(result.message,"fixture loader error"));
    CHECK(strstr(result.trace,"loader_throw;free:1;") && !live);

    const int statuses[]={LUA_ERRRUN,LUA_ERRERR,LUA_ERRMEM};
    const char *messages[]={"handler result","error in error handling","not enough memory"};
    for (unsigned i=0;i<3;++i) {
        struct sample handled={0};
        handler_calls=0;
        handler_fails=i==1;
        raise_in_loadbuffer=i==2 ? LUA_ERRMEM : LUA_ERRRUN;
        native_side=true;
        opened=allocation=depth=0;
        active=&handled;
        lua_pushcfunction(L,handle_loader_error);
        lua_pushcfunction(L,load);
        CHECK(lua_pcall(L,0,LUA_MULTRET,1)==statuses[i]);
        CHECK(!handled.normal && lua_gettop(L)==2 && !live);
        CHECK(!strcmp(lua_tostring(L,-1),messages[i]));
        CHECK(handler_calls==(i==2 ? 0 : 1));
        CHECK(strstr(handled.trace,i==2 ? "loader_throw;free:1;" :
                                         "loader_throw;handle_error;free:1;"));
        active=NULL;
        lua_settop(L,0);
    }
    raise_in_loadbuffer=0;
    lua_close(L);
}
#endif
int main(void){probe_cases();lua_State *L=new_vm(NULL);const char *scripts[]={"return 1,'value',nil,true","local invalid = !","error('file runtime failure')","REENTER();return 'outer'","return 'x\\0y'","coroutine.yield('stop')","local a={} for i=1,20 do a[i]=i end return #a",""};for(unsigned script=0;script<8;++script){body=scripts[script];body_size=strlen(body);for(open_mask=0;open_mask<8;++open_mask)for(unsigned magic=0;magic<2;++magic)for(fail_allocation=0;fail_allocation<4;++fail_allocation)for(read_failure=0;read_failure<4;++read_failure){gzip_input=magic;compare(L);}}native_files(L);lua_close(L);faults();boundary_checks();
#ifdef ZAPRET_LUA_FILE_DIRECT
escaped_unwind();
#endif
printf("PASS lua_file cases=%u probes=%u vm_errors=%u reentries=%u native_cases=%u boundaries=%u fault_cases=%u vm_allocation_faults=%u real_luajit=1 exact_native_order=1 exact_partial_paths=1 exact_arity=1 files_closed_before_vm=1 native_allocations_released=1 vm_allocations_released=1 " LUA_FILE_UNWIND "\n",cases,probes,errors,reentries,native_cases,boundaries,fault_cases,vm_faults);return 0;}
