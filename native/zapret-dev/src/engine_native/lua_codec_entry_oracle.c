/* MIT. Real LuaJIT, real codecs and counted native/VM allocator lifetimes. */
#include "params.h"
#include "engine_lua.h"
#include "zlib.h"
#include <luajit.h>
#include <stdarg.h>
#include <math.h>
#undef main
#include "lua_entry_common.inc"
static unsigned cases,errors,collections,native_fault_cases,fault_cases,vm_faults,boundaries,native_live,contexts_live;
#define CHECK(v) do{if(!(v)){fprintf(stderr,"FAIL codec entry cases=%u live=%u contexts=%u line=%d: %s\n",cases,native_live,contexts_live,__LINE__,#v);exit(1);}}while(0)
struct sample {int status,type,end_status,repeat_status,window;bool valid,inflate;unsigned starts,ends,allocations,frees,nested;size_t encoded;uint64_t hash;char message[512],end_message[512],repeat_message[512],trace[4096];};
static struct sample *active;static unsigned allocation,fail_allocation,force_failure;static bool mutate_end,native_side;
static void *native_blocks[64],*contexts[8];static void *last_userdata;static unsigned nested_boundary,nested_kind,nested_total;static bool nested_entered,role_current;static void nested_call(lua_State *);
static int boundary_metatable(lua_State *L,int index){if(active && nested_boundary==2 && !nested_entered)nested_call(L);return lua_setmetatable(L,index);}
static void record(const char *format,...){if(!active)return;size_t used=strlen(active->trace);va_list args;va_start(args,format);int count=vsnprintf(active->trace+used,sizeof(active->trace)-used,format,args);va_end(args);CHECK(count>=0 && (size_t)count<sizeof(active->trace)-used);}
static void *native_malloc(size_t size){record("alloc:%zu;",size);++active->allocations;if(++allocation==fail_allocation)return NULL;CHECK(native_live<64);void *data=malloc(size?size:1);if(data)native_blocks[native_live++]=data;return data;}
static void native_free(void *data){record("free:%u;",data!=NULL);++active->frees;if(data){unsigned i=0;while(i<native_live && native_blocks[i]!=data)++i;CHECK(i<native_live);native_blocks[i]=native_blocks[--native_live];}free(data);}
#define malloc native_malloc
#define free native_free
#include "lua_codec_entry_common.inc"
#undef malloc
#undef free
static voidpf inflate_allocate(voidpf opaque,uInt items,uInt size){CHECK(!opaque);return native_malloc((size_t)items*size);}
static void inflate_release(voidpf opaque,voidpf data){CHECK(!opaque);native_free(data);}
static void *userdata(lua_State *L,size_t size){if(active && nested_boundary==1 && !nested_entered)nested_call(L);CHECK(size==sizeof(struct userdata_zs));void *data=lua_newuserdata(L,size);memset(data,0xa5,size);last_userdata=data;return data;}
static void started(z_stream *stream,bool inflating,int bits,int level,int memory){const uint8_t *raw=(const uint8_t *)stream-8;CHECK(raw[0]==0xa5 && raw[1]==0xa5);CHECK(!stream->next_in && !stream->avail_in && !stream->total_in && !stream->next_out && !stream->avail_out && !stream->total_out && !stream->state && !stream->msg && !stream->opaque && !stream->data_type && !stream->adler && !stream->reserved);if(inflating)CHECK(!stream->zalloc && !stream->zfree);else CHECK(stream->zalloc==z_alloc && stream->zfree==z_free);record("start:%u:%d:%d:%d;",inflating,bits,level,memory);++active->starts;active->window=bits;}
static void add_context(z_stream *stream){CHECK(stream->state && contexts_live<8);contexts[contexts_live++]=stream;}
static int start_inflate(z_stream *stream,int bits){started(stream,true,bits,0,0);if(force_failure)return Z_MEM_ERROR;stream->zalloc=inflate_allocate;stream->zfree=inflate_release;int status=zapret_inflate_init(stream,bits);record("result:%d;",status);if(status==Z_OK)add_context(stream);return status;}
static int start_deflate(z_stream *stream,int level,int method,int bits,int memory,int strategy){CHECK(method==Z_DEFLATED && strategy==Z_DEFAULT_STRATEGY);started(stream,false,bits,level,memory);if(force_failure)return Z_MEM_ERROR;int status=zapret_deflate_init(stream,level,method,bits,memory,strategy);record("result:%d;",status);if(status==Z_OK)add_context(stream);return status;}
static int finish(z_stream *stream,bool inflating){record("end:%u;",inflating);++active->ends;uint8_t *raw=(uint8_t *)stream-8;CHECK(raw[0]==1 && raw[1]==(uint8_t)inflating);int status=inflating?zapret_inflate_end(stream):zapret_deflate_end(stream);if(status==Z_OK){unsigned i=0;while(i<contexts_live && contexts[i]!=stream)++i;CHECK(i<contexts_live);contexts[i]=contexts[--contexts_live];}if(mutate_end)raw[1]^=1;return mutate_end?-2:status;}
static int end_inflate(z_stream *stream){return finish(stream,true);}
static int end_deflate(z_stream *stream){return finish(stream,false);}
#undef inflateInit2
#undef deflateInit2
#undef inflateEnd
#undef deflateEnd
#define inflateInit2 start_inflate
#define deflateInit2 start_deflate
#define inflateEnd end_inflate
#define deflateEnd end_deflate
#define lua_newuserdata userdata
#define lua_setmetatable boundary_metatable
#define lua_cfunc_zstream_gc reference_gc
#define lua_uzs reference_stream
#define luacall_gunzip_init reference_gunzip_init
#define luacall_gzip_init reference_gzip_init
#define luacall_gunzip_end reference_gunzip_end
#define luacall_gzip_end reference_gzip_end
#include "lua_codec_entry_reference.inc"
#undef lua_cfunc_zstream_gc
#undef lua_uzs
#undef luacall_gunzip_init
#undef luacall_gzip_init
#undef luacall_gunzip_end
#undef luacall_gzip_end
static const void *codec_ops(void);
#define ZAPRET_LUA_CODEC_OPS ((const zapret_lua_codec_ops *)codec_ops())
#include "lua_codec_windows.inc"
static const void *codec_ops(void){static const zapret_lua_codec_ops ops={start_inflate,start_deflate,end_inflate,end_deflate};return &ops;}
#undef lua_newuserdata
struct allocator {bool armed;unsigned attempts,rejected,limit,live;};static struct allocator *fault_allocator;
static void *allocate(void *context,void *pointer,size_t previous,size_t next){struct allocator *a=context;if(!next){if(pointer){CHECK(a->live);--a->live;}free(pointer);return NULL;}if(a->armed && next>previous && a->attempts++>=a->limit){++a->rejected;return NULL;}bool fresh=!pointer;void *result=realloc(pointer,next);if(result && fresh)++a->live;return result;}
static lua_CFunction init(bool rust,bool inflating){return inflating?(rust?luacall_gunzip_init:reference_gunzip_init):(rust?luacall_gzip_init:reference_gzip_init);}
static lua_CFunction end(bool rust,bool inflating){return inflating?(rust?luacall_gunzip_end:reference_gunzip_end):(rust?luacall_gzip_end:reference_gzip_end);}
static void nested_call(lua_State *L){nested_entered=true;int top=lua_gettop(L);lua_pushcfunction(L,init(native_side,!role_current));if(nested_kind==2)lua_pushboolean(L,false);int status=lua_pcall(L,nested_kind==2?1:0,LUA_MULTRET,0);record("nested:%d;",status);if(!status && lua_type(L,-1)==LUA_TUSERDATA){lua_pushcfunction(L,end(native_side,!role_current));lua_pushvalue(L,top+1);CHECK(!lua_pcall(L,1,0,0));}++active->nested;++nested_total;lua_settop(L,top);lua_gc(L,LUA_GCCOLLECT,0);}
static lua_State *new_vm(bool rust,struct allocator *a){lua_State *L=a?lua_newstate(allocate,a):luaL_newstate();CHECK(L);luaJIT_setmode(L,0,LUAJIT_MODE_ENGINE|LUAJIT_MODE_OFF);CHECK(luaL_newmetatable(L,"userdata_zstream"));lua_pushcfunction(L,rust?lua_cfunc_zstream_gc:reference_gc);lua_setfield(L,-2,"__gc");lua_pop(L,1);return L;}
static void option(lua_State *L,unsigned variant){switch(variant){case 0:lua_pushnil(L);break;case 1:lua_pushboolean(L,false);break;case 2:lua_pushboolean(L,true);break;case 3:lua_pushinteger(L,0);break;case 4:lua_pushinteger(L,-1);break;case 5:lua_pushinteger(L,-15);break;case 6:lua_pushinteger(L,15);break;case 7:lua_pushinteger(L,31);break;case 8:lua_pushinteger(L,47);break;case 9:lua_pushinteger(L,6);break;case 10:lua_pushinteger(L,8);break;case 11:lua_pushinteger(L,9);break;case 12:lua_pushinteger(L,99);break;case 13:lua_pushinteger(L,0x10000001fLL);break;case 14:lua_pushinteger(L,0x100000008LL);break;case 15:lua_pushnumber(L,3.75);break;case 16:lua_pushliteral(L,"31");break;case 17:lua_pushliteral(L,"6");break;case 18:lua_pushliteral(L,"bad");break;case 19:lua_pushliteral(L,"");break;case 20:lua_newtable(L);break;case 21:lua_pushnumber(L,HUGE_VAL);break;case 22:lua_pushnumber(L,0.0/0.0);break;default:lua_pushinteger(L,-4294967311LL);break;}}
static void process_stream(lua_State *L,bool inflating,struct sample *sample){struct userdata_zs *stream=lua_touserdata(L,1);uint8_t output[256];const uint8_t plain[]={99,111,100,101,99,0,102,105,120,116,117,114,101};const uint8_t compressed[]={0x1f,0x8b,0x08,0x00,0x00,0x00,0x00,0x00,0x02,0x03,0x4b,0xce,0x4f,0x49,0x4d,0x66,0x48,0xcb,0xac,0x28,0x29,0x2d,0x4a,0x05,0x00,0x14,0x0b,0x2f,0xcc,0x0d,0x00,0x00,0x00};stream->zs.next_in=inflating?compressed:plain;stream->zs.avail_in=inflating?sizeof(compressed):sizeof(plain);stream->zs.next_out=output;stream->zs.avail_out=sizeof(output);int status=inflating?zapret_inflate(&stream->zs,Z_NO_FLUSH):zapret_deflate(&stream->zs,Z_FINISH);CHECK(stream->zs.avail_out<=sizeof(output));sample->encoded=sizeof(output)-stream->zs.avail_out;if(inflating && !fail_allocation && (sample->window==31 || sample->window==47)){CHECK(status==Z_STREAM_END && sample->encoded==sizeof(plain) && !memcmp(output,plain,sizeof(plain)));}sample->hash=(uint64_t)(uint32_t)status;for(size_t i=0;i<sample->encoded;++i)sample->hash=sample->hash*1099511628211ULL^output[i];stream->zs.next_in=NULL;stream->zs.avail_in=0;stream->zs.next_out=NULL;stream->zs.avail_out=0;}
static void execute(bool rust,bool inflating,unsigned argc,unsigned field,unsigned variant,unsigned close_mode,struct allocator *allocator,struct sample *sample){CHECK(!native_live && !contexts_live);active=sample;native_side=rust;role_current=inflating;nested_entered=false;allocation=0;last_userdata=NULL;lua_State *L=new_vm(rust,allocator);lua_pushcfunction(L,init(rust,inflating));for(unsigned index=1;index<=argc;++index){if(index==field)option(L,variant);else if(index==1)lua_pushinteger(L,inflating?47:31);else if(index==2)lua_pushinteger(L,6);else lua_pushinteger(L,8);}if(allocator){allocator->armed=true;allocator->attempts=allocator->rejected=0;}sample->status=lua_pcall(L,argc,LUA_MULTRET,0);if(allocator)allocator->armed=false;CHECK(lua_gettop(L)==1);sample->type=lua_type(L,1);if(sample->status){const char *text=lua_tostring(L,1);snprintf(sample->message,sizeof(sample->message),"%s",text?text:"");}else if(sample->type==LUA_TUSERDATA){struct userdata_zs *stream=lua_touserdata(L,1);sample->valid=stream->valid;sample->inflate=stream->inflate;CHECK(sample->valid && sample->inflate==inflating && stream->zs.state);if(close_mode!=2){process_stream(L,inflating,sample);lua_pushcfunction(L,end(rust,close_mode==1?!inflating:inflating));lua_pushvalue(L,1);sample->end_status=lua_pcall(L,1,0,0);if(sample->end_status){snprintf(sample->end_message,sizeof(sample->end_message),"%s",lua_tostring(L,-1));lua_pop(L,1);}lua_pushcfunction(L,end(rust,inflating));lua_pushvalue(L,1);sample->repeat_status=lua_pcall(L,1,0,0);if(sample->repeat_status){snprintf(sample->repeat_message,sizeof(sample->repeat_message),"%s",lua_tostring(L,-1));lua_pop(L,1);}}}else CHECK(sample->type==LUA_TNIL);lua_settop(L,0);lua_gc(L,LUA_GCCOLLECT,0);lua_gc(L,LUA_GCCOLLECT,0);++collections;lua_close(L);CHECK(!native_live && !contexts_live);active=NULL;}
static void compare(bool inflating,unsigned argc,unsigned field,unsigned variant,unsigned close_mode){struct sample a={0},b={0};execute(false,inflating,argc,field,variant,close_mode,NULL,&a);execute(true,inflating,argc,field,variant,close_mode,NULL,&b);if(memcmp(&a,&b,sizeof(a))){fprintf(stderr,"DETAIL inflate=%u argc=%u field=%u variant=%u close=%u allocfail=%u forced=%u mutate=%u oldstatus=%d newstatus=%d oldtype=%d newtype=%d\noldmsg=%s\nnewmsg=%s\noldtrace=%s\nnewtrace=%s\n",inflating,argc,field,variant,close_mode,fail_allocation,force_failure,mutate_end,a.status,b.status,a.type,b.type,a.message,b.message,a.trace,b.trace);CHECK(false);}++cases;if(a.status)++errors;}
static void faults(void){fail_allocation=force_failure=0;mutate_end=false;for(unsigned inflate=0;inflate<2;++inflate)for(unsigned side=0;side<2;++side)for(unsigned limit=0;limit<48;++limit){struct allocator a={.limit=limit};struct sample result={0};execute(side!=0,inflate!=0,inflate?1:3,0,0,2,&a,&result);if(result.status){CHECK(result.status==LUA_ERRMEM && a.rejected);++vm_faults;}CHECK(!a.live);++fault_cases;}CHECK(vm_faults>0);}
static void boundary_checks(void){zapret_lua_codec_options options={0};int32_t index=99;CHECK(!zapret_lua_codec_options_begin(2,0,&options));++boundaries;CHECK(!zapret_lua_codec_options_begin(1,2,&options));++boundaries;CHECK(zapret_lua_codec_options_next(NULL,&index)==2 && index==99);++boundaries;CHECK(!zapret_lua_codec_options_observe(&options,2,0));++boundaries;CHECK(zapret_lua_codec_validate(NULL,1)==3);++boundaries;CHECK(zapret_lua_codec_initialize(NULL,&options,NULL,NULL)==-2);++boundaries;CHECK(zapret_lua_codec_finish(NULL,2,NULL)==-2);++boundaries;uint8_t *memory=VirtualAlloc(NULL,8192,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);CHECK(memory);DWORD old;CHECK(VirtualProtect(memory+4096,4096,PAGE_NOACCESS,&old));struct userdata_zs *closed=(void *)(memory+4096-8);memset(closed,0xff,8);((uint8_t *)closed)[0]=0;CHECK(zapret_lua_codec_validate(closed,0)==1);CHECK(zapret_lua_codec_finish(closed,2,NULL)==0);++boundaries;CHECK(VirtualFree(memory,0,MEM_RELEASE));}
int main(void){for(unsigned inflate=0;inflate<2;++inflate)for(unsigned argc=0;argc<5;++argc)for(unsigned field=0;field<=4;++field)for(unsigned variant=0;variant<24;++variant)for(unsigned close_mode=0;close_mode<3;++close_mode)compare(inflate!=0,argc,field,variant,close_mode);for(unsigned inflate=0;inflate<2;++inflate)for(fail_allocation=1;fail_allocation<9;++fail_allocation)for(unsigned close_mode=0;close_mode<3;++close_mode){compare(inflate!=0,inflate?1:3,0,0,close_mode);++native_fault_cases;}fail_allocation=0;for(force_failure=0;force_failure<2;++force_failure)for(unsigned inflate=0;inflate<2;++inflate){mutate_end=true;compare(inflate!=0,inflate?1:3,0,0,0);}mutate_end=false;force_failure=0;for(nested_boundary=1;nested_boundary<=2;++nested_boundary)for(nested_kind=1;nested_kind<=2;++nested_kind)for(unsigned inflate=0;inflate<2;++inflate)for(unsigned close_mode=0;close_mode<3;++close_mode)compare(inflate!=0,inflate?1:3,0,0,close_mode);nested_boundary=0;faults();boundary_checks();printf("PASS lua_codec_entry functions=6 cases=%u vm_errors=%u collections=%u native_fault_cases=%u nested_calls=%u boundaries=%u fault_cases=%u vm_allocation_faults=%u real_luajit=1 actual_codecs=1 exact_options=1 exact_flag_publication=1 exact_native_order=1 native_allocations_released=1 vm_allocations_released=1 c_only_unwind=1\n",cases,errors,collections,native_fault_cases,nested_total,boundaries,fault_cases,vm_faults);return 0;}
