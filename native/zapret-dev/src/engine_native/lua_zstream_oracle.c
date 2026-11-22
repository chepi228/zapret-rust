/* MIT. Real protected Lua calls, stream parity, injected allocation and VM OOM. */
#include "engine_lua.h"
#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#undef main
static unsigned cases,boundaries,reserve_faults,vm_faults,zero_hints,pointer_checks;
#define CHECK(value) do {if(!(value)){fprintf(stderr,"FAIL Lua zstream cases=%u bounds=%u line=%d: %s\n",cases,boundaries,__LINE__,#value);exit(1);}}while(0)
static void lua_check_argc(lua_State *L,const char *name,int count){if(lua_gettop(L)!=count)luaL_error(L,"%s expects %d arguments",name,count);}
void lua_check_argc_range(lua_State *L,const char *name,int low,int high){int count=lua_gettop(L);if(count<low || count>high)luaL_error(L,"%s expects %d..%d arguments",name,low,high);}
#include "lua_zstream_common.inc"
static bool track_geometry;static unsigned old_reserves,new_reserves;
static void *reference_malloc(size_t size){if(track_geometry)++old_reserves;return malloc(size);}
static void *reference_realloc(void *pointer,size_t size){if(track_geometry)++old_reserves;return realloc(pointer,size);}
#define malloc reference_malloc
#define realloc reference_realloc
#define luacall_gunzip_inflate reference_gunzip_inflate
#define luacall_gzip_deflate reference_gzip_deflate
#include "lua_zstream_reference.inc"
#undef luacall_gunzip_inflate
#undef luacall_gzip_deflate
#undef malloc
#undef realloc
typedef struct {uint8_t *data;size_t length,capacity;bool finished;} test_output;
typedef struct {int (*process)(z_stream *,int);bool (*reserve)(size_t);} stream_ops;
int zapret_lua_zstream_process(z_stream *,bool,const uint8_t *,size_t,uint64_t,bool,void *,const void *);
void zapret_lua_zstream_release(void *);
struct lua_allocator {bool fail;};
static struct lua_allocator allocator;
static unsigned allocated_outputs,released_outputs;static bool arm_vm_failure;
static bool monitored_reserve(size_t size){CHECK(size>=64 && size<=0x7fffff00u);++new_reserves;return true;}
int zapret_zstream_fixture_process(z_stream *stream,bool inflating,const uint8_t *data,size_t length,uint64_t hint,bool hinted,void *out,const void *ops)
{
    stream_ops monitored={inflating?zapret_inflate:zapret_deflate,monitored_reserve};
    int result=zapret_lua_zstream_process(stream,inflating,data,length,hint,hinted,out,track_geometry?&monitored:ops);
    CHECK(!stream->next_in && !stream->avail_in && !stream->next_out && !stream->avail_out);++pointer_checks;
    if(result==Z_OK){test_output *output=out;CHECK(output->data && output->length<=output->capacity);++allocated_outputs;if(arm_vm_failure){CHECK(output->length>64);allocator.fail=true;arm_vm_failure=false;}}
    return result;
}
void zapret_zstream_fixture_release(void *out){test_output *output=out;if(output && output->data)++released_outputs;zapret_lua_zstream_release(out);}
#include "windows_zstream_vm_abi.h"
static void *vm_allocate(void *context,void *pointer,size_t previous,size_t next)
{struct lua_allocator *state=context;if(!next){free(pointer);return NULL;}if(state->fail && next>previous)return NULL;return realloc(pointer,next);}
static lua_State *vm;
static int create_stream(bool inflate,int bits,int level)
{
    lua_settop(vm,0);lua_pushcfunction(vm,inflate?luacall_gunzip_init:luacall_gzip_init);lua_pushinteger(vm,bits);int count=1;if(!inflate){lua_pushinteger(vm,level);lua_pushinteger(vm,8);count=3;}
    CHECK(!lua_pcall(vm,count,1,0) && lua_isuserdata(vm,-1));return luaL_ref(vm,LUA_REGISTRYINDEX);
}
static void end_stream(int reference,bool inflate)
{
    lua_settop(vm,0);lua_pushcfunction(vm,inflate?luacall_gunzip_end:luacall_gzip_end);lua_rawgeti(vm,LUA_REGISTRYINDEX,reference);CHECK(!lua_pcall(vm,1,0,0));luaL_unref(vm,LUA_REGISTRYINDEX,reference);
}
struct snapshot {int status,kind;size_t length;bool finished;uint8_t data[65536];};
static struct snapshot invoke(lua_CFunction function,int reference,const uint8_t *data,size_t length,int64_t hint,bool hinted)
{
    lua_settop(vm,0);lua_pushcfunction(vm,function);lua_rawgeti(vm,LUA_REGISTRYINDEX,reference);int count=1;
    if(data || hinted){if(data)lua_pushlstring(vm,(const char *)data,length);else lua_pushnil(vm);++count;}
    if(hinted){lua_pushinteger(vm,hint);++count;}
    struct snapshot result={0};result.status=lua_pcall(vm,count,2,0);allocator.fail=false;
    if(!result.status){CHECK(lua_gettop(vm)==2);result.kind=lua_type(vm,-2);result.finished=lua_toboolean(vm,-1);if(result.kind==LUA_TSTRING){const char *bytes=lua_tolstring(vm,-2,&result.length);CHECK(result.length<=sizeof(result.data));memcpy(result.data,bytes,result.length);}else CHECK(result.kind==LUA_TNIL && lua_isnil(vm,-1));}
    return result;
}
static struct snapshot compare(lua_CFunction old,lua_CFunction updated,int left,int right,const uint8_t *data,size_t length,int64_t hint,bool hinted)
{
    struct snapshot a=invoke(old,left,data,length,hint,hinted),b=invoke(updated,right,data,length,hint,hinted);
    CHECK(a.status==b.status && a.kind==b.kind && a.length==b.length && a.finished==b.finished && !memcmp(a.data,b.data,a.length));++cases;return b;
}
static uint64_t random_state=0x6c75617a7374726dULL;
static uint8_t next_byte(void){random_state^=random_state<<13;random_state^=random_state>>7;random_state^=random_state<<17;return (uint8_t)random_state;}
static void roundtrip(const uint8_t *input,size_t length,int bits,int level,unsigned split,bool hinted,int64_t hint)
{
    int left=create_stream(false,bits,level),right=create_stream(false,bits,level);uint8_t encoded[131072];size_t used=0;
    size_t cut=length?length/(split+1):0;size_t offset=0;
    while(offset<length){size_t count=cut?cut:1;if(count>length-offset)count=length-offset;struct snapshot value=compare(reference_gzip_deflate,luacall_gzip_deflate,left,right,input+offset,count,hint,hinted);CHECK(!value.status && value.kind==LUA_TSTRING && !value.finished && used+value.length<=sizeof(encoded));memcpy(encoded+used,value.data,value.length);used+=value.length;offset+=count;}
    struct snapshot tail=compare(reference_gzip_deflate,luacall_gzip_deflate,left,right,NULL,0,hint,hinted);CHECK(!tail.status && tail.kind==LUA_TSTRING && tail.finished && used+tail.length<=sizeof(encoded));memcpy(encoded+used,tail.data,tail.length);used+=tail.length;end_stream(left,false);end_stream(right,false);
    left=create_stream(true,bits<0?-15:47,level);right=create_stream(true,bits<0?-15:47,level);uint8_t decoded[65536];size_t decoded_size=0;
    offset=0;bool finished=false;size_t compressed_cut=used/(split+1);if(!compressed_cut)compressed_cut=1;
    while(offset<used){size_t count=compressed_cut;if(count>used-offset)count=used-offset;struct snapshot value=compare(reference_gunzip_inflate,luacall_gunzip_inflate,left,right,encoded+offset,count,hint,hinted);CHECK(!value.status && value.kind==LUA_TSTRING && decoded_size+value.length<=sizeof(decoded));memcpy(decoded+decoded_size,value.data,value.length);decoded_size+=value.length;finished=value.finished;offset+=count;}
    CHECK(finished && decoded_size==length && !memcmp(decoded,input,length));end_stream(left,true);end_stream(right,true);
}
static void independent(void)
{
    static const uint8_t fixture[]={0x1f,0x8b,0x08,0,0,0,0,0,2,0x0a,0x4b,0xce,0x4f,0x49,0x4d,0x66,0x48,0xcb,0xac,0x28,0x29,0x2d,0x4a,0xe5,0xe5,2,0,0x5e,0x47,0xde,0xad,0x0f,0,0,0};
    static const char expected[]="codec\0fixture\r\n";
    for(unsigned cut=1;cut<sizeof(fixture);++cut){int left=create_stream(true,47,6),right=create_stream(true,47,6);struct snapshot a=compare(reference_gunzip_inflate,luacall_gunzip_inflate,left,right,fixture,cut,64,true),b=compare(reference_gunzip_inflate,luacall_gunzip_inflate,left,right,fixture+cut,sizeof(fixture)-cut,64,true);CHECK(!a.status && !b.status && a.kind==LUA_TSTRING && b.kind==LUA_TSTRING && b.finished && a.length+b.length==sizeof(expected)-1 && !memcmp(a.data,expected,a.length) && !memcmp(b.data,expected+a.length,b.length));end_stream(left,true);end_stream(right,true);}
    uint8_t corrupt[sizeof(fixture)];memcpy(corrupt,fixture,sizeof(fixture));corrupt[sizeof(fixture)-8]^=0xff;int left=create_stream(true,47,6),right=create_stream(true,47,6);struct snapshot value=compare(reference_gunzip_inflate,luacall_gunzip_inflate,left,right,corrupt,sizeof(corrupt),64,true);CHECK(!value.status && value.kind==LUA_TNIL);end_stream(left,true);end_stream(right,true);
    right=create_stream(true,47,6);value=invoke(luacall_gunzip_inflate,right,fixture,sizeof(fixture),0,true);CHECK(!value.status && value.kind==LUA_TSTRING && value.finished && value.length==sizeof(expected)-1 && !memcmp(value.data,expected,value.length));end_stream(right,true);++zero_hints;
    for(unsigned inflate=0;inflate<2;++inflate){right=create_stream(inflate!=0,inflate?47:31,6);value=invoke(inflate?luacall_gunzip_inflate:luacall_gzip_deflate,right,fixture,sizeof(fixture),-1,true);CHECK(!value.status && value.kind==LUA_TNIL);++boundaries;value=invoke(inflate?luacall_gunzip_inflate:luacall_gzip_deflate,right,fixture,sizeof(fixture),INT64_MAX,true);CHECK(!value.status && value.kind==LUA_TNIL);++boundaries;end_stream(right,inflate!=0);}
    left=create_stream(true,47,6);right=create_stream(true,47,6);value=compare(reference_gzip_deflate,luacall_gzip_deflate,left,right,NULL,0,0,false);CHECK(value.status);++boundaries;value=compare(reference_gunzip_inflate,luacall_gunzip_inflate,left,right,NULL,0,0,false);CHECK(value.status);++boundaries;value=compare(reference_gunzip_inflate,luacall_gunzip_inflate,left,right,NULL,0,64,true);CHECK(value.status);++boundaries;end_stream(left,true);end_stream(right,true);
}
static unsigned scripted_mode,allocation_calls,fail_after;
static bool allow_reserve(size_t size){CHECK(size>=64 && size<=0x7fffff00u);return allocation_calls++<fail_after;}
static int scripted(z_stream *stream,int flush)
{
    CHECK(flush==0);if(scripted_mode==1)return Z_OK;if(scripted_mode==2){++stream->avail_out;return Z_OK;}if(scripted_mode==3){memcpy(stream->next_out,"abc",3);stream->avail_out-=3;stream->avail_in=0;return Z_STREAM_END;}
    memset(stream->next_out,'x',stream->avail_out);stream->avail_out=0;return Z_OK;
}
static void io_clear(const z_stream *stream){CHECK(!stream->next_in && !stream->avail_in && !stream->next_out && !stream->avail_out);++pointer_checks;}
static void ffi_boundaries(void)
{
    z_stream stream={0};CHECK(inflateInit2(&stream,47)==Z_OK);test_output output={0};uint8_t byte=0;stream_ops ops={scripted,allow_reserve};
    for(unsigned fault=0;fault<4;++fault){scripted_mode=0;allocation_calls=0;fail_after=fault;CHECK(zapret_lua_zstream_process(&stream,true,&byte,1,64,true,&output,&ops)==Z_MEM_ERROR && allocation_calls==fault+1 && !output.data);io_clear(&stream);++reserve_faults;}
    scripted_mode=1;allocation_calls=0;fail_after=1;CHECK(zapret_lua_zstream_process(&stream,true,&byte,1,64,true,&output,&ops)==Z_BUF_ERROR && !output.data);io_clear(&stream);++boundaries;
    scripted_mode=2;allocation_calls=0;CHECK(zapret_lua_zstream_process(&stream,true,&byte,1,64,true,&output,&ops)==-2 && !output.data);io_clear(&stream);++boundaries;
    CHECK(zapret_lua_zstream_process(NULL,true,&byte,1,64,true,&output,&ops)==-2);++boundaries;CHECK(zapret_lua_zstream_process(&stream,true,&byte,1,64,true,NULL,&ops)==-2);++boundaries;
    allocation_calls=0;CHECK(zapret_lua_zstream_process(&stream,true,(const BYTE *)(uintptr_t)1,0x7fffff01u,64,true,&output,&ops)==-2 && !allocation_calls);++boundaries;
    CHECK(zapret_lua_zstream_process(&stream,true,NULL,1,64,true,&output,&ops)==-2 && !allocation_calls);++boundaries;
    CHECK(zapret_lua_zstream_process(&stream,true,&byte,1,UINT64_MAX,true,&output,&ops)==Z_MEM_ERROR && !allocation_calls);++boundaries;
    fail_after=0;CHECK(zapret_lua_zstream_process(&stream,true,&byte,1,0x7fffff00u,true,&output,&ops)==Z_MEM_ERROR && allocation_calls==1);++boundaries;
    scripted_mode=3;allocation_calls=0;fail_after=1;CHECK(!zapret_lua_zstream_process(&stream,true,&byte,1,64,true,&output,&ops) && output.data && output.length==3 && output.finished && !memcmp(output.data,"abc",3));io_clear(&stream);void *saved=output.data;CHECK(zapret_lua_zstream_process(&stream,true,&byte,1,64,true,&output,&ops)==-2 && output.data==saved);++boundaries;
    zapret_lua_zstream_release(&output);zapret_lua_zstream_release(&output);zapret_lua_zstream_release(NULL);CHECK(!output.data && !output.length && !output.capacity && !output.finished);++boundaries;
    stream_ops missing={0};CHECK(zapret_lua_zstream_process(&stream,true,&byte,1,64,true,&output,&missing)==-2);++boundaries;CHECK(inflateEnd(&stream)==Z_OK);
}
static void vm_memory_error(void)
{
    uint8_t data[32768],compressed[65536];
    for(unsigned round=0;round<8;++round)for(unsigned inflate=0;inflate<2;++inflate){
        for(unsigned i=0;i<sizeof(data);++i)data[i]=next_byte();const uint8_t *input=data;size_t length=sizeof(data);
        if(inflate){z_stream encoder={0};CHECK(deflateInit2(&encoder,6,Z_DEFLATED,31,8,Z_DEFAULT_STRATEGY)==Z_OK);encoder.next_in=data;encoder.avail_in=sizeof(data);encoder.next_out=compressed;encoder.avail_out=sizeof(compressed);CHECK(deflate(&encoder,Z_FINISH)==Z_STREAM_END);length=sizeof(compressed)-encoder.avail_out;CHECK(deflateEnd(&encoder)==Z_OK);input=compressed;}
        int reference=create_stream(inflate!=0,inflate?47:31,6);unsigned before=allocated_outputs-released_outputs;arm_vm_failure=true;struct snapshot value=invoke(inflate?luacall_gunzip_inflate:luacall_gzip_deflate,reference,input,length,64,true);CHECK(!arm_vm_failure && value.status==LUA_ERRMEM && allocated_outputs-released_outputs==before+1);
        lua_settop(vm,0);lua_gc(vm,LUA_GCCOLLECT,0);lua_gc(vm,LUA_GCCOLLECT,0);CHECK(allocated_outputs-released_outputs==before);end_stream(reference,inflate!=0);++vm_faults;
    }
}
static void geometric_growth(void)
{
    const size_t size=2*1024*1024;uint8_t *data=malloc(size),*encoded=malloc(size+4096);CHECK(data && encoded);for(size_t i=0;i<size;++i)data[i]=(uint8_t)(i%7);
    z_stream encoder={0};CHECK(deflateInit2(&encoder,6,Z_DEFLATED,31,8,Z_DEFAULT_STRATEGY)==Z_OK);encoder.next_in=data;encoder.avail_in=(uInt)size;encoder.next_out=encoded;encoder.avail_out=(uInt)size+4096;CHECK(deflate(&encoder,Z_FINISH)==Z_STREAM_END);size_t compressed=size+4096-encoder.avail_out;CHECK(deflateEnd(&encoder)==Z_OK);
    int left=create_stream(true,47,6),right=create_stream(true,47,6);track_geometry=true;
    for(unsigned variant=0;variant<2;++variant){lua_settop(vm,0);lua_pushcfunction(vm,variant?luacall_gunzip_inflate:reference_gunzip_inflate);lua_rawgeti(vm,LUA_REGISTRYINDEX,variant?right:left);lua_pushlstring(vm,(const char *)encoded,compressed);lua_pushinteger(vm,64);CHECK(!lua_pcall(vm,3,2,0) && lua_type(vm,-2)==LUA_TSTRING && lua_toboolean(vm,-1));size_t length=0;const char *output=lua_tolstring(vm,-2,&length);CHECK(length==size && !memcmp(output,data,size));++cases;}
    track_geometry=false;CHECK(new_reserves && old_reserves>new_reserves*4);end_stream(left,true);end_stream(right,true);free(data);free(encoded);
}
int main(void)
{
    vm=lua_newstate(vm_allocate,&allocator);CHECK(vm);lua_mt_init_zstream(vm);
    uint8_t data[32768];const size_t lengths[]={0,1,63,64,65,1024,16383,16384,16385,32768};const int bits[]={31,15,-15},levels[]={0,1,6,9};
    for(unsigned pattern=0;pattern<2;++pattern){for(unsigned i=0;i<sizeof(data);++i)data[i]=pattern?next_byte():(uint8_t)(i%7);for(unsigned mode=0;mode<3;++mode)for(unsigned level=0;level<4;++level)for(unsigned length=0;length<10;++length)for(unsigned hint=0;hint<3;++hint)roundtrip(data,lengths[length],bits[mode],levels[level],length%4,hint!=0,hint==1?64:4096);}
    independent();ffi_boundaries();geometric_growth();vm_memory_error();lua_settop(vm,0);lua_gc(vm,LUA_GCCOLLECT,0);lua_gc(vm,LUA_GCCOLLECT,0);CHECK(allocated_outputs==released_outputs);lua_close(vm);
    printf("PASS lua_zstream functions=2 cases=%u boundaries=%u reserve_faults=%u vm_allocation_faults=%u zero_hint_repairs=%u cleared_pointer_checks=%u owned_outputs=%u growth_old=%u growth_rust=%u rust_seh_unwind=1\n",cases,boundaries,reserve_faults,vm_faults,zero_hints,pointer_checks,allocated_outputs,old_reserves,new_reserves);return 0;
}
