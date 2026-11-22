/* MIT. Lua owns its stack and userdata; Rust owns bounded policy/store objects.
 * Lua errors occur only after the Rust call has returned. */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <windows.h>
#include <bcrypt.h>
#include <lua.h>
#include <lauxlib.h>
#include "rust_ring.h"
#include "rust_ring_pin.h"

#define RR_MAX_BYTES 262144
#define RR_STORE "zapret-ring.store.v1"
#define RR_CONTEXT "zapret-ring.context.v1"
#define RR_HOSTS "zapret-ring.hosts.v1"
#define RR_STORE_SCHEDULER 34
#define RR_STORE_STAT 36
#define RR_STORE_SLOT 2
#define RR_STORE_PRESENT (UINT64_C(1) << (16 + RR_STORE_SLOT))
typedef struct { double numbers[16]; uint64_t present; const unsigned char *strings[16]; size_t lengths[16]; uint64_t text_present; } rr_request;
typedef struct { uint32_t kind; double number; size_t offset,length; } rr_return;
typedef struct { uint32_t count; rr_return values[8]; void *object; } rr_response;
typedef struct {
    size_t size; uint32_t version;
    int (*invoke)(uint32_t,void *,const rr_request *,rr_response *,unsigned char *,size_t);
    void (*drop_object)(void *);
} rr_api;
_Static_assert(sizeof(rr_request)==400,"request ABI layout");
_Static_assert(sizeof(rr_return)==32,"return ABI layout");
_Static_assert(sizeof(rr_response)==272,"response ABI layout");
_Static_assert(sizeof(rr_api)==32,"API layout");
typedef const rr_api *(*rr_get_api)(void);
typedef struct {void *object;} rr_userdata;
static const rr_api *rr_backend;
static HANDLE rr_pin=INVALID_HANDLE_VALUE;
static HMODULE rr_module;

static int rr_load(void) {
    if(rr_backend)return 1;
    WCHAR path[32768];DWORD length=GetModuleFileNameW(NULL,path,32768);
    if(!length || length>=32768)return 0;
    while(length && path[length-1]!=L'\\' && path[length-1]!=L'/')length--;
    const WCHAR name[]=L"zapret-ring.dll";
    if(length+sizeof(name)/sizeof(WCHAR)>=32768)return 0;
    memcpy(path+length,name,sizeof(name));
    HANDLE pin=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(pin==INVALID_HANDLE_VALUE)return 0;
    LARGE_INTEGER size;if(!GetFileSizeEx(pin,&size) || size.QuadPart<=0 || size.QuadPart>32*1024*1024){CloseHandle(pin);return 0;}
    BCRYPT_ALG_HANDLE provider=NULL;BCRYPT_HASH_HANDLE hash=NULL;unsigned char digest[32],buffer[16384];DWORD read=0;int ok=0;
    if(BCryptOpenAlgorithmProvider(&provider,BCRYPT_SHA256_ALGORITHM,NULL,0)<0)goto done;
    if(BCryptCreateHash(provider,&hash,NULL,0,NULL,0,0)<0)goto done;
    for(;;){if(!ReadFile(pin,buffer,sizeof(buffer),&read,NULL))goto done;if(!read)break;if(BCryptHashData(hash,buffer,read,0)<0)goto done;}
    if(BCryptFinishHash(hash,digest,sizeof(digest),0)<0)goto done;
    char hex[65];for(size_t i=0;i<32;i++)snprintf(hex+i*2,3,"%02X",digest[i]);hex[64]=0;
    if(strcmp(hex,RUST_RING_DLL_SHA256))goto done;
    HMODULE module=LoadLibraryExW(path,NULL,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32);
    if(!module)goto done;
    rr_get_api get=(rr_get_api)GetProcAddress(module,"zapret_ring_api_v1");
    if(!get){FreeLibrary(module);goto done;}
    const rr_api *api=get();
    if(!api || api->version!=1 || api->size!=sizeof(rr_api) || !api->invoke || !api->drop_object){FreeLibrary(module);goto done;}
    rr_backend=api;rr_pin=pin;rr_module=module;ok=1;
done:
    if(hash)BCryptDestroyHash(hash);if(provider)BCryptCloseAlgorithmProvider(provider,0);
    if(!ok)CloseHandle(pin);
    return ok;
}
static int rr_gc(lua_State *L) {
    rr_userdata *object=(rr_userdata *)lua_touserdata(L,1);
    if(object && object->object && rr_backend){rr_backend->drop_object(object->object);object->object=NULL;}
    return 0;
}
static int rr_call(lua_State *L) {
    unsigned op=(unsigned)lua_tointeger(L,lua_upvalueindex(1));
    int arguments=lua_gettop(L);if(arguments>16)return luaL_error(L,"ring native: too many arguments");
    rr_request input;rr_response output;memset(&input,0,sizeof(input));memset(&output,0,sizeof(output));
    void *handle=NULL;rr_userdata *created=NULL;
    const char *object_type=NULL;
    if((op>=2 && op<=8) || op==RR_STORE_STAT)object_type=RR_STORE;else if((op>=10 && op<=12) || op==24 || op==30 || op==RR_STORE_SCHEDULER)object_type=RR_CONTEXT;
    else if(op>=26 && op<=28)object_type=RR_HOSTS;
    if(object_type){rr_userdata *object=(rr_userdata *)luaL_checkudata(L,1,object_type);if(!object->object)return luaL_error(L,"ring native: released object");handle=object->object;}
    for(int i=0;i<arguments;i++){
        int type=lua_type(L,i+1);
        if(type==LUA_TBOOLEAN){input.numbers[i]=lua_toboolean(L,i+1)?1:0;input.present|=(uint64_t)1<<i;}
        else if(type==LUA_TNUMBER){double number=lua_tonumber(L,i+1);if(!isfinite(number))return luaL_error(L,"ring native: nonfinite argument");input.numbers[i]=number;input.present|=(uint64_t)1<<i;}
        else if(type==LUA_TSTRING){input.strings[i]=(const unsigned char *)lua_tolstring(L,i+1,&input.lengths[i]);input.text_present|=(uint64_t)1<<i;}
        else if(op==RR_STORE_SCHEDULER && i==RR_STORE_SLOT && type==LUA_TUSERDATA){
            rr_userdata *store=luaL_checkudata(L,i+1,RR_STORE);
            if(!store->object)return luaL_error(L,"ring native: released object");
            input.strings[i]=(const unsigned char *)store->object;
            input.text_present|=RR_STORE_PRESENT;
        }
        else if(type!=LUA_TNIL && !(i==0 && object_type))return luaL_error(L,"ring native: unsupported argument");
    }
    if(op==1 || op==9 || op==25){
        created=(rr_userdata *)lua_newuserdata(L,sizeof(rr_userdata));created->object=NULL;
        luaL_getmetatable(L,op==1?RR_STORE:(op==9?RR_CONTEXT:RR_HOSTS));lua_setmetatable(L,-2);
    }
    unsigned char small[512],*bytes=small;size_t capacity=sizeof(small);
    if(op==4 || op==15 || op==29){capacity=op==4?RR_MAX_BYTES:32768;bytes=(unsigned char *)lua_newuserdata(L,capacity);}
    int result=rr_backend->invoke(op,handle,&input,&output,bytes,capacity);
    if(result)return luaL_error(L,"ring native: operation %u rejected input (%d)",op,result);
    if(created){created->object=output.object;if(!created->object)return luaL_error(L,"ring native: object unavailable");return 1;}
    if(output.count>8)return luaL_error(L,"ring native: invalid result size");
    for(unsigned i=0;i<output.count;i++){
        const rr_return *value=&output.values[i];
        switch(value->kind){
            case 0:lua_pushnil(L);break;
            case 1:lua_pushnumber(L,value->number);break;
            case 2:lua_pushboolean(L,value->number!=0);break;
            case 3:if(value->offset>capacity || value->length>capacity-value->offset)return luaL_error(L,"ring native: invalid string size");lua_pushlstring(L,(const char *)bytes+value->offset,value->length);break;
            default:return luaL_error(L,"ring native: invalid result type");
        }
    }
    return (int)output.count;
}
int rust_ring_register(lua_State *L) {
    if(!rr_load()){fprintf(stderr,"Rust ring module failed its pinned hash/ABI/load checks (Windows error %lu)\n",(unsigned long)GetLastError());return 0;}
    const char *types[]={RR_STORE,RR_CONTEXT,RR_HOSTS};
    for(unsigned i=0;i<3;i++){luaL_newmetatable(L,types[i]);lua_pushcfunction(L,rr_gc);lua_setfield(L,-2,"__gc");lua_pushliteral(L,"protected native ring object");lua_setfield(L,-2,"__metatable");lua_pop(L,1);}
    const char *names[]={"store_new","store_get","store_put","store_snapshot","store_due","store_commit","store_discard","store_stats","context_new","context_due","context_observe","context_read","network_key","link_guard","state_path","subnet","acked","forged","refused","success","failure","initial","skip","timer_gate","host_new","host_access","host_touch","host_count","legacy_state_path","context_poll","tcp_fallback","host_split","windows_absolute_path","store_scheduler","store_effect","store_stat","host_capacity"};
    lua_newtable(L);
    for(unsigned i=0;i<sizeof(names)/sizeof(names[0]);i++){lua_pushinteger(L,i+1);lua_pushcclosure(L,rr_call,1);lua_setfield(L,-2,names[i]);}
    lua_pushinteger(L,1);lua_setfield(L,-2,"api_version");lua_pushliteral(L,"Rust");lua_setfield(L,-2,"backend");
    lua_setglobal(L,"zapret_ring_native");
    return 1;
}
