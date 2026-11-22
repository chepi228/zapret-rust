/* MIT. Complete entries through real protected LuaJIT and migrated helpers. */
#include "params.h"
#include "engine_lua.h"
#include <luajit.h>
#include "lua_buffer_abi.h"
#include "windows_buffer_vm_abi.h"
#undef main
#include "lua_buffer_common.inc"
void zapret_helper_fill_random_bytes(uint8_t *,size_t);
void zapret_helper_fill_random_az(uint8_t *,size_t);
void zapret_helper_fill_random_az09(uint8_t *,size_t);
bool zapret_helper_parse_hex_str(const char *,uint8_t *,size_t *);
void zapret_helper_bxor(const uint8_t *,const uint8_t *,uint8_t *,size_t);
void zapret_helper_bor(const uint8_t *,const uint8_t *,uint8_t *,size_t);
void zapret_helper_band(const uint8_t *,const uint8_t *,uint8_t *,size_t);
bool zapret_engine_crypto_random(uint8_t *,size_t);
static unsigned cases,errors,native_calls,nested_total,fault_cases,vm_faults,boundaries,production_cases;
#define CHECK(v) do{if(!(v)){fprintf(stderr,"FAIL Lua buffer cases=%u line=%d: %s\n",cases,__LINE__,#v);exit(1);}}while(0)
struct sample {int status,arity,type;size_t length;uint8_t bytes[2048];char message[512];unsigned calls,nested;uint64_t trace,arguments,nested_hash;int32_t next_random;};
static struct sample *active;
static bool native_side,nested_entered,inside_native,fail_entropy,production;
static unsigned nested_boundary,nested_kind;
static void nested_call(lua_State *);
static uint64_t hash(const void *data,size_t length){uint64_t n=1469598103934665603ULL;const uint8_t *bytes=data;for(size_t i=0;i<length;++i)n=(n^bytes[i])*1099511628211ULL;return n;}
static void event(unsigned kind,size_t length){if(active)active->trace=(active->trace*1099511628211ULL^kind)*1099511628211ULL^length;}
static void *boundary_userdata(lua_State *L,size_t length){CHECK(!inside_native);if(active && nested_boundary==1 && !nested_entered)nested_call(L);event(100,length);void *p=lua_newuserdata(L,length);memset(p,0xa5,length);return p;}
static void boundary_string(lua_State *L,const char *data,size_t length){CHECK(!inside_native);if(active && nested_boundary==2 && !nested_entered)nested_call(L);event(101,length);lua_pushlstring(L,data,length);}
static void boundary_pop(lua_State *L,int count){event(102,count);lua_pop(L,count);}
static void boundary_remove(lua_State *L,int index){event(103,(size_t)index);lua_remove(L,index);}
static bool run_backend(uint32_t mode,const uint8_t *first,size_t first_size,const uint8_t *second,size_t second_size,uint8_t *output,size_t *length){
    CHECK(!inside_native);inside_native=true;++native_calls;if(active){++active->calls;event(mode,*length);event(20,first_size);event(21,second_size);event(22,hash(first,first_size));event(23,hash(second,second_size));}
    bool result=true;switch(mode){
    case 0:zapret_helper_fill_random_bytes(output,*length);break;
    case 1:zapret_helper_fill_random_az(output,*length);break;
    case 2:zapret_helper_fill_random_az09(output,*length);break;
    case 3:memset(output,0xa5,*length);if(fail_entropy)result=false;else for(size_t i=0;i<*length;++i)output[i]=(uint8_t)(i*17+31);break;
    case 4:result=zapret_helper_parse_hex_str((const char *)first,output,length);break;
    case 5:zapret_helper_bxor(first,second,output,*length);break;
    case 6:zapret_helper_bor(first,second,output,*length);break;
    case 7:zapret_helper_band(first,second,output,*length);break;
    default:CHECK(false);
    }if(active){event(24,*length);event(25,result);}inside_native=false;return result;
}
static void fill_bytes(uint8_t *p,size_t n){size_t count=n;CHECK(run_backend(0,NULL,0,NULL,0,p,&count));}
static void fill_az(uint8_t *p,size_t n){size_t count=n;CHECK(run_backend(1,NULL,0,NULL,0,p,&count));}
static void fill_az09(uint8_t *p,size_t n){size_t count=n;CHECK(run_backend(2,NULL,0,NULL,0,p,&count));}
static bool fill_crypto(uint8_t *p,size_t n){size_t count=n;return run_backend(3,NULL,0,NULL,0,p,&count);}
static bool parse_hex(const char *p,uint8_t *out,size_t *n){return run_backend(4,(const uint8_t *)p,*n*2,NULL,0,out,n);}
static void binary(unsigned mode,const uint8_t *a,const uint8_t *b,uint8_t *p,size_t n){size_t count=n;CHECK(run_backend(mode,a,n,b,n,p,&count));}
static void xor_bytes(const uint8_t *a,const uint8_t *b,uint8_t *p,size_t n){binary(5,a,b,p,n);}
static void or_bytes(const uint8_t *a,const uint8_t *b,uint8_t *p,size_t n){binary(6,a,b,p,n);}
static void and_bytes(const uint8_t *a,const uint8_t *b,uint8_t *p,size_t n){binary(7,a,b,p,n);}
void *zapret_buffer_fixture_userdata(lua_State *L,size_t length){return boundary_userdata(L,length);}
void zapret_buffer_fixture_string(lua_State *L,const char *data,size_t length){boundary_string(L,data,length);}
void zapret_buffer_fixture_settop(lua_State *L,int index){boundary_pop(L,-1-index);}
void zapret_buffer_fixture_remove(lua_State *L,int index){boundary_remove(L,index);}
bool zapret_buffer_fixture_step(zapret_lua_buffer_state *state,const zapret_lua_buffer_value *value,
    zapret_lua_buffer_action *action,const zapret_lua_buffer_ops *ops)
{
    CHECK(ops==NULL);
    static const zapret_lua_buffer_ops observed={run_backend};
    return zapret_lua_buffer_step(state,value,action,production?NULL:&observed);
}
#define lua_newuserdata boundary_userdata
#define lua_pushlstring boundary_string
#undef lua_pop
#define lua_pop boundary_pop
#define lua_remove boundary_remove
#define fill_random_bytes fill_bytes
#define fill_random_az fill_az
#define fill_random_az09 fill_az09
#define fill_crypto_random_bytes fill_crypto
#define parse_hex_str parse_hex
#define bxor xor_bytes
#define bor or_bytes
#define band and_bytes
#define luac_bop reference_bop
#define luacall_brandom reference_random
#define luacall_brandom_az reference_az
#define luacall_brandom_az09 reference_az09
#define luacall_bcryptorandom reference_crypto
#define luacall_parse_hex reference_hex
#define luacall_bxor reference_xor
#define luacall_bor reference_or
#define luacall_band reference_and
#include "lua_buffer_reference.inc"
#undef luac_bop
#undef luacall_brandom
#undef luacall_brandom_az
#undef luacall_brandom_az09
#undef luacall_bcryptorandom
#undef luacall_parse_hex
#undef luacall_bxor
#undef luacall_bor
#undef luacall_band
struct allocator {bool armed;unsigned attempts,rejected,limit,live;};
static struct allocator *fault_allocator;
static void *allocate(void *context,void *pointer,size_t previous,size_t next){struct allocator *a=context;if(!next){if(pointer){CHECK(a->live);--a->live;}free(pointer);return NULL;}if(a->armed && next>previous && a->attempts++>=a->limit){++a->rejected;return NULL;}bool fresh=!pointer;void *p=realloc(pointer,next);if(p && fresh)++a->live;return p;}
static lua_State *new_vm(struct allocator *a){lua_State *L=a?lua_newstate(allocate,a):luaL_newstate();CHECK(L);luaJIT_setmode(L,0,LUAJIT_MODE_ENGINE|LUAJIT_MODE_OFF);return L;}
static lua_CFunction resolve(bool rust,unsigned api){const lua_CFunction old[]={reference_random,reference_az,reference_az09,reference_crypto,reference_hex,reference_xor,reference_or,reference_and},current[]={luacall_brandom,luacall_brandom_az,luacall_brandom_az09,luacall_bcryptorandom,luacall_parse_hex,luacall_bxor,luacall_bor,luacall_band};return rust?current[api]:old[api];}
static void nested_call(lua_State *L){nested_entered=true;int top=lua_gettop(L);lua_pushcfunction(L,resolve(native_side,5));lua_pushliteral(L,"\0x");lua_pushlstring(L,"\xffz",nested_kind==2?1:2);int status=lua_pcall(L,2,LUA_MULTRET,0);uint64_t value=(uint32_t)status;for(int i=top+1;i<=lua_gettop(L);++i){value=value*16777619u^(unsigned)lua_type(L,i);if(lua_type(L,i)==LUA_TSTRING){size_t n;const char *p=lua_tolstring(L,i,&n);value^=hash(p,n);}}active->nested_hash=value;++active->nested;++nested_total;lua_settop(L,top);if(nested_kind==3){luaL_error(L,"nested buffer publication failure");return;}lua_gc(L,LUA_GCCOLLECT,0);}
struct argument {int kind;const void *data;size_t length;lua_Number number;};
static struct argument bytes(const void *p,size_t n){return (struct argument){.kind=LUA_TSTRING,.data=p,.length=n};}
static struct argument number(lua_Number n){return (struct argument){.kind=LUA_TNUMBER,.number=n};}
static int dummy(lua_State *L){(void)L;return 0;}
static void push(lua_State *L,struct argument a){switch(a.kind){case LUA_TSTRING:lua_pushlstring(L,a.data,a.length);break;case LUA_TNUMBER:lua_pushnumber(L,a.number);break;case LUA_TBOOLEAN:lua_pushboolean(L,false);break;case LUA_TTABLE:lua_newtable(L);break;case LUA_TLIGHTUSERDATA:lua_pushlightuserdata(L,(void *)(uintptr_t)1);break;case LUA_TFUNCTION:lua_pushcfunction(L,dummy);break;default:lua_pushnil(L);}}
static struct sample invoke(lua_State *L,bool rust,unsigned api,const struct argument *args,unsigned argc){
    struct sample sample={0};lua_settop(L,0);lua_pushcfunction(L,resolve(rust,api));int refs[4]={0};uint64_t before[4]={0};
    for(unsigned i=0;i<argc;++i){push(L,args[i]);lua_pushvalue(L,-1);refs[i]=luaL_ref(L,LUA_REGISTRYINDEX);if(lua_type(L,-1)==LUA_TSTRING){size_t n;const char *p=lua_tolstring(L,-1,&n);before[i]=hash(p,n);}}
    zapret_srandom(0x12345678u+cases);native_side=rust;nested_entered=false;active=&sample;if(fault_allocator){fault_allocator->armed=true;fault_allocator->attempts=fault_allocator->rejected=0;}
    sample.status=lua_pcall(L,argc,LUA_MULTRET,0);if(fault_allocator)fault_allocator->armed=false;active=NULL;sample.next_random=zapret_random();sample.arity=lua_gettop(L);CHECK(sample.arity==1);sample.type=lua_type(L,1);
    if(sample.status){const char *p=lua_tostring(L,1);snprintf(sample.message,sizeof(sample.message),"%s",p?p:"");}else if(sample.type==LUA_TSTRING){const char *p=lua_tolstring(L,1,&sample.length);CHECK(sample.length<=sizeof(sample.bytes));memcpy(sample.bytes,p,sample.length);}else CHECK(sample.type==LUA_TNIL);
    for(unsigned i=0;i<argc;++i){lua_rawgeti(L,LUA_REGISTRYINDEX,refs[i]);if(before[i]){size_t n;const char *p=lua_tolstring(L,-1,&n);CHECK(p && before[i]==hash(p,n));sample.arguments=sample.arguments*1099511628211ULL^before[i];}lua_pop(L,1);luaL_unref(L,LUA_REGISTRYINDEX,refs[i]);}lua_settop(L,0);return sample;
}
static struct sample compare(lua_State *L,unsigned api,const struct argument *args,unsigned argc){struct sample a=invoke(L,false,api,args,argc),b=invoke(L,true,api,args,argc);if(memcmp(&a,&b,sizeof(a))){fprintf(stderr,"DETAIL api=%u argc=%u entropy_fail=%u old=%d/%d/%d/%zu new=%d/%d/%d/%zu old_calls=%u new_calls=%u old_trace=%llx new_trace=%llx old_error=%s new_error=%s\n",api,argc,fail_entropy,a.status,a.arity,a.type,a.length,b.status,b.arity,b.type,b.length,a.calls,b.calls,(unsigned long long)a.trace,(unsigned long long)b.trace,a.message,b.message);CHECK(false);}++cases;if(a.status)++errors;return a;}
static int nibble(unsigned n){return n>='0' && n<='9'?n-'0':n>='A' && n<='F'?n-'A'+10:n>='a' && n<='f'?n-'a'+10:-1;}
static void faults(void){for(unsigned api=0;api<8;++api)for(unsigned failure=0;failure<(api==3?2:1);++failure)for(unsigned side=0;side<2;++side)for(unsigned budget=0;budget<64;++budget){fail_entropy=failure;struct allocator a={.limit=budget};lua_State *L=new_vm(&a);uint8_t input[514];memset(input,'a',sizeof(input));struct argument args[]={api<4?number(257):bytes(input,api==4?514:257),bytes(input,257)};fault_allocator=&a;struct sample result=invoke(L,side,api,args,api>=5?2:1);fault_allocator=NULL;if(result.status==LUA_ERRMEM){CHECK(a.rejected);++vm_faults;}else if(result.status)CHECK(api==3 && failure && strstr(result.message,"could not get entropy bytes"));lua_close(L);CHECK(!a.live);++fault_cases;}fail_entropy=false;CHECK(vm_faults>0);}
static void boundaries_check(void){_Alignas(8)uint8_t bytes[128];memset(bytes,0xa5,sizeof(bytes));zapret_lua_buffer_state *state=(void *)bytes;zapret_lua_buffer_action action={.kind=91};zapret_lua_buffer_value value={0};
    CHECK(!zapret_lua_buffer_begin(8,state,&action) && bytes[0]==0xa5 && action.kind==91);++boundaries;
    CHECK(!zapret_lua_buffer_begin(0,NULL,&action));++boundaries;CHECK(!zapret_lua_buffer_begin(0,(void *)(bytes+1),&action));++boundaries;CHECK(!zapret_lua_buffer_begin(0,state,NULL));++boundaries;
    CHECK(zapret_lua_buffer_begin(4,state,&action));CHECK(!zapret_lua_buffer_step(state,&value,NULL,NULL));++boundaries;CHECK(!zapret_lua_buffer_step(state,NULL,&action,NULL));++boundaries;
    CHECK(zapret_lua_buffer_step(state,&value,&action,NULL));value.span.data=(void *)(uintptr_t)1;value.span.length=SIZE_MAX;CHECK(!zapret_lua_buffer_step(state,&value,&action,NULL));++boundaries;value.span.data=NULL;value.span.length=2;CHECK(!zapret_lua_buffer_step(state,&value,&action,NULL));++boundaries;
    uint8_t *memory=VirtualAlloc(NULL,8192,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);CHECK(memory);DWORD old;CHECK(VirtualProtect(memory+4096,4096,PAGE_NOACCESS,&old));zapret_lua_buffer_state *edge=(void *)(memory+4096-sizeof(*edge));CHECK(zapret_lua_buffer_begin(0,edge,&action));CHECK(VirtualFree(memory,0,MEM_RELEASE));++boundaries;
}
int main(void){lua_State *L=new_vm(NULL);uint8_t first[2048],second[2048];for(unsigned i=0;i<sizeof(first);++i){first[i]=(uint8_t)(i*7);second[i]=(uint8_t)(i*13);}
    for(unsigned a=0;a<256;++a)for(unsigned b=0;b<256;++b){uint8_t text[]={(uint8_t)a,(uint8_t)b};struct argument hex[]={bytes(text,2)};struct sample parsed=compare(L,4,hex,1);if(!a)CHECK(parsed.type==LUA_TSTRING && parsed.length==0);else if(nibble(a)<0 || nibble(b)<0)CHECK(parsed.type==LUA_TNIL);else CHECK(parsed.length==1 && parsed.bytes[0]==(nibble(a)*16+nibble(b)));
        for(unsigned api=5;api<8;++api){struct argument args[]={bytes(text,1),bytes(text+1,1)};struct sample result=compare(L,api,args,2);CHECK(!result.status && result.length==1 && result.bytes[0]==(api==5?(a^b):api==6?(a|b):(a&b)));}}
    const size_t lengths[]={0,1,2,7,8,9,15,16,17,63,64,65,255,256,513,1024};
    for(unsigned api=0;api<4;++api)for(unsigned n=0;n<16;++n)for(unsigned shape=0;shape<3;++shape)for(unsigned failure=0;failure<(api==3?2:1);++failure){char text[32];snprintf(text,sizeof(text),"%zu",lengths[n]);struct argument args[]={shape==0?number(lengths[n]):shape==1?bytes(text,strlen(text)):number(lengths[n]+0.75)};fail_entropy=failure;compare(L,api,args,1);}fail_entropy=false;
    for(unsigned api=5;api<8;++api)for(unsigned a=0;a<16;++a)for(unsigned b=0;b<16;++b){struct argument args[]={bytes(first,lengths[a]),bytes(second,lengths[b])};compare(L,api,args,2);}
    for(unsigned n=0;n<=1024;++n){memset(first,'a',n);if(n%3==0 && n)first[n/2]=0;if(n%7==0 && n)first[n-1]='Z';struct argument args[]={bytes(first,n)};compare(L,4,args,1);}
    const int kinds[]={LUA_TNIL,LUA_TBOOLEAN,LUA_TNUMBER,LUA_TTABLE,LUA_TLIGHTUSERDATA,LUA_TFUNCTION,LUA_TSTRING};
    for(unsigned api=0;api<8;++api)for(unsigned argc=0;argc<=3;++argc)for(unsigned bad=0;bad<=argc;++bad)for(unsigned shape=0;shape<7;++shape){struct argument args[3];for(unsigned i=0;i<3;++i)args[i]=api<4?number(8):bytes("abcd",4);if(bad)args[bad-1]=(struct argument){.kind=kinds[shape],.data="not numeric",.length=11,.number=3.75};compare(L,api,args,argc);}
    const lua_Number negatives[]={-1,-0.75,-1.75,-2147483648.0,-9223372036854775808.0};for(unsigned api=0;api<4;++api)for(unsigned n=0;n<5;++n){struct argument args[]={number(negatives[n])};compare(L,api,args,1);}
    for(nested_boundary=1;nested_boundary<=2;++nested_boundary)for(nested_kind=1;nested_kind<=3;++nested_kind)for(unsigned api=0;api<8;++api){struct argument args[]={api<4?number(16):bytes("aabbccdd",8),bytes("11223344",8)};compare(L,api,args,api>=5?2:1);}nested_boundary=0;lua_close(L);faults();boundaries_check();
    production=true;L=new_vm(NULL);for(unsigned api=0;api<8;++api){struct argument args[]={api<4?number(17):bytes("00112233",8),bytes("aabbccdd",8)};struct sample result=invoke(L,true,api,args,api>=5?2:1);CHECK(!result.status && result.type==LUA_TSTRING && result.length==(api<4?17:api==4?4:8));++production_cases;}lua_close(L);
    printf("PASS lua_buffer apis=8 cases=%u vm_errors=%u native_calls=%u nested_calls=%u boundaries=%u fault_cases=%u vm_allocation_faults=%u production_cases=%u real_luajit=1 exhaustive_byte_pairs=1 exact_errors=1 exact_arity=1 exact_native_inputs=1 exact_vm_order=1 seeded_random_consumption=1 immutable_inputs=1 vm_allocations_released=1 rust_seh_unwind=1\n",cases,errors,native_calls,nested_total,boundaries,fault_cases,vm_faults,production_cases);return 0;}
