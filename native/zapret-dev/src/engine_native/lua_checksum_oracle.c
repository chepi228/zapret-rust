/* MIT. Pinned C predicates/checksums and Rust are compared inside real LuaJIT. */
#include <iphlpapi.h>
#include "params.h"
#include "engine_lua.h"
#include "checksum.h"
#include <luajit.h>
#undef main
struct params_s params;
#include "lua_checksum_common.inc"
#include "checksum_predicates.inc"
#define ip4_compute_csum reference_ip4_compute_csum
#define csum_tcpudp_magic reference_csum_tcpudp_magic
#define csum_ipv6_magic reference_csum_ipv6_magic
#define ip4_fix_checksum reference_ip4_fix_checksum
#define tcp4_fix_checksum reference_tcp4_fix_checksum
#define tcp6_fix_checksum reference_tcp6_fix_checksum
#define tcp_fix_checksum reference_tcp_fix_checksum
#define udp4_fix_checksum reference_udp4_fix_checksum
#define udp6_fix_checksum reference_udp6_fix_checksum
#define udp_fix_checksum reference_udp_fix_checksum
#define icmp4_fix_checksum reference_icmp4_fix_checksum
#define icmp6_fix_checksum reference_icmp6_fix_checksum
#define icmp_fix_checksum reference_icmp_fix_checksum
#include "checksum_reference.inc"
#define luacall_csum_ip4_fix old_ip4
#define luacall_csum_tcp_fix old_tcp
#define luacall_csum_udp_fix old_udp
#define luacall_csum_icmp_fix old_icmp
#include "lua_checksum_reference.inc"
#undef luacall_csum_ip4_fix
#undef luacall_csum_tcp_fix
#undef luacall_csum_udp_fix
#undef luacall_csum_icmp_fix
#undef ip4_compute_csum
#undef csum_tcpudp_magic
#undef csum_ipv6_magic
#undef ip4_fix_checksum
#undef tcp4_fix_checksum
#undef tcp6_fix_checksum
#undef tcp_fix_checksum
#undef udp4_fix_checksum
#undef udp6_fix_checksum
#undef udp_fix_checksum
#undef icmp4_fix_checksum
#undef icmp6_fix_checksum
#undef icmp_fix_checksum
#include "lua_checksum_windows.inc"

static unsigned cases,errors,independent,input_checks,boundaries,guarded,fault_cases,vm_faults;
static unsigned active_kind;
#define CHECK(v) do{if(!(v)){fprintf(stderr,"FAIL Lua checksum cases=%u kind=%u bounds=%u line=%d: %s\n",cases,active_kind,boundaries,__LINE__,#v);exit(1);}}while(0)
static lua_CFunction old_functions[]={old_ip4,old_tcp,old_udp,old_icmp};
static lua_CFunction new_functions[]={luacall_csum_ip4_fix,luacall_csum_tcp_fix,luacall_csum_udp_fix,luacall_csum_icmp_fix};
static uint8_t ip[160],header[65600],payload[65536];
static uint64_t random_state=0x636865636b73756dULL;
static uint8_t random_byte(void){random_state^=random_state<<13;random_state^=random_state>>7;random_state^=random_state<<17;return (uint8_t)random_state;}
static void fill(uint8_t *data,size_t length){for(size_t i=0;i<length;++i)data[i]=random_byte();}
static void put16(uint8_t *data,unsigned number){data[0]=(uint8_t)(number>>8);data[1]=(uint8_t)number;}
struct argument {int type;const uint8_t *data;size_t length;};
static struct argument binary(const uint8_t *data,size_t length){return (struct argument){LUA_TSTRING,data,length};}
static void push(lua_State *L,struct argument argument)
{
    switch(argument.type){
    case LUA_TSTRING:lua_pushlstring(L,(const char *)argument.data,argument.length);break;
    case LUA_TNUMBER:lua_pushnumber(L,42);break;case LUA_TTABLE:lua_newtable(L);break;
    case LUA_TBOOLEAN:lua_pushboolean(L,true);break;case LUA_TFUNCTION:lua_pushcfunction(L,old_ip4);break;
    default:lua_pushnil(L);break;
    }
}
struct sample {int status,type;size_t length;uint8_t data[131072];};
static struct sample left,right;
static void invoke(lua_State *L,lua_CFunction function,const struct argument *args,unsigned count,struct sample *out)
{
    int refs[5]={0};CHECK(count<=5);lua_settop(L,0);lua_pushcfunction(L,function);
    for(unsigned i=0;i<count;++i){push(L,args[i]);if(args[i].type==LUA_TSTRING){lua_pushvalue(L,-1);refs[i]=luaL_ref(L,LUA_REGISTRYINDEX);}}
    out->status=lua_pcall(L,count,1,0);CHECK(lua_gettop(L)==1);out->type=lua_type(L,-1);out->length=0;
    if(out->type==LUA_TSTRING){const char *data=lua_tolstring(L,-1,&out->length);CHECK(out->length<=sizeof(out->data));memcpy(out->data,data,out->length);}
    for(unsigned i=0;i<count;++i)if(refs[i]){
        lua_rawgeti(L,LUA_REGISTRYINDEX,refs[i]);size_t length;const char *data=lua_tolstring(L,-1,&length);
        CHECK(length==args[i].length && !memcmp(data,args[i].data,length));++input_checks;
        lua_pop(L,1);luaL_unref(L,LUA_REGISTRYINDEX,refs[i]);
    }
    lua_settop(L,0);
}
static uint64_t scalar_sum(const uint8_t *data,size_t length)
{
    uint64_t sum=0;for(size_t i=0;i<length;i+=2){sum+=(uint64_t)data[i]<<8;if(i+1<length)sum+=data[i+1];}return sum;
}
static uint16_t fold_sum(uint64_t value){while(value>>16)value=(value&65535)+(value>>16);return (uint16_t)value;}
static void independent_check(const struct argument *args)
{
    if(left.status)return;
    if(active_kind==0){CHECK(fold_sum(scalar_sum(right.data,(right.data[0]&15)*4))==65535);++independent;return;}
    static uint8_t combined[131072];size_t size=right.length+args[2].length;CHECK(size<=sizeof(combined));
    memcpy(combined,right.data,right.length);memcpy(combined+right.length,args[2].data,args[2].length);
    uint64_t sum=scalar_sum(combined,size);
    bool ipv6=(args[0].data[0]>>4)==6;
    if(active_kind!=3 || ipv6){
        unsigned width=ipv6?16:4,offset=ipv6?8:12;
        sum+=scalar_sum(args[0].data+offset,width)+scalar_sum(args[0].data+offset+width,width);
        sum+=size+(active_kind==1?6:active_kind==2?17:58);
    }
    CHECK(fold_sum(sum)==65535);++independent;
}
static void compare(lua_State *L,const struct argument *args,unsigned count)
{
    invoke(L,old_functions[active_kind],args,count,&left);invoke(L,new_functions[active_kind],args,count,&right);
    if(left.status!=right.status || left.type!=right.type || left.length!=right.length || memcmp(left.data,right.data,left.length)){
        fprintf(stderr,"DETAIL argc=%u ip=%zu header=%zu payload=%zu old_status=%d new_status=%d oldlen=%zu newlen=%zu\n",count,args[0].length,args[1].length,args[2].length,left.status,right.status,left.length,right.length);
        if(left.status)fprintf(stderr,"ERROR old=%.*s new=%.*s\n",(int)left.length,left.data,(int)right.length,right.data);
        CHECK(false);
    }
    if(left.status)++errors;else independent_check(args);++cases;
}
static void prepare(unsigned seed,unsigned family)
{
    fill(ip,sizeof(ip));fill(header,128);
    ip[0]=(uint8_t)((family<<4)|(5+seed%11));put16(ip+2,seed%5?65535:0);
    header[12]=(uint8_t)(((5+seed%11)<<4)|(seed&15));
}
static void valid_cases(lua_State *L)
{
    const size_t lengths[]={0,1,7,8,9,15,19,20,21,31,32,39,40,41,59,60,61,127};
    const size_t payloads[]={0,1,2,7,8,15,16,17,255,1023,65534,65535,65536};
    for(unsigned seed=0;seed<1024;++seed)for(unsigned family=4;family<=6;family+=2){
        prepare(seed,family);
        for(active_kind=0;active_kind<4;++active_kind){
            struct argument args[]={binary(ip,lengths[seed%18]),binary(header,lengths[(seed/3)%18]),binary(payload,seed%4?seed%257:1023)};
            compare(L,args,active_kind?3:1);
            args[0].length=family==4?60:40;ip[0]=family==4?0x45:0x60;put16(ip+2,65535);
            args[1].length=active_kind==1?20+seed%109:8+seed%121;header[12]=0x50;
            args[2].length=payloads[seed%13];compare(L,args,active_kind?3:1);
        }
    }
    // Very long "headers" are permitted by the existing Lua API. Retain
    // every byte and the pseudo-header length semantics even beyond 64 KiB.
    prepare(1,4);fill(header,sizeof(header));header[12]=0x50;
    for(active_kind=1;active_kind<4;++active_kind)for(unsigned family=4;family<=6;family+=2){
        ip[0]=family==4?0x45:0x60;put16(ip+2,65535);
        struct argument args[]={binary(ip,family==4?20:40),binary(header,65536),binary(payload,65535)};compare(L,args,3);
    }
}
static void error_cases(lua_State *L)
{
    prepare(1,4);ip[0]=0x45;put16(ip+2,20);header[12]=0x50;
    const int types[]={LUA_TNIL,LUA_TNUMBER,LUA_TBOOLEAN,LUA_TTABLE,LUA_TFUNCTION,LUA_TSTRING};
    for(active_kind=0;active_kind<4;++active_kind)for(unsigned count=0;count<=5;++count)
        for(unsigned bad=0;bad<3;++bad)for(unsigned type=0;type<6;++type){
            struct argument args[5]={binary(ip,20),binary(header,20),binary(payload,1),binary(payload,0),binary(payload,0)};
            args[bad].type=types[type];compare(L,args,count);
        }
    for(active_kind=1;active_kind<4;++active_kind)for(unsigned mask=0;mask<8;++mask){
        struct argument args[]={binary(ip,mask&1?1:20),binary(header,mask&2?1:20),binary(payload,mask&4?65536:1)};compare(L,args,3);
        args[1].type=LUA_TBOOLEAN;compare(L,args,3);args[2].type=LUA_TBOOLEAN;compare(L,args,3);
    }
}
struct allocator {bool armed;unsigned calls,fail_after,rejected,live;};
static void *allocate(void *context,void *pointer,size_t previous,size_t next)
{
    struct allocator *a=context;if(!next){if(pointer){CHECK(a->live);--a->live;}free(pointer);return NULL;}
    if(a->armed && next>previous && a->calls++>=a->fail_after){++a->rejected;return NULL;}
    bool fresh=!pointer;void *result=realloc(pointer,next);if(result && fresh)++a->live;return result;
}
static void fault_checks(void)
{
    for(active_kind=0;active_kind<4;++active_kind)for(unsigned limit=0;limit<24;++limit)for(unsigned side=0;side<2;++side){
        struct allocator a={.fail_after=limit};lua_State *L=lua_newstate(allocate,&a);CHECK(L);
        prepare(1,4);ip[0]=0x45;put16(ip+2,20);header[12]=0x50;
        lua_pushcfunction(L,side?new_functions[active_kind]:old_functions[active_kind]);
        lua_pushlstring(L,(char *)ip,20);
        if(active_kind){lua_pushlstring(L,(char *)header,20);lua_pushlstring(L,(char *)payload,65535);}
        a.armed=true;int status=lua_pcall(L,active_kind?3:1,1,0);a.armed=false;
        if(status){CHECK(status==LUA_ERRMEM && a.rejected);++vm_faults;}else CHECK(!a.rejected);
        lua_close(L);CHECK(!a.live);++fault_cases;
    }
    CHECK(vm_faults>=8);
}
static void boundaries_check(void)
{
    _Alignas(8) uint8_t bytes[256];zapret_lua_checksum_plan plan;uint8_t output[256],before[256];
    memset(output,0xa5,sizeof(output));memcpy(before,output,sizeof(output));memset(&plan,0xa5,sizeof(plan));
    prepare(1,4);ip[0]=0x45;put16(ip+2,20);header[12]=0x50;
#define BOUND(v) do{CHECK(v);++boundaries;}while(0)
    BOUND(!zapret_lua_checksum_ipv4(NULL,20,output,sizeof(output)));
    BOUND(!zapret_lua_checksum_ipv4(ip,20,NULL,sizeof(output)));
    BOUND(!zapret_lua_checksum_ipv4(ip,20,output,19));BOUND(!zapret_lua_checksum_ipv4(ip,61,output,sizeof(output)));
    BOUND(!zapret_lua_checksum_begin(3,ip,20,&plan));BOUND(!zapret_lua_checksum_begin(0,ip,SIZE_MAX,&plan));
    BOUND(!zapret_lua_checksum_begin(0,ip,20,NULL));BOUND(!zapret_lua_checksum_begin(0,ip,20,(void *)(bytes+1)));
    for(size_t i=0;i<sizeof(plan);++i)CHECK(((uint8_t *)&plan)[i]==0xa5);
    BOUND(!zapret_lua_checksum_header(NULL,header,20));BOUND(!zapret_lua_checksum_header((void *)(bytes+1),header,20));
    BOUND(zapret_lua_checksum_begin(0,ip,20,&plan));
    BOUND(!zapret_lua_checksum_header(&plan,header,SIZE_MAX));BOUND(!zapret_lua_checksum_header(&plan,NULL,20));
    BOUND(!zapret_lua_checksum_payload(&plan,payload,1));BOUND(!zapret_lua_checksum_finish(&plan,output,sizeof(output)));
    BOUND(zapret_lua_checksum_header(&plan,header,20));
    BOUND(!zapret_lua_checksum_payload(&plan,NULL,1));BOUND(!zapret_lua_checksum_payload(&plan,payload,65536));
    plan.header_length=SIZE_MAX;BOUND(!zapret_lua_checksum_payload(&plan,payload,1));
    plan.header_length=INT64_MAX;BOUND(!zapret_lua_checksum_payload(&plan,payload,1));
    plan.header_length=20;BOUND(zapret_lua_checksum_payload(&plan,NULL,0));
    BOUND(!zapret_lua_checksum_finish(NULL,output,sizeof(output)));BOUND(!zapret_lua_checksum_finish((void *)(bytes+1),output,sizeof(output)));
    BOUND(!zapret_lua_checksum_finish(&plan,NULL,20));BOUND(!zapret_lua_checksum_finish(&plan,output,19));
    plan.family=0;BOUND(!zapret_lua_checksum_finish(&plan,output,sizeof(output)));plan.family=4;
    plan.total_length=19;BOUND(!zapret_lua_checksum_finish(&plan,output,sizeof(output)));plan.total_length=20;
    plan.kind=3;BOUND(!zapret_lua_checksum_finish(&plan,output,sizeof(output)));
    CHECK(!memcmp(output,before,sizeof(output)));
#undef BOUND
}
struct guard {uint8_t *allocation,*end;};
static struct guard make_guard(void)
{
    struct guard g;g.allocation=VirtualAlloc(NULL,16384,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);CHECK(g.allocation);
    g.end=g.allocation+12288;DWORD old;CHECK(VirtualProtect(g.end,4096,PAGE_NOACCESS,&old));return g;
}
static void guarded_checks(void)
{
    struct guard ips=make_guard(),headers=make_guard(),payloads=make_guard(),out=make_guard();
    const size_t sizes[]={0,1,7,8,9,19,20,21,39,40,59,60,61,127};
    for(unsigned seed=0;seed<128;++seed)for(unsigned family=4;family<=6;family+=2){
        prepare(seed,family);ip[0]=family==4?0x45:0x60;put16(ip+2,65535);header[12]=0x50;
        size_t ilen=family==4?20:40,hlen=sizes[seed%14],plen=seed%65,total=hlen+plen;
        uint8_t *i=ips.end-ilen,*h=headers.end-hlen,*p=payloads.end-plen,*o=out.end-total;
        memcpy(i,ip,ilen);memcpy(h,header,hlen);memcpy(p,payload,plen);
        DWORD old;CHECK(VirtualProtect(ips.allocation,12288,PAGE_READONLY,&old));
        CHECK(VirtualProtect(headers.allocation,12288,PAGE_READONLY,&old));CHECK(VirtualProtect(payloads.allocation,12288,PAGE_READONLY,&old));
        for(unsigned kind=0;kind<3;++kind){
            zapret_lua_checksum_plan plan;CHECK(zapret_lua_checksum_begin(kind,i,ilen,&plan));
            bool accepted=kind==0?hlen>=20:hlen>=8;
            CHECK(zapret_lua_checksum_header(&plan,h,hlen)==accepted);
            if(accepted){
                CHECK(zapret_lua_checksum_payload(&plan,p,plen));memset(o,0xa5,total);
                CHECK(zapret_lua_checksum_finish(&plan,o,total));uint8_t expected[256];memcpy(expected,h,hlen);memcpy(expected+hlen,p,plen);
                switch(kind){case 0:reference_tcp_fix_checksum((void *)expected,total,family==4?(void *)i:NULL,family==6?(void *)i:NULL);break;
                case 1:reference_udp_fix_checksum((void *)expected,total,family==4?(void *)i:NULL,family==6?(void *)i:NULL);break;
                case 2:reference_icmp_fix_checksum((void *)expected,total,family==6?(void *)i:NULL);break;}
                CHECK(!memcmp(o,expected,total));
            }
            ++guarded;
        }
        CHECK(VirtualProtect(ips.allocation,12288,PAGE_READWRITE,&old));CHECK(VirtualProtect(headers.allocation,12288,PAGE_READWRITE,&old));
        CHECK(VirtualProtect(payloads.allocation,12288,PAGE_READWRITE,&old));
    }
    CHECK(VirtualFree(ips.allocation,0,MEM_RELEASE));CHECK(VirtualFree(headers.allocation,0,MEM_RELEASE));
    CHECK(VirtualFree(payloads.allocation,0,MEM_RELEASE));CHECK(VirtualFree(out.allocation,0,MEM_RELEASE));
}
int main(void)
{
    fill(payload,sizeof(payload));lua_State *L=luaL_newstate();CHECK(L);luaJIT_setmode(L,0,LUAJIT_MODE_ENGINE|LUAJIT_MODE_OFF);
    valid_cases(L);error_cases(L);lua_close(L);boundaries_check();guarded_checks();fault_checks();
    printf("PASS lua_checksum functions=4 cases=%u errors=%u independent_sums=%u input_checks=%u guarded=%u boundaries=%u vm_allocation_faults=%u fault_cases=%u real_luajit=1 error_order_preserved=1 vm_allocations_released=1\n",cases,errors,independent,input_checks,guarded,boundaries,vm_faults,fault_cases);
    return 0;
}
