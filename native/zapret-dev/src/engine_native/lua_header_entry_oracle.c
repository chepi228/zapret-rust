/* MIT. Complete header entries, mutable composite views and native addresses. */
#include <iphlpapi.h>
#include "params.h"
#include "engine_lua.h"
#include <lualib.h>
#include <luajit.h>
#include <stdarg.h>
#undef main
#ifdef ZAPRET_RUST_LUA_HEADER_VIEWS
#define VIEW_OBSERVER
#else
#define VIEW_OBSERVER static
#endif
struct params_s params;
static unsigned cases,errors,entry_cases,projection_cases,address_cases,native_calls,nested_total,mutations,fault_cases,vm_faults,boundaries,guarded,eager_controls;
#define CHECK(v) do{if(!(v)){fprintf(stderr,"FAIL header entry cases=%u line=%d: %s\n",cases,__LINE__,#v);exit(1);}}while(0)
struct sample {int status,arity,type;size_t length;char bytes[8192],message[512],log[512];uint64_t trace,inputs;unsigned calls,nested,mutated;};
static struct sample *active;
static bool native_side,nested_entered,mutated;
static unsigned nested_boundary,nested_kind,mutation_mode;
static struct dissect source;
static const struct dissect *selected_source;
static const struct sockaddr *selected_address;
static unsigned selected_operation;
static uint8_t ip_bytes[128],ip6_bytes[128],tcp_bytes[128],udp_bytes[128],icmp_bytes[128],payload[128];
static uint8_t *const header_bytes[]={tcp_bytes,udp_bytes,icmp_bytes,ip_bytes,ip6_bytes};
#ifdef ZAPRET_RUST_LUA_HEADER_VIEWS
static const void *selected_header;
static size_t selected_header_length;
static unsigned field_cases;
#endif
static void nested_call(lua_State *);
static uint64_t hash(const void *data,size_t n){uint64_t value=1469598103934665603ULL;const uint8_t *p=data;for(size_t i=0;i<n;++i)value=(value^p[i])*1099511628211ULL;return value;}
static void event(unsigned tag,uint64_t value){if(active)active->trace=(active->trace*1099511628211ULL^tag)*1099511628211ULL^value;}
static void mutate(unsigned point){if(!active || selected_operation<10 || selected_operation>11 || mutated || mutation_mode!=point)return;mutated=true;++mutations;++active->mutated;
    if(point==1){source.proto=251;source.frag=!source.frag;source.frag_off=65535;source.transport_len=SIZE_MAX;}
    if(point==2){source.data_payload=NULL;source.len_payload=SIZE_MAX;source.frag=!source.frag;source.frag_off=17;}
    if(point==3){source.ip=NULL;source.len_l3=40;source.tcp=NULL;source.len_l4=8;}
}
VIEW_OBSERVER void boundary_table(lua_State *L,int array,int records){if(active && nested_boundary==1 && !nested_entered)nested_call(L);event(1,(uint64_t)(uint32_t)array<<32|(uint32_t)records);mutate(1);lua_createtable(L,array,records);}
VIEW_OBSERVER void boundary_bytes(lua_State *L,const char *data,size_t length){if(active && nested_boundary==2 && !nested_entered)nested_call(L);event(2,length);event(3,hash(data,length));if(length==7 && !memcmp(data,"payload",7))mutate(2);if(length==2 && !memcmp(data,"ip",2))mutate(3);lua_pushlstring(L,data,length);}
static void boundary_string(lua_State *L,const char *data){if(active && nested_boundary==3 && !nested_entered)nested_call(L);event(4,data?hash(data,strlen(data)):0);if(data && !strcmp(data,"payload"))mutate(2);if(data && !strcmp(data,"ip"))mutate(3);lua_pushstring(L,data);}
VIEW_OBSERVER void boundary_nil(lua_State *L){event(5,0);lua_pushnil(L);}
VIEW_OBSERVER void boundary_rawset(lua_State *L,int index){event(6,(uint32_t)index);lua_rawset(L,index);}
static void boundary_getfield(lua_State *L,int index,const char *field){event(7,(uint32_t)index);event(8,hash(field,strlen(field)));lua_getfield(L,index,field);}
#define lua_createtable boundary_table
#define lua_pushlstring boundary_bytes
#define lua_pushstring boundary_string
#define lua_pushnil boundary_nil
#define lua_rawset boundary_rawset
#define lua_getfield boundary_getfield
int DLOG(const char *format,...){(void)format;return 0;}
int DLOG_ERR(const char *format,...){if(!active)return 0;va_list args;va_start(args,format);int n=vsnprintf(active->log,sizeof(active->log),format,args);va_end(args);return n;}
#define lua_check_argc reference_check_argc
#define lua_check_argc_range reference_check_argc_range
#define lua_reqlstring reference_reqlstring
#define lua_absindex reference_absindex
#include "lua_header_entry_common.inc"
#include "lua_numeric_windows.inc"
#include "lua_packet_options_windows.inc"
#define ZAPRET_LUA_PACKET_ASSEMBLY_RUST
#include "lua_header_entry_headers.inc"
#include "lua_packet_dissection_windows.inc"
void observe_header(lua_State *L,uint8_t kind,const uint8_t *data,size_t length){if(active){++active->calls;++native_calls;}event(20+kind,length);event(26,data!=NULL);if(data && length<=128)event(27,hash(data,length));native_lua_push_packet_header(L,kind,data,length);}
static void push_tcp(lua_State *L,const struct tcphdr *p,size_t n){observe_header(L,0,(const uint8_t *)p,n);}
static void push_udp(lua_State *L,const struct udphdr *p,size_t n){observe_header(L,1,(const uint8_t *)p,n);}
static void push_icmp(lua_State *L,const struct icmp46 *p,size_t n){observe_header(L,2,(const uint8_t *)p,n);}
static void push_ip(lua_State *L,const struct ip *p,size_t n){observe_header(L,3,(const uint8_t *)p,n);}
static void push_ip6(lua_State *L,const struct ip6_hdr *p,size_t n){observe_header(L,4,(const uint8_t *)p,n);}
static void build_start(unsigned kind,size_t n){if(active){++active->calls;++native_calls;}event(30+kind,n);}
static bool build_tcp(lua_State *L,int i,struct tcphdr *p,size_t *n){build_start(0,*n);bool ok=lua_reconstruct_tcphdr(L,i,p,n);event(36,ok);if(ok)event(37,hash(p,*n));return ok;}
static bool build_udp(lua_State *L,int i,struct udphdr *p){build_start(1,sizeof(*p));bool ok=lua_reconstruct_udphdr(L,i,p);event(36,ok);if(ok)event(37,hash(p,sizeof(*p)));return ok;}
static bool build_icmp(lua_State *L,int i,struct icmp46 *p){build_start(2,sizeof(*p));bool ok=lua_reconstruct_icmphdr(L,i,p);event(36,ok);if(ok)event(37,hash(p,sizeof(*p)));return ok;}
static bool build_ip(lua_State *L,int i,struct ip *p,size_t *n){build_start(3,*n);bool ok=lua_reconstruct_iphdr(L,i,p,n);event(36,ok);if(ok)event(37,hash(p,*n));return ok;}
static bool build_ip6(lua_State *L,int i,struct ip6_hdr *p,size_t *n,uint8_t protocol,bool preserve){build_start(4,*n);event(38,protocol);event(39,preserve);bool ok=lua_reconstruct_ip6hdr(L,i,p,n,protocol,preserve);event(36,ok);if(ok)event(37,hash(p,*n));return ok;}
static void extract_options(lua_State *L,int i,bool *keep,bool *bad,bool *preserve,uint8_t *protocol){event(40,(uint32_t)i);lua_reconstruct_extract_options(L,i,keep,bad,preserve,protocol);event(41,*protocol);event(42,*preserve);}
#define native_lua_push_packet_header observe_header
#define lua_push_tcphdr push_tcp
#define lua_push_udphdr push_udp
#define lua_push_icmphdr push_icmp
#define lua_push_iphdr push_ip
#define lua_push_ip6hdr push_ip6
#define lua_reconstruct_tcphdr build_tcp
#define lua_reconstruct_udphdr build_udp
#define lua_reconstruct_icmphdr build_icmp
#define lua_reconstruct_iphdr build_ip
#define lua_reconstruct_ip6hdr build_ip6
#define lua_reconstruct_extract_options extract_options
#define luacall_dissect_tcphdr old_decode_tcp
#define luacall_dissect_udphdr old_decode_udp
#define luacall_dissect_icmphdr old_decode_icmp
#define luacall_dissect_iphdr old_decode_ip
#define luacall_dissect_ip6hdr old_decode_ip6
#define luacall_reconstruct_tcphdr old_encode_tcp
#define luacall_reconstruct_udphdr old_encode_udp
#define luacall_reconstruct_icmphdr old_encode_icmp
#define luacall_reconstruct_iphdr old_encode_ip
#define luacall_reconstruct_ip6hdr old_encode_ip6
#define lua_pushf_tcphdr old_field_tcp
#define lua_pushf_udphdr old_field_udp
#define lua_pushf_icmphdr old_field_icmp
#define lua_pushf_iphdr old_field_ip
#define lua_pushf_ip6hdr old_field_ip6
#define lua_push_dissect old_packet
#define lua_pushf_dissect old_packet_field
#define lua_push_ipaddr old_address
#define lua_pushf_ipaddr old_address_field
#define lua_pushi_ipaddr old_address_index
#include "lua_header_entry_reference.inc"
#undef lua_check_argc
#undef lua_check_argc_range
#undef lua_reqlstring
#undef lua_absindex
#include "windows_lua_guards_abi.h"
#undef luacall_dissect_tcphdr
#undef luacall_dissect_udphdr
#undef luacall_dissect_icmphdr
#undef luacall_dissect_iphdr
#undef luacall_dissect_ip6hdr
#undef luacall_reconstruct_tcphdr
#undef luacall_reconstruct_udphdr
#undef luacall_reconstruct_icmphdr
#undef luacall_reconstruct_iphdr
#undef luacall_reconstruct_ip6hdr
#undef lua_pushf_tcphdr
#undef lua_pushf_udphdr
#undef lua_pushf_icmphdr
#undef lua_pushf_iphdr
#undef lua_pushf_ip6hdr
#undef lua_push_dissect
#undef lua_pushf_dissect
#undef lua_push_ipaddr
#undef lua_pushf_ipaddr
#undef lua_pushi_ipaddr
#ifdef ZAPRET_RUST_LUA_HEADER_VIEWS
#define lua_pushf_tcphdr policy_field_tcp
#define lua_pushf_udphdr policy_field_udp
#define lua_pushf_icmphdr policy_field_icmp
#define lua_pushf_iphdr policy_field_ip
#define lua_pushf_ip6hdr policy_field_ip6
#define lua_push_dissect policy_packet
#define lua_pushf_dissect policy_packet_field
#endif
#include "lua_header_entry_windows.inc"
#ifdef ZAPRET_RUST_LUA_HEADER_VIEWS
#undef lua_pushf_tcphdr
#undef lua_pushf_udphdr
#undef lua_pushf_icmphdr
#undef lua_pushf_iphdr
#undef lua_pushf_ip6hdr
#undef lua_push_dissect
#undef lua_pushf_dissect
#include "windows_lua_header_views_abi.h"
#endif
#include "lua_packet_address_windows.inc"
static const char *factory=
"function SNAP(v) local t=type(v);if t=='table' then local keys,out={},{};for k in pairs(v) do keys[#keys+1]=k end;table.sort(keys,function(a,b)if type(a)~=type(b) then return type(a)<type(b) end return a<b end);for _,k in ipairs(keys) do out[#out+1]=SNAP(k)..'='..SNAP(v[k]) end;return '{'..table.concat(out,';')..'}' elseif t=='string' then return t..#v..':'..v elseif t=='number' then return t..string.format('%.17g',v) else return t..tostring(v) end end "
"function HEADER(kind,id,option) LOOKUPS={} local z=string.rep(string.char(0),16);local fields=kind==0 and {th_sport=1234,th_dport=443,th_seq=12345,th_ack=54321,th_flags=2,th_win=4096} or kind==1 and {uh_sport=1234,uh_dport=443,uh_ulen=8,uh_sum=1234} or kind==2 and {icmp_type=8,icmp_code=0,icmp_data=16909060,icmp_cksum=1286} or kind==3 and {ip_ttl=64,ip_p=17,ip_src=z:sub(1,4),ip_dst=z:sub(1,4)} or {ip6_src=z,ip6_dst=z,ip6_hlim=64}; "
"local options;if option==1 then options=false elseif option==2 then options={} elseif option==3 or option==4 or option==5 then options=setmetatable({},{__index=function(_,k) LOOKUPS[#LOOKUPS+1]='option.'..k;if option==4 then error('option callback failed') end;if option==5 then fields.ip6_hlim=19 end;NESTED();if k=='ip6_last_proto' then return 17 end;return true end}) elseif option==6 then options={ip6_preserve_next=0,ip6_last_proto=4294967313} elseif option==7 then options=17 end; "
"if id==1 then fields={} elseif id==2 then fields=false elseif id==3 then fields=17 elseif id==4 then fields='table' elseif id==5 then for k,v in pairs(fields) do if type(v)=='number' then fields[k]=tostring(v) end end elseif id==6 or id==7 or id==8 then local original=fields;fields=setmetatable({},{__index=function(_,k) LOOKUPS[#LOOKUPS+1]=k;NESTED();if id==7 then error('header callback failed') end;if id==8 and k=='options' then return string.rep('x',41) end;return original[k] end}) elseif id==9 then fields.options=string.rep('x',41);fields.exthdr={{type=51,data='short'}} elseif id==10 then fields.ip6_plen=false elseif id==11 then fields.ip6_flow=0;fields.th_seq=4294967295 elseif id==12 then fields.ip6_preserve_next=true;fields.options={{kind=1},{kind=2,data=string.char(5,180)}} end;return fields,options end";
struct allocator {bool armed;unsigned calls,rejected,limit,live;};static struct allocator *fault_allocator;
static void *allocate(void *context,void *pointer,size_t before,size_t after){struct allocator *a=context;if(!after){if(pointer){CHECK(a->live);--a->live;}free(pointer);return NULL;}if(a->armed && after>before && a->calls++>=a->limit){++a->rejected;return NULL;}bool fresh=!pointer;void *p=realloc(pointer,after);if(p && fresh)++a->live;return p;}
static int nested_api(lua_State *L);
static lua_State *new_vm(struct allocator *a){lua_State *L=a?lua_newstate(allocate,a):luaL_newstate();CHECK(L);params.L=L;luaL_openlibs(L);luaJIT_setmode(L,0,LUAJIT_MODE_ENGINE|LUAJIT_MODE_OFF);CHECK(!luaL_dostring(L,factory));lua_pushcfunction(L,nested_api);lua_setglobal(L,"NESTED");return L;}
#ifndef ZAPRET_RUST_LUA_HEADER_VIEWS
static lua_CFunction resolve(bool rust,unsigned api){const lua_CFunction old[]={old_decode_tcp,old_decode_udp,old_decode_icmp,old_decode_ip,old_decode_ip6,old_encode_tcp,old_encode_udp,old_encode_icmp,old_encode_ip,old_encode_ip6},current[]={luacall_dissect_tcphdr,luacall_dissect_udphdr,luacall_dissect_icmphdr,luacall_dissect_iphdr,luacall_dissect_ip6hdr,luacall_reconstruct_tcphdr,luacall_reconstruct_udphdr,luacall_reconstruct_icmphdr,luacall_reconstruct_iphdr,luacall_reconstruct_ip6hdr};return rust?current[api]:old[api];}
#endif
#ifdef ZAPRET_RUST_LUA_HEADER_VIEWS
static int nested_view(lua_State *L)
{
    if(nested_kind==2)return luaL_error(L,"nested header view fixture");
    lua_newtable(L);
    (native_side?lua_pushf_udphdr:old_field_udp)(L,(const void *)udp_bytes,8);
    return 1;
}
#endif
static void nested_call(lua_State *L)
{
    nested_entered=true;
    int top=lua_gettop(L);
#ifdef ZAPRET_RUST_LUA_HEADER_VIEWS
    lua_pushcfunction(L,nested_view);
    int status=lua_pcall(L,0,1,0);
#else
    lua_pushcfunction(L,resolve(native_side,nested_kind==2?6:1));
    if(nested_kind==2)lua_pushboolean(L,false);else lua_pushlstring(L,"\0\0\0\0\0\0\0\0",8);
    int status=lua_pcall(L,1,1,0);
#endif
    event(50,status);event(51,lua_type(L,-1));lua_settop(L,top);
    if(active){++active->nested;++nested_total;}
    if(nested_kind==3){luaL_error(L,"nested header publication failure");return;}
    lua_gc(L,LUA_GCCOLLECT,0);
}
static int nested_api(lua_State *L){nested_call(L);return 0;}
static int projection(lua_State *L)
{
#ifdef ZAPRET_RUST_LUA_HEADER_VIEWS
    if(selected_operation>=15){
        lua_newtable(L);
        switch(selected_operation){
        case 15: (native_side?lua_pushf_tcphdr:old_field_tcp)(L,selected_header,selected_header_length); break;
        case 16: (native_side?lua_pushf_udphdr:old_field_udp)(L,selected_header,selected_header_length); break;
        case 17: (native_side?lua_pushf_icmphdr:old_field_icmp)(L,selected_header,selected_header_length); break;
        case 18: (native_side?lua_pushf_iphdr:old_field_ip)(L,selected_header,selected_header_length); break;
        case 19: (native_side?lua_pushf_ip6hdr:old_field_ip6)(L,selected_header,selected_header_length); break;
        default: CHECK(false);
        }
        return 1;
    }
#endif
    if(selected_operation==10){
        if(native_side)lua_push_dissect(L,selected_source);else old_packet(L,selected_source);
    }else if(selected_operation==11){
        lua_newtable(L);
        if(native_side)lua_pushf_dissect(L,selected_source);else old_packet_field(L,selected_source);
    }else if(selected_operation==12){
        if(native_side)lua_push_ipaddr(L,selected_address);else old_address(L,selected_address);
    }else{
        lua_newtable(L);
        if(selected_operation==13){
            if(native_side)lua_pushf_ipaddr(L,"address",selected_address);else old_address_field(L,"address",selected_address);
        }else{
            if(native_side)lua_pushi_ipaddr(L,-7,selected_address);else old_address_index(L,-7,selected_address);
        }
    }
    return 1;
}
static void capture(lua_State *L,struct sample *result){result->arity=lua_gettop(L);CHECK(result->arity==1);result->type=lua_type(L,1);if(result->status){const char *message=lua_tostring(L,1);snprintf(result->message,sizeof(result->message),"%s",message?message:"");return;}lua_getglobal(L,"SNAP");lua_pushvalue(L,1);CHECK(!lua_pcall(L,1,1,0));const char *bytes=lua_tolstring(L,-1,&result->length);CHECK(bytes && result->length<sizeof(result->bytes));memcpy(result->bytes,bytes,result->length);lua_pop(L,1);}
#ifndef ZAPRET_RUST_LUA_HEADER_VIEWS
static void snapshot_lookups(lua_State *L,struct sample *result){lua_getglobal(L,"LOOKUPS");if(lua_istable(L,-1)){for(unsigned i=1;;++i){lua_rawgeti(L,-1,i);if(lua_isnil(L,-1)){lua_pop(L,1);break;}size_t n;const char *p=lua_tolstring(L,-1,&n);CHECK(p);result->inputs=result->inputs*1099511628211ULL^hash(p,n);lua_pop(L,1);}}lua_pop(L,1);}

static void push_read_argument(lua_State *L,unsigned api,unsigned variant,size_t length)
{
    switch(variant){
    case 0: lua_pushlstring(L,(const char *)header_bytes[api],length); break;
    case 1: lua_pushinteger(L,123); break;
    case 2: lua_pushboolean(L,false); break;
    case 3: lua_newtable(L); break;
    case 4: lua_pushnil(L); break;
    case 5: lua_pushlightuserdata(L,header_bytes[api]); break;
    case 6: lua_pushcfunction(L,nested_api); break;
    case 7: lua_pushthread(L); break;
    case 8: (void)lua_newuserdata(L,1); break;
    default: CHECK(false);
    }
}

static struct sample invoke_entry(lua_State *L,bool rust,unsigned api,unsigned variant,unsigned option,unsigned argc,size_t length){
    struct sample result={0};lua_settop(L,0);lua_pushcfunction(L,resolve(rust,api));if(api<5){for(unsigned i=0;i<argc;++i){if(i)lua_pushboolean(L,false);else push_read_argument(L,api,variant,length);}}
    else{lua_getglobal(L,"HEADER");lua_pushinteger(L,api%5);lua_pushinteger(L,variant);lua_pushinteger(L,option);CHECK(!lua_pcall(L,3,2,0));if(argc==0)lua_settop(L,1);else if(argc==1)lua_pop(L,1);else for(unsigned i=2;i<argc;++i)lua_pushboolean(L,false);}
    selected_operation=api;native_side=rust;nested_entered=false;mutated=false;active=&result;if(fault_allocator){fault_allocator->armed=true;fault_allocator->calls=fault_allocator->rejected=0;}result.status=lua_pcall(L,argc,LUA_MULTRET,0);if(fault_allocator)fault_allocator->armed=false;active=NULL;capture(L,&result);if(api>=5)snapshot_lookups(L,&result);lua_settop(L,0);return result;
}
#endif
static void equal(struct sample *a,struct sample *b,unsigned api,unsigned variant,unsigned option){if(memcmp(a,b,sizeof(*a))){fprintf(stderr,"DETAIL api=%u variant=%u option=%u old_status=%d new_status=%d old_type=%d new_type=%d old_size=%zu new_size=%zu old_trace=%llx new_trace=%llx old_calls=%u new_calls=%u old_error=%s new_error=%s\n",api,variant,option,a->status,b->status,a->type,b->type,a->length,b->length,(unsigned long long)a->trace,(unsigned long long)b->trace,a->calls,b->calls,a->message,b->message);CHECK(false);}++cases;if(a->status)++errors;}
#ifndef ZAPRET_RUST_LUA_HEADER_VIEWS
static unsigned read_cases,read_reentries,read_vm_faults;

static void compare_entry(lua_State *L,unsigned api,unsigned variant,unsigned option,unsigned argc,size_t length)
{
    struct sample a=invoke_entry(L,false,api,variant,option,argc,length);
    struct sample b=invoke_entry(L,true,api,variant,option,argc,length);
    equal(&a,&b,api,variant,option);
    ++entry_cases;
    if(api>=5)return;
    ++read_cases;
    if(argc!=1 || variant!=0){
        CHECK(a.status==LUA_ERRRUN && a.calls==0);
    }else if(nested_boundary==0){
        static const size_t minimum[]={20,8,8,20,40};
        CHECK(!a.status && a.calls==1);
        CHECK(a.type==(length>=minimum[api]?LUA_TTABLE:LUA_TNIL));
    }else if(nested_boundary==1 || nested_boundary==3){
        CHECK(a.nested==1 && a.status==(nested_kind==3?LUA_ERRRUN:0));
        ++read_reentries;
    }
}

static void compare_reads(lua_State *L)
{
    static const size_t varied_offset[]={12,3,0,0,6};
    for(unsigned api=0;api<5;++api){
        uint8_t *field=header_bytes[api]+varied_offset[api];
        const uint8_t original=*field;
        for(unsigned pattern=0;pattern<16;++pattern){
            *field=(uint8_t)(original^(pattern*17));
            for(size_t length=0;length<=128;++length)compare_entry(L,api,0,0,1,length);
        }
        *field=original;
        for(unsigned variant=0;variant<=8;++variant)
            for(unsigned argc=0;argc<4;++argc)compare_entry(L,api,variant,0,argc,64);
    }
}
#endif
static void setup_source(unsigned mask,unsigned fragment,size_t l3,size_t l4,unsigned payload_mode){memset(&source,0xa5,sizeof(source));source.ip=mask&1?(void *)ip_bytes:NULL;source.ip6=mask&2?(void *)ip6_bytes:NULL;source.tcp=mask&4?(void *)tcp_bytes:NULL;source.udp=mask&8?(void *)udp_bytes:NULL;source.icmp=mask&16?(void *)icmp_bytes:NULL;source.len_l3=l3;source.len_l4=l4;source.proto=(uint8_t)(mask*7);source.transport_len=mask%2?SIZE_MAX:65536;source.data_payload=payload_mode&1?payload:NULL;source.len_payload=payload_mode&1?payload_mode*3:SIZE_MAX;source.frag=fragment;source.frag_off=(uint16_t)(mask*2047);selected_source=&source;}
static struct sample invoke_projection(lua_State *L,bool rust,unsigned operation){struct sample result={0};lua_settop(L,0);lua_pushcfunction(L,projection);selected_operation=operation;native_side=rust;nested_entered=false;mutated=false;active=&result;if(fault_allocator){fault_allocator->armed=true;fault_allocator->calls=fault_allocator->rejected=0;}result.status=lua_pcall(L,0,1,0);if(fault_allocator)fault_allocator->armed=false;active=NULL;capture(L,&result);lua_settop(L,0);return result;}
static void compare_projection(lua_State *L,unsigned operation,unsigned mask,unsigned fragment,size_t l3,size_t l4,unsigned payload_mode){setup_source(mask,fragment,l3,l4,payload_mode);struct sample a=invoke_projection(L,false,operation);setup_source(mask,fragment,l3,l4,payload_mode);struct sample b=invoke_projection(L,true,operation);equal(&a,&b,operation,mask,mutation_mode);++projection_cases;}
static void compare_address(lua_State *L,unsigned operation,const void *address){selected_address=address;struct sample a=invoke_projection(L,false,operation),b=invoke_projection(L,true,operation);equal(&a,&b,operation,0,0);++address_cases;}
/* Negative control: a deliberately eager snapshot must differ from live reads. */
static void eager_snapshot_controls(lua_State *L){for(mutation_mode=1;mutation_mode<=3;++mutation_mode)for(unsigned op=10;op<=11;++op){setup_source(31,0,64,64,3);struct sample live=invoke_projection(L,false,op);setup_source(31,0,64,64,3);struct dissect frozen=source;selected_source=&frozen;struct sample eager=invoke_projection(L,false,op);CHECK(!live.status && !eager.status && (live.length!=eager.length || memcmp(live.bytes,eager.bytes,live.length)));++eager_controls;}mutation_mode=0;}
#ifndef ZAPRET_RUST_LUA_HEADER_VIEWS
static void faults(void)
{
    for(unsigned api=0;api<15;++api)for(unsigned side=0;side<2;++side){
        unsigned read_failures=0;
        for(unsigned limit=0;limit<64;++limit){
            struct allocator a={.limit=limit};
            lua_State *L=new_vm(&a);
            fault_allocator=&a;
            struct sample result;
            if(api<10){
                result=invoke_entry(L,side,api,api<5?0:6,api==9?3:0,api==9?2:1,64);
            }else{
                setup_source(31,1,64,64,3);
                struct sockaddr_in6 address={.sin6_family=AF_INET6};
                memset(&address.sin6_addr,0x13,16);
                selected_address=(void *)&address;
                result=invoke_projection(L,side,api);
            }
            fault_allocator=NULL;
            if(result.status){
                CHECK(result.status==LUA_ERRMEM && a.rejected);
                ++vm_faults;
                if(api<5){
                    ++read_failures;
                    struct sample recovered=invoke_entry(L,side,api,0,0,1,64);
                    CHECK(!recovered.status && recovered.type==LUA_TTABLE && recovered.calls==1);
                }
            }
            lua_close(L);
            CHECK(!a.live);
            ++fault_cases;
        }
        if(api<5)CHECK(read_failures>0);
        read_vm_faults+=read_failures;
    }
}
#endif
static void guard_checks(lua_State *L){uint8_t *memory=VirtualAlloc(NULL,16384,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);CHECK(memory);DWORD old;CHECK(VirtualProtect(memory+4096,4096,PAGE_NOACCESS,&old) && VirtualProtect(memory+12288,4096,PAGE_NOACCESS,&old));
    for(unsigned family=0;family<65536;++family){size_t length=family==AF_INET?8:family==AF_INET6?24:2;uint8_t *p=memory+4096-length;memset(p,0x3f,length);uint16_t f=(uint16_t)family;memcpy(p,&f,2);for(unsigned op=12;op<15;++op)compare_address(L,op,p);guarded+=3;}
    setup_source(31,1,64,64,3);struct dissect *dis=(void *)(memory+12288-sizeof(source));memcpy(dis,&source,sizeof(source));selected_source=dis;CHECK(VirtualProtect(memory+8192,4096,PAGE_READONLY,&old));for(unsigned op=10;op<=11;++op){struct sample a=invoke_projection(L,false,op),b=invoke_projection(L,true,op);equal(&a,&b,op,0,0);++projection_cases;++guarded;}CHECK(VirtualProtect(memory+8192,4096,PAGE_READWRITE,&old));
    zapret_lua_header_entry_state state;zapret_lua_header_entry_action action={.kind=91};zapret_lua_header_entry_value value={0};CHECK(!zapret_lua_header_entry_begin(10,NULL,0,&state,&action) && action.kind==91);++boundaries;CHECK(!zapret_lua_header_entry_begin(9,memory,511,&state,&action));++boundaries;CHECK(!zapret_lua_header_entry_begin(0,NULL,0,NULL,&action));++boundaries;CHECK(!zapret_lua_header_entry_begin(0,NULL,0,(void *)(memory+1),&action));++boundaries;CHECK(!zapret_lua_header_entry_begin(0,NULL,0,&state,NULL));++boundaries;
    CHECK(zapret_lua_header_entry_begin(0,NULL,0,&state,&action));CHECK(!zapret_lua_header_entry_step(&state,NULL,&action));++boundaries;CHECK(!zapret_lua_header_entry_step(&state,&value,NULL));++boundaries;CHECK(zapret_lua_header_entry_step(&state,&value,&action));value.length=1;CHECK(!zapret_lua_header_entry_step(&state,&value,&action));++boundaries;
    uint32_t cursor=0;zapret_lua_packet_projection_action out={.kind=91};CHECK(!zapret_lua_packet_projection((void *)(memory+1),&cursor,&out) && out.kind==91);++boundaries;CHECK(!zapret_lua_packet_projection(NULL,NULL,&out));++boundaries;cursor=13;CHECK(!zapret_lua_packet_projection(NULL,&cursor,&out));++boundaries;CHECK(zapret_lua_header_field_name(5)==NULL);++boundaries;CHECK(!zapret_lua_packet_address(NULL,NULL));++boundaries;
    zapret_lua_header_entry_state *edge=(void *)(memory+4096-sizeof(state));zapret_lua_header_entry_action *end=(void *)(memory+12288-sizeof(action));CHECK(zapret_lua_header_entry_begin(0,NULL,0,edge,end));++boundaries;CHECK(VirtualFree(memory,0,MEM_RELEASE));}

#ifdef ZAPRET_RUST_LUA_HEADER_VIEWS
static const uint8_t *field_source(unsigned operation)
{
    CHECK(operation>=15 && operation<20);
    return header_bytes[operation-15];
}

static void compare_field(lua_State *L,unsigned operation,const void *data,size_t length)
{
    selected_header=data;
    selected_header_length=length;
    struct sample a=invoke_projection(L,false,operation);
    struct sample b=invoke_projection(L,true,operation);
    equal(&a,&b,operation,(unsigned)length,data!=NULL);
    ++field_cases;
}

static void direct_view_guards(lua_State *L)
{
    uint8_t *memory=VirtualAlloc(NULL,8192,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    CHECK(memory);
    DWORD old;
    CHECK(VirtualProtect(memory+4096,4096,PAGE_NOACCESS,&old));
    for(unsigned operation=15;operation<20;++operation){
        const uint8_t *data=field_source(operation);
        for(size_t length=0;length<=128;++length){
            uint8_t *edge=memory+4096-length;
            memcpy(edge,data,length);
            compare_field(L,operation,edge,length);
            ++guarded;
        }
    }
    setup_source(31,1,64,64,3);
    struct dissect *decoded=(void *)(memory+4096-sizeof(source));
    memcpy(decoded,&source,sizeof(source));
    selected_source=decoded;
    CHECK(VirtualProtect(memory,4096,PAGE_READONLY,&old));
    for(unsigned op=10;op<=11;++op){
        struct sample a=invoke_projection(L,false,op),b=invoke_projection(L,true,op);
        equal(&a,&b,op,31,0);
        ++projection_cases;++guarded;
    }
    CHECK(VirtualFree(memory,0,MEM_RELEASE));
}

static void direct_view_faults(void)
{
    static const unsigned operations[]={10,11,15,16,17,18,19};
    for(unsigned alternative=0;alternative<sizeof(operations)/sizeof(*operations);++alternative)
        for(unsigned side=0;side<2;++side)for(unsigned limit=0;limit<64;++limit){
            unsigned operation=operations[alternative];
            struct allocator a={.limit=limit};
            lua_State *L=new_vm(&a);
            setup_source(31,1,64,64,3);
            if(operation>=15){
                selected_header=field_source(operation);
                selected_header_length=64;
            }
            fault_allocator=&a;
            struct sample result=invoke_projection(L,side,operation);
            fault_allocator=NULL;
            if(result.status){CHECK(result.status==LUA_ERRMEM && a.rejected);++vm_faults;}
            lua_close(L);CHECK(!a.live);++fault_cases;
        }
    CHECK(vm_faults>0);
}
#endif
int main(void){for(unsigned i=0;i<128;++i){ip_bytes[i]=(uint8_t)(i*7);ip6_bytes[i]=(uint8_t)(i*11);tcp_bytes[i]=(uint8_t)(i*13);udp_bytes[i]=(uint8_t)(i*17);icmp_bytes[i]=(uint8_t)(i*19);payload[i]=(uint8_t)(i*23);}tcp_bytes[12]=0x50;ip_bytes[0]=0x45;ip6_bytes[0]=0x60;ip6_bytes[6]=59;lua_State *L=new_vm(NULL);
#ifndef ZAPRET_RUST_LUA_HEADER_VIEWS
    compare_reads(L);
    for(unsigned api=5;api<10;++api)for(unsigned variant=0;variant<13;++variant)for(unsigned option=0;option<8;++option)for(unsigned argc=0;argc<4;++argc)compare_entry(L,api,variant,option,argc,64);
#endif
    const size_t l3[]={0,7,8,19,20,39,40,48,60,64},l4[]={0,7,8,19,20,60};for(unsigned op=10;op<=11;++op)for(unsigned mask=0;mask<32;++mask)for(unsigned frag=0;frag<2;++frag)for(unsigned a=0;a<10;++a)for(unsigned b=0;b<6;++b)compare_projection(L,op,mask,frag,l3[a],l4[b],mask%4);
    for(mutation_mode=1;mutation_mode<=3;++mutation_mode)for(unsigned op=10;op<=11;++op)for(unsigned mask=0;mask<32;++mask)for(unsigned frag=0;frag<2;++frag)compare_projection(L,op,mask,frag,64,64,3);mutation_mode=0;
    selected_source=NULL;for(unsigned op=10;op<=11;++op){struct sample a=invoke_projection(L,false,op),b=invoke_projection(L,true,op);equal(&a,&b,op,0,0);++projection_cases;}
#ifdef ZAPRET_RUST_LUA_HEADER_VIEWS
    for(unsigned op=15;op<20;++op){
        for(size_t length=0;length<=128;++length)compare_field(L,op,field_source(op),length);
        compare_field(L,op,NULL,64);
    }
    for(nested_boundary=1;nested_boundary<=3;++nested_boundary)
        for(nested_kind=1;nested_kind<=3;++nested_kind){
            for(unsigned op=10;op<=11;++op)compare_projection(L,op,31,1,64,64,3);
            for(unsigned op=15;op<20;++op)compare_field(L,op,field_source(op),64);
        }
    nested_boundary=0;
    eager_snapshot_controls(L);direct_view_guards(L);lua_close(L);direct_view_faults();
    printf("PASS windows_lua_header_views cases=%u projection_cases=%u field_cases=%u vm_errors=%u native_calls=%u nested_calls=%u mutable_source_updates=%u eager_snapshot_controls=%u guarded=%u fault_cases=%u vm_allocation_faults=%u real_luajit=1 exact_errors=1 exact_arity=1 exact_vm_order=1 deferred_native_reads=1 captured_header_spans=1 vm_allocations_released=1 rust_seh_unwind=1\n",cases,projection_cases,field_cases,errors,native_calls,nested_total,mutations,eager_controls,guarded,fault_cases,vm_faults);
    return 0;
#else
    for(nested_boundary=1;nested_boundary<=3;++nested_boundary)for(nested_kind=1;nested_kind<=3;++nested_kind)for(unsigned api=0;api<12;++api){if(api<10)compare_entry(L,api,0,0,1,64);else compare_projection(L,api,31,1,64,64,3);}nested_boundary=0;
    uint8_t address[40];for(unsigned offset=0;offset<8;++offset)for(unsigned family=0;family<24;++family){memset(address,0x57,sizeof(address));uint16_t f=(uint16_t)family;memcpy(address+offset,&f,2);for(unsigned op=12;op<15;++op)compare_address(L,op,address+offset);}for(unsigned op=12;op<15;++op)compare_address(L,op,NULL);
    eager_snapshot_controls(L);guard_checks(L);lua_close(L);faults();
    printf("PASS lua_header_entry apis=10 cases=%u entry_cases=%u read_cases=%u projection_cases=%u address_cases=%u vm_errors=%u native_calls=%u nested_calls=%u read_reentries=%u mutable_source_updates=%u eager_snapshot_controls=%u guarded=%u boundaries=%u fault_cases=%u vm_allocation_faults=%u read_vm_allocation_faults=%u real_luajit=1 actual_headers=1 all_address_families=1 strict_read_types=1 exact_errors=1 exact_arity=1 exact_native_capacities=1 exact_vm_order=1 deferred_native_reads=1 captured_header_spans=1 vm_allocations_released=1 rust_read_seh_unwind=1\n",cases,entry_cases,read_cases,projection_cases,address_cases,errors,native_calls,nested_total,read_reentries,mutations,eager_controls,guarded,boundaries,fault_cases,vm_faults,read_vm_faults);
    return 0;
#endif
}
