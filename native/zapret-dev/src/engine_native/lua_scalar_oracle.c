/* MIT. Extend the existing full system entry oracle with all scalar entries. */
#define ZAPRET_LUA_SCALAR_ORACLE 1
#include "lua_system_tables_oracle.c"
static lua_CFunction basic_resolver(bool rust,unsigned api){const lua_CFunction old[]={reference_luacall_DLOG,reference_luacall_DLOG_ERR,reference_luacall_DLOG_CONDUP,reference_luacall_getpid,reference_luacall_gettid,reference_luacall_get_ifaddrs,reference_luacall_get_source_ip},now[]={luacall_DLOG,luacall_DLOG_ERR,luacall_DLOG_CONDUP,luacall_getpid,luacall_gettid,luacall_get_ifaddrs,luacall_get_source_ip};return rust?now[api]:old[api];}
static void basic_execute(lua_State *L,bool rust,unsigned api,unsigned shape,unsigned argc,struct sample *sample,struct allocator *allocator){
    lua_settop(L,0);lua_pushcfunction(L,basic_resolver(rust,api));
    for(unsigned i=0;i<argc;++i){switch(shape){case 0:lua_pushlstring(L,api==6?"\127\0\0\1":"hello",api==6?4:5);break;case 1:lua_pushinteger(L,123);break;case 2:lua_pushboolean(L,false);break;case 3:lua_pushnil(L);break;case 4:lua_newtable(L);break;case 5:lua_pushlstring(L,"foo\0tail",8);break;case 6:lua_pushlstring(L,"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1",16);break;default:lua_pushliteral(L,"");break;}}
    active=sample;scalar_basic_api=api;errno=EDOM;
    if(allocator)allocator->armed=true;
    sample->status=lua_pcall(L,argc,LUA_MULTRET,0);
    if(allocator)allocator->armed=false;
    sample->errno_after=errno;sample->arity=lua_gettop(L);CHECK(sample->arity>=0 && sample->arity<=1);
    if(sample->status){snprintf(sample->message,sizeof(sample->message),"%s",lua_tostring(L,-1));}
    else if(sample->arity && lua_type(L,1)==LUA_TTABLE){lua_getfield(L,1,"fixture");atom(L,-1,&sample->values[0]);lua_pop(L,1);}
    else if(sample->arity)atom(L,1,&sample->values[0]);
    active=NULL;
}
static void basic_compare(lua_State *L,unsigned api,unsigned shape,unsigned argc){struct sample old={0},now={0};basic_execute(L,false,api,shape,argc,&old,NULL);basic_execute(L,true,api,shape,argc,&now,NULL);if(memcmp(&old,&now,sizeof(old))){fprintf(stderr,"scalar api=%u shape=%u argc=%u variant=%u old=%d/%d new=%d/%d\noldtrace=%s\nnewtrace=%s\noldmsg=%s\nnewmsg=%s\n",api,shape,argc,native_variant,old.status,old.arity,now.status,now.arity,old.trace,now.trace,old.message,now.message);CHECK(false);}++cases;if(old.status)++errors;}
static void basic_faults(void){for(unsigned api=0;api<7;++api)for(unsigned side=0;side<2;++side)for(unsigned budget=0;budget<48;++budget){struct allocator allocator={.limit=budget};lua_State *L=new_vm(&allocator);struct sample result={0};basic_execute(L,side!=0,api,1,api<3||api==6?1:0,&result,&allocator);if(result.status){CHECK(result.status==LUA_ERRMEM || api==6);if(result.status==LUA_ERRMEM){CHECK(allocator.rejected);++vm_faults;}}lua_close(L);CHECK(!allocator.live);++fault_cases;}}
static void scalar_boundaries(void){zapret_lua_scalar_state state={0};zapret_lua_scalar_action action={.kind=77};zapret_lua_scalar_value value={0};
    CHECK(!zapret_lua_scalar_begin(15,0,&state,&action) && action.kind==77);++boundaries;CHECK(!zapret_lua_scalar_begin(0,-1,&state,&action));++boundaries;CHECK(!zapret_lua_scalar_begin(0,1,NULL,&action));++boundaries;CHECK(!zapret_lua_scalar_begin(0,1,(void *)(uintptr_t)1,&action));++boundaries;CHECK(!zapret_lua_scalar_begin(0,1,&state,(void *)(uintptr_t)1));++boundaries;
    CHECK(zapret_lua_scalar_begin(0,1,&state,&action));CHECK(!zapret_lua_scalar_step(NULL,&value,&action));++boundaries;CHECK(!zapret_lua_scalar_step(&state,NULL,&action));++boundaries;CHECK(!zapret_lua_scalar_step(&state,(void *)(uintptr_t)1,&action));++boundaries;CHECK(!zapret_lua_scalar_step(&state,&value,(void *)(uintptr_t)1));++boundaries;}
int main(void){FILE *file=fopen(native_file,"wb");CHECK(file);CHECK(fwrite("a\0b\r\n",1,5,file)==5);CHECK(!fclose(file));lua_State *L=new_vm(NULL);
    for(native_variant=0;native_variant<24;++native_variant)for(unsigned api=0;api<8;++api)for(unsigned shape=0;shape<12;++shape)for(unsigned argc=0;argc<3;++argc)compare(L,api,shape,0,shape%21,0,argc);
    for(native_variant=0;native_variant<8;++native_variant)for(unsigned api=6;api<8;++api)for(unsigned field=0;field<=7;++field)for(unsigned variant=0;variant<=20;++variant)for(unsigned behavior=0;behavior<6;++behavior)compare(L,api,0,field,variant,behavior,1);
    for(native_variant=0;native_variant<24;++native_variant)for(unsigned api=0;api<7;++api)for(unsigned shape=0;shape<8;++shape)for(unsigned argc=0;argc<4;++argc)basic_compare(L,api,shape,argc);
    for(scalar_errno_mutation=1;scalar_errno_mutation<=2;++scalar_errno_mutation)for(native_variant=0;native_variant<24;++native_variant)compare(L,0,0,0,0,0,1);scalar_errno_mutation=0;
    real_native=true;native_variant=1;for(unsigned api=0;api<8;++api)for(unsigned shape=0;shape<12;++shape)compare(L,api,shape,0,shape%21,0,api==1||api==2||api==3?0:1);
    lua_close(L);faults();native_variant=1;basic_faults();scalar_boundaries();CHECK(!remove(native_file));
    printf("PASS lua_scalar apis=15 cases=%u vm_errors=%u reentries=%u boundaries=%u native_cases=%u fault_cases=%u vm_allocation_faults=%u real_luajit=1 exact_vm_order=1 exact_errors=1 exact_arity=1 deferred_errno=1 c_only_unwind=1 vm_allocations_released=1\n",cases,errors,reentries,boundaries,real_cases,fault_cases,vm_faults);return 0;}
