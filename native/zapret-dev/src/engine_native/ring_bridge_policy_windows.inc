/* MIT. The trusted loader and Lua callback addresses stay C; Rust selects all entry stages. */
#include <stdbool.h>
#include "ring_bridge_policy_abi.h"
static int rr_call(lua_State *L)
{
    zapret_ring_entry_flow flow={0};zapret_ring_entry_feedback value={0};
    rr_request input;rr_response output;void *handle=NULL;rr_userdata *created=NULL;
    unsigned char small[512],*bytes=small;
    for(;;)switch(zapret_ring_entry_step(&flow,&value)) {
    case 1:value.operation=(unsigned)lua_tointeger(L,lua_upvalueindex(1));break;
    case 2:value.arguments=lua_gettop(L);break;
    case 3:memset(&input,0,sizeof(input));memset(&output,0,sizeof(output));break;
    case 4:{rr_userdata *object=luaL_checkudata(L,1,zapret_ring_class_name(flow.object_class));handle=object->object;value.available=handle!=NULL;break;}
    case 5:value.kind=lua_type(L,flow.index+1);break;
    case 6:zapret_ring_request_number(&input,flow.index,lua_toboolean(L,flow.index+1)!=0);break;
    case 7:value.number=lua_tonumber(L,flow.index+1);break;
    case 8:{
        size_t length=0;
        const uint8_t *text=(const uint8_t *)lua_tolstring(L,flow.index+1,&length);
        zapret_ring_request_text(&input,flow.index,text,length);break;
    }
    case 9:zapret_ring_request_number(&input,flow.index,value.number);break;
    case 34:{
        rr_userdata *store=luaL_checkudata(L,flow.index+1,zapret_ring_class_name(1));
        value.available=store->object!=NULL;
        if(value.available)zapret_ring_request_store(&input,store->object);
        break;
    }
    case 10:created=lua_newuserdata(L,sizeof(*created));created->object=NULL;luaL_getmetatable(L,zapret_ring_class_name(flow.constructor_class));lua_setmetatable(L,-2);break;
    case 11:bytes=lua_newuserdata(L,flow.capacity);break;
    case 12:bytes=small;break;
    case 13:value.backend=rr_backend->invoke(flow.operation,handle,&input,&output,bytes,flow.capacity);break;
    case 14:return luaL_error(L,zapret_ring_entry_error(flow.phase),flow.operation,value.backend);
    case 15:created->object=output.object;value.available=created->object!=NULL;break;
    case 17:case 19:value.results=output.count;break;
    case 20:value.kind=output.values[flow.output_index].kind;break;
    case 21:lua_pushnil(L);break;
    case 22:lua_pushnumber(L,output.values[flow.output_index].number);break;
    case 23:lua_pushboolean(L,output.values[flow.output_index].number!=0);break;
    case 24:value.offset=output.values[flow.output_index].offset;value.length=output.values[flow.output_index].length;break;
    case 26:lua_pushlstring(L,(const char *)bytes+value.offset,value.length);break;
    case 27:return flow.return_count;
    default:return luaL_error(L,"%s",zapret_ring_entry_error(flow.phase));
    }
}
int rust_ring_register(lua_State *L)
{
    if(!rr_load()){unsigned long error=GetLastError();fprintf(stderr,zapret_ring_loader_error_text(),error);return 0;}
    zapret_ring_registration_flow flow={0};zapret_ring_registration_view value={0};
    for(;;)switch(zapret_ring_registration_step(&flow,&value)) {
    case 1:luaL_newmetatable(L,value.name);break;
    case 2:lua_pushcfunction(L,rr_gc);break;
    case 3:lua_setfield(L,-2,value.name);break;
    case 4:lua_pushlstring(L,value.name,value.name_length);break;
    case 5:lua_setfield(L,-2,value.name);break;
    case 6:lua_pop(L,1);break;
    case 7:lua_newtable(L);break;
    case 8:lua_pushinteger(L,(lua_Integer)value.integer);break;
    case 9:lua_pushcclosure(L,rr_call,1);break;
    case 10:lua_setfield(L,-2,value.name);break;
    case 11:lua_pushinteger(L,(lua_Integer)value.integer);break;
    case 12:lua_setfield(L,-2,value.name);break;
    case 13:lua_pushlstring(L,value.name,value.name_length);break;
    case 14:lua_setfield(L,-2,value.name);break;
    case 15:lua_setglobal(L,value.name);break;
    case 16:return 1;
    default:return 0;
    }
}
