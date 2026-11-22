/* MIT. C creates VM objects after each borrowed Rust field query returns. */
#include "lua_packet_arguments_windows.h"
static void native_lua_packet_arguments(const zapret_lua_packet_argument_input *input,
    const t_ctrack *track,const t_ctrack_positions *positions)
{
    lua_newtable(params.L);
    lua_pushf_dissect(params.L,input->packet);
    lua_pushf_ctrack(params.L,track,positions,input->incoming);
    uint32_t index=0,status;zapret_lua_packet_argument field;
    while((status=zapret_lua_packet_argument_next(&index,input,&field))==1){
        switch(field.kind){
            case 1:lua_pushf_int(params.L,field.name,(lua_Integer)field.number);break;
            case 2:lua_pushf_bool(params.L,field.name,field.number!=0);break;
            case 3:lua_pushf_str(params.L,field.name,(const char *)field.data);break;
            case 4:lua_pushf_lstr(params.L,field.name,(const char *)field.data,field.length);break;
            case 5:lua_pushf_raw(params.L,field.name,field.data,field.length);break;
            case 6:lua_pushf_table(params.L,field.name);break;
            case 7:lua_getfield(params.L,-1,field.name);break;
            case 8:lua_pop(params.L,1);break;
            case 9:lua_pushf_str(params.L,field.name,l7payload_str((t_l7payload)field.number));break;
            case 10:lua_pushf_str(params.L,field.name,l7proto_str((t_l7proto)field.number));break;
            case 11:lua_pushf_global(params.L,field.name,(const char *)field.data);break;
            default:luaL_error(params.L,"invalid Lua packet argument kind");return;
        }
    }
    if(status!=0)luaL_error(params.L,"invalid Lua packet argument state");
}
