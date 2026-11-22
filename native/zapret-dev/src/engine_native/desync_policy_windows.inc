/* MIT. Rust selects final packet/Lua stages; VM operations remain on the C stack. */
#include "desync_policy_abi.h"
static uint8_t desync(
    struct desync_profile *dp, uint32_t fwmark, const char *ifin, const char *ifout,
    bool bIncoming, t_ctrack *ctrack, const t_ctrack_positions *tpos,
    t_l7payload l7payload, t_l7proto l7proto, const struct dissect *dis,
    const struct in_addr *sdp4, const struct in6_addr *sdp6, uint16_t sdport,
    uint8_t *mod_pkt, size_t *len_mod_pkt, unsigned int replay_piece,
    unsigned int replay_piece_count, size_t reasm_offset, const uint8_t *rdata_payload,
    size_t rlen_payload, const uint8_t *data_decrypt, size_t len_decrypt)
{
    zapret_desync_flow flow={0}; zapret_desync_feedback value={0};
    zapret_rule_direction direction; t_lua_desync_context *ctx=NULL;
    const t_ctrack_position *pos=NULL, *rpos=NULL;
    int reference=LUA_NOREF, stack=0;
    char instance[256];
    for(;;) switch(zapret_desync_step(&flow,&value)) {
    case 1:value.ok=zapret_lua_rule_direction(ctrack,tpos,bIncoming,params.server,&direction);break;
    case 2:case 8:case 9:case 16:case 17:case 19:case 20:case 21:
        zapret_desync_report(&flow,bIncoming,l7payload,dis,len_mod_pkt,DLOG,DLOG_ERR);break;
    case 3:tpos=direction.positions;pos=direction.current;rpos=direction.opposite;stack=lua_gettop(params.L);break;
    case 4:value.functions=LIST_FIRST(&dp->lua_desync)!=NULL;break;
    case 5:
        lua_rawgeti(params.L,LUA_REGISTRYINDEX,params.ref_desync_ctx);
        ctx=luaL_checkudata(params.L,-1,"desync_ctx");lua_pop(params.L,1);break;
    case 6:value.ok=zapret_lua_context_prepare(ctx,dp,ctrack,dis,bIncoming);break;
    case 7:value.gate=lua_rules_preflight(ctx,&direction,l7payload,bIncoming,instance,sizeof(instance));break;
    case 10:{
        zapret_lua_packet_argument_input arguments={
            .profile=dp,.packet=dis,.current=pos,.opposite=rpos,.interface_in=ifin,.interface_out=ifout,
            .target4=(const uint8_t *)sdp4,.target6=(const uint8_t *)sdp6,.port=sdport,.incoming=bIncoming,
            .mark=fwmark,.piece=replay_piece,.pieces=replay_piece_count,.payload=l7payload,.protocol=l7proto,
            .reassembly_offset=reasm_offset,.reassembly=rdata_payload,.reassembly_length=rlen_payload,
            .decryption=data_decrypt,.decryption_length=len_decrypt};
        native_lua_packet_arguments(&arguments,ctrack,tpos);break;
    }
    case 11:reference=luaL_ref(params.L,LUA_REGISTRYINDEX);break;
    case 12:value.ok=native_lua_invocation(dp,pos,bIncoming,l7payload,ctrack,ctx,reference,instance,sizeof(instance),&value.verdict);break;
    case 13:lua_rawgeti(params.L,LUA_REGISTRYINDEX,reference);lua_getfield(params.L,-1,"dis");value.kind=lua_type(params.L,-1);break;
    case 14:value.ok=lua_reconstruct_dissect(params.L,-1,mod_pkt,len_mod_pkt,false,false,IPPROTO_NONE,flow.preserve);break;
    case 15:lua_pop(params.L,2);break;
    case 18:lua_pop(params.L,2);break;
    case 22:luaL_unref(params.L,LUA_REGISTRYINDEX,reference);break;
    case 23:if(stack!=lua_gettop(params.L))luaL_error(params.L,"stack guard failure");break;
    case 24:return flow.verdict;
    default:zapret_desync_report(&flow,bIncoming,l7payload,dis,len_mod_pkt,DLOG,DLOG_ERR);return VERDICT_PASS;
    }
}
