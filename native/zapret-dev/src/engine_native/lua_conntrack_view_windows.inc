/* MIT. Rust computes connection views; C alone constructs Lua VM objects. */
typedef struct {
    int64_t counters[3], tcp[10];
    uint32_t ipv6_flow;
    bool is_tcp, over_2g;
} zapret_lua_track_position_values;
typedef struct {
    zapret_lua_track_position_values positions[2];
    const char *hostname, *protocol;
    double started, elapsed;
    int32_t lua_state;
    uint8_t incoming_ttl;
    bool hostname_is_ip, incoming_cutoff, outgoing_cutoff, direct_is_server;
} zapret_lua_track_values;
bool zapret_lua_track_position(const t_ctrack *, const t_ctrack_position *, zapret_lua_track_position_values *);
uint32_t zapret_lua_track_view(const t_ctrack *, const t_ctrack_positions *, bool, bool, zapret_lua_track_values *);
_Static_assert(sizeof(zapret_lua_track_position_values)==112 && sizeof(zapret_lua_track_values)==272 &&
    offsetof(zapret_lua_track_values,hostname)==224 && offsetof(zapret_lua_track_values,lua_state)==256 &&
    offsetof(zapret_lua_track_values,direct_is_server)==264, "Rust Lua connection view ABI");
#define TRACK_OFFSET(field,offset) _Static_assert(offsetof(t_ctrack,field)==offset,"Rust Lua track ABI: " #field)
TRACK_OFFSET(t_start,8);TRACK_OFFSET(pos,24);TRACK_OFFSET(dp,184);
TRACK_OFFSET(incoming_ttl,195);TRACK_OFFSET(b_lua_in_cutoff,197);TRACK_OFFSET(b_lua_out_cutoff,198);
TRACK_OFFSET(l7proto,200);TRACK_OFFSET(hostname,208);TRACK_OFFSET(hostname_is_ip,216);TRACK_OFFSET(lua_state,220);
#undef TRACK_OFFSET
#define POSITION_OFFSET(field,offset) _Static_assert(offsetof(t_ctrack_position,field)==offset,"Rust Lua position ABI: " #field)
POSITION_OFFSET(pcounter,0);POSITION_OFFSET(pdcounter,8);POSITION_OFFSET(pbcounter,16);POSITION_OFFSET(ip6flow,24);
POSITION_OFFSET(pos,28);POSITION_OFFSET(uppos,32);POSITION_OFFSET(uppos_prev,36);POSITION_OFFSET(seq_last,40);
POSITION_OFFSET(seq0,44);POSITION_OFFSET(winsize,48);POSITION_OFFSET(mss,50);POSITION_OFFSET(winsize_calc,52);
POSITION_OFFSET(scale,56);POSITION_OFFSET(rseq_over_2G,57);
#undef POSITION_OFFSET
_Static_assert(sizeof(struct timespec)==16 && offsetof(struct timespec,tv_sec)==0 &&
    offsetof(struct timespec,tv_nsec)==8 && sizeof(((struct timespec *)0)->tv_nsec)==4 &&
    sizeof(t_ctrack_positions)==160 && offsetof(t_ctrack_positions,t_last)==0 &&
    offsetof(t_ctrack_positions,client)==24 && offsetof(t_ctrack_positions,server)==88 &&
    offsetof(t_ctrack_positions,ipproto)==152, "Rust Lua timestamp and positions ABI");

static void native_lua_push_track_position(lua_State *L,const zapret_lua_track_position_values *view)
{
    LUA_STACK_GUARD_ENTER(L)
    static const char *counters[]={"pcounter","pdcounter","pbcounter"};
    static const char *tcp[]={"seq0","seq","rseq","pos","uppos","uppos_prev","winsize","winsize_calc","scale","mss"};
    for(unsigned i=0;i<3;++i)lua_pushf_lint(L,counters[i],view->counters[i]);
    if(view->ipv6_flow)lua_pushf_int(L,"ip6_flow",view->ipv6_flow);
    if(view->is_tcp){
        lua_pushliteral(L,"tcp");lua_createtable(L,0,11);
        for(unsigned i=0;i<10;++i){
            lua_pushf_lint(L,tcp[i],view->tcp[i]);
            if(i==2)lua_pushf_bool(L,"rseq_over_2G",view->over_2g);
        }
        lua_rawset(L,-3);
    }
    LUA_STACK_GUARD_LEAVE(L,0)
}
void lua_pushf_ctrack_pos(lua_State *L,const t_ctrack *track,const t_ctrack_position *position)
{
    zapret_lua_track_position_values view;
    if(!zapret_lua_track_position(track,position,&view)){luaL_error(L,"invalid connection position view");return;}
    native_lua_push_track_position(L,&view);
}
void lua_push_ctrack(lua_State *L,const t_ctrack *track,const t_ctrack_positions *positions,bool incoming)
{
    LUA_STACK_GUARD_ENTER(L)
    zapret_lua_track_values view;
    uint32_t status=zapret_lua_track_view(track,positions,incoming,params.server,&view);
    if(status==0)lua_pushnil(L);
    else if(status!=1){luaL_error(L,"invalid connection view");return;}
    else{
        lua_createtable(L,0,9);
        if(view.incoming_ttl)lua_pushf_int(L,"incoming_ttl",view.incoming_ttl);
        lua_pushf_str(L,"l7proto",view.protocol);lua_pushf_str(L,"hostname",view.hostname);
        if(view.hostname)lua_pushf_bool(L,"hostname_is_ip",view.hostname_is_ip);
        lua_pushf_reg(L,"lua_state",view.lua_state);
        lua_pushf_bool(L,"lua_in_cutoff",view.incoming_cutoff);lua_pushf_bool(L,"lua_out_cutoff",view.outgoing_cutoff);
        lua_pushf_number(L,"t_start",view.started);
        lua_pushliteral(L,"pos");lua_createtable(L,0,5);lua_pushf_number(L,"dt",view.elapsed);
        lua_pushliteral(L,"client");lua_newtable(L);native_lua_push_track_position(L,&view.positions[0]);lua_rawset(L,-3);
        lua_pushliteral(L,"server");lua_newtable(L);native_lua_push_track_position(L,&view.positions[1]);lua_rawset(L,-3);
        lua_pushliteral(L,"direct");lua_getfield(L,-2,view.direct_is_server?"server":"client");lua_rawset(L,-3);
        lua_pushliteral(L,"reverse");lua_getfield(L,-2,view.direct_is_server?"client":"server");lua_rawset(L,-3);
        lua_rawset(L,-3);
    }
    LUA_STACK_GUARD_LEAVE(L,1)
}
