/* MIT. Rust selects lifecycle; C executes one native/VM operation per return. */
typedef struct{
    uint32_t entry,stage,status,reverse,reset,find_direction,protocol,queue_limit;
    uint32_t after_clear,after_init,after_new,after_feed;
    int32_t incoming;uint32_t tcp,udp,padding;
    uintptr_t track,element,out_track,out_reverse;
    uint64_t cursor;int64_t now,last,interval;uintptr_t result;
} zapret_conntrack_lifecycle_state;
uint32_t zapret_conntrack_lifecycle_step(zapret_conntrack_lifecycle_state *);
_Static_assert(sizeof(zapret_conntrack_lifecycle_state) == 104 + 4 * sizeof(void *) &&
    offsetof(zapret_conntrack_lifecycle_state, track) == 64 &&
    offsetof(zapret_conntrack_lifecycle_state, cursor) == 64 + 4 * sizeof(void *) &&
    offsetof(zapret_conntrack_lifecycle_state, result) == 96 + 4 * sizeof(void *),
    "Rust conntrack lifecycle ABI");
typedef struct{t_conntrack *table;const struct dissect *packet;t_conn key;zapret_conntrack_packet input;time_t interval;uint32_t syn,established,fin,udp;} conntrack_lifecycle_native;
static uintptr_t conntrack_lifecycle(zapret_conntrack_lifecycle_state *s,conntrack_lifecycle_native *c)
{
    uint32_t op;
    while((op=zapret_conntrack_lifecycle_step(s)))switch(op){
    case 1:free(((t_ctrack *)s->track)->hostname);break;
    case 2:((t_ctrack *)s->track)->hostname=NULL;((t_ctrack *)s->track)->hostname_is_ip=false;break;
    case 3:ReasmClear(&((t_ctrack *)s->track)->reasm_client);break;
    case 4:rawpacket_queue_destroy(&((t_ctrack *)s->track)->delayed);break;
    case 5:luaL_unref(params.L,LUA_REGISTRYINDEX,((t_ctrack *)s->track)->lua_state);break;
    case 6:luaL_unref(params.L,LUA_REGISTRYINDEX,((t_ctrack *)s->track)->lua_instance_cutoff);break;
    case 7:free((void *)s->element);break;
    case 8:memset((void *)s->track,0,sizeof(t_ctrack));break;
    case 9:((t_ctrack *)s->track)->lua_state=((t_ctrack *)s->track)->lua_instance_cutoff=LUA_NOREF;
        ((t_ctrack *)s->track)->l7proto=L7_UNKNOWN;((t_ctrack *)s->track)->reasm_client_payload=L7P_UNKNOWN;break;
    case 10:rawpacket_queue_init(&((t_ctrack *)s->track)->delayed,s->queue_limit);break;
    case 11:lua_newtable(params.L);break;
    case 12:((t_ctrack *)s->track)->lua_state=luaL_ref(params.L,LUA_REGISTRYINDEX);break;
    case 14:((t_ctrack *)s->track)->lua_instance_cutoff=luaL_ref(params.L,LUA_REGISTRYINDEX);break;
    case 15:c->table->timeout_syn=c->syn;c->table->timeout_established=c->established;c->table->timeout_fin=c->fin;c->table->timeout_udp=c->udp;c->table->t_purge_interval=c->interval;break;
    case 16:s->now=boottime();break;
    case 17:c->table->t_last_purge=s->now;c->table->pool=NULL;break;
    case 18:s->element=(uintptr_t)malloc(sizeof(t_conntrack_pool));break;
    case 19:((t_conntrack_pool *)s->element)->conn=c->key;break;
    case 20:s->status=zapret_conntrack_insert(&c->table->pool,&c->key,(void *)s->element);break;
    case 21:s->track=(uintptr_t)&((t_conntrack_pool *)s->element)->track;break;
    case 22:s->element=(uintptr_t)zapret_conntrack_after(c->table->pool,&s->cursor);break;
    case 23:zapret_conntrack_remove(&c->table->pool,&((t_conntrack_pool *)s->element)->conn);break;
    case 24:s->status=ConntrackExtractConn(&c->key,s->reverse,c->packet);break;
    case 25:s->element=(uintptr_t)zapret_conntrack_find(c->table->pool,&c->key,s->find_direction?&s->incoming:NULL);break;
    case 26:s->status=zapret_conntrack_start((const unsigned char *)c->packet->tcp,c->packet->udp!=NULL);break;
    case 27:c->input=(zapret_conntrack_packet){.tcp=(const unsigned char *)c->packet->tcp,.tcp_size=c->packet->len_l4,.payload_size=c->packet->len_payload,
        .ipv6_flow=c->packet->ip6?ntohl(c->packet->ip6->ip6_flow):0,.ipv6=c->packet->ip6!=NULL};break;
    case 28:s->status=zapret_conntrack_update(&((t_ctrack *)s->track)->pos,&c->input,s->reverse,s->reset);break;
    case 29:clock_gettime(CLOCK_BOOT_OR_UPTIME,&((t_ctrack *)s->track)->pos.t_last);break;
    case 30:s->status=!((t_ctrack *)s->track)->t_start.tv_sec;break;
    case 31:((t_ctrack *)s->track)->t_start=((t_ctrack *)s->track)->pos.t_last;break;
    case 32:*(t_ctrack **)s->out_track=(t_ctrack *)s->track;break;
    case 33:*(bool *)s->out_reverse=s->reverse;break;
    case 34:s->tcp=c->packet->tcp!=NULL;s->udp=c->packet->udp!=NULL;break;
    case 35:((t_ctrack *)s->track)->pos.ipproto=s->protocol;break;
    case 36:s->last=c->table->t_last_purge;s->interval=c->table->t_purge_interval;break;
    case 37:s->status=zapret_conntrack_expired(c->table,&((t_conntrack_pool *)s->element)->track.pos,
        ((t_conntrack_pool *)s->element)->conn.l4proto,((t_conntrack_pool *)s->element)->track.b_cutoff,s->now);break;
    case 38:c->table->t_last_purge=s->now;break;
    }
    return s->result;
}
void ConntrackClearHostname(t_ctrack *track){zapret_conntrack_lifecycle_state s={.entry=1,.track=(uintptr_t)track};conntrack_lifecycle_native c={0};conntrack_lifecycle(&s,&c);}
void ConntrackPoolDestroy(t_conntrack *table){zapret_conntrack_lifecycle_state s={.entry=5};conntrack_lifecycle_native c={.table=table};conntrack_lifecycle(&s,&c);}
void ConntrackPoolInit(t_conntrack *table,time_t interval,uint32_t syn,uint32_t established,uint32_t fin,uint32_t udp)
{zapret_conntrack_lifecycle_state s={.entry=6};conntrack_lifecycle_native c={.table=table,.interval=interval,.syn=syn,.established=established,.fin=fin,.udp=udp};conntrack_lifecycle(&s,&c);}
bool ConntrackPoolDoubleSearch(t_conntrack *table,const struct dissect *packet,t_ctrack **track,bool *reverse)
{zapret_conntrack_lifecycle_state s={.entry=9,.out_track=(uintptr_t)track,.out_reverse=(uintptr_t)reverse};conntrack_lifecycle_native c={.table=table,.packet=packet};return conntrack_lifecycle(&s,&c)!=0;}
bool ConntrackPoolFeed(t_conntrack *table,const struct dissect *packet,t_ctrack **track,bool *reverse)
{zapret_conntrack_lifecycle_state s={.entry=10,.out_track=(uintptr_t)track,.out_reverse=(uintptr_t)reverse};conntrack_lifecycle_native c={.table=table,.packet=packet};return conntrack_lifecycle(&s,&c)!=0;}
bool ConntrackPoolDrop(t_conntrack *table,const struct dissect *packet)
{zapret_conntrack_lifecycle_state s={.entry=11};conntrack_lifecycle_native c={.table=table,.packet=packet};return conntrack_lifecycle(&s,&c)!=0;}
void ConntrackPoolPurge(t_conntrack *table){zapret_conntrack_lifecycle_state s={.entry=12};conntrack_lifecycle_native c={.table=table};conntrack_lifecycle(&s,&c);}
