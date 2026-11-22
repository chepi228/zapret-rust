/* MIT. Each selected VM call runs after the Rust step has returned. */
#include "timer_lifecycle_windows.h"
uint32_t zapret_timer_lifecycle_step(zapret_timer_lifecycle_state *);
static uint64_t timer_lifecycle(uint32_t entry,timer_pool **pool,bool *dirty,uint64_t now)
{
    zapret_timer_lifecycle_state state={.entry=entry,.now=now};uint32_t op;
    while((op=zapret_timer_lifecycle_step(&state)))switch(op){
    case 1:state.now=boottime_ms();break;
    case 2:*dirty=false;break;
    case 3:state.status=zapret_timer_due(*pool,state.after,state.now,&state.info);break;
    case 4:state.status=run_timer(&state.info);break;
    case 5:state.status=zapret_timer_finish(pool,state.info.id,state.now,state.succeeded,&state.removed);break;
    case 6:lua_rawgeti(params.L,LUA_REGISTRYINDEX,state.removed.name_ref);break;
    case 7:{
        zapret_lua_timer_log report=zapret_lua_timer_report(true,state.succeeded!=0);
        DLOG(report.format,lua_tostring(params.L,-1),report.reason);break;
    }
    case 8:lua_pop(params.L,1);break;
    case 9:zapret_timer_unref(&state.removed);break;
    case 10:state.status=*dirty;break;
    case 11:state.output=zapret_timer_next(*pool);break;
    case 12:state.status=zapret_timer_after(*pool,0,&state.info);break;
    case 13:state.status=zapret_timer_remove(pool,state.info.id,&state.info);break;
    case 14:zapret_timer_unref(&state.info);break;
    }
    return state.output;
}
void TimerPoolDestroy(timer_pool **pool){timer_lifecycle(1,pool,NULL,0);}
uint64_t TimerPoolNext(const timer_pool *pool,bool *dirty){timer_pool *borrowed=(timer_pool *)pool;return timer_lifecycle(2,&borrowed,dirty,0);}
uint64_t TimerPoolRun(timer_pool **pool,bool *dirty,uint64_t now){return timer_lifecycle(3,pool,dirty,now);}
