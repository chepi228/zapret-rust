/* MIT. Rust chooses phases and diagnostics; Lua calls stay on the C stack. */
#include "lua_invocation_abi.h"
void zapret_lua_rule_range_report(const zapret_rule_cursor *, const zapret_rule_step *,
    const char *, zapret_log_sink);
void zapret_lua_rule_payload_report(const zapret_rule_cursor *, const zapret_rule_step *,
    const char *, zapret_log_sink);
void zapret_lua_report_missing_function(const char *, zapret_log_sink);
static bool native_lua_invocation(struct desync_profile *profile,const t_ctrack_position *position,
    bool incoming,t_l7payload payload,t_ctrack *track,t_lua_desync_context *ctx,int reference,
    char *instance,size_t capacity,uint8_t *verdict)
{
    zapret_rule_cursor cursor=lua_rule_cursor(profile,position,incoming,payload);
    zapret_rule_step step;struct func_list *func=NULL;
    zapret_lua_invocation_flow flow={.verdict=*verdict};zapret_lua_invocation_feedback feedback={0};
    for(;;)switch(zapret_lua_invocation_step(&flow,&feedback)){
        case LUA_INVOKE_NEXT:
            feedback.available=zapret_lua_invoke_next(&cursor,&step,!track && !params.debug);
            if(feedback.available){feedback.in_range=step.in_range;feedback.payload=step.accepts_payload;}
            break;
        case LUA_INVOKE_INSTANCE:func=step.rule;lua_rule_instance(ctx,&step,instance,capacity);break;
        case LUA_INVOKE_CUTOFF:feedback.cutoff=lua_instance_cutoff_check(params.L,ctx,incoming);break;
        case LUA_INVOKE_RANGE:zapret_lua_rule_range_report(&cursor,&step,instance,DLOG);break;
        case LUA_INVOKE_PAYLOAD:zapret_lua_rule_payload_report(&cursor,&step,instance,DLOG);break;
        case LUA_INVOKE_LOOKUP:
            lua_getglobal(params.L,func->func);feedback.function=lua_isfunction(params.L,-1);
            if(!feedback.function){lua_pop(params.L,1);zapret_lua_report_missing_function(func->func,DLOG_ERR);}break;
        case LUA_INVOKE_ARGUMENTS:
            lua_rawgeti(params.L,LUA_REGISTRYINDEX,params.ref_desync_ctx);lua_rawgeti(params.L,LUA_REGISTRYINDEX,reference);
            feedback.args=lua_pushf_args(params.L,&func->args,-1,true);if(!feedback.args)lua_pop(params.L,3);break;
        case LUA_INVOKE_IDENTITY:
            lua_pushf_str(params.L,"func",func->func);lua_pushf_int(params.L,"func_n",ctx->func_n);lua_pushf_str(params.L,"func_instance",instance);break;
        case LUA_INVOKE_CALL:
            zapret_lua_context_active(ctx,true);
            feedback.call=lua_pcall(params.L,2,LUA_MULTRET,0)==0;
            zapret_lua_context_active(ctx,false);break;
        case LUA_INVOKE_CALL_ERROR:lua_dlog_error();break;
        case LUA_INVOKE_RESULT:feedback.result=desync_get_result(&feedback.verdict);break;
        case LUA_INVOKE_CANCEL:feedback.cancelled=zapret_lua_context_cancelled(ctx);break;
        case LUA_INVOKE_DONE:*verdict=flow.verdict;return true;
        case LUA_INVOKE_FAILED:return false;
        default:DLOG_ERR("invalid Lua invocation state\n");return false;
    }
}
