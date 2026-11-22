/* MIT. Bind main's existing parser storage to Rust's routing policy. */
#include "engine_entry_abi.h"
typedef struct{
    int index;char *text;native_profile_flow *flow;
    struct desync_profile_list **entry;struct desync_profile **profile;
    struct zapret_list_file **anonymous[4];uint64_t *payload;
    struct packet_range *incoming,*outgoing;bool *dry;zapret_capture_cli *capture;
}native_engine_cli;
_Static_assert(sizeof(native_engine_cli) == 14 * sizeof(void *) &&
    offsetof(native_engine_cli, anonymous) == 5 * sizeof(void *) &&
    offsetof(native_engine_cli, capture) == 13 * sizeof(void *),
    "Rust main CLI adapter layout");
static int32_t native_engine_option_category(void *context,uint32_t category)
{
    native_engine_cli *state=context;
    switch(category){
        case 0:return engine_numeric_option(state->index,state->text,*state->profile);
        case 1:return engine_startup_option(state->index,state->text);
        case 2:return engine_list_option(state->index,state->text,*state->profile,state->flow->skip,
            state->anonymous[0],state->anonymous[1],state->anonymous[2],state->anonymous[3]);
        case 3:return engine_profile_filter(state->index,state->text,*state->profile,state->payload,state->incoming,state->outgoing);
        case 4:return engine_capture_option(state->index,state->text,state->capture);
        case 5:return engine_control_option(state->index,state->text,state->flow,state->entry,state->profile,
            state->anonymous[0],state->anonymous[1],state->anonymous[2],state->anonymous[3],state->payload,state->incoming,state->outgoing,state->dry);
        default:return 0;
    }
}
static const char *native_engine_option_text(const void *context, uint32_t field)
{
    const native_engine_cli *state = context;
    switch (field) {
        case ENTRY_READ_OPTION_NAME: return long_options[state->index].name;
        case ENTRY_READ_PROFILE_NAME: return (*state->profile)->name;
        case ENTRY_READ_ARGUMENT: return state->text;
        default: return NULL;
    }
}
static bool native_engine_apply_option_result(native_engine_cli *state, zapret_engine_route route)
{
    zapret_engine_route_result result = zapret_engine_route_effect(route, state->index, state,
        native_engine_option_text, DLOG_ERR);
    if (result.terminate) exit_clean(result.exit_code);
    return result.handled;
}
static int native_engine_finish(native_profile_flow *profiles,struct desync_profile *profile,zapret_capture_cli *capture,
    bool *dry,int *argc,char ***argv)
{
    zapret_engine_finish flow={0};zapret_engine_finish_feedback feedback={0};HANDLE mutex=NULL;
    for(;;)switch(zapret_engine_finish_step(&flow,&feedback)){
        case FINISH_PROFILE:feedback.status=native_profile_finish(profiles);break;
        case FINISH_PROFILE_ERROR:native_profile_exit(feedback.status,profile->name);break;
        case FINISH_ARGUMENTS:cleanup_args(&params);*argv=NULL;*argc=0;break;
        case FINISH_VALIDATE:feedback.status=native_startup_validate(profiles->count,profiles->template_count)?0:1;break;
        case FINISH_CAPTURE:{
            zapret_capture_prepare_result prepared=native_capture_prepare(*capture->index,*capture->sub_index,*capture->ipv4,*capture->ipv6,
                *capture->lan,*capture->loopback,*capture->empty,*capture->duplicate,*dry,capture->save,capture->hashes,&mutex);
            feedback.status=prepared.status;break;
        }
        case FINISH_LIFECYCLE:feedback.status=native_lifecycle_prepare(*dry);break;
        case FINISH_RUN:feedback.result=win_main();break;
        case FINISH_CLEANUP:cleanup_params(&params);break;
        case FINISH_MUTEX:native_lifecycle_release_mutex(&mutex);break;
        case FINISH_STDIO:close_std();break;
        case FINISH_RETURN:return flow.result;
        case FINISH_EXIT_SUCCESS:exit_clean(0);break;
        case FINISH_EXIT_ERROR:exit_clean(1);break;
        default:DLOG_ERR("invalid main finish state\n");exit_clean(1);break;
    }
}
