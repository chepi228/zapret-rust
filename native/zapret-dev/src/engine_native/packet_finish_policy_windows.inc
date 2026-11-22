/* MIT. Finish profile selection and packet verdict after resource-free Rust steps. */
#include "desync_policy_abi.h"
static uint8_t packet_play_finish(struct play_state *ps, const struct packet_play_call *call,
    zapret_play_payload tcp, zapret_play_payload decrypted)
{
    const zapret_payload_input *in=call->input;
    zapret_play_finish_flow flow={0};zapret_play_finish_feedback value={0};
    for(;;)switch(zapret_play_finish_step(&flow,&value)) {
    case 1:value.found=dp_rediscovery(ps);break;
    case 2:
        ps->verdict=desync(ps->dp,in->mark,in->ifin,in->ifout,ps->bReverseFixed,
            ps->ctrack_replay,call->positions,ps->l7payload,ps->l7proto,ps->dis,
            ps->sdip4,ps->sdip6,ps->sdport,call->modified,call->modified_length,
            call->replay_piece,call->replay_count,call->reasm_offset,tcp.data,tcp.length,
            decrypted.data,decrypted.length);break;
    case 3:reasm_client_cancel(ps->ctrack);break;
    case 4:value.verdict=ps->verdict;value.incoming=ps->bReverseFixed;break;
    case 5:value.verdict=ct_new_postnat_fix(ps->ctrack,ps->dis,call->modified,call->modified_length);break;
    case 6:return flow.verdict;
    case 8:value.tcp=ps->dis->tcp!=NULL;break;
    default:DLOG_ERR("invalid final packet play policy\n");return VERDICT_PASS;
    }
}
