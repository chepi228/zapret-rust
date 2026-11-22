/* MIT. Rust preserves yield/quit/network short-circuit between native observations. */
typedef struct {uint32_t phase,status;} zapret_capture_poll_flow;
typedef struct {bool quitting,network;} zapret_capture_poll_feedback;
uint32_t zapret_capture_poll_step(zapret_capture_poll_flow *,const zapret_capture_poll_feedback *);
static uint32_t receive_poll(void)
{
    zapret_capture_poll_flow flow={0};zapret_capture_poll_feedback value={0};
    for(;;)switch(zapret_capture_poll_step(&flow,&value)) {
    case 1:usleep(0);break;
    case 2:value.quitting=bQuit;break;
    case 3:value.network=logical_net_filter_match_rate_limited();break;
    case 4:return flow.status;
    default:return ZAPRET_QUIT;
    }
}
