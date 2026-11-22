/* MIT. C owns engine fields, protected VM initialization and capture storage. */
typedef struct {bool daemon,pid,intercept;} zapret_boot_input;
typedef struct {
    void (*daemon)(void);
    bool (*pid)(void),(*selftest)(void),(*sandbox)(void),(*lua)(void);
    void (*idle)(void);
    bool (*network)(void);
    uint32_t (*error)(void);
    int (*capture)(void);
    void (*network_destroy)(void),(*lua_destroy)(void),(*raw_destroy)(void);
    void (*report)(uint32_t,uint32_t);
} zapret_boot_ops;
int zapret_engine_bootstrap(const zapret_boot_input *,const zapret_boot_ops *);
_Static_assert(sizeof(zapret_boot_input) == 3 && sizeof(zapret_boot_ops) == 13 * sizeof(void *) &&
    offsetof(zapret_boot_ops, report) == 12 * sizeof(void *), "Rust bootstrap ABI");
static bool native_boot_pid(void){return writepid(params.pidfile);}
static bool native_boot_selftest(void){const char *value=getenv("ZAPRET_RING_SELFTEST");return value && !strcmp(value,"1");}
static bool native_boot_network(void){return win_dark_init(&params.ssid_filter,params.ssid_filter_neg,&params.nlm_filter,params.nlm_filter_neg);}
static uint32_t native_boot_error(void){return w_win32_error;}
static int native_boot_capture(void){WINDIVERT_ADDRESS addresses[ZAPRET_CAPTURE_ADDRESS_COUNT];return zapret_capture_loop(&capture_ops,addresses,params.intercept);}
static void native_boot_report(uint32_t event,uint32_t error)
{if(!event)DLOG_ERR("could not write pidfile");else DLOG_ERR("win_dark_init failed. win32 error %u (0x%08X)\n",error,error);}
static int win_main(void)
{
    const zapret_boot_input input={params.daemon,*params.pidfile!=0,params.intercept};
    static const zapret_boot_ops ops={daemonize,native_boot_pid,native_boot_selftest,win_sandbox,lua_init,NoInterceptLoop,native_boot_network,native_boot_error,native_boot_capture,win_dark_deinit,lua_shutdown,rawsend_cleanup,native_boot_report};
    return zapret_engine_bootstrap(&input,&ops);
}
