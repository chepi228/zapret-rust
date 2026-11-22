/* MIT. Main state addresses and diagnostics; the VM runs outside these calls. */
#include "runtime_log_windows.h"

typedef struct{void *pool;uint32_t timeouts[4],lifetime;bool dry,disabled;}zapret_lifecycle_input;
typedef struct {void (*init)(void *,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t);zapret_log_sink debug,console;} zapret_lifecycle_main_ops;
uint32_t zapret_lifecycle_prepare(const zapret_lifecycle_input *,const zapret_lifecycle_main_ops *);
typedef struct{bool(*release)(void *);void(*close)(void *);}zapret_lifecycle_mutex_ops;
bool zapret_lifecycle_release_mutex(void **,const zapret_lifecycle_mutex_ops *);
_Static_assert(sizeof(zapret_lifecycle_input) == sizeof(void *) + 24 &&
    sizeof(zapret_lifecycle_main_ops) == 3 * sizeof(void *) &&
    sizeof(zapret_lifecycle_mutex_ops) == 2 * sizeof(void *), "Rust main lifecycle ABI");
static void native_lifecycle_conntrack(void *pool,uint32_t bins,uint32_t syn,uint32_t established,uint32_t fin,uint32_t udp){ConntrackPoolInit(pool,bins,syn,established,fin,udp);}
static uint32_t native_lifecycle_prepare(bool dry)
{
    const zapret_lifecycle_input input = {&params.conntrack,
        {params.ctrack_t_syn,params.ctrack_t_est,params.ctrack_t_fin,params.ctrack_t_udp},
        params.ipcache_lifetime,dry,params.ctrack_disable};
    static const zapret_lifecycle_main_ops ops = {native_lifecycle_conntrack,DLOG,DLOG_CONDUP};
    uint32_t status = zapret_lifecycle_prepare(&input,&ops);
    if (status == 1) DLOG_ERR("invalid main lifecycle state\n");
    return status;
}
static bool native_lifecycle_mutex_release(void *handle){return ReleaseMutex(handle)!=0;}
static void native_lifecycle_mutex_close(void *handle){CloseHandle(handle);}
static void native_lifecycle_release_mutex(HANDLE *handle){static const zapret_lifecycle_mutex_ops ops={native_lifecycle_mutex_release,native_lifecycle_mutex_close};if(!zapret_lifecycle_release_mutex(handle,&ops))abort();}
