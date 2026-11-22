/* MIT. Selected native observations only; cache control and ownership are Rust. */
typedef uintptr_t (*zapret_cache_native)(uint32_t,uintptr_t,uintptr_t,uintptr_t,uintptr_t,uintptr_t);
uintptr_t zapret_cache_lifecycle(uint32_t,uintptr_t,uintptr_t,uintptr_t,uintptr_t,uintptr_t,zapret_cache_native);
_Static_assert(sizeof(time_t)==8,"Rust cache lifecycle time ABI");
static uintptr_t cache_native(uint32_t op,uintptr_t a,uintptr_t b,uintptr_t c,uintptr_t d,uintptr_t e)
{
    switch(op){
    case 1:return (uintptr_t)boottime();
    case 2:return (uintptr_t)zapret_hostfail_after((hostfail_index *)a,(uint64_t *)b);
    case 3:return zapret_hostfail_expired((hostfail_pool *)a,(time_t)b);
    case 4:zapret_hostfail_remove((hostfail_index **)a,(hostfail_pool *)b);return 0;
    case 5:return (uintptr_t)zapret_ipcache_after((ip_cache4 *)a,(uint64_t *)b,NULL,NULL);
    case 6:return zapret_ipcache_expired((ip_cache_item *)a,(time_t)b,(time_t)c);
    case 7:zapret_ipcache_remove((ip_cache4 **)a,(ip_cache_item *)b);return 0;
    case 8:return (uintptr_t)((ip_cache_item *)a)->hostname;
    case 9:free((void *)a);return 0;
    case 10:return (uintptr_t)zapret_ipcache_find((ip_cache4 *)a,(const unsigned char *)b,(size_t)c,(const char *)d);
    case 11:return (uintptr_t)zapret_ipcache_add((ip_cache4 **)a,(const unsigned char *)b,(size_t)c,(const char *)d,(time_t)e);
    case 12:zapret_ipcache_touch((ip_cache_item *)a,(time_t)b);return 0;
    case 13:return zapret_cache_purge_due((time_t)a,(time_t)b);
    default:return 0;
    }
}
void HostFailPoolPurge(hostfail_index **pool){zapret_cache_lifecycle(1,(uintptr_t)pool,0,0,0,0,cache_native);}
void HostFailPoolPurgeRateLimited(hostfail_index **pool,time_t *previous){zapret_cache_lifecycle(2,(uintptr_t)pool,(uintptr_t)previous,0,0,0,cache_native);}
void ipcacheDestroy(ip_cache *cache){zapret_cache_lifecycle(3,(uintptr_t)&cache->ipcache4,(uintptr_t)&cache->ipcache6,0,0,0,cache_native);}
ip_cache_item *ipcacheFind(ip_cache *cache,const struct in_addr *a4,const struct in6_addr *a6,const char *iface)
{return (ip_cache_item *)zapret_cache_lifecycle(4,(uintptr_t)&cache->ipcache4,(uintptr_t)&cache->ipcache6,(uintptr_t)a4,(uintptr_t)a6,(uintptr_t)iface,cache_native);}
ip_cache_item *ipcacheTouch(ip_cache *cache,const struct in_addr *a4,const struct in6_addr *a6,const char *iface)
{return (ip_cache_item *)zapret_cache_lifecycle(5,(uintptr_t)&cache->ipcache4,(uintptr_t)&cache->ipcache6,(uintptr_t)a4,(uintptr_t)a6,(uintptr_t)iface,cache_native);}
void ipcachePurgeRateLimited(ip_cache *cache,time_t lifetime)
{zapret_cache_lifecycle(6,(uintptr_t)&cache->ipcache4,(uintptr_t)&cache->ipcache6,(uintptr_t)lifetime,(uintptr_t)&ipcache_purge_prev,0,cache_native);}
