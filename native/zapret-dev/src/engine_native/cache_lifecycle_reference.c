/* MIT. Complete pre-lifecycle facade over the same Rust index owner. */
#include "cache_fixture.h"
#include "helpers.h"
#define printf cache_oracle_printf
#include "cache_lifecycle_before.inc"
void *reference_fail_create(void){return calloc(1,sizeof(hostfail_index *));}
void *reference_fail_add(void *root,const char *name,int timeout){return HostFailPoolAdd(root,name,timeout);}
void *reference_fail_find(void *root,const char *name){return HostFailPoolFind(*(hostfail_index **)root,name);}
void reference_fail_read(void *value,cache_fail_view *view){hostfail_pool *p=value;view->name=p->str;view->counter=p->counter;view->expires=p->expire;}
void reference_fail_increment(void *value){++((hostfail_pool *)value)->counter;}
void reference_fail_set_counter(void *value,int counter){((hostfail_pool *)value)->counter=counter;}
void reference_fail_delete(void *root,void *entry){HostFailPoolDel(root,entry);}
void reference_fail_purge(void *root,time_t *previous,bool limited){if(limited)HostFailPoolPurgeRateLimited(root,previous);else HostFailPoolPurge(root);}
void reference_fail_destroy(void *root){HostFailPoolDestroy(root);}
void reference_fail_dump(void *root){HostFailPoolDump(*(hostfail_index **)root);}
void *reference_fail_after(void *root,size_t *cursor){return zapret_hostfail_after(*(hostfail_index **)root,(uint64_t *)cursor);}
void *reference_ip_create(void){return calloc(1,sizeof(ip_cache));}
ip_cache_item *reference_ip_touch(void *root,const struct in_addr *a4,const struct in6_addr *a6,const char *iface){return ipcacheTouch(root,a4,a6,iface);}
ip_cache_item *reference_ip_find(void *root,const struct in_addr *a4,const struct in6_addr *a6,const char *iface){return ipcacheFind(root,a4,a6,iface);}
void reference_ip_purge(void *root,time_t lifetime){ipcachePurgeRateLimited(root,lifetime);}
void reference_ip_destroy(void *root){ipcacheDestroy(root);}
void reference_ip_dump(void *root){ipcachePrint(root);}
ip_cache_item *reference_ip_after(void *root,bool ipv6,size_t *cursor,unsigned char *address,unsigned char *iface)
{ip_cache *cache=root;return zapret_ipcache_after(ipv6?cache->ipcache6:cache->ipcache4,(uint64_t *)cursor,address,iface);}
