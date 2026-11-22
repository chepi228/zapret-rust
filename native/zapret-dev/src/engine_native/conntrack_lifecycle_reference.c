/* MIT. Complete old facade using the same Rust index and packet core. */
#include "conntrack_fixture.h"
#define clock_gettime fixture_clock_gettime
#include "conntrack_lifecycle_before.inc"
void *reference_create(time_t interval,uint32_t syn,uint32_t est,uint32_t fin,uint32_t udp)
{t_conntrack *t=calloc(1,sizeof(*t));if(!t)abort();ConntrackPoolInit(t,interval,syn,est,fin,udp);return t;}
void reference_destroy(void *table){ConntrackPoolDestroy(table);}
bool reference_feed(void *table,const struct dissect *p,t_ctrack **track,bool *reverse){return ConntrackPoolFeed(table,p,track,reverse);}
bool reference_search(void *table,const struct dissect *p,t_ctrack **track,bool *reverse){return ConntrackPoolDoubleSearch(table,p,track,reverse);}
bool reference_drop(void *table,const struct dissect *p){return ConntrackPoolDrop(table,p);}
void reference_purge(void *table){ConntrackPoolPurge(table);}
t_ctrack *reference_after(void *table,size_t *cursor,t_conn *key)
{t_conntrack_pool *e=zapret_conntrack_after(((t_conntrack *)table)->pool,(uint64_t *)cursor);if(!e)return NULL;*key=e->conn;return &e->track;}
time_t reference_last_purge(void *table){return ((t_conntrack *)table)->t_last_purge;}
bool reference_ReasmInit(t_reassemble *r,size_t size,uint32_t seq){return ReasmInit(r,size,seq);}
void reference_ReasmClear(t_reassemble *r){ReasmClear(r);}
bool reference_ReasmFeed(t_reassemble *r,uint32_t seq,const void *p,size_t size){return ReasmFeed(r,seq,p,size);}
bool reference_ReasmHasSpace(t_reassemble *r,size_t size){return ReasmHasSpace(r,size);}
