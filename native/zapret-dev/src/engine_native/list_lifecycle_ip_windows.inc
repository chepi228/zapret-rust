/* MIT. Rust owns token truncation, parse precedence and teardown selection. */
#include "list_lifecycle_windows.h"
typedef struct{ipset *pool;struct cidr4 ipv4;struct cidr6 ipv6;} list_ip_native_context;
static uintptr_t list_ip_native(uint32_t op,uintptr_t a,uintptr_t b,uintptr_t c,uintptr_t d,uintptr_t e)
{(void)d;(void)e;list_ip_native_context *n=(list_ip_native_context *)a;switch(op){
case 7:return parse_cidr4((char *)b,&n->ipv4);case 8:return ipset4AddCidr(&n->pool->ips4,&n->ipv4);
case 9:return parse_cidr6((char *)b,&n->ipv6);case 10:return ipset6AddCidr(&n->pool->ips6,&n->ipv6);
case 11:DLOG_ERR((const char *)c,(const char *)b);return 0;case 12:ipsetDestroy(n->pool);return 0;default:return 0;}}
static int insert_ip(void *context,const unsigned char *token,size_t length,uint32_t flags)
{(void)flags;list_ip_native_context n={.pool=context};return (int)(intptr_t)zapret_list_lifecycle(3,(uintptr_t)&n,(uintptr_t)token,length,0,0,list_ip_native);}
