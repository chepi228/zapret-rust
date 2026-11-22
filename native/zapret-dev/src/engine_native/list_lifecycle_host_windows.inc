/* MIT. The Rust policy owns insertion failure destruction. */
#include "list_lifecycle_windows.h"
static uintptr_t list_host_native(uint32_t op,uintptr_t a,uintptr_t b,uintptr_t c,uintptr_t d,uintptr_t e)
{(void)e;switch(op){case 5:return HostlistPoolAddStrLen((hostlist_pool **)a,(const char *)b,(size_t)c,(uint32_t)d);case 6:HostlistPoolDestroy((hostlist_pool **)a);return 0;default:return 0;}}
static int insert_host(void *context,const unsigned char *token,size_t length,uint32_t flags)
{return (int)(intptr_t)zapret_list_lifecycle(2,(uintptr_t)context,(uintptr_t)token,length,flags,0,list_host_native);}
