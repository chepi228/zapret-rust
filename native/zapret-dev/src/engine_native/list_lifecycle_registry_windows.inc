/* MIT. Optional path resolution and registration ordering are Rust policy. */
#include "list_lifecycle_windows.h"
static uintptr_t list_registry_native(uint32_t op,uintptr_t a,uintptr_t b,uintptr_t c,uintptr_t d,uintptr_t e)
{(void)d;(void)e;switch(op){case 13:return (uintptr_t)realpath((const char *)a,(char *)b);case 14:return (uintptr_t)zapret_list_register((struct zapret_list_files **)a,(struct zapret_list_collection **)b,(const char *)c);default:return 0;}}
struct zapret_list_file *zapret_list_register_path(struct zapret_list_files **files,struct zapret_list_collection **collection,const char *filename)
{return (struct zapret_list_file *)zapret_list_lifecycle(4,(uintptr_t)files,(uintptr_t)collection,(uintptr_t)filename,0,0,list_registry_native);}
