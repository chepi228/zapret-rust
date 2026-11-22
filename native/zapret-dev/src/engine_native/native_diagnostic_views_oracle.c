/* MIT. Original and Rust presenters against actual Windows layouts. */
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "params.h"
#include "hostlist.h"
#include "ipset.h"
#undef main
static unsigned cases;
#define CHECK(c)do{if(!(c)){fprintf(stderr,"FAIL native_diagnostic_views case=%u line=%d: %s\n",cases,__LINE__,#c);exit(1);}}while(0)
struct fixture{struct params_s fields;struct desync_profile_list profiles[3],templates[2];struct blob_item blobs[2];struct func_list rules[2];struct str2_list arguments[3];char names[5][32];unsigned calls,mutation;size_t used;unsigned char trace[131072];};
static struct fixture fixtures[2],*active;
#define params (active->fields)
static void append(const void *bytes,size_t size){CHECK(size<=sizeof(active->trace)-active->used);memcpy(active->trace+active->used,bytes,size);active->used+=size;}
static void mutate(const char *format){if(active->mutation==3&&!strcmp(format,",")){active->arguments[1].str1="after-comma";return;}if(active->mutation==5&&!strcmp(format," %s")){active->rules[0].payload_type=(1ULL<<0)|(1ULL<<30);return;}if(active->calls!=1)return;switch(active->mutation){case 1:active->profiles[0].dp.name="changed-profile";break;case 2:active->profiles[0].next.le_next=NULL;break;case 4:active->blobs[0].next.le_next=NULL;break;case 6:CHECK(zapret_list_register(&params.hostlists,&active->profiles[1].dp.hl_collection,"late-file"));break;default:break;}}
static int capture(const char *format,...){char bytes[32768];va_list args;va_start(args,format);int size=vsnprintf(bytes,sizeof(bytes),format,args);va_end(args);CHECK(size>=0&&(size_t)size<sizeof(bytes));uint32_t length=(uint32_t)strlen(format);append(&length,sizeof(length));append(format,length);length=(uint32_t)size;append(&length,sizeof(length));append(bytes,(size_t)size);++active->calls;mutate(format);return size;}
static const char *payload(t_l7payload index){uint32_t marker=0xf0000000u|index;append(&marker,sizeof(marker));return l7payload_str(index);}
#define l7payload_str payload
#define DLOG capture
#define DLOG_ERR capture
#define DLOG_CONDUP capture
#define HostlistsDebugProfile reference_HostlistsDebugProfile
#define HostlistsDebug reference_HostlistsDebug
#define dbg_ipset_fill reference_dbg_ipset_fill
#define IpsetsDebugProfile reference_IpsetsDebugProfile
#define IpsetsDebug reference_IpsetsDebug
#define BlobDebug reference_BlobDebug
#define LuaDesyncDebug reference_LuaDesyncDebug
#include "native_diagnostic_reference.inc"
#undef HostlistsDebugProfile
#undef HostlistsDebug
#undef dbg_ipset_fill
#undef IpsetsDebugProfile
#undef IpsetsDebug
#undef BlobDebug
#undef LuaDesyncDebug
#include "native_host_diagnostics_windows.inc"
#include "native_ip_diagnostics_windows.inc"
#include "native_collection_diagnostics_windows.inc"
static void populate(struct desync_profile *profile,unsigned number,unsigned variant){profile->n=number;profile->name=(variant%3==0)?NULL:(variant%3==1)?"":"named-profile";struct zapret_list_file *file;
file=zapret_list_register(&params.hostlists,&profile->hl_collection,"host-A");CHECK(file);file->hostlist=(hostlist_pool *)(uintptr_t)(variant&1);
file=zapret_list_register(&params.hostlists,&profile->hl_collection,NULL);CHECK(file);file->hostlist=(hostlist_pool *)(uintptr_t)(variant&2);
file=zapret_list_register(&params.hostlists,&profile->hl_collection,"host-B");CHECK(file);profile->hostlist_auto=(variant&4)?file:NULL;
file=zapret_list_register(&params.hostlists,&profile->hl_collection_exclude,"host-X");CHECK(file);file->hostlist=(hostlist_pool *)(uintptr_t)(variant&1);
file=zapret_list_register(&params.ipsets,&profile->ips_collection,"ip-A");CHECK(file);file->ipset.ips4=(struct zapret_ip_pool *)(uintptr_t)(variant&1);file->ipset.ips6=(struct zapret_ip_pool *)(uintptr_t)(variant&2);
file=zapret_list_register(&params.ipsets,&profile->ips_collection,NULL);CHECK(file);file->ipset.ips4=(struct zapret_ip_pool *)(uintptr_t)(variant&2);file->ipset.ips6=(struct zapret_ip_pool *)(uintptr_t)(variant&1);
file=zapret_list_register(&params.ipsets,&profile->ips_collection_exclude,"ip-X");CHECK(file);file->ipset.ips4=NULL;file->ipset.ips6=(struct zapret_ip_pool *)(uintptr_t)(variant&1);
}
static void initial(struct fixture *value,bool debug,unsigned variant,unsigned mutation){memset(value,0,sizeof(*value));active=value;value->mutation=mutation;params.debug=debug;params.desync_profiles.lh_first=&value->profiles[0];params.desync_templates.lh_first=&value->templates[0];
for(unsigned i=0;i<3;i++){populate(&value->profiles[i].dp,UINT32_MAX-i,variant+i);value->profiles[i].next.le_next=i<2?&value->profiles[i+1]:NULL;}
for(unsigned i=0;i<2;i++){populate(&value->templates[i].dp,i,variant+i+1);value->templates[i].next.le_next=i<1?&value->templates[i+1]:NULL;}
params.blobs.lh_first=&value->blobs[0];for(unsigned i=0;i<2;i++){value->blobs[i].name=i?"blob-2":"blob-1";value->blobs[i].size=i?SIZE_MAX:0;value->blobs[i].size_buf=i?SIZE_MAX-1:128;value->blobs[i].next.le_next=i?NULL:&value->blobs[1];}
value->arguments[0]=(struct str2_list){.str1="one",.str2="value"};value->arguments[1]=(struct str2_list){.str1="before-comma",.str2=NULL};value->arguments[2]=(struct str2_list){.str1="three",.str2=""};value->arguments[0].next.le_next=&value->arguments[1];value->arguments[1].next.le_next=&value->arguments[2];
value->profiles[0].dp.lua_desync.lh_first=&value->rules[0];for(unsigned i=0;i<2;i++){value->rules[i].func=i?"next-handler":"first-handler";value->rules[i].payload_type=variant&1?(1ULL<<0)|(1ULL<<4):0;value->rules[i].range_in=(struct packet_range){{'n',UINT32_MAX},{'p',4},(variant&2)!=0};value->rules[i].range_out=(struct packet_range){{'a',0},{'s',0},(variant&4)!=0};value->rules[i].args.lh_first=i?NULL:&value->arguments[0];value->rules[i].next.le_next=i?NULL:&value->rules[1];}}
static void clear_registry(struct zapret_list_files **registry){struct zapret_list_file *file;for(size_t i=0;(file=zapret_list_files_at(*registry,i));i++){file->hostlist=NULL;file->ipset.ips4=file->ipset.ips6=NULL;}zapret_list_files_destroy(registry);}
static void cleanup(struct fixture *value){for(unsigned group=0;group<2;group++)for(unsigned i=0;i<(group?2u:3u);i++){struct desync_profile *profile=group?&value->templates[i].dp:&value->profiles[i].dp;zapret_list_collection_destroy(&profile->hl_collection);zapret_list_collection_destroy(&profile->hl_collection_exclude);zapret_list_collection_destroy(&profile->ips_collection);zapret_list_collection_destroy(&profile->ips_collection_exclude);}clear_registry(&value->fields.hostlists);clear_registry(&value->fields.ipsets);}
static void run(bool rust,unsigned entry){switch(entry){case 0:if(rust)HostlistsDebug();else reference_HostlistsDebug();break;case 1:if(rust)zapret_native_list_profile_debug(&active->profiles[0].dp,"entity",false,DLOG);else reference_HostlistsDebugProfile(&active->profiles[0].dp,"entity");break;case 2:if(rust)IpsetsDebug();else reference_IpsetsDebug();break;case 3:if(rust)IpsetsDebugProfile(&active->profiles[0].dp,"entity");else reference_IpsetsDebugProfile(&active->profiles[0].dp,"entity");break;case 4:if(rust)BlobDebug();else reference_BlobDebug();break;case 5:if(rust)LuaDesyncDebug(&active->profiles[0].dp,"entity");else reference_LuaDesyncDebug(&active->profiles[0].dp,"entity");break;default:{ipset value={(void *)(uintptr_t)(entry&1),(void *)(uintptr_t)(entry&2)};const char *text=rust?zapret_native_ip_fill(value.ips4,value.ips6):reference_dbg_ipset_fill(&value);append(text,strlen(text));break;}}}
int main(void){for(unsigned debug=0;debug<2;debug++)for(unsigned variant=0;variant<8;variant++)for(unsigned mutation=0;mutation<7;mutation++)for(unsigned entry=0;entry<10;entry++){initial(&fixtures[0],debug,variant,mutation);run(false,entry);initial(&fixtures[1],debug,variant,mutation);run(true,entry);CHECK(fixtures[0].calls==fixtures[1].calls&&fixtures[0].used==fixtures[1].used);CHECK(!memcmp(fixtures[0].trace,fixtures[1].trace,fixtures[0].used));cleanup(&fixtures[0]);cleanup(&fixtures[1]);++cases;}printf("PASS native_diagnostic_views complete_cases=%u functions=7 exact_fragments=1 native_layouts=1 deferred_mutations=7\n",cases);return 0;}
