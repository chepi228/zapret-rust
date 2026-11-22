/* MIT. Independent pinned C table, category metadata and complete scalar adapter. */
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <getopt.h>
#include "native_cli_catalog_abi.h"
#undef main
#include "native_cli_reference.inc"
static unsigned cases;
#define CHECK(c)do{if(!(c)){fprintf(stderr,"FAIL native_cli_catalog case=%u line=%d: %s\n",cases,__LINE__,#c);exit(1);}}while(0)
struct desync_profile{int hostlist_auto_fail_threshold,hostlist_auto_fail_time,hostlist_auto_retrans_threshold,hostlist_auto_udp_in,hostlist_auto_udp_out;unsigned hostlist_auto_retrans_maxseq,hostlist_auto_incoming_maxseq;bool hostlist_auto_retrans_reset,b_hostlist_auto_fail_threshold,b_hostlist_auto_fail_time,b_hostlist_auto_retrans_threshold,b_hostlist_auto_udp_in,b_hostlist_auto_udp_out,b_hostlist_auto_retrans_maxseq,b_hostlist_auto_incoming_maxseq,b_hostlist_auto_retrans_reset;};
static struct{bool intercept,daemon,ctrack_disable,server,cache_hostname,ssid_filter_neg,nlm_filter_neg;unsigned fuzz,ipcache_lifetime,ctrack_t_syn,ctrack_t_est,ctrack_t_fin,ctrack_t_udp;uint64_t lua_gc;}params;
typedef struct{void *target;bool *explicit;int64_t lower,upper;uint32_t scale,kind;bool *disable;}zapret_numeric_option;
struct capture{zapret_numeric_option option;const char *text;unsigned type;void *slots[4];};
static struct capture captured;static bool backend;
#define zapret_cli_set_number catalog_fixture_number
#define zapret_cli_timeouts catalog_fixture_timeouts
static bool zapret_cli_set_number(const char *text,const zapret_numeric_option *option){captured.option=*option;captured.text=text;captured.type=1;return backend;}
static bool zapret_cli_timeouts(const char *text,unsigned *a,unsigned *b,unsigned *c,unsigned *d){captured.type=2;captured.text=text;captured.slots[0]=a;captured.slots[1]=b;captured.slots[2]=c;captured.slots[3]=d;return backend;}
#define engine_numeric_option reference_engine_numeric_option
#include "native_cli_numeric_reference.inc"
#undef engine_numeric_option
#include "native_cli_numeric_windows.inc"
static void scalar(int index,const char *text){struct desync_profile dp={0};memset(&captured,0,sizeof(captured));int a=reference_engine_numeric_option(index,text,&dp);struct capture expected=captured;memset(&captured,0,sizeof(captured));int b=engine_numeric_option(index,text,&dp);CHECK(a==b&&expected.type==captured.type&&expected.text==captured.text);CHECK(expected.option.target==captured.option.target&&expected.option.explicit==captured.option.explicit&&expected.option.lower==captured.option.lower&&expected.option.upper==captured.option.upper&&expected.option.scale==captured.option.scale&&expected.option.kind==captured.option.kind&&expected.option.disable==captured.option.disable);for(unsigned i=0;i<4;i++)CHECK(expected.slots[i]==captured.slots[i]);++cases;}
int main(void){CHECK(zapret_native_cli_count()==IDX_LAST+1);const struct option *actual=zapret_native_cli_options();for(unsigned i=0;i<IDX_LAST;i++){const struct option *expected=&long_options[i];CHECK(actual[i].name&&!strcmp(actual[i].name,expected->name));CHECK(actual[i].has_arg==expected->has_arg&&actual[i].flag==expected->flag&&actual[i].val==expected->val);++cases;}
const struct option builtin=actual[IDX_LAST];
CHECK(builtin.name&&!strcmp(builtin.name,"builtin-rules")&&!builtin.has_arg&&!builtin.flag&&!builtin.val);
CHECK(!actual[IDX_LAST+1].name&&!actual[IDX_LAST+1].has_arg&&!actual[IDX_LAST+1].flag&&!actual[IDX_LAST+1].val);
for(int index=-1;index<IDX_LAST+3;index++){for(unsigned category=1;category<=5;category++){const int kind=index==IDX_LAST&&category==1?reference_kind(IDX_LUA_INIT,category):reference_kind(index,category);CHECK(zapret_native_cli_kind(index,category)==kind);++cases;}CHECK(zapret_native_cli_skip_numeric(index)==(index==IDX_SSID_FILTER_NEG||index==IDX_NLM_FILTER_NEG));CHECK(zapret_native_cli_capacity(index)==((index==IDX_WF_RAW||index==IDX_WF_RAW_PART||index==IDX_WF_RAW_FILTER)?65536:4096));for(unsigned result=0;result<2;result++){backend=result;scalar(index,NULL);scalar(index,"-19junk");}}
printf("PASS native_cli_catalog comparisons=%u upstream_options=%u builtin_rules=1 scalar_adapter=1 independent_kind_schema=1\n",cases,IDX_LAST);return 0;}
