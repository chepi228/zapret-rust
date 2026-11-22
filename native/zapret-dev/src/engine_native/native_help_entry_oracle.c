/* MIT. Complete original/new help, exact bytes/defaults/lookups/exit, guarded names. */
#include <windows.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <setjmp.h>
#include "params.h"
#undef main
static unsigned cases,mode;static unsigned char *guard;
#define CHECK(c)do{if(!(c)){fprintf(stderr,"FAIL native_help_entry case=%u line=%d: %s\n",cases,__LINE__,#c);exit(1);}}while(0)
struct captured{unsigned index,lookups[64],exits,code;size_t length;char bytes[65536];};static struct captured captures[2],*active;static jmp_buf closed;
static const char *label(bool protocol,unsigned index){CHECK(active->index<64);active->lookups[active->index++]=(protocol?0x100:0)|index;static char long_name[4097];switch(mode){case 1:memset(long_name,'x',4096);long_name[4096]=0;return long_name;case 2:return "";case 3:return "\xff-name\0ignored";case 4:return (char *)guard-(protocol?511:1023);default:return protocol?l7proto_str((t_l7proto)index):l7payload_str((t_l7payload)index);}}
static const char *payload(uint32_t index){return label(false,index);}static const char *protocol(uint32_t index){return label(true,index);}
static int print_help(const char *format,...){va_list args;va_start(args,format);int size=vsnprintf(active->bytes,sizeof(active->bytes),format,args);va_end(args);CHECK(size>=0&&(size_t)size<sizeof(active->bytes));active->length=(size_t)size;return mode==3?-1:size;}
static void close_exit(int code){++active->exits;active->code=(unsigned)code;longjmp(closed,1);}
#define l7payload_str payload
#define l7proto_str protocol
#define printf print_help
#define close_std_and_exit close_exit
#define exithelp reference_exithelp
#include "native_help_reference.inc"
#undef exithelp
#define ZAPRET_HELP_NAMES (&(zapret_help_names){ payload, protocol })
#include "native_help_entry_windows.inc"
#undef printf
int main(void){SYSTEM_INFO info;GetSystemInfo(&info);unsigned char *memory=VirtualAlloc(NULL,info.dwPageSize*2,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);CHECK(memory);DWORD old;guard=memory+info.dwPageSize;CHECK(VirtualProtect(guard,info.dwPageSize,PAGE_NOACCESS,&old));memset(memory,'g',info.dwPageSize);for(mode=0;mode<5;mode++){memset(captures,0,sizeof(captures));for(unsigned version=0;version<2;version++){active=&captures[version];if(!setjmp(closed)){if(version)exithelp();else reference_exithelp();CHECK(false);}}CHECK(captures[0].index==47&&captures[1].index==47&&captures[0].exits==1&&captures[1].exits==1&&captures[0].code==1&&captures[1].code==1);CHECK(captures[0].length==captures[1].length&&!memcmp(captures[0].bytes,captures[1].bytes,captures[0].length));CHECK(!memcmp(captures[0].lookups,captures[1].lookups,47*sizeof(unsigned)));++cases;}CHECK(VirtualFree(memory,0,MEM_RELEASE));printf("PASS native_help_entry complete_cases=%u exact_bytes=1 lookups=47 native_exit=1 guarded_names=1\n",cases);return 0;}
