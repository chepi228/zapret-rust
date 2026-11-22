/* MIT. Complete rollback/insertion/path entries; real Rust filter collections. */
#include "pools.h"
#include "helpers.h"
#include "list_windows.h"
#include <inttypes.h>
#include <errno.h>
#include <stdarg.h>
#undef main
static uint64_t trace;
static unsigned cases,attempts,fail_at,live;
static bool observing,v4_ok,v6_ok,add_ok,path_ok;
#define CHECK(x) do{if(!(x)){fprintf(stderr,"FAIL list_lifecycle case=%u line=%u: %s\n",cases,__LINE__,#x);exit(1);}}while(0)
static void event(unsigned op,uint64_t value){if(observing)trace=(trace^op)*1099511628211ULL^value;}
static uint64_t bytes(const void *p,size_t n){const uint8_t *b=p;uint64_t h=0;for(size_t i=0;i<n;++i)h=h*131+b[i];return h;}
static void *allocate(size_t size){event(1,size);if(++attempts==fail_at)return NULL;void *p=malloc(size);CHECK(p);++live;return p;}
static void release(void *p){event(2,p!=NULL);if(p){CHECK(live);--live;}free(p);errno=79;}
#define malloc allocate
#define free release
#include "collections_windows.inc"
#include "filter_collections_windows.inc"
#define parse_pf_list old_parse_pf_list
#define parse_icf_list old_parse_icf_list
#define parse_ipp_list old_parse_ipp_list
#include "list_lifecycle_before_filter.inc"
#undef parse_pf_list
#undef parse_icf_list
#undef parse_ipp_list
#include "list_lifecycle_filter_windows.inc"
bool HostlistPoolAddStrLen(hostlist_pool **pool,const char *text,size_t length,uint32_t flags){event(3,bytes(text,length));event(4,length);event(5,flags);errno=11;if(add_ok)*pool=(hostlist_pool *)(uintptr_t)19;return add_ok;}
void HostlistPoolDestroy(hostlist_pool **pool){event(6,0);*pool=NULL;errno=12;}
bool parse_cidr4(char *text,struct cidr4 *out){event(7,bytes(text,strlen(text)));memset(out,0,sizeof(*out));out->preflen=24;errno=13;return v4_ok;}
bool parse_cidr6(char *text,struct cidr6 *out){event(8,bytes(text,strlen(text)));memset(out,0,sizeof(*out));out->preflen=64;errno=14;return v6_ok;}
bool ipset4Add(struct zapret_ip_pool **pool,const struct in_addr *a,uint8_t bits){(void)a;event(9,bits);errno=15;if(add_ok)*pool=(struct zapret_ip_pool *)(uintptr_t)23;return add_ok;}
bool ipset6Add(struct zapret_ip_pool **pool,const struct in6_addr *a,uint8_t bits){(void)a;event(10,bits);errno=16;if(add_ok)*pool=(struct zapret_ip_pool *)(uintptr_t)29;return add_ok;}
void ipsetDestroy(ipset *pool){event(11,0);pool->ips4=pool->ips6=NULL;errno=17;}
static int list_fixture_log_row(unsigned sink,const char *format,va_list ap)
{char text[256];int n=vsnprintf(text,sizeof(text),format,ap);CHECK(n>=0&&(size_t)n<sizeof(text));event(sink,bytes(format,strlen(format)));event(sink,bytes(text,n));event(sink,errno);return n;}
static int list_fixture_log(const char *format,...)
{va_list ap;va_start(ap,format);int n=list_fixture_log_row(12,format,ap);va_end(ap);return n;}
static int list_fixture_condup(const char *format,...)
{va_list ap;va_start(ap,format);int n=list_fixture_log_row(18,format,ap);va_end(ap);return n;}
static int list_fixture_perror(const char *label){event(19,bytes(label,strlen(label)));event(19,errno);return 0;}
static void list_fixture_wf_error(DWORD error){event(20,error);errno=EACCES;SetLastError(error);}
#define DLOG_ERR list_fixture_log
#define insert_host old_insert_host
#include "list_lifecycle_before_host.inc"
#undef insert_host
#include "list_lifecycle_host_windows.inc"
#define insert_ip old_insert_ip
#include "list_lifecycle_before_ip.inc"
#undef insert_ip
#include "list_lifecycle_ip_windows.inc"
static int load_status;
static uint32_t load_error, compressed;
static zapret_list_insert expected_insert;
static void *expected_list;
static int list_fixture_load(const char *filename,int hosts,zapret_list_insert insert,void *target,zapret_list_info *out)
{
    CHECK(insert == expected_insert && target == expected_list);
    event(21,hosts);event(22,bytes(filename,strlen(filename)));
    *out=(zapret_list_info){UINT64_C(0x0180000001),UINT64_MAX,compressed,load_error};
    errno=EAGAIN;
    return load_status;
}
#define DLOG_CONDUP list_fixture_condup
#define DLOG_PERROR list_fixture_perror
#define wf_error list_fixture_wf_error
#define zapret_list_load list_fixture_load
#define AppendHostList old_AppendHostList
#define AppendIpset old_AppendIpset
#define insert_host old_insert_host
#define insert_ip old_insert_ip
#include "list_lifecycle_before_host_load.inc"
#include "list_lifecycle_before_ip_load.inc"
#undef insert_ip
#undef insert_host
#undef AppendIpset
#undef AppendHostList
#include "list_append_windows.inc"
#include "list_lifecycle_host_load.inc"
#include "list_lifecycle_ip_load.inc"
#undef zapret_list_load
#undef wf_error
#undef DLOG_PERROR
#undef DLOG_CONDUP
static char *list_fixture_realpath(const char *input,char *out){event(13,input?bytes(input,strlen(input)):0);errno=77;if(!path_ok)return NULL;strcpy(out,"canonical/path");return out;}
static struct zapret_list_file *list_fixture_register(struct zapret_list_files **files,struct zapret_list_collection **collection,const char *name){(void)files;(void)collection;event(14,name?bytes(name,strlen(name)):0);errno=78;return (struct zapret_list_file *)(uintptr_t)41;}
#undef realpath
#define realpath list_fixture_realpath
#define zapret_list_register list_fixture_register
#define zapret_list_register_path old_register_path
#include "list_lifecycle_before_registry.inc"
#undef zapret_list_register_path
#include "list_lifecycle_registry_windows.inc"
#undef free
#undef malloc
typedef union{struct port_filters_head port;struct icmp_filters_head icmp;struct ipp_filters_head ip;void *first;} root;
typedef struct{uint64_t trace;intptr_t value;int error;unsigned count;uint32_t nodes[32][4];uintptr_t roots[2];} sample;
static sample filter(bool old,unsigned kind,const char *input)
{root head={0};fail_at=0;observing=false;const port_filter p={443,443,false};const icmp_filter i={FLTMODE_ANY,0,0,false};const ipp_filter n={FLTMODE_FILTER,6};
    CHECK(kind==0?port_filter_add(&head.port,&p):kind==1?icmp_filter_add(&head.icmp,&i):ipp_filter_add(&head.ip,&n));
    void *previous=head.first;attempts=0;fail_at=(unsigned)(uintptr_t)input; /* replaced by caller immediately below */
    return (sample){0};}
static unsigned selected_failure;
static sample filter_case(bool old,unsigned kind,const char *input)
{
    root head={0};fail_at=0;observing=false;const port_filter p={443,443,false};const icmp_filter i={FLTMODE_ANY,0,0,false};const ipp_filter n={FLTMODE_FILTER,6};
    CHECK(kind==0?port_filter_add(&head.port,&p):kind==1?icmp_filter_add(&head.icmp,&i):ipp_filter_add(&head.ip,&n));void *previous=head.first;
    attempts=0;fail_at=selected_failure;trace=0;errno=71;observing=true;
    bool result=kind==0?(old?old_parse_pf_list(input,&head.port):parse_pf_list(input,&head.port)):kind==1?(old?old_parse_icf_list(input,&head.icmp):parse_icf_list(input,&head.icmp)):(old?old_parse_ipp_list(input,&head.ip):parse_ipp_list(input,&head.ip));
    observing=false;sample s;memset(&s,0,sizeof(s));s.trace=trace;s.value=result;s.error=errno;if(!result)CHECK(head.first==previous);
    void *node=head.first;void **expected=&head.first;while(node){CHECK(s.count<32);struct links{void *next;void **previous;} *links=(void *)((char *)node+8);CHECK(links->previous==expected&&*expected==node);uint32_t *v=s.nodes[s.count++];
        if(kind==0){port_filter *f=node;v[0]=f->from;v[1]=f->to;v[2]=f->neg;}else if(kind==1){icmp_filter *f=node;v[0]=f->mode;v[1]=f->type;v[2]=f->code;v[3]=f->code_valid;}else{ipp_filter *f=node;v[0]=f->mode;v[1]=f->proto;}expected=&links->next;node=links->next;}
    if(kind==0)port_filters_destroy(&head.port);else if(kind==1)icmp_filters_destroy(&head.icmp);else ipp_filters_destroy(&head.ip);CHECK(!live);return s;
}
static sample insertion(bool old,unsigned kind,const unsigned char *text,size_t length)
{hostlist_pool *host=(hostlist_pool *)(uintptr_t)11;ipset ip={(struct zapret_ip_pool *)(uintptr_t)13,(struct zapret_ip_pool *)(uintptr_t)17};trace=0;errno=71;observing=true;
    int result=kind==0?(old?old_insert_host(&host,text,length,9):insert_host(&host,text,length,9)):(old?old_insert_ip(&ip,text,length,0):insert_ip(&ip,text,length,0));observing=false;
    sample s;memset(&s,0,sizeof(s));s.trace=trace;s.value=result;s.error=errno;s.roots[0]=kind?(uintptr_t)ip.ips4:(uintptr_t)host;s.roots[1]=kind?(uintptr_t)ip.ips6:0;return s;}
static sample file_append(bool old,unsigned hosts)
{
    hostlist_pool *host=NULL;ipset ips={0};
    const char *filename="fixture-\xff.txt";
    expected_list=hosts?(void *)&host:(void *)&ips;
    expected_insert=hosts?(old?old_insert_host:insert_host):(old?old_insert_ip:insert_ip);
    trace=0;errno=71;SetLastError(73);observing=true;
    bool result=hosts?(old?old_AppendHostList(&host,filename):AppendHostList(&host,filename)):
        (old?old_AppendIpset(&ips,filename):AppendIpset(&ips,filename));
    DWORD last_error=GetLastError();
    observing=false;
    sample s;memset(&s,0,sizeof(s));s.trace=trace;s.value=result;s.error=errno;s.roots[0]=last_error;return s;
}
static void same(sample a,sample b){CHECK(!memcmp(&a,&b,sizeof(a)));++cases;}
int main(void){const char *inputs[]={NULL,"","80","80,443","80,bad","bad,80","1,,2","0","65536","1-2","~80","*","all","6,17","any","8:0,3"};
    for(unsigned kind=0;kind<3;++kind)for(unsigned i=0;i<sizeof(inputs)/sizeof(*inputs);++i)for(selected_failure=0;selected_failure<6;++selected_failure)same(filter_case(true,kind,inputs[i]),filter_case(false,kind,inputs[i]));
    unsigned char input[240];memset(input,'x',sizeof(input));const size_t lengths[]={0,1,126,127,128,200};
    for(unsigned flags=0;flags<8;++flags){v4_ok=flags&1;v6_ok=flags&2;add_ok=flags&4;for(unsigned kind=0;kind<2;++kind)for(unsigned i=0;i<sizeof(lengths)/sizeof(*lengths);++i)same(insertion(true,kind,input,lengths[i]),insertion(false,kind,input,lengths[i]));}
    const char *names[]={NULL,"","path","unicode-é"};for(unsigned ok=0;ok<2;++ok){path_ok=ok;for(unsigned i=0;i<4;++i){sample a,b;memset(&a,0,sizeof(a));memset(&b,0,sizeof(b));observing=true;trace=0;errno=71;a.value=(intptr_t)old_register_path(NULL,NULL,names[i]);a.trace=trace;a.error=errno;trace=0;errno=71;b.value=(intptr_t)zapret_list_register_path(NULL,NULL,names[i]);b.trace=trace;b.error=errno;observing=false;same(a,b);}}
    for(unsigned hosts=0;hosts<2;++hosts)for(load_status=0;load_status<=5;++load_status)
        for(compressed=0;compressed<2;++compressed)for(unsigned error=0;error<2;++error){
            load_error=error?ERROR_ACCESS_DENIED:0;same(file_append(true,hosts),file_append(false,hosts));
        }
    printf("PASS list_lifecycle entries=8 cases=%u rollback_identity=1 allocation_failures=1 insertion_traces=1 borrowed_paths=1 load_logs=48\n",cases);return 0;}
