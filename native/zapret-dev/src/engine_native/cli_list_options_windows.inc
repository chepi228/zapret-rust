/* MIT. Field marshalling and FILE primitives; Rust owns the list option policy. */
#include "runtime_log_windows.h"

typedef struct {void *profile, **cached, **autolist;bool skip;} zapret_list_option_target;
typedef struct {
    void *(*register_file)(void *,bool,const char *);
    bool (*parse)(void *,const char *);
} zapret_list_option_backend;
typedef struct {
    zapret_list_option_backend hosts, ips;
    uint32_t (*probe_auto)(const char *);
} zapret_list_option_ops;
uint32_t zapret_cli_list_option(uint32_t,const char *,const zapret_list_option_target *,const zapret_list_option_ops *);
uint32_t zapret_cli_auto_probe(const char *,FILE *(*)(const char *,const char *),
    bool (*)(FILE *),int (*)(FILE *),int (*)(FILE *));
int zapret_cli_list_report(uint32_t,uint32_t,const char *,zapret_log_sink);
_Static_assert(sizeof(zapret_list_option_target) == 4 * sizeof(void *) &&
    sizeof(zapret_list_option_ops) == 5 * sizeof(void *), "Rust list option ABI");
static void *native_list_register_host(void *profile, bool exclude, const char *text)
{return RegisterHostlist(profile, exclude, text);}
static void *native_list_register_ip(void *profile, bool exclude, const char *text)
{return RegisterIpset(profile, exclude, text);}
static bool native_list_parse_host(void *file, const char *text)
{return parse_domain_list((char *)text, &((struct zapret_list_file *)file)->hostlist);}
static bool native_list_parse_ip(void *file, const char *text)
{return parse_ip_list((char *)text, &((struct zapret_list_file *)file)->ipset);}
static uint32_t native_list_option_probe(const char *path)
{
    return zapret_cli_auto_probe(path,fopen,is_gzip,ferror,fclose);
}
static const zapret_list_option_ops native_list_option_ops = {
    {native_list_register_host, native_list_parse_host},
    {native_list_register_ip, native_list_parse_ip},
    native_list_option_probe,
};
static int engine_list_option(int index,const char *text,struct desync_profile *profile,bool skip,
    struct zapret_list_file **host,struct zapret_list_file **host_exclude,struct zapret_list_file **ip,struct zapret_list_file **ip_exclude)
{
    uint32_t kind;void **cached=NULL;
    switch(index){
        case IDX_HOSTLIST:kind=0;break;
        case IDX_HOSTLIST_DOMAINS:kind=1;cached=(void **)host;break;
        case IDX_HOSTLIST_EXCLUDE:kind=2;break;
        case IDX_HOSTLIST_EXCLUDE_DOMAINS:kind=3;cached=(void **)host_exclude;break;
        case IDX_HOSTLIST_AUTO:kind=4;break;
        case IDX_IPSET:kind=5;break;
        case IDX_IPSET_IP:kind=6;cached=(void **)ip;break;
        case IDX_IPSET_EXCLUDE:kind=7;break;
        case IDX_IPSET_EXCLUDE_IP:kind=8;cached=(void **)ip_exclude;break;
        default:return 0;
    }
    zapret_list_option_target target={profile,cached,skip?NULL:(void **)&profile->hostlist_auto,skip};
    uint32_t status=zapret_cli_list_option(kind,text,&target,&native_list_option_ops);
    return zapret_cli_list_report(kind,status,text,DLOG_ERR);
}
