/* MIT. Bind the current C profile and local parser storage to Rust control. */
typedef struct{void *flow,*profile;bool *skip,*template;void **caches[4];uint64_t *payload;struct packet_range *incoming,*outgoing;bool *dry;}zapret_cli_control_target;
typedef struct{uint32_t (*next)(void *,const char *),(*label)(void *,bool,const char *),(*import)(const void *,const char *);}zapret_cli_control_ops;
uint32_t zapret_cli_control(uint32_t,const char *,const zapret_cli_control_target *,const zapret_cli_control_ops *);
int32_t zapret_cli_control_apply(uint32_t, const char *, const zapret_cli_control_target *, const zapret_cli_control_ops *,
    void *, void *, void (*)(const void *, void *, void *));
_Static_assert(sizeof(zapret_cli_control_target)==96 && sizeof(zapret_cli_control_ops)==24 && sizeof(struct packet_range)==20,"Rust CLI control ABI");
static uint32_t native_control_next(void *flow,const char *text){return native_profile_next(flow,text);}
static uint32_t native_control_label(void *profile,bool cookie,const char *text){return native_profile_label(profile,cookie,text);}
static uint32_t native_control_import(const void *flow,const char *text){return native_profile_import(flow,text);}
static void native_control_publish(const void *source, void *entry_slot, void *profile_slot)
{
    const native_profile_flow *flow = source;
    struct desync_profile_list **entry = entry_slot;
    struct desync_profile **profile = profile_slot;
    *entry = flow->current;
    *profile = &(*entry)->dp;
}
static int engine_control_option(int index,const char *text,native_profile_flow *flow,struct desync_profile_list **entry,struct desync_profile **profile,
    struct zapret_list_file **host,struct zapret_list_file **host_exclude,struct zapret_list_file **ip,struct zapret_list_file **ip_exclude,
    uint64_t *payload,struct packet_range *incoming,struct packet_range *outgoing,bool *dry)
{
    uint32_t kind;switch(index){case IDX_NEW:kind=0;break;case IDX_SKIP:kind=1;break;case IDX_TEMPLATE:kind=2;break;case IDX_NAME:kind=3;break;case IDX_COOKIE:kind=4;break;case IDX_IMPORT:kind=5;break;case IDX_DRY_RUN:kind=6;break;case IDX_VERSION:kind=7;break;case IDX_COMMENT:kind=8;break;default:return 0;}
    zapret_cli_control_target target={flow,*profile,&flow->skip,&flow->template,{(void **)host,(void **)host_exclude,(void **)ip,(void **)ip_exclude},payload,incoming,outgoing,dry};
    static const zapret_cli_control_ops ops={native_control_next,native_control_label,native_control_import};
    return zapret_cli_control_apply(kind, text, &target, &ops, entry, profile, native_control_publish);
}
