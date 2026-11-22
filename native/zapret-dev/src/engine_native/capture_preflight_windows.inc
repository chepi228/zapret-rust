/* MIT. Capture metadata, allocator primitives and Win32 handle calls. */
typedef struct{
    char **output;const char *save;const uint32_t *hashes;HANDLE *mutex;
    const char *sources[12],*raw;const struct str_list *parts;size_t capacity;uint32_t index,sub_index;
    bool ipv4,ipv6,lan,loopback,empty,intercept,server,duplicate,dry;
}zapret_capture_prepare_target;
typedef struct{HANDLE handle;uint32_t error;}zapret_capture_mutex_result;
typedef struct{
    void *(*resize)(void *,size_t);void (*release_clauses)(void);
    uint32_t (*save)(const char *,const uint8_t *,size_t);
    zapret_capture_mutex_result (*create)(const char *);
    void (*close)(HANDLE),(*report)(uint32_t,size_t,const char *);
}zapret_capture_prepare_ops;
typedef struct{uint32_t status,error;}zapret_capture_prepare_result;
zapret_capture_prepare_result zapret_capture_prepare(const zapret_capture_prepare_target *,const zapret_capture_prepare_ops *);
uint32_t zapret_engine_save_file(const char *,const uint8_t *,size_t);
_Static_assert(sizeof(zapret_capture_prepare_target) == (sizeof(void *) == 4 ? 96 : 176) &&
    offsetof(zapret_capture_prepare_target, sources) == 4 * sizeof(void *) &&
    offsetof(zapret_capture_prepare_target, capacity) == 18 * sizeof(void *) &&
    offsetof(zapret_capture_prepare_target, index) == 19 * sizeof(void *) &&
    offsetof(zapret_capture_prepare_target, dry) == 19 * sizeof(void *) + 16 &&
    sizeof(zapret_capture_prepare_ops) == 6 * sizeof(void *) &&
    sizeof(zapret_capture_mutex_result) == 2 * sizeof(void *) &&
    sizeof(zapret_capture_prepare_result) == 8 && WF_COUNT == 16 && WINDIVERT_MAX == 65536,
    "Rust capture preparation ABI");
static void native_capture_release_clauses(void){cleanup_windivert_portfilters(&params);}
static zapret_capture_mutex_result native_capture_create_mutex(const char *name){SetLastError(0);HANDLE handle=CreateMutexA(NULL,TRUE,name);DWORD error=GetLastError();zapret_capture_mutex_result result={handle,error};return result;}
static void native_capture_close_mutex(HANDLE handle){CloseHandle(handle);}
static void native_capture_prepare_report(uint32_t event,size_t size,const char *text){if(event==0)DLOG("windivert filter size: %zu\nwindivert filter:\n%s\n",size,text);else DLOG_ERR("windivert filter: raw filter saved to %s\n",text);}
static zapret_capture_prepare_result native_capture_prepare(unsigned index,unsigned sub_index,bool ipv4,bool ipv6,bool lan,bool loopback,bool empty,bool duplicate,bool dry,const char *save,const unsigned *hashes,HANDLE *mutex)
{
    const zapret_capture_prepare_target target={&params.windivert_filter,save,hashes,mutex,
        {params.wf_pf_tcp_src_out,params.wf_pf_tcp_dst_out,params.wf_pf_tcp_src_in,params.wf_pf_tcp_dst_in,params.wf_pf_udp_src_in,params.wf_pf_udp_dst_in,params.wf_pf_udp_src_out,params.wf_pf_udp_dst_out,params.wf_icf_out,params.wf_icf_in,params.wf_ipf_out,params.wf_ipf_in},
        params.wf_raw_filter,LIST_FIRST(&params.wf_raw_part),WINDIVERT_MAX,index,sub_index,ipv4,ipv6,lan,loopback,empty,params.intercept,params.server,duplicate,dry};
    static const zapret_capture_prepare_ops ops={realloc,native_capture_release_clauses,zapret_engine_save_file,native_capture_create_mutex,native_capture_close_mutex,native_capture_prepare_report};
    zapret_capture_prepare_result result=zapret_capture_prepare(&target,&ops);
    switch(result.status){
        case 0:case 8:break;
        case 1:DLOG_ERR("invalid capture preparation storage\n");break;
        case 2:DLOG_ERR("windivert filter : must specify port or/and partial raw filter\n");break;
        case 3:DLOG_ERR("windivert filter : could not make filter\n");break;
        case 4:DLOG_ERR("out of memory\n");break;
        case 5:wf_error(result.error);DLOG_ERR("windivert filter: could not save raw filter to %s\n",save);break;
        case 6:DLOG_ERR("A copy of winws2 is already running with the same filter\n");break;
        default:wf_error(result.error);DLOG_ERR("could not create the argument mutex: Windows error %u\n",result.error);break;
    }
    return result;
}
