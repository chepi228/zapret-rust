/* MIT. Rust owns rollback to the prior list head, including backlink repair. */
#include "list_lifecycle_windows.h"
bool zapret_parse_port_list(const char *,struct port_filters_head *,bool (*)(struct port_filters_head *,const port_filter *));
bool zapret_parse_icmp_list(const char *,struct icmp_filters_head *,bool (*)(struct icmp_filters_head *,const icmp_filter *));
bool zapret_parse_ip_list(const char *,struct ipp_filters_head *,bool (*)(struct ipp_filters_head *,const ipp_filter *));
static uintptr_t list_filter_native(uint32_t op,uintptr_t a,uintptr_t b,uintptr_t c,uintptr_t d,uintptr_t e)
{(void)c;(void)d;(void)e;switch(op){
case 1:return zapret_parse_port_list((const char *)a,(struct port_filters_head *)b,port_filter_add);
case 2:return zapret_parse_icmp_list((const char *)a,(struct icmp_filters_head *)b,icmp_filter_add);
case 3:return zapret_parse_ip_list((const char *)a,(struct ipp_filters_head *)b,ipp_filter_add);
case 4:free((void *)a);return 0;default:return 0;}}
static bool parse_pf_list(const char *text,struct port_filters_head *head)
{return zapret_list_lifecycle(1,0,(uintptr_t)head,(uintptr_t)text,offsetof(struct port_filter_item,next),0,list_filter_native)!=0;}
static bool parse_icf_list(const char *text,struct icmp_filters_head *head)
{return zapret_list_lifecycle(1,1,(uintptr_t)head,(uintptr_t)text,offsetof(struct icmp_filter_item,next),0,list_filter_native)!=0;}
static bool parse_ipp_list(const char *text,struct ipp_filters_head *head)
{return zapret_list_lifecycle(1,2,(uintptr_t)head,(uintptr_t)text,offsetof(struct ipp_filter_item,next),0,list_filter_native)!=0;}
