/* MIT. Byte-for-byte bounded formatting and captured legacy print limits. */
#include "darkmagic.h"
#include "helpers.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#undef main
static unsigned labels,texts,prints,boundaries;
#define CHECK(condition) do { if(!(condition)){ \
 fprintf(stderr,"FAIL packet describe labels=%u texts=%u prints=%u line=%d: %s\n",labels,texts,prints,__LINE__,#condition);exit(1); } } while(0)
static char captured[512];
static int capture(const char *format,...) {va_list args;va_start(args,format);int count=vsnprintf(captured,sizeof(captured),format,args);va_end(args);return count;}
#define proto_name reference_proto_name
#define str_proto_name reference_str_proto_name
#define icmp_type_name reference_icmp_type_name
#define str_icmp_type_name reference_str_icmp_type_name
#define str_srcdst_ip reference_str_srcdst_ip
#define str_ip reference_str_ip
#define print_ip reference_print_ip
#define str_srcdst_ip6 reference_str_srcdst_ip6
#define str_ip6hdr reference_str_ip6hdr
#define print_ip6hdr reference_print_ip6hdr
#define str_tcphdr reference_str_tcphdr
#define print_tcphdr reference_print_tcphdr
#define str_udphdr reference_str_udphdr
#define print_udphdr reference_print_udphdr
#define str_icmphdr reference_str_icmphdr
#define print_icmphdr reference_print_icmphdr
#define printf capture
#include "packet_describe_reference.inc"
#undef proto_name
#undef str_proto_name
#undef icmp_type_name
#undef str_icmp_type_name
#undef str_srcdst_ip
#undef str_ip
#undef print_ip
#undef str_srcdst_ip6
#undef str_ip6hdr
#undef print_ip6hdr
#undef str_tcphdr
#undef print_tcphdr
#undef str_udphdr
#undef print_udphdr
#undef str_icmphdr
#undef print_icmphdr
#include "packet_describe_windows.inc"
#undef printf

void zapret_packet_describe(uint32_t, const void *, uint8_t, bool, char *, size_t);

typedef union {uint8_t bytes[64];uint64_t alignment;struct ip ip;struct ip6_hdr ip6;struct tcphdr tcp;struct udphdr udp;struct icmp46 icmp;} packet;
static uint32_t random_state=0x791deb52;
static void fill(void *data,size_t size) {for(size_t index=0;index<size;++index){random_state=random_state*1664525+1013904223;((uint8_t *)data)[index]=(uint8_t)(random_state>>24);}}
static void equal_name(const char *left,const char *right) {
    if(!!left!=!!right || (left && strcmp(left,right)))fprintf(stderr,"label differs: expected=%s actual=%s\n",left?left:"(null)",right?right:"(null)");
    CHECK(!!left==!!right);if(left)CHECK(!strcmp(left,right));++labels;
}
#define FORMAT(prefix,out) do {switch(operation){ \
case 0:prefix##str_ip(out,capacity,&data.ip);break; \
case 1:prefix##str_ip6hdr(out,capacity,&data.ip6,protocol);break; \
case 2:prefix##str_srcdst_ip6(out,capacity,&data.ip6.ip6_src,&data.ip6.ip6_dst);break; \
case 3:prefix##str_tcphdr(out,capacity,&data.tcp);break; \
case 4:prefix##str_udphdr(out,capacity,&data.udp);break; \
case 5:prefix##str_icmphdr(out,capacity,false,&data.icmp);break; \
case 6:prefix##str_icmphdr(out,capacity,true,&data.icmp);break; \
} } while(0)

static void guarded_entries(void)
{
    const packet data = {0};
    const uint8_t protocol = 6;
    char output[16], expected[16];
    memset(expected, 0x69, sizeof(expected));
    memcpy(output, expected, sizeof(output));

    str_proto_name(NULL, sizeof(output), protocol);
    str_icmp_type_name(NULL, sizeof(output), true, 128);
    str_proto_name(output, SIZE_MAX, protocol);
    CHECK(!memcmp(output, expected, sizeof(output)));
    str_icmp_type_name(output, SIZE_MAX, true, 128);
    CHECK(!memcmp(output, expected, sizeof(output)));
    boundaries += 4;

    for (unsigned operation = 0; operation < 7; ++operation) {
        size_t capacity = sizeof(output);
        FORMAT(, NULL);
        capacity = SIZE_MAX;
        FORMAT(, output);
        CHECK(!memcmp(output, expected, sizeof(output)));
        boundaries += 2;
    }

    str_srcdst_ip6(output, sizeof(output), NULL, &data.ip6.ip6_dst);
    CHECK(!memcmp(output, expected, sizeof(output)));
    str_srcdst_ip6(output, sizeof(output), &data.ip6.ip6_src, NULL);
    CHECK(!memcmp(output, expected, sizeof(output)));
    boundaries += 2;

    expected[0] = 0;
    str_ip(output, sizeof(output), NULL);
    CHECK(!memcmp(output, expected, sizeof(output)));
    output[0] = 0x69;
    zapret_packet_describe(99, data.bytes, protocol, false, output, sizeof(output));
    CHECK(!memcmp(output, expected, sizeof(output)));
    boundaries += 2;
}

#define PRINT(prefix) do {switch(operation){ \
case 0:prefix##print_ip(&data.ip);break; \
case 1:prefix##print_ip6hdr(&data.ip6,protocol);break; \
case 2:prefix##print_tcphdr(&data.tcp);break; \
case 3:prefix##print_udphdr(&data.udp);break; \
case 4:prefix##print_icmphdr(&data.icmp,false);break; \
case 5:prefix##print_icmphdr(&data.icmp,true);break; \
} } while(0)
static int compare_double(const void *a,const void *b) {double x=*(const double *)a,y=*(const double *)b;return (x>y)-(x<y);}
static void benchmark(void)
{
    packet data;fill(&data,sizeof(data));data.tcp.th_flags=TH_SYN|TH_ACK;
    void (*volatile functions[2])(char *,size_t,const struct tcphdr *)={reference_str_tcphdr,str_tcphdr};
    LARGE_INTEGER frequency,start,end;CHECK(QueryPerformanceFrequency(&frequency));double times[2][9];char output[80];
    for(unsigned round=0;round<9;++round)for(unsigned turn=0;turn<2;++turn){unsigned variant=turn^(round&1);CHECK(QueryPerformanceCounter(&start));
        for(unsigned index=0;index<16384;++index)functions[variant](output,sizeof(output),&data.tcp);
        CHECK(QueryPerformanceCounter(&end));times[variant][round]=(double)(end.QuadPart-start.QuadPart)*1e9/(double)frequency.QuadPart/16384.0;
    }
    qsort(times[0],9,sizeof(double),compare_double);qsort(times[1],9,sizeof(double),compare_double);
    printf("BENCH packet_describe tcp_text c_ns=%.2f rust_ns=%.2f rounds=9 calls_per_round=16384\n",times[0][4],times[1][4]);
}
int main(void)
{
    WSADATA wsa;CHECK(!WSAStartup(MAKEWORD(2,2),&wsa));
    for(unsigned number=0;number<256;++number){
        equal_name(reference_proto_name((uint8_t)number),proto_name((uint8_t)number));
        for(unsigned family=0;family<2;++family)equal_name(reference_icmp_type_name(family!=0,(uint8_t)number),icmp_type_name(family!=0,(uint8_t)number));
        for(size_t capacity=0;capacity<=40;++capacity){char a[64],b[64];memset(a,0x69,sizeof(a));memcpy(b,a,sizeof(a));
            reference_str_proto_name(a+8,capacity,(uint8_t)number);str_proto_name(b+8,capacity,(uint8_t)number);CHECK(!memcmp(a,b,sizeof(a)));++texts;
            for(unsigned family=0;family<2;++family){memset(a,0x69,sizeof(a));memcpy(b,a,sizeof(a));
                reference_str_icmp_type_name(a+8,capacity,family!=0,(uint8_t)number);str_icmp_type_name(b+8,capacity,family!=0,(uint8_t)number);CHECK(!memcmp(a,b,sizeof(a)));++texts;
            }
        }
    }
    for(unsigned iteration=0;iteration<256;++iteration){packet data;fill(&data,sizeof(data));data.bytes[0]=(uint8_t)iteration;data.tcp.th_flags=(uint8_t)iteration;packet saved=data;uint8_t protocol=(uint8_t)iteration;
        for(unsigned operation=0;operation<7;++operation)for(size_t capacity=0;capacity<=160;++capacity){char a[192],b[192];memset(a,0x69,sizeof(a));memcpy(b,a,sizeof(a));
            FORMAT(reference_,a+8);FORMAT(,b+8);CHECK(!memcmp(a,b,sizeof(a)));++texts;
        }
        for(unsigned operation=0;operation<6;++operation){char expected[512];memset(captured,0x69,sizeof(captured));PRINT(reference_);memcpy(expected,captured,sizeof(expected));
            memset(captured,0x69,sizeof(captured));PRINT();CHECK(!memcmp(expected,captured,sizeof(expected)));++prints;
        }
        CHECK(!memcmp(&data,&saved,sizeof(data)));
    }
    guarded_entries();
    printf("PASS packet_describe functions=16 labels=%u text_cases=%u printed_cases=%u boundaries=%u\n",labels,texts,prints,boundaries);
    benchmark();CHECK(!WSACleanup());return 0;
}
