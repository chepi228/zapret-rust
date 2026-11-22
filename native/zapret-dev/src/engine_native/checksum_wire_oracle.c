/* MIT. Complete checksum-field mutations and independent scalar wire sums. */
#include "checksum.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#undef main
static unsigned cases,independent,unaligned,boundaries;
#define CHECK(condition) do { if(!(condition)) { \
 fprintf(stderr,"FAIL checksum wire cases=%u independent=%u line=%d: %s\n",cases,independent,__LINE__,#condition); exit(1); } } while(0)
#define ip4_fix_checksum reference_ip4_fix_checksum
#define tcp4_fix_checksum reference_tcp4_fix_checksum
#define tcp6_fix_checksum reference_tcp6_fix_checksum
#define tcp_fix_checksum reference_tcp_fix_checksum
#define udp4_fix_checksum reference_udp4_fix_checksum
#define udp6_fix_checksum reference_udp6_fix_checksum
#define udp_fix_checksum reference_udp_fix_checksum
#define icmp4_fix_checksum reference_icmp4_fix_checksum
#define icmp6_fix_checksum reference_icmp6_fix_checksum
#define icmp_fix_checksum reference_icmp_fix_checksum
#include "checksum_wire_reference.inc"
#undef ip4_fix_checksum
#undef tcp4_fix_checksum
#undef tcp6_fix_checksum
#undef tcp_fix_checksum
#undef udp4_fix_checksum
#undef udp6_fix_checksum
#undef udp_fix_checksum
#undef icmp4_fix_checksum
#undef icmp6_fix_checksum
#undef icmp_fix_checksum
#include "checksum_windows.h"
typedef union { uint8_t bytes[2112];uint64_t alignment;struct ip ip;struct ip6_hdr ip6; } storage;
static uint32_t random_state=0x4c573de1;
static void fill(void *output,size_t size)
{ for(size_t index=0;index<size;++index){random_state=random_state*1664525+1013904223;((uint8_t *)output)[index]=(uint8_t)(random_state>>24);} }
static uint32_t scalar_sum(const uint8_t *data,size_t size)
{
    uint32_t sum=0;for(size_t index=0;index<size;index+=2){sum+=(uint32_t)data[index]<<8;if(index+1<size)sum+=data[index+1];}
    return sum;
}
static uint16_t fold_scalar(uint32_t sum)
{ while(sum>>16)sum=(sum&65535)+(sum>>16);return (uint16_t)sum; }
static void independent_sum(unsigned operation,const uint8_t *data,size_t length,const struct ip *ip4,const struct ip6_hdr *ip6)
{
    if(!operation){size_t header=(data[0]&15)*4;if(header>=12){CHECK(fold_scalar(scalar_sum(data,header))==65535);++independent;}return;}
    unsigned offset=operation<=3?16:operation<=6?6:2;
    if(length<offset+2)return;
    const uint8_t *source=NULL,*destination=NULL;unsigned width=0,protocol=0;
    if(operation==1 || operation==4 || ((operation==3 || operation==6) && ip4)) {
        source=(const uint8_t *)&ip4->ip_src;destination=(const uint8_t *)&ip4->ip_dst;width=4;
    } else if(operation==2 || operation==5 || operation==8 || ((operation==3 || operation==6 || operation==9) && ip6)) {
        source=(const uint8_t *)&ip6->ip6_src;destination=(const uint8_t *)&ip6->ip6_dst;width=16;
    } else if(operation==3 || operation==6)return;
    if(width)protocol=operation<=3?6:operation<=6?17:58;
    uint32_t sum=scalar_sum(data,length);
    if(width)sum+=scalar_sum(source,width)+scalar_sum(destination,width)+(uint32_t)length+protocol;
    CHECK(fold_scalar(sum)==65535);++independent;
}
#define APPLY(prefix,buffer) do { switch(operation){ \
    case 0:prefix##ip4_fix_checksum((struct ip *)(buffer));break; \
    case 1:prefix##tcp4_fix_checksum((struct tcphdr *)(buffer),length,&four.ip.ip_src,&four.ip.ip_dst);break; \
    case 2:prefix##tcp6_fix_checksum((struct tcphdr *)(buffer),length,&six.ip6.ip6_src,&six.ip6.ip6_dst);break; \
    case 3:prefix##tcp_fix_checksum((struct tcphdr *)(buffer),length,ip4,ip6);break; \
    case 4:prefix##udp4_fix_checksum((struct udphdr *)(buffer),length,&four.ip.ip_src,&four.ip.ip_dst);break; \
    case 5:prefix##udp6_fix_checksum((struct udphdr *)(buffer),length,&six.ip6.ip6_src,&six.ip6.ip6_dst);break; \
    case 6:prefix##udp_fix_checksum((struct udphdr *)(buffer),length,ip4,ip6);break; \
    case 7:prefix##icmp4_fix_checksum((struct icmp46 *)(buffer),length);break; \
    case 8:prefix##icmp6_fix_checksum((struct icmp46 *)(buffer),length,&six.ip6);break; \
    case 9:prefix##icmp_fix_checksum((struct icmp46 *)(buffer),length,ip6);break; \
} } while(0)
static void compare(unsigned operation,size_t length,unsigned mode)
{
    storage input,four,six,expected;fill(&input,sizeof(input));fill(&four,sizeof(four));fill(&six,sizeof(six));
    input.bytes[8]=(input.bytes[8]&0xf0)|((unsigned)length%16);expected=input;
    const struct ip *ip4=mode&1?&four.ip:NULL;const struct ip6_hdr *ip6=mode&2?&six.ip6:NULL;
    APPLY(reference_,expected.bytes+8);
    for(unsigned offset=0;offset<8;++offset){uint8_t actual[2136];memset(actual,0x69,sizeof(actual));memcpy(actual+8+offset,input.bytes+8,sizeof(input)-8);
        APPLY(,actual+8+offset);
        CHECK(!memcmp(actual+8+offset,expected.bytes+8,sizeof(input)-8));
        for(size_t index=0;index<sizeof(actual);++index)if(index<8+offset || index>=sizeof(input)+offset)CHECK(actual[index]==0x69);
        ++cases;if(offset)++unaligned;
    }
    if(operation==1 || operation==4)independent_sum(operation,expected.bytes+8,length,&four.ip,NULL);
    else if(operation==2 || operation==5 || operation==8)independent_sum(operation,expected.bytes+8,length,NULL,&six.ip6);
    else independent_sum(operation,expected.bytes+8,length,ip4,ip6);
}
static int compare_double(const void *a,const void *b) { double x=*(const double *)a,y=*(const double *)b;return (x>y)-(x<y); }
static void benchmark_case(const char *name,size_t size,bool ipv6)
{
    storage data,four,six;fill(&data,sizeof(data));fill(&four,sizeof(four));fill(&six,sizeof(six));
    void (*volatile functions[2])(struct tcphdr *,size_t,const struct ip *,const struct ip6_hdr *)={reference_tcp_fix_checksum,tcp_fix_checksum};
    LARGE_INTEGER frequency,start,end;CHECK(QueryPerformanceFrequency(&frequency));double times[2][9];
    for(unsigned round=0;round<9;++round)for(unsigned turn=0;turn<2;++turn){unsigned variant=turn^(round&1);
        CHECK(QueryPerformanceCounter(&start));
        for(unsigned index=0;index<32768;++index)functions[variant]((struct tcphdr *)data.bytes,size,ipv6?NULL:&four.ip,ipv6?&six.ip6:NULL);
        CHECK(QueryPerformanceCounter(&end));times[variant][round]=(double)(end.QuadPart-start.QuadPart)*1e9/(double)frequency.QuadPart/32768.0;
    }
    qsort(times[0],9,sizeof(double),compare_double);qsort(times[1],9,sizeof(double),compare_double);
    printf("BENCH checksum_wire %s c_ns=%.2f rust_ns=%.2f rounds=9 calls_per_round=32768\n",name,times[0][4],times[1][4]);
}
int main(void)
{
    for(size_t length=0;length<=2048;++length)for(unsigned operation=0;operation<10;++operation)compare(operation,length,(unsigned)length%4);
    _Alignas(uint64_t) uint8_t data[64];
    uint8_t saved[64];fill(data,sizeof(data));memcpy(saved,data,sizeof(data));
    struct in_addr address4 = {0};
    struct in6_addr address6 = {0};
    ip4_fix_checksum(NULL);++boundaries;
    tcp4_fix_checksum(NULL,20,&address4,&address4);++boundaries;
    tcp4_fix_checksum((struct tcphdr *)data,20,NULL,&address4);++boundaries;
    tcp6_fix_checksum((struct tcphdr *)data,SIZE_MAX,&address6,&address6);++boundaries;
    udp_fix_checksum((struct udphdr *)data,20,NULL,NULL);++boundaries;
    icmp4_fix_checksum((struct icmp46 *)data,SIZE_MAX);++boundaries;
    icmp6_fix_checksum((struct icmp46 *)data,8,NULL);++boundaries;
    CHECK(!memcmp(data,saved,sizeof(data)));
    printf("PASS checksum_wire functions=10 cases=%u independent_sums=%u unaligned=%u boundaries=%u\n",cases,independent,unaligned,boundaries);
    benchmark_case("tcp4_64",64,false);benchmark_case("tcp4_1400",1400,false);
    benchmark_case("tcp6_64",64,true);benchmark_case("tcp6_1400",1400,true);
    return 0;
}
