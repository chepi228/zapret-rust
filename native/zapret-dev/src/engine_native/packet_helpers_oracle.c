/* MIT. Pinned C option parsing and exact guarded packet/address mutations. */
#include "darkmagic.h"
#include "helpers.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#undef main
static unsigned arithmetic,options,flags,ports,endpoints,destinations,reversals,unaligned,boundaries,guarded;
#define CHECK(condition) do { if(!(condition)) { \
 fprintf(stderr,"FAIL packet helpers options=%u ports=%u endpoints=%u reversals=%u line=%d: %s\n",options,ports,endpoints,reversals,__LINE__,#condition); exit(1); } } while(0)

size_t zapret_ipv4_header(const uint8_t *, size_t);
uint8_t zapret_ipv6_header(const uint8_t *, size_t);
size_t zapret_tcp_header(const uint8_t *, size_t);

/* The previous destination helper called these predicates through C. */
static bool reference_check_ipv4(const uint8_t *data, size_t length)
{
    return zapret_ipv4_header(data, length) != 0;
}

static bool reference_check_ipv6(const uint8_t *data, size_t length)
{
    return zapret_ipv6_header(data, length) != 0;
}

#define proto_check_ipv4 reference_check_ipv4
#define proto_check_ipv6 reference_check_ipv6
#define net32_add reference_net32_add
#define net16_add reference_net16_add
#define tcp_find_option reference_tcp_find_option
#define tcp_find_scale_factor reference_tcp_find_scale_factor
#define tcp_find_mss reference_tcp_find_mss
#define tcp_synack_segment reference_tcp_synack_segment
#define tcp_syn_segment reference_tcp_syn_segment
#define extract_ports reference_extract_ports
#define extract_dst reference_extract_dst
#define extract_endpoints reference_extract_endpoints
#define reverse_ip reference_reverse_ip
#define reverse_tcp reference_reverse_tcp
#define ttl46 reference_ttl46
#define family_from_proto reference_family_from_proto
#include "packet_helpers_reference.inc"
#undef proto_check_ipv4
#undef proto_check_ipv6
#undef net32_add
#undef net16_add
#undef tcp_find_option
#undef tcp_find_scale_factor
#undef tcp_find_mss
#undef tcp_synack_segment
#undef tcp_syn_segment
#undef extract_ports
#undef extract_dst
#undef extract_endpoints
#undef reverse_ip
#undef reverse_tcp
#undef ttl46
#undef family_from_proto
#include "packet.c"
#include "packet_helpers_windows.inc"
static uint32_t state=0x5719ac2d;
static uint32_t next(void) { state=state*1664525+1013904223; return state; }
static void pattern(void *data,size_t size) { for(size_t index=0;index<size;++index)((uint8_t *)data)[index]=(uint8_t)(next()>>24); }
typedef union { uint8_t bytes[96]; struct tcphdr tcp; struct ip ip; struct ip6_hdr ip6; uint64_t alignment; } wire;

static unsigned predicate_entries(void)
{
    wire packet = {0};
    unsigned cases = 0;
    for (unsigned version = 4; version <= 6; ++version)
        for (unsigned words = 0; words < 16; ++words) {
            packet.ip.ip_v = version;
            packet.ip.ip_hl = words;
            packet.ip.ip_len = htons(60);
            packet.tcp.th_off = words;
            for (size_t length = 0; length <= 64; ++length) {
                CHECK(proto_check_ipv4(packet.bytes, length) == (zapret_ipv4_header(packet.bytes, length) != 0));
                CHECK(proto_check_ipv6(packet.bytes, length) == (zapret_ipv6_header(packet.bytes, length) != 0));
                CHECK(proto_check_tcp(packet.bytes, length) == (zapret_tcp_header(packet.bytes, length) != 0));
                CHECK(proto_check_udp(NULL, length) == (length >= sizeof(struct udphdr)));
                CHECK(proto_check_icmp(NULL, length) == (length >= sizeof(struct icmp46)));
                cases += 5;
            }
        }
    return cases;
}

typedef struct { uint64_t before; struct sockaddr_storage value; uint64_t after; } address;
static void init_address(address *value) { memset(value,0x69,sizeof(*value)); }
static ptrdiff_t option_offset(uint8_t *result,const void *tcp) { return result ? result-(const uint8_t *)tcp : -1; }
static void endpoint_cases(const wire *ip4,const wire *ip6,const wire *transport,unsigned mode,bool alias)
{
    address a,b,c,d; init_address(&a); init_address(&b); c=a; d=b;
    const struct ip *v4=mode&1 ? &ip4->ip : NULL;
    const struct ip6_hdr *v6=mode&2 ? &ip6->ip6 : NULL;
    const struct tcphdr *tcp=mode&4 ? &transport->tcp : NULL;
    const struct udphdr *udp=mode&8 ? (const struct udphdr *)transport->bytes : NULL;
    struct sockaddr_storage *as=mode&16 ? &a.value : NULL,*ad=mode&32 ? (alias ? &a.value : &b.value) : NULL;
    struct sockaddr_storage *cs=mode&16 ? &c.value : NULL,*cd=mode&32 ? (alias ? &c.value : &d.value) : NULL;
    reference_extract_endpoints(v4,v6,tcp,udp,as,ad); extract_endpoints(v4,v6,tcp,udp,cs,cd);
    CHECK(!memcmp(&a,&c,sizeof(a)) && !memcmp(&b,&d,sizeof(b))); ++endpoints;
}
static int compare_double(const void *a,const void *b) { double x=*(const double *)a,y=*(const double *)b; return (x>y)-(x<y); }
static void benchmark_case(const char *name,wire *data,uint8_t *expected)
{
    uint8_t *(*volatile functions[2])(struct tcphdr *,uint8_t)={reference_tcp_find_option,tcp_find_option};
    LARGE_INTEGER frequency,start,end; CHECK(QueryPerformanceFrequency(&frequency)); double times[2][9];
    for(unsigned round=0;round<9;++round)for(unsigned turn=0;turn<2;++turn){unsigned variant=turn^(round&1);
        CHECK(QueryPerformanceCounter(&start));
        for(unsigned index=0;index<131072;++index)CHECK(functions[variant](&data->tcp,8)==expected);
        CHECK(QueryPerformanceCounter(&end)); times[variant][round]=(double)(end.QuadPart-start.QuadPart)*1e9/(double)frequency.QuadPart/131072.0;
    }
    qsort(times[0],9,sizeof(double),compare_double); qsort(times[1],9,sizeof(double),compare_double);
    printf("BENCH packet_helpers %s c_ns=%.2f rust_ns=%.2f rounds=9 calls_per_round=131072\n",name,times[0][4],times[1][4]);
}
static void benchmark(void)
{
    wire data={0}; data.tcp.th_off=15; memset(data.bytes+20,1,40);data.bytes[48]=8;data.bytes[49]=10;
    benchmark_case("long_padding",&data,data.bytes+48);
    data.tcp.th_off=8; memset(data.bytes+20,1,40);data.bytes[22]=8;data.bytes[23]=10;
    benchmark_case("timestamp",&data,data.bytes+22);
    data.tcp.th_off=8;memset(data.bytes+20,1,40);
    benchmark_case("missing_short",&data,NULL);
    data.tcp.th_off=5;benchmark_case("empty",&data,NULL);
}
static void guarded_headers(void)
{
    SYSTEM_INFO info;GetSystemInfo(&info);size_t page=info.dwPageSize;
    uint8_t *allocation=VirtualAlloc(NULL,page*2,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);CHECK(allocation);
    DWORD old;CHECK(VirtualProtect(allocation+page,page,PAGE_NOACCESS,&old));
    for(unsigned words=0;words<16;++words)for(unsigned pattern=0;pattern<4;++pattern){
        unsigned length=words*4,storage=length<20?20:length;
        uint8_t *header=allocation+page-storage;memset(header,1,storage);header[12]=(uint8_t)(words<<4);
        if(length>20){
            if(pattern==1)header[length-1]=0;
            if(pattern==2)header[length-1]=8;
            if(pattern==3){header[length-2]=8;header[length-1]=2;}
        }
        struct tcphdr *tcp=(struct tcphdr *)header;
        CHECK(option_offset(reference_tcp_find_option(tcp,8),tcp)==option_offset(tcp_find_option(tcp,8),tcp));++guarded;
    }
    CHECK(VirtualFree(allocation,0,MEM_RELEASE));
}
int main(void)
{
    const uint16_t increments[]={0,1,32767,65535};
    for(unsigned value=0;value<65536;++value)for(unsigned index=0;index<4;++index){
        CHECK(reference_net16_add((uint16_t)value,increments[index])==net16_add((uint16_t)value,increments[index])); ++arithmetic;
        uint32_t wide=((uint32_t)value<<16)|increments[index],add=~wide;
        CHECK(reference_net32_add(wide,add)==net32_add(wide,add)); ++arithmetic;
    }
    for(unsigned iteration=0;iteration<4096;++iteration){
        wire tcp; pattern(&tcp,sizeof(tcp)); tcp.tcp.th_off=iteration%16;
        switch((iteration/16)%8){
            case 0: memset(tcp.bytes+20,1,40); break;
            case 1: memset(tcp.bytes+20,0,40); break;
            case 2: for(unsigned offset=20;offset<60;offset+=4){tcp.bytes[offset]=2;tcp.bytes[offset+1]=4;} break;
            case 3: tcp.bytes[20]=3;tcp.bytes[21]=3;tcp.bytes[22]=7;tcp.bytes[23]=0;break;
            case 4: tcp.bytes[20]=8;tcp.bytes[21]=0;break;
            case 5: tcp.bytes[20]=8;tcp.bytes[21]=255;break;
            case 6: memset(tcp.bytes+20,1,40);tcp.bytes[59]=8;break;
        }
        wire saved=tcp;
        for(unsigned kind=0;kind<256;++kind){
            CHECK(option_offset(reference_tcp_find_option(&tcp.tcp,(uint8_t)kind),&tcp)==option_offset(tcp_find_option(&tcp.tcp,(uint8_t)kind),&tcp)); ++options;
        }
        CHECK(reference_tcp_find_scale_factor(&tcp.tcp)==tcp_find_scale_factor(&tcp.tcp)); ++options;
        CHECK(reference_tcp_find_mss(&tcp.tcp)==tcp_find_mss(&tcp.tcp)); ++options;
        CHECK(!memcmp(&saved,&tcp,sizeof(tcp)));
    }
    for(unsigned value=0;value<256;++value){wire tcp={0};tcp.tcp.th_flags=(uint8_t)value;
        CHECK(reference_tcp_synack_segment(&tcp.tcp)==tcp_synack_segment(&tcp.tcp));
        CHECK(reference_tcp_syn_segment(&tcp.tcp)==tcp_syn_segment(&tcp.tcp)); flags+=2;
        CHECK(reference_family_from_proto((uint8_t)value)==family_from_proto((uint8_t)value));
    }
    for(unsigned iteration=0;iteration<256;++iteration){
        wire ip4,ip6,tcp; pattern(&ip4,sizeof(ip4));pattern(&ip6,sizeof(ip6));pattern(&tcp,sizeof(tcp));
        for(unsigned mode=0;mode<64;++mode)endpoint_cases(&ip4,&ip6,&tcp,mode,false);
        for(unsigned mode=0;mode<16;++mode)endpoint_cases(&ip4,&ip6,&tcp,mode|48,true);
        for(unsigned mode=0;mode<32;++mode){
            uint16_t sa=0x6969,sb=sa,da=sa,db=sa;uint8_t pa=0x69,pb=pa;
            const struct tcphdr *t=mode&1 ? &tcp.tcp : NULL;const struct udphdr *u=mode&2 ? (const struct udphdr *)tcp.bytes : NULL;
            reference_extract_ports(t,u,mode&4?&pa:NULL,mode&8?&sa:NULL,mode&16?&da:NULL);
            extract_ports(t,u,mode&4?&pb:NULL,mode&8?&sb:NULL,mode&16?&db:NULL);
            CHECK(sa==sb && da==db && pa==pb);++ports;
        }
        for(unsigned mode=0;mode<4;++mode){CHECK(reference_ttl46(mode&1?&ip4.ip:NULL,mode&2?&ip6.ip6:NULL)==ttl46(mode&1?&ip4.ip:NULL,mode&2?&ip6.ip6:NULL));}
    }
    for(unsigned iteration=0;iteration<8192;++iteration){
        wire packet; pattern(&packet,sizeof(packet)); packet.ip.ip_v=iteration%3==0?4:iteration%3==1?6:0;packet.ip.ip_hl=(iteration/3)%16;
        packet.ip.ip_len=htons((uint16_t)(iteration%97)); size_t length=(iteration/16)%97;
        address a,b;init_address(&a);b=a;
        CHECK(reference_extract_dst(packet.bytes,length,(struct sockaddr *)&a.value)==extract_dst(packet.bytes,length,(struct sockaddr *)&b.value));
        CHECK(!memcmp(&a,&b,sizeof(a)));++destinations;
    }
    for(unsigned iteration=0;iteration<1024;++iteration){
        wire a,b,c,d;pattern(&a,sizeof(a));pattern(&b,sizeof(b));a.ip.ip_hl=iteration%16;c=a;d=b;
        unsigned mode=iteration%4; reference_reverse_ip(mode&1?&a.ip:NULL,mode&2?&b.ip6:NULL);reverse_ip(mode&1?&c.ip:NULL,mode&2?&d.ip6:NULL);
        CHECK(!memcmp(&a,&c,sizeof(a)) && !memcmp(&b,&d,sizeof(b)));++reversals;
        wire tcp;pattern(&tcp,sizeof(tcp));wire expected=tcp;reference_reverse_tcp(&expected.tcp);
        for(unsigned offset=0;offset<8;++offset){uint8_t storage[128];memset(storage,0x69,sizeof(storage));memcpy(storage+8+offset,&tcp,sizeof(tcp));
            zapret_packet_reverse_tcp(storage+8+offset);CHECK(!memcmp(storage+8+offset,&expected,sizeof(expected)));
            for(unsigned index=0;index<sizeof(storage);++index)if(index<8+offset || index>=8+offset+sizeof(tcp))CHECK(storage[index]==0x69);++unaligned;
        }
    }
    CHECK(!zapret_packet_tcp_find_option(NULL,8));++boundaries;
    CHECK(zapret_packet_tcp_find_scale_factor(NULL)==255);++boundaries;
    CHECK(!zapret_packet_tcp_find_mss(NULL));++boundaries;
    CHECK(!zapret_packet_tcp_synack_segment(NULL) && !zapret_packet_tcp_syn_segment(NULL));++boundaries;
    CHECK(!zapret_packet_extract_dst(NULL,1,NULL));++boundaries;
    wire valid={0};valid.ip.ip_v=4;valid.ip.ip_hl=5;valid.ip.ip_len=htons(20);
    CHECK(!zapret_packet_extract_dst(valid.bytes,20,NULL));++boundaries;
    address untouched;init_address(&untouched);address saved=untouched;
    CHECK(!zapret_packet_extract_dst(NULL,1,&untouched.value));++boundaries;
    CHECK(!zapret_packet_extract_dst(valid.bytes,SIZE_MAX,&untouched.value) && !memcmp(&untouched,&saved,sizeof(saved)));++boundaries;
    zapret_packet_reverse_tcp(NULL);++boundaries;
    CHECK(!ttl46(NULL,NULL));++boundaries;
    guarded_headers();
    printf("PASS packet_helpers functions=14 arithmetic=%u options=%u flags=%u ports=%u endpoints=%u "
        "destinations=%u reversals=%u unaligned=%u boundaries=%u guarded_headers=%u "
        "rust_read_bindings=13 predicate_cases=%u\n",
        arithmetic,options,flags,ports,endpoints,destinations,reversals,unaligned,boundaries,guarded,predicate_entries());
    benchmark();return 0;
}
