/* MIT. Compare the public pinned protocol API with the Rust implementation. */
#include "protocol_reference.h"
#include "protocol_reference.c"
#undef main
#include <assert.h>
#include <stdio.h>

#include "protocol_helper_reference.inc"

/* The original translation unit is now renamed, so declare the ordinary ABI. */
#include "protocol_ordinary.h"

struct params_s params;
const char *tld[6] = { "com", "org", "net", "edu", "gov", "biz" };
int DLOG(const char *format, ...) { return 0; }
int DLOG_ERR(const char *format, ...) { return 0; }
#include "tls_mod_windows.inc"
#include "quic_vectors.h"

static uint64_t assertions, detector_cases, tls_cases, positions_cases, frame_cases;
static uint64_t tls_boundary_rejections;
static uint64_t tls_mod_cases, tls_mod_atomic_failures, tls_mod_length_fixes;
static uint64_t quic_decrypt_cases, quic_authenticated, quic_atomic_fixes, quic_header_rejections;
static unsigned fixture_id;
#define CHECK(condition) do { ++assertions; if (!(condition)) { \
    fprintf(stderr,"protocol fixture %u failed at line %d: %s\n",fixture_id,__LINE__,#condition); exit(1); } } while(0)

static uint32_t seed=UINT32_C(0x20261115);
static uint32_t random_word(void)
{
    seed=seed*UINT32_C(1664525)+UINT32_C(1013904223);
    return seed^(seed>>16);
}

typedef bool (*detector)(const uint8_t *,size_t);
#define DETECTOR(name) { #name, reference_##name, name }
static struct { const char *name; detector original, rust; unsigned positives; } detectors[] = {
    DETECTOR(IsHttp), DETECTOR(IsHttpReply), DETECTOR(IsTLSRecordFull), DETECTOR(IsTLSHandshakeFull),
    DETECTOR(IsTLSClientHelloPartial), DETECTOR(IsTLSServerHelloPartial), DETECTOR(IsQUICInitial),
    DETECTOR(QUICIsLongHeader), DETECTOR(IsXMPPStream), DETECTOR(IsXMPPStartTLS),
    DETECTOR(IsXMPPProceedTLS), DETECTOR(IsXMPPFeatures), DETECTOR(IsDNSQuery), DETECTOR(IsDNSResponse),
    DETECTOR(IsWireguardHandshakeInitiation), DETECTOR(IsWireguardHandshakeResponse),
    DETECTOR(IsWireguardHandshakeCookie), DETECTOR(IsWireguardKeepalive), DETECTOR(IsWireguardData),
    DETECTOR(IsDht), DETECTOR(IsDiscordIpDiscoveryRequest), DETECTOR(IsStunMessage),
    DETECTOR(IsMTProto), DETECTOR(IsDTLS), DETECTOR(IsDTLSClientHello), DETECTOR(IsDTLSServerHello),
    DETECTOR(IsBTHandshake), DETECTOR(IsUTP_BTHandshake),
};

static void compare_detectors(const uint8_t *data,size_t length)
{
    for(size_t i=0;i<sizeof(detectors)/sizeof(*detectors);++i) {
        bool original=detectors[i].original(data,length), rust=detectors[i].rust(data,length);
        if(original!=rust) fprintf(stderr,"detector %s, length %zu\n",detectors[i].name,length);
        CHECK(original==rust);
        detectors[i].positives+=original;
        ++detector_cases;
    }
}

static void compare_http(const uint8_t *data,size_t length)
{
    static const char *headers[]={"\nHost:","\nLocation:","\ncontent-type:","",":"};
    char a[300],b[300];
    for(size_t field=0;field<sizeof(headers)/sizeof(*headers);++field) {
        for(size_t cap=0;cap<=20;++cap) {
            memset(a,0xa5,sizeof(a));memset(b,0xa5,sizeof(b));
            CHECK(reference_HttpExtractHeader(data,length,headers[field],a,cap)==
                HttpExtractHeader(data,length,headers[field],b,cap));
            CHECK(!memcmp(a,b,sizeof(a)));
        }
    }
    const char *hosts[]={"WWW.Example.COM","a.other.net","localhost","a.","..a","","a.b.c.test"};
    for(size_t i=0;i<sizeof(hosts)/sizeof(*hosts);++i)
        CHECK(reference_HttpReplyLooksLikeDPIRedirect(data,length,hosts[i])==
            HttpReplyLooksLikeDPIRedirect(data,length,hosts[i]));
    uint8_t *a_host=NULL,*b_host=NULL;
    CHECK(reference_HttpFindHost(&a_host,(uint8_t *)data,length)==HttpFindHost(&b_host,(uint8_t *)data,length));
    CHECK(a_host==b_host);
}

/* The migration now rejects fields past the advertised handshake boundary.
   Keep the original algorithm as the oracle for all fields inside that bound. */
static bool extension_in_bounds(const uint8_t *data,const uint8_t *extension,size_t length,bool handshake)
{
    size_t start=handshake ? 0 : 5;
    return (size_t)(extension-data)+length<=start+reference_TLSHandshakeLen(data+start);
}

static bool extension_offset_in_bounds(const uint8_t *data,size_t offset,bool handshake)
{
    if(handshake) return offset+2<=reference_TLSHandshakeLen(data);
    return offset+2<=reference_TLSRecordLen(data) &&
        offset+2<=5+reference_TLSHandshakeLen(data+5);
}

static bool host_extension_in_bounds(const uint8_t *data,size_t length,bool partial,bool handshake)
{
    const uint8_t *extension=NULL;
    size_t extension_length=0;
    bool found=handshake ?
        reference_TLSFindExtInHandshake(data,length,0,&extension,&extension_length,partial) :
        reference_TLSFindExt(data,length,0,&extension,&extension_length,partial);
    return found && extension_in_bounds(data,extension,extension_length,handshake);
}

static ssize_t expected_tls_position(const uint8_t *data,size_t length,t_marker marker,int16_t offset)
{
    if((marker>=PM_HOST && marker<=PM_HOST_ENDSLD) || marker==PM_SNI_EXT) {
        if(!host_extension_in_bounds(data,length,true,false)) return POS_NOT_FOUND;
    } else if(marker==PM_EXT_LEN) {
        size_t position;
        if(!reference_TLSFindExtLen(data,length,&position) ||
            !extension_offset_in_bounds(data,position,false)) return POS_NOT_FOUND;
    }
    return reference_TLSPos(marker,offset,data,length);
}

static void compare_tls(const uint8_t *data,size_t length)
{
    CHECK(reference_TLSHandshakeDataLen(data)==TLSHandshakeDataLen(data));
    CHECK(reference_TLSHandshakeLen(data)==TLSHandshakeLen(data));
    CHECK(reference_TLSRecordDataLen(data)==TLSRecordDataLen(data));
    CHECK(reference_TLSRecordLen(data)==TLSRecordLen(data));
    for(unsigned partial=0;partial<=1;++partial) {
        for(unsigned kind=0;kind<=3;++kind) {
            CHECK(reference_IsTLSHello(data,length,kind,partial)==IsTLSHello(data,length,kind,partial));
            CHECK(reference_IsTLSHandshakeHello(data,length,kind,partial)==IsTLSHandshakeHello(data,length,kind,partial));
        }
        CHECK(reference_IsTLSClientHello(data,length,partial)==IsTLSClientHello(data,length,partial));
        CHECK(reference_IsTLSServerHello(data,length,partial)==IsTLSServerHello(data,length,partial));
        CHECK(reference_IsTLSHandshakeClientHello(data,length,partial)==IsTLSHandshakeClientHello(data,length,partial));
        CHECK(reference_IsTLSHandshakeServerHello(data,length,partial)==IsTLSHandshakeServerHello(data,length,partial));
        for(unsigned type_index=0;type_index<5;++type_index) {
            const uint16_t types[]={0,16,21,43,65037};
            for(unsigned handshake=0;handshake<=1;++handshake) {
                const uint8_t *ap=data+1,*bp=data+1;
                size_t al=12345,bl=12345;
                bool a=handshake ? reference_TLSFindExtInHandshake(data,length,types[type_index],&ap,&al,partial) :
                    reference_TLSFindExt(data,length,types[type_index],&ap,&al,partial);
                bool b=handshake ? TLSFindExtInHandshake(data,length,types[type_index],&bp,&bl,partial) :
                    TLSFindExt(data,length,types[type_index],&bp,&bl,partial);
                bool bounded=a && extension_in_bounds(data,ap,al,handshake);
                tls_boundary_rejections+=a && !bounded;
                CHECK(bounded==b);
                CHECK(b ? ap==bp && al==bl : bp==data+1 && bl==12345);
                ++tls_cases;
            }
        }
        char a[300],b[300];
        for(size_t cap=0;cap<=257;cap+=cap ? 32 : 1) {
            memset(a,0x5a,sizeof(a));memset(b,0x5a,sizeof(b));
            bool original=reference_TLSHelloExtractHost(data,length,a,cap,partial);
            bool bounded=original && host_extension_in_bounds(data,length,partial,false);
            if(!bounded) memset(a,0x5a,sizeof(a));
            CHECK(bounded==TLSHelloExtractHost(data,length,b,cap,partial));
            CHECK(!memcmp(a,b,sizeof(a)));
            memset(a,0x5a,sizeof(a));memset(b,0x5a,sizeof(b));
            original=reference_TLSHelloExtractHostFromHandshake(data,length,a,cap,partial);
            bounded=original && host_extension_in_bounds(data,length,partial,true);
            if(!bounded) memset(a,0x5a,sizeof(a));
            CHECK(bounded==TLSHelloExtractHostFromHandshake(data,length,b,cap,partial));
            CHECK(!memcmp(a,b,sizeof(a)));
        }
    }
    size_t a=12345,b=12345;
    bool original=reference_TLSFindExtLen(data,length,&a);
    bool bounded=original && extension_offset_in_bounds(data,a,false);
    CHECK(bounded==TLSFindExtLen(data,length,&b));
    CHECK(bounded ? a==b : b==12345);
    a=b=12345;
    original=reference_TLSFindExtLenOffsetInHandshake(data,length,&a);
    bounded=original && extension_offset_in_bounds(data,a,true);
    CHECK(bounded==TLSFindExtLenOffsetInHandshake(data,length,&b));
    CHECK(bounded ? a==b : b==12345);
    const uint8_t *ap=data,*bp=data;
    size_t al=length,bl=length,an=123,bn=123;
    CHECK(reference_TLSAdvanceToHostInSNI(&ap,&al,&an)==TLSAdvanceToHostInSNI(&bp,&bl,&bn));
    CHECK(ap==bp && al==bl && an==bn);
}

static void compare_positions(const uint8_t *data,size_t length)
{
    const int16_t offsets[]={INT16_MIN,-80,-5,-1,0,1,2,5,80,INT16_MAX};
    struct proto_pos markers[64];
    unsigned count=0;
    for(unsigned marker=0;marker<=PM_LAST;++marker) {
        for(unsigned i=0;i<sizeof(offsets)/sizeof(*offsets);++i) {
            int16_t offset=offsets[i];
            CHECK(reference_AnyProtoPos(marker,offset,data,length)==AnyProtoPos(marker,offset,data,length));
            CHECK(reference_HttpPos(marker,offset,data,length)==HttpPos(marker,offset,data,length));
            CHECK(expected_tls_position(data,length,marker,offset)==TLSPos(marker,offset,data,length));
            if(count<64) markers[count++]=(struct proto_pos){.pos=offset,.marker=marker};
            ++positions_cases;
        }
    }
    for(unsigned payload=0;payload<L7P_LAST;++payload) {
        ssize_t a[64],b[64];
        memset(a,0xa5,sizeof(a));memset(b,0xa5,sizeof(b));
        int ac=-1,bc=-1;
        if(payload==L7P_TLS_CLIENT_HELLO) {
            ac=0;
            for(unsigned i=0;i<count;++i) {
                ssize_t value=expected_tls_position(data,length,markers[i].marker,markers[i].pos);
                if(value!=POS_NOT_FOUND) a[ac++]=value;
            }
            qsort_ssize_t(a,ac);ac=unique_ssize_t(a,ac);
        } else {
            reference_ResolveMultiPos(data,length,payload,markers,count,a,&ac);
        }
        ResolveMultiPos(data,length,payload,markers,count,b,&bc);
        CHECK(ac==bc && !memcmp(a,b,ac*sizeof(*a)));
    }
}

static size_t client_hello(uint8_t *data,bool server,const char *host)
{
    memset(data,0,512);
    data[0]=0x16;data[1]=3;data[2]=1;
    data[5]=server?2:1;data[9]=3;data[10]=3;
    unsigned offset=44;
    if(server) { data[offset++]=0x13;data[offset++]=1;data[offset++]=0; }
    else { data[offset++]=0;data[offset++]=2;data[offset++]=0x13;data[offset++]=1;data[offset++]=1;data[offset++]=0; }
    unsigned extensions=offset;offset+=2;
    unsigned length=strlen(host);
    data[offset++]=0;data[offset++]=0;
    phton16(data+offset,length+5);offset+=2;
    phton16(data+offset,length+3);offset+=2;
    data[offset++]=0;
    phton16(data+offset,length);offset+=2;
    memcpy(data+offset,host,length);offset+=length;
    data[offset++]=0;data[offset++]=43;data[offset++]=0;data[offset++]=3;
    data[offset++]=2;data[offset++]=3;data[offset++]=4;
    phton16(data+extensions,offset-extensions-2);
    phton16(data+3,offset-5);phton24(data+6,offset-9);
    return offset;
}

static size_t mod_hello(uint8_t *data,const char *host,unsigned sid,unsigned padding)
{
    size_t length=client_hello(data,false,host);
    memmove(data+44+sid,data+44,length-44);
    data[43]=sid;
    for(unsigned i=0;i<sid;++i) data[44+i]=(uint8_t)(i+33);
    length+=sid;
    if(padding) {
        phton16(data+length,21);phton16(data+length+2,5);length+=4;
        memset(data+length,0,5);length+=5;
        if(padding==2) { phton16(data+length,0xffee);phton16(data+length+2,0);length+=4; }
    }
    phton16(data+50+sid,length-52-sid);
    phton16(data+3,length-5);phton24(data+6,length-9);
    return length;
}

static void compare_tls_mod_parser(const char *text)
{
    struct fake_tls_mod original,rust;
    memset(&original,0xa5,sizeof(original));memset(&rust,0xa5,sizeof(rust));
    CHECK(reference_TLSMod_parse_list(text,&original)==TLSMod_parse_list(text,&rust));
    CHECK(!memcmp(&original,&rust,sizeof(rust)));
    ++tls_mod_cases;
}

static void compare_tls_modifications(void)
{
    const char *lists[]={"","none","none=ignored","rnd=ignored,dupsid,","sni=a.b","rnd,rndsni,sni=a.test,padencap,dupsid",
        "sni=","sni","rnd,,dupsid",",rnd",",","unknown","RND","rnd,sni=","sni=last=equals"};
    for(unsigned i=0;i<sizeof(lists)/sizeof(*lists);++i) compare_tls_mod_parser(lists[i]);
    for(unsigned length=0;length<400;++length) {
        char text[440];memcpy(text,"sni=",4);memset(text+4,'a',length);strcpy(text+4+length,",rnd");
        compare_tls_mod_parser(text);
        text[length%4]='=';compare_tls_mod_parser(text);
    }
    const char *hosts[]={"a.b","example.com","","abcdefghijklmnop.example.net"};
    const char *newhosts[]={"x","a.b","","longer.hostname.example.net"};
    const unsigned sessions[]={0,1,2,31,32,255};
    const uint32_t seeds[]={0,1,17,UINT32_MAX};
    for(unsigned round=0;round<24000;++round) {
        ++fixture_id;
        unsigned alignment=round&1;
        uint8_t base[1024],payload[1024],a[1400],b[1400];
        unsigned sid=sessions[random_word()%6],padding=random_word()%3;
        size_t length=mod_hello(base,hosts[random_word()%4],sid,padding);
        size_t payload_length=mod_hello(payload,"real.example.net",sid,1);
        unsigned payload_kind=random_word()%6;
        const uint8_t *real=payload;
        if(payload_kind==0) real=NULL;
        else if(payload_kind==2) payload[43]^=1;
        else if(payload_kind==3) payload_length=43;
        else if(payload_kind==4) payload[0]=0;
        else if(payload_kind==5) payload_length=0;
        struct fake_tls_mod options={0};
        options.mod=random_word()%32;
        strcpy(options.sni,newhosts[random_word()%4]);
        memset(a,0xa5,sizeof(a));memset(b,0xa5,sizeof(b));
        uint8_t *original=a+16+alignment,*rust=b+16+alignment;
        memcpy(original,base,length);memcpy(rust,base,length);
        size_t original_size=length,rust_size=length;
        size_t capacity=length+(random_word()%2 ? 0 : 260);
        uint32_t initial=seeds[random_word()%4];
        params.debug=random_word()%2;
        zapret_srandom(initial);
        bool expected=reference_TLSMod(&options,real,payload_length,original,&original_size,capacity);
        int32_t expected_next=zapret_random();
        zapret_srandom(initial);
        bool actual=TLSMod(&options,real,payload_length,rust,&rust_size,capacity);
        int32_t actual_next=zapret_random();
        if(expected!=actual) fprintf(stderr,"TLS mod flags %u, SID %u, padding %u, payload %u, capacity %zu\n",options.mod,sid,padding,payload_kind,capacity);
        CHECK(expected==actual);
        if(expected) {
            CHECK(original_size==rust_size);
            CHECK(!memcmp(a,b,sizeof(a)));
            CHECK(expected_next==actual_next);
        } else {
            CHECK(rust_size==length);
            CHECK(!memcmp(rust,base,length));
            for(size_t i=length;i<capacity;++i) CHECK(rust[i]==0xa5);
            ++tls_mod_atomic_failures;
        }
        for(unsigned i=0;i<16+alignment;++i) CHECK(b[i]==0xa5);
        for(size_t i=16+alignment+capacity;i<sizeof(b);++i) CHECK(b[i]==0xa5);
        ++tls_mod_cases;
    }

    /* Record growth used to wrap u16 while reporting success. */
    uint8_t original[66000],rust[66000];
    size_t length=mod_hello(original,"a.b",0,1);
    size_t padding_offset=length-7;
    memset(original+length,0,65540-length);
    phton16(original+padding_offset,5+65540-length);
    length=65540;
    phton16(original+3,length-5);phton24(original+6,length-9);phton16(original+50,length-52);
    memcpy(rust,original,length);
    struct fake_tls_mod options={.mod=FAKE_TLS_MOD_SNI};strcpy(options.sni,"a.longer.example.com");
    size_t original_size=length,rust_size=length;
    CHECK(reference_TLSMod(&options,NULL,0,original,&original_size,sizeof(original)));
    CHECK(!TLSMod(&options,NULL,0,rust,&rust_size,sizeof(rust)));
    CHECK(rust_size==length && pntoh16(rust+3)==65535 && original_size>length);
    ++tls_mod_length_fixes;

    /* SIZE_MAX is a length-only input for padencap: no payload bytes are read. */
    length=mod_hello(original,"a.b",0,1);memcpy(rust,original,length);
    options.mod=FAKE_TLS_MOD_PADENCAP;original_size=rust_size=length;
    CHECK(reference_TLSMod(&options,original,SIZE_MAX,original,&original_size,sizeof(original)));
    CHECK(TLSMod(&options,rust,SIZE_MAX,rust,&rust_size,sizeof(rust)));
    CHECK(pntoh16(rust+3)==length-5 && pntoh16(original+3)==length-6);
    ++tls_mod_length_fixes;
}

static void compare_catalog(void)
{
    for(unsigned version=0;version<=UINT16_MAX;++version)
        CHECK(!strcmp(reference_TLSVersionStr(version),TLSVersionStr(version)));
    const char *catalogs[3][40]={{0}};
    for(unsigned i=0;i<L7_LAST;++i) catalogs[0][i]=reference_l7proto_str(i);
    for(unsigned i=0;i<L7P_LAST;++i) catalogs[1][i]=reference_l7payload_str(i);
    for(unsigned i=0;i<PM_LAST;++i) catalogs[2][i]=reference_posmarker_name(i);
    for(unsigned i=0;i<L7_LAST;++i) {
        CHECK(!strcmp(catalogs[0][i],l7proto_str(i)));
        CHECK(reference_l7proto_from_name(catalogs[0][i])==l7proto_from_name(catalogs[0][i]));
    }
    for(unsigned i=0;i<L7P_LAST;++i) {
        CHECK(!strcmp(catalogs[1][i],l7payload_str(i)));
        CHECK(reference_l7payload_from_name(catalogs[1][i])==l7payload_from_name(catalogs[1][i]));
    }
    for(unsigned i=0;i<PM_LAST;++i) CHECK(!strcmp(catalogs[2][i],posmarker_name(i)));
    CHECK(!l7proto_str(L7_LAST) && !l7payload_str(L7P_LAST) && !posmarker_name(PM_LAST));
    for(unsigned i=0;i<PM_LAST;++i)
        CHECK(reference_posmarker_from_name(catalogs[2][i])==posmarker_from_name(catalogs[2][i]));
    const char *invalids[]={"","HTTP","tls ","none","-1","http,quic"};
    for(unsigned i=0;i<sizeof(invalids)/sizeof(*invalids);++i) {
        CHECK(reference_l7proto_from_name(invalids[i])==l7proto_from_name(invalids[i]));
        CHECK(reference_l7payload_from_name(invalids[i])==l7payload_from_name(invalids[i]));
        CHECK(reference_posmarker_from_name(invalids[i])==posmarker_from_name(invalids[i]));
    }
    for(unsigned round=0;round<1000;++round) {
        uint64_t filter=round ? ((uint64_t)random_word()<<32)|random_word() : 0;
        for(unsigned value=0;value<64;++value) {
            CHECK(reference_l7_proto_match(value,filter)==l7_proto_match(value,filter));
            CHECK(reference_l7_payload_match(value,filter)==l7_payload_match(value,filter));
        }
        char a[512],b[512];
        unsigned capacity=round%512;
        memset(a,0xa5,sizeof(a));memset(b,0xa5,sizeof(b));
        CHECK(reference_l7_payload_str_list(filter,a,capacity)==l7_payload_str_list(filter,b,capacity));
        CHECK(!memcmp(a,b,sizeof(a)));
    }
    const uint64_t filters[]={0,1,2,4,8,UINT64_C(1)<<30,UINT64_C(1)<<63,UINT64_MAX};
    for(unsigned i=0;i<sizeof(filters)/sizeof(*filters);++i) {
        for(unsigned capacity=0;capacity<=512;++capacity) {
            char a[512],b[512];
            memset(a,0xa5,sizeof(a));memset(b,0xa5,sizeof(b));
            CHECK(reference_l7_payload_str_list(filters[i],a,capacity)==l7_payload_str_list(filters[i],b,capacity));
            CHECK(!memcmp(a,b,sizeof(a)));
        }
    }
    const char *markers[]={"1","0","-1","32767","-32768","32768","-32769","4294967296",
        "host","endhost-1","sld+2","midsld","endsld+","method-","extlen+3","sniext-2",
        "host+garbage","--5","+","-","12garbage"," abs","ABS","","host-99999",
        "host,1,midsld-2","1,","1,,2",",1","host+32768","1,2,3,4,5",
        "0000000000000000000000000000000000000000000000000000000000000000000000000000012",
        "-0000000000000000000000000000000000000000000000000000000000000000000000000000012",
        "+ 123","99999999999999999999999999999999999999999999999999999999999999999999999999"};
    for(unsigned i=0;i<sizeof(markers)/sizeof(*markers);++i) {
        struct proto_pos a={.pos=123,.marker=33},b=a;
        CHECK(reference_posmarker_parse(markers[i],&a)==posmarker_parse(markers[i],&b));
        CHECK(a.pos==b.pos && a.marker==b.marker);
        for(unsigned capacity=0;capacity<6;++capacity) {
            struct proto_pos aa[8],bb[8];
            memset(aa,0xa5,sizeof(aa));memset(bb,0xa5,sizeof(bb));
            int ac=capacity,bc=capacity;
            CHECK(reference_posmarker_list_parse(markers[i],aa,&ac)==posmarker_list_parse(markers[i],bb,&bc));
            CHECK(ac==bc && !memcmp(aa,bb,sizeof(aa)));
        }
    }
}

static void compare_defrag(const uint8_t *data,size_t length,size_t capacity)
{
    uint8_t a[4096],b[4096];
    memset(a,0xa5,sizeof(a));memset(b,0xa5,sizeof(b));
    size_t al=capacity,bl=capacity;
    bool af=false,bf=false;
    CHECK(reference_QUICDefragCrypto(data,length,a,&al,&af)==QUICDefragCrypto(data,length,b,&bl,&bf));
    CHECK(al==bl && af==bf && !memcmp(a,b,sizeof(a)));
    ++frame_cases;
}

static size_t write_variable(uint8_t *data,uint64_t value,unsigned width)
{
    for(unsigned i=0;i<width;++i) data[width-i-1]=value>>(8*i);
    unsigned prefix=width==1 ? 0 : width==2 ? 1 : width==4 ? 2 : 3;
    data[0]|=prefix<<6;
    return width;
}

static void compare_fragment_boundaries(void)
{
    uint8_t data[4096];
    const unsigned widths[]={1,2,4,8};
    for(unsigned first=0;first<4;++first) {
        for(unsigned second=0;second<4;++second) {
            size_t length=0;
            const unsigned starts[]={16,0,8,0};
            const unsigned sizes[]={8,16,16,16};
            for(unsigned i=0;i<4;++i) {
                data[length++]=6;
                length+=write_variable(data+length,starts[i],widths[first]);
                length+=write_variable(data+length,sizes[i],widths[second]);
                memset(data+length,'a'+i,sizes[i]);length+=sizes[i];
            }
            for(size_t cut=0;cut<=length;++cut) {
                ++fixture_id;compare_defrag(data,cut,128);
            }
            for(size_t capacity=0;capacity<=40;++capacity) {
                ++fixture_id;compare_defrag(data,length,capacity);
            }
        }
    }
    for(unsigned pieces=127;pieces<=129;++pieces) {
        size_t length=0;
        for(unsigned i=0;i<pieces;++i) {
            data[length++]=6;
            length+=write_variable(data+length,i,2);
            data[length++]=1;data[length++]=i;
        }
        ++fixture_id;compare_defrag(data,length,sizeof(data));
    }
    size_t length=0;
    for(unsigned i=0;i<200;++i) {
        data[length++]=6;data[length++]=0;data[length++]=1;data[length++]=i;
    }
    ++fixture_id;compare_defrag(data,length,sizeof(data));
}

static void compare_quic(const uint8_t *data,size_t length)
{
    uint32_t version=QUICExtractVersion(data,length);
    CHECK(reference_QUICExtractVersion(data,length)==version);
    CHECK(reference_QUICDraftVersion(version)==QUICDraftVersion(version));
    quic_cid_t a,b;
    memset(&a,0xa5,sizeof(a));memset(&b,0xa5,sizeof(b));
    CHECK(reference_QUICExtractDCID(data,length,&a)==QUICExtractDCID(data,length,&b));
    CHECK(!memcmp(&a,&b,sizeof(a)));
    size_t ao=123,bo=123,al=456,bl=456;
    CHECK(reference_IsQUICCryptoHello(data,length,&ao,&al)==IsQUICCryptoHello(data,length,&bo,&bl));
    CHECK(ao==bo && al==bl);
}

static void signature_boundaries(uint8_t *data,size_t length)
{
    for(size_t cut=0;cut<=length;++cut) {
        ++fixture_id;
        compare_detectors(data,cut);compare_quic(data,cut);
    }
    for(size_t byte=0;byte<length;++byte) {
        uint8_t saved=data[byte];
        data[byte]^=0xff;
        ++fixture_id;compare_detectors(data,length);compare_quic(data,length);
        data[byte]=saved;
    }
}

static void compare_signatures(void)
{
    uint8_t data[4096];
    const char *xmpp[]={"<stream:stream >","<?xml version='1.0' ?><stream:stream >",
        "<starttls ","<proceed ","<stream:features>"};
    for(unsigned i=0;i<sizeof(xmpp)/sizeof(*xmpp);++i) {
        memset(data,0,sizeof(data));memcpy(data,xmpp[i],strlen(xmpp[i]));
        signature_boundaries(data,strlen(xmpp[i]));
    }
    memset(data,0,sizeof(data));data[5]=1;
    signature_boundaries(data,12);
    data[2]=0x80;signature_boundaries(data,12);
    const unsigned lengths[]={148,92,64,32,52};
    for(unsigned i=0;i<5;++i) {
        memset(data,0,sizeof(data));data[0]=i<3 ? i+1 : 4;
        signature_boundaries(data,lengths[i]);
    }
    memset(data,0,sizeof(data));memcpy(data,"d1:ade",6);signature_boundaries(data,6);
    memset(data,0,sizeof(data));data[1]=1;data[3]=70;signature_boundaries(data,74);
    memset(data,0,sizeof(data));phton32(data+4,0x2112a442);signature_boundaries(data,20);
    for(unsigned type=1;type<=2;++type) {
        memset(data,0,sizeof(data));data[0]=0x16;data[1]=0xfe;data[2]=0xfd;data[12]=1;data[13]=type;
        signature_boundaries(data,14);
    }
    memset(data,0,sizeof(data));memcpy(data,"\x13""BitTorrent protocol",20);signature_boundaries(data,68);
    memset(data,0,sizeof(data));data[0]=1;memcpy(data+20,"\x13""BitTorrent protocol",20);signature_boundaries(data,88);
    for(unsigned wrap=0;wrap<4;++wrap) {
        for(unsigned i=0;i<sizeof(data);++i) data[i]=random_word();
        if(wrap) memset(data+40,0xff,16);
        data[55]-=wrap;
        uint8_t counter[16],encrypted[16];
        aes_context context;
        memcpy(counter,data+40,16);ctr_add(counter,3);
        CHECK(!aes_setkey(&context,AES_ENCRYPT,data+8,32));
        CHECK(!aes_cipher(&context,counter,encrypted));
        for(unsigned i=0;i<4;++i) data[56+i]=encrypted[8+i]^0xef;
        CHECK(reference_IsMTProto(data,64) && IsMTProto(data,64));
        signature_boundaries(data,64);
    }
    const uint32_t versions[]={1,0x6b3343cf,0x709a50c4,0xfaceb001,0xfaceb002,0xfaceb00e,
        0x51303530,0x54303530,0x54303531,0xff00000a,0xff00000b,0xff00001b,0xff00001d,0x1a2a3a4a};
    for(unsigned i=0;i<sizeof(versions)/sizeof(*versions);++i) {
        memset(data,0,sizeof(data));
        data[0]=(versions[i]==0x6b3343cf || versions[i]==0x709a50c4) ? 0xd0 : 0xc0;
        phton32(data+1,versions[i]);
        data[5]=8;memset(data+6,0xab,8);data[14]=0;data[15]=0;data[16]=0;
        signature_boundaries(data,128);
    }
    for(unsigned i=0;i<10000;++i) {
        uint32_t version=random_word();
        CHECK(reference_QUICDraftVersion(version)==QUICDraftVersion(version));
    }
    size_t record_length=client_hello(data,false,"www.example.test");
    size_t handshake_length=record_length-5;
    memmove(data+4,data+5,handshake_length);
    data[0]=6;data[1]=0;data[2]=0x40|(handshake_length>>8);data[3]=handshake_length;
    signature_boundaries(data,handshake_length+4);
    size_t offset=0,length=0;
    CHECK(IsQUICCryptoHello(data,handshake_length+4,&offset,&length));
    CHECK(offset==4 && length==handshake_length);
}

static unsigned encode_variable(uint8_t *out,uint64_t value,unsigned width)
{
    while(width<8 && value >= (UINT64_C(1)<<(8*width-2))) width*=2;
    for(unsigned i=0;i<width;++i) out[i]=(uint8_t)(value>>(8*(width-1-i)));
    out[0]|=(width==1?0:width==2?1:width==4?2:3)<<6;
    return width;
}

static size_t encrypted_initial(uint8_t *data,uint32_t version,unsigned dcid_length,unsigned scid_length,
    unsigned token,unsigned width,unsigned number_length,uint32_t number,size_t plaintext_length,unsigned invalid_bits)
{
    data[0]=(is_quic_v2(version)?0xd0:0xc0)|(number_length-1)|invalid_bits;phton32(data+1,version);
    data[5]=dcid_length;
    quic_cid_t dcid={.len=dcid_length};
    for(unsigned i=0;i<dcid_length;++i) data[6+i]=dcid.cid[i]=(uint8_t)(i+version);
    size_t offset=6+dcid_length;data[offset++]=scid_length;
    for(unsigned i=0;i<scid_length;++i) data[offset++]=(uint8_t)(i+77);
    offset+=encode_variable(data+offset,token,width);memset(data+offset,0xa7,token);offset+=token;
    if(plaintext_length+number_length<4) plaintext_length=4-number_length;
    offset+=encode_variable(data+offset,number_length+plaintext_length+16,width);
    size_t number_offset=offset;
    uint32_t truncated=number&(uint32_t)((UINT64_C(1)<<(8*number_length))-1);
    for(unsigned i=0;i<number_length;++i) data[offset++]=(uint8_t)(truncated>>(8*(number_length-i-1)));
    uint8_t secret[32],key[16],iv[12],hp[16];
    CHECK(quic_derive_initial_secret(&dcid,secret,version));
    CHECK(quic_hkdf_expand_label(secret,32,is_quic_v2(version)?"tls13 quicv2 key":"tls13 quic key",key,16));
    CHECK(quic_hkdf_expand_label(secret,32,is_quic_v2(version)?"tls13 quicv2 iv":"tls13 quic iv",iv,12));
    CHECK(quic_hkdf_expand_label(secret,32,is_quic_v2(version)?"tls13 quicv2 hp":"tls13 quic hp",hp,16));
    phton64(iv+4,pntoh64(iv+4)^truncated);
    static uint8_t plaintext[65536];
    for(size_t i=0;i<plaintext_length;++i) plaintext[i]=(uint8_t)(i*17+3);
    CHECK(!aes_gcm_crypt(AES_ENCRYPT,data+offset,plaintext,plaintext_length,key,16,iv,12,data,offset,data+offset+plaintext_length,16));
    aes_context context;uint8_t mask[16];
    CHECK(!aes_setkey(&context,1,hp,16));CHECK(!aes_cipher(&context,data+number_offset+4,mask));
    data[0]^=mask[0]&15;
    for(unsigned i=0;i<number_length;++i) data[number_offset+i]^=mask[i+1];
    return offset+plaintext_length+16;
}

static bool compare_initial(const uint8_t *data,size_t length,size_t capacity,bool reject_header)
{
    static uint8_t original[65600],rust[65600],sentinel[65600];
    CHECK(capacity<=65535);
    memset(original,0xa5,sizeof(original));memset(rust,0xa5,sizeof(rust));memset(sentinel,0xa5,sizeof(sentinel));
    size_t old_size=capacity,new_size=capacity;
    bool old=reference_QUICDecryptInitial(data,length,original+16,&old_size);
    bool actual=QUICDecryptInitial(data,length,rust+16,&new_size);
    if(reject_header) { CHECK(old);CHECK(!actual);++quic_header_rejections; }
    else { CHECK(old==actual); }
    if(actual) {
        CHECK(old_size==new_size && new_size<=capacity);
        CHECK(!memcmp(original+16,rust+16,new_size));
        CHECK(!memcmp(rust,sentinel,16));
        CHECK(!memcmp(rust+16+new_size,sentinel+16+new_size,sizeof(rust)-16-new_size));
        ++quic_authenticated;
    } else {
        CHECK(new_size==capacity);CHECK(!memcmp(rust,sentinel,sizeof(rust)));
        if(old_size!=capacity || memcmp(original,sentinel,sizeof(original))) ++quic_atomic_fixes;
    }
    ++quic_decrypt_cases;
    return actual;
}

static void compare_initial_decryption(void)
{
    const uint8_t *vectors[]={quic_v1,quic_v2};
    for(unsigned vector=0;vector<2;++vector) {
        CHECK(compare_initial(vectors[vector],1200,1200,false));
        uint8_t decoded[1200];size_t decoded_length=sizeof(decoded);
        CHECK(QUICDecryptInitial(vectors[vector],1200,decoded,&decoded_length));
        CHECK(decoded_length==1162 && !memcmp(decoded,quic_crypto,sizeof(quic_crypto)));
        for(size_t i=sizeof(quic_crypto);i<decoded_length;++i) CHECK(decoded[i]==0);
        for(size_t cut=0;cut<1200;++cut) CHECK(!compare_initial(vectors[vector],cut,1200,false));
        for(size_t byte=0;byte<1200;++byte) {
            uint8_t corrupted[1200];memcpy(corrupted,vectors[vector],1200);corrupted[byte]^=1;
            CHECK(!compare_initial(corrupted,1200,1200,false));
        }
    }
    const uint32_t versions[]={1,0x6b3343cf,0x709a50c4,0xff00000b,0xff000016,0xff000017,0xff00001c,0xff00001d,
        0xff000020,0xff000021,0xff000022,0xfaceb001,0xfaceb002,0xfaceb00e,0x51303530,0x54303530,0x54303531,0x1a2a3a4a,0xdeadbeef};
    const unsigned widths[]={1,2,4,8};
    const unsigned tokens[]={0,1,31,300};
    const unsigned lengths[]={0,1,3,16,31,255,1200,4096};
    static uint8_t packet[70000];
    for(unsigned round=0;round<4000;++round) {
        ++fixture_id;
        unsigned number_length=1+random_word()%4;
        size_t plaintext_length=lengths[random_word()%8];
        if(plaintext_length+number_length<4) plaintext_length=4-number_length;
        size_t length=encrypted_initial(packet,versions[random_word()%19],1+random_word()%20,random_word()%21,
            tokens[random_word()%4],widths[random_word()%4],number_length,random_word(),plaintext_length,0);
        CHECK(compare_initial(packet,length,plaintext_length,false));
        if(plaintext_length) CHECK(!compare_initial(packet,length,plaintext_length-1,false));
        packet[length-1]^=1;CHECK(!compare_initial(packet,length,65535,false));
    }
    for(unsigned number_length=1;number_length<=4;++number_length) {
        size_t length=encrypted_initial(packet,1,20,20,0,8,number_length,UINT32_MAX,65000,0);
        CHECK(compare_initial(packet,length,65000,false));
    }
    for(unsigned token=2000;token<=2050;++token) {
        size_t length=encrypted_initial(packet,1,8,0,token,1,4,1,32,0);
        compare_initial(packet,length,65535,false);
    }
    size_t length=encrypted_initial(packet,1,8,21,0,1,4,1,32,0);
    CHECK(!compare_initial(packet,length,65535,true));
    length=encrypted_initial(packet,1,8,0,0,1,4,1,32,4);
    CHECK(!compare_initial(packet,length,65535,true));
    length=encrypted_initial(packet,1,8,0,0,1,4,1,32,0x20);
    CHECK(!compare_initial(packet,length,65535,true));
}

static int compare_double(const void *left,const void *right)
{
    double a=*(const double *)left,b=*(const double *)right;
    return (a>b)-(a<b);
}

static void benchmark_tls_mod(void)
{
    enum { ROUNDS=40, ITERATIONS=2000 };
    const unsigned flags[]={FAKE_TLS_MOD_SNI,FAKE_TLS_MOD_RND|FAKE_TLS_MOD_DUP_SID,
        FAKE_TLS_MOD_SNI|FAKE_TLS_MOD_RND_SNI|FAKE_TLS_MOD_PADENCAP,31};
    typedef bool (*modifier)(const struct fake_tls_mod *,const uint8_t *,size_t,uint8_t *,size_t *,size_t);
    modifier functions[]={reference_TLSMod,TLSMod};
    LARGE_INTEGER frequency;CHECK(QueryPerformanceFrequency(&frequency));
    printf("{\"unit\":\"ns/op\",\"rounds\":%u,\"iterations_per_round\":%u,\"measurement\":\"Quantiles of amortized batch timings, including identical fake reset copies; logger is a no-op\",\"cases\":[",ROUNDS,ITERATIONS);
    for(unsigned mode=0;mode<2;++mode) for(unsigned variant=0;variant<4;++variant) {
        params.debug=mode;
        uint8_t base[1024],payload[1024],buffer[1024];
        size_t length=mod_hello(base,"example.com",32,1);
        size_t payload_length=mod_hello(payload,"real.example.net",32,1);
        struct fake_tls_mod options={.mod=flags[variant]};strcpy(options.sni,"different.example.net");
        double samples[2][ROUNDS];
        for(unsigned round=0;round<ROUNDS+5;++round) {
            for(unsigned order=0;order<2;++order) {
                unsigned function=(round+order)&1;
                zapret_srandom(17);
                LARGE_INTEGER begin,end;CHECK(QueryPerformanceCounter(&begin));
                for(unsigned iteration=0;iteration<ITERATIONS;++iteration) {
                    memcpy(buffer,base,length);size_t size=length;
                    if(!functions[function](&options,payload,payload_length,buffer,&size,sizeof(buffer))) exit(2);
                }
                CHECK(QueryPerformanceCounter(&end));
                if(round>=5) samples[function][round-5]=(double)(end.QuadPart-begin.QuadPart)*1e9/frequency.QuadPart/ITERATIONS;
            }
        }
        if(mode || variant) printf(",");
        printf("{\"flags\":%u,\"debug_allocations_enabled\":%s",flags[variant],mode?"true":"false");
        for(unsigned function=0;function<2;++function) {
            qsort(samples[function],ROUNDS,sizeof(double),compare_double);
            printf(",\"%s\":{\"p50\":%.3f,\"p95\":%.3f,\"p99\":%.3f}",function?"rust":"original_c",
                samples[function][ROUNDS/2-1],samples[function][ROUNDS*95/100-1],samples[function][ROUNDS-1]);
        }
        printf("}");
    }
    printf("]}\n");
}

static void benchmark_quic_decrypt(void)
{
    enum { ROUNDS=40, ITERATIONS=256 };
    typedef bool (*decoder)(const uint8_t *,size_t,uint8_t *,size_t *);
    decoder functions[]={reference_QUICDecryptInitial,QUICDecryptInitial};
    LARGE_INTEGER frequency;CHECK(QueryPerformanceFrequency(&frequency));
    printf("{\"unit\":\"ns/op\",\"rounds\":%u,\"iterations_per_round\":%u,\"measurement\":\"Quantiles of amortized complete decryption batches, including HKDF, header protection and tag verification\",\"cases\":[",ROUNDS,ITERATIONS);
    static uint8_t packet[18000],plaintext[65535];
    for(unsigned variant=0;variant<4;++variant) {
        uint32_t version=variant==1?0x6b3343cf:variant==2?0xff00001d:1;
        size_t length;
        if(variant<2) { memcpy(packet,variant?quic_v2:quic_v1,1200);length=1200; }
        else length=encrypted_initial(packet,version,8,0,0,1,4,17,variant==2?64:16384,0);
        double samples[2][ROUNDS];
        for(unsigned round=0;round<ROUNDS+5;++round) for(unsigned order=0;order<2;++order) {
            unsigned function=(round+order)&1;
            LARGE_INTEGER begin,end;CHECK(QueryPerformanceCounter(&begin));
            for(unsigned iteration=0;iteration<ITERATIONS;++iteration) {
                size_t capacity=sizeof(plaintext);
                if(!functions[function](packet,length,plaintext,&capacity)) exit(3);
            }
            CHECK(QueryPerformanceCounter(&end));
            if(round>=5) samples[function][round-5]=(double)(end.QuadPart-begin.QuadPart)*1e9/frequency.QuadPart/ITERATIONS;
        }
        if(variant) printf(",");
        printf("{\"version\":%u,\"packet_bytes\":%zu",version,length);
        for(unsigned function=0;function<2;++function) {
            qsort(samples[function],ROUNDS,sizeof(double),compare_double);
            printf(",\"%s\":{\"p50\":%.3f,\"p95\":%.3f,\"p99\":%.3f}",function?"rust":"original_c",
                samples[function][ROUNDS/2-1],samples[function][ROUNDS*95/100-1],samples[function][ROUNDS-1]);
        }
        printf("}");
    }
    printf("]}\n");
}

int main(int argc,char **argv)
{
    aes_init_keygen_tables();
    if(argc==2 && !strcmp(argv[1],"--benchmark")) { benchmark_tls_mod();return 0; }
    if(argc==2 && !strcmp(argv[1],"--quic-benchmark")) { benchmark_quic_decrypt();return 0; }
    compare_catalog();
    compare_signatures();
    compare_fragment_boundaries();
    compare_tls_modifications();
    compare_initial_decryption();
    uint8_t data[4096];
    const char *http[]={
        "GET / HTTP/1.1\r\nHost: WWW.Example.COM\r\n\r\n",
        "\r\nGET / HTTP/1.1\r\nhOsT:\t a.b.Example.COM:443\r\n",
        "POST\t/ HTTP/1.1\r\nHost: a.test\r\n",
        "HTTP/1.1 302 Found\r\nLocation: HTTPS://Different.NET/block\r\n\r\n",
        "HTTP/1.0 307 Found\r\nLocation: https://www.example.com/path\r\n",
    };
    for(unsigned i=0;i<sizeof(http)/sizeof(*http);++i) {
        memset(data,0,sizeof(data));memcpy(data,http[i],strlen(http[i]));
        for(size_t length=0;length<=strlen(http[i]);++length) {
            ++fixture_id;
            compare_detectors(data,length);compare_http(data,length);compare_positions(data,length);
        }
    }
    for(unsigned server=0;server<=1;++server) {
        const char *hosts[]={"WWW.Example.COM","a.b.c.test","a.","..a",""};
        for(unsigned host=0;host<sizeof(hosts)/sizeof(*hosts);++host) {
            size_t length=client_hello(data,server,hosts[host]);
            compare_detectors(data+5,length-5);
            for(size_t cut=0;cut<=length+8;++cut) {
                ++fixture_id;
                compare_detectors(data,cut);compare_tls(data,cut);compare_positions(data,cut);
            }
            /* Every length-field byte, including values outside the record. */
            for(size_t byte=0;byte<length;++byte) {
                uint8_t saved=data[byte];
                for(unsigned value=0;value<256;value+=17) {
                    data[byte]=value;++fixture_id;
                    compare_detectors(data,length);compare_tls(data,length);compare_positions(data,length);
                }
                data[byte]=saved;
            }
        }
    }
    for(unsigned round=0;round<6000;++round) {
        size_t length=random_word()%512;
        for(size_t i=0;i<sizeof(data);++i) data[i]=random_word();
        ++fixture_id;compare_detectors(data,length);compare_tls(data,length);
        compare_quic(data,length);
        if(round%31==0) { compare_http(data,length);compare_positions(data,length); }
        compare_defrag(data,length,round%4097);
    }
    for(size_t i=0;i<sizeof(detectors)/sizeof(*detectors);++i) {
        if(!detectors[i].positives) fprintf(stderr,"no positive fixture for %s\n",detectors[i].name);
        CHECK(detectors[i].positives);
    }
    for(unsigned round=0;round<6000;++round) {
        size_t length=0;
        unsigned pieces=1+random_word()%140;
        for(unsigned i=0;i<pieces;++i) {
            if(random_word()%3==0) data[length++]=random_word()&1;
            data[length++]=6;data[length++]=random_word()%40;data[length++]=random_word()%20;
            unsigned size=data[length-1];
            for(unsigned j=0;j<size;++j) data[length++]=random_word();
        }
        ++fixture_id;compare_defrag(data,length,round%137);
        size_t a=123,b=456,c=a,d=b;
        CHECK(reference_IsQUICCryptoHello(data,length,&a,&b)==IsQUICCryptoHello(data,length,&c,&d));
        CHECK(a==c && b==d);
    }
    printf("PASS %llu assertions, %llu protocol detections, %llu TLS extension searches, %llu marker positions and %llu QUIC defragmentations; %llu out-of-handshake TLS fields rejected; %llu TLS modification cases, %llu atomic failure cases and %llu TLS length fixes; %llu QUIC decrypt cases, %llu authenticated, %llu atomic output fixes and %llu invalid header rejections\n",
        (unsigned long long)assertions,(unsigned long long)detector_cases,(unsigned long long)tls_cases,
        (unsigned long long)positions_cases,(unsigned long long)frame_cases,
        (unsigned long long)tls_boundary_rejections,(unsigned long long)tls_mod_cases,
        (unsigned long long)tls_mod_atomic_failures,(unsigned long long)tls_mod_length_fixes,
        (unsigned long long)quic_decrypt_cases,(unsigned long long)quic_authenticated,
        (unsigned long long)quic_atomic_fixes,(unsigned long long)quic_header_rejections);
    return 0;
}
