/* MIT. Exercise the actual C poll adapter with yield/quit/network mutations. */
#include "engine_loop_windows.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#undef main
static bool bQuit,network;static unsigned mode,queries,steps;
static char trace[8];
#define CHECK(v) do{if(!(v)){fprintf(stderr,"FAIL capture poll line=%d mode=%u %s\n",__LINE__,mode,#v);exit(1);}}while(0)
static void yielded(unsigned delay)
{
    CHECK(delay==0);trace[steps++]='Y';
    if(mode==1)bQuit=true;
    if(mode==2)bQuit=false;
}
static bool logical_net_filter_match_rate_limited(void)
{
    trace[steps++]='N';++queries;bQuit=!bQuit;return network;
}
#undef usleep
#define usleep yielded
#define receive_poll reference_poll
#include "capture_poll_reference.inc"
#undef receive_poll
#include "capture_poll_policy_windows.inc"
int main(void)
{
    unsigned cases=0,short_circuits=0;
    for(mode=0;mode<3;++mode)for(unsigned quit=0;quit<2;++quit)for(unsigned ready=0;ready<2;++ready){
        char previous[8];uint32_t status=99;unsigned count=99;bool final_quit=false;
        for(unsigned side=0;side<2;++side){
            bQuit=quit;network=ready;queries=steps=0;memset(trace,0,sizeof(trace));
            uint32_t current=side?receive_poll():reference_poll();
            CHECK(trace[0]=='Y');
            if(!side){status=current;count=queries;final_quit=bQuit;memcpy(previous,trace,sizeof(trace));}
            else CHECK(status==current && count==queries && final_quit==bQuit && !memcmp(previous,trace,sizeof(trace)));
            if(current==ZAPRET_QUIT){CHECK(queries==0 && steps==1);++short_circuits;}
            else CHECK(queries==1 && steps==2 && current==(ready?ZAPRET_BATCH:ZAPRET_RECONNECT));
        }++cases;
    }
    CHECK(short_circuits);printf("PASS capture_poll cases=%u quit_short_circuits=%u native_order=1\n",cases,short_circuits);return 0;
}
