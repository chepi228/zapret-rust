/* MIT. Whole old/new TCP/UDP/QUIC packet play including final-stage policy. */
#include "packet_finish_contract.inc"
int main(void)
{
    int status=packet_contract_main();
    if(status)return status;
    puts("PASS packet_finish final_stages=1 independent_reference=1");
    return 0;
}
