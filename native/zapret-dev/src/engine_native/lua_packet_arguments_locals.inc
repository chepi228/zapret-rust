/* MIT. Original argument expressions, retaining the C function parameter types. */
static void reference_packet_arguments(const zapret_lua_packet_argument_input *input,
    const t_ctrack *ctrack,const t_ctrack_positions *tpos)
{
    const struct desync_profile *dp=input->profile;const struct dissect *dis=input->packet;
    const t_ctrack_position *pos=input->current,*rpos=input->opposite;
    const char *ifin=input->interface_in,*ifout=input->interface_out;
    const struct in_addr *sdp4=(const struct in_addr *)input->target4;
    const struct in6_addr *sdp6=(const struct in6_addr *)input->target6;
    uint16_t sdport=input->port;bool bIncoming=input->incoming;
    uint32_t fwmark=input->mark;unsigned int replay_piece=input->piece,replay_piece_count=input->pieces;
    t_l7payload l7payload=(t_l7payload)input->payload;t_l7proto l7proto=(t_l7proto)input->protocol;
    size_t reasm_offset=input->reassembly_offset,rlen_payload=input->reassembly_length,len_decrypt=input->decryption_length;
    const uint8_t *rdata_payload=input->reassembly,*data_decrypt=input->decryption;
