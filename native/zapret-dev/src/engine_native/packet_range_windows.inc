/* MIT. Range checks use the native connection counters and wrapping TCP sequence numbers. */
_Static_assert(sizeof(struct packet_range) == 20 && sizeof(struct packet_pos) == 8 &&
    offsetof(struct packet_pos, pos) == 4 && offsetof(struct packet_range, to) == 8 &&
    offsetof(struct packet_range, upper_cutoff) == 16 && sizeof(t_ctrack_position) == 64 &&
    offsetof(t_ctrack_position, pcounter) == 0 && offsetof(t_ctrack_position, pdcounter) == 8 &&
    offsetof(t_ctrack_position, pbcounter) == 16 && offsetof(t_ctrack_position, pos) == 28 &&
    offsetof(t_ctrack_position, seq_last) == 40 && offsetof(t_ctrack_position, seq0) == 44 &&
    offsetof(t_ctrack_position, rseq_over_2G) == 57, "Rust packet range ABI");

uint64_t zapret_packet_position(const t_ctrack_position *, uint8_t);
bool zapret_packet_position_overflow(const t_ctrack_position *, uint8_t);
bool zapret_check_packet_cutoff(const t_ctrack_position *, const struct packet_range *);
bool zapret_check_packet_range(const t_ctrack_position *, const struct packet_range *);

#define pos_get zapret_packet_position
#define pos_overflow zapret_packet_position_overflow
#define check_pos_cutoff zapret_check_packet_cutoff
#define check_pos_range zapret_check_packet_range
