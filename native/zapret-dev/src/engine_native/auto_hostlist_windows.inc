/* MIT. Native cache, file, logging and send boundaries for Rust failure detection. */
typedef struct zapret_autolist_context {
    struct desync_profile *profile;
    const char *hostname, *client_text;
    const struct sockaddr *client;
    const char *interface;
    t_ctrack *track;
    uint32_t l7, flags;
    bool no_subdomains;
} zapret_autolist_context;

typedef struct {
    hostfail_pool *(*find_counter)(struct desync_profile *, const char *);
    hostfail_pool *(*add_counter)(struct desync_profile *, const char *, int32_t);
    void (*remove_counter)(struct desync_profile *, hostfail_pool *);
    bool (*check_host)(const struct desync_profile *, const char *, bool, bool *, bool);
    bool (*append)(const zapret_autolist_context *);
    bool (*stamp)(const zapret_autolist_context *);
    bool (*send)(const zapret_autolist_context *, const uint8_t *, size_t);
    void (*report)(uint32_t, const zapret_autolist_context *, uint64_t, uint64_t, uint64_t, uint64_t);
} zapret_autolist_ops;

typedef struct {
    t_ctrack *track;
    struct desync_profile *profile;
    const struct sockaddr *client;
    const char *interface;
    uint32_t l7;
} zapret_autolist_track_input;

typedef struct {
    const zapret_autolist_ops *effects;
    const bool *server, *debug;
    const char *append_path;
    void (*format_client)(const struct sockaddr *, char *, size_t);
} zapret_autolist_track_ops;

enum zapret_autolist_track_kind { AUTOLIST_TCP, AUTOLIST_UDP, AUTOLIST_INCOMING };

void zapret_autolist_track(const zapret_autolist_track_input *, uint32_t, const struct dissect *,
    const t_ctrack_positions *, uint32_t, const zapret_autolist_track_ops *);

#define AUTO_HOSTLIST_SETTINGS_OFFSET (sizeof(void *) == 8 ? 104 : 56)
_Static_assert(offsetof(struct desync_profile, hostlist_auto) == AUTO_HOSTLIST_SETTINGS_OFFSET &&
    offsetof(struct desync_profile, hostlist_auto_fail_threshold) == AUTO_HOSTLIST_SETTINGS_OFFSET + sizeof(void *) &&
    offsetof(struct desync_profile, hostlist_auto_fail_time) == AUTO_HOSTLIST_SETTINGS_OFFSET + sizeof(void *) + 4 &&
    offsetof(struct desync_profile, hostlist_auto_retrans_threshold) == AUTO_HOSTLIST_SETTINGS_OFFSET + sizeof(void *) + 8 &&
    offsetof(struct desync_profile, hostlist_auto_udp_in) == AUTO_HOSTLIST_SETTINGS_OFFSET + sizeof(void *) + 12 &&
    offsetof(struct desync_profile, hostlist_auto_udp_out) == AUTO_HOSTLIST_SETTINGS_OFFSET + sizeof(void *) + 16 &&
    offsetof(struct desync_profile, hostlist_auto_retrans_maxseq) == AUTO_HOSTLIST_SETTINGS_OFFSET + sizeof(void *) + 20 &&
    offsetof(struct desync_profile, hostlist_auto_incoming_maxseq) == AUTO_HOSTLIST_SETTINGS_OFFSET + sizeof(void *) + 24 &&
    offsetof(struct desync_profile, hostlist_auto_retrans_reset) == AUTO_HOSTLIST_SETTINGS_OFFSET + sizeof(void *) + 28,
    "Rust auto hostlist settings ABI");
#undef AUTO_HOSTLIST_SETTINGS_OFFSET
_Static_assert(offsetof(t_ctrack, pos) == 24 && offsetof(t_ctrack, dp) == 184 &&
    offsetof(t_ctrack_position, winsize) == 48 && offsetof(t_ctrack_position, ip6flow) == 24 &&
    SYN == 0 && RETRANS_COUNTER_STOP == 255 && L7P_HTTP_REPLY == 8, "Rust failure tracking ABI");
_Static_assert(sizeof(zapret_autolist_context) == (sizeof(void *) == 8 ? 64 : 36) &&
    offsetof(zapret_autolist_context, l7) == 6 * sizeof(void *) &&
    offsetof(struct zapret_list_file, hostlist) == 32, "Rust auto hostlist context ABI");
_Static_assert(sizeof(zapret_autolist_track_input) == 5 * sizeof(void *) &&
    offsetof(zapret_autolist_track_input, l7) == 4 * sizeof(void *) &&
    sizeof(zapret_autolist_track_ops) == 5 * sizeof(void *) &&
    offsetof(zapret_autolist_track_ops, format_client) == 4 * sizeof(void *), "Rust auto hostlist track ABI");

static hostfail_pool *autolist_find_counter(struct desync_profile *profile, const char *host)
{
    return HostFailPoolFind(profile->hostlist_auto_fail_counters, host);
}
static hostfail_pool *autolist_add_counter(struct desync_profile *profile, const char *host, int32_t timeout)
{
    return HostFailPoolAdd(&profile->hostlist_auto_fail_counters, host, timeout);
}
static void autolist_remove_counter(struct desync_profile *profile, hostfail_pool *counter)
{
    HostFailPoolDel(&profile->hostlist_auto_fail_counters, counter);
}
static bool autolist_append(const zapret_autolist_context *c)
{
    return append_to_list_file(c->profile->hostlist_auto->filename, c->hostname);
}
static bool autolist_stamp(const zapret_autolist_context *c)
{
    return file_mod_signature(c->profile->hostlist_auto->filename, &c->profile->hostlist_auto->mod_sig);
}
static bool autolist_send(const zapret_autolist_context *c, const uint8_t *packet, size_t length)
{
    return rawsend(c->client, 0, c->interface, packet, length);
}

static void autolist_report(uint32_t event, const zapret_autolist_context *c,
    uint64_t a, uint64_t b, uint64_t d, uint64_t e)
{
    struct desync_profile *dp = c->profile;
    switch (event) {
    case 0:
        DLOG("auto hostlist (profile %u (%s)) : %s : fail counter reset. website is working.\n", dp->n, PROFILE_NAME(dp), c->hostname);
        HOSTLIST_DEBUGLOG_APPEND("%s : profile %u (%s) : client %s : proto %s : fail counter reset. website is working.",
            c->hostname, dp->n, PROFILE_NAME(dp), c->client_text, l7proto_str(c->l7));
        break;
    case 1:
        DLOG("retrans : tcp seq %u not within range %u-%u. stop tracking.\n", (uint32_t)a, (uint32_t)b, (uint32_t)d);
        break;
    case 2: DLOG("retrans threshold reached : %u/%u\n", (unsigned)a, (unsigned)b); break;
    case 3: DLOG("sending RST to retransmitter. ifname=%s\n", c->interface ? c->interface : ""); break;
    case 4: DLOG("retrans counter : %u/%u\n", (unsigned)a, (unsigned)b); break;
    case 5: DLOG_ERR("HostFailPoolAdd: out of memory\n"); break;
    case 6:
        DLOG("auto hostlist (profile %u (%s)) : %s : fail counter %d/%d\n", dp->n, PROFILE_NAME(dp), c->hostname, (int)a, (int)b);
        HOSTLIST_DEBUGLOG_APPEND("%s : profile %u (%s) : client %s : proto %s : fail counter %d/%d",
            c->hostname, dp->n, PROFILE_NAME(dp), c->client_text, l7proto_str(c->l7), (int)a, (int)b);
        break;
    case 7:
        DLOG("auto hostlist (profile %u (%s)) : fail threshold reached. about to add %s to auto hostlist\n", dp->n, PROFILE_NAME(dp), c->hostname);
        break;
    case 8:
        DLOG("auto hostlist (profile %u (%s)) : rechecking %s to avoid duplicates\n", dp->n, PROFILE_NAME(dp), c->hostname);
        break;
    case 9:
        DLOG("auto hostlist (profile %u) : adding %s to %s\n", dp->n, c->hostname, dp->hostlist_auto->filename);
        HOSTLIST_DEBUGLOG_APPEND("%s : profile %u (%s) : client %s : proto %s : adding to %s",
            c->hostname, dp->n, PROFILE_NAME(dp), c->client_text, l7proto_str(c->l7), dp->hostlist_auto->filename);
        break;
    case 10:
        DLOG("auto hostlist (profile %u) : NOT adding %s\n", dp->n, c->hostname);
        HOSTLIST_DEBUGLOG_APPEND("%s : profile %u (%s) : client %s : proto %s : NOT adding, duplicate detected",
            c->hostname, dp->n, PROFILE_NAME(dp), c->client_text, l7proto_str(c->l7));
        break;
    case 11: DLOG_ERR("StrPoolAddStr out of memory\n"); break;
    case 12: DLOG_PERROR("write to auto hostlist"); break;
    case 13: DLOG_PERROR("file_mod_signature"); break;
    case 14:
        HOSTLIST_DEBUGLOG_APPEND("%s : profile %u (%s) : client %s : proto %s : retrans threshold reached",
            c->hostname, dp->n, PROFILE_NAME(dp), c->client_text, l7proto_str(c->l7));
        break;
    case 15: DLOG("udp_in %u > %u\n", (unsigned)a, (unsigned)b); break;
    case 16:
        DLOG("udp_in %u <= %u, udp_out %u >= %u\n", (unsigned)a, (unsigned)b, (unsigned)d, (unsigned)e);
        HOSTLIST_DEBUGLOG_APPEND("%s : profile %u (%s) : client %s : proto %s : udp_in %u<=%u udp_out %u>=%u",
            c->hostname, dp->n, PROFILE_NAME(dp), c->client_text, l7proto_str(c->l7),
            (unsigned)a, (unsigned)b, (unsigned)d, (unsigned)e);
        break;
    case 17:
        DLOG("incoming RST detected for hostname %s rseq %u\n", c->hostname, (unsigned)a);
        HOSTLIST_DEBUGLOG_APPEND("%s : profile %u (%s) : client %s : proto %s : rseq %u : incoming RST",
            c->hostname, c->track->dp->n, PROFILE_NAME(dp), c->client_text, l7proto_str(c->l7), (unsigned)a);
        break;
    case 18: DLOG("incoming HTTP reply detected for hostname %s rseq %u\n", c->hostname, (unsigned)a); break;
    case 19:
        DLOG("redirect to another domain detected. possibly DPI redirect.\n");
        HOSTLIST_DEBUGLOG_APPEND("%s : profile %u (%s) : client %s : proto %s : rseq %u : redirect to another domain",
            c->hostname, c->track->dp->n, PROFILE_NAME(dp), c->client_text, l7proto_str(c->l7), (unsigned)a);
        break;
    case 20: DLOG("local or in-domain redirect detected. it's not a DPI redirect.\n"); break;
    case 21: DLOG("incoming rseq %u > %u\n", (unsigned)a, (unsigned)b); break;
    }
}

static const zapret_autolist_ops autolist_ops = {
    autolist_find_counter, autolist_add_counter, autolist_remove_counter, HostlistCheck,
    autolist_append, autolist_stamp, autolist_send, autolist_report,
};

static const zapret_autolist_track_ops autolist_track_ops = {
    &autolist_ops, &params.server, &params.debug, params.hostlist_auto_debuglog, ntop46_port,
};

static void process_retrans_fail(t_ctrack *track, const struct dissect *packet,
    struct sockaddr *client, const char *interface)
{
    const zapret_autolist_track_input input = {.track = track, .client = client, .interface = interface};
    zapret_autolist_track(&input, AUTOLIST_TCP, packet, NULL, 0, &autolist_track_ops);
}
static void process_udp_fail(t_ctrack *track, const t_ctrack_positions *positions,
    const struct sockaddr *client)
{
    const zapret_autolist_track_input input = {.track = track, .client = client};
    zapret_autolist_track(&input, AUTOLIST_UDP, NULL, positions, 0, &autolist_track_ops);
}
static void process_incoming_fail(t_ctrack *track, struct desync_profile *profile,
    const struct dissect *packet, t_l7payload payload, t_l7proto l7, const struct sockaddr *client)
{
    const zapret_autolist_track_input input = {.track = track, .profile = profile, .client = client, .l7 = l7};
    zapret_autolist_track(&input, AUTOLIST_INCOMING, packet, NULL, payload, &autolist_track_ops);
}
