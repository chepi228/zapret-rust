/* MIT. Compare scalar option changes and verify atomic failures. */
#include <setjmp.h>
static jmp_buf numeric_error;
int DLOG_ERR(const char *format, ...) { (void)format; return 0; }
static void exit_clean(int code) { (void)code; longjmp(numeric_error, 1); }
static void reference_numeric(int option_index, char *optarg, struct desync_profile *dp)
{
    switch (option_index) {
#include "cli_numeric_reference.inc"
    default: CHECK(false);
    }
}
#include "cli_numeric_windows.inc"
static void check_numeric_options(void)
{
    static const int indices[] = {IDX_INTERCEPT, IDX_FUZZ, IDX_DAEMON, IDX_CTRACK_DISABLE, IDX_SERVER,
        IDX_IPCACHE_HOSTNAME, IDX_IPCACHE_LIFETIME, IDX_LUA_GC, IDX_HOSTLIST_AUTO_FAIL_THRESHOLD,
        IDX_HOSTLIST_AUTO_FAIL_TIME, IDX_HOSTLIST_AUTO_RETRANS_THRESHOLD, IDX_HOSTLIST_AUTO_RETRANS_MAXSEQ,
        IDX_HOSTLIST_AUTO_INCOMING_MAXSEQ, IDX_HOSTLIST_AUTO_RETRANS_RESET, IDX_HOSTLIST_AUTO_UDP_OUT,
        IDX_HOSTLIST_AUTO_UDP_IN};
    static const char *const values[] = {"-2147483648", "-500", "-1", "0", "-0", "1", "2", "3", "5", "10", "20",
        "21", "100", "32768", "65535", "2147483", " 2", "+3", "3tail"};
    unsigned checked = 0, failures = 0;
    struct params_s expected;
    for (unsigned option = 0; option < sizeof(indices) / sizeof(*indices); ++option)
    for (unsigned value = 0; value < sizeof(values) / sizeof(*values); ++value) {
        struct desync_profile left = {0}, right = {0};
        memset(&params, 0, sizeof(params));
        params.ctrack_t_udp = 17;
        params.intercept = true;
        if (indices[option] == IDX_IPCACHE_LIFETIME && values[value][0] == '-' && atoi(values[value])) {
            CHECK(engine_numeric_option(indices[option], values[value], &right) == -1 && !params.ipcache_lifetime);
            ++checked;
            continue;
        }
        if (!setjmp(numeric_error)) {
            reference_numeric(indices[option], (char *)values[value], &left);
            memcpy(&expected, &params, sizeof(params));
            memset(&params, 0, sizeof(params));
            params.ctrack_t_udp = 17;
            params.intercept = true;
            int applied = engine_numeric_option(indices[option], values[value], &right);
            if (applied != 1) fprintf(stderr, "rejected numeric option=%d input=%s\n", indices[option], values[value]);
            CHECK(applied == 1);
            if (memcmp(&expected, &params, sizeof(params)) || memcmp(&left, &right, sizeof(left)))
                fprintf(stderr, "numeric option=%d input=%s\n", indices[option], values[value]);
            CHECK(!memcmp(&expected, &params, sizeof(params)) && !memcmp(&left, &right, sizeof(left)));
        } else {
            memset(&params, 0, sizeof(params));
            memset(&right, 0, sizeof(right));
            CHECK(engine_numeric_option(indices[option], values[value], &right) == -1);
            struct desync_profile empty = {0};
            CHECK(!memcmp(&right, &empty, sizeof(empty)));
            ++failures;
        }
        ++checked;
    }
    struct desync_profile dp = {0};
    memset(&params, 0, sizeof(params));
    CHECK(engine_numeric_option(IDX_INTERCEPT, NULL, &dp) == 1 && params.intercept);
    CHECK(engine_numeric_option(IDX_LUA_GC, "2147483647", &dp) == 1 && params.lua_gc == 2147483647000ull);
    CHECK(engine_numeric_option(IDX_LUA_GC, "2147483648", &dp) == -1 && params.lua_gc == 2147483647000ull);
    CHECK(engine_numeric_option(IDX_HOSTLIST_AUTO_FAIL_THRESHOLD, "4294967299", &dp) == -1 && !dp.b_hostlist_auto_fail_threshold);
    CHECK(engine_numeric_option(IDX_HOSTLIST_AUTO_FAIL_THRESHOLD, "junk", &dp) == -1 && !dp.b_hostlist_auto_fail_threshold);
    CHECK(engine_numeric_option(IDX_FUZZ, "4294967296", &dp) == -1 && params.intercept && !params.fuzz);
    CHECK(engine_numeric_option(IDX_IPCACHE_LIFETIME, "4294967296", &dp) == -1 && !params.ipcache_lifetime);
    static const char *const timeouts[] = {"1:2:3", "1:2:3:4", " 3:4:5:6", "1:2:3junk", "1:2:3:", "1:2:3:bad", "bad", "1:bad:2", "1:2"};
    for (unsigned i = 0; i < sizeof(timeouts) / sizeof(*timeouts); ++i) {
        unsigned int a[] = {5, 6, 7, 8}, b[] = {5, 6, 7, 8};
        bool old = sscanf(timeouts[i], "%u:%u:%u:%u", a, a+1, a+2, a+3) >= 3;
        CHECK(zapret_cli_timeouts(timeouts[i], b, b+1, b+2, b+3) == old);
        CHECK(old ? !memcmp(a, b, sizeof(a)) : (b[0] == 5 && b[1] == 6 && b[2] == 7 && b[3] == 8));
        ++checked;
    }
    unsigned int t[] = {1, 2, 3, 4};
    CHECK(!zapret_cli_timeouts("1:4294967296:3", t, t+1, t+2, t+3));
    CHECK(t[0] == 1 && t[1] == 2 && t[2] == 3 && t[3] == 4);
    printf("PASS engine_numbers cases=%u rejected=%u boundary_cases=8\n", checked, failures);
}
