/* MIT. Compare the Windows long-only cursor with the linked getopt. */
#include <getopt.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include "params.h"
#undef main
#include "option_reference.inc"
static char diagnostic[128];
static char **observed_argument;
static bool argument_cleared;
static int capture_vfprintf(FILE *file, const char *format, va_list args)
{
    argument_cleared=file==stderr && observed_argument && !*observed_argument;
    return vsnprintf(diagnostic,sizeof(diagnostic),format,args);
}
#define vfprintf capture_vfprintf
#include "cli_stderr_windows.h"
#undef vfprintf
#include "cli_windows.inc"

static int native_cli_next(int argc, char **argv, const struct option *options, size_t count,
    size_t *cursor, bool stop_at_operand, char **argument, int *index)
{
    const zapret_cli_output output = {argument, index, native_cli_stderr};
    return zapret_cli_next(argc, argv, options, count, cursor, stop_at_operand, &output);
}
struct params_s params;

static unsigned cases, reads, errors;
#define CHECK(condition) do { \
    if (!(condition)) { fprintf(stderr, "FAIL engine CLI case %u line %d: %s\n", cases, __LINE__, #condition); exit(1); } \
} while (0)
#include "cli_numeric_oracle.inc"
#include "cli_stderr_oracle.h"
static size_t check_parser_diagnostics(void)
{
    static const struct { char *token; const char *expected; } inputs[]={
        {"--bogus=value","engine: unknown option -- bogus=value\n"},
        {"--wf","engine: ambiguous option -- wf\n"},
        {"--hostlist","engine: option requires an argument -- hostlist\n"},
        {"--dry-run=oops","engine: option doesn't take an argument -- dry-run\n"},
        {"--bad-%s-\xff","engine: unknown option -- bad-%s-\xff\n"},
    };
    for (size_t i=0;i<sizeof(inputs)/sizeof(*inputs);++i) {
        char *argv[]={"engine",inputs[i].token,NULL};
        char *value="prior";
        observed_argument=&value;
        diagnostic[0]=0;
        argument_cleared=false;
        int index=-7;
        size_t cursor=1;
        CHECK(native_cli_next(2,argv,long_options,IDX_LAST,&cursor,false,&value,&index)=='?');
        CHECK(argument_cleared && cursor==2 && index==-7 && !strcmp(diagnostic,inputs[i].expected));

        value = "prior";
        cursor = 1;
        const zapret_cli_output output = {&value, &index, NULL};
        cli_stderr_capture capture = cli_capture_stderr();
        int result = zapret_cli_next(2, argv, long_options, IDX_LAST, &cursor, false, &output);
        cli_expect_stderr(capture, inputs[i].expected);
        CHECK(result == '?' && !value && cursor == 2 && index == -7);
    }
    observed_argument=NULL;
    return sizeof(inputs)/sizeof(*inputs);
}
static void compare(int count, char **arguments, bool strict)
{
    char *reference[16];
    char *stable[16];
    CHECK(count < 16);
    memcpy(reference, arguments, (count + 1) * sizeof(*reference));
    memcpy(stable, reference, (count + 1) * sizeof(*stable));
    optind = 0;
    opterr = 0;
    int reference_index = -3;
    size_t cursor = 1;
    for (unsigned steps = 0;; ++steps) {
        CHECK(steps <= (unsigned)count);
        int previous = getopt_long_only(count, reference, "", long_options, &reference_index);
        zapret_cli_option current;
        uint32_t status = zapret_cli_read(count, arguments, long_options, IDX_LAST, &cursor, strict, &current);
        int code = status == 0 ? -1 : status == 1 ? 0 : '?';
        if (previous != code)
            for (int i = 0; i < count; ++i) fprintf(stderr, "%s\n", stable[i]);
        CHECK(previous == code);
        if (code < 0) break;
        if (!code) {
            CHECK(reference_index == current.index);
            CHECK(optarg == current.argument);
        } else {
            ++errors;
        }
        ++reads;
    }
    CHECK(!memcmp(stable, arguments, (count + 1) * sizeof(*stable)));
    ++cases;
}
int main(void)
{
    static const char *const fragments[] = {"word", "-", "--", "--=", "-xrx", "--unknown=value",
        "--dry-run", "--new", "--intercept", "--intercept=0", "--comment=",
        "--debug=1", "-dry-run=bad", "--hostlist", "--filter-l3", "ipv4", "two words",
        "--template", "--import=p"};
    uint32_t seed = 0x21365f37;
    for (unsigned strict = 0; strict < 2; ++strict) {
        CHECK(!_putenv(strict ? "POSIXLY_CORRECT=1" : "POSIXLY_CORRECT="));
        for (unsigned id = 0; id < IDX_LAST; ++id) {
            const char *name = long_options[id].name;
            CHECK(name && long_options[id].val == 0 && !long_options[id].flag);
            for (unsigned length = 1; length <= strlen(name); ++length)
            for (unsigned shape = 0; shape < 4; ++shape) {
                char text[128];
                snprintf(text, sizeof(text), "%s%.*s%s", shape & 1 ? "-" : "--", length, name,
                    shape & 2 ? "=text" : "");
                char *args[] = {"winws2", text, "operand", "--dry-run", NULL};
                compare(4, args, strict);
                args[2] = NULL;
                compare(2, args, strict);
            }
        }
        for (unsigned n = 0; n < 4096; ++n) {
            char *args[12] = {"winws2"};
            int len = 1 + n % 10;
            for (int i = 1; i < len; ++i) {
                seed = seed * 1664525u + 1013904223u;
                args[i] = (char *)fragments[(seed >> 16) % (sizeof(fragments) / sizeof(*fragments))];
            }
            compare(len, args, strict);
        }
    }
    char *arguments[] = {"winws2", "--dry-run", NULL}, *arg = (char *)1;
    size_t cursor = 1;
    int option = -1;
    CHECK(native_cli_next(2, arguments, long_options, IDX_LAST, &cursor, false, &arg, &option) == 0);
    CHECK(!arg && option == IDX_DRY_RUN);
    CHECK(native_cli_next(2, arguments, long_options, IDX_LAST, &cursor, false, &arg, &option) == -1);
    size_t diagnostics = check_parser_diagnostics();
    printf("PASS engine_cli options=%u scenarios=%u reads=%u errors=%u diagnostic_cases=%zu ucrt_stderr_cases=%zu\n", IDX_LAST, cases, reads, errors, diagnostics, diagnostics);
    check_numeric_options();
    return 0;
}
