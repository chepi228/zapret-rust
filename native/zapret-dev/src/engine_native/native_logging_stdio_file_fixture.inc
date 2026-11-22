/* MIT. Compare the selected formatter over private UTF-8 paths and UCRT streams. */
#include "win_files.h"

static int fixture_print(bool rust, FILE *file, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int result = rust ? zapret_crt_log_file(file, format, args, NULL) : vfprintf(file, format, args);
    va_end(args);
    return result;
}

static int fixture_append(bool rust, const char *path, bool stamp, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int result;
    if (rust) {
        result = zapret_crt_log_path(path, format, args, stamp, NULL);
    } else {
        FILE *file = fopen(path, "at");
        if (!file) result = -1;
        else {
            result = vfprintf(file, format, args);
            fclose(file);
        }
    }
    va_end(args);
    return result;
}

static size_t fixture_log_bytes(const char *path, char output[512])
{
    FILE *file = fopen(path, "rb");
    CHECK(file);
    size_t count = fread(output, 1, 511, file);
    CHECK(!ferror(file) && feof(file) && !fclose(file));
    output[count] = 0;
    return count;
}

static char formatted_log[4096];
static unsigned formatted_writes;

static void fixture_log_writer(int32_t priority, const char *text)
{
    CHECK(priority == 7 && strlen(text) < sizeof(formatted_log));
    strcpy(formatted_log, text);
    ++formatted_writes;
}

bool zapret_log_buffer(const char *, size_t, int, zapret_log_writer);
static void fixture_buffer(bool rust, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    if (rust) {
        zapret_crt_log_buffered(fixture_log_writer, 7, format, args);
    } else {
        char text[4095];
        if (vsnprintf(text, sizeof(text), format, args) > 0)
            zapret_log_buffer(text, strlen(text), 7, fixture_log_writer);
    }
    va_end(args);
}

static void check_native_logging_stdio(void)
{
    const char *const paths[] = {"лог-эталон.txt", "лог-rust.txt"};
    const char *format = "%.*s|%lld|%#x|%.4f|%zu|%ls|%%\n";
    char left[512], right[512];
    int lengths[2], errors[2];
    for (unsigned rust = 0; rust < 2; ++rust) {
        FILE *file = fopen(paths[rust], "wb");
        CHECK(file);
        errno = EACCES;
        lengths[rust] = fixture_print(rust, file, format, 8, "тест", -800000000000LL,
            0xabcdefU, 3.125, (size_t)16000, L"wide");
        errors[rust] = errno;
        CHECK(!fclose(file));
    }
    size_t count = fixture_log_bytes(paths[0], left);
    CHECK(count == fixture_log_bytes(paths[1], right) && !memcmp(left, right, count));
    CHECK(lengths[0] == lengths[1] && lengths[1] == (int)count && errors[0] == errors[1]);
    for (unsigned rust = 0; rust < 2; ++rust) {
        errno = EACCES;
        lengths[rust] = fixture_append(rust, paths[rust], false, "%s %d\n", "добавлено", -7);
        errors[rust] = errno;
    }
    count = fixture_log_bytes(paths[0], left);
    CHECK(count == fixture_log_bytes(paths[1], right) && !memcmp(left, right, count));
    CHECK(lengths[0] == lengths[1] && errors[0] == errors[1] && strstr(right, "добавлено -7\r\n"));
    for (unsigned rust = 0; rust < 2; ++rust) {
        SetLastError(ERROR_SUCCESS);
        errno = EACCES;
        CHECK(fixture_append(rust, "missing-native-log-dir/failure.txt", false, "%s", "body") == -1);
        CHECK(GetLastError() == ERROR_PATH_NOT_FOUND && errno == ENOENT);
    }
    zapret_crt_log_line(paths[1], "%s literal %n\n", NULL);
    CHECK(fixture_append(true, paths[1], true, "%s", "timestamped") == 11);
    fixture_log_bytes(paths[1], right);
    CHECK(strstr(right, "%s literal %n\r\n") && strstr(right, " : timestamped\r\n"));
    CHECK(!remove(paths[0]) && !remove(paths[1]));

    char expected[sizeof(formatted_log)];
    fixture_buffer(false, "%-4200s %d\n", "буфер", 123);
    strcpy(expected, formatted_log);
    fixture_buffer(true, "%-4200s %d\n", "буфер", 123);
    CHECK(formatted_writes == 2 && !strcmp(expected, formatted_log));
    fixture_buffer(false, "%s %.2f %lld\n", "буфер", 1.25, -4000000000LL);
    strcpy(expected, formatted_log);
    fixture_buffer(true, "%s %.2f %lld\n", "буфер", 1.25, -4000000000LL);
    CHECK(formatted_writes == 4 && !strcmp(expected, formatted_log));
    printf("PASS native_logging_stdio mixed_va=1 unicode=1 text_append=1 errno=1 timestamp=1 bounded_buffer=1\n");
}
