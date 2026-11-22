/* MIT. Capture the real UCRT stderr bytes inside the CLI comparisons. */
#pragma once
#include <fcntl.h>
#include <io.h>

typedef struct {
    FILE *file;
    int descriptor, previous;
} cli_stderr_capture;

static cli_stderr_capture cli_capture_stderr(void)
{
    cli_stderr_capture capture = {tmpfile(), _fileno(stderr), -1};
    CHECK(capture.file && !fflush(stderr));
    int file = _fileno(capture.file);
    CHECK(_setmode(file, _O_BINARY) != -1);
    capture.previous = _dup(capture.descriptor);
    CHECK(capture.previous != -1);
    CHECK(!_dup2(file, capture.descriptor));
    return capture;
}

static void cli_expect_stderr(cli_stderr_capture capture, const char *expected)
{
    int flushed = fflush(stderr);
    CHECK(!_dup2(capture.previous, capture.descriptor));
    CHECK(!_close(capture.previous));
    CHECK(!flushed && !fseek(capture.file, 0, SEEK_SET));
    for (const unsigned char *byte = (const unsigned char *)expected; *byte; ++byte)
        CHECK(fgetc(capture.file) == *byte);
    CHECK(fgetc(capture.file) == EOF && feof(capture.file));
    CHECK(!fclose(capture.file));
}
