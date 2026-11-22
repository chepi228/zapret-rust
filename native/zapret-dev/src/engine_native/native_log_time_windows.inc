/* MIT. Timestamp oracle with injected clock and UCRT writer. */
int zapret_log_write_timestamp(FILE *, const int32_t *, int (*)(FILE *, const char *), void (*)(void));

static int native_write_timestamp(FILE *file, const char *text)
{
    return fprintf(file, "%s", text);
}

int fprint_localtime(FILE *file)
{
    struct tm value;
    time_t now;
    time(&now);
    localtime_r(&now, &value);
    int32_t fields[] = {value.tm_mday, value.tm_mon, value.tm_year, value.tm_hour, value.tm_min, value.tm_sec};
    return zapret_log_write_timestamp(file, fields, native_write_timestamp, abort);
}
