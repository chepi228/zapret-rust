/* MIT. Keep UCRT formatting outside Rust and pass only initialized text. */
bool zapret_log_buffer(const char *, size_t, int, f_log_function);
static void log_buffered(f_log_function writer, int priority, const char *format, va_list arguments)
{
    char text[4095];
    if (vsnprintf(text, sizeof(text), format, arguments) > 0)
        zapret_log_buffer(text, strlen(text), priority, writer);
}
