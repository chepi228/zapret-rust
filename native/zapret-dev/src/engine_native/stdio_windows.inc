/* MIT. Rust retries UCRT calls using the same FILE and errno ownership. */
ssize_t zapret_engine_read(int, void *, size_t, const void *);
bool zapret_engine_fread(void *, size_t, size_t, FILE *, size_t *, const void *);
char *zapret_engine_fgets(char *, int, FILE *, const void *);
bool zapret_engine_crypto_random(uint8_t *, size_t);
ssize_t read_intr(int fd, void *buffer, size_t count)
{ return zapret_engine_read(fd, buffer, count, NULL); }
bool fread_safe(void *buffer, size_t size, size_t count, FILE *stream, size_t *read)
{ return zapret_engine_fread(buffer, size, count, stream, read, NULL); }
char *fgets_safe(char *buffer, int size, FILE *stream)
{ return zapret_engine_fgets(buffer, size, stream, NULL); }
bool fill_crypto_random_bytes(uint8_t *buffer, size_t count)
{ return zapret_engine_crypto_random(buffer, count); }
