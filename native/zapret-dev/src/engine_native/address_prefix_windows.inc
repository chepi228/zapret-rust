/* MIT. Keep legacy symbols for comparisons that still compile filter.c. */
#include "filters_windows.h"
bool parse_cidr4(char *text, struct cidr4 *cidr)
{ return zapret_parse_cidr4(text, cidr); }
bool parse_cidr6(char *text, struct cidr6 *cidr)
{ return zapret_parse_cidr6(text, cidr); }
void str_cidr4(char *output, size_t capacity, const struct cidr4 *cidr)
{ zapret_str_cidr4(output, capacity, cidr); }
void str_cidr6(char *output, size_t capacity, const struct cidr6 *cidr)
{ zapret_str_cidr6(output, capacity, cidr); }
void print_cidr4(const struct cidr4 *cidr)
{ char text[INET_ADDRSTRLEN + 4]; str_cidr4(text, sizeof(text), cidr); printf("%s", text); }
void print_cidr6(const struct cidr6 *cidr)
{ char text[INET6_ADDRSTRLEN + 5]; str_cidr6(text, sizeof(text), cidr); printf("%s", text); }
