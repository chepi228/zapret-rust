/* MIT. Startup comma-list entries provided by Rust. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include "pools.h"

_Static_assert(sizeof(struct str_list_head) == sizeof(void *) && offsetof(struct str_list_head, lh_first) == 0,
    "Rust startup string list ABI");

bool parse_domain_list(char *, hostlist_pool **);
bool parse_ip_list(char *, ipset *);
bool parse_strlist(char *, struct str_list_head *);
