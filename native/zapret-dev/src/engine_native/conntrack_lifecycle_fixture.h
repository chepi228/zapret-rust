/* MIT. Observe native allocation/insert failures without changing the index. */
#pragma once
#include "conntrack_fixture.h"
void *conntrack_fixture_malloc(size_t);
void conntrack_fixture_free(void *);
int conntrack_fixture_insert(struct zapret_conntrack_index **,const t_conn *,void *);
#define malloc conntrack_fixture_malloc
#define free conntrack_fixture_free
#define zapret_conntrack_insert conntrack_fixture_insert
