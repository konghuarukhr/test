#ifndef _ROUTE_H_
#define _ROUTE_H_

#include "common.h"

struct route_table;

struct route_table *route_table_init(void);
void route_table_uninit(struct route_table *rt);

bool route_table_contains(struct route_table *rt, __be32 ip);
int route_table_add(struct route_table *rt, __be32 network,
                unsigned char mask);
int route_table_add_expire(struct route_table *rt, __be32 network,
		unsigned char mask, int secs);
void route_table_clear(struct route_table *rt);

#endif
