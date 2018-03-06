#ifndef _ROUTE_H_
#define _ROUTE_H_

#include "common.h"

struct route_table;

struct route_table *route_table_init(void);
void route_table_uninit(struct route_table *rt);

void route_table_clear(struct route_table *rt);
int route_table_add(struct route_table *rt, __be32 network,
                unsigned char mask);
int route_table_add_expire(struct route_table *rt, __be32 network,
		unsigned char mask, int secs);
int route_table_delete(struct route_table *rt, __be32 network,
                unsigned char mask);
unsigned char route_table_get_mask(struct route_table *rt, __be32 ip);

#endif
