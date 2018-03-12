#ifndef _MASQ_H_
#define _MASQ_H_

#include "common.h"

void masq_data(struct sk_buff *skb, unsigned long passwd);
void demasq_data(struct sk_buff *skb, unsigned long passwd);

#endif
