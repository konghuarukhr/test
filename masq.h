#ifndef _MASQ_H_
#define _MASQ_H_

#include "common.h"

void masq_data(struct sk_buff *skb, u8 passwd);
void demasq_data(struct sk_buff *skb, u8 passwd);

#endif
