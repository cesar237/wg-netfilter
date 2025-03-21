/* SPDX-License-Identifier: GPL-2.0 */
/*
* Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
*/

#ifndef _WG_NETFILTER_H
#define _WG_NETFILTER_H

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

struct wg_device;

struct wg_hook_data {
    struct wg_device *wg;
};

unsigned int hook_tx(
    void *priv, struct sk_buff *skb, 
    const struct nf_hook_state *state
);

unsigned int hook_rx(
    void *priv, struct sk_buff *skb, 
    const struct nf_hook_state *state
);

int wg_netfilter_init(struct wg_device *wg);
void wg_netfilter_uninit(void);

#endif /* _WG_NETFILTER_H */
