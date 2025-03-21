// SPDX-License-Identifier: GPL-2.0
/*
* Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
*/

#include "wg_netfilter.h"
#include "device.h"
#include "queueing.h"

#include <net/ip_tunnels.h>
#include <linux/udp.h>

#define WG_SERVER_IP 16777226
#define SKB_TYPE_LE32(skb) (((struct message_header *)(skb)->data)->type)

/**
* hook_tx - Netfilter hook for tx pipeline.
* Encrypts UDP payload for specified port
*/
unsigned int hook_tx(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    return NF_ACCEPT;
}

/**
* hook_rx - Netfilter hook for rx pipeline
* Decrypts UDP payload for specified port
*/
unsigned int hook_rx(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct udphdr *udph;
    struct wg_device *wg;
    struct wg_hook_data *data;

    data = (struct wg_hook_data *)priv;
    wg = data->wg;

    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (iph->protocol != IPPROTO_UDP)
        return NF_ACCEPT;

    // Get UDP header and see if packet is for Wireguard
    udph = udp_hdr(skb);
    // if (iph->daddr == WG_SERVER_IP)
    if (ntohs(udph->dest) == wg->incoming_port)
    {
        size_t data_offset;
        unsigned char *skb_offset;
        __le32 type;

        data_offset = (u8 *)udph + sizeof(struct udphdr) - skb->data;
        skb_offset = skb->data + data_offset;
        type = ((struct message_header *)skb_offset)->type;

        if (type != cpu_to_le32(MESSAGE_DATA)) {
            pr_info("HOOK: Got HANDSHAKE\n");
            return NF_ACCEPT;
        }
        pr_info("HOOK: Got MESSAGE DATA packet...\n");

        if (unlikely(prepare_skb_header(skb, wg) < 0))
            goto err;
        PACKET_CB(skb)->ds = ip_tunnel_get_dsfield(ip_hdr(skb), skb);

        __le32 idx = ((struct message_data *)skb->data)->key_idx;
        struct wg_peer *peer = NULL;
        struct noise_keypair *keypair;
        struct endpoint endpoint;

        rcu_read_lock_bh();
        PACKET_CB(skb)->keypair =
            (struct noise_keypair *)wg_index_hashtable_lookup(
                wg->index_hashtable, INDEX_HASHTABLE_KEYPAIR, idx,
                &peer);
        if (unlikely(!wg_noise_keypair_get(PACKET_CB(skb)->keypair)))
            goto err;
        keypair = PACKET_CB(skb)->keypair;

        // Decrypt packet
        atomic_set_release(&PACKET_CB(skb)->state, PACKET_STATE_UNCRYPTED);
        enum packet_state state = 
            likely(decrypt_packet(skb, keypair)) ?
				PACKET_STATE_CRYPTED : PACKET_STATE_DEAD;
        
        atomic_set_release(&PACKET_CB(skb)->state, state);
        rcu_read_unlock_bh();

        // do wg_packet_rx_poll
        if (unlikely(!counter_validate(&keypair->receiving_counter,
                    PACKET_CB(skb)->nonce))) {
            net_dbg_ratelimited("%s: Packet has invalid nonce %llu (max %llu)\n",
                    peer->device->dev->name,
                    PACKET_CB(skb)->nonce,
                    READ_ONCE(keypair->receiving_counter.counter));
            goto next;
        }

        if (unlikely(wg_socket_endpoint_from_skb(&endpoint, skb)))
			goto next;

        wg_reset_packet(skb, false);
next:
        wg_noise_keypair_put(keypair, false);
        wg_peer_put(peer);

        pr_info("HOOK: decrypted=%d\n", state);
        // wg_nf_packet_consume_data(wg, skb);
    }

    return NF_ACCEPT;

err:
    return NF_ACCEPT;
}

/* Netfilter hook operations */
static struct nf_hook_ops nf_hook_ops[] = {
    {
        .hook       = hook_tx,
        .pf         = PF_INET,
        .hooknum    = NF_INET_POST_ROUTING,
        .priority   = NF_IP_PRI_FIRST,
    },
    {
        .hook       = hook_rx,
        .pf         = PF_INET,
        .hooknum    = NF_INET_PRE_ROUTING,
        .priority   = NF_IP_PRI_FIRST,
    },
};

int wg_netfilter_init(struct wg_device *wg) 
{
    int ret;
    struct wg_hook_data *data;

    /* Allocate private data */
    data = kmalloc(sizeof(struct wg_hook_data), GFP_KERNEL);
    if (!data) {
        pr_err("Failed to allocate private data\n");
        return -ENOMEM;
    }

    data->wg = wg;

    nf_hook_ops[0].priv = data;
    nf_hook_ops[1].priv = data;

    /* Register netfilter hooks */
    ret = nf_register_net_hooks(&init_net, nf_hook_ops, ARRAY_SIZE(nf_hook_ops));
    if (ret) {
        pr_err("Failed to register netfilter hooks\n");
        return ret;
    }

    return 0;
}

void wg_netfilter_uninit(void)
{
    /* Unregister netfilter hooks */
    // struct wg_hook_data *data1 = nf_hook_ops[0].priv;
    // struct wg_hook_data *data2 = nf_hook_ops[1].priv;

    nf_unregister_net_hooks(&init_net, nf_hook_ops, ARRAY_SIZE(nf_hook_ops));

    // kfree(data1);
    // kfree(data2);
    pr_info("Netfilter hooks unregistered!\n");
}
