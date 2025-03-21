/**
* wg_netfilter.c - Linux kernel module for encrypting socket buffers
* using ChaCha20-Poly1305 with Curve25519 keys and BLAKE2s KDF
*
* This module implements socket buffer encryption/decryption by hooking
* into the Linux network stack via netfilter.
*/

#include "noise.h"

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/random.h>
#include <net/sock.h>
#include <net/inet_connection_sock.h>
#include <net/udp.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Césaire");
MODULE_DESCRIPTION("Socket Buffer Encryption with ChaCha20-Poly1305");
MODULE_VERSION("0.1");

/* Key storage */
struct noise_static_identity static_identity;
struct noise_keypair keypair;
static u8 peer_public_key[NOISE_PUBLIC_KEY_LEN];
// static u8 shared_secret[X25519_SHARED_SIZE];
// static u8 chacha_key[CHACHA20POLY1305_KEY_SIZE];

/* Ports to filter (configurable) */
static int port_to_encrypt = 8000;
module_param(port_to_encrypt, int, 0644);
MODULE_PARM_DESC(port_to_encrypt, "UDP port to encrypt/decrypt");

/* Function prototypes */
static unsigned int hook_outgoing(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
static unsigned int hook_incoming(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
static int encrypt_packet(struct sk_buff *skb);
static int decrypt_packet(struct sk_buff *skb);
static int setup_crypto(void);
static int x25519_generate_keypair(void);
static int x25519_compute_shared_secret(const u8 *private_key, const u8 *peer_public, u8 *shared);
static int derive_chacha_key(const u8 *shared, const u8 *local_pub, const u8 *remote_pub, u8 *out_key);

/* Netfilter hook operations */
static struct nf_hook_ops nf_hook_ops[] = {
    {
        .hook = hook_outgoing,
        .pf = PF_INET,
        .hooknum = NF_INET_POST_ROUTING,
        .priority = NF_IP_PRI_FIRST,
    },
    {
        .hook = hook_incoming,
        .pf = PF_INET,
        .hooknum = NF_INET_PRE_ROUTING,
        .priority = NF_IP_PRI_FIRST,
    },
};

/**
* x25519_generate_keypair - Generates X25519 keypair
* 
* Note: In a production module, this should use a proper X25519 implementation.
* This is a placeholder that uses random bytes for the public key.
*
* Returns 0 on success, negative error code on failure
*/
static int x25519_generate_keypair(void)
{
    /* Generate private key (random 32 bytes) */
    get_random_bytes(private_key, X25519_KEY_SIZE);
    
    /* Clamp according to X25519 requirements */
    x25519_clamp_scalar(private_key);
    
    /* Note: This is a placeholder for the public key generation
    * In a real implementation, you would compute:
    * public_key = x25519_base_point_mult(private_key)
    */
    get_random_bytes(public_key, X25519_KEY_SIZE);
    
    printk(KERN_INFO "X25519 keypair generated (placeholder)\n");
    return 0;
}

/**
* x25519_compute_shared_secret - Computes X25519 shared secret
* @private_key: Our private key
* @peer_public: Peer's public key
* @shared: Buffer to store the shared secret
*
* Note: In a production module, this should use a proper X25519 implementation.
* This is a placeholder that creates a deterministic value based on inputs.
*
* Returns 0 on success, negative error code on failure
*/
static int x25519_compute_shared_secret(const u8 *private_key, const u8 *peer_public, u8 *shared)
{
    int i;
    
    /* Note: This is a placeholder for the actual X25519 scalar multiplication
    * In a real implementation, you would compute:
    * shared = x25519_scalar_mult(private_key, peer_public)
    *
    * For demonstration, we'll create a deterministic "shared secret"
    * based on XOR of private key and peer's public key. DO NOT USE IN PRODUCTION!
    */
    for (i = 0; i < X25519_KEY_SIZE; i++) {
        shared[i] = private_key[i] ^ peer_public[i];
    }
    
    return 0;
}

/**
* derive_chacha_key - Derives ChaCha20-Poly1305 key using BLAKE2s
* @shared: The shared secret from X25519
* @local_pub: Local public key
* @remote_pub: Remote public key
* @out_key: Output buffer for the derived key
*
* Returns 0 on success, negative error code on failure
*/
static int derive_chacha_key(const u8 *shared, const u8 *local_pub, const u8 *remote_pub, u8 *out_key)
{
    struct crypto_shash *tfm_blake2s;
    DECLARE_CRYPTO_WAIT(wait);
    struct shash_desc *desc;
    int desc_size, ret;
    
    /* Allocate transform for BLAKE2s */
    tfm_blake2s = crypto_alloc_shash("blake2s-256", 0, 0);
    if (IS_ERR(tfm_blake2s)) {
        printk(KERN_ERR "Failed to allocate BLAKE2s transform: %ld\n", PTR_ERR(tfm_blake2s));
        return PTR_ERR(tfm_blake2s);
    }
    
    /* Allocate descriptor */
    desc_size = sizeof(*desc) + crypto_shash_descsize(tfm_blake2s);
    desc = kzalloc(desc_size, GFP_KERNEL);
    if (!desc) {
        crypto_free_shash(tfm_blake2s);
        return -ENOMEM;
    }
    
    /* Initialize descriptor */
    desc->tfm = tfm_blake2s;
    
    /* Key derivation: BLAKE2s(shared_secret || local_public || remote_public) */
    ret = crypto_shash_init(desc);
    if (ret) {
        goto out;
    }
    
    ret = crypto_shash_update(desc, shared, X25519_SHARED_SIZE);
    if (ret) {
        goto out;
    }
    
    ret = crypto_shash_update(desc, local_pub, X25519_KEY_SIZE);
    if (ret) {
        goto out;
    }
    
    ret = crypto_shash_update(desc, remote_pub, X25519_KEY_SIZE);
    if (ret) {
        goto out;
    }
    
    ret = crypto_shash_final(desc, out_key);
    
out:
    kfree(desc);
    crypto_free_shash(tfm_blake2s);
    return ret;
}

/**
* setup_crypto - Initialize cryptographic transforms
* Returns 0 on success, negative error code on failure
*/
static int setup_crypto(void)
{
    /* Allocate and set up ChaCha20-Poly1305 transform */
    tfm = crypto_alloc_aead("rfc7539(chacha20,poly1305)", 0, 0);
    if (IS_ERR(tfm)) {
        printk(KERN_ERR "Failed to allocate ChaCha20-Poly1305 transform: %ld\n", PTR_ERR(tfm));
        return PTR_ERR(tfm);
    }
    
    /* Set key for ChaCha20-Poly1305 */
    if (crypto_aead_setkey(tfm, chacha_key, CHACHA20POLY1305_KEY_SIZE)) {
        printk(KERN_ERR "Failed to set ChaCha20-Poly1305 key\n");
        crypto_free_aead(tfm);
        return -EINVAL;
    }
    
    /* Set authentication tag size */
    if (crypto_aead_setauthsize(tfm, CHACHA20POLY1305_AUTHTAG_SIZE)) {
        printk(KERN_ERR "Failed to set auth tag size\n");
        crypto_free_aead(tfm);
        return -EINVAL;
    }
    
    return 0;
}

/**
* hook_outgoing - Netfilter hook for outgoing packets
* Encrypts UDP payload for specified port
*/
static unsigned int hook_outgoing(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct udphdr *udph;
    
    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (iph->protocol != IPPROTO_UDP)
        return NF_ACCEPT;

    /* Get UDP header */
    udph = (struct udphdr *)((u8 *)iph + (iph->ihl << 2));
    
    /* Check if this is our target port */
    if (ntohs(udph->dest) == port_to_encrypt) {
        /* Only encrypt packets with payload */
        if (skb->len > ((iph->ihl << 2) + (udph->doff << 2))) {
            if (encrypt_packet(skb, udph) < 0) {
                printk(KERN_ERR "Failed to encrypt packet\n");
                /* Still allow the packet through even if encryption fails */
            }
        }
    }
    
    return NF_ACCEPT;
}

/**
* hook_incoming - Netfilter hook for incoming packets
* Decrypts UDP payload for specified port
*/
static unsigned int hook_incoming(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct udphdr *udph;
    
    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (iph->protocol != IPPROTO_UDP)
        return NF_ACCEPT;

    /* Get UDP header */
    udph = (struct udphdr *)((u8 *)iph + (iph->ihl << 2));
    
    /* Check if this is from our target port */
    if (ntohs(udph->source) == port_to_encrypt) {
        /* Only decrypt packets with payload */
        if (skb->len > ((iph->ihl << 2) + (udph->doff << 2))) {
            if (decrypt_packet(skb, udph) < 0) {
                printk(KERN_ERR "Failed to decrypt packet\n");
                /* Still allow the packet through even if decryption fails */
            }
        }
    }
    
    return NF_ACCEPT;
}

/**
* encrypt_packet - Encrypts UDP payload with ChaCha20-Poly1305
* @skb: Socket buffer containing the packet
* @udph: UDP header
*
* Returns 0 on success, negative error code on failure
*/
static int encrypt_packet(struct sk_buff *skb)
{
    struct scatterlist sg_in[2], sg_out[2];
    struct aead_request *req;
    DECLARE_CRYPTO_WAIT(wait);
    struct sk_buff *new_skb;
    u8 *payload, *encrypted_data;
    u8 nonce[CHACHA20POLY1305_IV_SIZE];
    struct iphdr *iph = ip_hdr(skb);
    int payload_len, ip_hdrlen, udp_hdrlen, ret;
    
    /* Calculate header and payload lengths */
    ip_hdrlen = iph->ihl << 2;
    udp_hdrlen = udph->doff << 2;
    payload_len = skb->len - ip_hdrlen - udp_hdrlen;
    
    if (payload_len <= 0) {
        return -EINVAL;
    }
    
    /* Allocate memory for encrypted data (payload + auth tag) */
    encrypted_data = kmalloc(payload_len + CHACHA20POLY1305_AUTHTAG_SIZE, GFP_ATOMIC);
    if (!encrypted_data) {
        return -ENOMEM;
    }
    
    /* Get pointer to payload */
    payload = skb->data + ip_hdrlen + udp_hdrlen;
    
    /* Prepare AEAD request */
    req = aead_request_alloc(tfm, GFP_ATOMIC);
    if (!req) {
        kfree(encrypted_data);
        return -ENOMEM;
    }
    
    /* Generate nonce (should be unique per message in production) */
    get_random_bytes(nonce, CHACHA20POLY1305_IV_SIZE);
    
    /* Set up AEAD request */
    aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
                            crypto_req_done, &wait);
    
    /* Set up scatterlists for input and output */
    sg_init_one(&sg_in[0], payload, payload_len);
    sg_init_one(&sg_out[0], encrypted_data, payload_len + CHACHA20POLY1305_AUTHTAG_SIZE);
    
    aead_request_set_crypt(req, sg_in, sg_out, payload_len, nonce);
    aead_request_set_ad(req, 0); /* No associated data for simplicity */
    
    /* Perform encryption */
    ret = crypto_wait_req(crypto_aead_encrypt(req), &wait);
    if (ret) {
        printk(KERN_ERR "ChaCha20-Poly1305 encryption failed: %d\n", ret);
        aead_request_free(req);
        kfree(encrypted_data);
        return ret;
    }
    
    /* Create a new skb with enough headroom for the larger encrypted data */
    new_skb = skb_copy_expand(skb, skb_headroom(skb), 
                            CHACHA20POLY1305_AUTHTAG_SIZE, GFP_ATOMIC);
    if (!new_skb) {
        aead_request_free(req);
        kfree(encrypted_data);
        return -ENOMEM;
    }
    
    /* Replace the payload with encrypted data */
    skb_put(new_skb, CHACHA20POLY1305_AUTHTAG_SIZE);
    memcpy(new_skb->data + ip_hdrlen + udp_hdrlen, encrypted_data, 
        payload_len + CHACHA20POLY1305_AUTHTAG_SIZE);
    
    /* Update IP header */
    iph = ip_hdr(new_skb);
    iph->tot_len = htons(new_skb->len);
    ip_send_check(iph);
    
    /* Update UDP checksum */
    udph = (struct udphdr *)(new_skb->data + ip_hdrlen);
    udph->check = 0;
    udph->check = udp_v4_check(new_skb->len - ip_hdrlen, iph->saddr, iph->daddr,
                            csum_partial(udph, new_skb->len - ip_hdrlen, 0));
    
    /* Replace original skb with the new one */
    skb_copy_from_linear_data(new_skb, skb->data, ip_hdrlen + udp_hdrlen);
    memcpy(skb_put(skb, CHACHA20POLY1305_AUTHTAG_SIZE), 
        new_skb->data + ip_hdrlen + udp_hdrlen,
        payload_len + CHACHA20POLY1305_AUTHTAG_SIZE);
    
    /* Clean up */
    kfree_skb(new_skb);
    aead_request_free(req);
    kfree(encrypted_data);
    
    return 0;
}

/**
* decrypt_packet - Decrypts UDP payload with ChaCha20-Poly1305
* @skb: Socket buffer containing the packet
* @udph: UDP header
*
* Returns 0 on success, negative error code on failure
*/
static int decrypt_packet(struct sk_buff *skb)
{
    struct scatterlist sg_in[2], sg_out[2];
    struct aead_request *req;
    DECLARE_CRYPTO_WAIT(wait);
    u8 *payload, *decrypted_data;
    u8 nonce[CHACHA20POLY1305_IV_SIZE];
    struct iphdr *iph = ip_hdr(skb);
    int payload_len, ip_hdrlen, udp_hdrlen, ret;
    
    /* Calculate header and payload lengths */
    ip_hdrlen = iph->ihl << 2;
    udp_hdrlen = udph->doff << 2;
    payload_len = skb->len - ip_hdrlen - udp_hdrlen;
    
    /* Check if we have enough data for encrypted payload + auth tag */
    if (payload_len <= CHACHA20POLY1305_AUTHTAG_SIZE) {
        return -EINVAL;
    }
    
    /* Allocate memory for decrypted data */
    decrypted_data = kmalloc(payload_len - CHACHA20POLY1305_AUTHTAG_SIZE, GFP_ATOMIC);
    if (!decrypted_data) {
        return -ENOMEM;
    }
    
    /* Get pointer to payload */
    payload = skb->data + ip_hdrlen + udp_hdrlen;
    
    /* Prepare AEAD request */
    req = aead_request_alloc(tfm, GFP_ATOMIC);
    if (!req) {
        kfree(decrypted_data);
        return -ENOMEM;
    }
    
    /* In production, nonce would need to be received from the sender or derived
    * For this example, we're using a fixed nonce (insecure!) */
    memset(nonce, 0, CHACHA20POLY1305_IV_SIZE);
    
    /* Set up AEAD request */
    aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
                            crypto_req_done, &wait);
    
    /* Set up scatterlists for input and output */
    sg_init_one(&sg_in[0], payload, payload_len);
    sg_init_one(&sg_out[0], decrypted_data, payload_len - CHACHA20POLY1305_AUTHTAG_SIZE);
    
    aead_request_set_crypt(req, sg_in, sg_out, payload_len, nonce);
    aead_request_set_ad(req, 0); /* No associated data for simplicity */
    
    /* Perform decryption */
    ret = crypto_wait_req(crypto_aead_decrypt(req), &wait);
    if (ret) {
        printk(KERN_ERR "ChaCha20-Poly1305 decryption failed: %d\n", ret);
        aead_request_free(req);
        kfree(decrypted_data);
        return ret;
    }
    
    /* Replace the encrypted payload with decrypted data */
    memcpy(payload, decrypted_data, payload_len - CHACHA20POLY1305_AUTHTAG_SIZE);
    
    /* Trim the skb to remove the auth tag */
    pskb_trim(skb, skb->len - CHACHA20POLY1305_AUTHTAG_SIZE);
    
    /* Update IP header */
    iph = ip_hdr(skb);
    iph->tot_len = htons(skb->len);
    ip_send_check(iph);
    
    /* Update UDP checksum */
    udph = (struct udphdr *)(skb->data + ip_hdrlen);
    udph->check = 0;
    udph->check = udp_v4_check(skb->len - ip_hdrlen, iph->saddr, iph->daddr,
                            csum_partial(udph, skb->len - ip_hdrlen, 0));
    
    /* Clean up */
    aead_request_free(req);
    kfree(decrypted_data);
    
    return 0;
}

/**
* Module initialization
*/
static int __init secure_skbuff_init(void)
{
    int ret;
    
    printk(KERN_INFO "Loading secure socket buffer encryption module\n");
    
    /* Generate X25519 keypair */
    ret = x25519_generate_keypair();
    if (ret) {
        printk(KERN_ERR "Failed to generate X25519 keypair: %d\n", ret);
        return ret;
    }
    
    printk(KERN_INFO "X25519 keypair generated\n");
    
    /* For demonstration, we use a hardcoded remote public key
    * In a real implementation, you would exchange keys through a secure channel */
    u8 demo_remote_pubkey[X25519_KEY_SIZE] = {
        0x89, 0x45, 0x67, 0xab, 0xcd, 0xef, 0xfe, 0xdc,
        0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23,
        0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc,
        0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23
    };
    
    /* Copy remote public key */
    memcpy(remote_public_key, demo_remote_pubkey, X25519_KEY_SIZE);
    
    /* Compute shared secret */
    ret = x25519_compute_shared_secret(private_key, remote_public_key, shared_secret);
    if (ret) {
        printk(KERN_ERR "Failed to compute shared secret: %d\n", ret);
        return ret;
    }
    
    printk(KERN_INFO "Shared secret computed\n");
    
    /* Derive ChaCha20-Poly1305 key using BLAKE2s */
    ret = derive_chacha_key(shared_secret, public_key, remote_public_key, chacha_key);
    if (ret) {
        printk(KERN_ERR "Failed to derive ChaCha20-Poly1305 key: %d\n", ret);
        return ret;
    }
    
    printk(KERN_INFO "ChaCha20-Poly1305 key derived using BLAKE2s\n");
    
    /* Set up cryptographic transforms */
    ret = setup_crypto();
    if (ret) {
        printk(KERN_ERR "Failed to set up crypto: %d\n", ret);
        return ret;
    }
    
    printk(KERN_INFO "Crypto setup complete\n");
    
    /* Register netfilter hooks */
    ret = nf_register_net_hooks(&init_net, nf_hook_ops, ARRAY_SIZE(nf_hook_ops));
    if (ret) {
        printk(KERN_ERR "Failed to register netfilter hooks: %d\n", ret);
        crypto_free_aead(tfm);
        return ret;
    }
    
    printk(KERN_INFO "Secure socket buffer encryption module loaded successfully\n");
    printk(KERN_INFO "Encrypting traffic on UDP port %d\n", port_to_encrypt);
    
    return 0;
}

/**
* Module cleanup
*/
static void __exit secure_skbuff_exit(void)
{
    /* Unregister netfilter hooks */
    nf_unregister_net_hooks(&init_net, nf_hook_ops, ARRAY_SIZE(nf_hook_ops));
    
    /* Free crypto resources */
    crypto_free_aead(tfm);
    
    printk(KERN_INFO "Secure socket buffer encryption module unloaded\n");
}

module_init(secure_skbuff_init);
module_exit(secure_skbuff_exit);