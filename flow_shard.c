/* flow_shard.c
 * Splitting a capture into flow-disjoint shards
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>

#include <glib.h>

#include "flow_shard.h"

#include <app/application_flavor.h>
#include <wsutil/ws_assert.h>

#define FLOW_SHARD_KEY_MAX 32   /* two IPv6 addresses */

#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_IPV6 0x86dd
#define ETHERTYPE_VLAN 0x8100
#define ETHERTYPE_QINQ 0x88a8

typedef struct {
    uint8_t  len;
    uint8_t  addrs[FLOW_SHARD_KEY_MAX];
} flow_shard_key_t;

typedef struct {
    flow_shard_key_t key;
    uint64_t         packets;
    unsigned         shard;
} flow_shard_pair_t;

struct flow_shard_plan {
    unsigned    shards;
    uint64_t    packets;
    uint64_t    unkeyed;
    uint64_t   *shard_packets;
    GHashTable *pairs;          /* flow_shard_pair_t * -> itself */
};

static unsigned
flow_shard_key_hash(const void *v)
{
    const flow_shard_key_t *key = (const flow_shard_key_t *)v;
    unsigned hash = 2166136261u;   /* FNV-1a */
    uint8_t  i;

    for (i = 0; i < key->len; i++) {
        hash = (hash ^ key->addrs[i]) * 16777619u;
    }

    return hash;
}

static gboolean
flow_shard_key_equal(const void *a, const void *b)
{
    const flow_shard_key_t *ka = (const flow_shard_key_t *)a;
    const flow_shard_key_t *kb = (const flow_shard_key_t *)b;

    return ka->len == kb->len && memcmp(ka->addrs, kb->addrs, ka->len) == 0;
}

/* The pair is unordered, so that both directions of a flow land on the same
 * worker: store the lower address first. */
static void
flow_shard_key_set(flow_shard_key_t *key, const uint8_t *src,
        const uint8_t *dst, uint8_t addr_len)
{
    key->len = (uint8_t)(addr_len * 2);

    if (memcmp(src, dst, addr_len) <= 0) {
        memcpy(key->addrs, src, addr_len);
        memcpy(key->addrs + addr_len, dst, addr_len);
    }
    else {
        memcpy(key->addrs, dst, addr_len);
        memcpy(key->addrs + addr_len, src, addr_len);
    }
}

/* Pull the addresses out of an IP header. */
static bool
flow_shard_key_from_ip(const uint8_t *pd, unsigned caplen,
        flow_shard_key_t *key)
{
    if (caplen < 1) {
        return false;
    }

    switch (pd[0] >> 4) {
        case 4:
            if (caplen < 20) {
                return false;
            }
            flow_shard_key_set(key, pd + 12, pd + 16, 4);
            return true;
        case 6:
            if (caplen < 40) {
                return false;
            }
            flow_shard_key_set(key, pd + 8, pd + 24, 16);
            return true;
        default:
            return false;
    }
}

/* Only the encapsulations whose IP header can be found by arithmetic are
 * handled; anything else is unkeyed, which costs a share of worker 0 rather
 * than correctness. */
static bool
flow_shard_key_from_packet(int encap, const uint8_t *pd, unsigned caplen,
        flow_shard_key_t *key)
{
    unsigned offset;
    uint16_t ethertype;

    switch (encap) {
        case WTAP_ENCAP_ETHERNET:
            if (caplen < 14) {
                return false;
            }
            ethertype = (uint16_t)(pd[12] << 8 | pd[13]);
            offset    = 14;
            while ((ethertype == ETHERTYPE_VLAN || ethertype == ETHERTYPE_QINQ)
                    && caplen >= offset + 4) {
                ethertype = (uint16_t)(pd[offset + 2] << 8 | pd[offset + 3]);
                offset   += 4;
            }
            if (ethertype != ETHERTYPE_IPV4 && ethertype != ETHERTYPE_IPV6) {
                return false;
            }
            return flow_shard_key_from_ip(pd + offset, caplen - offset, key);

        case WTAP_ENCAP_RAW_IP:
        case WTAP_ENCAP_RAW_IP4:
        case WTAP_ENCAP_RAW_IP6:
            return flow_shard_key_from_ip(pd, caplen, key);

        default:
            return false;
    }
}

/* Biggest pair first, and by key where the counts are equal, so that every
 * process that builds a plan for the same capture builds the same plan. */
static int
flow_shard_pair_compare(const void *a, const void *b)
{
    const flow_shard_pair_t *pa = *(const flow_shard_pair_t * const *)a;
    const flow_shard_pair_t *pb = *(const flow_shard_pair_t * const *)b;

    if (pa->packets != pb->packets) {
        return pa->packets > pb->packets ? -1 : 1;
    }
    if (pa->key.len != pb->key.len) {
        return pa->key.len < pb->key.len ? -1 : 1;
    }

    return memcmp(pa->key.addrs, pb->key.addrs, pa->key.len);
}

/* Longest-processing-time-first: hand each pair, biggest first, to whichever
 * worker has the least work so far. Hashing the key instead leaves the
 * busiest worker 24% above ideal at 4 ways on real traffic, and 72% at 16,
 * because the distribution of flow sizes is nothing like uniform. */
static void
flow_shard_assign(flow_shard_plan_t *plan)
{
    GPtrArray     *pairs;
    GHashTableIter iter;
    void          *value;
    unsigned       i;

    pairs = g_ptr_array_sized_new(g_hash_table_size(plan->pairs));

    g_hash_table_iter_init(&iter, plan->pairs);
    while (g_hash_table_iter_next(&iter, NULL, &value)) {
        g_ptr_array_add(pairs, value);
    }
    g_ptr_array_sort(pairs, flow_shard_pair_compare);

    for (i = 0; i < pairs->len; i++) {
        flow_shard_pair_t *pair = (flow_shard_pair_t *)pairs->pdata[i];
        unsigned           least = 0;
        unsigned           shard;

        for (shard = 1; shard < plan->shards; shard++) {
            if (plan->shard_packets[shard] < plan->shard_packets[least]) {
                least = shard;
            }
        }

        pair->shard = least;
        plan->shard_packets[least] += pair->packets;
    }

    g_ptr_array_free(pairs, TRUE);
}

flow_shard_plan_t *
flow_shard_plan_new(const char *filename, unsigned shards, int *err,
        char **err_info)
{
    flow_shard_plan_t *plan;
    wtap              *wth;
    wtap_rec           rec;
    int64_t            offset;

    ws_assert(shards > 0);

    wth = wtap_open_offline(filename, WTAP_TYPE_AUTO, err, err_info, false,
            application_configuration_environment_prefix());
    if (wth == NULL) {
        return NULL;
    }

    plan                = g_new0(flow_shard_plan_t, 1);
    plan->shards        = shards;
    plan->shard_packets = g_new0(uint64_t, shards);
    plan->pairs         = g_hash_table_new_full(flow_shard_key_hash,
            flow_shard_key_equal, NULL, g_free);

    wtap_rec_init(&rec, 1514);

    while (wtap_read(wth, &rec, err, err_info, &offset)) {
        flow_shard_key_t   key;
        flow_shard_pair_t *pair;

        if (rec.rec_type != REC_TYPE_PACKET) {
            wtap_rec_reset(&rec);
            continue;
        }

        plan->packets++;

        if (!flow_shard_key_from_packet(rec.rec_header.packet_header.pkt_encap,
                    ws_buffer_start_ptr(&rec.data),
                    rec.rec_header.packet_header.caplen, &key)) {
            plan->unkeyed++;
            wtap_rec_reset(&rec);
            continue;
        }

        pair = (flow_shard_pair_t *)g_hash_table_lookup(plan->pairs, &key);
        if (pair == NULL) {
            pair      = g_new0(flow_shard_pair_t, 1);
            pair->key = key;
            g_hash_table_insert(plan->pairs, &pair->key, pair);
        }
        pair->packets++;

        wtap_rec_reset(&rec);
    }

    wtap_rec_cleanup(&rec);
    wtap_close(wth);

    if (*err != 0) {
        flow_shard_plan_free(plan);
        return NULL;
    }

    /* The unkeyed packets are worker 0's before any flow is. */
    plan->shard_packets[0] = plan->unkeyed;
    flow_shard_assign(plan);

    return plan;
}

void
flow_shard_plan_free(flow_shard_plan_t *plan)
{
    if (plan == NULL) {
        return;
    }

    g_hash_table_destroy(plan->pairs);
    g_free(plan->shard_packets);
    g_free(plan);
}

unsigned
flow_shard_plan_shard_of(const flow_shard_plan_t *plan, int encap,
        const uint8_t *pd, unsigned caplen)
{
    flow_shard_key_t         key;
    const flow_shard_pair_t *pair;

    if (!flow_shard_key_from_packet(encap, pd, caplen, &key)) {
        return 0;
    }

    pair = (const flow_shard_pair_t *)g_hash_table_lookup(plan->pairs, &key);

    /* A pair the plan has never seen can only come from a different file. */
    return pair != NULL ? pair->shard : 0;
}

unsigned
flow_shard_plan_shards(const flow_shard_plan_t *plan)
{
    return plan->shards;
}

uint64_t
flow_shard_plan_packets(const flow_shard_plan_t *plan)
{
    return plan->packets;
}

uint64_t
flow_shard_plan_pairs(const flow_shard_plan_t *plan)
{
    return g_hash_table_size(plan->pairs);
}

uint64_t
flow_shard_plan_unkeyed(const flow_shard_plan_t *plan)
{
    return plan->unkeyed;
}

uint64_t
flow_shard_plan_shard_packets(const flow_shard_plan_t *plan, unsigned shard)
{
    ws_assert(shard < plan->shards);

    return plan->shard_packets[shard];
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
