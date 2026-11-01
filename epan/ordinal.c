/* ordinal.c
 * Numbers handed out in the order things are first seen
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stddef.h>

#include "ordinal.h"

static ordinal_provider_fn ordinal_provider;
static void               *ordinal_provider_data;

uint32_t
ordinal_next_for(ordinal_counter_t *counter, uint32_t frame,
        uint64_t identity)
{
    uint32_t value;

    if (ordinal_provider != NULL) {
        value = ordinal_provider(counter->name, &counter->provider_id, frame,
                identity, ordinal_provider_data);
        /* Keep the plain counter past the values handed out, so that
         * callers asking "how many are there" still get an answer. */
        if (value >= counter->next) {
            counter->next = value + 1;
        }
        return value;
    }

    return counter->next++;
}

static uint64_t
ordinal_hash_endpoint(uint64_t hash, const address *addr, uint32_t port)
{
    const uint8_t *bytes = (const uint8_t *)addr->data;
    int            i;

    for (i = 0; i < addr->len; i++) {
        hash = (hash ^ bytes[i]) * UINT64_C(1099511628211);
    }
    for (i = 0; i < 4; i++) {
        hash = (hash ^ ((port >> (i * 8)) & 0xff)) * UINT64_C(1099511628211);
    }

    return hash;
}

uint64_t
ordinal_identity(const address *addr_a, uint32_t port_a,
        const address *addr_b, uint32_t port_b)
{
    uint64_t hash  = UINT64_C(14695981039346656037);
    int      order = cmp_address(addr_a, addr_b);

    /* Lower endpoint first, so that both directions hash the same. */
    if (order > 0 || (order == 0 && port_a > port_b)) {
        const address *swap_addr = addr_a;
        uint32_t       swap_port = port_a;

        addr_a = addr_b;
        port_a = port_b;
        addr_b = swap_addr;
        port_b = swap_port;
    }

    hash = ordinal_hash_endpoint(hash, addr_a, port_a);
    hash = ordinal_hash_endpoint(hash, addr_b, port_b);

    /* Zero means "nothing else numbers this", so never hand it back. */
    return hash != 0 ? hash : 1;
}

void
ordinal_counter_reset(ordinal_counter_t *counter)
{
    counter->next = 0;
}

void
ordinal_set_provider(ordinal_provider_fn fn, void *user)
{
    ordinal_provider      = fn;
    ordinal_provider_data = user;
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
