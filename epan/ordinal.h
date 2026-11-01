/** @file
 * Numbers handed out in the order things are first seen
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __EPAN_ORDINAL_H__
#define __EPAN_ORDINAL_H__

#include <stdint.h>
#include <epan/address.h>
#include <ws_symbol_export.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * Several things a dissection hands to the user are numbered by the order
 * in which they were first seen: conversation indices, tcp.stream,
 * mptcp.stream and so on. A single sequential pass gives those numbers
 * their meaning, and anything that dissects a capture in pieces - several
 * processes each taking a subset of the flows - would otherwise number
 * its own pieces from zero and produce different output.
 *
 * A counter therefore asks for its next value rather than incrementing a
 * static, and a process that is dissecting part of a capture can install
 * a provider that answers with the value the whole capture would have
 * produced. With no provider installed, which is the normal case, this is
 * exactly the static it replaces.
 */
typedef struct ordinal_counter {
    const char *name;       /**< Stable across processes; the provider's key. */
    uint32_t    next;       /**< Next value when there is no provider. */
    int         provider_id;/**< Provider's handle for this counter, or -1. */
} ordinal_counter_t;

/** Initializer for a counter; @p n must be a literal, stable name. */
#define ORDINAL_COUNTER_INIT(n) { n, 0, -1 }

/**
 * @brief Take the next value of a counter.
 *
 * @param counter The counter.
 * @param frame The frame number being dissected, which is what orders
 *            the values across processes.
 * @param identity What the value is being handed out for, where more
 *            than one process can be numbering the same thing - a
 *            conversation between two MAC addresses, say, which is not
 *            confined to one flow. Everything numbering that identity
 *            gets the same value. Zero where the thing being numbered
 *            belongs to one process alone, which is the usual case.
 * @return The value.
 */
WS_DLL_PUBLIC
uint32_t
ordinal_next_for(ordinal_counter_t *counter, uint32_t frame,
        uint64_t identity);

/** @brief ordinal_next_for() for something only one process numbers. */
#define ordinal_next(counter, frame) ordinal_next_for((counter), (frame), 0)

/**
 * @brief An identity for something numbered per conversation.
 *
 * Hashes the two endpoints in a fixed order, so that both directions of
 * a flow - and every process that meets that flow - produce the same
 * identity. A process can meet a flow it does not own: the inner header
 * of an ICMP error names another flow, and whoever dissects the error
 * creates state for it.
 *
 * @param addr_a One endpoint's address.
 * @param port_a Its port, or 0 where the thing is not keyed on ports.
 * @param addr_b The other endpoint's address.
 * @param port_b Its port, or 0.
 * @return The identity, never zero.
 */
WS_DLL_PUBLIC
uint64_t
ordinal_identity(const address *addr_a, uint32_t port_a,
        const address *addr_b, uint32_t port_b);

/**
 * @brief Start a counter over, as at the start of a capture file.
 *
 * @param counter The counter.
 */
WS_DLL_PUBLIC
void
ordinal_counter_reset(ordinal_counter_t *counter);

/**
 * @brief Answer for ordinal_next() instead of the counter itself.
 *
 * @param name The counter's name.
 * @param id In/out: the provider's handle for this counter, -1 the first
 *            time it is asked about, whatever the provider stored after
 *            that. Lets a provider avoid looking the name up every time.
 * @param frame The frame number being dissected.
 * @param identity What the value is for, or zero; see
 *            ordinal_next_for().
 * @param user The pointer given to ordinal_set_provider().
 * @return The value to hand out.
 */
typedef uint32_t (*ordinal_provider_fn)(const char *name, int *id,
        uint32_t frame, uint64_t identity, void *user);

/**
 * @brief Install, or remove, a provider of ordinal values.
 *
 * @param fn The provider, or NULL to go back to plain counting.
 * @param user Passed to the provider.
 */
WS_DLL_PUBLIC
void
ordinal_set_provider(ordinal_provider_fn fn, void *user);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __EPAN_ORDINAL_H__ */
