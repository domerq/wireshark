/** @file
 * Splitting a capture into flow-disjoint shards
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __FLOW_SHARD_H__
#define __FLOW_SHARD_H__

#include <stdint.h>

#include <wiretap/wtap.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * A plan for dividing the packets of a capture file between N workers so
 * that each worker sees whole flows and the work is evenly divided.
 *
 * Packets are keyed on the unordered pair of IP addresses rather than on
 * the 5-tuple, because IP fragments carry no ports: a 5-tuple key would
 * separate a fragmented datagram from the flow it belongs to. The pairs
 * are assigned longest-processing-time-first, which needs the packet
 * counts, which is why building a plan costs one pass over the file.
 *
 * The plan holds one entry per address pair, not per packet, so a worker
 * decides what to do with a packet by looking its key up rather than by
 * consulting a per-frame index.
 */
typedef struct flow_shard_plan flow_shard_plan_t;

/**
 * @brief Build a plan for a capture file.
 *
 * Reads the whole file once, parsing only enough of each packet to find
 * the addresses. Nothing is dissected.
 *
 * A file that stops in the middle of a packet is planned as far as it
 * goes: whoever reads it next reaches the same point and reports the
 * same error as a single process would.
 *
 * @param filename The capture file to plan for.
 * @param shards Number of workers to divide the packets between.
 * @param err Set to a wiretap error code if the file could not be opened
 *            or could not be read to the end.
 * @param err_info Set to a newly allocated error string, which the caller
 *            must g_free(), if the file could not be opened.
 * @return The plan, or NULL if the file could not be opened.
 */
flow_shard_plan_t *
flow_shard_plan_new(const char *filename, unsigned shards, int *err,
        char **err_info);

/**
 * @brief Free a plan.
 *
 * @param plan The plan, or NULL.
 */
void
flow_shard_plan_free(flow_shard_plan_t *plan);

/**
 * @brief Which worker a packet belongs to.
 *
 * Packets with no IP addresses - ARP, STP, and anything in an encapsulation
 * this does not parse - all go to worker 0, since they carry no flow state
 * that another packet could need.
 *
 * @param plan The plan.
 * @param encap The packet's WTAP_ENCAP_ value.
 * @param pd The packet data.
 * @param caplen The number of bytes captured.
 * @return The worker index, in 0..shards-1.
 */
unsigned
flow_shard_plan_shard_of(const flow_shard_plan_t *plan, int encap,
        const uint8_t *pd, unsigned caplen);

/** @brief Number of workers the plan divides the capture between. */
unsigned
flow_shard_plan_shards(const flow_shard_plan_t *plan);

/** @brief Total number of packets in the capture. */
uint64_t
flow_shard_plan_packets(const flow_shard_plan_t *plan);

/** @brief Number of distinct address pairs found. */
uint64_t
flow_shard_plan_pairs(const flow_shard_plan_t *plan);

/** @brief Number of packets that had no IP addresses to key on. */
uint64_t
flow_shard_plan_unkeyed(const flow_shard_plan_t *plan);

/**
 * @brief Number of packets assigned to one worker.
 *
 * @param plan The plan.
 * @param shard The worker index.
 * @return The packet count.
 */
uint64_t
flow_shard_plan_shard_packets(const flow_shard_plan_t *plan, unsigned shard);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __FLOW_SHARD_H__ */
