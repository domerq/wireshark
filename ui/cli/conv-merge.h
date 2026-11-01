/** @file
 *
 * Folding the conversation and endpoint tables of several processes into
 * the table one process would have built.
 *
 * A flow-sharded run (tshark --jobs) gives each worker whole flows, so
 * each worker's table holds the conversations it was given and nothing
 * else. The rows are the whole state of these two statistics, so the
 * parent can read them back and add them up: same address pair, same
 * ports, same type is the same conversation, and a conversation two
 * workers both saw - the inner header of an ICMP error names a flow that
 * belongs to someone else - has to be folded rather than dropped, since
 * each of them counted part of it.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __CONV_MERGE_H__
#define __CONV_MERGE_H__

#include <epan/conversation_table.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Register a conversation or endpoint table.
 *
 * Every process in a sharded run - the workers and the parent - creates
 * the same tables in the same order, the order of the -z arguments, so
 * the index this returns names the table a spooled row belongs to.
 *
 * @param hash The table's hash, whose conv_array holds the rows.
 * @param is_endpoint true for an endpoint table, false for conversations.
 * @return The index of the table.
 */
unsigned conv_merge_add_table(conv_hash_t *hash, bool is_endpoint);

/**
 * @brief Worker, second pass: spool the tables to this descriptor
 * instead of printing them.
 */
void conv_merge_spool_to(int fd);

/**
 * @brief Worker, first pass: this pass prints nothing, so its tables are
 * thrown away.
 */
void conv_merge_discard(void);

/**
 * @brief Does the creation frame of each row have to be recorded?
 *
 * The parent prints the rows in the order the capture created them, which
 * is the order the draw functions break ties in, so a spooling worker has
 * to say which frame created each of its rows.
 */
bool conv_merge_needs_frames(void);

/**
 * @brief Note that a tap packet function appended rows to a table.
 *
 * @param table The table index from conv_merge_add_table().
 * @param rows How many rows were appended.
 * @param frame The frame being dissected.
 */
void conv_merge_rows_added(unsigned table, unsigned rows, uint32_t frame);

/**
 * @brief Called by a draw function before it prints anything.
 *
 * @param table The table index from conv_merge_add_table().
 * @return true if the table should be printed; false if it has been
 * spooled for the parent to fold, or discarded.
 */
bool conv_merge_draw(unsigned table);

/**
 * @brief Parent: fold the workers' rows into the registered tables.
 *
 * @param fds One spool descriptor per worker.
 * @param count How many workers.
 * @return true if every spool could be read.
 */
bool conv_merge_collect(const int *fds, unsigned count);

#ifdef __cplusplus
}
#endif

#endif /* __CONV_MERGE_H__ */
