/* conv-merge.c
 *
 * Folding the conversation and endpoint tables of several processes into
 * the table one process would have built. See conv-merge.h.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <ws_exit_codes.h>
#include <epan/address.h>
#include <epan/conversation_table.h>
#include <wsutil/cmdarg_err.h>
#include <wsutil/file_util.h>
#include <wsutil/nstime.h>

#include "conv-merge.h"

/* One row as it crosses from a worker to the parent: the fixed-width
 * part, then addr1_len and addr2_len bytes of address. Both ends are the
 * same binary in the same process family, so the struct goes out as it
 * stands. */
typedef struct {
    uint64_t tx_frames, rx_frames, tx_bytes, rx_bytes;
    uint64_t tx_frames_total, rx_frames_total, tx_bytes_total, rx_bytes_total;
    uint64_t flows;
    int64_t  start_secs, stop_secs, abs_secs;
    int32_t  start_nsecs, stop_nsecs, abs_nsecs;
    uint32_t table;             /* which -z table, in registration order */
    uint32_t frame;             /* the frame that created the row */
    uint32_t index;             /* its place in this worker's table */
    int32_t  type;              /* conversation_type or endpoint_type */
    uint32_t port1, port2;
    int32_t  addr1_type, addr2_type;
    uint32_t addr1_len, addr2_len;
    uint8_t  is_endpoint, filtered, modified, pad;
} conv_merge_row_t;

/* An address longer than this is not something these tables hold; a
 * spool that claims one has been corrupted. */
#define CONV_MERGE_MAX_ADDR 1024

typedef enum {
    CONV_MERGE_PRINT,           /* one process, or the parent printing */
    CONV_MERGE_SPOOL,           /* a worker handing its rows over */
    CONV_MERGE_DISCARD          /* a worker's first pass, which prints nothing */
} conv_merge_mode_e;

typedef struct {
    conv_hash_t *hash;
    bool         is_endpoint;
    GArray      *frames;        /* worker side: creation frame per row */
} conv_merge_table_t;

/* The folded form of one conversation or endpoint. The counters are kept
 * in the canonical direction - addr1 is the lower of the two addresses -
 * so that two workers which first saw the conversation from opposite
 * ends still add up. */
typedef struct {
    uint64_t order;             /* frame and row that created it first */
    unsigned rows;              /* how many workers' rows went in */
    unsigned table;
    bool     is_endpoint;
    int32_t  type;
    address  addr1, addr2;
    uint32_t port1, port2;
    bool     reversed;          /* the earliest row had src == addr2 */
    uint64_t tx_frames, rx_frames, tx_bytes, rx_bytes;
    uint64_t tx_frames_total, rx_frames_total, tx_bytes_total, rx_bytes_total;
    uint64_t flows;
    nstime_t start_time, stop_time, start_abs_time;
    bool     filtered, modified;
} conv_merge_item_t;

static conv_merge_mode_e  conv_merge_mode = CONV_MERGE_PRINT;
static FILE              *conv_merge_fp;
static GArray            *conv_merge_tables;    /* of conv_merge_table_t */

unsigned
conv_merge_add_table(conv_hash_t *hash, bool is_endpoint)
{
    conv_merge_table_t table;

    if (conv_merge_tables == NULL) {
        conv_merge_tables = g_array_new(FALSE, FALSE,
                sizeof(conv_merge_table_t));
    }

    table.hash        = hash;
    table.is_endpoint = is_endpoint;
    table.frames      = NULL;
    g_array_append_val(conv_merge_tables, table);

    return conv_merge_tables->len - 1;
}

void
conv_merge_spool_to(int fd)
{
    conv_merge_fp = ws_fdopen(fd, "wb");
    if (conv_merge_fp == NULL) {
        cmdarg_err("Can't spool the statistics: %s", g_strerror(errno));
        exit(WS_EXIT_INVALID_FILE);
    }
    conv_merge_mode = CONV_MERGE_SPOOL;
}

void
conv_merge_discard(void)
{
    conv_merge_mode = CONV_MERGE_DISCARD;
}

bool
conv_merge_needs_frames(void)
{
    return conv_merge_mode == CONV_MERGE_SPOOL;
}

void
conv_merge_rows_added(unsigned table, unsigned rows, uint32_t frame)
{
    conv_merge_table_t *t;

    if (conv_merge_mode != CONV_MERGE_SPOOL || rows == 0 ||
            conv_merge_tables == NULL || table >= conv_merge_tables->len) {
        return;
    }

    t = &g_array_index(conv_merge_tables, conv_merge_table_t, table);
    if (t->frames == NULL) {
        t->frames = g_array_new(FALSE, FALSE, sizeof(uint32_t));
    }
    while (rows-- != 0) {
        g_array_append_val(t->frames, frame);
    }
}

static void
conv_merge_spill(const void *data, size_t len)
{
    if (len != 0 && fwrite(data, 1, len, conv_merge_fp) != len) {
        cmdarg_err("Can't spool the statistics: %s", g_strerror(errno));
        exit(WS_EXIT_INVALID_FILE);
    }
}

/* Hand one table's rows to the parent. */
static void
conv_merge_write(unsigned table)
{
    conv_merge_table_t *t = &g_array_index(conv_merge_tables,
            conv_merge_table_t, table);
    unsigned i;

    for (i = 0; t->hash->conv_array != NULL && i < t->hash->conv_array->len;
            i++) {
        conv_merge_row_t row;
        const address   *addr1, *addr2 = NULL;

        memset(&row, 0, sizeof(row));
        row.table = table;
        row.index = i;
        row.frame = (t->frames != NULL && i < t->frames->len) ?
            g_array_index(t->frames, uint32_t, i) : 0;

        if (t->is_endpoint) {
            endpoint_item_t *e = &g_array_index(t->hash->conv_array,
                    endpoint_item_t, i);

            row.is_endpoint     = 1;
            row.type            = (int32_t)e->etype;
            row.port1           = e->port;
            row.tx_frames       = e->tx_frames;
            row.rx_frames       = e->rx_frames;
            row.tx_bytes        = e->tx_bytes;
            row.rx_bytes        = e->rx_bytes;
            row.tx_frames_total = e->tx_frames_total;
            row.rx_frames_total = e->rx_frames_total;
            row.tx_bytes_total  = e->tx_bytes_total;
            row.rx_bytes_total  = e->rx_bytes_total;
            row.filtered        = e->filtered ? 1 : 0;
            row.modified        = e->modified ? 1 : 0;
            addr1               = &e->myaddress;
        }
        else {
            conv_item_t *c = &g_array_index(t->hash->conv_array, conv_item_t,
                    i);

            row.type            = (int32_t)c->ctype;
            row.port1           = c->src_port;
            row.port2           = c->dst_port;
            row.tx_frames       = c->tx_frames;
            row.rx_frames       = c->rx_frames;
            row.tx_bytes        = c->tx_bytes;
            row.rx_bytes        = c->rx_bytes;
            row.tx_frames_total = c->tx_frames_total;
            row.rx_frames_total = c->rx_frames_total;
            row.tx_bytes_total  = c->tx_bytes_total;
            row.rx_bytes_total  = c->rx_bytes_total;
            row.flows           = c->ext_tcp.flows;
            row.filtered        = c->filtered ? 1 : 0;
            row.start_secs      = (int64_t)c->start_time.secs;
            row.start_nsecs     = c->start_time.nsecs;
            row.stop_secs       = (int64_t)c->stop_time.secs;
            row.stop_nsecs      = c->stop_time.nsecs;
            row.abs_secs        = (int64_t)c->start_abs_time.secs;
            row.abs_nsecs       = c->start_abs_time.nsecs;
            addr1               = &c->src_address;
            addr2               = &c->dst_address;
        }

        row.addr1_type = addr1->type;
        row.addr1_len  = (uint32_t)addr1->len;
        if (addr2 != NULL) {
            row.addr2_type = addr2->type;
            row.addr2_len  = (uint32_t)addr2->len;
        }

        conv_merge_spill(&row, sizeof(row));
        conv_merge_spill(addr1->data, row.addr1_len);
        if (addr2 != NULL) {
            conv_merge_spill(addr2->data, row.addr2_len);
        }
    }

    if (fflush(conv_merge_fp) != 0) {
        cmdarg_err("Can't spool the statistics: %s", g_strerror(errno));
        exit(WS_EXIT_INVALID_FILE);
    }
}

bool
conv_merge_draw(unsigned table)
{
    switch (conv_merge_mode) {

    case CONV_MERGE_SPOOL:
        conv_merge_write(table);
        return false;

    case CONV_MERGE_DISCARD:
        return false;

    case CONV_MERGE_PRINT:
    default:
        return true;
    }
}

/* What makes two rows the same conversation: the type, the addresses and
 * ports in canonical order, and, for the rare table that holds the same
 * five-tuple twice because a port was reused, which of those it is. */
static GBytes *
conv_merge_key(const conv_merge_row_t *row, const address *addr1,
        const address *addr2, uint32_t port1, uint32_t port2,
        unsigned occurrence, bool with_occurrence)
{
    GByteArray *key = g_byte_array_new();
    int32_t     type = row->type;
    uint8_t     endpoint = row->is_endpoint;

    g_byte_array_append(key, (const uint8_t *)&type, sizeof(type));
    g_byte_array_append(key, &endpoint, sizeof(endpoint));
    g_byte_array_append(key, (const uint8_t *)&addr1->type,
            sizeof(addr1->type));
    g_byte_array_append(key, (const uint8_t *)&addr1->len, sizeof(addr1->len));
    if (addr1->len > 0) {
        g_byte_array_append(key, (const uint8_t *)addr1->data,
                (unsigned)addr1->len);
    }
    g_byte_array_append(key, (const uint8_t *)&port1, sizeof(port1));
    if (!row->is_endpoint) {
        g_byte_array_append(key, (const uint8_t *)&addr2->type,
                sizeof(addr2->type));
        g_byte_array_append(key, (const uint8_t *)&addr2->len,
                sizeof(addr2->len));
        if (addr2->len > 0) {
            g_byte_array_append(key, (const uint8_t *)addr2->data,
                    (unsigned)addr2->len);
        }
        g_byte_array_append(key, (const uint8_t *)&port2, sizeof(port2));
    }
    if (with_occurrence) {
        g_byte_array_append(key, (const uint8_t *)&occurrence,
                sizeof(occurrence));
    }

    return g_byte_array_free_to_bytes(key);
}

/* Add one worker's row to the table being folded. */
static void
conv_merge_fold(GHashTable *folded, GHashTable *seen, GPtrArray *items,
        const conv_merge_row_t *row, const uint8_t *data1,
        const uint8_t *data2)
{
    conv_merge_item_t *item;
    address            addr1, addr2;
    uint32_t           port1 = row->port1, port2 = row->port2;
    uint64_t           order;
    unsigned           occurrence;
    bool               reversed = false;
    GBytes            *base, *key;

    set_address(&addr1, row->addr1_type, (int)row->addr1_len,
            row->addr1_len != 0 ? data1 : NULL);
    clear_address(&addr2);

    if (!row->is_endpoint) {
        int cmp;

        set_address(&addr2, row->addr2_type, (int)row->addr2_len,
                row->addr2_len != 0 ? data2 : NULL);

        /* The two directions of a conversation, and the two workers that
         * may each have met it first from a different end, have to land
         * on one key. */
        cmp = cmp_address(&addr1, &addr2);
        if (cmp > 0 || (cmp == 0 && port1 > port2)) {
            address  tmp_addr = addr1;
            uint32_t tmp_port = port1;

            addr1    = addr2;
            addr2    = tmp_addr;
            port1    = port2;
            port2    = tmp_port;
            reversed = true;
        }
    }

    /* A worker that holds the same five-tuple twice - a reused port, a
     * new conversation - keeps them apart by the order it met them, which
     * is the order a single process met them in too. */
    base = conv_merge_key(row, &addr1, &addr2, port1, port2, 0, false);
    occurrence = GPOINTER_TO_UINT(g_hash_table_lookup(seen, base));
    g_hash_table_insert(seen, g_bytes_ref(base),
            GUINT_TO_POINTER(occurrence + 1));
    g_bytes_unref(base);

    key = conv_merge_key(row, &addr1, &addr2, port1, port2, occurrence, true);
    item = (conv_merge_item_t *)g_hash_table_lookup(folded, key);
    if (item == NULL) {
        item = g_new0(conv_merge_item_t, 1);
        item->table       = row->table;
        item->is_endpoint = row->is_endpoint != 0;
        item->type        = row->type;
        item->port1       = port1;
        item->port2       = port2;
        copy_address(&item->addr1, &addr1);
        if (!item->is_endpoint) {
            copy_address(&item->addr2, &addr2);
        }
        g_hash_table_insert(folded, key, item);
        g_ptr_array_add(items, item);
    }
    else {
        g_bytes_unref(key);
    }

    if (reversed) {
        item->tx_frames       += row->rx_frames;
        item->rx_frames       += row->tx_frames;
        item->tx_bytes        += row->rx_bytes;
        item->rx_bytes        += row->tx_bytes;
        item->tx_frames_total += row->rx_frames_total;
        item->rx_frames_total += row->tx_frames_total;
        item->tx_bytes_total  += row->rx_bytes_total;
        item->rx_bytes_total  += row->tx_bytes_total;
    }
    else {
        item->tx_frames       += row->tx_frames;
        item->rx_frames       += row->rx_frames;
        item->tx_bytes        += row->tx_bytes;
        item->rx_bytes        += row->rx_bytes;
        item->tx_frames_total += row->tx_frames_total;
        item->rx_frames_total += row->rx_frames_total;
        item->tx_bytes_total  += row->tx_bytes_total;
        item->rx_bytes_total  += row->rx_bytes_total;
    }
    item->flows += row->flows;

    /* Only a row no worker saw any unfiltered traffic for is filtered. */
    item->filtered = item->rows == 0 ?
        (row->filtered != 0) : (item->filtered && row->filtered != 0);
    item->modified = item->modified || row->modified != 0;

    if (!item->is_endpoint) {
        nstime_t start, stop, abs_start;

        start.secs      = (time_t)row->start_secs;
        start.nsecs     = row->start_nsecs;
        stop.secs       = (time_t)row->stop_secs;
        stop.nsecs      = row->stop_nsecs;
        abs_start.secs  = (time_t)row->abs_secs;
        abs_start.nsecs = row->abs_nsecs;

        if (item->rows == 0 || nstime_cmp(&start, &item->start_time) < 0) {
            item->start_time     = start;
            item->start_abs_time = abs_start;
        }
        if (item->rows == 0 || nstime_cmp(&stop, &item->stop_time) > 0) {
            item->stop_time = stop;
        }
    }

    /* The row a single process would have created, and the direction it
     * would have created it in, is the earliest one. */
    order = ((uint64_t)row->frame << 32) | row->index;
    if (item->rows == 0 || order < item->order) {
        item->order    = order;
        item->reversed = reversed;
    }

    item->rows++;
}

/* Read back everything one worker spooled. */
static bool
conv_merge_read(int fd, GHashTable *folded, GHashTable *seen, GPtrArray *items)
{
    conv_merge_row_t row;
    FILE            *fp;
    bool             ok = true;

    if (ws_lseek64(fd, 0, SEEK_SET) == (off_t)-1) {
        return false;
    }
    fp = ws_fdopen(ws_dup(fd), "rb");
    if (fp == NULL) {
        return false;
    }

    while (fread(&row, sizeof(row), 1, fp) == 1) {
        uint8_t *data1 = NULL, *data2 = NULL;

        if (row.addr1_len > CONV_MERGE_MAX_ADDR ||
                row.addr2_len > CONV_MERGE_MAX_ADDR) {
            ok = false;
            break;
        }
        if (row.addr1_len != 0) {
            data1 = (uint8_t *)g_malloc(row.addr1_len);
            if (fread(data1, 1, row.addr1_len, fp) != row.addr1_len) {
                g_free(data1);
                ok = false;
                break;
            }
        }
        if (row.addr2_len != 0) {
            data2 = (uint8_t *)g_malloc(row.addr2_len);
            if (fread(data2, 1, row.addr2_len, fp) != row.addr2_len) {
                g_free(data1);
                g_free(data2);
                ok = false;
                break;
            }
        }

        if (conv_merge_tables == NULL || row.table >= conv_merge_tables->len ||
                g_array_index(conv_merge_tables, conv_merge_table_t,
                        row.table).is_endpoint != (row.is_endpoint != 0)) {
            /* The worker's tables are not the ones this process built,
             * so nothing can be said about these rows. */
            g_free(data1);
            g_free(data2);
            ok = false;
            break;
        }

        conv_merge_fold(folded, seen, items, &row, data1, data2);
        g_free(data1);
        g_free(data2);
    }

    fclose(fp);

    return ok;
}

/* Creation order, which is the order the draw functions print rows of
 * equal size in. */
static int
conv_merge_compare(const void *a, const void *b)
{
    const conv_merge_item_t *x = *(const conv_merge_item_t * const *)a;
    const conv_merge_item_t *y = *(const conv_merge_item_t * const *)b;

    if (x->table != y->table) {
        return x->table < y->table ? -1 : 1;
    }
    if (x->order != y->order) {
        return x->order < y->order ? -1 : 1;
    }

    return 0;
}

/* Put one folded row back into the table it came from, in the direction
 * the process that saw it first would have recorded. */
static void
conv_merge_fill(const conv_merge_item_t *item)
{
    conv_merge_table_t *t = &g_array_index(conv_merge_tables,
            conv_merge_table_t, item->table);

    if (t->hash->conv_array == NULL) {
        t->hash->conv_array = g_array_new(FALSE, FALSE, t->is_endpoint ?
                sizeof(endpoint_item_t) : sizeof(conv_item_t));
    }

    if (t->is_endpoint) {
        endpoint_item_t endpoint;

        memset(&endpoint, 0, sizeof(endpoint));
        /* The dissector info block is a per-dissector static, and only
         * the filter names the GUI builds come out of it; nothing the
         * command line prints does. */
        endpoint.dissector_info  = NULL;
        copy_address(&endpoint.myaddress, &item->addr1);
        endpoint.etype           = (endpoint_type)item->type;
        endpoint.port            = item->port1;
        endpoint.tx_frames       = item->tx_frames;
        endpoint.rx_frames       = item->rx_frames;
        endpoint.tx_bytes        = item->tx_bytes;
        endpoint.rx_bytes        = item->rx_bytes;
        endpoint.tx_frames_total = item->tx_frames_total;
        endpoint.rx_frames_total = item->rx_frames_total;
        endpoint.tx_bytes_total  = item->tx_bytes_total;
        endpoint.rx_bytes_total  = item->rx_bytes_total;
        endpoint.filtered        = item->filtered;
        endpoint.modified        = item->modified;
        g_array_append_val(t->hash->conv_array, endpoint);
    }
    else {
        const address *src = item->reversed ? &item->addr2 : &item->addr1;
        const address *dst = item->reversed ? &item->addr1 : &item->addr2;
        conv_item_t    conv;

        memset(&conv, 0, sizeof(conv));
        conv.dissector_info  = NULL;
        copy_address(&conv.src_address, src);
        copy_address(&conv.dst_address, dst);
        conv.ctype           = (conversation_type)item->type;
        conv.src_port        = item->reversed ? item->port2 : item->port1;
        conv.dst_port        = item->reversed ? item->port1 : item->port2;
        /* The conversation id is each worker's own numbering of its own
         * flows; the folded row is not any one worker's. */
        conv.conv_id         = CONV_ID_UNSET;
        conv.tx_frames       = item->reversed ? item->rx_frames : item->tx_frames;
        conv.rx_frames       = item->reversed ? item->tx_frames : item->rx_frames;
        conv.tx_bytes        = item->reversed ? item->rx_bytes : item->tx_bytes;
        conv.rx_bytes        = item->reversed ? item->tx_bytes : item->rx_bytes;
        conv.tx_frames_total = item->reversed ?
            item->rx_frames_total : item->tx_frames_total;
        conv.rx_frames_total = item->reversed ?
            item->tx_frames_total : item->rx_frames_total;
        conv.tx_bytes_total  = item->reversed ?
            item->rx_bytes_total : item->tx_bytes_total;
        conv.rx_bytes_total  = item->reversed ?
            item->tx_bytes_total : item->rx_bytes_total;
        conv.start_time      = item->start_time;
        conv.stop_time       = item->stop_time;
        conv.start_abs_time  = item->start_abs_time;
        conv.filtered        = item->filtered;
        conv.ext_tcp.flows   = item->flows;
        g_array_append_val(t->hash->conv_array, conv);
    }
}

static void
conv_merge_item_free(void *data)
{
    conv_merge_item_t *item = (conv_merge_item_t *)data;

    free_address(&item->addr1);
    free_address(&item->addr2);
    g_free(item);
}

bool
conv_merge_collect(const int *fds, unsigned count)
{
    GHashTable *folded;
    GPtrArray  *items;
    unsigned    i;
    bool        ok = true;

    folded = g_hash_table_new_full(g_bytes_hash, g_bytes_equal,
            (GDestroyNotify)g_bytes_unref, NULL);
    items  = g_ptr_array_new_with_free_func(conv_merge_item_free);

    for (i = 0; i < count && ok; i++) {
        GHashTable *seen = g_hash_table_new_full(g_bytes_hash, g_bytes_equal,
                (GDestroyNotify)g_bytes_unref, NULL);

        ok = conv_merge_read(fds[i], folded, seen, items);
        g_hash_table_destroy(seen);
    }

    if (ok) {
        g_ptr_array_sort(items, conv_merge_compare);
        for (i = 0; i < items->len; i++) {
            conv_merge_fill((const conv_merge_item_t *)
                    g_ptr_array_index(items, i));
        }
    }

    g_hash_table_destroy(folded);
    g_ptr_array_free(items, TRUE);

    return ok;
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
