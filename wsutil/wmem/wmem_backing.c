/* wmem_backing.c
 * Wireshark Memory Manager disk backing store
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifdef __linux__
/* for fallocate(), used to punch holes in the backing file */
#define _GNU_SOURCE
#endif

#include "config.h"

#include <string.h>

#include <glib.h>
#include <glib/gstdio.h>

#include "wmem_backing.h"
#include <wsutil/file_util.h>
#include <wsutil/ws_assert.h>

#ifndef _WIN32
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#ifdef __linux__
/* FALLOC_FL_PUNCH_HOLE lives here, not in <fcntl.h>. */
#include <linux/falloc.h>
#endif
#endif

struct _wmem_backing_t {
    int         fd;
    char       *path;
    uint8_t    *base;      /* start of the mapped range */
    uint64_t    reserve;   /* size of the mapped range */
    uint64_t    live;      /* bytes currently handed out from the file */
    uint64_t    high_water;
    size_t      pagesize;

    /* Regions are served from the heap until this much is outstanding, and
     * from the file after that. Analysis that fits in memory therefore costs
     * nothing, and only the excess pays for the disk. */
    uint64_t    threshold;
    uint64_t    heap_live;
    uint64_t    heap_high_water;

    /* region pointer -> region size. Frees come in without a size, and we
     * want regions to stay page-aligned, so the sizes live beside the data
     * rather than in a header. One entry per multi-megabyte region makes
     * this metadata negligible. The heap map doubles as the record of which
     * source a region came from. */
    GHashTable *sizes;
    GHashTable *heap_sizes;

    /* Free regions: start -> size, and end -> start. A region being freed
     * is merged with the free regions on either side of it, and an
     * allocation is served from the smallest free region that holds it,
     * splitting off the remainder. Without merging and splitting, a size
     * that never recurs - every jumbo allocation is its own size - would
     * pin the space it was carved from for the life of the store, and a
     * long-lived process would exhaust the range with most of it free. */
    GHashTable *free_starts;
    GHashTable *free_ends;
};

static inline uint64_t
wmem_backing_round_up(uint64_t value, uint64_t multiple)
{
    return ((value + multiple - 1) / multiple) * multiple;
}

/* Record a region as free, or stop recording it. */
static void
wmem_backing_free_add(wmem_backing_t *backing, uint8_t *ptr, size_t size)
{
    g_hash_table_insert(backing->free_starts, ptr, GSIZE_TO_POINTER(size));
    g_hash_table_insert(backing->free_ends, ptr + size, ptr);
}

static void
wmem_backing_free_take(wmem_backing_t *backing, uint8_t *ptr, size_t size)
{
    g_hash_table_remove(backing->free_starts, ptr);
    g_hash_table_remove(backing->free_ends, ptr + size);
}

/* Hand the pages of a region back to the OS, and the disk blocks back to the
 * filesystem where we can. The region stays mapped and stays ours; it just
 * stops costing anything until it is handed out again. */
static void
wmem_backing_release(wmem_backing_t *backing, void *ptr, size_t size)
{
#ifndef _WIN32
    off_t offset = (off_t)((uint8_t *)ptr - backing->base);

#if defined(__APPLE__) && defined(F_PUNCHHOLE)
    {
        fpunchhole_t args;

        memset(&args, 0, sizeof(args));
        args.fp_offset = offset;
        args.fp_length = (off_t)size;
        /* Best effort; a filesystem that cannot punch holes just keeps the
         * blocks allocated. */
        fcntl(backing->fd, F_PUNCHHOLE, &args);
    }
#elif defined(FALLOC_FL_PUNCH_HOLE)
    fallocate(backing->fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
            offset, (off_t)size);
#else
    (void)offset;
#endif

    /* Discard the pages without writing them back; the contents of a freed
     * region are not ours to preserve. */
#ifdef MADV_DONTNEED
    madvise(ptr, size, MADV_DONTNEED);
#elif defined(MADV_FREE)
    madvise(ptr, size, MADV_FREE);
#endif
#else /* _WIN32 */
    (void)backing; (void)ptr; (void)size;
#endif
}

wmem_backing_t *
wmem_backing_file_new(const char *dir, uint64_t reserve, uint64_t threshold,
        char **err)
{
#ifdef _WIN32
    (void)dir; (void)reserve; (void)threshold;
    *err = g_strdup("disk-backed memory is not supported on this platform");
    return NULL;
#else
    wmem_backing_t *backing;
    char           *path;
    int             fd;
    void           *base;
    size_t          pagesize;

    pagesize = (size_t)getpagesize();
    reserve  = wmem_backing_round_up(reserve, pagesize);

    path = g_build_filename(dir != NULL ? dir : g_get_tmp_dir(),
            "wireshark_wmem_XXXXXX", NULL);

    fd = g_mkstemp(path);
    if (fd < 0) {
        *err = g_strdup_printf("can't create %s: %s", path, g_strerror(errno));
        g_free(path);
        return NULL;
    }

    /* Sparse: this sets the size of the file, it does not allocate any disk
     * blocks. Blocks are allocated as pages are written back. */
    if (ftruncate(fd, (off_t)reserve) != 0) {
        *err = g_strdup_printf("can't size %s to %" PRIu64 " bytes: %s",
                path, reserve, g_strerror(errno));
        ws_close(fd);
        g_unlink(path);
        g_free(path);
        return NULL;
    }

    /* Map the whole range once. Addresses handed out of it are stable for
     * the lifetime of the store, so nothing above us has to care that the
     * memory is file-backed. */
    base = mmap(NULL, (size_t)reserve, PROT_READ | PROT_WRITE, MAP_SHARED,
            fd, 0);
    if (base == MAP_FAILED) {
        *err = g_strdup_printf("can't map %" PRIu64 " bytes of %s: %s",
                reserve, path, g_strerror(errno));
        ws_close(fd);
        g_unlink(path);
        g_free(path);
        return NULL;
    }

#ifdef MADV_RANDOM
    /* Dissection state is reached through hash tables and trees, so a fault
     * says nothing about which page is wanted next. Reading ahead around it
     * would just multiply the I/O. */
    madvise(base, (size_t)reserve, MADV_RANDOM);
#endif

    /* The mapping keeps the file alive; unlinking now means no leftovers if
     * we die, and no way for anything else to read the capture state. */
    g_unlink(path);

    backing             = g_new0(wmem_backing_t, 1);
    backing->fd         = fd;
    backing->path       = path;
    backing->base       = (uint8_t *)base;
    backing->reserve    = reserve;
    backing->threshold  = threshold;
    backing->pagesize   = pagesize;
    backing->sizes      = g_hash_table_new(g_direct_hash, g_direct_equal);
    backing->heap_sizes = g_hash_table_new(g_direct_hash, g_direct_equal);
    backing->free_starts = g_hash_table_new(g_direct_hash, g_direct_equal);
    backing->free_ends  = g_hash_table_new(g_direct_hash, g_direct_equal);

    /* The whole range starts out free; allocation is carving it up. */
    wmem_backing_free_add(backing, backing->base, (size_t)reserve);

    return backing;
#endif /* _WIN32 */
}

void
wmem_backing_destroy(wmem_backing_t *backing)
{
    if (backing == NULL) {
        return;
    }

#ifndef _WIN32
    munmap(backing->base, (size_t)backing->reserve);
    ws_close(backing->fd);
#endif

    g_hash_table_destroy(backing->sizes);
    g_hash_table_destroy(backing->heap_sizes);
    g_hash_table_destroy(backing->free_starts);
    g_hash_table_destroy(backing->free_ends);
    g_free(backing->path);
    g_free(backing);
}

/* Hand out a region from the file. */
static void *
wmem_backing_alloc_mapped(wmem_backing_t *backing, size_t want)
{
    GHashTableIter iter;
    void          *key, *value;
    uint8_t       *best = NULL;
    size_t         best_size = 0;
    uint8_t       *ptr;

    /* Best fit, so that a long run of free space is left for the request
     * that needs all of it. The number of free regions stays small because
     * neighbours are merged as they are freed. */
    g_hash_table_iter_init(&iter, backing->free_starts);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        size_t size = GPOINTER_TO_SIZE(value);

        if (size < want) {
            continue;
        }
        if (best == NULL || size < best_size) {
            best      = (uint8_t *)key;
            best_size = size;
        }
        if (size == want) {
            break;
        }
    }

    if (best == NULL) {
        ws_error("wmem: disk-backed memory exhausted after %" PRIu64
                " MB; raise the reserved size to analyze this capture",
                backing->reserve / (1024 * 1024));
    }

    wmem_backing_free_take(backing, best, best_size);
    if (best_size > want) {
        /* The tail is page-aligned, so it is a region in its own right. */
        wmem_backing_free_add(backing, best + want, best_size - want);
    }
    ptr = best;

    g_hash_table_insert(backing->sizes, ptr, GSIZE_TO_POINTER(want));

    backing->live += want;
    if (backing->live > backing->high_water) {
        backing->high_water = backing->live;
    }

    return ptr;
}

void *
wmem_backing_alloc(wmem_backing_t *backing, size_t size)
{
    size_t want;
    void  *ptr;

    want = (size_t)wmem_backing_round_up(size, backing->pagesize);

    /* Below the watermark the memory is ordinary heap memory, so a capture
     * whose state fits in RAM runs exactly as it would without a store. */
    if (backing->heap_live + want <= backing->threshold) {
        ptr = g_malloc(want);
        g_hash_table_insert(backing->heap_sizes, ptr, GSIZE_TO_POINTER(want));
        backing->heap_live += want;
        if (backing->heap_live > backing->heap_high_water) {
            backing->heap_high_water = backing->heap_live;
        }
        return ptr;
    }

    return wmem_backing_alloc_mapped(backing, want);
}

void
wmem_backing_free(wmem_backing_t *backing, void *ptr)
{
    uint8_t *start, *next, *prev;
    size_t   size, neighbour;
    void    *value;

    if (ptr == NULL) {
        return;
    }

    size = GPOINTER_TO_SIZE(g_hash_table_lookup(backing->heap_sizes, ptr));
    if (size != 0) {
        g_hash_table_remove(backing->heap_sizes, ptr);
        backing->heap_live -= size;
        g_free(ptr);
        return;
    }

    size = GPOINTER_TO_SIZE(g_hash_table_lookup(backing->sizes, ptr));
    ws_assert(size != 0);
    g_hash_table_remove(backing->sizes, ptr);

    backing->live -= size;

    wmem_backing_release(backing, ptr, size);

    /* Merge with the free region that ends where this one starts, and with
     * the one that starts where it ends, so that the space goes back as one
     * extent rather than as a size that may never be asked for again. */
    start = (uint8_t *)ptr;

    prev = (uint8_t *)g_hash_table_lookup(backing->free_ends, start);
    if (prev != NULL) {
        neighbour = GPOINTER_TO_SIZE(g_hash_table_lookup(backing->free_starts,
                    prev));
        wmem_backing_free_take(backing, prev, neighbour);
        start = prev;
        size += neighbour;
    }

    next = start + size;
    if (g_hash_table_lookup_extended(backing->free_starts, next, NULL,
                &value)) {
        neighbour = GPOINTER_TO_SIZE(value);
        wmem_backing_free_take(backing, next, neighbour);
        size += neighbour;
    }

    wmem_backing_free_add(backing, start, size);
}

void *
wmem_backing_realloc(wmem_backing_t *backing, void *ptr, size_t size)
{
    size_t old, want;
    void  *new_ptr;

    if (ptr == NULL) {
        return wmem_backing_alloc(backing, size);
    }

    want = (size_t)wmem_backing_round_up(size, backing->pagesize);

    old = GPOINTER_TO_SIZE(g_hash_table_lookup(backing->heap_sizes, ptr));
    if (old != 0) {
        /* Still in RAM. Keep it there if it fits under the watermark,
         * otherwise this is where it moves to the file. */
        if (backing->heap_live - old + want <= backing->threshold) {
            new_ptr = g_realloc(ptr, want);
            g_hash_table_remove(backing->heap_sizes, ptr);
            g_hash_table_insert(backing->heap_sizes, new_ptr,
                    GSIZE_TO_POINTER(want));
            backing->heap_live += want - old;
            if (backing->heap_live > backing->heap_high_water) {
                backing->heap_high_water = backing->heap_live;
            }
            return new_ptr;
        }

        new_ptr = wmem_backing_alloc_mapped(backing, want);
        memcpy(new_ptr, ptr, old < want ? old : want);
        wmem_backing_free(backing, ptr);
        return new_ptr;
    }

    old = GPOINTER_TO_SIZE(g_hash_table_lookup(backing->sizes, ptr));
    ws_assert(old != 0);

    if (want == old) {
        return ptr;
    }

    if (want < old) {
        /* Shrinking: keep the head where it is and return the tail, which is
         * page-aligned and therefore a valid region in its own right. */
        void *tail = (uint8_t *)ptr + want;

        g_hash_table_insert(backing->sizes, ptr, GSIZE_TO_POINTER(want));
        g_hash_table_insert(backing->sizes, tail, GSIZE_TO_POINTER(old - want));
        wmem_backing_free(backing, tail);
        return ptr;
    }

    new_ptr = wmem_backing_alloc_mapped(backing, want);
    memcpy(new_ptr, ptr, old);
    wmem_backing_free(backing, ptr);

    return new_ptr;
}

uint64_t
wmem_backing_bytes_live(const wmem_backing_t *backing)
{
    return backing->live;
}

uint64_t
wmem_backing_bytes_high_water(const wmem_backing_t *backing)
{
    return backing->high_water;
}

uint64_t
wmem_backing_bytes_reserved(const wmem_backing_t *backing)
{
    return backing->reserve;
}

uint64_t
wmem_backing_bytes_in_ram(const wmem_backing_t *backing)
{
    return backing->heap_high_water;
}

uint64_t
wmem_backing_threshold(const wmem_backing_t *backing)
{
    return backing->threshold;
}

const char *
wmem_backing_path(const wmem_backing_t *backing)
{
    return backing->path;
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
