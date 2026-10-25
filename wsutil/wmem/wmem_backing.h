/** @file
 * Definitions for the Wireshark Memory Manager disk backing store
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WMEM_BACKING_H__
#define __WMEM_BACKING_H__

#include <stddef.h>
#include <stdint.h>
#include <ws_symbol_export.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @addtogroup wmem
 *  @{
 *
 * A backing store is the source of the large memory regions that a block
 * allocator hands out chunks from. By default a block allocator takes those
 * regions from the system heap, which means every byte an allocator holds is
 * a byte of RAM.
 *
 * A file backing store instead carves the regions out of a single large
 * shared file mapping. The pages are only resident while they are in use;
 * under memory pressure the kernel writes them to the backing file instead of
 * failing the allocation. Analysis of a capture whose dissection state does
 * not fit in RAM therefore gets slower instead of dying.
 *
 * Addresses are stable for the lifetime of the backing store: the entire
 * range is reserved and mapped once, so no pointer rewriting is needed and
 * the allocator (and its consumers) are unaware of where the memory lives.
 */

struct _wmem_backing_t;
/** An opaque type representing one backing store. */
typedef struct _wmem_backing_t wmem_backing_t;
/**
 * @brief Create a file-backed memory store.
 *
 * Reserves (sparsely) and maps a region of the given size out of a temporary
 * file. The file is unlinked immediately, so it occupies no name in the
 * filesystem and is reclaimed even if the process dies abnormally.
 *
 * Regions are served from the heap until @p threshold bytes are outstanding
 * and from the file after that, so analysis whose state fits in RAM costs
 * nothing and only the excess pays for the disk. A threshold of 0 sends
 * everything to the file.
 *
 * @param dir Directory to create the temporary file in, or NULL for the
 *            system temporary directory.
 * @param reserve Size of the address range to reserve, in bytes. This is an
 *            upper bound on the amount of memory the store can hand out, not
 *            an amount of memory or disk that is consumed up front.
 * @param threshold Bytes to keep in RAM before spilling.
 * @param err If creation fails, set to a newly allocated error string that
 *            the caller must g_free().
 * @return The new backing store, or NULL on failure.
 */
WS_DLL_PUBLIC
wmem_backing_t *
wmem_backing_file_new(const char *dir, uint64_t reserve, uint64_t threshold,
        char **err);


/**
 * @brief Destroy a backing store, unmapping all memory it handed out.
 *
 * Every allocator using this store must have been destroyed first.
 *
 * @param backing The backing store to destroy.
 */
WS_DLL_PUBLIC
void
wmem_backing_destroy(wmem_backing_t *backing);

/**
 * @brief Allocate a region from the backing store.
 *
 * The returned region is page-aligned and its size is rounded up to a whole
 * number of pages. Aborts the program if the store is exhausted, matching the
 * wmem contract that allocation either succeeds or aborts.
 *
 * @param backing The backing store.
 * @param size The requested size in bytes.
 * @return A pointer to the new region.
 */
WS_DLL_PUBLIC
void *
wmem_backing_alloc(wmem_backing_t *backing, size_t size);

/**
 * @brief Resize a region previously returned by wmem_backing_alloc().
 *
 * @param backing The backing store.
 * @param ptr The region to resize, or NULL to allocate a new one.
 * @param size The new size in bytes.
 * @return The new location of the region, which may differ from ptr.
 */
WS_DLL_PUBLIC
void *
wmem_backing_realloc(wmem_backing_t *backing, void *ptr, size_t size);

/**
 * @brief Return a region to the backing store.
 *
 * The region is made available for reuse and its pages are released back to
 * the operating system (and punched out of the backing file where the
 * platform supports it).
 *
 * @param backing The backing store.
 * @param ptr The region to free, or NULL.
 */
WS_DLL_PUBLIC
void
wmem_backing_free(wmem_backing_t *backing, void *ptr);

/** @brief Bytes currently handed out by the store. */
WS_DLL_PUBLIC
uint64_t
wmem_backing_bytes_live(const wmem_backing_t *backing);

/** @brief Largest number of bytes ever simultaneously handed out. */
WS_DLL_PUBLIC
uint64_t
wmem_backing_bytes_high_water(const wmem_backing_t *backing);

/** @brief Size of the reserved address range, in bytes. */
WS_DLL_PUBLIC
uint64_t
wmem_backing_bytes_reserved(const wmem_backing_t *backing);

/** @brief Largest number of bytes ever held in RAM below the watermark. */
WS_DLL_PUBLIC
uint64_t
wmem_backing_bytes_in_ram(const wmem_backing_t *backing);

/** @brief The watermark the store was created with, in bytes. */
WS_DLL_PUBLIC
uint64_t
wmem_backing_threshold(const wmem_backing_t *backing);

/** @brief Path the backing file was created at (it is already unlinked). */
WS_DLL_PUBLIC
const char *
wmem_backing_path(const wmem_backing_t *backing);

/** @} */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WMEM_BACKING_H__ */

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
