/** @file
 * Definitions for the Wireshark Memory Manager Scopes
 * Copyright 2012, Evan Huus <eapache@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include <wsutil/wmem/wmem.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Fetch the current epan scope.
 *
 * Allocated memory is freed when wmem_leave_epan_scope() is called, which is normally at program exit.
 *
 * @return A pointer to the current epan scope allocator.
 */
WS_DLL_PUBLIC
wmem_allocator_t *
wmem_epan_scope(void);

/**
 * @brief Fetch the current file scope.
 *
 * Allocated memory is freed when wmem_leave_file_scope() is called, which is normally when a capture file is closed.
 *
 * @return A pointer to the current file scope allocator.
 */
WS_DLL_PUBLIC
wmem_allocator_t *
wmem_file_scope(void);

/**
 * @brief Enters a file scope for memory management.
 *
 * This function marks the beginning of a new scope in which memory allocations are tracked and managed.
 * It ensures that any memory allocated within this scope can be properly cleaned up when the scope is exited.
 */
WS_DLL_LOCAL
void
wmem_enter_file_scope(void);

/**
 * @brief Leave the file scope.
 *
 * This function is used to leave the current file scope and clean up any resources associated with it.
 */
WS_DLL_LOCAL
void
wmem_leave_file_scope(void);

/* Capture-state backing store */

/**
 * @brief Make capture-lifetime state live in a backing store.
 *
 * Called before wmem_init_scopes(), i.e. before epan_init(), the file
 * scope - which owns conversations, reassembly state, per-packet proto
 * data and everything else that has to survive until the capture file is
 * closed - is served out of the given store instead of out of the heap.
 *
 * It may also be called after a process has forked, as long as no capture
 * file has been opened yet, which replaces the file scope allocator so
 * that the new process allocates from its own store rather than from one
 * its siblings are also allocating from.
 *
 * The caller owns the store and must keep it alive until after
 * wmem_cleanup_scopes().
 *
 * @param backing The backing store, or NULL to use the heap.
 */
WS_DLL_PUBLIC
void
wmem_set_capture_backing(wmem_backing_t *backing);

/**
 * @brief Fetch the backing store set by wmem_set_capture_backing().
 *
 * @return The backing store, or NULL if capture state lives on the heap.
 */
WS_DLL_PUBLIC
wmem_backing_t *
wmem_capture_backing(void);

/* Scope Management */

/**
 * @brief Initializes the memory scopes.
 *
 * This function initializes the file scope and epan scope allocators.
 */
WS_DLL_PUBLIC
void
wmem_init_scopes(void);

/**
 * @brief Cleans up all memory scopes.
 *
 * This function destroys the allocators for file_scope and epan_scope, cleans up
 * any remaining memory allocations, and sets both scope pointers to NULL.
 */
WS_DLL_PUBLIC
void
wmem_cleanup_scopes(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

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
