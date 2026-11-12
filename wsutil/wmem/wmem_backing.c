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

#ifdef _WIN32
#include <windows.h>
#include <winioctl.h>
#include <wsutil/unicode-utils.h>
#include <wsutil/win32-utils.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/statvfs.h>
#ifdef __linux__
/* FALLOC_FL_PUNCH_HOLE lives here, not in <fcntl.h>. */
#include <linux/falloc.h>
#endif
#endif

/*
 * The lock covers the bookkeeping, which on POSIX is shared with every
 * process forked since the store was created, so it is a process-shared
 * mutex living in that shared mapping. Windows has no fork(), so the
 * store there is one process's own and an SRW lock is enough: it still
 * has to be taken, because TShark's two passes and the GUI's dissection
 * can both reach the store from more than one thread.
 */
#ifdef _WIN32
typedef SRWLOCK wmem_backing_lock_t;
#define wmem_backing_lock(l)   AcquireSRWLockExclusive(l)
#define wmem_backing_unlock(l) ReleaseSRWLockExclusive(l)
#else
typedef pthread_mutex_t wmem_backing_lock_t;
#define wmem_backing_lock(l)   pthread_mutex_lock(l)
#define wmem_backing_unlock(l) pthread_mutex_unlock(l)
#endif

/*
 * Everything the store knows about which bytes are handed out lives in
 * file offsets rather than addresses, behind a lock. On POSIX the
 * bookkeeping is a shared anonymous mapping, so a process that forks
 * after the store is created allocates from the same store as its
 * parent and its siblings, with one watermark and one set of figures
 * for all of them; on Windows, which has no fork(), it is ordinary
 * memory belonging to the one process that created it.
 *
 * Offsets rather than addresses because nothing dereferences another
 * process's memory: workers keep their own dissection state, so all that
 * has to be agreed is who owns which bytes. Each process maps the file
 * where its own kernel likes.
 */

#define WMEM_BACKING_MAX_SEGMENTS 256
#define WMEM_BACKING_MAX_REGIONS  (64 * 1024)

/* One mapped piece of the backing file. The store starts with a single
 * piece and maps another when it runs out, so the reserved size is where
 * the store starts rather than how far it can go. */
typedef struct {
    uint64_t    offset;    /* where it lives in the backing file */
    uint64_t    size;
} wmem_backing_segment_t;

/* A run of the file, either handed out or free. Regions are kept in
 * offset order, so a region being freed can be merged with its
 * neighbours and an allocation can be served from the smallest free one
 * that holds it. Without merging and splitting, a size that never
 * recurs - every jumbo allocation is its own size - would pin the space
 * it was carved from for the life of the store. */
typedef struct {
    uint64_t    offset;
    uint64_t    size;
    uint32_t    used;
    uint32_t    segment;
} wmem_backing_region_t;

typedef struct {
    wmem_backing_lock_t lock;

    uint64_t    reserve;   /* total size of the file that is mapped */
    uint64_t    grow;      /* size to add when it is all handed out */
    uint64_t    live;      /* bytes currently handed out from the file */
    uint64_t    high_water;

    /* Regions are served from the heap until this much is outstanding,
     * and from the file after that, so analysis that fits in memory
     * costs nothing and only the excess pays for the disk. The memory
     * itself is each process's own; only the budget is shared. */
    uint64_t    threshold;
    uint64_t    heap_live;
    uint64_t    heap_high_water;

    unsigned    segment_count;
    unsigned    region_count;

    wmem_backing_segment_t segments[WMEM_BACKING_MAX_SEGMENTS];
    wmem_backing_region_t  regions[WMEM_BACKING_MAX_REGIONS];
} wmem_backing_shared_t;

struct _wmem_backing_t {
#ifdef _WIN32
    HANDLE      file;
    /* One file mapping object per segment: a mapping object is sized
     * when it is created, so growing the store means another one. */
    HANDLE      maps[WMEM_BACKING_MAX_SEGMENTS];
#else
    int         fd;
#endif
    char       *path;
    char       *dir;     /* the directory it was created in */
    size_t      pagesize;

    wmem_backing_shared_t *shared;

    /* Where this process has put each segment, which is nobody else's
     * business. A process maps a segment the first time it needs one. */
    uint8_t    *bases[WMEM_BACKING_MAX_SEGMENTS];
    unsigned    mapped;

    /* Heap regions are this process's own, so their sizes are too. The
     * map doubles as the record of which source a region came from. */
    GHashTable *heap_sizes;
};

static inline uint64_t
wmem_backing_round_up(uint64_t value, uint64_t multiple)
{
    return ((value + multiple - 1) / multiple) * multiple;
}

/* Make sure this process has the segment mapped, and say where. */
static uint8_t *
wmem_backing_base(wmem_backing_t *backing, unsigned segment)
{
#ifdef _WIN32
    uint64_t  offset, size;
    void     *base;

    if (segment < backing->mapped && backing->bases[segment] != NULL) {
        return backing->bases[segment];
    }

    ws_assert(segment < backing->shared->segment_count);

    offset = backing->shared->segments[segment].offset;
    size   = backing->shared->segments[segment].size;

    /* A mapping object is sized when it is created, so each segment
     * gets one of its own rather than the whole file getting a new one
     * every time the store grows. */
    if (backing->maps[segment] == NULL) {
        backing->maps[segment] = CreateFileMappingW(backing->file, NULL,
                PAGE_READWRITE, (DWORD)((offset + size) >> 32),
                (DWORD)(offset + size), NULL);
        if (backing->maps[segment] == NULL) {
            ws_error("wmem: can't create a %" PRIu64 " byte mapping of the "
                    "backing file: %s", size,
                    win32strerror(GetLastError()));
        }
    }

    base = MapViewOfFile(backing->maps[segment], FILE_MAP_ALL_ACCESS,
            (DWORD)(offset >> 32), (DWORD)offset, (SIZE_T)size);
    if (base == NULL) {
        ws_error("wmem: can't map %" PRIu64 " bytes of the backing file: %s",
                size, win32strerror(GetLastError()));
    }

    backing->bases[segment] = (uint8_t *)base;
    if (segment >= backing->mapped) {
        backing->mapped = segment + 1;
    }

    return backing->bases[segment];
#else
    void *base;

    if (segment < backing->mapped && backing->bases[segment] != NULL) {
        return backing->bases[segment];
    }

    ws_assert(segment < backing->shared->segment_count);

    base = mmap(NULL, (size_t)backing->shared->segments[segment].size,
            PROT_READ | PROT_WRITE, MAP_SHARED, backing->fd,
            (off_t)backing->shared->segments[segment].offset);
    if (base == MAP_FAILED) {
        ws_error("wmem: can't map %" PRIu64 " bytes of the backing file: %s",
                backing->shared->segments[segment].size, g_strerror(errno));
    }

#if defined(MADV_RANDOM) && defined(__APPLE__)
    /* Dissection state is reached through hash tables and trees, so a
     * fault says nothing about which page is wanted next, and on Darwin
     * reading ahead around it just multiplies the I/O: 1 M packets over
     * 500 k flows at --spill-after 0 takes 41.2 s with this and 51.9 s
     * without it.
     *
     * Linux is the other way round, by more. The same capture under a
     * 1 GB cgroup limit takes 8.9 s when the kernel is left to read
     * ahead and 22.0 s with MADV_RANDOM, because a fault that brings in
     * one page at a time faults 896 k times rather than 613. The advice
     * is therefore Darwin's alone, not an opinion about the access
     * pattern.
     */
    madvise(base, (size_t)backing->shared->segments[segment].size,
            MADV_RANDOM);
#endif

    backing->bases[segment] = (uint8_t *)base;
    if (segment >= backing->mapped) {
        backing->mapped = segment + 1;
    }

    return backing->bases[segment];
#endif /* _WIN32 */
}

static void *
wmem_backing_address(wmem_backing_t *backing, const wmem_backing_region_t *r)
{
    return wmem_backing_base(backing, r->segment) +
        (r->offset - backing->shared->segments[r->segment].offset);
}

/* Which region a pointer came from. There is one region per
 * multi-megabyte allocation, so this list stays short. */
static unsigned
wmem_backing_region_of(wmem_backing_t *backing, const void *ptr)
{
    unsigned i;

    for (i = 0; i < backing->shared->region_count; i++) {
        wmem_backing_region_t *r = &backing->shared->regions[i];

        if (!r->used || r->segment >= backing->mapped ||
                backing->bases[r->segment] == NULL) {
            continue;
        }
        if (ptr == wmem_backing_address(backing, r)) {
            return i;
        }
    }

    ws_assert_not_reached();
}

static void
wmem_backing_region_insert(wmem_backing_shared_t *shared, unsigned at,
        uint64_t offset, uint64_t size, unsigned segment, uint32_t used)
{
    if (shared->region_count == WMEM_BACKING_MAX_REGIONS) {
        ws_error("wmem: the backing store is in too many pieces");
    }

    memmove(&shared->regions[at + 1], &shared->regions[at],
            (shared->region_count - at) * sizeof(shared->regions[0]));
    shared->regions[at].offset  = offset;
    shared->regions[at].size    = size;
    shared->regions[at].segment = segment;
    shared->regions[at].used    = used;
    shared->region_count++;
}

static void
wmem_backing_region_remove(wmem_backing_shared_t *shared, unsigned at)
{
    shared->region_count--;
    memmove(&shared->regions[at], &shared->regions[at + 1],
            (shared->region_count - at) * sizeof(shared->regions[0]));
}

/* Make the backing file this long. The file is sparse, so this does not
 * allocate disk blocks; those are claimed per region by
 * wmem_backing_reserve() as regions are handed out. */
static bool
wmem_backing_set_size(wmem_backing_t *backing, uint64_t size, char **err)
{
#ifdef _WIN32
    /* Nothing to do: a mapping object created for a range past the end
     * of the file extends the file to reach it, and the store maps a
     * segment before it hands any of it out. Setting the size here
     * instead would mean resizing a file that already has views of it,
     * which Windows is entitled to refuse. */
    (void)backing; (void)size; (void)err;
#else
    if (ftruncate(backing->fd, (off_t)size) != 0) {
        *err = g_strdup_printf("can't size %s to %" PRIu64 " bytes: %s",
                backing->path, size, g_strerror(errno));
        return false;
    }
#endif

    return true;
}

/* Add another piece of the backing file. Returns false with *err set if
 * the OS will not give us the space. */
static bool
wmem_backing_map_segment(wmem_backing_t *backing, uint64_t size, char **err)
{
    wmem_backing_shared_t *shared = backing->shared;
    uint64_t               offset = shared->reserve;

    if (shared->segment_count == WMEM_BACKING_MAX_SEGMENTS) {
        *err = g_strdup("the backing store is in too many pieces");
        return false;
    }

    if (!wmem_backing_set_size(backing, offset + size, err)) {
        return false;
    }

    shared->segments[shared->segment_count].offset = offset;
    shared->segments[shared->segment_count].size   = size;
    shared->segment_count++;
    shared->reserve += size;

    /* A new piece of the file is one free region. */
    wmem_backing_region_insert(shared, shared->region_count, offset, size,
            shared->segment_count - 1, 0);

    return true;
}

/* Hand the pages of a region back to the OS, and the disk blocks back to
 * the filesystem where we can. The region stays mapped and stays ours; it
 * just stops costing anything until it is handed out again. */
static void
wmem_backing_release(wmem_backing_t *backing, void *ptr, uint64_t offset,
        size_t size)
{
#ifndef _WIN32
#if defined(__APPLE__) && defined(F_PUNCHHOLE)
    {
        fpunchhole_t args;

        memset(&args, 0, sizeof(args));
        args.fp_offset = (off_t)offset;
        args.fp_length = (off_t)size;
        /* Best effort; a filesystem that cannot punch holes just keeps
         * the blocks allocated. */
        fcntl(backing->fd, F_PUNCHHOLE, &args);
    }
#elif defined(FALLOC_FL_PUNCH_HOLE)
    fallocate(backing->fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
            (off_t)offset, (off_t)size);
#else
    (void)offset;
#endif

    /* Drop this process's pages. The punch above is what discards the
     * contents and frees the blocks - MADV_DONTNEED on a shared file
     * mapping only takes the pages away from us, leaving the data in the
     * page cache to be written back - so where the punch worked this
     * costs 3 to 7 us per 8 MB and changes nothing, and where it did not
     * it is the only thing keeping the resident set down. MADV_FREE is
     * not an alternative: it is for anonymous memory and returns EINVAL
     * on a shared file mapping.
     */
#ifdef MADV_DONTNEED
    madvise(ptr, size, MADV_DONTNEED);
#else
    (void)ptr;
#endif
#else /* _WIN32 */
    FILE_ZERO_DATA_INFORMATION zero;
    DWORD                      ret;

    /* The equivalent of punching a hole in a sparse file. Best effort:
     * a volume that will not do it keeps the blocks allocated, and the
     * region is reused either way. There is no counterpart to
     * MADV_DONTNEED for a mapped view, so the pages go when the cache
     * manager decides they do. */
    zero.FileOffset.QuadPart      = (LONGLONG)offset;
    zero.BeyondFinalZero.QuadPart = (LONGLONG)(offset + size);
    DeviceIoControl(backing->file, FSCTL_SET_ZERO_DATA, &zero,
            sizeof(zero), NULL, 0, &ret, NULL);

    (void)ptr;
#endif
}

/* Make sure the file really holds the blocks for a region before
 * anything writes to it.
 *
 * The mapping is sparse, so a filesystem that fills up does not fail an
 * allocation: the first write to a page that has no block behind it
 * faults, and the process dies of SIGBUS, unrecoverably and without a
 * word about why, after however long the capture has been running.
 * Allocating the blocks up front turns that into an error at the point
 * the space ran out.
 *
 * Returns false with *err set if the space is not there.
 */
static bool
wmem_backing_reserve(wmem_backing_t *backing, uint64_t offset, uint64_t size,
        char **err)
{
#ifdef _WIN32
    ULARGE_INTEGER avail;

    (void)offset;

    /* Windows has no way to allocate the blocks behind part of a sparse
     * file - SetFileValidData() needs a privilege and does not apply to
     * sparse ranges - so all that can be done is to look at what the
     * volume says is left. A write that runs out anyway raises
     * EXCEPTION_IN_PAGE_ERROR, which is as fatal as SIGBUS. */
    if (GetDiskFreeSpaceExW(utf_8to16(backing->dir), &avail, NULL, NULL) &&
            avail.QuadPart < size) {
        *err = g_strdup("No space left on device");
        return false;
    }

    return true;
#else
    struct statvfs st;

#ifdef __linux__
    if (fallocate(backing->fd, 0, (off_t)offset, (off_t)size) == 0) {
        return true;
    }
    if (errno != EOPNOTSUPP && errno != ENOSYS) {
        *err = g_strdup(g_strerror(errno));
        return false;
    }
    /* The filesystem cannot preallocate, so all that is left is to look
     * at how much room it says it has. */
#else
    (void)offset;
#endif

    /* Racy by nature - another writer can take the space between this
     * and the fault - but it catches the case that actually happens,
     * which is a spill directory that has run out. */
    if (fstatvfs(backing->fd, &st) == 0 &&
            (uint64_t)st.f_bavail * (uint64_t)st.f_frsize < size) {
        *err = g_strdup(g_strerror(ENOSPC));
        return false;
    }

    return true;
#endif /* _WIN32 */
}

wmem_backing_t *
wmem_backing_file_new(const char *dir, uint64_t reserve, uint64_t threshold,
        char **err)
{
#ifdef _WIN32
    wmem_backing_t *backing;
    char           *path;
    HANDLE          file;
    SYSTEM_INFO     info;
    size_t          pagesize;
    DWORD           ret;
    unsigned        attempt;

    /* A view has to start on an allocation granularity boundary, which
     * is coarser than a page, so that is what the store rounds to. */
    GetSystemInfo(&info);
    pagesize = (size_t)info.dwAllocationGranularity;
    reserve  = wmem_backing_round_up(reserve, pagesize);

    if (dir == NULL) {
        dir = g_get_tmp_dir();
    }

    /* There is no O_TMPFILE here and no unlinking a file that is open,
     * so the file keeps its name for as long as the store exists.
     * FILE_FLAG_DELETE_ON_CLOSE is what takes it away again, including
     * when the process dies, and FILE_SHARE_DELETE lets that happen
     * while the mapping still holds it. */
    file = INVALID_HANDLE_VALUE;
    path = NULL;
    for (attempt = 0; attempt < 128; attempt++) {
        path = g_strdup_printf("%s\\wireshark_wmem_%lu_%u", dir,
                (unsigned long)GetCurrentProcessId(), attempt);

        file = CreateFileW(utf_8to16(path), GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                NULL, CREATE_NEW,
                FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
        if (file != INVALID_HANDLE_VALUE) {
            break;
        }

        g_free(path);
        path = NULL;
        if (GetLastError() != ERROR_FILE_EXISTS) {
            break;
        }
    }
    if (file == INVALID_HANDLE_VALUE) {
        *err = g_strdup_printf("can't create a temporary file in %s: %s",
                dir, win32strerror(GetLastError()));
        return NULL;
    }

    /* The store sizes the file to its whole address range, so a volume
     * that will not hold a sparse file cannot hold the store: say so
     * rather than asking it for 64 GB of real blocks. */
    if (!DeviceIoControl(file, FSCTL_SET_SPARSE, NULL, 0, NULL, 0,
                &ret, NULL)) {
        *err = g_strdup_printf("%s can't hold a sparse file: %s", dir,
                win32strerror(GetLastError()));
        CloseHandle(file);
        g_free(path);
        return NULL;
    }

    backing             = g_new0(wmem_backing_t, 1);
    backing->file       = file;
    backing->path       = path;
    backing->dir        = g_strdup(dir);
    backing->pagesize   = pagesize;
    backing->shared     = g_new0(wmem_backing_shared_t, 1);
    backing->heap_sizes = g_hash_table_new(g_direct_hash, g_direct_equal);

    InitializeSRWLock(&backing->shared->lock);

    backing->shared->grow      = reserve;
    backing->shared->threshold = threshold;

    if (!wmem_backing_map_segment(backing, reserve, err)) {
        wmem_backing_destroy(backing);
        return NULL;
    }

    return backing;
#else
    wmem_backing_t      *backing;
    char                *path;
    int                  fd;
    size_t               pagesize;
    void                *shared;
    pthread_mutexattr_t  attr;

    pagesize = (size_t)getpagesize();
    reserve  = wmem_backing_round_up(reserve, pagesize);

    if (dir == NULL) {
        dir = g_get_tmp_dir();
    }

    path = NULL;
    fd   = -1;

#ifdef O_TMPFILE
    /* A file that never had a name cannot be opened by anything else,
     * and cannot be left behind by a process that dies between creating
     * it and unlinking it. Filesystems that do not implement it (NFS,
     * overlayfs and others) fail the open, which is what the named file
     * below is for. */
    fd = open(dir, O_TMPFILE | O_RDWR | O_EXCL, 0600);
    if (fd >= 0) {
        path = g_strdup_printf("%s (unnamed temporary file)", dir);
    }
#endif

    if (fd < 0) {
        path = g_build_filename(dir, "wireshark_wmem_XXXXXX", NULL);

        fd = g_mkstemp(path);
        if (fd < 0) {
            *err = g_strdup_printf("can't create %s: %s", path,
                    g_strerror(errno));
            g_free(path);
            return NULL;
        }

        /* The fd keeps the file alive, so take the name away at once:
         * nothing else can then open the capture's state, and nothing
         * is left in the directory if this process is killed. */
        g_unlink(path);
    }

    /* The bookkeeping goes in a shared anonymous mapping rather than in
     * this process's heap, so that processes forked from here allocate
     * from the same store rather than from a copy of it. */
    shared = mmap(NULL, sizeof(wmem_backing_shared_t),
            PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (shared == MAP_FAILED) {
        *err = g_strdup_printf("can't map %zu bytes for the backing store: "
                "%s", sizeof(wmem_backing_shared_t), g_strerror(errno));
        ws_close(fd);
        g_free(path);
        return NULL;
    }
    memset(shared, 0, sizeof(wmem_backing_shared_t));

    backing             = g_new0(wmem_backing_t, 1);
    backing->fd         = fd;
    backing->path       = path;
    backing->dir        = g_strdup(dir);
    backing->pagesize   = pagesize;
    backing->shared     = (wmem_backing_shared_t *)shared;
    backing->heap_sizes = g_hash_table_new(g_direct_hash, g_direct_equal);

    pthread_mutexattr_init(&attr);
    pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
    pthread_mutex_init(&backing->shared->lock, &attr);
    pthread_mutexattr_destroy(&attr);

    backing->shared->grow      = reserve;
    backing->shared->threshold = threshold;

    if (!wmem_backing_map_segment(backing, reserve, err)) {
        wmem_backing_destroy(backing);
        return NULL;
    }

    return backing;
#endif /* _WIN32 */
}

void
wmem_backing_destroy(wmem_backing_t *backing)
{
    if (backing == NULL) {
        return;
    }

#ifdef _WIN32
    {
        unsigned i;

        for (i = 0; i < backing->mapped; i++) {
            if (backing->bases[i] != NULL) {
                UnmapViewOfFile(backing->bases[i]);
            }
            if (backing->maps[i] != NULL) {
                CloseHandle(backing->maps[i]);
            }
        }
    }
    /* The last handle to a file opened with FILE_FLAG_DELETE_ON_CLOSE
     * is what deletes it. */
    CloseHandle(backing->file);
    g_free(backing->shared);
#else
    {
        unsigned i;

        for (i = 0; i < backing->mapped; i++) {
            if (backing->bases[i] != NULL) {
                munmap(backing->bases[i],
                        (size_t)backing->shared->segments[i].size);
            }
        }
    }
    ws_close(backing->fd);
    munmap(backing->shared, sizeof(wmem_backing_shared_t));
#endif

    g_hash_table_destroy(backing->heap_sizes);
    g_free(backing->path);
    g_free(backing->dir);
    g_free(backing);
}

/* The smallest free region that holds want bytes, or the region count if
 * there is none. Best fit, so that a long run of free space is left for
 * the request that needs all of it; the list stays short because
 * neighbours are merged as they are freed. */
static unsigned
wmem_backing_best_fit(wmem_backing_shared_t *shared, uint64_t want)
{
    unsigned best = shared->region_count;
    unsigned i;

    for (i = 0; i < shared->region_count; i++) {
        if (shared->regions[i].used || shared->regions[i].size < want) {
            continue;
        }
        if (best == shared->region_count ||
                shared->regions[i].size < shared->regions[best].size) {
            best = i;
        }
        if (shared->regions[i].size == want) {
            break;
        }
    }

    return best;
}

/* Hand out a region of the file. The lock is taken once per
 * multi-megabyte region, so what it costs does not show up anywhere. */
static void *
wmem_backing_alloc_mapped(wmem_backing_t *backing, size_t want)
{
    wmem_backing_shared_t *shared = backing->shared;
    unsigned               best;
    void                  *ptr;

    wmem_backing_lock(&shared->lock);

    best = wmem_backing_best_fit(shared, want);
    if (best == shared->region_count) {
        /* Nothing mapped can hold it, so add more file. The reserved
         * size is the growth step as well as the starting size, and a
         * request larger than that gets a piece of its own. */
        uint64_t size = shared->grow > want ? shared->grow : want;
        char    *err  = NULL;

        if (!wmem_backing_map_segment(backing, size, &err)) {
            wmem_backing_unlock(&shared->lock);
            ws_error("wmem: can't grow disk-backed memory past %" PRIu64
                    " MB: %s", shared->reserve / (1024 * 1024), err);
        }

        best = wmem_backing_best_fit(shared, want);
        ws_assert(best != shared->region_count);
    }

    if (shared->regions[best].size > want) {
        /* The tail is page-aligned, so it is a region in its own
         * right. */
        wmem_backing_region_insert(shared, best + 1,
                shared->regions[best].offset + want,
                shared->regions[best].size - want,
                shared->regions[best].segment, 0);
        shared->regions[best].size = want;
    }

    {
        /* Before this region is written to, and while the lock still
         * says it is nobody's, make the filesystem commit the space for
         * it. */
        char *err = NULL;

        if (!wmem_backing_reserve(backing, shared->regions[best].offset,
                    want, &err)) {
            uint64_t live = shared->live;

            wmem_backing_unlock(&shared->lock);
            ws_error("wmem: can't reserve %" PRIu64 " MB for disk-backed "
                    "memory in %s, with %" PRIu64 " MB of it already in "
                    "use: %s", (uint64_t)want / (1024 * 1024), backing->path,
                    live / (1024 * 1024), err);
        }
    }
    shared->regions[best].used = 1;

    shared->live += want;
    if (shared->live > shared->high_water) {
        shared->high_water = shared->live;
    }

    ptr = wmem_backing_address(backing, &shared->regions[best]);

    wmem_backing_unlock(&shared->lock);

    return ptr;
}

void *
wmem_backing_alloc(wmem_backing_t *backing, size_t size)
{
    wmem_backing_shared_t *shared = backing->shared;
    size_t                 want;
    void                  *ptr = NULL;

    want = (size_t)wmem_backing_round_up(size, backing->pagesize);

    /* Below the watermark the memory is ordinary heap memory, so a
     * capture whose state fits in RAM runs exactly as it would without a
     * store. The memory is this process's own; the budget is shared, so
     * one process holding a great deal of state leaves less for the
     * others rather than each getting its own allowance. */
    wmem_backing_lock(&shared->lock);
    if (shared->heap_live + want <= shared->threshold) {
        ptr = g_malloc(want);
        shared->heap_live += want;
        if (shared->heap_live > shared->heap_high_water) {
            shared->heap_high_water = shared->heap_live;
        }
    }
    wmem_backing_unlock(&shared->lock);

    if (ptr != NULL) {
        g_hash_table_insert(backing->heap_sizes, ptr, GSIZE_TO_POINTER(want));
        return ptr;
    }

    return wmem_backing_alloc_mapped(backing, want);
}

void
wmem_backing_free(wmem_backing_t *backing, void *ptr)
{
    wmem_backing_shared_t *shared = backing->shared;
    unsigned               at;
    uint64_t               offset, size;
    size_t                 heap_size;

    if (ptr == NULL) {
        return;
    }

    heap_size = GPOINTER_TO_SIZE(g_hash_table_lookup(backing->heap_sizes,
                ptr));
    if (heap_size != 0) {
        g_hash_table_remove(backing->heap_sizes, ptr);
        wmem_backing_lock(&shared->lock);
        shared->heap_live -= heap_size;
        wmem_backing_unlock(&shared->lock);
        g_free(ptr);
        return;
    }

    /* Give the pages back before the region is marked free, and with
     * the lock not held: the kernel work is the expensive part of a
     * free, and holding a lock that every process needs across a
     * syscall would serialize them on it. The region still counts as
     * handed out while this happens, so nothing else can be given the
     * bytes being discarded. */
    wmem_backing_lock(&shared->lock);
    at     = wmem_backing_region_of(backing, ptr);
    offset = shared->regions[at].offset;
    size   = shared->regions[at].size;
    wmem_backing_unlock(&shared->lock);

    wmem_backing_release(backing, ptr, offset, (size_t)size);

    wmem_backing_lock(&shared->lock);

    at = wmem_backing_region_of(backing, ptr);
    shared->regions[at].used = 0;
    shared->live -= size;

    /* Merge with the region before and the region after, so that the
     * space goes back as one extent rather than as a size that may never
     * be asked for again. Pieces of the file are independent of each
     * other, so a merge stays inside the one this region came from. */
    if (at + 1 < shared->region_count && !shared->regions[at + 1].used &&
            shared->regions[at + 1].segment == shared->regions[at].segment) {
        shared->regions[at].size += shared->regions[at + 1].size;
        wmem_backing_region_remove(shared, at + 1);
    }
    if (at > 0 && !shared->regions[at - 1].used &&
            shared->regions[at - 1].segment == shared->regions[at].segment) {
        shared->regions[at - 1].size += shared->regions[at].size;
        wmem_backing_region_remove(shared, at);
    }

    wmem_backing_unlock(&shared->lock);
}

void *
wmem_backing_realloc(wmem_backing_t *backing, void *ptr, size_t size)
{
    wmem_backing_shared_t *shared = backing->shared;
    size_t                 old, want;
    void                  *new_ptr;
    bool                   keep_in_heap = false;

    if (ptr == NULL) {
        return wmem_backing_alloc(backing, size);
    }

    want = (size_t)wmem_backing_round_up(size, backing->pagesize);

    old = GPOINTER_TO_SIZE(g_hash_table_lookup(backing->heap_sizes, ptr));
    if (old != 0) {
        /* Still in RAM. Keep it there if it fits under the watermark,
         * otherwise this is where it moves to the file. */
        wmem_backing_lock(&shared->lock);
        if (shared->heap_live - old + want <= shared->threshold) {
            shared->heap_live += want - old;
            if (shared->heap_live > shared->heap_high_water) {
                shared->heap_high_water = shared->heap_live;
            }
            keep_in_heap = true;
        }
        wmem_backing_unlock(&shared->lock);

        if (keep_in_heap) {
            new_ptr = g_realloc(ptr, want);
            g_hash_table_remove(backing->heap_sizes, ptr);
            g_hash_table_insert(backing->heap_sizes, new_ptr,
                    GSIZE_TO_POINTER(want));
            return new_ptr;
        }

        new_ptr = wmem_backing_alloc_mapped(backing, want);
        memcpy(new_ptr, ptr, old < want ? old : want);
        wmem_backing_free(backing, ptr);
        return new_ptr;
    }

    wmem_backing_lock(&shared->lock);
    old = (size_t)shared->regions[wmem_backing_region_of(backing, ptr)].size;
    wmem_backing_unlock(&shared->lock);

    if (want == old) {
        return ptr;
    }

    if (want < old) {
        /* Shrinking: keep the head where it is and give back the tail,
         * which is page-aligned and so a region in its own right. */
        unsigned at;

        wmem_backing_lock(&shared->lock);
        at = wmem_backing_region_of(backing, ptr);
        wmem_backing_region_insert(shared, at + 1,
                shared->regions[at].offset + want, old - want,
                shared->regions[at].segment, 1);
        shared->regions[at].size = want;
        wmem_backing_unlock(&shared->lock);

        wmem_backing_free(backing, (uint8_t *)ptr + want);
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
    return backing->shared->live;
}

uint64_t
wmem_backing_bytes_high_water(const wmem_backing_t *backing)
{
    return backing->shared->high_water;
}

uint64_t
wmem_backing_bytes_reserved(const wmem_backing_t *backing)
{
    return backing->shared->reserve;
}

uint64_t
wmem_backing_bytes_in_ram(const wmem_backing_t *backing)
{
    return backing->shared->heap_high_water;
}

uint64_t
wmem_backing_threshold(const wmem_backing_t *backing)
{
    return backing->shared->threshold;
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
