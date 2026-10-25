/* memcap.dylib - DYLD interposer that fails heap allocations past a budget.
 * Used to reproduce an out-of-memory condition deterministically:
 *   DYLD_INSERT_LIBRARIES=memcap.dylib MEMCAP_BYTES=$((2*1024*1024*1024)) tshark ...
 * Only malloc-family allocations are counted; file-backed mappings are not,
 * which is exactly the distinction under test.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdatomic.h>
#include <malloc/malloc.h>

static atomic_size_t live;
static atomic_size_t peak;
static size_t cap;

__attribute__((destructor)) static void memcap_report(void)
{
    fprintf(stderr, "memcap: peak heap %zu MB, live at exit %zu MB\n",
            atomic_load(&peak) / (1024 * 1024),
            atomic_load(&live) / (1024 * 1024));
}
__attribute__((constructor)) static void memcap_init(void)
{
    const char *e = getenv("MEMCAP_BYTES");
    cap = e ? strtoull(e, NULL, 10) : 0;
}

static int reserve(size_t n)
{
    size_t now = atomic_fetch_add(&live, n) + n;
    if (cap != 0 && now > cap) {
        atomic_fetch_sub(&live, n);
        return 0;
    }
    if (now > atomic_load(&peak)) atomic_store(&peak, now);
    return 1;
}
static void *account(void *p, size_t asked)
{
    if (p == NULL) { atomic_fetch_sub(&live, asked); return NULL; }
    size_t real = malloc_size(p);
    if (real > asked) atomic_fetch_add(&live, real - asked);
    else atomic_fetch_sub(&live, asked - real);
    return p;
}

static void *cap_malloc(size_t n)
{
    if (!reserve(n)) return NULL;
    return account(malloc(n), n);
}

static void *cap_calloc(size_t c, size_t s)
{
    size_t n = c * s;
    if (!reserve(n)) return NULL;
    return account(calloc(c, s), n);
}

static void cap_free(void *p)
{
    if (p) atomic_fetch_sub(&live, malloc_size(p));
    free(p);
}

static void *cap_realloc(void *p, size_t n)
{
    size_t old = p ? malloc_size(p) : 0;
    if (n > old && !reserve(n - old)) return NULL;
    void *q = realloc(p, n);
    if (q == NULL) {
        if (n > old) atomic_fetch_sub(&live, n - old);
        return NULL;
    }
    size_t real = malloc_size(q);
    /* live currently counts old + (n - old) if grown */
    size_t counted = old + (n > old ? n - old : 0);
    if (real > counted) atomic_fetch_add(&live, real - counted);
    else atomic_fetch_sub(&live, counted - real);
    return q;
}

#define DYLD_INTERPOSE(_repl, _orig) \
    __attribute__((used)) static struct { const void *repl; const void *orig; } \
    _interpose_##_orig __attribute__((section("__DATA,__interpose"))) = \
    { (const void *)(unsigned long)&_repl, (const void *)(unsigned long)&_orig };

DYLD_INTERPOSE(cap_malloc, malloc)
DYLD_INTERPOSE(cap_calloc, calloc)
DYLD_INTERPOSE(cap_realloc, realloc)
DYLD_INTERPOSE(cap_free, free)
