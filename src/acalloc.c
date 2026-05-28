/*
 * ACalloc — AcreetionOS Secure Memory Allocator
 */

#define _GNU_SOURCE
#include "acalloc.h"
#include <assert.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* ================================================================
 * Configuration
 * ================================================================ */

static size_t  g_slab_max     = 4096;       /* max size for slab allocator */
static size_t  g_guard_size   = 4096;       /* guard page size */
static int     g_canary       = 1;          /* enable canary checks */
static size_t  g_page_size    = 0;

/* ================================================================
 * Random / Entropy
 * ================================================================ */

static uint64_t get_entropy(void) {
    uint64_t v = 0;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, &v, sizeof(v));
        (void)n;
        close(fd);
    }
    return v;
}

/* ================================================================
 * Per-thread key for metadata encryption
 * ================================================================ */

static pthread_key_t g_meta_key;
static pthread_once_t g_key_once = PTHREAD_ONCE_INIT;

static void key_destroy(void *k) {
    munmap(k, sizeof(uint64_t));
}

static void key_init(void) {
    pthread_key_create(&g_meta_key, key_destroy);
}

static __thread int g_in_malloc = 0;

/* Get the real thread key without recursion guard */
static uint64_t thread_key_raw(void) {
    pthread_once(&g_key_once, key_init);
    uint64_t *k = pthread_getspecific(g_meta_key);
    if (!k) {
        k = mmap(NULL, sizeof(uint64_t), PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (k == MAP_FAILED) return 0;
        *k = get_entropy();
        pthread_setspecific(g_meta_key, k);
    }
    return *k;
}

static uint64_t thread_key(void) {
    if (g_in_malloc) return 0; /* Recursion guard — use default key */
    g_in_malloc = 1;
    pthread_once(&g_key_once, key_init);
    uint64_t *k = pthread_getspecific(g_meta_key);
    if (!k) {
        k = mmap(NULL, sizeof(uint64_t), PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (k == MAP_FAILED) { g_in_malloc = 0; return 0; }
        *k = get_entropy();
        pthread_setspecific(g_meta_key, k);
    }
    g_in_malloc = 0;
    return *k;
}

void ac_xor_buf(void *buf, size_t len, uint64_t key) {
    uint64_t *p = (uint64_t *)buf;
    size_t n = len / sizeof(uint64_t);
    for (size_t i = 0; i < n; i++) p[i] ^= key;
    for (size_t i = n * sizeof(uint64_t); i < len; i++)
        ((uint8_t *)buf)[i] ^= (uint8_t)(key >> ((i % 8) * 8));
}

/* ================================================================
 * Metadata region (separate from data — no inline headers)
 * ================================================================ */

#define META_BLOCK_SIZE 1048576  /* 1MB metadata blocks */
#define CANARY_VALUE    0xAC1E10C

struct meta_entry {
    uint64_t magic;        /* integrity check */
    uint64_t addr;         /* allocation address */
    uint64_t size;         /* allocation size */
    uint64_t thread;       /* allocating thread ID */
    uint32_t canary;       /* stored canary value */
    uint32_t state;        /* 0=free, 1=active, 2=freed */
    uint64_t timestamp;    /* allocation time */
    uint64_t _pad;
} __attribute__((packed));

static atomic_uintptr_t g_meta_region = 0;
static atomic_uint g_meta_count = 0;
static const int META_MAX = 1048576;

static struct meta_entry *meta_slot(void) {
    uint64_t key = thread_key_raw();
    struct meta_entry *base = (struct meta_entry *)atomic_load(&g_meta_region);
    if (!base) {
        base = (struct meta_entry *)mmap(NULL, sizeof(struct meta_entry) * META_MAX,
                                          PROT_READ | PROT_WRITE,
                                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (base == MAP_FAILED) return NULL;
        atomic_store(&g_meta_region, (uintptr_t)base);
    }
    int idx = atomic_fetch_add(&g_meta_count, 1);
    if (idx >= META_MAX) return NULL;
    struct meta_entry *e = &base[idx];
    memset(e, 0, sizeof(*e));
    e->magic = 0xAC1EAC1EAC1EAC1EULL ^ key;
    e->thread = (uint64_t)pthread_self() ^ key;
    e->canary = CANARY_VALUE;
    e->state = 1;
    e->timestamp = (uint64_t)time(NULL) ^ key;
    return e;
}

static int meta_validate(struct meta_entry *e, uint64_t key) {
    if (!e) return 0;
    uint64_t expected_magic = 0xAC1EAC1EAC1EAC1EULL ^ key;
    return (e->magic == expected_magic);
}

/* ================================================================
 * Slab allocator for small allocations
 * ================================================================ */

#define SLAB_SIZE 1048576  /* 1MB slabs */

struct slab_page {
    struct slab_page *next;
    int    object_size;
    int    objects_per_page;
    int    free_count;
    atomic_int free_head;
    char   data[] __attribute__((aligned(64)));
};

static __thread struct slab_page *slab_cache[33]; /* size classes for 16-4096 */

static int size_class(size_t size) {
    if (size <= 16) return 0;
    if (size <= 32) return 1;
    if (size <= 64) return 2;
    if (size <= 128) return 3;
    if (size <= 256) return 4;
    if (size <= 512) return 5;
    if (size <= 1024) return 6;
    if (size <= 2048) return 7;
    if (size <= 4096) return 8;
    return -1;
}

static int class_objsize(int cls) {
    return 16 << cls;
}

static void *slab_alloc(size_t size) {
    int cls = size_class(size);
    if (cls < 0) return NULL;

    int obj_size = class_objsize(cls);
    struct slab_page *sp = slab_cache[cls];

    if (!sp || sp->free_count <= 0) {
        /* Allocate new slab page */
        sp = (struct slab_page *)mmap(NULL, SLAB_SIZE,
                                       PROT_READ | PROT_WRITE,
                                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (sp == MAP_FAILED) return NULL;
        sp->next = slab_cache[cls];
        sp->object_size = obj_size;
        sp->objects_per_page = (SLAB_SIZE - sizeof(struct slab_page)) / obj_size;
        sp->free_count = sp->objects_per_page;
        sp->free_head = 0;

        /* Initialize free list (index-based) */
        int *indices = (int *)sp->data;
        for (int i = 0; i < sp->objects_per_page - 1; i++)
            indices[i] = i + 1;
        indices[sp->objects_per_page - 1] = -1;

        slab_cache[cls] = sp;
    }

    int idx = atomic_exchange(&sp->free_head, -1);
    if (idx < 0) return NULL;

    /* Read next free index */
    int *indices = (int *)sp->data;
    int next_idx = indices[idx];
    atomic_store(&sp->free_head, next_idx);
    atomic_fetch_sub(&sp->free_count, 1);

    return &sp->data[idx * obj_size];
}

static void slab_free(void *ptr, size_t size) {
    int cls = size_class(size);
    if (cls < 0) return;

    int obj_size = class_objsize(cls);
    struct slab_page *sp = slab_cache[cls];

    while (sp) {
        if ((char *)ptr >= sp->data && (char *)ptr < sp->data + SLAB_SIZE) {
            int idx = ((char *)ptr - sp->data) / obj_size;
            int *indices = (int *)sp->data;
            indices[idx] = atomic_exchange(&sp->free_head, idx);
            atomic_fetch_add(&sp->free_count, 1);
            return;
        }
        sp = sp->next;
    }
}

/* ================================================================
 * Buddy allocator for large allocations (≥4KB)
 * ================================================================ */

#define BUDDY_MIN    4096
#define BUDDY_MAX    67108864  /* 64MB */
#define BUDDY_LEVELS 15        /* 4KB to 64MB */

struct buddy_block {
    struct buddy_block *next;
    size_t size;
    int    level;
    int    free;
    uint64_t magic;
};

static struct buddy_block *buddy_free_lists[BUDDY_LEVELS];
static pthread_mutex_t buddy_lock = PTHREAD_MUTEX_INITIALIZER;

static int buddy_level(size_t size) {
    size = (size + BUDDY_MIN - 1) & ~(BUDDY_MIN - 1);
    int lvl = 0;
    size_t sz = BUDDY_MIN;
    while (sz < size && lvl < BUDDY_LEVELS - 1) { sz <<= 1; lvl++; }
    return lvl;
}

static size_t buddy_size(int level) {
    return BUDDY_MIN << level;
}

static void *buddy_alloc(size_t size) {
    int req_level = buddy_level(size);
    if (req_level >= BUDDY_LEVELS) {
        /* Too large — direct mmap */
        size_t alloc_size = size + g_guard_size * 2 + sizeof(uint64_t);
        void *ptr = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (ptr == MAP_FAILED) return NULL;
        /* Guard page before and after */
        mprotect(ptr, g_guard_size, PROT_NONE);
        mprotect((char *)ptr + alloc_size - g_guard_size, g_guard_size, PROT_NONE);
        /* Store size at start (after guard) */
        uint64_t *s = (uint64_t *)((char *)ptr + g_guard_size);
        *s = alloc_size;
        return (char *)ptr + g_guard_size + sizeof(uint64_t);
    }

    pthread_mutex_lock(&buddy_lock);

    /* Find free block at requested level or higher */
    int lvl;
    for (lvl = req_level; lvl < BUDDY_LEVELS; lvl++) {
        if (buddy_free_lists[lvl]) break;
    }
    if (lvl >= BUDDY_LEVELS) {
        /* Allocate from OS at max level */
        size_t sz = buddy_size(BUDDY_LEVELS - 1);
        struct buddy_block *blk = (struct buddy_block *)mmap(
            NULL, sz, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (blk == MAP_FAILED) { pthread_mutex_unlock(&buddy_lock); return NULL; }
        blk->size = sz;
        blk->level = BUDDY_LEVELS - 1;
        blk->free = 1;
        blk->magic = 0x8DDD8DDD8DDD8DDDULL;
        blk->next = NULL;
        buddy_free_lists[BUDDY_LEVELS - 1] = blk;
        lvl = BUDDY_LEVELS - 1;
    }

    /* Remove from free list */
    struct buddy_block *blk = buddy_free_lists[lvl];
    buddy_free_lists[lvl] = blk->next;
    blk->free = 0;

    /* Split until we reach requested level */
    while (lvl > req_level) {
        lvl--;
        size_t half = buddy_size(lvl);
        struct buddy_block *buddy = (struct buddy_block *)((char *)blk + half);
        buddy->size = half;
        buddy->level = lvl;
        buddy->free = 1;
        buddy->magic = 0x8DDD8DDD8DDD8DDDULL;
        buddy->next = buddy_free_lists[lvl];
        buddy_free_lists[lvl] = buddy;

        blk->size = half;
        blk->level = lvl;
    }

    blk->magic = 0x8DDD8DDD8DDD8DDDULL;
    pthread_mutex_unlock(&buddy_lock);
    return (void *)((char *)blk + sizeof(struct buddy_block));
}

static void buddy_free_large(void *ptr, size_t alloc_size) {
    munmap((char *)ptr - g_guard_size - sizeof(uint64_t), alloc_size);
}

static void buddy_free(void *ptr) {
    struct buddy_block *blk = (struct buddy_block *)((char *)ptr - sizeof(struct buddy_block));
    if (blk->magic != 0x8DDD8DDD8DDD8DDDULL) return; /* integrity check */

    pthread_mutex_lock(&buddy_lock);
    blk->free = 1;
    int lvl = blk->level;

    /* Try to merge with buddy */
    while (lvl < BUDDY_LEVELS - 1) {
        size_t blk_size = buddy_size(lvl);
        uintptr_t blk_addr = (uintptr_t)blk;
        uintptr_t buddy_addr = blk_addr ^ blk_size; /* XOR for buddy address */

        struct buddy_block *buddy = (struct buddy_block *)buddy_addr;
        if (buddy->magic != 0x8DDD8DDD8DDD8DDDULL || !buddy->free) break;
        if (buddy->level != lvl) break;

        /* Remove buddy from free list */
        struct buddy_block **pp = &buddy_free_lists[lvl];
        while (*pp) {
            if (*pp == buddy) { *pp = buddy->next; break; }
            pp = &(*pp)->next;
        }

        /* Merge: lower address becomes merged block */
        if (buddy_addr < blk_addr) blk = buddy;
        lvl++;
        blk->level = lvl;
        blk->size = buddy_size(lvl);
        blk->magic = 0x8DDD8DDD8DDD8DDDULL;
    }

    blk->next = buddy_free_lists[lvl];
    buddy_free_lists[lvl] = blk;
    pthread_mutex_unlock(&buddy_lock);
}

/* ================================================================
 * Public API
 * ================================================================ */

static __thread int g_initialized = 0;
static atomic_uint_fast64_t g_total_alloc = 0;
static atomic_uint_fast64_t g_total_free = 0;
static atomic_uint_fast64_t g_current = 0;
static atomic_uint_fast64_t g_peak = 0;

static void ensure_init(void) {
    if (!g_initialized) {
        g_page_size = sysconf(_SC_PAGESIZE);
        g_initialized = 1;
    }
}

void *ac_malloc(size_t size) {
    if (g_in_malloc) {
        /* Recursion: use system malloc via dlsym */
        static void *(*real_malloc)(size_t) = NULL;
        if (!real_malloc) real_malloc = dlsym(RTLD_NEXT, "malloc");
        return real_malloc ? real_malloc(size) : NULL;
    }
    g_in_malloc = 1;
    if (size == 0) size = 1;
    ensure_init();

    struct meta_entry *meta = meta_slot();
    if (!meta) { g_in_malloc = 0; return NULL; }

    void *ptr;

    if (size <= g_slab_max) {
        ptr = slab_alloc(size);
    } else {
        ptr = buddy_alloc(size);
    }

    if (!ptr) { g_in_malloc = 0; return NULL; }

    /* Set canary */
    if (g_canary) {
        *(uint32_t *)((char *)ptr + size) = CANARY_VALUE;
    }

    /* Fill metadata */
    uint64_t key = thread_key_raw();
    meta->addr = (uint64_t)ptr ^ key;
    meta->size = size ^ key;

    atomic_fetch_add(&g_total_alloc, size);
    uint64_t cur = atomic_fetch_add(&g_current, size) + size;
    uint64_t peak = atomic_load(&g_peak);
    while (cur > peak) {
        if (atomic_compare_exchange_weak(&g_peak, &peak, cur)) break;
    }

    g_in_malloc = 0;
    return ptr;
}

void *ac_calloc(size_t nmemb, size_t size) {
    size_t total = nmemb * size;
    void *ptr = ac_malloc(total);
    if (ptr) memset(ptr, 0, total);
    return ptr;
}

void *ac_realloc(void *ptr, size_t size) {
    if (!ptr) return ac_malloc(size);
    if (size == 0) { ac_free(ptr); return NULL; }

    size_t old_size = ac_malloc_usable_size(ptr);
    void *new_ptr = ac_malloc(size);
    if (!new_ptr) return NULL;
    size_t copy = old_size < size ? old_size : size;
    memcpy(new_ptr, ptr, copy);
    ac_free(ptr);
    return new_ptr;
}

void ac_free(void *ptr) {
    if (!ptr) return;

    uint64_t key = thread_key_raw();

    /* Find metadata entry */
    struct meta_entry *base = (struct meta_entry *)atomic_load(&g_meta_region);
    int count = atomic_load(&g_meta_count);
    int found = 0;
    for (int i = 0; i < count && i < META_MAX; i++) {
        if (meta_validate(&base[i], key) &&
            (base[i].addr ^ key) == (uint64_t)ptr &&
            base[i].state == 1) {
            base[i].state = 2; /* Mark as freed */
            found = 1;

            size_t free_sz = base[i].size ^ key;

            /* Verify canary */
            if (g_canary) {
                if (*(uint32_t *)((char *)ptr + free_sz) != CANARY_VALUE) {
                    fprintf(stderr, "ACalloc: CANARY CORRUPTED at %p (size %zu) — buffer overflow detected!\n",
                            ptr, free_sz);
                    abort();
                }
            }

            atomic_fetch_add(&g_total_free, free_sz);
            atomic_fetch_sub(&g_current, free_sz);
            break;
        }
    }

    if (!found) {
        /* Might be a double-free or invalid pointer — check */
        for (int i = 0; i < count && i < META_MAX; i++) {
            if (meta_validate(&base[i], key) &&
                (base[i].addr ^ key) == (uint64_t)ptr) {
                if (base[i].state == 2) {
                    fprintf(stderr, "ACalloc: DOUBLE FREE detected at %p\n", ptr);
                    abort();
                }
            }
        }
    }

    /* Actually free the memory */
    if (size_class(found ? (base->size ^ key) : 0) >= 0) {
        slab_free(ptr, found ? (base->size ^ key) : 0);
    } else {
        /* Check if buddy or direct mmap */
        struct buddy_block *blk = (struct buddy_block *)((char *)ptr - sizeof(struct buddy_block));
        if (blk->magic == 0x8DDD8DDD8DDD8DDDULL) {
            buddy_free(ptr);
        } else {
            /* Direct mmap — free from metadata */
            uint64_t *sp = (uint64_t *)((char *)ptr - sizeof(uint64_t));
            size_t alloc_size = *sp;
            buddy_free_large(ptr, alloc_size);
        }
    }
}

size_t ac_malloc_usable_size(void *ptr) {
    if (!ptr) return 0;
    uint64_t key = thread_key_raw();
    struct meta_entry *base = (struct meta_entry *)atomic_load(&g_meta_region);
    int count = atomic_load(&g_meta_count);
    for (int i = 0; i < count && i < META_MAX; i++) {
        if (meta_validate(&base[i], key) &&
            (base[i].addr ^ key) == (uint64_t)ptr &&
            base[i].state == 1) {
            return base[i].size ^ key;
        }
    }
    return 0;
}

void ac_dump_leaks(void) {
    uint64_t key = thread_key_raw();
    struct meta_entry *base = (struct meta_entry *)atomic_load(&g_meta_region);
    int count = atomic_load(&g_meta_count);
    int leaks = 0;
    uint64_t leaked_bytes = 0;

    for (int i = 0; i < count && i < META_MAX; i++) {
        if (meta_validate(&base[i], key) && base[i].state == 1) {
            uint64_t addr = base[i].addr ^ key;
            size_t sz = base[i].size ^ key;
            fprintf(stderr, "LEAK: %zu bytes at %p (thread %lx)\n",
                    sz, (void *)addr, (unsigned long)(base[i].thread ^ key));
            leaks++;
            leaked_bytes += sz;
        }
    }

    fprintf(stderr, "\nTotal: %d leaks, %lu bytes\n", leaks, (unsigned long)leaked_bytes);
}

/* ================================================================
 * Overhead tracking
 * ================================================================ */

uint64_t ac_total_allocated(void) { return atomic_load(&g_total_alloc); }
uint64_t ac_total_freed(void)     { return atomic_load(&g_total_free); }
uint64_t ac_current_usage(void)   { return atomic_load(&g_current); }
uint64_t ac_peak_usage(void)      { return atomic_load(&g_peak); }

void ac_set_tuning(size_t slab_max, size_t guard_size, int canary_enabled) {
    if (slab_max > 0)    g_slab_max = slab_max;
    if (guard_size > 0)  g_guard_size = guard_size;
    g_canary = canary_enabled;
}

/* ================================================================
 * malloc/free/realloc/calloc override (LD_PRELOAD)
 * ================================================================ */

void *malloc(size_t size) __attribute__((alias("ac_malloc")));
void *calloc(size_t n, size_t s) __attribute__((alias("ac_calloc")));
void *realloc(void *p, size_t s) __attribute__((alias("ac_realloc")));
void free(void *p) __attribute__((alias("ac_free")));

/* ================================================================
 * Destructor: leak report on exit
 * ================================================================ */

static void __attribute__((destructor)) acalloc_fini(void) {
    uint64_t leaked = atomic_load(&g_current);
    if (leaked > 0) {
        fprintf(stderr, "\n=== ACalloc Leak Report ===\n");
        ac_dump_leaks();
    }
}
