#ifndef ACALLOC_H
#define ACALLOC_H

#include <stddef.h>
#include <stdint.h>

/* ACalloc — AcreetionOS Secure Memory Allocator
 *
 * Features:
 *  - Heap metadata encryption (XOR with per-thread key)
 *  - Guard pages around allocation regions
 *  - Canary values at end of each allocation
 *  - Free-list integrity verification
 *  - Thread-local caches for zero-contention allocation
 *  - Buddy allocator for large blocks, slab for small
 *  - Automatic leak detection and reporting on exit
 *  - Metadata separated from data (no inline headers)
 *  - Double-free and use-after-free detection
 */

/* Standard malloc interface — thread-safe, async-signal-safe */
void *ac_malloc(size_t size);
void *ac_calloc(size_t nmemb, size_t size);
void *ac_realloc(void *ptr, size_t size);
void  ac_free(void *ptr);

/* Extension: get the usable size of an allocation */
size_t ac_malloc_usable_size(void *ptr);

/* Extension: manually trigger a leak report */
void ac_dump_leaks(void);

/* Extension: set allocator tuning parameters (0 = default) */
void ac_set_tuning(size_t slab_max, size_t guard_size, int canary_enabled);

/* Overhead tracking */
uint64_t ac_total_allocated(void);
uint64_t ac_total_freed(void);
uint64_t ac_current_usage(void);
uint64_t ac_peak_usage(void);

/* Encryption helper for hacrypt CLI tool */
void ac_xor_buf(void *buf, size_t len, uint64_t key);

#endif
