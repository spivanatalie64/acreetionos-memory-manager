/* Test: leak detection */
#include "acalloc.h"
#include <stdio.h>

int main(void) {
    void *p1 = ac_malloc(64);
    void *p2 = ac_malloc(128);
    void *p3 = ac_malloc(256);
    (void)p1; (void)p2; (void)p3;

    ac_free(p2);  /* free one, leak two */

    printf("Allocated: %lu\n", (unsigned long)ac_total_allocated());
    printf("Freed:     %lu\n", (unsigned long)ac_total_freed());
    printf("Current:   %lu\n", (unsigned long)ac_current_usage());
    printf("Peak:      %lu\n", (unsigned long)ac_peak_usage());

    printf("\n=== Expected: 2 leaks (64 + 256 bytes) ===\n");
    return 0;
}
