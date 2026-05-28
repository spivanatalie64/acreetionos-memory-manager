/* Test: multi-threaded stress */
#include "acalloc.h"
#include <pthread.h>
#include <stdio.h>
#include <string.h>

static void *worker(void *arg) {
    (void)arg;
    for (int i = 0; i < 1000; i++) {
        void *p = ac_malloc(16 + (i % 256));
        if (p) {
            memset(p, 0xAB, 16 + (i % 256));
            ac_free(p);
        }
    }
    return NULL;
}

int main(void) {
    pthread_t threads[8];
    for (int i = 0; i < 8; i++)
        pthread_create(&threads[i], NULL, worker, NULL);
    for (int i = 0; i < 8; i++)
        pthread_join(threads[i], NULL);

    printf("Stress test: %lu allocs, %lu frees, %lu current\n",
           (unsigned long)ac_total_allocated(),
           (unsigned long)ac_total_freed(),
           (unsigned long)ac_current_usage());
    printf("Peak usage: %lu bytes\n", (unsigned long)ac_peak_usage());

    if (ac_current_usage() == 0)
        printf("STRESS TEST PASSED (no leaks)\n");
    else
        printf("STRESS TEST FAILED (%lu leaked)\n", (unsigned long)ac_current_usage());
    return 0;
}
