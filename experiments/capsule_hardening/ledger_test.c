#include <assert.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include "phase1_resources.h"

static void *watched;
static size_t watched_size;
void __real_free(void *data);
void __wrap_free(void *data) {
    if (data == watched && data) {
        for (size_t i = 0; i < watched_size; i++) assert(((unsigned char *)data)[i] == 0);
        watched = NULL;
    }
    __real_free(data);
}

static void *worker(void *arg) {
    const char *owner = arg;
    for (unsigned i = 0; i < 1000; i++) {
        void *data = tf_alloc_calloc(8, 8, owner);
        assert(data); memset(data, 0xab, 64);
        data = tf_alloc_realloc(data, 128, owner);
        assert(data); tf_alloc_free(data);
    }
    return NULL;
}

int main(int argc, char **argv) {
    assert(argc == 2);
    const char *mode = argv[1];
    char option[128];
    uint64_t size = tf_resources_reserved() +
        (!strcmp(mode,"below") || !strcmp(mode,"exact") || !strcmp(mode,"above") ? 64 : 16*1024*1024);
    snprintf(option, sizeof(option), "m4-memory-bytes=%" PRIu64, size);
    char *options[] = {option};
    assert(tf_resources_configure(1, options));
    if (!strcmp(mode,"below") || !strcmp(mode,"exact") || !strcmp(mode,"above")) {
        size_t n = !strcmp(mode,"below") ? 63 : !strcmp(mode,"exact") ? 64 : 65;
        void *data = tf_alloc_malloc(n,"page.c");
        memset(data,0xab,n); watched=data; watched_size=n;
        tf_alloc_free(data); assert(!watched);
    } else if (!strcmp(mode,"overflow")) {
        (void)tf_alloc_calloc(SIZE_MAX, 2,"trace.c");
        abort();
    } else if (!strcmp(mode,"realloc")) {
        unsigned char *data=tf_alloc_malloc(32,"trace.c");
        memset(data,0xab,32); watched=data; watched_size=32;
        data=tf_alloc_realloc(data,64,"trace.c");
        assert(!watched);
        for (unsigned i=0;i<32;i++) assert(data[i]==0xab);
        watched=data; watched_size=64;
        tf_alloc_free(data); assert(!watched);
    } else if (!strcmp(mode,"threads")) {
        pthread_t first,second;
        assert(!pthread_create(&first,NULL,worker,"trace.c"));
        assert(!pthread_create(&second,NULL,worker,"provenance.c"));
        assert(!pthread_join(first,NULL)); assert(!pthread_join(second,NULL));
    } else if (!strcmp(mode,"partial")) {
        void *first=tf_alloc_malloc(12,"state.c");
        tf_alloc_free(first); tf_alloc_free(NULL);
        assert(!tf_resources_remaining());
        assert(tf_resources_configure(1,options));
    } else if (!strcmp(mode,"leak")) {
        (void)tf_alloc_malloc(8,"state.c");
        assert(!tf_resources_configure(0,NULL));
    } else if (!strcmp(mode,"capacity")) {
        for (unsigned i=0;i<129;i++) (void)tf_alloc_malloc(1,"trace.c");
        abort();
    } else if (!strcmp(mode,"zero")) {
        void *data=tf_alloc_malloc(0,"state.c");
        tf_alloc_free(data);
    } else if (!strcmp(mode,"invalid-owner")) {
        (void)tf_alloc_malloc(2,"invalid\"owner");
        abort();
    } else assert(0);
    tf_resources_json(stdout,true); puts("");
    return 0;
}
