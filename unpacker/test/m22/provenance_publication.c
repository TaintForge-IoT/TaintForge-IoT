#include "provenance.h"
#include <assert.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>

static ProvRegistry *registry;
static _Atomic ProvLabelId observed;
static _Atomic bool finished;

static void identity_checks(ProvLabelId id) {
    assert(prov_label_is_valid(registry, id));
    assert(prov_label_may_be_tainted(registry, id) == (id != PROV_LABEL_CLEAN));
    assert(prov_label_join(registry, PROV_LABEL_CLEAN, id) == id);
    assert(prov_label_join(registry, id, PROV_LABEL_CLEAN) == id);
    assert(prov_label_join(registry, id, id) == id);
    ProvLabelId repeated[] = {PROV_LABEL_CLEAN, id, id, PROV_LABEL_CLEAN, id};
    assert(prov_label_join_many(registry, repeated, 5) == id);
    ProvLabelId bad[] = {id, PROV_LABEL_CLEAN, PROV_LABEL_ID_INVALID};
    assert(prov_label_join_many(registry, bad, 3) == PROV_LABEL_ID_INVALID);
    assert(prov_label_join(registry, PROV_LABEL_CLEAN, PROV_LABEL_ID_INVALID) == PROV_LABEL_ID_INVALID);
    assert(prov_label_join(registry, PROV_LABEL_ID_INVALID, PROV_LABEL_ID_INVALID) == PROV_LABEL_ID_INVALID);
    assert(!prov_label_is_valid(registry, PROV_LABEL_ID_INVALID));
    assert(!prov_label_is_valid(registry, UINT32_C(100000000)));
    assert(!prov_label_may_be_tainted(registry, PROV_LABEL_ID_INVALID));
    assert(prov_label_may_be_tainted_conservative(registry, PROV_LABEL_ID_INVALID));
}

static void *reader(void *unused) {
    (void)unused;
    do {
        ProvLabelId id = atomic_load_explicit(&observed, memory_order_acquire);
        identity_checks(id);
    } while (!atomic_load_explicit(&finished, memory_order_acquire));
    return NULL;
}

int main(void) {
    registry = prov_registry_create(NULL);
    assert(registry);
    atomic_init(&observed, PROV_LABEL_UNKNOWN);
    atomic_init(&finished, false);
    identity_checks(PROV_LABEL_CLEAN);
    identity_checks(PROV_LABEL_UNKNOWN);
    assert(!prov_label_is_valid(NULL, PROV_LABEL_CLEAN));
    assert(!prov_label_may_be_tainted(NULL, PROV_LABEL_UNKNOWN));
    assert(prov_label_join_many(registry, NULL, 0) == PROV_LABEL_CLEAN);
    assert(prov_label_join_many(registry, NULL, 1) == PROV_LABEL_ID_INVALID);
    pthread_t threads[4];
    for (unsigned i = 0; i < 4; i++)
        assert(pthread_create(&threads[i], NULL, reader, NULL) == 0);
    for (unsigned i = 0; i < 6000; i++) {
        ProvRootKey key = {.kind = PROV_ROOT_ARGV_BYTE, .source_id = 1, .offset = i};
        ProvRootId root = prov_root_intern(registry, &key);
        assert(root);
        ProvLabelId id = prov_label_from_root(registry, root, PROV_CHANNEL_DATA);
        assert(id != PROV_LABEL_ID_INVALID);
        identity_checks(id);
        ProvLabelId partial = prov_label_mark_incomplete(registry, id, PROV_COMPLETE_ALL,
                                                         PROV_INCOMPLETE_UNRESOLVED_MEMORY);
        identity_checks(partial);
        assert(!prov_label_is_complete(registry, partial, PROV_COMPLETE_ALL));
        atomic_store_explicit(&observed, partial, memory_order_release);
    }
    atomic_store_explicit(&finished, true, memory_order_release);
    for (unsigned i = 0; i < 4; i++)
        assert(pthread_join(threads[i], NULL) == 0);
    ProvRegistryStats stats;
    prov_registry_get_stats(registry, &stats);
    printf("{\"status\":\"PASS\",\"roots\":%u,\"sets\":%u,\"labels\":%u,\"digest\":\"%016" PRIx64 "\"}\n",
           stats.root_count, stats.root_set_count, stats.label_count, stats.registry_semantic_digest);
    prov_registry_destroy(registry);
    return 0;
}
