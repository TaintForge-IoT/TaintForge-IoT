#define _POSIX_C_SOURCE 200809L
#include "provenance.h"
#include <assert.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

static uint64_t digest = UINT64_C(1469598103934665603);
static uint32_t random_state = 19;

static void hash(uint64_t value) {
    for (unsigned i = 0; i < 8; i++) {
        digest ^= (value >> (i * 8)) & 255;
        digest *= UINT64_C(1099511628211);
    }
}

static uint32_t random_word(void) {
    random_state ^= random_state << 13;
    random_state ^= random_state >> 17;
    random_state ^= random_state << 5;
    return random_state;
}

static void hash_set(ProvRegistry *registry, ProvRootSetId id) {
    ProvRootSetView set = {0};
    assert(prov_root_set_get(registry, id, &set));
    hash(id);
    hash(set.count);
    for (uint32_t i = 0; i < set.count; i++)
        hash(set.roots[i]);
}

/* Independent membership oracle: inspect each possible root, rather than
 * repeating the implementation's sorted merge algorithm. */
static void check_union(ProvRegistry *registry, ProvRootSetId left, ProvRootSetId right,
                         uint32_t cap, uint32_t pool_size) {
    bool truncated = false;
    ProvRootSetId id = prov_root_set_union(registry, left, right, &truncated);
    assert(id != PROV_ROOT_SET_ID_INVALID);
    ProvRootSetView result = {0};
    assert(prov_root_set_get(registry, id, &result));
    uint32_t unique = 0;
    for (uint32_t root = 1; root <= pool_size; root++) {
        if (prov_root_set_contains(registry, left, root) ||
            prov_root_set_contains(registry, right, root)) {
            if (unique < cap) {
                assert(unique < result.count);
                assert(result.roots[unique] == root);
            }
            unique++;
        }
    }
    assert(result.count == (unique < cap ? unique : cap));
    assert(truncated == (unique > cap));
    bool cached_truncated = false;
    assert(prov_root_set_union(registry, right, left, &cached_truncated) == id);
    assert(cached_truncated == truncated);
    hash_set(registry, id);
    hash(truncated);
}

typedef struct {
    ProvRegistry *registry;
    ProvRootSetId left;
    ProvRootSetId right;
    ProvRootSetId result;
    bool truncated;
} ThreadInput;

static void *thread_join(void *opaque) {
    ThreadInput *input = opaque;
    for (unsigned i = 0; i < 1000; i++) {
        bool truncated = false;
        assert(prov_root_set_union(input->registry, input->left, input->right,
                                    &truncated) == input->result);
        assert(truncated == input->truncated);
    }
    return NULL;
}

static void scenario(uint32_t cap) {
    ProvRegistryConfig config = {.max_roots_per_set = cap};
    ProvRegistry *registry = prov_registry_create(&config);
    assert(registry);
    const uint32_t pool_size = cap < 128 ? 97 : cap * 2 + 3;
    for (uint32_t i = 0; i < pool_size; i++) {
        ProvRootKey key = {.kind = PROV_ROOT_ARGV_BYTE, .source_id = 1, .offset = i};
        assert(prov_root_intern(registry, &key) == i + 1);
    }
    ProvResourceKey resource = {.kind = PROV_RESOURCE_FILE, .object_id = 12};
    ProvResourceId resource_id = prov_resource_intern(registry, &resource, NULL, 0);
    assert(resource_id);
    assert(prov_resource_intern(registry, &resource, "oracle", 0) == resource_id);
    ProvRootSetId sets[64] = {0};
    ProvRootId *roots = malloc((size_t)pool_size * sizeof(*roots));
    assert(roots);
    for (unsigned i = 1; i < 64; i++) {
        uint32_t count = cap < 128 ? 1 + random_word() % 32 : cap;
        for (uint32_t j = 0; j < count; j++)
            roots[j] = 1 + random_word() % pool_size;
        bool truncated = false;
        sets[i] = prov_root_set_intern(registry, roots, count, &truncated);
        assert(sets[i] != PROV_ROOT_SET_ID_INVALID);
        hash_set(registry, sets[i]);
        hash(truncated);
    }
    /* Disjoint saturated sets, subset, repeated, empty and symmetric cases. */
    for (uint32_t i = 0; i < cap; i++)
        roots[i] = i + 1;
    sets[1] = prov_root_set_intern(registry, roots, cap, NULL);
    for (uint32_t i = 0; i < cap; i++)
        roots[i] = cap + i + 1;
    sets[2] = prov_root_set_intern(registry, roots, cap, NULL);
    sets[3] = prov_root_set_singleton(registry, 1);
    sets[5] = prov_root_set_singleton(registry, pool_size);
    roots[0] = 1;
    roots[1] = cap / 2 + 1;
    roots[2] = cap;
    sets[4] = prov_root_set_intern(registry, roots, 3, NULL);
    check_union(registry, sets[1], sets[3], cap, pool_size);
    check_union(registry, sets[1], sets[4], cap, pool_size);
    check_union(registry, sets[4], sets[1], cap, pool_size);
    check_union(registry, sets[2], sets[3], cap, pool_size);
    check_union(registry, sets[1], sets[5], cap, pool_size);
    check_union(registry, sets[5], sets[1], cap, pool_size);
    check_union(registry, sets[1], sets[2], cap, pool_size);
    check_union(registry, sets[1], sets[1], cap, pool_size);
    check_union(registry, sets[1], sets[0], cap, pool_size);
    for (unsigned i = 0; i < 700; i++) {
        unsigned l = random_word() % 64, r = random_word() % 64;
        check_union(registry, sets[l], sets[r], cap, pool_size);
        ProvLabelView a = {.data_roots = sets[l], .address_roots = sets[r],
                           .complete_mask = PROV_COMPLETE_ALL};
        ProvLabelView b = {.data_roots = sets[r], .address_roots = sets[l],
                           .complete_mask = i % 3 ? PROV_COMPLETE_ALL : PROV_COMPLETE_DATA,
                           .incomplete_reasons = PROV_INCOMPLETE_UNRESOLVED_MEMORY};
        ProvLabelId joined = prov_label_join(registry, prov_label_intern(registry, &a),
                                             prov_label_intern(registry, &b));
        ProvLabelView result = {0};
        assert(prov_label_get(registry, joined, &result));
        bool truncated = false;
        ProvRootSetId both = prov_root_set_union(registry, sets[l], sets[r], &truncated);
        assert(result.data_roots == both && result.address_roots == both);
        uint8_t expected_complete = b.complete_mask;
        uint64_t expected_reason = b.complete_mask == PROV_COMPLETE_ALL
                                       ? PROV_INCOMPLETE_NONE : b.incomplete_reasons;
        if (truncated) {
            expected_complete = PROV_COMPLETE_NONE;
            expected_reason |= PROV_INCOMPLETE_ROOT_SET_BUDGET;
        }
        assert(result.complete_mask == expected_complete);
        assert(result.incomplete_reasons == expected_reason);
        bool expected_taint = result.data_roots != PROV_ROOT_SET_EMPTY ||
                              result.address_roots != PROV_ROOT_SET_EMPTY ||
                              result.complete_mask != PROV_COMPLETE_ALL;
        assert(prov_label_may_be_tainted_conservative(registry, joined) == expected_taint);
        assert((!prov_label_is_valid(registry, joined) ||
                prov_label_may_be_tainted(registry, joined)) == expected_taint);
        hash(joined);
        hash(result.complete_mask);
        hash(result.incomplete_reasons);
    }
    bool bad_truncated = true;
    assert(prov_root_set_union(registry, PROV_ROOT_SET_ID_INVALID, sets[1],
                                &bad_truncated) == PROV_ROOT_SET_ID_INVALID);
    assert(!bad_truncated);
    assert(!prov_label_may_be_tainted_conservative(registry, PROV_LABEL_CLEAN));
    assert(prov_label_may_be_tainted_conservative(registry, PROV_LABEL_UNKNOWN));
    assert(prov_label_may_be_tainted_conservative(registry, PROV_LABEL_ID_INVALID));
    assert(prov_label_may_be_tainted_conservative(registry, UINT32_MAX - 1));
    assert(prov_label_may_be_tainted_conservative(NULL, PROV_LABEL_CLEAN));
    ProvLabelView normalized_clean = {.complete_mask = PROV_COMPLETE_ALL,
        .incomplete_reasons = PROV_INCOMPLETE_ROOT_SET_BUDGET};
    assert(prov_label_intern(registry, &normalized_clean) == PROV_LABEL_CLEAN);
    assert(!prov_label_may_be_tainted_conservative(registry,
                                                   prov_label_intern(registry, &normalized_clean)));
    bool truncated = false;
    ProvRootSetId result = prov_root_set_union(registry, sets[1], sets[2], &truncated);
    ThreadInput input = {registry, sets[1], sets[2], result, truncated};
    pthread_t threads[4];
    for (unsigned i = 0; i < 4; i++)
        assert(pthread_create(&threads[i], NULL, thread_join, &input) == 0);
    for (unsigned i = 0; i < 4; i++)
        assert(pthread_join(threads[i], NULL) == 0);
    ProvRegistryStats stats = {0};
    prov_registry_get_stats(registry, &stats);
    assert(stats.max_roots_per_set == cap);
    assert(stats.resource_name_bytes == 7);
    assert(stats.root_set_payload_bytes > 0);
    assert(stats.registry_accounted_bytes > stats.root_set_payload_bytes);
    assert(stats.union_cache_entries > 0);
    assert(stats.root_set_union_cache_hits > 4000);
    assert(stats.union_fastpath_enabled ? stats.union_temp_allocations == 1
                                       : stats.union_temp_allocations > 1);
    assert(stats.union_scratch_bytes == (stats.union_fastpath_enabled ? (uint64_t)cap * 4 : 0));
    if (cap == 4096)
        assert(stats.union_fastpath_enabled ? stats.union_retained_prefix_hits >= 2 : stats.union_retained_prefix_hits == 0);
    printf("{\"cap\":%u,\"digest\":\"%016" PRIx64 "\",\"sets\":%u,\"labels\":%u,"
           "\"truncations\":%" PRIu64 ",\"allocations\":%" PRIu64 ",\"iterations\":%" PRIu64
           ",\"registry_digest\":\"%016" PRIx64 "\"}\n",
           cap, digest, stats.root_set_count, stats.label_count, stats.root_set_truncations,
           stats.union_temp_allocations, stats.union_merge_iterations, stats.registry_semantic_digest);
    free(roots);
    prov_registry_destroy(registry);
}

int main(void) {
    const uint32_t caps[] = {1, 2, 7, 32, 4096};
    for (unsigned i = 0; i < sizeof(caps) / sizeof(caps[0]); i++)
        scenario(caps[i]);
    return 0;
}
