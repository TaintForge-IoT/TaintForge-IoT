#include "provenance.h"

#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define PROV_INITIAL_BUCKET_COUNT ((size_t)16)
#define PROV_LOAD_NUMERATOR ((size_t)7)
#define PROV_LOAD_DENOMINATOR ((size_t)10)

typedef struct {
    ProvResourceKey key;
    uint32_t roles;
    char *display_name;
} ProvResourceRecord;

typedef struct {
    ProvRootKey key;
} ProvRootRecord;

typedef struct {
    ProvRootId *roots;
    uint32_t count;
    uint64_t hash;
} ProvRootSetRecord;

typedef struct {
    ProvLabelView view;
    uint64_t hash;
} ProvLabelRecord;

typedef struct {
    uint64_t key;
    ProvRootSetId result;
    bool truncated;
    bool used;
} ProvUnionCacheEntry;

struct ProvRegistry {
    pthread_mutex_t lock;
    uint64_t instance;
    uint32_t max_roots_per_set;

    ProvResourceRecord *resources;
    size_t resource_count;
    size_t resource_capacity;
    uint32_t *resource_buckets;
    size_t resource_bucket_count;

    ProvRootRecord *roots;
    size_t root_count;
    size_t root_capacity;
    uint32_t *root_buckets;
    size_t root_bucket_count;

    ProvRootSetRecord *root_sets;
    size_t root_set_count;
    size_t root_set_capacity;
    uint32_t *root_set_buckets;
    size_t root_set_bucket_count;

    ProvLabelRecord *labels;
    size_t label_count;
    size_t label_capacity;
    uint32_t *label_buckets;
    size_t label_bucket_count;
    ProvLabelId unknown_label;

    ProvUnionCacheEntry *union_cache;
    size_t union_cache_count;
    size_t union_cache_capacity;

    uint64_t union_requests;
    uint64_t union_cache_hits;
    uint64_t root_set_truncations;
};

typedef struct {
    ProvResourceId resource_id;
    uint64_t current_offset;
    uint32_t flags;
    uint32_t reference_count;
    bool active;
} ProvOpenFileDescriptionRecord;

typedef struct {
    int32_t fd;
    ProvOpenFileDescriptionId ofd_id;
    uint8_t state;
} ProvFdSlot;

enum {
    PROV_FD_SLOT_EMPTY = 0,
    PROV_FD_SLOT_OCCUPIED = 1,
    PROV_FD_SLOT_TOMBSTONE = 2
};

struct ProvFdTable {
    pthread_mutex_t lock;
    ProvRegistry *registry;
    ProvOpenFileDescriptionRecord *ofds;
    size_t ofd_count;
    size_t ofd_capacity;
    ProvFdSlot *slots;
    size_t slot_capacity;
    size_t binding_count;
    size_t tombstone_count;
};

static uint64_t prov_mix64(uint64_t value) {
    value ^= value >> 30;
    value *= UINT64_C(0xbf58476d1ce4e5b9);
    value ^= value >> 27;
    value *= UINT64_C(0x94d049bb133111eb);
    value ^= value >> 31;
    return value;
}

static uint64_t prov_hash_combine(uint64_t hash, uint64_t value) {
    return prov_mix64(
        hash ^ (prov_mix64(value) + UINT64_C(0x9e3779b97f4a7c15) + (hash << 6) + (hash >> 2)));
}

static char *prov_strdup(const char *source) {
    if (!source)
        return NULL;
    size_t length = strlen(source);
    if (length == SIZE_MAX)
        return NULL;
    char *copy = malloc(length + 1);
    if (!copy)
        return NULL;
    memcpy(copy, source, length + 1);
    return copy;
}

static bool prov_size_multiply(size_t count, size_t element_size, size_t *out_size) {
    if (!out_size || element_size == 0)
        return false;
    if (count > SIZE_MAX / element_size)
        return false;
    *out_size = count * element_size;
    return true;
}

static bool prov_grow_array(void **array, size_t element_size, size_t *capacity, size_t required) {
    if (!array || !capacity || element_size == 0)
        return false;
    if (*capacity >= required)
        return true;
    size_t next = *capacity ? *capacity : 8;
    while (next < required) {
        if (next > SIZE_MAX / 2) {
            next = required;
            break;
        }
        next *= 2;
    }
    if (next > SIZE_MAX / element_size)
        return false;
    void *grown = realloc(*array, next * element_size);
    if (!grown)
        return false;
    *array = grown;
    *capacity = next;
    return true;
}

static bool prov_should_grow(size_t entries, size_t buckets) {
    if (buckets == 0)
        return true;
    if (entries > SIZE_MAX / PROV_LOAD_DENOMINATOR)
        return true;
    if (buckets > SIZE_MAX / PROV_LOAD_NUMERATOR)
        return false;
    return entries * PROV_LOAD_DENOMINATOR >= buckets * PROV_LOAD_NUMERATOR;
}

static bool prov_resource_key_equal(const ProvResourceKey *left, const ProvResourceKey *right) {
    return left && right && left->kind == right->kind && left->scope_id == right->scope_id &&
           left->object_id == right->object_id && left->semantic_version == right->semantic_version;
}

static uint64_t prov_resource_key_hash(const ProvResourceKey *key) {
    uint64_t hash = prov_mix64((uint64_t)key->kind);
    hash = prov_hash_combine(hash, key->scope_id);
    hash = prov_hash_combine(hash, key->object_id);
    return prov_hash_combine(hash, key->semantic_version);
}

static bool prov_root_key_equal(const ProvRootKey *left, const ProvRootKey *right) {
    return left && right && left->kind == right->kind && left->source_id == right->source_id &&
           left->discriminator == right->discriminator && left->offset == right->offset &&
           left->semantic_instance == right->semantic_instance;
}

static uint64_t prov_root_key_hash(const ProvRootKey *key) {
    uint64_t hash = prov_mix64((uint64_t)key->kind);
    hash = prov_hash_combine(hash, key->source_id);
    hash = prov_hash_combine(hash, key->discriminator);
    hash = prov_hash_combine(hash, key->offset);
    return prov_hash_combine(hash, key->semantic_instance);
}

static uint64_t prov_root_set_hash(const ProvRootId *roots, uint32_t count) {
    uint64_t hash = prov_mix64(count);
    for (uint32_t index = 0; index < count; index++) {
        hash = prov_hash_combine(hash, roots[index]);
    }
    return hash;
}

static uint64_t prov_label_hash(const ProvLabelView *label) {
    uint64_t hash = prov_mix64(label->data_roots);
    hash = prov_hash_combine(hash, label->address_roots);
    hash = prov_hash_combine(hash, label->complete_mask);
    return prov_hash_combine(hash, label->incomplete_reasons);
}

static bool prov_label_equal(const ProvLabelView *left, const ProvLabelView *right) {
    return left && right && left->data_roots == right->data_roots &&
           left->address_roots == right->address_roots &&
           left->complete_mask == right->complete_mask &&
           left->incomplete_reasons == right->incomplete_reasons;
}

static bool prov_resource_rehash_locked(ProvRegistry *registry, size_t capacity) {
    uint32_t *buckets = calloc(capacity, sizeof(*buckets));
    if (!buckets)
        return false;
    for (size_t index = 0; index < registry->resource_count; index++) {
        uint64_t hash = prov_resource_key_hash(&registry->resources[index].key);
        size_t slot = (size_t)hash & (capacity - 1);
        while (buckets[slot] != 0)
            slot = (slot + 1) & (capacity - 1);
        buckets[slot] = (uint32_t)(index + 1);
    }
    free(registry->resource_buckets);
    registry->resource_buckets = buckets;
    registry->resource_bucket_count = capacity;
    return true;
}

static bool prov_root_rehash_locked(ProvRegistry *registry, size_t capacity) {
    uint32_t *buckets = calloc(capacity, sizeof(*buckets));
    if (!buckets)
        return false;
    for (size_t index = 0; index < registry->root_count; index++) {
        uint64_t hash = prov_root_key_hash(&registry->roots[index].key);
        size_t slot = (size_t)hash & (capacity - 1);
        while (buckets[slot] != 0)
            slot = (slot + 1) & (capacity - 1);
        buckets[slot] = (uint32_t)(index + 1);
    }
    free(registry->root_buckets);
    registry->root_buckets = buckets;
    registry->root_bucket_count = capacity;
    return true;
}

static bool prov_root_set_rehash_locked(ProvRegistry *registry, size_t capacity) {
    uint32_t *buckets = calloc(capacity, sizeof(*buckets));
    if (!buckets)
        return false;
    for (size_t index = 0; index < registry->root_set_count; index++) {
        uint64_t hash = registry->root_sets[index].hash;
        size_t slot = (size_t)hash & (capacity - 1);
        while (buckets[slot] != 0)
            slot = (slot + 1) & (capacity - 1);
        buckets[slot] = (uint32_t)(index + 1);
    }
    free(registry->root_set_buckets);
    registry->root_set_buckets = buckets;
    registry->root_set_bucket_count = capacity;
    return true;
}

static bool prov_label_rehash_locked(ProvRegistry *registry, size_t capacity) {
    uint32_t *buckets = calloc(capacity, sizeof(*buckets));
    if (!buckets)
        return false;
    for (size_t index = 0; index < registry->label_count; index++) {
        uint64_t hash = registry->labels[index].hash;
        size_t slot = (size_t)hash & (capacity - 1);
        while (buckets[slot] != 0)
            slot = (slot + 1) & (capacity - 1);
        buckets[slot] = (uint32_t)(index + 1);
    }
    free(registry->label_buckets);
    registry->label_buckets = buckets;
    registry->label_bucket_count = capacity;
    return true;
}

static bool prov_union_cache_rehash_locked(ProvRegistry *registry, size_t capacity) {
    ProvUnionCacheEntry *entries = calloc(capacity, sizeof(*entries));
    if (!entries)
        return false;
    for (size_t index = 0; index < registry->union_cache_capacity; index++) {
        ProvUnionCacheEntry entry = registry->union_cache[index];
        if (!entry.used)
            continue;
        size_t slot = (size_t)prov_mix64(entry.key) & (capacity - 1);
        while (entries[slot].used)
            slot = (slot + 1) & (capacity - 1);
        entries[slot] = entry;
    }
    free(registry->union_cache);
    registry->union_cache = entries;
    registry->union_cache_capacity = capacity;
    return true;
}

static ProvResourceId prov_resource_find_locked(ProvRegistry *registry, const ProvResourceKey *key,
                                                uint64_t hash) {
    if (!registry->resource_bucket_count)
        return PROV_RESOURCE_ID_INVALID;
    size_t mask = registry->resource_bucket_count - 1;
    size_t slot = (size_t)hash & mask;
    for (size_t probe = 0; probe < registry->resource_bucket_count; probe++) {
        uint32_t id = registry->resource_buckets[slot];
        if (id == 0)
            return PROV_RESOURCE_ID_INVALID;
        if (prov_resource_key_equal(&registry->resources[id - 1].key, key)) {
            return id;
        }
        slot = (slot + 1) & mask;
    }
    return PROV_RESOURCE_ID_INVALID;
}

static ProvRootId prov_root_find_locked(ProvRegistry *registry, const ProvRootKey *key,
                                        uint64_t hash) {
    if (!registry->root_bucket_count)
        return PROV_ROOT_ID_INVALID;
    size_t mask = registry->root_bucket_count - 1;
    size_t slot = (size_t)hash & mask;
    for (size_t probe = 0; probe < registry->root_bucket_count; probe++) {
        uint32_t id = registry->root_buckets[slot];
        if (id == 0)
            return PROV_ROOT_ID_INVALID;
        if (prov_root_key_equal(&registry->roots[id - 1].key, key))
            return id;
        slot = (slot + 1) & mask;
    }
    return PROV_ROOT_ID_INVALID;
}

static ProvRootSetId prov_root_set_find_locked(ProvRegistry *registry, const ProvRootId *roots,
                                               uint32_t count, uint64_t hash) {
    if (!registry->root_set_bucket_count)
        return PROV_ROOT_SET_EMPTY;
    size_t mask = registry->root_set_bucket_count - 1;
    size_t slot = (size_t)hash & mask;
    for (size_t probe = 0; probe < registry->root_set_bucket_count; probe++) {
        uint32_t id = registry->root_set_buckets[slot];
        if (id == 0)
            return PROV_ROOT_SET_EMPTY;
        ProvRootSetRecord *record = &registry->root_sets[id - 1];
        if (record->hash == hash && record->count == count &&
            memcmp(record->roots, roots, (size_t)count * sizeof(*roots)) == 0) {
            return id;
        }
        slot = (slot + 1) & mask;
    }
    return PROV_ROOT_SET_EMPTY;
}

static ProvLabelId prov_label_find_locked(ProvRegistry *registry, const ProvLabelView *label,
                                          uint64_t hash) {
    if (!registry->label_bucket_count)
        return PROV_LABEL_ID_INVALID;
    size_t mask = registry->label_bucket_count - 1;
    size_t slot = (size_t)hash & mask;
    for (size_t probe = 0; probe < registry->label_bucket_count; probe++) {
        uint32_t encoded = registry->label_buckets[slot];
        if (encoded == 0)
            return PROV_LABEL_ID_INVALID;
        ProvLabelId id = encoded - 1;
        ProvLabelRecord *record = &registry->labels[id];
        if (record->hash == hash && prov_label_equal(&record->view, label)) {
            return id;
        }
        slot = (slot + 1) & mask;
    }
    return PROV_LABEL_ID_INVALID;
}

static bool prov_root_set_id_valid_locked(const ProvRegistry *registry, ProvRootSetId set_id) {
    return set_id == PROV_ROOT_SET_EMPTY || set_id <= registry->root_set_count;
}

static bool prov_label_id_valid_locked(const ProvRegistry *registry, ProvLabelId label_id) {
    return label_id != PROV_LABEL_ID_INVALID && label_id < registry->label_count;
}

static ProvRootSetId prov_root_set_intern_sorted_locked(ProvRegistry *registry,
                                                        const ProvRootId *roots, uint32_t count) {
    if (count == 0)
        return PROV_ROOT_SET_EMPTY;
    uint64_t hash = prov_root_set_hash(roots, count);
    ProvRootSetId existing = prov_root_set_find_locked(registry, roots, count, hash);
    if (existing != PROV_ROOT_SET_EMPTY)
        return existing;
    if (registry->root_set_count >= UINT32_MAX)
        return PROV_ROOT_SET_ID_INVALID;

    if (prov_should_grow(registry->root_set_count + 1, registry->root_set_bucket_count)) {
        size_t capacity = registry->root_set_bucket_count ? registry->root_set_bucket_count * 2
                                                          : PROV_INITIAL_BUCKET_COUNT;
        if (capacity < registry->root_set_bucket_count ||
            !prov_root_set_rehash_locked(registry, capacity)) {
            return PROV_ROOT_SET_ID_INVALID;
        }
    }
    if (!prov_grow_array((void **)&registry->root_sets, sizeof(*registry->root_sets),
                         &registry->root_set_capacity, registry->root_set_count + 1)) {
        return PROV_ROOT_SET_ID_INVALID;
    }
    size_t allocation_size = 0;
    if (!prov_size_multiply(count, sizeof(*roots), &allocation_size)) {
        return PROV_ROOT_SET_ID_INVALID;
    }
    ProvRootId *copy = malloc(allocation_size);
    if (!copy)
        return PROV_ROOT_SET_ID_INVALID;
    memcpy(copy, roots, allocation_size);

    ProvRootSetId id = (ProvRootSetId)(registry->root_set_count + 1);
    ProvRootSetRecord *record = &registry->root_sets[registry->root_set_count++];
    record->roots = copy;
    record->count = count;
    record->hash = hash;

    size_t mask = registry->root_set_bucket_count - 1;
    size_t slot = (size_t)hash & mask;
    while (registry->root_set_buckets[slot] != 0)
        slot = (slot + 1) & mask;
    registry->root_set_buckets[slot] = id;
    return id;
}

static ProvLabelId prov_label_intern_locked(ProvRegistry *registry, const ProvLabelView *input) {
    if (!input || !prov_root_set_id_valid_locked(registry, input->data_roots) ||
        !prov_root_set_id_valid_locked(registry, input->address_roots)) {
        return PROV_LABEL_ID_INVALID;
    }

    ProvLabelView label = *input;
    label.complete_mask &= PROV_COMPLETE_ALL;
    if (label.complete_mask == PROV_COMPLETE_ALL) {
        label.incomplete_reasons = PROV_INCOMPLETE_NONE;
    } else if (label.incomplete_reasons == PROV_INCOMPLETE_NONE) {
        label.incomplete_reasons = PROV_INCOMPLETE_UNKNOWN;
    }

    uint64_t hash = prov_label_hash(&label);
    ProvLabelId existing = prov_label_find_locked(registry, &label, hash);
    if (existing != PROV_LABEL_ID_INVALID)
        return existing;
    if (registry->label_count >= UINT32_MAX)
        return PROV_LABEL_ID_INVALID;
    if (prov_should_grow(registry->label_count + 1, registry->label_bucket_count)) {
        size_t capacity = registry->label_bucket_count ? registry->label_bucket_count * 2
                                                       : PROV_INITIAL_BUCKET_COUNT;
        if (capacity < registry->label_bucket_count ||
            !prov_label_rehash_locked(registry, capacity)) {
            return PROV_LABEL_ID_INVALID;
        }
    }
    if (!prov_grow_array((void **)&registry->labels, sizeof(*registry->labels),
                         &registry->label_capacity, registry->label_count + 1)) {
        return PROV_LABEL_ID_INVALID;
    }

    ProvLabelId id = (ProvLabelId)registry->label_count;
    registry->labels[registry->label_count].view = label;
    registry->labels[registry->label_count].hash = hash;
    registry->label_count++;
    size_t mask = registry->label_bucket_count - 1;
    size_t slot = (size_t)hash & mask;
    while (registry->label_buckets[slot] != 0)
        slot = (slot + 1) & mask;
    registry->label_buckets[slot] = id + 1;
    return id;
}

static bool prov_union_cache_lookup_locked(ProvRegistry *registry, uint64_t key,
                                           ProvRootSetId *out_result, bool *out_truncated) {
    if (!registry->union_cache_capacity)
        return false;
    size_t mask = registry->union_cache_capacity - 1;
    size_t slot = (size_t)prov_mix64(key) & mask;
    for (size_t probe = 0; probe < registry->union_cache_capacity; probe++) {
        ProvUnionCacheEntry *entry = &registry->union_cache[slot];
        if (!entry->used)
            return false;
        if (entry->key == key) {
            if (out_result)
                *out_result = entry->result;
            if (out_truncated)
                *out_truncated = entry->truncated;
            return true;
        }
        slot = (slot + 1) & mask;
    }
    return false;
}

static void prov_union_cache_insert_locked(ProvRegistry *registry, uint64_t key,
                                           ProvRootSetId result, bool truncated) {
    if (prov_should_grow(registry->union_cache_count + 1, registry->union_cache_capacity)) {
        size_t capacity = registry->union_cache_capacity ? registry->union_cache_capacity * 2
                                                         : PROV_INITIAL_BUCKET_COUNT;
        if (capacity < registry->union_cache_capacity ||
            !prov_union_cache_rehash_locked(registry, capacity)) {
            return;
        }
    }
    size_t mask = registry->union_cache_capacity - 1;
    size_t slot = (size_t)prov_mix64(key) & mask;
    while (registry->union_cache[slot].used) {
        if (registry->union_cache[slot].key == key)
            return;
        slot = (slot + 1) & mask;
    }
    registry->union_cache[slot].key = key;
    registry->union_cache[slot].result = result;
    registry->union_cache[slot].truncated = truncated;
    registry->union_cache[slot].used = true;
    registry->union_cache_count++;
}

static const ProvRootSetRecord *prov_root_set_record_locked(const ProvRegistry *registry,
                                                            ProvRootSetId set_id) {
    if (set_id == PROV_ROOT_SET_EMPTY || set_id > registry->root_set_count) {
        return NULL;
    }
    return &registry->root_sets[set_id - 1];
}

static ProvRootSetId prov_root_set_union_locked(ProvRegistry *registry, ProvRootSetId left,
                                                ProvRootSetId right, bool *out_truncated) {
    if (out_truncated)
        *out_truncated = false;
    if (!prov_root_set_id_valid_locked(registry, left) ||
        !prov_root_set_id_valid_locked(registry, right)) {
        return PROV_ROOT_SET_ID_INVALID;
    }
    registry->union_requests++;
    if (left == PROV_ROOT_SET_EMPTY)
        return right;
    if (right == PROV_ROOT_SET_EMPTY || left == right)
        return left;

    ProvRootSetId first = left < right ? left : right;
    ProvRootSetId second = left < right ? right : left;
    uint64_t cache_key = ((uint64_t)first << 32) | second;
    ProvRootSetId cached = PROV_ROOT_SET_EMPTY;
    bool cached_truncated = false;
    if (prov_union_cache_lookup_locked(registry, cache_key, &cached, &cached_truncated)) {
        registry->union_cache_hits++;
        if (out_truncated)
            *out_truncated = cached_truncated;
        return cached;
    }

    const ProvRootSetRecord *left_record = prov_root_set_record_locked(registry, left);
    const ProvRootSetRecord *right_record = prov_root_set_record_locked(registry, right);
    if (!left_record || !right_record)
        return PROV_ROOT_SET_ID_INVALID;
    uint32_t limit = registry->max_roots_per_set;
    ProvRootId *merged = malloc((size_t)limit * sizeof(*merged));
    if (!merged)
        return PROV_ROOT_SET_ID_INVALID;
    uint32_t left_index = 0;
    uint32_t right_index = 0;
    uint64_t unique_count = 0;
    uint32_t stored_count = 0;

    while (left_index < left_record->count || right_index < right_record->count) {
        ProvRootId value;
        if (right_index >= right_record->count ||
            (left_index < left_record->count &&
             left_record->roots[left_index] < right_record->roots[right_index])) {
            value = left_record->roots[left_index++];
        } else if (left_index >= left_record->count ||
                   right_record->roots[right_index] < left_record->roots[left_index]) {
            value = right_record->roots[right_index++];
        } else {
            value = left_record->roots[left_index];
            left_index++;
            right_index++;
        }
        if (stored_count < limit)
            merged[stored_count++] = value;
        unique_count++;
    }

    bool truncated = unique_count > limit;
    if (truncated)
        registry->root_set_truncations++;
    ProvRootSetId result = prov_root_set_intern_sorted_locked(registry, merged, stored_count);
    free(merged);
    if (result != PROV_ROOT_SET_ID_INVALID) {
        prov_union_cache_insert_locked(registry, cache_key, result, truncated);
    }
    if (out_truncated)
        *out_truncated = truncated;
    return result;
}

static pthread_mutex_t prov_instance_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t prov_last_instance;

uint64_t prov_registry_instance(const ProvRegistry *registry) {
    return registry ? registry->instance : 0;
}

ProvRegistry *prov_registry_create(const ProvRegistryConfig *config) {
    uint32_t max_roots = config && config->max_roots_per_set ? config->max_roots_per_set
                                                             : PROV_DEFAULT_MAX_ROOTS_PER_SET;
    if (max_roots == UINT32_MAX)
        return NULL;

    ProvRegistry *registry = calloc(1, sizeof(*registry));
    if (!registry)
        return NULL;
    pthread_mutex_lock(&prov_instance_lock);
    if (prov_last_instance != UINT64_MAX)
        registry->instance = ++prov_last_instance;
    pthread_mutex_unlock(&prov_instance_lock);
    if (!registry->instance) {
        free(registry);
        return NULL;
    }
    if (pthread_mutex_init(&registry->lock, NULL) != 0) {
        free(registry);
        return NULL;
    }
    registry->max_roots_per_set = max_roots;

    if (!prov_resource_rehash_locked(registry, PROV_INITIAL_BUCKET_COUNT) ||
        !prov_root_rehash_locked(registry, PROV_INITIAL_BUCKET_COUNT) ||
        !prov_root_set_rehash_locked(registry, PROV_INITIAL_BUCKET_COUNT) ||
        !prov_label_rehash_locked(registry, PROV_INITIAL_BUCKET_COUNT) ||
        !prov_union_cache_rehash_locked(registry, PROV_INITIAL_BUCKET_COUNT)) {
        prov_registry_destroy(registry);
        return NULL;
    }

    ProvLabelView clean = {.data_roots = PROV_ROOT_SET_EMPTY,
                           .address_roots = PROV_ROOT_SET_EMPTY,
                           .complete_mask = PROV_COMPLETE_ALL,
                           .incomplete_reasons = PROV_INCOMPLETE_NONE};
    if (prov_label_intern_locked(registry, &clean) != PROV_LABEL_CLEAN) {
        prov_registry_destroy(registry);
        return NULL;
    }
    ProvLabelView unknown = {.data_roots = PROV_ROOT_SET_EMPTY,
                             .address_roots = PROV_ROOT_SET_EMPTY,
                             .complete_mask = PROV_COMPLETE_NONE,
                             .incomplete_reasons = PROV_INCOMPLETE_UNKNOWN};
    registry->unknown_label = prov_label_intern_locked(registry, &unknown);
    if (registry->unknown_label != PROV_LABEL_UNKNOWN) {
        prov_registry_destroy(registry);
        return NULL;
    }
    return registry;
}

void prov_registry_destroy(ProvRegistry *registry) {
    if (!registry)
        return;
    pthread_mutex_lock(&registry->lock);
    for (size_t index = 0; index < registry->resource_count; index++) {
        free(registry->resources[index].display_name);
    }
    for (size_t index = 0; index < registry->root_set_count; index++) {
        free(registry->root_sets[index].roots);
    }
    free(registry->resources);
    free(registry->resource_buckets);
    free(registry->roots);
    free(registry->root_buckets);
    free(registry->root_sets);
    free(registry->root_set_buckets);
    free(registry->labels);
    free(registry->label_buckets);
    free(registry->union_cache);
    pthread_mutex_unlock(&registry->lock);
    pthread_mutex_destroy(&registry->lock);
    free(registry);
}

void prov_registry_get_stats(ProvRegistry *registry, ProvRegistryStats *out_stats) {
    if (!registry || !out_stats)
        return;
    pthread_mutex_lock(&registry->lock);
    out_stats->resource_count = (uint32_t)registry->resource_count;
    out_stats->root_count = (uint32_t)registry->root_count;
    out_stats->root_set_count = (uint32_t)registry->root_set_count;
    out_stats->label_count = (uint32_t)registry->label_count;
    out_stats->root_set_union_requests = registry->union_requests;
    out_stats->root_set_union_cache_hits = registry->union_cache_hits;
    out_stats->root_set_truncations = registry->root_set_truncations;
    pthread_mutex_unlock(&registry->lock);
}

ProvResourceId prov_resource_intern(ProvRegistry *registry, const ProvResourceKey *key,
                                    const char *display_name, uint32_t roles) {
    if (!registry || !key || key->kind == PROV_RESOURCE_INVALID) {
        return PROV_RESOURCE_ID_INVALID;
    }
    pthread_mutex_lock(&registry->lock);
    uint64_t hash = prov_resource_key_hash(key);
    ProvResourceId existing = prov_resource_find_locked(registry, key, hash);
    if (existing != PROV_RESOURCE_ID_INVALID) {
        ProvResourceRecord *record = &registry->resources[existing - 1];
        record->roles |= roles;
        if (!record->display_name && display_name) {
            record->display_name = prov_strdup(display_name);
        }
        pthread_mutex_unlock(&registry->lock);
        return existing;
    }
    if (registry->resource_count >= UINT32_MAX) {
        pthread_mutex_unlock(&registry->lock);
        return PROV_RESOURCE_ID_INVALID;
    }
    if (prov_should_grow(registry->resource_count + 1, registry->resource_bucket_count)) {
        size_t capacity = registry->resource_bucket_count * 2;
        if (capacity < registry->resource_bucket_count ||
            !prov_resource_rehash_locked(registry, capacity)) {
            pthread_mutex_unlock(&registry->lock);
            return PROV_RESOURCE_ID_INVALID;
        }
    }
    if (!prov_grow_array((void **)&registry->resources, sizeof(*registry->resources),
                         &registry->resource_capacity, registry->resource_count + 1)) {
        pthread_mutex_unlock(&registry->lock);
        return PROV_RESOURCE_ID_INVALID;
    }
    char *name_copy = display_name ? prov_strdup(display_name) : NULL;
    if (display_name && !name_copy) {
        pthread_mutex_unlock(&registry->lock);
        return PROV_RESOURCE_ID_INVALID;
    }

    ProvResourceId id = (ProvResourceId)(registry->resource_count + 1);
    ProvResourceRecord *record = &registry->resources[registry->resource_count++];
    record->key = *key;
    record->roles = roles;
    record->display_name = name_copy;
    size_t mask = registry->resource_bucket_count - 1;
    size_t slot = (size_t)hash & mask;
    while (registry->resource_buckets[slot] != 0)
        slot = (slot + 1) & mask;
    registry->resource_buckets[slot] = id;
    pthread_mutex_unlock(&registry->lock);
    return id;
}

bool prov_resource_get(ProvRegistry *registry, ProvResourceId resource_id,
                       ProvResourceView *out_resource) {
    if (!registry || !out_resource || resource_id == PROV_RESOURCE_ID_INVALID) {
        return false;
    }
    pthread_mutex_lock(&registry->lock);
    if (resource_id > registry->resource_count) {
        pthread_mutex_unlock(&registry->lock);
        return false;
    }
    ProvResourceRecord *record = &registry->resources[resource_id - 1];
    out_resource->key = record->key;
    out_resource->roles = record->roles;
    out_resource->display_name = record->display_name;
    pthread_mutex_unlock(&registry->lock);
    return true;
}

ProvRootId prov_root_intern(ProvRegistry *registry, const ProvRootKey *key) {
    if (!registry || !key || key->kind == PROV_ROOT_INVALID) {
        return PROV_ROOT_ID_INVALID;
    }
    pthread_mutex_lock(&registry->lock);
    if (key->kind == PROV_ROOT_RESOURCE_BYTE &&
        (key->source_id == PROV_RESOURCE_ID_INVALID || key->source_id > registry->resource_count)) {
        pthread_mutex_unlock(&registry->lock);
        return PROV_ROOT_ID_INVALID;
    }
    uint64_t hash = prov_root_key_hash(key);
    ProvRootId existing = prov_root_find_locked(registry, key, hash);
    if (existing != PROV_ROOT_ID_INVALID) {
        pthread_mutex_unlock(&registry->lock);
        return existing;
    }
    if (registry->root_count >= UINT32_MAX) {
        pthread_mutex_unlock(&registry->lock);
        return PROV_ROOT_ID_INVALID;
    }
    if (prov_should_grow(registry->root_count + 1, registry->root_bucket_count)) {
        size_t capacity = registry->root_bucket_count * 2;
        if (capacity < registry->root_bucket_count ||
            !prov_root_rehash_locked(registry, capacity)) {
            pthread_mutex_unlock(&registry->lock);
            return PROV_ROOT_ID_INVALID;
        }
    }
    if (!prov_grow_array((void **)&registry->roots, sizeof(*registry->roots),
                         &registry->root_capacity, registry->root_count + 1)) {
        pthread_mutex_unlock(&registry->lock);
        return PROV_ROOT_ID_INVALID;
    }
    ProvRootId id = (ProvRootId)(registry->root_count + 1);
    registry->roots[registry->root_count++].key = *key;
    size_t mask = registry->root_bucket_count - 1;
    size_t slot = (size_t)hash & mask;
    while (registry->root_buckets[slot] != 0)
        slot = (slot + 1) & mask;
    registry->root_buckets[slot] = id;
    pthread_mutex_unlock(&registry->lock);
    return id;
}

bool prov_root_get(ProvRegistry *registry, ProvRootId root_id, ProvRootKey *out_key) {
    if (!registry || !out_key || root_id == PROV_ROOT_ID_INVALID)
        return false;
    pthread_mutex_lock(&registry->lock);
    if (root_id > registry->root_count) {
        pthread_mutex_unlock(&registry->lock);
        return false;
    }
    *out_key = registry->roots[root_id - 1].key;
    pthread_mutex_unlock(&registry->lock);
    return true;
}

static int prov_root_id_compare(const void *left, const void *right) {
    ProvRootId a = *(const ProvRootId *)left;
    ProvRootId b = *(const ProvRootId *)right;
    return (a > b) - (a < b);
}

ProvRootSetId prov_root_set_singleton(ProvRegistry *registry, ProvRootId root_id) {
    if (!registry || root_id == PROV_ROOT_ID_INVALID)
        return PROV_ROOT_SET_ID_INVALID;
    pthread_mutex_lock(&registry->lock);
    ProvRootSetId result = PROV_ROOT_SET_ID_INVALID;
    if (root_id <= registry->root_count) {
        result = prov_root_set_intern_sorted_locked(registry, &root_id, 1);
    }
    pthread_mutex_unlock(&registry->lock);
    return result;
}

ProvRootSetId prov_root_set_intern(ProvRegistry *registry, const ProvRootId *roots, uint32_t count,
                                   bool *out_truncated) {
    if (out_truncated)
        *out_truncated = false;
    if (!registry || (count != 0 && !roots))
        return PROV_ROOT_SET_ID_INVALID;
    if (count == 0)
        return PROV_ROOT_SET_EMPTY;
    size_t allocation_size = 0;
    if (!prov_size_multiply(count, sizeof(*roots), &allocation_size)) {
        return PROV_ROOT_SET_ID_INVALID;
    }

    ProvRootId *copy = malloc(allocation_size);
    if (!copy)
        return PROV_ROOT_SET_ID_INVALID;
    memcpy(copy, roots, allocation_size);
    qsort(copy, count, sizeof(*copy), prov_root_id_compare);

    pthread_mutex_lock(&registry->lock);
    for (uint32_t index = 0; index < count; index++) {
        if (copy[index] == PROV_ROOT_ID_INVALID || copy[index] > registry->root_count) {
            pthread_mutex_unlock(&registry->lock);
            free(copy);
            return PROV_ROOT_SET_ID_INVALID;
        }
    }
    uint32_t unique_count = 0;
    for (uint32_t index = 0; index < count; index++) {
        if (unique_count == 0 || copy[index] != copy[unique_count - 1]) {
            copy[unique_count++] = copy[index];
        }
    }
    bool truncated = unique_count > registry->max_roots_per_set;
    uint32_t stored_count = truncated ? registry->max_roots_per_set : unique_count;
    if (truncated)
        registry->root_set_truncations++;
    ProvRootSetId result = prov_root_set_intern_sorted_locked(registry, copy, stored_count);
    pthread_mutex_unlock(&registry->lock);
    free(copy);
    if (out_truncated)
        *out_truncated = truncated;
    return result;
}

ProvRootSetId prov_root_set_union(ProvRegistry *registry, ProvRootSetId left, ProvRootSetId right,
                                  bool *out_truncated) {
    if (out_truncated)
        *out_truncated = false;
    if (!registry)
        return PROV_ROOT_SET_ID_INVALID;
    pthread_mutex_lock(&registry->lock);
    ProvRootSetId result = prov_root_set_union_locked(registry, left, right, out_truncated);
    pthread_mutex_unlock(&registry->lock);
    return result;
}

bool prov_root_set_get(ProvRegistry *registry, ProvRootSetId set_id, ProvRootSetView *out_set) {
    if (!registry || !out_set)
        return false;
    pthread_mutex_lock(&registry->lock);
    if (!prov_root_set_id_valid_locked(registry, set_id)) {
        pthread_mutex_unlock(&registry->lock);
        return false;
    }
    if (set_id == PROV_ROOT_SET_EMPTY) {
        out_set->roots = NULL;
        out_set->count = 0;
    } else {
        ProvRootSetRecord *record = &registry->root_sets[set_id - 1];
        out_set->roots = record->roots;
        out_set->count = record->count;
    }
    pthread_mutex_unlock(&registry->lock);
    return true;
}

bool prov_root_set_contains(ProvRegistry *registry, ProvRootSetId set_id, ProvRootId root_id) {
    if (!registry || root_id == PROV_ROOT_ID_INVALID)
        return false;
    pthread_mutex_lock(&registry->lock);
    const ProvRootSetRecord *record = prov_root_set_record_locked(registry, set_id);
    bool found = false;
    if (record) {
        uint32_t low = 0;
        uint32_t high = record->count;
        while (low < high) {
            uint32_t middle = low + (high - low) / 2;
            if (record->roots[middle] < root_id)
                low = middle + 1;
            else
                high = middle;
        }
        found = low < record->count && record->roots[low] == root_id;
    }
    pthread_mutex_unlock(&registry->lock);
    return found;
}

bool prov_root_sets_intersect(ProvRegistry *registry, ProvRootSetId left, ProvRootSetId right) {
    if (!registry)
        return false;
    pthread_mutex_lock(&registry->lock);
    const ProvRootSetRecord *a = prov_root_set_record_locked(registry, left);
    const ProvRootSetRecord *b = prov_root_set_record_locked(registry, right);
    bool intersects = false;
    if (a && b) {
        uint32_t ai = 0;
        uint32_t bi = 0;
        while (ai < a->count && bi < b->count) {
            if (a->roots[ai] < b->roots[bi])
                ai++;
            else if (b->roots[bi] < a->roots[ai])
                bi++;
            else {
                intersects = true;
                break;
            }
        }
    }
    pthread_mutex_unlock(&registry->lock);
    return intersects;
}

ProvLabelId prov_label_unknown(ProvRegistry *registry) {
    if (!registry)
        return PROV_LABEL_ID_INVALID;
    pthread_mutex_lock(&registry->lock);
    ProvLabelId result = registry->unknown_label;
    pthread_mutex_unlock(&registry->lock);
    return result;
}

ProvLabelId prov_label_intern(ProvRegistry *registry, const ProvLabelView *label) {
    if (!registry || !label)
        return PROV_LABEL_ID_INVALID;
    pthread_mutex_lock(&registry->lock);
    ProvLabelId result = prov_label_intern_locked(registry, label);
    pthread_mutex_unlock(&registry->lock);
    return result;
}

ProvLabelId prov_label_from_root(ProvRegistry *registry, ProvRootId root_id, ProvChannel channel) {
    if (!registry || root_id == PROV_ROOT_ID_INVALID ||
        (channel != PROV_CHANNEL_DATA && channel != PROV_CHANNEL_ADDRESS)) {
        return PROV_LABEL_ID_INVALID;
    }
    pthread_mutex_lock(&registry->lock);
    if (root_id > registry->root_count) {
        pthread_mutex_unlock(&registry->lock);
        return PROV_LABEL_ID_INVALID;
    }
    ProvRootSetId singleton = prov_root_set_intern_sorted_locked(registry, &root_id, 1);
    if (singleton == PROV_ROOT_SET_ID_INVALID) {
        pthread_mutex_unlock(&registry->lock);
        return PROV_LABEL_ID_INVALID;
    }
    ProvLabelView label = {
        .data_roots = channel == PROV_CHANNEL_DATA ? singleton : PROV_ROOT_SET_EMPTY,
        .address_roots = channel == PROV_CHANNEL_ADDRESS ? singleton : PROV_ROOT_SET_EMPTY,
        .complete_mask = PROV_COMPLETE_ALL,
        .incomplete_reasons = PROV_INCOMPLETE_NONE};
    ProvLabelId result = prov_label_intern_locked(registry, &label);
    pthread_mutex_unlock(&registry->lock);
    return result;
}

static ProvLabelId prov_label_join_locked(ProvRegistry *registry, ProvLabelId left,
                                          ProvLabelId right) {
    if (!prov_label_id_valid_locked(registry, left) ||
        !prov_label_id_valid_locked(registry, right)) {
        return PROV_LABEL_ID_INVALID;
    }
    if (left == right)
        return left;
    ProvLabelView a = registry->labels[left].view;
    ProvLabelView b = registry->labels[right].view;
    bool data_truncated = false;
    bool address_truncated = false;
    ProvLabelView joined = {.data_roots = prov_root_set_union_locked(registry, a.data_roots,
                                                                     b.data_roots, &data_truncated),
                            .address_roots = prov_root_set_union_locked(
                                registry, a.address_roots, b.address_roots, &address_truncated),
                            .complete_mask = (uint8_t)(a.complete_mask & b.complete_mask),
                            .incomplete_reasons = a.incomplete_reasons | b.incomplete_reasons};
    if (data_truncated) {
        joined.complete_mask &= (uint8_t)~PROV_COMPLETE_DATA;
        joined.incomplete_reasons |= PROV_INCOMPLETE_ROOT_SET_BUDGET;
    }
    if (address_truncated) {
        joined.complete_mask &= (uint8_t)~PROV_COMPLETE_ADDRESS;
        joined.incomplete_reasons |= PROV_INCOMPLETE_ROOT_SET_BUDGET;
    }
    return prov_label_intern_locked(registry, &joined);
}

ProvLabelId prov_label_join(ProvRegistry *registry, ProvLabelId left, ProvLabelId right) {
    if (!registry)
        return PROV_LABEL_ID_INVALID;
    pthread_mutex_lock(&registry->lock);
    ProvLabelId result = prov_label_join_locked(registry, left, right);
    pthread_mutex_unlock(&registry->lock);
    return result;
}

ProvLabelId prov_label_join_many(ProvRegistry *registry, const ProvLabelId *labels,
                                 uint32_t count) {
    if (!registry || (count != 0 && !labels))
        return PROV_LABEL_ID_INVALID;
    pthread_mutex_lock(&registry->lock);
    ProvLabelId result = PROV_LABEL_CLEAN;
    for (uint32_t index = 0; index < count; index++) {
        result = prov_label_join_locked(registry, result, labels[index]);
        if (result == PROV_LABEL_ID_INVALID)
            break;
    }
    pthread_mutex_unlock(&registry->lock);
    return result;
}

ProvLabelId prov_label_as_address_dependency(ProvRegistry *registry, ProvLabelId label_id) {
    if (!registry)
        return PROV_LABEL_ID_INVALID;
    pthread_mutex_lock(&registry->lock);
    if (!prov_label_id_valid_locked(registry, label_id)) {
        pthread_mutex_unlock(&registry->lock);
        return PROV_LABEL_ID_INVALID;
    }

    ProvLabelView source = registry->labels[label_id].view;
    bool truncated = false;
    ProvRootSetId address_roots =
        prov_root_set_union_locked(registry, source.data_roots, source.address_roots, &truncated);
    if (address_roots == PROV_ROOT_SET_ID_INVALID) {
        pthread_mutex_unlock(&registry->lock);
        return PROV_LABEL_ID_INVALID;
    }

    bool source_complete = (source.complete_mask & PROV_COMPLETE_ALL) == PROV_COMPLETE_ALL;
    ProvLabelView projected = {.data_roots = PROV_ROOT_SET_EMPTY,
                               .address_roots = address_roots,
                               .complete_mask = PROV_COMPLETE_DATA,
                               .incomplete_reasons = source.incomplete_reasons};
    if (source_complete && !truncated) {
        projected.complete_mask |= PROV_COMPLETE_ADDRESS;
    }
    if (truncated) {
        projected.incomplete_reasons |= PROV_INCOMPLETE_ROOT_SET_BUDGET;
    }
    ProvLabelId result = prov_label_intern_locked(registry, &projected);
    pthread_mutex_unlock(&registry->lock);
    return result;
}

ProvLabelId prov_label_mark_incomplete(ProvRegistry *registry, ProvLabelId label_id,
                                       uint8_t incomplete_channels, uint64_t reasons) {
    if (!registry)
        return PROV_LABEL_ID_INVALID;
    incomplete_channels &= PROV_COMPLETE_ALL;
    if (incomplete_channels == 0)
        return label_id;
    pthread_mutex_lock(&registry->lock);
    if (!prov_label_id_valid_locked(registry, label_id)) {
        pthread_mutex_unlock(&registry->lock);
        return PROV_LABEL_ID_INVALID;
    }
    ProvLabelView label = registry->labels[label_id].view;
    label.complete_mask &= (uint8_t)~incomplete_channels;
    label.incomplete_reasons |= reasons ? reasons : PROV_INCOMPLETE_UNKNOWN;
    ProvLabelId result = prov_label_intern_locked(registry, &label);
    pthread_mutex_unlock(&registry->lock);
    return result;
}

bool prov_label_get(ProvRegistry *registry, ProvLabelId label_id, ProvLabelView *out_label) {
    if (!registry || !out_label)
        return false;
    pthread_mutex_lock(&registry->lock);
    if (!prov_label_id_valid_locked(registry, label_id)) {
        pthread_mutex_unlock(&registry->lock);
        return false;
    }
    *out_label = registry->labels[label_id].view;
    pthread_mutex_unlock(&registry->lock);
    return true;
}

bool prov_label_is_valid(ProvRegistry *registry, ProvLabelId label_id) {
    if (!registry)
        return false;
    pthread_mutex_lock(&registry->lock);
    bool valid = prov_label_id_valid_locked(registry, label_id);
    pthread_mutex_unlock(&registry->lock);
    return valid;
}

bool prov_label_has_known_roots(ProvRegistry *registry, ProvLabelId label_id) {
    ProvLabelView label;
    return prov_label_get(registry, label_id, &label) &&
           (label.data_roots != PROV_ROOT_SET_EMPTY || label.address_roots != PROV_ROOT_SET_EMPTY);
}

bool prov_label_channel_may_be_tainted(ProvRegistry *registry, ProvLabelId label_id,
                                       ProvChannel channel) {
    if (channel != PROV_CHANNEL_DATA && channel != PROV_CHANNEL_ADDRESS) {
        return false;
    }
    ProvLabelView label;
    if (!prov_label_get(registry, label_id, &label))
        return false;
    if (channel == PROV_CHANNEL_DATA) {
        return label.data_roots != PROV_ROOT_SET_EMPTY ||
               (label.complete_mask & PROV_COMPLETE_DATA) == 0;
    }
    return label.address_roots != PROV_ROOT_SET_EMPTY ||
           (label.complete_mask & PROV_COMPLETE_ADDRESS) == 0;
}

bool prov_label_may_be_tainted(ProvRegistry *registry, ProvLabelId label_id) {
    ProvLabelView label;
    return prov_label_get(registry, label_id, &label) &&
           (label.data_roots != PROV_ROOT_SET_EMPTY || label.address_roots != PROV_ROOT_SET_EMPTY ||
            label.complete_mask != PROV_COMPLETE_ALL);
}

bool prov_label_is_complete(ProvRegistry *registry, ProvLabelId label_id, uint8_t channels) {
    channels &= PROV_COMPLETE_ALL;
    if (channels == 0)
        return true;
    ProvLabelView label;
    return prov_label_get(registry, label_id, &label) &&
           (label.complete_mask & channels) == channels;
}

static uint64_t prov_fd_hash(int32_t fd) {
    return prov_mix64((uint32_t)fd);
}

static size_t prov_fd_find_slot_locked(const ProvFdTable *table, int32_t fd, bool *out_found) {
    if (!table->slot_capacity) {
        if (out_found)
            *out_found = false;
        return SIZE_MAX;
    }
    size_t mask = table->slot_capacity - 1;
    size_t slot = (size_t)prov_fd_hash(fd) & mask;
    size_t first_tombstone = SIZE_MAX;
    for (size_t probe = 0; probe < table->slot_capacity; probe++) {
        const ProvFdSlot *entry = &table->slots[slot];
        if (entry->state == PROV_FD_SLOT_EMPTY) {
            if (out_found)
                *out_found = false;
            return first_tombstone != SIZE_MAX ? first_tombstone : slot;
        }
        if (entry->state == PROV_FD_SLOT_OCCUPIED && entry->fd == fd) {
            if (out_found)
                *out_found = true;
            return slot;
        }
        if (entry->state == PROV_FD_SLOT_TOMBSTONE && first_tombstone == SIZE_MAX) {
            first_tombstone = slot;
        }
        slot = (slot + 1) & mask;
    }
    if (out_found)
        *out_found = false;
    return first_tombstone;
}

static bool prov_fd_rehash_locked(ProvFdTable *table, size_t capacity) {
    ProvFdSlot *old_slots = table->slots;
    size_t old_capacity = table->slot_capacity;
    ProvFdSlot *slots = calloc(capacity, sizeof(*slots));
    if (!slots)
        return false;
    table->slots = slots;
    table->slot_capacity = capacity;
    table->binding_count = 0;
    table->tombstone_count = 0;
    for (size_t index = 0; index < old_capacity; index++) {
        if (old_slots[index].state != PROV_FD_SLOT_OCCUPIED)
            continue;
        bool found = false;
        size_t slot = prov_fd_find_slot_locked(table, old_slots[index].fd, &found);
        (void)found;
        table->slots[slot] = old_slots[index];
        table->binding_count++;
    }
    free(old_slots);
    return true;
}

static bool prov_fd_ensure_capacity_locked(ProvFdTable *table) {
    size_t entries = table->binding_count + table->tombstone_count + 1;
    if (!prov_should_grow(entries, table->slot_capacity))
        return true;
    size_t capacity = table->slot_capacity ? table->slot_capacity * 2 : PROV_INITIAL_BUCKET_COUNT;
    if (capacity < table->slot_capacity)
        return false;
    return prov_fd_rehash_locked(table, capacity);
}

static bool prov_fd_close_slot_locked(ProvFdTable *table, size_t slot) {
    ProvFdSlot *binding = &table->slots[slot];
    if (binding->state != PROV_FD_SLOT_OCCUPIED || binding->ofd_id == PROV_OFD_ID_INVALID ||
        binding->ofd_id > table->ofd_count) {
        return false;
    }
    ProvOpenFileDescriptionRecord *ofd = &table->ofds[binding->ofd_id - 1];
    if (ofd->reference_count > 0)
        ofd->reference_count--;
    if (ofd->reference_count == 0)
        ofd->active = false;
    binding->state = PROV_FD_SLOT_TOMBSTONE;
    binding->ofd_id = PROV_OFD_ID_INVALID;
    table->binding_count--;
    table->tombstone_count++;
    return true;
}

static bool prov_fd_insert_binding_locked(ProvFdTable *table, int32_t fd,
                                          ProvOpenFileDescriptionId ofd_id) {
    bool found = false;
    size_t slot = prov_fd_find_slot_locked(table, fd, &found);
    if (found || slot == SIZE_MAX)
        return false;
    if (table->slots[slot].state == PROV_FD_SLOT_TOMBSTONE) {
        table->tombstone_count--;
    }
    table->slots[slot].fd = fd;
    table->slots[slot].ofd_id = ofd_id;
    table->slots[slot].state = PROV_FD_SLOT_OCCUPIED;
    table->binding_count++;
    return true;
}

ProvFdTable *prov_fd_table_create(ProvRegistry *registry) {
    if (!registry)
        return NULL;
    ProvFdTable *table = calloc(1, sizeof(*table));
    if (!table)
        return NULL;
    if (pthread_mutex_init(&table->lock, NULL) != 0) {
        free(table);
        return NULL;
    }
    table->registry = registry;
    if (!prov_fd_rehash_locked(table, PROV_INITIAL_BUCKET_COUNT)) {
        pthread_mutex_destroy(&table->lock);
        free(table);
        return NULL;
    }
    return table;
}

void prov_fd_table_destroy(ProvFdTable *table) {
    if (!table)
        return;
    pthread_mutex_lock(&table->lock);
    free(table->ofds);
    free(table->slots);
    pthread_mutex_unlock(&table->lock);
    pthread_mutex_destroy(&table->lock);
    free(table);
}

bool prov_fd_table_bind_new(ProvFdTable *table, int32_t fd, ProvResourceId resource_id,
                            uint64_t initial_offset, uint32_t flags,
                            ProvOpenFileDescriptionId *out_ofd_id) {
    if (out_ofd_id)
        *out_ofd_id = PROV_OFD_ID_INVALID;
    if (!table || fd < 0 || resource_id == PROV_RESOURCE_ID_INVALID)
        return false;
    ProvResourceView resource;
    if (!prov_resource_get(table->registry, resource_id, &resource))
        return false;
    (void)resource;

    pthread_mutex_lock(&table->lock);
    if (table->ofd_count >= UINT32_MAX || !prov_fd_ensure_capacity_locked(table) ||
        !prov_grow_array((void **)&table->ofds, sizeof(*table->ofds), &table->ofd_capacity,
                         table->ofd_count + 1)) {
        pthread_mutex_unlock(&table->lock);
        return false;
    }
    bool found = false;
    size_t existing_slot = prov_fd_find_slot_locked(table, fd, &found);
    if (found)
        (void)prov_fd_close_slot_locked(table, existing_slot);

    ProvOpenFileDescriptionId ofd_id = (ProvOpenFileDescriptionId)(table->ofd_count + 1);
    ProvOpenFileDescriptionRecord *ofd = &table->ofds[table->ofd_count++];
    ofd->resource_id = resource_id;
    ofd->current_offset = initial_offset;
    ofd->flags = flags;
    ofd->reference_count = 1;
    ofd->active = true;
    if (!prov_fd_insert_binding_locked(table, fd, ofd_id)) {
        ofd->reference_count = 0;
        ofd->active = false;
        pthread_mutex_unlock(&table->lock);
        return false;
    }
    if (out_ofd_id)
        *out_ofd_id = ofd_id;
    pthread_mutex_unlock(&table->lock);
    return true;
}

bool prov_fd_table_dup(ProvFdTable *table, int32_t old_fd, int32_t new_fd,
                       ProvOpenFileDescriptionId *out_ofd_id) {
    if (out_ofd_id)
        *out_ofd_id = PROV_OFD_ID_INVALID;
    if (!table || old_fd < 0 || new_fd < 0)
        return false;
    pthread_mutex_lock(&table->lock);
    bool old_found = false;
    size_t old_slot = prov_fd_find_slot_locked(table, old_fd, &old_found);
    if (!old_found) {
        pthread_mutex_unlock(&table->lock);
        return false;
    }
    ProvOpenFileDescriptionId ofd_id = table->slots[old_slot].ofd_id;
    if (old_fd == new_fd) {
        if (out_ofd_id)
            *out_ofd_id = ofd_id;
        pthread_mutex_unlock(&table->lock);
        return true;
    }
    if (!prov_fd_ensure_capacity_locked(table)) {
        pthread_mutex_unlock(&table->lock);
        return false;
    }
    bool new_found = false;
    size_t new_slot = prov_fd_find_slot_locked(table, new_fd, &new_found);
    if (new_found)
        (void)prov_fd_close_slot_locked(table, new_slot);
    if (ofd_id == PROV_OFD_ID_INVALID || ofd_id > table->ofd_count) {
        pthread_mutex_unlock(&table->lock);
        return false;
    }
    ProvOpenFileDescriptionRecord *ofd = &table->ofds[ofd_id - 1];
    if (!ofd->active || ofd->reference_count == UINT32_MAX) {
        pthread_mutex_unlock(&table->lock);
        return false;
    }
    ofd->reference_count++;
    if (!prov_fd_insert_binding_locked(table, new_fd, ofd_id)) {
        ofd->reference_count--;
        pthread_mutex_unlock(&table->lock);
        return false;
    }
    if (out_ofd_id)
        *out_ofd_id = ofd_id;
    pthread_mutex_unlock(&table->lock);
    return true;
}

bool prov_fd_table_close(ProvFdTable *table, int32_t fd) {
    if (!table || fd < 0)
        return false;
    pthread_mutex_lock(&table->lock);
    bool found = false;
    size_t slot = prov_fd_find_slot_locked(table, fd, &found);
    bool result = found && prov_fd_close_slot_locked(table, slot);
    pthread_mutex_unlock(&table->lock);
    return result;
}

bool prov_fd_table_lookup(ProvFdTable *table, int32_t fd,
                          ProvOpenFileDescriptionView *out_description) {
    if (!table || !out_description || fd < 0)
        return false;
    pthread_mutex_lock(&table->lock);
    bool found = false;
    size_t slot = prov_fd_find_slot_locked(table, fd, &found);
    if (!found) {
        pthread_mutex_unlock(&table->lock);
        return false;
    }
    ProvOpenFileDescriptionId ofd_id = table->slots[slot].ofd_id;
    if (ofd_id == PROV_OFD_ID_INVALID || ofd_id > table->ofd_count) {
        pthread_mutex_unlock(&table->lock);
        return false;
    }
    ProvOpenFileDescriptionRecord *ofd = &table->ofds[ofd_id - 1];
    out_description->ofd_id = ofd_id;
    out_description->resource_id = ofd->resource_id;
    out_description->current_offset = ofd->current_offset;
    out_description->flags = ofd->flags;
    out_description->reference_count = ofd->reference_count;
    out_description->active = ofd->active;
    pthread_mutex_unlock(&table->lock);
    return true;
}

bool prov_fd_table_advance(ProvFdTable *table, int32_t fd, uint64_t byte_count) {
    if (!table || fd < 0)
        return false;
    pthread_mutex_lock(&table->lock);
    bool found = false;
    size_t slot = prov_fd_find_slot_locked(table, fd, &found);
    if (!found) {
        pthread_mutex_unlock(&table->lock);
        return false;
    }
    ProvOpenFileDescriptionId ofd_id = table->slots[slot].ofd_id;
    ProvOpenFileDescriptionRecord *ofd = &table->ofds[ofd_id - 1];
    if (!ofd->active || byte_count > UINT64_MAX - ofd->current_offset) {
        pthread_mutex_unlock(&table->lock);
        return false;
    }
    ofd->current_offset += byte_count;
    pthread_mutex_unlock(&table->lock);
    return true;
}

bool prov_fd_table_set_offset(ProvFdTable *table, int32_t fd, uint64_t offset) {
    if (!table || fd < 0)
        return false;
    pthread_mutex_lock(&table->lock);
    bool found = false;
    size_t slot = prov_fd_find_slot_locked(table, fd, &found);
    if (!found) {
        pthread_mutex_unlock(&table->lock);
        return false;
    }
    ProvOpenFileDescriptionId ofd_id = table->slots[slot].ofd_id;
    ProvOpenFileDescriptionRecord *ofd = &table->ofds[ofd_id - 1];
    if (!ofd->active) {
        pthread_mutex_unlock(&table->lock);
        return false;
    }
    ofd->current_offset = offset;
    pthread_mutex_unlock(&table->lock);
    return true;
}
