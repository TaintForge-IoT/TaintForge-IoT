#include "replay_sources.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint32_t id, index;
} Slot; /* index+1, so id zero is usable. */

typedef struct {
    void *records;
    Slot *slots;
    uint32_t count, capacity, slot_capacity;
    size_t stride;
} Table;

struct ReplaySources {
    atomic_uint references;
    Table labels, roots, resources;
    ReplaySourceLimits limits;
    ReplaySourceInfo info;
    size_t owned;
};

ReplaySourceLimits replay_source_default_limits(void) {
    return (ReplaySourceLimits){.bytes = 8U * 1024U * 1024U, .work = UINT64_C(4000000)};
}

static uint32_t hash_id(uint32_t x) {
    x ^= x >> 16;
    x *= UINT32_C(0x7feb352d);
    x ^= x >> 15;
    x *= UINT32_C(0x846ca68b);
    return x ^ (x >> 16);
}

static bool spend(ReplaySources *s, uint64_t n) {
    if (n > s->limits.work - s->info.work) {
        s->info.status = REPLAY_SOURCES_RESOURCE_LIMIT;
        return false;
    }
    s->info.work += n;
    return true;
}

static void *allocate(ReplaySources *s, size_t n) {
    if (n > s->limits.bytes - s->owned) {
        s->info.status = REPLAY_SOURCES_RESOURCE_LIMIT;
        return NULL;
    }
    void *p = calloc(1, n);
    if (!p) {
        s->info.status = REPLAY_SOURCES_OUT_OF_MEMORY;
        return NULL;
    }
    s->owned += n;
    if (s->owned > s->info.bytes)
        s->info.bytes = s->owned;
    return p;
}

static uint32_t lookup(const Table *t, uint32_t id) {
    if (!t->slot_capacity)
        return 0;
    uint32_t slot = hash_id(id) & (t->slot_capacity - 1U);
    while (t->slots[slot].index && t->slots[slot].id != id)
        slot = (slot + 1U) & (t->slot_capacity - 1U);
    return t->slots[slot].index;
}

static bool place(ReplaySources *s, Slot *slots, uint32_t cap, Slot item) {
    uint32_t slot = hash_id(item.id) & (cap - 1U);
    do {
        if (!spend(s, 1))
            return false;
        if (!slots[slot].index) {
            slots[slot] = item;
            return true;
        }
        slot = (slot + 1U) & (cap - 1U);
    } while (true);
}

static void *record(ReplaySources *s, Table *t, uint32_t id, bool *fresh) {
    *fresh = false;
    if (t->slot_capacity) {
        uint32_t slot = hash_id(id) & (t->slot_capacity - 1U);
        do {
            if (!spend(s, 1))
                return NULL;
            Slot item = t->slots[slot];
            if (!item.index)
                break;
            if (item.id == id)
                return (char *)t->records + (size_t)(item.index - 1U) * t->stride;
            slot = (slot + 1U) & (t->slot_capacity - 1U);
        } while (true);
    }
    if (t->count == t->capacity) {
        uint32_t cap = t->capacity ? t->capacity * 2U : 8U;
        if (t->capacity > UINT32_MAX / 4U || cap > SIZE_MAX / t->stride || !spend(s, t->count)) {
            s->info.status = REPLAY_SOURCES_RESOURCE_LIMIT;
            return NULL;
        }
        void *p = allocate(s, (size_t)cap * t->stride);
        if (!p)
            return NULL;
        if (t->count)
            memcpy(p, t->records, (size_t)t->count * t->stride);
        free(t->records);
        s->owned -= (size_t)t->capacity * t->stride;
        t->records = p;
        t->capacity = cap;
    }
    if (!t->slot_capacity || t->count >= t->slot_capacity / 2U) {
        uint32_t cap = t->slot_capacity ? t->slot_capacity * 2U : 16U;
        if (t->slot_capacity > UINT32_MAX / 2U || (uint64_t)cap * sizeof(Slot) > SIZE_MAX) {
            s->info.status = REPLAY_SOURCES_RESOURCE_LIMIT;
            return NULL;
        }
        Slot *p = allocate(s, (size_t)cap * sizeof(*p));
        if (!p)
            return NULL;
        for (uint32_t i = 0; i < t->slot_capacity; ++i) {
            if (!spend(s, 1) || (t->slots[i].index && !place(s, p, cap, t->slots[i]))) {
                free(p);
                s->owned -= (size_t)cap * sizeof(*p);
                return NULL;
            }
        }
        free(t->slots);
        s->owned -= (size_t)t->slot_capacity * sizeof(*p);
        t->slots = p;
        t->slot_capacity = cap;
    }
    if (!place(s, t->slots, t->slot_capacity, (Slot){id, t->count + 1U}))
        return NULL;
    void *p = (char *)t->records + (size_t)t->count++ * t->stride;
    *fresh = true;
    return p;
}

static bool import_resource(ReplaySources *s, ProvRegistry *registry, ProvResourceId id) {
    bool fresh;
    ReplaySourceResource *r = record(s, &s->resources, id, &fresh);
    if (!r)
        return false;
    if (!fresh)
        return true;
    r->id = id;
    ProvResourceView view;
    if (!spend(s, 1))
        return false;
    if (!id || !prov_resource_get(registry, id, &view) || view.key.kind <= PROV_RESOURCE_INVALID ||
        view.key.kind > PROV_RESOURCE_SYSTEM_VALUE) {
        s->info.issues |= REPLAY_SOURCE_INVALID_RESOURCE;
        return true;
    }
    r->valid = true;
    r->view = view;
    r->view.display_name = NULL;
    if (view.display_name) {
        size_t n = 0;
        do {
            if (!spend(s, 1))
                return false;
            if (n == SIZE_MAX - 1U) {
                s->info.status = REPLAY_SOURCES_RESOURCE_LIMIT;
                return false;
            }
        } while (view.display_name[n++]);
        if (!spend(s, n))
            return false;
        char *name = allocate(s, n);
        if (!name)
            return false;
        memcpy(name, view.display_name, n);
        r->view.display_name = name;
    }
    return true;
}

static bool import_root(ReplaySources *s, ProvRegistry *registry, ProvRootId id) {
    bool fresh;
    ReplaySourceRoot *r = record(s, &s->roots, id, &fresh);
    if (!r)
        return false;
    if (!fresh)
        return true;
    r->id = id;
    if (!spend(s, 1))
        return false;
    if (!id || !prov_root_get(registry, id, &r->key) || r->key.kind <= PROV_ROOT_INVALID ||
        r->key.kind > PROV_ROOT_BOUNDARY_MEMORY_BYTE) {
        s->info.issues |= REPLAY_SOURCE_INVALID_ROOT;
        return true;
    }
    r->valid = true;
    if (r->key.kind == PROV_ROOT_RESOURCE_BYTE) {
        if (!r->key.source_id || r->key.source_id > UINT32_MAX) {
            s->info.issues |= REPLAY_SOURCE_INVALID_RESOURCE;
            return true;
        }
        return import_resource(s, registry, (ProvResourceId)r->key.source_id);
    }
    return true;
}

static bool import_set(ReplaySources *s, ProvRegistry *registry, ProvRootSetId id,
                       const ProvRootId **out, uint32_t *count) {
    ProvRootSetView set;
    if (!spend(s, 1))
        return false;
    if (!prov_root_set_get(registry, id, &set) || (set.count && !set.roots)) {
        s->info.issues |= REPLAY_SOURCE_INVALID_ROOT;
        return true;
    }
    if (!set.count)
        return true;
    if ((uint64_t)set.count * sizeof(ProvRootId) > SIZE_MAX || !spend(s, set.count)) {
        s->info.status = REPLAY_SOURCES_RESOURCE_LIMIT;
        return false;
    }
    ProvRootId *p = allocate(s, (size_t)set.count * sizeof(*p));
    if (!p)
        return false;
    *out = p;
    *count = set.count;
    memcpy(p, set.roots, (size_t)set.count * sizeof(*p));
    for (uint32_t i = 0; i < set.count; ++i)
        if (!import_root(s, registry, p[i]))
            return false;
    return true;
}

ReplaySources *replay_sources_capture(ProvRegistry *registry, const ProvLabelId *labels,
                                      uint32_t count, const ReplaySourceLimits *limits,
                                      ReplaySourceInfo *info) {
    ReplaySourceInfo result = {.status = REPLAY_SOURCES_INVALID};
    if (info)
        *info = result;
    if (!registry || (count && !labels))
        return NULL;
    ReplaySourceLimits bound = limits ? *limits : replay_source_default_limits();
    if (bound.bytes < sizeof(ReplaySources)) {
        if (info)
            info->status = REPLAY_SOURCES_RESOURCE_LIMIT;
        return NULL;
    }
    ReplaySources *s = calloc(1, sizeof(*s));
    if (!s) {
        if (info)
            info->status = REPLAY_SOURCES_OUT_OF_MEMORY;
        return NULL;
    }
    atomic_init(&s->references, 1U);
    s->limits = bound;
    s->owned = sizeof(*s);
    s->info.bytes = s->owned;
    s->labels.stride = sizeof(ReplaySourceLabel);
    s->roots.stride = sizeof(ReplaySourceRoot);
    s->resources.stride = sizeof(ReplaySourceResource);
    s->info.status = REPLAY_SOURCES_READY;
    s->info.registry_instance = prov_registry_instance(registry);
    for (uint32_t i = 0; i < count; ++i) {
        bool fresh;
        if (!spend(s, 1))
            goto fail;
        ReplaySourceLabel *label = record(s, &s->labels, labels[i], &fresh);
        if (!label)
            goto fail;
        if (!fresh)
            continue;
        label->id = labels[i];
        if (!spend(s, 1))
            goto fail;
        if (!prov_label_get(registry, label->id, &label->view)) {
            s->info.issues |= REPLAY_SOURCE_INVALID_LABEL;
            continue;
        }
        label->valid = true;
        if (label->view.complete_mask != PROV_COMPLETE_ALL || label->view.incomplete_reasons)
            s->info.issues |= REPLAY_SOURCE_INCOMPLETE;
        if (!import_set(s, registry, label->view.data_roots, &label->data, &label->data_count) ||
            !import_set(s, registry, label->view.address_roots, &label->address,
                        &label->address_count))
            goto fail;
    }
    if (s->info.issues)
        s->info.status = REPLAY_SOURCES_UNKNOWN;
    s->info.labels = s->labels.count;
    s->info.roots = s->roots.count;
    s->info.resources = s->resources.count;
    if (info)
        *info = s->info;
    return s;
fail:
    if (info)
        *info = s->info;
    replay_sources_release(s);
    return NULL;
}

ReplaySources *replay_sources_retain(const ReplaySources *s) {
    ReplaySources *p = (ReplaySources *)s;
    if (p)
        atomic_fetch_add_explicit(&p->references, 1U, memory_order_relaxed);
    return p;
}

void replay_sources_release(ReplaySources *s) {
    if (!s || atomic_fetch_sub_explicit(&s->references, 1U, memory_order_acq_rel) != 1U)
        return;
    ReplaySourceLabel *labels = s->labels.records;
    for (uint32_t i = 0; i < s->labels.count; ++i) {
        free((void *)labels[i].data);
        free((void *)labels[i].address);
    }
    ReplaySourceResource *resources = s->resources.records;
    for (uint32_t i = 0; i < s->resources.count; ++i)
        free((void *)resources[i].view.display_name);
    free(s->labels.records);
    free(s->labels.slots);
    free(s->roots.records);
    free(s->roots.slots);
    free(s->resources.records);
    free(s->resources.slots);
    free(s);
}

size_t replay_sources_bytes(const ReplaySources *s) {
    return s ? s->owned : 0;
}

ReplaySourceInfo replay_sources_info(const ReplaySources *s) {
    return s ? s->info : (ReplaySourceInfo){.status = REPLAY_SOURCES_NOT_CAPTURED};
}

const ReplaySourceLabel *replay_sources_label(const ReplaySources *s, ProvLabelId id) {
    uint32_t n = s ? lookup(&s->labels, id) : 0;
    return n ? (const ReplaySourceLabel *)s->labels.records + n - 1U : NULL;
}

const ReplaySourceRoot *replay_sources_root(const ReplaySources *s, ProvRootId id) {
    uint32_t n = s ? lookup(&s->roots, id) : 0;
    return n ? (const ReplaySourceRoot *)s->roots.records + n - 1U : NULL;
}

const ReplaySourceResource *replay_sources_resource(const ReplaySources *s, ProvResourceId id) {
    uint32_t n = s ? lookup(&s->resources, id) : 0;
    return n ? (const ReplaySourceResource *)s->resources.records + n - 1U : NULL;
}
