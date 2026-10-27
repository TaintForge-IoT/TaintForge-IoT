#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>

#include "dta.h"

#define SHADOW_INITIAL_SLOT_CAPACITY ((size_t)64)
#define SHADOW_SLOT_EMPTY ((uint8_t)0)
#define SHADOW_SLOT_OCCUPIED ((uint8_t)1)
#define SHADOW_SLOT_TOMBSTONE ((uint8_t)2)
#define SHADOW_BLOCKS_PER_PAGE (DTA_SHADOW_PAGE_SIZE / DTA_CMLB_BLOCK_SIZE)

_Static_assert(DTA_SHADOW_PAGE_SIZE % DTA_CMLB_BLOCK_SIZE == 0, "whole blocks per page");
_Static_assert(DTA_CMLB_BLOCK_SIZE <= UINT16_MAX, "block counter width");
_Static_assert((DTA_CMLB_ENTRY_COUNT & (DTA_CMLB_ENTRY_COUNT - 1)) == 0, "power of two cache");

typedef struct {
    ProvLabelId labels[DTA_SHADOW_PAGE_SIZE];
    uint32_t nonclean_count;
    uint16_t block_nonclean_count[SHADOW_BLOCKS_PER_PAGE];
} ShadowPage;

typedef struct {
    uint64_t page_index;
    ShadowPage *page;
    uint8_t state;
} ShadowPageSlot;

typedef struct {
    uint64_t block, generation;
} ShadowCmlbEntry;

struct ShadowMemory {
    uint8_t guest_bits;
    ProvRegistry *registry;
    bool owns_registry;
    pthread_mutex_t lock;
    ShadowPageSlot *slots;
    size_t slot_capacity, page_count, tombstone_count;
    ShadowCmlbEntry *cmlb;
    uint64_t cmlb_generation;
    bool knowledge_valid, stats_enabled;
    ShadowStats stats;
#ifdef TF_DTA_TESTING
    int64_t allocation_budget;
#endif
};

/* Opt-in counters saturate, so long-running diagnostics never wrap. */
#define SHADOW_COUNT(sm, field, amount)                                                            \
    do {                                                                                           \
        if ((sm)->stats_enabled) {                                                                 \
            uint64_t delta_ = (uint64_t)(amount);                                                  \
            uint64_t *counter_ = &(sm)->stats.field;                                               \
            *counter_ = UINT64_MAX - *counter_ < delta_ ? UINT64_MAX : *counter_ + delta_;         \
        }                                                                                          \
    } while (0)

static void *shadow_calloc_locked(ShadowMemory *sm, size_t count, size_t size) {
#ifdef TF_DTA_TESTING
    if (sm->allocation_budget == 0)
        return NULL;
    if (sm->allocation_budget > 0)
        sm->allocation_budget--;
#else
    (void)sm;
#endif
    return calloc(count, size);
}

static uint64_t shadow_mix64(uint64_t value) {
    value ^= value >> 30;
    value *= UINT64_C(0xbf58476d1ce4e5b9);
    value ^= value >> 27;
    value *= UINT64_C(0x94d049bb133111eb);
    value ^= value >> 31;
    return value;
}

static uint64_t shadow_normalize_addr(const ShadowMemory *sm, uint64_t addr) {
    return sm->guest_bits == 32 ? addr & UINT64_C(0xffffffff) : addr;
}

static uint64_t shadow_clamp_range(const ShadowMemory *sm, uint64_t *addr, uint64_t size) {
    *addr = shadow_normalize_addr(sm, *addr);
    if (sm->guest_bits == 32) {
        uint64_t available = (UINT64_C(1) << 32) - *addr;
        return size > available ? available : size;
    }
    if (*addr != 0) {
        uint64_t available = UINT64_MAX - *addr + UINT64_C(1);
        return size > available ? available : size;
    }
    return size;
}

static ShadowCmlbEntry *shadow_cmlb_entry(ShadowMemory *sm, uint64_t block) {
    return &sm->cmlb[shadow_mix64(block) & (DTA_CMLB_ENTRY_COUNT - 1)];
}

static void shadow_cmlb_flush_locked(ShadowMemory *sm) {
    if (!sm->cmlb)
        return;
    if (++sm->cmlb_generation == 0) {
        memset(sm->cmlb, 0, DTA_CMLB_ENTRY_COUNT * sizeof(*sm->cmlb));
        sm->cmlb_generation = 1;
    }
    SHADOW_COUNT(sm, cmlb_flushes, 1);
}

static void shadow_fail_locked(ShadowMemory *sm) {
    SHADOW_COUNT(sm, semantic_failures, 1);
    if (sm->knowledge_valid)
        shadow_cmlb_flush_locked(sm);
    sm->knowledge_valid = false;
}

/* Caller validates the range first; size is nonzero. A miss says nothing
 * about the labels. Stop at the first miss and use the bulk authoritative path. */
static bool shadow_cmlb_range_hit_locked(ShadowMemory *sm, uint64_t addr, uint64_t size) {
    if (!sm->cmlb || !sm->knowledge_valid)
        return false;
    uint64_t last = (addr + (size - 1)) / DTA_CMLB_BLOCK_SIZE;
    for (uint64_t block = addr / DTA_CMLB_BLOCK_SIZE; block <= last; block++) {
        ShadowCmlbEntry *entry = shadow_cmlb_entry(sm, block);
        SHADOW_COUNT(sm, cmlb_probes, 1);
        if (entry->generation != sm->cmlb_generation || entry->block != block) {
            SHADOW_COUNT(sm, cmlb_misses, 1);
            return false;
        }
        SHADOW_COUNT(sm, cmlb_hits, 1);
    }
    SHADOW_COUNT(sm, cmlb_full_hits, 1);
    return true;
}

static void shadow_cmlb_invalidate_locked(ShadowMemory *sm, uint64_t block) {
    if (!sm->cmlb)
        return;
    ShadowCmlbEntry *entry = shadow_cmlb_entry(sm, block);
    if (entry->generation == sm->cmlb_generation && entry->block == block) {
        entry->generation = 0;
        SHADOW_COUNT(sm, cmlb_invalidations, 1);
    }
}

/* Only whole-block counters may admit a proof, including for partial reads. */
static void shadow_cmlb_fill_locked(ShadowMemory *sm, uint64_t page_index, const ShadowPage *page,
                                    uint32_t offset, uint32_t count) {
    if (!sm->cmlb || !sm->knowledge_valid)
        return;
    uint32_t last = (offset + count - 1) / DTA_CMLB_BLOCK_SIZE;
    for (uint32_t b = offset / DTA_CMLB_BLOCK_SIZE; b <= last; b++) {
        if (page && page->block_nonclean_count[b] != 0)
            continue;
        uint64_t block = page_index * SHADOW_BLOCKS_PER_PAGE + b;
        ShadowCmlbEntry *entry = shadow_cmlb_entry(sm, block);
        if (entry->generation == sm->cmlb_generation) {
            if (entry->block == block)
                continue;
            SHADOW_COUNT(sm, cmlb_collisions, 1);
        }
        *entry = (ShadowCmlbEntry){block, sm->cmlb_generation};
        SHADOW_COUNT(sm, cmlb_fills, 1);
    }
}

static size_t shadow_find_slot_locked(ShadowMemory *sm, uint64_t page_index, bool *out_found) {
    SHADOW_COUNT(sm, hash_lookups, 1);
    size_t mask = sm->slot_capacity - 1;
    size_t slot = (size_t)shadow_mix64(page_index) & mask;
    size_t first_tombstone = SIZE_MAX;
    for (size_t probe = 0; probe < sm->slot_capacity; probe++) {
        const ShadowPageSlot *entry = &sm->slots[slot];
        SHADOW_COUNT(sm, hash_probes, 1);
        if (entry->state == SHADOW_SLOT_EMPTY) {
            if (out_found)
                *out_found = false;
            return first_tombstone != SIZE_MAX ? first_tombstone : slot;
        }
        if (entry->state == SHADOW_SLOT_OCCUPIED && entry->page_index == page_index) {
            if (out_found)
                *out_found = true;
            return slot;
        }
        if (entry->state == SHADOW_SLOT_TOMBSTONE && first_tombstone == SIZE_MAX)
            first_tombstone = slot;
        slot = (slot + 1) & mask;
    }
    if (out_found)
        *out_found = false;
    return first_tombstone;
}

static bool shadow_rehash_locked(ShadowMemory *sm, size_t capacity) {
    ShadowPageSlot *new_slots = shadow_calloc_locked(sm, capacity, sizeof(*new_slots));
    if (!new_slots)
        return false;
    ShadowPageSlot *old_slots = sm->slots;
    size_t old_capacity = sm->slot_capacity;
    sm->slots = new_slots;
    sm->slot_capacity = capacity;
    sm->page_count = 0;
    sm->tombstone_count = 0;
    for (size_t index = 0; index < old_capacity; index++) {
        if (old_slots[index].state != SHADOW_SLOT_OCCUPIED)
            continue;
        size_t slot = shadow_find_slot_locked(sm, old_slots[index].page_index, NULL);
        sm->slots[slot] = old_slots[index];
        sm->page_count++;
    }
    free(old_slots);
    return true;
}

static bool shadow_ensure_capacity_locked(ShadowMemory *sm) {
    size_t used = sm->page_count + sm->tombstone_count + 1;
    size_t threshold = (sm->slot_capacity / 10) * 7 + (sm->slot_capacity % 10) * 7 / 10;
    if (used <= threshold)
        return true;
    if (sm->slot_capacity > SIZE_MAX / 2)
        return false;
    return shadow_rehash_locked(sm, sm->slot_capacity * 2);
}

static ShadowPage *shadow_page_locked(ShadowMemory *sm, uint64_t page_index, bool create) {
    bool found = false;
    size_t slot = shadow_find_slot_locked(sm, page_index, &found);
    if (found)
        return sm->slots[slot].page;
    if (!create || !shadow_ensure_capacity_locked(sm))
        return NULL;
    slot = shadow_find_slot_locked(sm, page_index, &found);
    if (found)
        return sm->slots[slot].page;
    if (slot == SIZE_MAX)
        return NULL;
    ShadowPage *page = shadow_calloc_locked(sm, 1, sizeof(*page));
    if (!page)
        return NULL;
    if (sm->slots[slot].state == SHADOW_SLOT_TOMBSTONE)
        sm->tombstone_count--;
    sm->slots[slot] = (ShadowPageSlot){page_index, page, SHADOW_SLOT_OCCUPIED};
    sm->page_count++;
    return page;
}

static void shadow_remove_page_locked(ShadowMemory *sm, uint64_t page_index) {
    bool found = false;
    size_t slot = shadow_find_slot_locked(sm, page_index, &found);
    if (!found)
        return;
    free(sm->slots[slot].page);
    sm->slots[slot].page = NULL;
    sm->slots[slot].state = SHADOW_SLOT_TOMBSTONE;
    sm->page_count--;
    sm->tombstone_count++;
}

static bool shadow_page_store(ShadowMemory *sm, uint64_t page_index, ShadowPage *page,
                              uint32_t offset, ProvLabelId label_id) {
    ProvLabelId old = page->labels[offset];
    if (old == label_id)
        return true;
    uint32_t block = offset / DTA_CMLB_BLOCK_SIZE;
    if (label_id != PROV_LABEL_CLEAN)
        shadow_cmlb_invalidate_locked(sm, page_index * SHADOW_BLOCKS_PER_PAGE + block);
    if (old == PROV_LABEL_CLEAN && label_id != PROV_LABEL_CLEAN) {
        if (page->block_nonclean_count[block] == DTA_CMLB_BLOCK_SIZE ||
            page->nonclean_count == DTA_SHADOW_PAGE_SIZE)
            return false;
        page->block_nonclean_count[block]++;
        page->nonclean_count++;
    } else if (old != PROV_LABEL_CLEAN && label_id == PROV_LABEL_CLEAN) {
        if (!page->nonclean_count || !page->block_nonclean_count[block])
            return false;
        page->block_nonclean_count[block]--;
        page->nonclean_count--;
    }
    page->labels[offset] = label_id;
    return true;
}

ShadowMemory *shadow_create_with_registry(uint8_t guest_bits, ProvRegistry *registry) {
    if (!registry || (guest_bits != 32 && guest_bits != 64))
        return NULL;
    ShadowMemory *sm = calloc(1, sizeof(*sm));
    if (!sm)
        return NULL;
    if (pthread_mutex_init(&sm->lock, NULL) != 0) {
        free(sm);
        return NULL;
    }
    sm->slots = calloc(SHADOW_INITIAL_SLOT_CAPACITY, sizeof(*sm->slots));
    if (!sm->slots) {
        pthread_mutex_destroy(&sm->lock);
        free(sm);
        return NULL;
    }
    sm->guest_bits = guest_bits;
    sm->registry = registry;
    sm->slot_capacity = SHADOW_INITIAL_SLOT_CAPACITY;
    sm->knowledge_valid = true;
#ifdef TF_DTA_TESTING
    sm->allocation_budget = -1;
#endif
    return sm;
}

ShadowMemory *shadow_create(uint8_t guest_bits) {
    ProvRegistry *registry = prov_registry_create(NULL);
    if (!registry)
        return NULL;
    ShadowMemory *sm = shadow_create_with_registry(guest_bits, registry);
    if (!sm) {
        prov_registry_destroy(registry);
        return NULL;
    }
    sm->owns_registry = true;
    return sm;
}

bool shadow_set_cmlb_enabled(ShadowMemory *sm, bool enabled) {
    if (!sm)
        return false;
    pthread_mutex_lock(&sm->lock);
    bool ok = true;
    if (enabled && !sm->cmlb) {
        sm->cmlb = shadow_calloc_locked(sm, DTA_CMLB_ENTRY_COUNT, sizeof(*sm->cmlb));
        if (!sm->cmlb) {
            SHADOW_COUNT(sm, cache_alloc_failures, 1);
            ok = false;
        } else
            sm->cmlb_generation = 1;
    } else if (!enabled) {
        free(sm->cmlb);
        sm->cmlb = NULL;
    }
    pthread_mutex_unlock(&sm->lock);
    return ok;
}

void shadow_cmlb_flush(ShadowMemory *sm) {
    if (!sm)
        return;
    pthread_mutex_lock(&sm->lock);
    shadow_cmlb_flush_locked(sm);
    pthread_mutex_unlock(&sm->lock);
}

void shadow_mark_incomplete(ShadowMemory *sm) {
    if (!sm)
        return;
    pthread_mutex_lock(&sm->lock);
    shadow_fail_locked(sm);
    pthread_mutex_unlock(&sm->lock);
}

bool shadow_knowledge_valid(ShadowMemory *sm) {
    if (!sm)
        return false;
    pthread_mutex_lock(&sm->lock);
    bool valid = sm->knowledge_valid;
    pthread_mutex_unlock(&sm->lock);
    return valid;
}

void shadow_set_stats_enabled(ShadowMemory *sm, bool enabled) {
    if (!sm)
        return;
    pthread_mutex_lock(&sm->lock);
    sm->stats_enabled = enabled;
    pthread_mutex_unlock(&sm->lock);
}

void shadow_reset_stats(ShadowMemory *sm) {
    if (!sm)
        return;
    pthread_mutex_lock(&sm->lock);
    memset(&sm->stats, 0, sizeof(sm->stats));
    pthread_mutex_unlock(&sm->lock);
}

bool shadow_get_stats(ShadowMemory *sm, ShadowStats *out) {
    if (!sm || !out)
        return false;
    pthread_mutex_lock(&sm->lock);
    *out = sm->stats;
    out->enabled = sm->stats_enabled;
    out->cmlb_enabled = sm->cmlb != NULL;
    out->knowledge_valid = sm->knowledge_valid;
    out->page_count = sm->page_count;
    out->page_bytes = sizeof(ShadowPage);
    out->cmlb_bytes = sm->cmlb ? DTA_CMLB_ENTRY_COUNT * sizeof(*sm->cmlb) : 0;
    pthread_mutex_unlock(&sm->lock);
    return true;
}

#ifdef TF_DTA_TESTING
bool shadow_test_allocation_budget(ShadowMemory *sm, int64_t successes) {
    if (!sm || successes < -1)
        return false;
    pthread_mutex_lock(&sm->lock);
    sm->allocation_budget = successes;
    pthread_mutex_unlock(&sm->lock);
    return true;
}

void shadow_test_cmlb_generation(ShadowMemory *sm, uint64_t generation) {
    if (!sm || !generation)
        return;
    pthread_mutex_lock(&sm->lock);
    shadow_cmlb_flush_locked(sm);
    sm->cmlb_generation = generation;
    /* A test epoch change must not revive any entry either. */
    if (sm->cmlb)
        memset(sm->cmlb, 0, DTA_CMLB_ENTRY_COUNT * sizeof(*sm->cmlb));
    pthread_mutex_unlock(&sm->lock);
}
#endif

ProvLabelId shadow_load_label(ShadowMemory *sm, uint64_t addr) {
    ProvLabelId label = PROV_LABEL_ID_INVALID;
    (void)shadow_load_labels(sm, addr, &label, 1);
    return label;
}

bool shadow_load_labels(ShadowMemory *sm, uint64_t addr, ProvLabelId *out_labels, uint32_t count) {
    if (!sm || (count && !out_labels))
        return false;
    if (shadow_clamp_range(sm, &addr, count) != count)
        return false;
    if (!count)
        return true;
    pthread_mutex_lock(&sm->lock);
    SHADOW_COUNT(sm, read_calls, 1);
    SHADOW_COUNT(sm, read_bytes, count);
    if (!sm->knowledge_valid) {
        for (uint32_t i = 0; i < count; i++)
            out_labels[i] = PROV_LABEL_UNKNOWN;
    } else if (shadow_cmlb_range_hit_locked(sm, addr, count)) {
        memset(out_labels, 0, (size_t)count * sizeof(*out_labels));
    } else {
        uint32_t index = 0;
        while (index < count) {
            uint64_t current = addr + index;
            uint64_t page_index = current / DTA_SHADOW_PAGE_SIZE;
            uint32_t offset = (uint32_t)(current % DTA_SHADOW_PAGE_SIZE);
            uint32_t chunk = DTA_SHADOW_PAGE_SIZE - offset;
            if (chunk > count - index)
                chunk = count - index;
            ShadowPage *page = shadow_page_locked(sm, page_index, false);
            if (page)
                memcpy(out_labels + index, page->labels + offset, chunk * sizeof(*out_labels));
            else
                memset(out_labels + index, 0, chunk * sizeof(*out_labels));
            shadow_cmlb_fill_locked(sm, page_index, page, offset, chunk);
            index += chunk;
        }
    }
    pthread_mutex_unlock(&sm->lock);
    return true;
}

bool shadow_store_label(ShadowMemory *sm, uint64_t addr, ProvLabelId label_id) {
    return shadow_store_labels(sm, addr, &label_id, 1);
}

/* All mutation paths share counters, proof invalidation and fail-closed state.
 * labels != NULL selects an array; otherwise fill_label is repeated. */
static bool shadow_write_locked(ShadowMemory *sm, uint64_t addr, uint64_t size,
                                const ProvLabelId *labels, ProvLabelId fill_label) {
    if (!sm->knowledge_valid)
        return false;
    SHADOW_COUNT(sm, write_calls, 1);
    SHADOW_COUNT(sm, write_bytes, size);
    while (size) {
        uint64_t page_index = addr / DTA_SHADOW_PAGE_SIZE;
        uint32_t offset = (uint32_t)(addr % DTA_SHADOW_PAGE_SIZE);
        uint32_t chunk = DTA_SHADOW_PAGE_SIZE - offset;
        if (chunk > size)
            chunk = (uint32_t)size;
        bool nonclean = fill_label != PROV_LABEL_CLEAN;
        if (labels) {
            nonclean = false;
            for (uint32_t b = 0; b < chunk; b++) {
                if (labels[b] != PROV_LABEL_CLEAN) {
                    nonclean = true;
                    break;
                }
            }
        }
        if (!nonclean && shadow_cmlb_range_hit_locked(sm, addr, chunk)) {
            SHADOW_COUNT(sm, clean_store_skips, 1);
        } else {
            ShadowPage *page = shadow_page_locked(sm, page_index, nonclean);
            if (nonclean && !page) {
                shadow_fail_locked(sm);
                return false;
            }
            if (page) {
                for (uint32_t b = 0; b < chunk; b++) {
                    if (!shadow_page_store(sm, page_index, page, offset + b,
                                           labels ? labels[b] : fill_label)) {
                        shadow_fail_locked(sm);
                        return false;
                    }
                }
            }
            shadow_cmlb_fill_locked(sm, page_index, page, offset, chunk);
            if (page && !page->nonclean_count)
                shadow_remove_page_locked(sm, page_index);
        }
        addr += chunk;
        size -= chunk;
        if (labels)
            labels += chunk;
    }
    return true;
}

bool shadow_store_labels(ShadowMemory *sm, uint64_t addr, const ProvLabelId *labels,
                         uint32_t count) {
    if (!sm || (count && !labels))
        return false;
    if (shadow_clamp_range(sm, &addr, count) != count)
        return false;
    for (uint32_t i = 0; i < count; i++)
        if (!prov_label_is_valid(sm->registry, labels[i]))
            return false;
    if (!count)
        return true;
    pthread_mutex_lock(&sm->lock);
    bool ok = shadow_write_locked(sm, addr, count, labels, PROV_LABEL_CLEAN);
    pthread_mutex_unlock(&sm->lock);
    return ok;
}

bool shadow_fill_label(ShadowMemory *sm, uint64_t addr, uint64_t size, ProvLabelId label_id) {
    if (!sm || !prov_label_is_valid(sm->registry, label_id))
        return false;
    if (!size)
        return true;
    size = shadow_clamp_range(sm, &addr, size);
    pthread_mutex_lock(&sm->lock);
    bool ok = shadow_write_locked(sm, addr, size, NULL, label_id);
    pthread_mutex_unlock(&sm->lock);
    return ok;
}

void shadow_destroy(ShadowMemory *sm) {
    if (!sm)
        return;
    pthread_mutex_lock(&sm->lock);
    for (size_t i = 0; i < sm->slot_capacity; i++)
        if (sm->slots[i].state == SHADOW_SLOT_OCCUPIED)
            free(sm->slots[i].page);
    free(sm->slots);
    free(sm->cmlb);
    ProvRegistry *registry = sm->registry;
    bool owns_registry = sm->owns_registry;
    pthread_mutex_unlock(&sm->lock);
    pthread_mutex_destroy(&sm->lock);
    free(sm);
    if (owns_registry)
        prov_registry_destroy(registry);
}

ProvRegistry *shadow_registry(ShadowMemory *sm) {
    return sm ? sm->registry : NULL;
}

void shadow_taint_byte(ShadowMemory *sm, uint64_t addr, uint64_t ip) {
    (void)ip;
    if (sm)
        (void)shadow_store_label(sm, addr, PROV_LABEL_UNKNOWN);
}

bool shadow_taint_range(ShadowMemory *sm, uint64_t addr, uint64_t size, uint64_t ip) {
    (void)ip;
    return sm && shadow_fill_label(sm, addr, size, PROV_LABEL_UNKNOWN);
}

void shadow_untaint_byte(ShadowMemory *sm, uint64_t addr) {
    if (sm)
        (void)shadow_store_label(sm, addr, PROV_LABEL_CLEAN);
}

void shadow_untaint_range(ShadowMemory *sm, uint64_t addr, uint64_t size) {
    if (sm)
        (void)shadow_fill_label(sm, addr, size, PROV_LABEL_CLEAN);
}

bool shadow_is_tainted(ShadowMemory *sm, uint64_t addr) {
    return sm && prov_label_may_be_tainted(sm->registry, shadow_load_label(sm, addr));
}

bool shadow_page_has_taint(ShadowMemory *sm, uint64_t addr) {
    if (!sm)
        return false;
    addr = shadow_normalize_addr(sm, addr);
    pthread_mutex_lock(&sm->lock);
    bool result = true;
    if (sm->knowledge_valid) {
        ShadowPage *page = shadow_page_locked(sm, addr / DTA_SHADOW_PAGE_SIZE, false);
        result = page && page->nonclean_count != 0;
    }
    pthread_mutex_unlock(&sm->lock);
    return result;
}

RegSlice reg_slice_invalid(void) {
    RegSlice slice = {.reg_id = REG_INVALID, .byte_offset = 0, .width = 0, .mask = 0};
    return slice;
}

bool reg_slice_is_valid(RegSlice slice) {
    if (slice.reg_id < 0 || slice.reg_id >= REG_COUNT)
        return false;
    if (slice.width == 0 || slice.width > MAX_REG_BYTES)
        return false;
    if (slice.byte_offset >= MAX_REG_BYTES)
        return false;
    if (slice.width > MAX_REG_BYTES - slice.byte_offset)
        return false;
    uint16_t low_bits = (uint16_t)((1U << slice.width) - 1U);
    uint8_t expected_mask = (uint8_t)(low_bits << slice.byte_offset);
    return slice.mask == expected_mask;
}

RegSlice reg_slice_from_x86(unsigned cs_reg, uint8_t size_bytes) {
    int rid = x86_reg_to_rid(cs_reg);
    if (rid < 0 || size_bytes == 0 || size_bytes > MAX_REG_BYTES) {
        return reg_slice_invalid();
    }

    x86_reg reg = (x86_reg)cs_reg;
    uint8_t byte_offset =
        (reg == X86_REG_AH || reg == X86_REG_BH || reg == X86_REG_CH || reg == X86_REG_DH) ? 1 : 0;

    if (size_bytes > MAX_REG_BYTES - byte_offset)
        return reg_slice_invalid();

    uint16_t low_bits = (uint16_t)((1U << size_bytes) - 1U);
    RegSlice slice = {.reg_id = (RegId)rid,
                      .byte_offset = byte_offset,
                      .width = size_bytes,
                      .mask = (uint8_t)(low_bits << byte_offset)};
    return slice;
}

bool reg_slice_equal(RegSlice left, RegSlice right) {
    return reg_slice_is_valid(left) && reg_slice_is_valid(right) && left.reg_id == right.reg_id &&
           left.byte_offset == right.byte_offset && left.width == right.width &&
           left.mask == right.mask;
}

RegSlice meta_first_reg_read(const InsnMeta *meta) {
    if (!meta || meta->reg_read_count == 0)
        return reg_slice_invalid();
    return meta->reg_reads[0];
}

RegSlice meta_first_reg_write(const InsnMeta *meta) {
    if (!meta || meta->reg_write_count == 0)
        return reg_slice_invalid();
    return meta->reg_writes[0];
}

int x86_reg_to_rid(unsigned cs_reg) {
    switch ((x86_reg)cs_reg) {
    case X86_REG_RAX:
    case X86_REG_EAX:
    case X86_REG_AX:
    case X86_REG_AL:
    case X86_REG_AH:
        return REG_RAX;
    case X86_REG_RCX:
    case X86_REG_ECX:
    case X86_REG_CX:
    case X86_REG_CL:
    case X86_REG_CH:
        return REG_RCX;
    case X86_REG_RDX:
    case X86_REG_EDX:
    case X86_REG_DX:
    case X86_REG_DL:
    case X86_REG_DH:
        return REG_RDX;
    case X86_REG_RBX:
    case X86_REG_EBX:
    case X86_REG_BX:
    case X86_REG_BL:
    case X86_REG_BH:
        return REG_RBX;
    case X86_REG_RSP:
    case X86_REG_ESP:
    case X86_REG_SP:
    case X86_REG_SPL:
        return REG_RSP;
    case X86_REG_RBP:
    case X86_REG_EBP:
    case X86_REG_BP:
    case X86_REG_BPL:
        return REG_RBP;
    case X86_REG_RSI:
    case X86_REG_ESI:
    case X86_REG_SI:
    case X86_REG_SIL:
        return REG_RSI;
    case X86_REG_RDI:
    case X86_REG_EDI:
    case X86_REG_DI:
    case X86_REG_DIL:
        return REG_RDI;
    case X86_REG_R8:
    case X86_REG_R8D:
    case X86_REG_R8W:
    case X86_REG_R8B:
        return REG_R8;
    case X86_REG_R9:
    case X86_REG_R9D:
    case X86_REG_R9W:
    case X86_REG_R9B:
        return REG_R9;
    case X86_REG_R10:
    case X86_REG_R10D:
    case X86_REG_R10W:
    case X86_REG_R10B:
        return REG_R10;
    case X86_REG_R11:
    case X86_REG_R11D:
    case X86_REG_R11W:
    case X86_REG_R11B:
        return REG_R11;
    case X86_REG_R12:
    case X86_REG_R12D:
    case X86_REG_R12W:
    case X86_REG_R12B:
        return REG_R12;
    case X86_REG_R13:
    case X86_REG_R13D:
    case X86_REG_R13W:
    case X86_REG_R13B:
        return REG_R13;
    case X86_REG_R14:
    case X86_REG_R14D:
    case X86_REG_R14W:
    case X86_REG_R14B:
        return REG_R14;
    case X86_REG_R15:
    case X86_REG_R15D:
    case X86_REG_R15W:
    case X86_REG_R15B:
        return REG_R15;
    default:
        return -1;
    }
}

static bool reg_id_is_valid(RegId rid) {
    return rid >= 0 && rid < REG_COUNT;
}

static bool reg_label_is_valid(const RegShadow *rs, ProvLabelId label_id) {
    if (!rs)
        return false;
    if (rs->registry)
        return prov_label_is_valid(rs->registry, label_id);
    return label_id == PROV_LABEL_CLEAN || label_id == PROV_LABEL_UNKNOWN;
}

static ProvLabelId reg_unknown_label(const RegShadow *rs) {
    if (rs && rs->registry)
        return prov_label_unknown(rs->registry);
    return PROV_LABEL_UNKNOWN;
}

static ProvLabelId reg_join_labels(const RegShadow *rs, ProvLabelId left, ProvLabelId right) {
    if (rs && rs->registry)
        return prov_label_join(rs->registry, left, right);
    return left == PROV_LABEL_CLEAN && right == PROV_LABEL_CLEAN ? PROV_LABEL_CLEAN
                                                                 : PROV_LABEL_UNKNOWN;
}

static ProvLabelId reg_join_many(const RegShadow *rs, const ProvLabelId *labels, uint32_t count) {
    if (!rs || (count != 0 && !labels))
        return PROV_LABEL_ID_INVALID;
    if (rs->registry)
        return prov_label_join_many(rs->registry, labels, count);
    for (uint32_t index = 0; index < count; index++) {
        if (labels[index] != PROV_LABEL_CLEAN)
            return PROV_LABEL_UNKNOWN;
    }
    return PROV_LABEL_CLEAN;
}

static ProvLabelId reg_mark_incomplete(const RegShadow *rs, ProvLabelId label_id, uint8_t channels,
                                       uint64_t reasons) {
    if (rs && rs->registry) {
        return prov_label_mark_incomplete(rs->registry, label_id, channels, reasons);
    }
    return label_id == PROV_LABEL_CLEAN ? PROV_LABEL_UNKNOWN : label_id;
}

static bool reg_label_may_be_tainted(const RegShadow *rs, ProvLabelId label_id) {
    if (rs && rs->registry) {
        return !prov_label_is_valid(rs->registry, label_id) ||
               prov_label_may_be_tainted(rs->registry, label_id);
    }
    return label_id != PROV_LABEL_CLEAN;
}

void reg_taint_set(RegShadow *rs, RegId rid, uint8_t byte_mask, uint64_t ip) {
    if (!rs)
        return;
    (void)reg_label_set(rs, rid, byte_mask, reg_unknown_label(rs), ip);
}

void reg_taint_clear(RegShadow *rs, RegId rid, uint8_t byte_mask) {
    if (!rs)
        return;
    (void)reg_label_set(rs, rid, byte_mask, PROV_LABEL_CLEAN, 0);
}

bool reg_shadow_init(RegShadow *rs, ProvRegistry *registry) {
    if (!rs || !registry)
        return false;
    memset(rs, 0, sizeof(*rs));
    rs->registry = registry;
    return true;
}

void reg_shadow_reset(RegShadow *rs) {
    if (!rs)
        return;
    ProvRegistry *registry = rs->registry;
    memset(rs, 0, sizeof(*rs));
    rs->registry = registry;
}

ProvLabelId reg_label_get(const RegShadow *rs, RegId rid, uint8_t byte_index) {
    if (!rs || !reg_id_is_valid(rid) || byte_index >= MAX_REG_BYTES) {
        return PROV_LABEL_ID_INVALID;
    }
    return rs->bytes[rid][byte_index];
}

bool reg_label_set(RegShadow *rs, RegId rid, uint8_t byte_mask, ProvLabelId label_id, uint64_t ip) {
    if (!rs || !reg_id_is_valid(rid) || !reg_label_is_valid(rs, label_id)) {
        return false;
    }
    if (byte_mask == 0)
        return true;
    for (uint8_t byte = 0; byte < MAX_REG_BYTES; byte++) {
        if (byte_mask & (uint8_t)(1U << byte)) {
            rs->bytes[rid][byte] = label_id;
        }
    }
    bool any_nonclean = false;
    for (uint8_t byte = 0; byte < MAX_REG_BYTES; byte++) {
        if (rs->bytes[rid][byte] != PROV_LABEL_CLEAN) {
            any_nonclean = true;
            break;
        }
    }
    if (!any_nonclean)
        rs->src_ip[rid] = 0;
    else if (label_id != PROV_LABEL_CLEAN)
        rs->src_ip[rid] = ip;
    return true;
}

static bool reg_has_nonclean_byte(const RegShadow *rs, RegId rid) {
    if (!rs || !reg_id_is_valid(rid))
        return false;
    for (uint8_t byte = 0; byte < MAX_REG_BYTES; byte++) {
        if (rs->bytes[rid][byte] != PROV_LABEL_CLEAN)
            return true;
    }
    return false;
}

static void reg_apply_slice_write_semantics(RegShadow *rs, RegSlice slice) {
    if (!rs || !reg_slice_is_valid(slice) || slice.byte_offset != 0 || slice.width != 4) {
        return;
    }
    for (uint8_t byte = 4; byte < MAX_REG_BYTES; byte++) {
        rs->bytes[slice.reg_id][byte] = PROV_LABEL_CLEAN;
    }
}

bool reg_slice_set_label(RegShadow *rs, RegSlice slice, ProvLabelId label_id, uint64_t ip) {
    if (!rs || !reg_slice_is_valid(slice))
        return false;
    if (!reg_label_set(rs, slice.reg_id, slice.mask, label_id, ip)) {
        return false;
    }
    reg_apply_slice_write_semantics(rs, slice);
    if (!reg_has_nonclean_byte(rs, slice.reg_id))
        rs->src_ip[slice.reg_id] = 0;
    return true;
}

bool reg_slice_load_labels(const RegShadow *rs, RegSlice slice, ProvLabelId *out_labels) {
    if (!rs || !out_labels || !reg_slice_is_valid(slice))
        return false;
    for (uint8_t byte = 0; byte < slice.width; byte++) {
        out_labels[byte] = rs->bytes[slice.reg_id][slice.byte_offset + byte];
    }
    return true;
}

bool reg_slice_store_labels(RegShadow *rs, RegSlice slice, const ProvLabelId *labels, uint8_t count,
                            uint64_t ip) {
    if (!rs || !labels || !reg_slice_is_valid(slice) || count != slice.width) {
        return false;
    }
    for (uint8_t byte = 0; byte < count; byte++) {
        if (!reg_label_is_valid(rs, labels[byte]))
            return false;
    }
    for (uint8_t byte = 0; byte < count; byte++) {
        rs->bytes[slice.reg_id][slice.byte_offset + byte] = labels[byte];
    }
    reg_apply_slice_write_semantics(rs, slice);
    bool written_nonclean = false;
    for (uint8_t byte = 0; byte < count; byte++) {
        if (labels[byte] != PROV_LABEL_CLEAN)
            written_nonclean = true;
    }
    if (!reg_has_nonclean_byte(rs, slice.reg_id)) {
        rs->src_ip[slice.reg_id] = 0;
    } else if (written_nonclean) {
        rs->src_ip[slice.reg_id] = ip;
    }
    return true;
}

bool reg_is_tainted(const RegShadow *rs, RegId rid, uint8_t byte_mask) {
    if (!rs || !reg_id_is_valid(rid))
        return false;
    for (uint8_t byte = 0; byte < MAX_REG_BYTES; byte++) {
        if ((byte_mask & (uint8_t)(1U << byte)) &&
            reg_label_may_be_tainted(rs, rs->bytes[rid][byte])) {
            return true;
        }
    }
    return false;
}

void reg_slice_taint_set(RegShadow *rs, RegSlice slice, uint64_t ip) {
    if (!rs || !reg_slice_is_valid(slice))
        return;
    (void)reg_slice_set_label(rs, slice, reg_unknown_label(rs), ip);
}

void reg_slice_taint_clear(RegShadow *rs, RegSlice slice) {
    if (!rs || !reg_slice_is_valid(slice))
        return;
    (void)reg_slice_set_label(rs, slice, PROV_LABEL_CLEAN, 0);
}

bool reg_slice_is_tainted(const RegShadow *rs, RegSlice slice) {
    if (!rs || !reg_slice_is_valid(slice))
        return false;
    return reg_is_tainted(rs, slice.reg_id, slice.mask);
}

bool dta_vcpu_state_init(DtaVcpuState *state, uint32_t vcpu_index, ProvRegistry *registry) {
    if (!state || !registry)
        return false;
    memset(state, 0, sizeof(*state));
    state->vcpu_index = vcpu_index;
    state->registry = registry;
    return reg_shadow_init(&state->regs, registry);
}

void dta_vcpu_state_reset(DtaVcpuState *state) {
    if (!state)
        return;
    uint32_t vcpu_index = state->vcpu_index;
    ProvRegistry *registry = state->registry;
    memset(state, 0, sizeof(*state));
    state->vcpu_index = vcpu_index;
    state->registry = registry;
    (void)reg_shadow_init(&state->regs, registry);
}

static uint8_t dta_flag_bit(DtaFlagSlot flag) {
    static const uint8_t bits[DTA_FLAG_SLOT_COUNT] = {X86_FLAG_CF, X86_FLAG_PF, X86_FLAG_AF,
                                                      X86_FLAG_ZF, X86_FLAG_SF, X86_FLAG_OF};
    if (flag < 0 || flag >= DTA_FLAG_SLOT_COUNT) {
        return 0;
    }
    return bits[flag];
}

ProvLabelId dta_flag_get_label(const DtaVcpuState *state, DtaFlagSlot flag) {
    uint8_t bit = dta_flag_bit(flag);
    if (!state || bit == 0 || (state->flags.valid_mask & bit) == 0) {
        return PROV_LABEL_ID_INVALID;
    }
    return state->flags.labels[flag];
}

bool dta_flag_set_label(DtaVcpuState *state, DtaFlagSlot flag, ProvLabelId label_id) {
    uint8_t bit = dta_flag_bit(flag);
    if (!state || bit == 0 || !prov_label_is_valid(state->registry, label_id)) {
        return false;
    }
    state->flags.labels[flag] = label_id;
    state->flags.valid_mask |= bit;
    return true;
}

bool dta_flag_set_mask(DtaVcpuState *state, uint8_t flag_mask, ProvLabelId label_id) {
    if (!state || (flag_mask & (uint8_t)~X86_FLAG_TRACKED) != 0 ||
        !prov_label_is_valid(state->registry, label_id)) {
        return false;
    }
    for (int flag = 0; flag < DTA_FLAG_SLOT_COUNT; flag++) {
        uint8_t bit = dta_flag_bit((DtaFlagSlot)flag);
        if ((flag_mask & bit) != 0) {
            state->flags.labels[flag] = label_id;
        }
    }
    state->flags.valid_mask |= flag_mask;
    return true;
}

ProvLabelId dta_flag_join_mask(const DtaVcpuState *state, uint8_t flag_mask) {
    if (!state || (flag_mask & (uint8_t)~X86_FLAG_TRACKED) != 0) {
        return PROV_LABEL_ID_INVALID;
    }
    if (flag_mask == 0)
        return PROV_LABEL_CLEAN;
    if ((state->flags.valid_mask & flag_mask) != flag_mask) {
        return PROV_LABEL_ID_INVALID;
    }

    ProvLabelId labels[DTA_FLAG_SLOT_COUNT];
    uint32_t count = 0;
    for (int flag = 0; flag < DTA_FLAG_SLOT_COUNT; flag++) {
        uint8_t bit = dta_flag_bit((DtaFlagSlot)flag);
        if ((flag_mask & bit) != 0) {
            labels[count++] = state->flags.labels[flag];
        }
    }
    return prov_label_join_many(state->registry, labels, count);
}

bool dta_flag_mask_is_tainted(const DtaVcpuState *state, uint8_t flag_mask) {
    ProvLabelId label = dta_flag_join_mask(state, flag_mask);
    return label == PROV_LABEL_ID_INVALID || prov_label_may_be_tainted(state->registry, label);
}

void dta_pending_branch_clear(DtaVcpuState *state) {
    if (!state)
        return;
    memset(&state->pending_branch, 0, sizeof(state->pending_branch));
}

bool dta_pending_branch_begin(DtaVcpuState *state, uint64_t seq_id, MetaId meta_id, uint64_t pc,
                              uint64_t fallthrough, bool direct_target_valid,
                              uint64_t direct_target, X86ConditionCode condition_code,
                              ProvLabelId condition_label) {
    if (!state || seq_id == 0 || !prov_label_is_valid(state->registry, condition_label)) {
        return false;
    }
    state->pending_branch.active = true;
    state->pending_branch.seq_id = seq_id;
    state->pending_branch.meta_id = meta_id;
    state->pending_branch.pc = pc;
    state->pending_branch.fallthrough = fallthrough;
    state->pending_branch.direct_target_valid = direct_target_valid;
    state->pending_branch.direct_target = direct_target;
    state->pending_branch.condition_code = condition_code;
    state->pending_branch.condition_label = condition_label;
    return true;
}

void propagate_reg2reg(RegShadow *rs, RegSlice dst, RegSlice src, uint16_t insn_id) {
    if (!rs || !reg_slice_is_valid(dst) || !reg_slice_is_valid(src))
        return;
    uint8_t copy_width = src.width < dst.width ? src.width : dst.width;
    ProvLabelId source_labels[MAX_REG_BYTES] = {PROV_LABEL_CLEAN};
    for (uint8_t byte = 0; byte < src.width; byte++) {
        source_labels[byte] = rs->bytes[src.reg_id][src.byte_offset + byte];
    }
    for (uint8_t byte = 0; byte < copy_width; byte++) {
        rs->bytes[dst.reg_id][dst.byte_offset + byte] = source_labels[byte];
    }
    if (insn_id == X86_INS_MOVZX) {
        for (uint8_t byte = copy_width; byte < dst.width; byte++) {
            rs->bytes[dst.reg_id][dst.byte_offset + byte] = PROV_LABEL_CLEAN;
        }
    } else if (insn_id == X86_INS_MOVSX) {
        ProvLabelId sign_label = source_labels[src.width - 1];
        for (uint8_t byte = copy_width; byte < dst.width; byte++) {
            rs->bytes[dst.reg_id][dst.byte_offset + byte] = sign_label;
        }
    }
    reg_apply_slice_write_semantics(rs, dst);
    rs->src_ip[dst.reg_id] = 0;
}

void propagate_mem_labels2reg(RegShadow *rs, RegSlice dst, const ProvLabelId *mem_labels,
                              uint8_t mem_width, uint16_t insn_id, bool overwrite) {
    if (!rs || !mem_labels || !reg_slice_is_valid(dst) || mem_width == 0 ||
        mem_width > MAX_REG_BYTES ||
        ((insn_id == X86_INS_MOVZX || insn_id == X86_INS_MOVSX) && mem_width > dst.width)) {
        return;
    }
    for (uint8_t byte = 0; byte < mem_width; byte++) {
        if (!reg_label_is_valid(rs, mem_labels[byte]))
            return;
    }
    uint8_t copy_width = mem_width < dst.width ? mem_width : dst.width;
    bool strong_update = overwrite || insn_id == X86_INS_MOVZX || insn_id == X86_INS_MOVSX;
    for (uint8_t byte = 0; byte < copy_width; byte++) {
        uint8_t destination = dst.byte_offset + byte;
        if (strong_update) {
            rs->bytes[dst.reg_id][destination] = mem_labels[byte];
        } else {
            rs->bytes[dst.reg_id][destination] =
                reg_join_labels(rs, rs->bytes[dst.reg_id][destination], mem_labels[byte]);
        }
    }
    if (insn_id == X86_INS_MOVZX) {
        for (uint8_t byte = copy_width; byte < dst.width; byte++) {
            rs->bytes[dst.reg_id][dst.byte_offset + byte] = PROV_LABEL_CLEAN;
        }
    } else if (insn_id == X86_INS_MOVSX) {
        ProvLabelId sign_label = mem_labels[mem_width - 1];
        for (uint8_t byte = copy_width; byte < dst.width; byte++) {
            rs->bytes[dst.reg_id][dst.byte_offset + byte] = sign_label;
        }
    }
    reg_apply_slice_write_semantics(rs, dst);
    rs->src_ip[dst.reg_id] = 0;
}

void propagate_mem2reg(RegShadow *rs, RegSlice dst, uint8_t mem_taint_mask, uint8_t mem_width,
                       uint16_t insn_id, bool overwrite) {
    if (!rs || mem_width == 0 || mem_width > MAX_REG_BYTES)
        return;
    ProvLabelId labels[MAX_REG_BYTES];
    for (uint8_t byte = 0; byte < mem_width; byte++) {
        labels[byte] =
            (mem_taint_mask & (uint8_t)(1U << byte)) ? reg_unknown_label(rs) : PROV_LABEL_CLEAN;
    }
    propagate_mem_labels2reg(rs, dst, labels, mem_width, insn_id, overwrite);
}

void reg_propagate_clear(RegShadow *rs, RegId rid) {
    if (!rs || !reg_id_is_valid(rid))
        return;
    (void)reg_label_set(rs, rid, UINT8_MAX, PROV_LABEL_CLEAN, 0);
}

static ProvLabelId snapshot_slice_label(const RegShadow *snapshot, RegSlice slice,
                                        uint8_t local_byte) {
    if (!snapshot || !reg_slice_is_valid(slice) || local_byte >= slice.width) {
        return PROV_LABEL_CLEAN;
    }
    return snapshot->bytes[slice.reg_id][slice.byte_offset + local_byte];
}

static void write_slice_label(RegShadow *rs, RegSlice slice, uint8_t local_byte,
                              ProvLabelId label_id) {
    if (!rs || !reg_slice_is_valid(slice) || local_byte >= slice.width)
        return;
    rs->bytes[slice.reg_id][slice.byte_offset + local_byte] = label_id;
    reg_apply_slice_write_semantics(rs, slice);
}

static ProvLabelId meta_read_state_join(const RegShadow *snapshot, const InsnMeta *meta) {
    if (!snapshot || !meta)
        return PROV_LABEL_ID_INVALID;
    ProvLabelId labels[REG_COUNT * MAX_REG_BYTES];
    uint32_t count = 0;
    if (meta->reg_read_count > 0) {
        for (uint8_t read = 0; read < meta->reg_read_count; read++) {
            RegSlice slice = meta->reg_reads[read];
            if (!reg_slice_is_valid(slice))
                continue;
            for (uint8_t byte = 0; byte < slice.width; byte++) {
                labels[count++] = snapshot_slice_label(snapshot, slice, byte);
            }
        }
    } else {
        for (int rid = 0; rid < REG_COUNT; rid++) {
            if (!(meta->regs_read_mask & (1U << rid)))
                continue;
            for (uint8_t byte = 0; byte < MAX_REG_BYTES; byte++) {
                labels[count++] = snapshot->bytes[rid][byte];
            }
        }
    }
    return reg_join_many(snapshot, labels, count);
}

static bool dta_flag_family_is_modeled(const InsnMeta *meta) {
    if (!meta)
        return false;
    switch (meta->family) {
    case DTA_FAMILY_COMPARE:
    case DTA_FAMILY_ARITHMETIC:
    case DTA_FAMILY_LOGICAL:
        return true;
    default:
        return false;
    }
}

DtaTransferResult dta_apply_flag_transfer(DtaVcpuState *state, const RegShadow *pre_regs,
                                          const InsnMeta *meta, const ProvLabelId *memory_labels,
                                          uint8_t memory_label_count) {
    if (!state || !pre_regs || !meta || state->registry != pre_regs->registry ||
        memory_label_count > MAX_REG_BYTES || (memory_label_count != 0 && !memory_labels)) {
        return DTA_TRANSFER_NOT_APPLICABLE;
    }

    uint8_t written_mask = meta->flags_write_mask & X86_FLAG_TRACKED;
    if (written_mask == 0) {
        return DTA_TRANSFER_NOT_APPLICABLE;
    }
    uint64_t incomplete_reasons = PROV_INCOMPLETE_NONE;
    ProvLabelId joined = meta_read_state_join(pre_regs, meta);
    if (joined == PROV_LABEL_ID_INVALID) {
        joined = prov_label_unknown(state->registry);
        incomplete_reasons |= PROV_INCOMPLETE_UNKNOWN;
    }
    if (meta->has_mem_read && memory_label_count == 0) {
        incomplete_reasons |= PROV_INCOMPLETE_UNRESOLVED_MEMORY;
    }

    for (uint8_t byte = 0; byte < memory_label_count; byte++) {
        ProvLabelId label = memory_labels[byte];
        if (!prov_label_is_valid(state->registry, label)) {
            incomplete_reasons |= PROV_INCOMPLETE_UNRESOLVED_MEMORY;
            continue;
        }
        joined = prov_label_join(state->registry, joined, label);
        if (joined == PROV_LABEL_ID_INVALID) {
            joined = prov_label_unknown(state->registry);
            incomplete_reasons |= PROV_INCOMPLETE_UNKNOWN;
            break;
        }
    }

    if (meta->flags_read_mask != 0) {
        ProvLabelId flag_input = dta_flag_join_mask(state, meta->flags_read_mask);
        if (flag_input == PROV_LABEL_ID_INVALID) {
            incomplete_reasons |= PROV_INCOMPLETE_UNDEFINED_FLAG;
        } else {
            joined = prov_label_join(state->registry, joined, flag_input);
            if (joined == PROV_LABEL_ID_INVALID) {
                joined = prov_label_unknown(state->registry);
                incomplete_reasons |= PROV_INCOMPLETE_UNKNOWN;
            }
        }
    }
    if (!dta_flag_family_is_modeled(meta)) {
        incomplete_reasons |= PROV_INCOMPLETE_UNSUPPORTED_INSTRUCTION;
    }
    if (meta->is_self_zeroing && !meta->has_mem_read) {
        joined = PROV_LABEL_CLEAN;
        incomplete_reasons = PROV_INCOMPLETE_NONE;
    }
    if (incomplete_reasons != PROV_INCOMPLETE_NONE) {
        joined = prov_label_mark_incomplete(state->registry, joined, PROV_COMPLETE_ALL,
                                            incomplete_reasons);
    }
    if (joined == PROV_LABEL_ID_INVALID)
        return DTA_TRANSFER_INCOMPLETE;

    uint8_t ordinary_mask = written_mask;
    if (meta->family == DTA_FAMILY_LOGICAL && (written_mask & X86_FLAG_AF) != 0) {
        ordinary_mask &= (uint8_t)~X86_FLAG_AF;
        ProvLabelId af_label = prov_label_mark_incomplete(
            state->registry, joined, PROV_COMPLETE_ALL, PROV_INCOMPLETE_UNDEFINED_FLAG);
        if (af_label == PROV_LABEL_ID_INVALID ||
            !dta_flag_set_label(state, DTA_FLAG_SLOT_AF, af_label)) {
            return DTA_TRANSFER_INCOMPLETE;
        }
        incomplete_reasons |= PROV_INCOMPLETE_UNDEFINED_FLAG;
    }
    if (ordinary_mask != 0 && !dta_flag_set_mask(state, ordinary_mask, joined)) {
        return DTA_TRANSFER_INCOMPLETE;
    }
    if (incomplete_reasons != PROV_INCOMPLETE_NONE) {
        return DTA_TRANSFER_INCOMPLETE;
    }
    return meta->is_self_zeroing ? DTA_TRANSFER_EXACT : DTA_TRANSFER_CONSERVATIVE;
}

static void copy_slice_from_snapshot(RegShadow *rs, const RegShadow *snapshot, RegSlice dst,
                                     RegSlice src, uint16_t insn_id) {
    if (!rs || !snapshot || !reg_slice_is_valid(dst) || !reg_slice_is_valid(src)) {
        return;
    }
    uint8_t copy_width = src.width < dst.width ? src.width : dst.width;
    for (uint8_t i = 0; i < copy_width; i++) {
        write_slice_label(rs, dst, i, snapshot_slice_label(snapshot, src, i));
    }
    if (insn_id == X86_INS_MOVZX) {
        for (uint8_t i = copy_width; i < dst.width; i++) {
            write_slice_label(rs, dst, i, PROV_LABEL_CLEAN);
        }
    } else if (insn_id == X86_INS_MOVSX) {
        ProvLabelId sign_label = snapshot_slice_label(snapshot, src, (uint8_t)(src.width - 1));
        for (uint8_t i = copy_width; i < dst.width; i++) {
            write_slice_label(rs, dst, i, sign_label);
        }
    }
    rs->src_ip[dst.reg_id] = 0;
}

static ProvLabelId incomplete_input_join(const RegShadow *snapshot, const InsnMeta *meta,
                                         uint64_t reasons) {
    ProvLabelId joined = meta_read_state_join(snapshot, meta);
    if (joined == PROV_LABEL_ID_INVALID)
        return reg_unknown_label(snapshot);
    return reg_mark_incomplete(snapshot, joined, PROV_COMPLETE_ALL, reasons);
}

static void fill_slice_label(RegShadow *rs, RegSlice slice, ProvLabelId label_id) {
    if (!rs || !reg_slice_is_valid(slice))
        return;
    for (uint8_t byte = 0; byte < slice.width; byte++) {
        write_slice_label(rs, slice, byte, label_id);
    }
    rs->src_ip[slice.reg_id] = 0;
}

static DtaTransferResult apply_data_movement(RegShadow *rs, const RegShadow *snapshot,
                                             const InsnMeta *meta) {
    RegSlice dst = meta_first_reg_write(meta);
    switch (meta->insn_id) {
    case X86_INS_MOV:
    case X86_INS_MOVZX:
    case X86_INS_MOVSX: {
        if (!reg_slice_is_valid(dst))
            return DTA_TRANSFER_NOT_APPLICABLE;
        if (meta->insn_id == X86_INS_MOV && meta->has_imm_operand && meta->reg_read_count == 0) {
            reg_slice_taint_clear(rs, dst);
            rs->src_ip[dst.reg_id] = 0;
            return DTA_TRANSFER_EXACT;
        }
        RegSlice src = meta_first_reg_read(meta);
        if (!reg_slice_is_valid(src)) {
            ProvLabelId incomplete =
                incomplete_input_join(snapshot, meta, PROV_INCOMPLETE_IMPLICIT_OPERAND);
            fill_slice_label(rs, dst, incomplete);
            return DTA_TRANSFER_INCOMPLETE;
        }
        if ((meta->insn_id == X86_INS_MOV && src.width != dst.width) ||
            (meta->insn_id != X86_INS_MOV && src.width > dst.width)) {
            ProvLabelId incomplete = incomplete_input_join(snapshot, meta, PROV_INCOMPLETE_UNKNOWN);
            fill_slice_label(rs, dst, incomplete);
            return DTA_TRANSFER_INCOMPLETE;
        }
        copy_slice_from_snapshot(rs, snapshot, dst, src, meta->insn_id);
        return DTA_TRANSFER_EXACT;
    }
    case X86_INS_LEA: {
        if (!reg_slice_is_valid(dst))
            return DTA_TRANSFER_NOT_APPLICABLE;
        if (meta->mem_addr_reg_mask == 0) {
            reg_slice_taint_clear(rs, dst);
            rs->src_ip[dst.reg_id] = 0;
            return DTA_TRANSFER_EXACT;
        }
        for (uint8_t out_byte = 0; out_byte < dst.width; out_byte++) {
            ProvLabelId inputs[REG_COUNT * MAX_REG_BYTES];
            uint32_t count = 0;
            for (int rid = 0; rid < REG_COUNT; rid++) {
                if (!(meta->mem_addr_reg_mask & (1U << rid)))
                    continue;
                uint8_t max_input = out_byte < MAX_REG_BYTES ? out_byte : MAX_REG_BYTES - 1;
                for (uint8_t in_byte = 0; in_byte <= max_input; in_byte++) {
                    inputs[count++] = snapshot->bytes[rid][in_byte];
                }
            }
            write_slice_label(rs, dst, out_byte, reg_join_many(snapshot, inputs, count));
        }
        rs->src_ip[dst.reg_id] = 0;
        return DTA_TRANSFER_CONSERVATIVE;
    }
    case X86_INS_XCHG: {
        if (meta->reg_write_count < 2) {
            ProvLabelId incomplete =
                incomplete_input_join(snapshot, meta, PROV_INCOMPLETE_IMPLICIT_OPERAND);
            uint32_t affected = meta->regs_read_mask | meta->regs_written_mask;
            for (int rid = 0; rid < REG_COUNT; rid++) {
                if (affected & (1U << rid)) {
                    (void)reg_label_set(rs, (RegId)rid, UINT8_MAX, incomplete, 0);
                }
            }
            return DTA_TRANSFER_INCOMPLETE;
        }
        RegSlice left = meta->reg_writes[0];
        RegSlice right = meta->reg_writes[1];
        if (!reg_slice_is_valid(left) || !reg_slice_is_valid(right) || left.width != right.width) {
            ProvLabelId incomplete =
                incomplete_input_join(snapshot, meta, PROV_INCOMPLETE_IMPLICIT_OPERAND);
            if (reg_slice_is_valid(left))
                fill_slice_label(rs, left, incomplete);
            if (reg_slice_is_valid(right))
                fill_slice_label(rs, right, incomplete);
            return DTA_TRANSFER_INCOMPLETE;
        }
        for (uint8_t i = 0; i < left.width; i++) {
            ProvLabelId left_label = snapshot_slice_label(snapshot, left, i);
            ProvLabelId right_label = snapshot_slice_label(snapshot, right, i);
            write_slice_label(rs, left, i, right_label);
            write_slice_label(rs, right, i, left_label);
        }
        rs->src_ip[left.reg_id] = 0;
        rs->src_ip[right.reg_id] = 0;
        return DTA_TRANSFER_EXACT;
    }
    default:
        return DTA_TRANSFER_NOT_APPLICABLE;
    }
}

static DtaTransferResult apply_logical_transfer(RegShadow *rs, const RegShadow *snapshot,
                                                const InsnMeta *meta) {
    RegSlice dst = meta_first_reg_write(meta);
    if (!reg_slice_is_valid(dst))
        return DTA_TRANSFER_NOT_APPLICABLE;
    if (meta->is_self_zeroing) {
        reg_slice_taint_clear(rs, dst);
        rs->src_ip[dst.reg_id] = 0;
        return DTA_TRANSFER_EXACT;
    }
    if (meta->reg_read_count == 0) {
        fill_slice_label(rs, dst,
                         incomplete_input_join(snapshot, meta, PROV_INCOMPLETE_IMPLICIT_OPERAND));
        return DTA_TRANSFER_INCOMPLETE;
    }
    for (uint8_t out_byte = 0; out_byte < dst.width; out_byte++) {
        ProvLabelId inputs[MAX_INSN_REG_SLICES];
        uint32_t count = 0;
        for (uint8_t read_index = 0; read_index < meta->reg_read_count; read_index++) {
            RegSlice src = meta->reg_reads[read_index];
            if (reg_slice_is_valid(src) && out_byte < src.width) {
                inputs[count++] = snapshot_slice_label(snapshot, src, out_byte);
            }
        }
        write_slice_label(rs, dst, out_byte, reg_join_many(snapshot, inputs, count));
    }
    rs->src_ip[dst.reg_id] = 0;
    return meta->insn_id == X86_INS_NOT ? DTA_TRANSFER_EXACT : DTA_TRANSFER_CONSERVATIVE;
}

static DtaTransferResult apply_arithmetic_transfer(RegShadow *rs, const RegShadow *snapshot,
                                                   const InsnMeta *meta) {
    RegSlice dst = meta_first_reg_write(meta);
    if (!reg_slice_is_valid(dst))
        return DTA_TRANSFER_NOT_APPLICABLE;
    if (meta->is_self_zeroing) {
        reg_slice_taint_clear(rs, dst);
        rs->src_ip[dst.reg_id] = 0;
        return DTA_TRANSFER_EXACT;
    }
    if (meta->reg_read_count == 0) {
        fill_slice_label(rs, dst,
                         incomplete_input_join(snapshot, meta, PROV_INCOMPLETE_IMPLICIT_OPERAND));
        return DTA_TRANSFER_INCOMPLETE;
    }
    bool carry_input_missing = meta->insn_id == X86_INS_ADC || meta->insn_id == X86_INS_SBB;
    for (uint8_t out_byte = 0; out_byte < dst.width; out_byte++) {
        ProvLabelId inputs[MAX_INSN_REG_SLICES * MAX_REG_BYTES];
        uint32_t count = 0;
        for (uint8_t read_index = 0; read_index < meta->reg_read_count; read_index++) {
            RegSlice src = meta->reg_reads[read_index];
            if (!reg_slice_is_valid(src))
                continue;
            uint8_t max_input = out_byte < src.width ? out_byte : (uint8_t)(src.width - 1);
            for (uint8_t in_byte = 0; in_byte <= max_input; in_byte++) {
                inputs[count++] = snapshot_slice_label(snapshot, src, in_byte);
            }
        }
        ProvLabelId output = reg_join_many(snapshot, inputs, count);
        if (carry_input_missing) {
            output = reg_mark_incomplete(snapshot, output, PROV_COMPLETE_ALL,
                                         PROV_INCOMPLETE_IMPLICIT_OPERAND);
        }
        write_slice_label(rs, dst, out_byte, output);
    }
    rs->src_ip[dst.reg_id] = 0;
    return carry_input_missing ? DTA_TRANSFER_INCOMPLETE : DTA_TRANSFER_CONSERVATIVE;
}

static bool immediate_shift_labels(const RegShadow *rs, const InsnMeta *meta,
                                   const ProvLabelId *input, uint8_t width, ProvLabelId *output) {
    if (!meta->shift_count_valid || !meta->shift_count_is_immediate ||
        meta->reg_slice_detail_truncated ||
        (width != 1 && width != 2 && width != 4 && width != 8) ||
        meta->shift_operand_width != width * 8U) {
        return false;
    }
    bool left = meta->insn_id == X86_INS_SHL || meta->insn_id == X86_INS_SAL;
    bool sign = meta->insn_id == X86_INS_SAR;
    if (!left && !sign && meta->insn_id != X86_INS_SHR)
        return false;

    int bits = width * 8;
    int shift = meta->shift_count_imm & (width == 8 ? 63 : 31);
    for (uint8_t byte = 0; byte < width; ++byte) {
        /* A destination byte can intersect at most two source bytes. Inserted
         * zero bits have no source; SAR extends the original sign byte. */
        int first = byte * 8 + (left ? -shift : shift);
        int last = first + 7;
        if (last < 0 || first >= bits) {
            output[byte] = sign ? input[width - 1] : PROV_LABEL_CLEAN;
            continue;
        }
        if (first < 0)
            first = 0;
        if (last >= bits)
            last = bits - 1;
        output[byte] = first / 8 == last / 8
                           ? input[first / 8]
                           : reg_join_labels(rs, input[first / 8], input[last / 8]);
    }
    return true;
}

static DtaTransferResult apply_shift_rotate_transfer(RegShadow *rs, const RegShadow *snapshot,
                                                     const InsnMeta *meta) {
    RegSlice dst = meta_first_reg_write(meta);
    if (!reg_slice_is_valid(dst))
        return DTA_TRANSFER_NOT_APPLICABLE;
    if (meta->reg_read_count == 1 && meta->reg_write_count == 1 &&
        reg_slice_equal(meta->reg_reads[0], dst)) {
        ProvLabelId input[MAX_REG_BYTES], output[MAX_REG_BYTES];
        for (uint8_t byte = 0; byte < dst.width; ++byte)
            input[byte] = snapshot_slice_label(snapshot, dst, byte);
        if (immediate_shift_labels(snapshot, meta, input, dst.width, output)) {
            for (uint8_t byte = 0; byte < dst.width; ++byte)
                write_slice_label(rs, dst, byte, output[byte]);
            rs->src_ip[dst.reg_id] = 0;
            return DTA_TRANSFER_CONSERVATIVE;
        }
    }
    ProvLabelId joined = meta_read_state_join(snapshot, meta);
    if (joined == PROV_LABEL_ID_INVALID || meta->reg_read_count == 0) {
        joined = incomplete_input_join(snapshot, meta, PROV_INCOMPLETE_IMPLICIT_OPERAND);
        fill_slice_label(rs, dst, joined);
        return DTA_TRANSFER_INCOMPLETE;
    }
    bool carry_input_missing = meta->insn_id == X86_INS_RCL || meta->insn_id == X86_INS_RCR;
    if (carry_input_missing) {
        joined = reg_mark_incomplete(snapshot, joined, PROV_COMPLETE_ALL,
                                     PROV_INCOMPLETE_IMPLICIT_OPERAND);
    }
    fill_slice_label(rs, dst, joined);
    return carry_input_missing ? DTA_TRANSFER_INCOMPLETE : DTA_TRANSFER_CONSERVATIVE;
}

static DtaTransferResult apply_unsupported_register_transfer(RegShadow *rs,
                                                             const RegShadow *snapshot,
                                                             const InsnMeta *meta) {
    ProvLabelId output =
        incomplete_input_join(snapshot, meta, PROV_INCOMPLETE_UNSUPPORTED_INSTRUCTION);
    uint32_t explicitly_written = 0;
    bool changed = false;
    for (uint8_t i = 0; i < meta->reg_write_count; i++) {
        RegSlice dst = meta->reg_writes[i];
        if (!reg_slice_is_valid(dst))
            continue;
        fill_slice_label(rs, dst, output);
        explicitly_written |= 1U << dst.reg_id;
        changed = true;
    }
    for (int rid = 0; rid < REG_COUNT; rid++) {
        if (!(meta->regs_written_mask & (1U << rid)) || (explicitly_written & (1U << rid))) {
            continue;
        }
        (void)reg_label_set(rs, (RegId)rid, UINT8_MAX, output, 0);
        changed = true;
    }
    return changed ? DTA_TRANSFER_INCOMPLETE : DTA_TRANSFER_NOT_APPLICABLE;
}

DtaTransferResult dta_apply_reg_transfer(RegShadow *rs, const InsnMeta *meta) {
    if (!rs || !meta) {
        return DTA_TRANSFER_NOT_APPLICABLE;
    }
    if (meta->has_mem_read || meta->has_mem_write) {
        return DTA_TRANSFER_NOT_APPLICABLE;
    }
    RegShadow snapshot = *rs;

    switch (meta->family) {
    case DTA_FAMILY_DATA_MOVEMENT:
        return apply_data_movement(rs, &snapshot, meta);
    case DTA_FAMILY_LOGICAL:
        return apply_logical_transfer(rs, &snapshot, meta);
    case DTA_FAMILY_ARITHMETIC:
        return apply_arithmetic_transfer(rs, &snapshot, meta);
    case DTA_FAMILY_COMPARE:
        return DTA_TRANSFER_EXACT;
    case DTA_FAMILY_SHIFT_ROTATE:
        return apply_shift_rotate_transfer(rs, &snapshot, meta);
    case DTA_FAMILY_STACK:
    case DTA_FAMILY_STRING:
        return DTA_TRANSFER_NOT_APPLICABLE;

    case DTA_FAMILY_UNSUPPORTED:
    default:
        return apply_unsupported_register_transfer(rs, &snapshot, meta);
    }
}

static uint8_t dta_width_mask(uint8_t width) {
    if (width == 0)
        return 0;
    if (width >= MAX_REG_BYTES)
        return UINT8_MAX;

    return (uint8_t)((1U << width) - 1U);
}

static bool reg_shadow_compatible(const RegShadow *left, const RegShadow *right) {
    if (!left || !right)
        return false;
    return left->registry == right->registry;
}

static bool label_array_is_valid(const RegShadow *rs, const ProvLabelId *labels, uint8_t count) {
    if (!rs || (count != 0 && !labels))
        return false;
    for (uint8_t byte = 0; byte < count; byte++) {
        if (!reg_label_is_valid(rs, labels[byte]))
            return false;
    }
    return true;
}

static void label_array_fill(ProvLabelId *labels, uint8_t count, ProvLabelId label_id) {
    if (!labels)
        return;
    for (uint8_t byte = 0; byte < count; byte++)
        labels[byte] = label_id;
}

static ProvLabelId snapshot_address_mask_join(const RegShadow *pre_regs,
                                              uint32_t address_reg_mask) {
    if (!pre_regs)
        return PROV_LABEL_ID_INVALID;
    ProvLabelId inputs[REG_COUNT * MAX_REG_BYTES];
    uint32_t count = 0;
    for (int rid = 0; rid < REG_COUNT; rid++) {
        if (!(address_reg_mask & (UINT32_C(1) << rid)))
            continue;
        for (uint8_t byte = 0; byte < MAX_REG_BYTES; byte++) {
            inputs[count++] = pre_regs->bytes[rid][byte];
        }
    }
    return reg_join_many(pre_regs, inputs, count);
}

static bool snapshot_address_mask_has_taint(const RegShadow *pre_regs, uint32_t address_reg_mask) {
    ProvLabelId joined = snapshot_address_mask_join(pre_regs, address_reg_mask);
    return joined != PROV_LABEL_ID_INVALID && reg_label_may_be_tainted(pre_regs, joined);
}

bool dta_address_mask_is_tainted(const RegShadow *pre_regs, uint32_t address_reg_mask) {
    return snapshot_address_mask_has_taint(pre_regs, address_reg_mask);
}

static uint8_t label_array_taint_mask(const RegShadow *rs, const ProvLabelId *labels,
                                      uint8_t width) {
    uint8_t result = 0;
    if (!rs || !labels)
        return result;
    for (uint8_t byte = 0; byte < width; byte++) {
        if (reg_label_may_be_tainted(rs, labels[byte])) {
            result |= (uint8_t)(1U << byte);
        }
    }
    return result;
}

static ProvLabelId reg_as_address_dependency(const RegShadow *rs, ProvLabelId label_id) {
    if (rs && rs->registry) {
        return prov_label_as_address_dependency(rs->registry, label_id);
    }
    return label_id == PROV_LABEL_CLEAN ? PROV_LABEL_CLEAN : PROV_LABEL_UNKNOWN;
}

uint8_t dta_effective_mem_read_taint(const RegShadow *pre_regs, const InsnMeta *meta,
                                     uint8_t mem_taint_mask, uint8_t mem_width) {
    uint8_t valid_bytes = dta_width_mask(mem_width);
    uint8_t raw = mem_taint_mask & valid_bytes;
    if (!pre_regs || !meta || mem_width == 0 || mem_width > MAX_REG_BYTES) {
        return raw;
    }
    ProvLabelId input[MAX_REG_BYTES];
    ProvLabelId output[MAX_REG_BYTES];
    ProvLabelId unknown = reg_unknown_label(pre_regs);
    for (uint8_t byte = 0; byte < mem_width; byte++) {
        input[byte] = (raw & (uint8_t)(1U << byte)) ? unknown : PROV_LABEL_CLEAN;
    }
    if (!dta_effective_mem_read_labels(pre_regs, meta, input, mem_width, output)) {
        return valid_bytes;
    }
    return label_array_taint_mask(pre_regs, output, mem_width);
}

bool dta_effective_mem_read_labels(const RegShadow *pre_regs, const InsnMeta *meta,
                                   const ProvLabelId *mem_labels, uint8_t mem_width,
                                   ProvLabelId *out_labels) {
    if (!pre_regs || !meta || !out_labels || mem_width == 0 || mem_width > MAX_REG_BYTES ||
        !label_array_is_valid(pre_regs, mem_labels, mem_width)) {
        return false;
    }
    ProvLabelId address = snapshot_address_mask_join(pre_regs, meta->mem_read_addr_reg_mask);
    if (address == PROV_LABEL_ID_INVALID)
        return false;
    ProvLabelId address_dependency = reg_as_address_dependency(pre_regs, address);
    if (address_dependency == PROV_LABEL_ID_INVALID)
        return false;
    ProvLabelId result[MAX_REG_BYTES];
    for (uint8_t byte = 0; byte < mem_width; byte++) {
        result[byte] = reg_join_labels(pre_regs, mem_labels[byte], address_dependency);
        if (result[byte] == PROV_LABEL_ID_INVALID)
            return false;
    }
    memcpy(out_labels, result, mem_width * sizeof(*out_labels));
    return true;
}

static void snapshot_reg_sources_labels(const RegShadow *pre_regs, const InsnMeta *meta,
                                        uint8_t width, ProvLabelId *out_labels) {
    label_array_fill(out_labels, width, PROV_LABEL_CLEAN);
    if (!pre_regs || !meta || !out_labels)
        return;
    for (uint8_t read_index = 0; read_index < meta->reg_read_count; read_index++) {
        RegSlice source = meta->reg_reads[read_index];
        if (!reg_slice_is_valid(source))
            continue;
        uint8_t copy_width = source.width < width ? source.width : width;
        for (uint8_t byte = 0; byte < copy_width; byte++) {
            ProvLabelId source_label = snapshot_slice_label(pre_regs, source, byte);
            out_labels[byte] = reg_join_labels(pre_regs, out_labels[byte], source_label);
        }
    }
}

static void snapshot_slice_labels(const RegShadow *pre_regs, RegSlice slice,
                                  ProvLabelId *out_labels) {
    if (!out_labels || !reg_slice_is_valid(slice))
        return;
    for (uint8_t byte = 0; byte < slice.width; byte++) {
        out_labels[byte] = snapshot_slice_label(pre_regs, slice, byte);
    }
}

static void write_slice_labels(RegShadow *rs, RegSlice slice, const ProvLabelId *labels) {
    if (!rs || !labels || !reg_slice_is_valid(slice))
        return;
    for (uint8_t byte = 0; byte < slice.width; byte++) {
        write_slice_label(rs, slice, byte, labels[byte]);
    }
    rs->src_ip[slice.reg_id] = 0;
}

static void snapshot_accumulator_labels(const RegShadow *pre_regs, uint8_t width,
                                        ProvLabelId *out_labels) {
    if (!pre_regs || !out_labels || width == 0 || width > MAX_REG_BYTES) {
        return;
    }
    for (uint8_t byte = 0; byte < width; byte++) {
        out_labels[byte] = pre_regs->bytes[REG_RAX][byte];
    }
}

static bool prefix_dependency_labels(const RegShadow *pre_regs, const ProvLabelId *input,
                                     uint8_t width, ProvLabelId *output) {
    if (!pre_regs || !input || !output)
        return false;
    ProvLabelId prefix = PROV_LABEL_CLEAN;
    for (uint8_t byte = 0; byte < width; byte++) {
        prefix = reg_join_labels(pre_regs, prefix, input[byte]);
        if (prefix == PROV_LABEL_ID_INVALID)
            return false;
        output[byte] = prefix;
    }
    return true;
}

bool dta_apply_leave32_labels(RegShadow *regs, const RegShadow *pre_regs,
                               const ProvLabelId *popped_labels, uint64_t ip) {
    if (!reg_shadow_compatible(regs, pre_regs) ||
        !label_array_is_valid(pre_regs, popped_labels, 4)) {
        return false;
    }
    RegShadow before = *pre_regs;
    RegShadow updated = *regs;
    RegSlice ebp = reg_slice_from_x86(X86_REG_EBP, 4);
    RegSlice esp = reg_slice_from_x86(X86_REG_ESP, 4);
    ProvLabelId frame[4], stack[4];
    /* LEAVE ends with ESP = old EBP + 4. Carries can make every higher
     * stack-pointer byte depend on lower frame-pointer bytes. */
    if (!reg_slice_load_labels(&before, ebp, frame) ||
        !label_array_is_valid(&before, frame, 4) ||
        !prefix_dependency_labels(&before, frame, 4, stack) ||
        !reg_slice_store_labels(&updated, esp, stack, 4, ip) ||
        !reg_slice_store_labels(&updated, ebp, popped_labels, 4, ip)) {
        return false;
    }
    *regs = updated;
    return true;
}

static ProvLabelId join_known_inputs(const RegShadow *pre_regs, const InsnMeta *meta,
                                     const ProvLabelId *extra, uint8_t extra_count) {
    ProvLabelId joined = meta_read_state_join(pre_regs, meta);
    if (joined == PROV_LABEL_ID_INVALID)
        joined = PROV_LABEL_CLEAN;
    if (extra_count != 0) {
        ProvLabelId extra_join = reg_join_many(pre_regs, extra, extra_count);
        joined = reg_join_labels(pre_regs, joined, extra_join);
    }
    return joined;
}

static DtaTransferResult write_incomplete_destination(RegShadow *rs, const RegShadow *pre_regs,
                                                      const InsnMeta *meta, RegSlice dst,
                                                      const ProvLabelId *extra, uint8_t extra_count,
                                                      uint64_t reasons) {
    if (!rs || !pre_regs || !meta || !reg_slice_is_valid(dst)) {
        return DTA_TRANSFER_NOT_APPLICABLE;
    }
    ProvLabelId joined = join_known_inputs(pre_regs, meta, extra, extra_count);
    if (joined == PROV_LABEL_ID_INVALID)
        joined = reg_unknown_label(pre_regs);
    joined = reg_mark_incomplete(pre_regs, joined, PROV_COMPLETE_ALL, reasons);
    fill_slice_label(rs, dst, joined);
    return DTA_TRANSFER_INCOMPLETE;
}

static void mark_label_array_incomplete(const RegShadow *pre_regs, ProvLabelId *labels,
                                        uint8_t width, uint64_t reasons) {
    if (!pre_regs || !labels)
        return;
    for (uint8_t byte = 0; byte < width; byte++) {
        labels[byte] = reg_mark_incomplete(pre_regs, labels[byte], PROV_COMPLETE_ALL, reasons);
    }
}

DtaTransferResult dta_apply_mem_read_labels(RegShadow *rs, const RegShadow *pre_regs,
                                            const InsnMeta *meta, const ProvLabelId *mem_labels,
                                            uint8_t mem_width) {
    if (!rs || !pre_regs || !meta || mem_width == 0 || mem_width > MAX_REG_BYTES ||
        !reg_shadow_compatible(rs, pre_regs) ||
        !label_array_is_valid(pre_regs, mem_labels, mem_width)) {
        return DTA_TRANSFER_NOT_APPLICABLE;
    }
    RegShadow snapshot = *pre_regs;
    RegSlice dst = meta_first_reg_write(meta);
    if (!reg_slice_is_valid(dst)) {
        if (meta->family == DTA_FAMILY_UNSUPPORTED) {
            return apply_unsupported_register_transfer(rs, &snapshot, meta);
        }
        return DTA_TRANSFER_NOT_APPLICABLE;
    }
    ProvLabelId effective_mem[MAX_REG_BYTES];
    if (!dta_effective_mem_read_labels(&snapshot, meta, mem_labels, mem_width, effective_mem)) {
        return write_incomplete_destination(rs, &snapshot, meta, dst, mem_labels, mem_width,
                                            PROV_INCOMPLETE_UNRESOLVED_MEMORY);
    }
    bool address_tainted = snapshot_address_mask_has_taint(&snapshot, meta->mem_read_addr_reg_mask);
    ProvLabelId destination_before[MAX_REG_BYTES];
    ProvLabelId register_sources[MAX_REG_BYTES];
    snapshot_slice_labels(&snapshot, dst, destination_before);
    snapshot_reg_sources_labels(&snapshot, meta, dst.width, register_sources);

    switch (meta->family) {
    case DTA_FAMILY_DATA_MOVEMENT:
        switch (meta->insn_id) {
        case X86_INS_MOV:
        case X86_INS_XCHG:
            if (mem_width != dst.width) {
                return write_incomplete_destination(rs, &snapshot, meta, dst, effective_mem,
                                                    mem_width, PROV_INCOMPLETE_UNKNOWN);
            }
            propagate_mem_labels2reg(rs, dst, effective_mem, mem_width, meta->insn_id, true);
            return address_tainted ? DTA_TRANSFER_CONSERVATIVE : DTA_TRANSFER_EXACT;
        case X86_INS_MOVZX:
        case X86_INS_MOVSX:
            if (mem_width > dst.width) {
                return write_incomplete_destination(rs, &snapshot, meta, dst, effective_mem,
                                                    mem_width, PROV_INCOMPLETE_UNKNOWN);
            }
            propagate_mem_labels2reg(rs, dst, effective_mem, mem_width, meta->insn_id, true);
            return address_tainted ? DTA_TRANSFER_CONSERVATIVE : DTA_TRANSFER_EXACT;
        default:
            return write_incomplete_destination(rs, &snapshot, meta, dst, effective_mem, mem_width,
                                                PROV_INCOMPLETE_UNSUPPORTED_INSTRUCTION);
        }
    case DTA_FAMILY_LOGICAL: {
        if (mem_width != dst.width) {
            return write_incomplete_destination(rs, &snapshot, meta, dst, effective_mem, mem_width,
                                                PROV_INCOMPLETE_UNKNOWN);
        }
        if (meta->insn_id != X86_INS_XOR && meta->insn_id != X86_INS_AND &&
            meta->insn_id != X86_INS_OR) {
            return write_incomplete_destination(rs, &snapshot, meta, dst, effective_mem, mem_width,
                                                PROV_INCOMPLETE_UNSUPPORTED_INSTRUCTION);
        }
        ProvLabelId output[MAX_REG_BYTES];
        for (uint8_t byte = 0; byte < dst.width; byte++) {
            ProvLabelId inputs[3] = {destination_before[byte], effective_mem[byte],
                                     register_sources[byte]};
            output[byte] = reg_join_many(&snapshot, inputs, 3);
        }
        write_slice_labels(rs, dst, output);
        return DTA_TRANSFER_CONSERVATIVE;
    }
    case DTA_FAMILY_ARITHMETIC: {
        if (mem_width != dst.width) {
            return write_incomplete_destination(rs, &snapshot, meta, dst, effective_mem, mem_width,
                                                PROV_INCOMPLETE_UNKNOWN);
        }
        switch (meta->insn_id) {
        case X86_INS_ADD:
        case X86_INS_SUB:
        case X86_INS_ADC:
        case X86_INS_SBB:
        case X86_INS_INC:
        case X86_INS_DEC:
        case X86_INS_NEG:
            break;
        default:
            return write_incomplete_destination(rs, &snapshot, meta, dst, effective_mem, mem_width,
                                                PROV_INCOMPLETE_UNSUPPORTED_INSTRUCTION);
        }
        ProvLabelId base[MAX_REG_BYTES];
        ProvLabelId output[MAX_REG_BYTES];
        for (uint8_t byte = 0; byte < dst.width; byte++) {
            ProvLabelId inputs[3] = {destination_before[byte], effective_mem[byte],
                                     register_sources[byte]};
            base[byte] = reg_join_many(&snapshot, inputs, 3);
        }
        if (!prefix_dependency_labels(&snapshot, base, dst.width, output)) {
            return write_incomplete_destination(rs, &snapshot, meta, dst, effective_mem, mem_width,
                                                PROV_INCOMPLETE_UNKNOWN);
        }
        bool carry_input_missing = meta->insn_id == X86_INS_ADC || meta->insn_id == X86_INS_SBB;
        if (carry_input_missing) {
            mark_label_array_incomplete(&snapshot, output, dst.width,
                                        PROV_INCOMPLETE_IMPLICIT_OPERAND);
        }
        write_slice_labels(rs, dst, output);
        return carry_input_missing ? DTA_TRANSFER_INCOMPLETE : DTA_TRANSFER_CONSERVATIVE;
    }
    case DTA_FAMILY_SHIFT_ROTATE: {
        ProvLabelId inputs[MAX_REG_BYTES * 3];
        uint32_t count = 0;
        for (uint8_t byte = 0; byte < dst.width; byte++) {
            inputs[count++] = destination_before[byte];
            inputs[count++] = register_sources[byte];
        }
        for (uint8_t byte = 0; byte < mem_width; byte++) {
            inputs[count++] = effective_mem[byte];
        }
        ProvLabelId joined = reg_join_many(&snapshot, inputs, count);
        bool carry_input_missing = meta->insn_id == X86_INS_RCL || meta->insn_id == X86_INS_RCR;
        if (carry_input_missing) {
            joined = reg_mark_incomplete(&snapshot, joined, PROV_COMPLETE_ALL,
                                         PROV_INCOMPLETE_IMPLICIT_OPERAND);
        }
        fill_slice_label(rs, dst, joined);
        return carry_input_missing ? DTA_TRANSFER_INCOMPLETE : DTA_TRANSFER_CONSERVATIVE;
    }
    case DTA_FAMILY_STACK:
        if (meta->insn_id != X86_INS_POP || mem_width != dst.width) {
            return DTA_TRANSFER_NOT_APPLICABLE;
        }
        propagate_mem_labels2reg(rs, dst, effective_mem, mem_width, X86_INS_POP, true);
        return address_tainted ? DTA_TRANSFER_CONSERVATIVE : DTA_TRANSFER_EXACT;
    case DTA_FAMILY_STRING:
        switch (meta->insn_id) {
        case X86_INS_LODSB:
        case X86_INS_LODSW:
        case X86_INS_LODSD:
        case X86_INS_LODSQ: {
            if (meta->string_element_size == 0 || meta->string_element_size != mem_width ||
                dst.reg_id != REG_RAX || dst.byte_offset != 0 || dst.width != mem_width) {
                return DTA_TRANSFER_NOT_APPLICABLE;
            }
            propagate_mem_labels2reg(rs, dst, effective_mem, mem_width, X86_INS_MOV, true);
            RegSlice source_index = reg_slice_from_x86(X86_REG_ESI, 4);
            ProvLabelId source_before[4];
            ProvLabelId source_after[4];
            snapshot_slice_labels(&snapshot, source_index, source_before);
            if (!prefix_dependency_labels(&snapshot, source_before, 4, source_after)) {
                return DTA_TRANSFER_INCOMPLETE;
            }
            write_slice_labels(rs, source_index, source_after);
            return DTA_TRANSFER_CONSERVATIVE;
        }
        default:
            return DTA_TRANSFER_NOT_APPLICABLE;
        }
    case DTA_FAMILY_COMPARE:
        return DTA_TRANSFER_NOT_APPLICABLE;
    case DTA_FAMILY_UNSUPPORTED:
    default:
        return write_incomplete_destination(rs, &snapshot, meta, dst, effective_mem, mem_width,
                                            PROV_INCOMPLETE_UNSUPPORTED_INSTRUCTION);
    }
}

static bool explicit_reg_source_covers_width(const InsnMeta *meta, uint8_t width) {
    if (!meta || meta->reg_read_count == 0)
        return false;
    for (uint8_t index = 0; index < meta->reg_read_count; index++) {
        RegSlice source = meta->reg_reads[index];
        if (reg_slice_is_valid(source) && source.width >= width)
            return true;
    }
    return false;
}

DtaTransferResult dta_apply_mem_read_transfer(RegShadow *rs, const RegShadow *pre_regs,
                                              const InsnMeta *meta, uint8_t mem_taint_mask,
                                              uint8_t mem_width) {
    if (!rs || !pre_regs || mem_width == 0 || mem_width > MAX_REG_BYTES) {
        return DTA_TRANSFER_NOT_APPLICABLE;
    }
    ProvLabelId labels[MAX_REG_BYTES];
    ProvLabelId unknown = reg_unknown_label(pre_regs);
    for (uint8_t byte = 0; byte < mem_width; byte++) {
        labels[byte] = (mem_taint_mask & (uint8_t)(1U << byte)) ? unknown : PROV_LABEL_CLEAN;
    }
    return dta_apply_mem_read_labels(rs, pre_regs, meta, labels, mem_width);
}

static void taint_mask_to_labels(const RegShadow *rs, uint8_t taint_mask, uint8_t width,
                                 ProvLabelId *out_labels) {
    if (!rs || !out_labels || width == 0 || width > MAX_REG_BYTES) {
        return;
    }
    ProvLabelId unknown = reg_unknown_label(rs);
    for (uint8_t byte = 0; byte < width; byte++) {
        out_labels[byte] = (taint_mask & (uint8_t)(1U << byte)) ? unknown : PROV_LABEL_CLEAN;
    }
}

static uint8_t labels_to_taint_mask(const RegShadow *rs, const ProvLabelId *labels, uint8_t width) {
    if (!rs || !labels || width == 0 || width > MAX_REG_BYTES) {
        return 0;
    }
    uint8_t result = 0;
    for (uint8_t byte = 0; byte < width; byte++) {
        if (reg_label_may_be_tainted(rs, labels[byte])) {
            result |= (uint8_t)(1U << byte);
        }
    }
    return result;
}

static DtaTransferResult
fill_incomplete_memory_result(const RegShadow *pre_regs, const InsnMeta *meta,
                              const ProvLabelId *old_mem_labels,
                              const ProvLabelId *source_mem_labels, bool source_mem_valid,
                              uint8_t width, uint64_t reasons, ProvLabelId *result_labels) {
    ProvLabelId inputs[(MAX_REG_BYTES * 2) + (MAX_INSN_REG_SLICES * MAX_REG_BYTES)];
    uint32_t count = 0;
    for (uint8_t byte = 0; byte < width; byte++) {
        inputs[count++] = old_mem_labels[byte];
    }
    if (source_mem_valid) {
        for (uint8_t byte = 0; byte < width; byte++) {
            inputs[count++] = source_mem_labels[byte];
        }
    }
    if (meta->reg_read_count > 0) {
        for (uint8_t read = 0; read < meta->reg_read_count; read++) {
            RegSlice slice = meta->reg_reads[read];
            if (!reg_slice_is_valid(slice))
                continue;
            for (uint8_t byte = 0; byte < slice.width; byte++) {
                inputs[count++] = snapshot_slice_label(pre_regs, slice, byte);
            }
        }
    }
    ProvLabelId joined = reg_join_many(pre_regs, inputs, count);
    if (joined == PROV_LABEL_ID_INVALID)
        joined = reg_unknown_label(pre_regs);
    joined = reg_mark_incomplete(pre_regs, joined, PROV_COMPLETE_ALL, reasons);
    label_array_fill(result_labels, width, joined);
    return DTA_TRANSFER_INCOMPLETE;
}

DtaTransferResult dta_compute_mem_write_labels(const RegShadow *pre_regs, const InsnMeta *meta,
                                               const ProvLabelId *old_mem_labels,
                                               bool source_mem_valid,
                                               const ProvLabelId *source_mem_labels, uint8_t width,
                                               ProvLabelId *result_labels) {
    if (!pre_regs || !meta || !old_mem_labels || !result_labels || width == 0 ||
        width > MAX_REG_BYTES || !label_array_is_valid(pre_regs, old_mem_labels, width) ||
        (source_mem_valid && !label_array_is_valid(pre_regs, source_mem_labels, width))) {
        return DTA_TRANSFER_NOT_APPLICABLE;
    }
    ProvLabelId old_memory[MAX_REG_BYTES];
    ProvLabelId source_memory[MAX_REG_BYTES];
    ProvLabelId register_sources[MAX_REG_BYTES];
    ProvLabelId output[MAX_REG_BYTES];
    memcpy(old_memory, old_mem_labels, width * sizeof(*old_memory));
    if (source_mem_valid) {
        memcpy(source_memory, source_mem_labels, width * sizeof(*source_memory));
    } else {
        label_array_fill(source_memory, width, PROV_LABEL_CLEAN);
    }
    snapshot_reg_sources_labels(pre_regs, meta, width, register_sources);
    switch (meta->family) {
    case DTA_FAMILY_DATA_MOVEMENT:
        switch (meta->insn_id) {
        case X86_INS_MOV:
            if (meta->has_imm_operand && meta->reg_read_count == 0) {
                label_array_fill(output, width, PROV_LABEL_CLEAN);
                break;
            }
            if (explicit_reg_source_covers_width(meta, width)) {
                memcpy(output, register_sources, width * sizeof(*output));
                break;
            }
            return fill_incomplete_memory_result(pre_regs, meta, old_memory, source_memory,
                                                 source_mem_valid, width,
                                                 PROV_INCOMPLETE_IMPLICIT_OPERAND, result_labels);
        case X86_INS_XCHG:
            if (explicit_reg_source_covers_width(meta, width)) {
                memcpy(output, register_sources, width * sizeof(*output));
                break;
            }
            return fill_incomplete_memory_result(pre_regs, meta, old_memory, source_memory,
                                                 source_mem_valid, width,
                                                 PROV_INCOMPLETE_IMPLICIT_OPERAND, result_labels);
        default:
            return fill_incomplete_memory_result(
                pre_regs, meta, old_memory, source_memory, source_mem_valid, width,
                PROV_INCOMPLETE_UNSUPPORTED_INSTRUCTION, result_labels);
        }
        memcpy(result_labels, output, width * sizeof(*result_labels));
        return DTA_TRANSFER_EXACT;
    case DTA_FAMILY_LOGICAL:
        switch (meta->insn_id) {
        case X86_INS_NOT:
            memcpy(result_labels, old_memory, width * sizeof(*result_labels));
            return DTA_TRANSFER_EXACT;
        case X86_INS_XOR:
        case X86_INS_AND:
        case X86_INS_OR:
            if (meta->reg_read_count == 0 && !meta->has_imm_operand) {
                return fill_incomplete_memory_result(
                    pre_regs, meta, old_memory, source_memory, source_mem_valid, width,
                    PROV_INCOMPLETE_IMPLICIT_OPERAND, result_labels);
            }
            for (uint8_t byte = 0; byte < width; byte++) {
                output[byte] = reg_join_labels(pre_regs, old_memory[byte], register_sources[byte]);
            }
            memcpy(result_labels, output, width * sizeof(*result_labels));
            return DTA_TRANSFER_CONSERVATIVE;
        default:
            return fill_incomplete_memory_result(
                pre_regs, meta, old_memory, source_memory, source_mem_valid, width,
                PROV_INCOMPLETE_UNSUPPORTED_INSTRUCTION, result_labels);
        }
    case DTA_FAMILY_ARITHMETIC:
        switch (meta->insn_id) {
        case X86_INS_ADD:
        case X86_INS_SUB:
        case X86_INS_ADC:
        case X86_INS_SBB:
        case X86_INS_INC:
        case X86_INS_DEC:
        case X86_INS_NEG:
            break;
        default:
            return fill_incomplete_memory_result(
                pre_regs, meta, old_memory, source_memory, source_mem_valid, width,
                PROV_INCOMPLETE_UNSUPPORTED_INSTRUCTION, result_labels);
        }
        if ((meta->insn_id == X86_INS_ADD || meta->insn_id == X86_INS_SUB ||
             meta->insn_id == X86_INS_ADC || meta->insn_id == X86_INS_SBB) &&
            meta->reg_read_count == 0 && !meta->has_imm_operand) {
            return fill_incomplete_memory_result(pre_regs, meta, old_memory, source_memory,
                                                 source_mem_valid, width,
                                                 PROV_INCOMPLETE_IMPLICIT_OPERAND, result_labels);
        }
        for (uint8_t byte = 0; byte < width; byte++) {
            output[byte] = reg_join_labels(pre_regs, old_memory[byte], register_sources[byte]);
        }
        if (!prefix_dependency_labels(pre_regs, output, width, result_labels)) {
            return DTA_TRANSFER_NOT_APPLICABLE;
        }
        if (meta->insn_id == X86_INS_ADC || meta->insn_id == X86_INS_SBB) {
            mark_label_array_incomplete(pre_regs, result_labels, width,
                                        PROV_INCOMPLETE_IMPLICIT_OPERAND);
            return DTA_TRANSFER_INCOMPLETE;
        }
        return DTA_TRANSFER_CONSERVATIVE;
    case DTA_FAMILY_SHIFT_ROTATE: {
        if (meta->has_mem_read && meta->has_mem_write && meta->reg_read_count == 0 &&
            immediate_shift_labels(pre_regs, meta, old_memory, width, output)) {
            memcpy(result_labels, output, width * sizeof(*result_labels));
            return DTA_TRANSFER_CONSERVATIVE;
        }
        ProvLabelId inputs[MAX_REG_BYTES * 2];
        uint32_t count = 0;
        for (uint8_t byte = 0; byte < width; byte++) {
            inputs[count++] = old_memory[byte];
            inputs[count++] = register_sources[byte];
        }
        ProvLabelId joined = reg_join_many(pre_regs, inputs, count);
        if (meta->insn_id == X86_INS_RCL || meta->insn_id == X86_INS_RCR) {
            joined = reg_mark_incomplete(pre_regs, joined, PROV_COMPLETE_ALL,
                                         PROV_INCOMPLETE_IMPLICIT_OPERAND);
            label_array_fill(result_labels, width, joined);
            return DTA_TRANSFER_INCOMPLETE;
        }
        label_array_fill(result_labels, width, joined);
        return DTA_TRANSFER_CONSERVATIVE;
    }
    case DTA_FAMILY_STACK:
        switch (meta->insn_id) {
        case X86_INS_CALL:
            label_array_fill(result_labels, width, PROV_LABEL_CLEAN);
            return DTA_TRANSFER_EXACT;
        case X86_INS_PUSHF:
        case X86_INS_PUSHFD:
        case X86_INS_PUSHFQ:
            return fill_incomplete_memory_result(pre_regs, meta, old_memory, source_memory,
                                                 source_mem_valid, width,
                                                 PROV_INCOMPLETE_IMPLICIT_OPERAND, result_labels);
        case X86_INS_PUSH:
            if (meta->has_mem_read) {
                if (source_mem_valid) {
                    memcpy(result_labels, source_memory, width * sizeof(*result_labels));
                    return DTA_TRANSFER_EXACT;
                }
                return fill_incomplete_memory_result(
                    pre_regs, meta, old_memory, source_memory, false, width,
                    PROV_INCOMPLETE_UNRESOLVED_MEMORY, result_labels);
            }
            if (meta->has_imm_operand) {
                label_array_fill(result_labels, width, PROV_LABEL_CLEAN);
                return DTA_TRANSFER_EXACT;
            }
            if (explicit_reg_source_covers_width(meta, width)) {
                memcpy(result_labels, register_sources, width * sizeof(*result_labels));
                return DTA_TRANSFER_EXACT;
            }
            return fill_incomplete_memory_result(pre_regs, meta, old_memory, source_memory,
                                                 source_mem_valid, width,
                                                 PROV_INCOMPLETE_IMPLICIT_OPERAND, result_labels);
        case X86_INS_POP:
            if (source_mem_valid) {
                memcpy(result_labels, source_memory, width * sizeof(*result_labels));
                return DTA_TRANSFER_EXACT;
            }
            return fill_incomplete_memory_result(pre_regs, meta, old_memory, source_memory, false,
                                                 width, PROV_INCOMPLETE_UNRESOLVED_MEMORY,
                                                 result_labels);
        default:
            return fill_incomplete_memory_result(
                pre_regs, meta, old_memory, source_memory, source_mem_valid, width,
                PROV_INCOMPLETE_UNSUPPORTED_INSTRUCTION, result_labels);
        }
    case DTA_FAMILY_STRING:
        switch (meta->insn_id) {
        case X86_INS_MOVSB:
        case X86_INS_MOVSW:
        case X86_INS_MOVSD:
        case X86_INS_MOVSQ:
            if (source_mem_valid) {
                memcpy(result_labels, source_memory, width * sizeof(*result_labels));
                return DTA_TRANSFER_EXACT;
            }
            return fill_incomplete_memory_result(pre_regs, meta, old_memory, source_memory, false,
                                                 width, PROV_INCOMPLETE_UNRESOLVED_MEMORY,
                                                 result_labels);
        case X86_INS_STOSB:
        case X86_INS_STOSW:
        case X86_INS_STOSD:
        case X86_INS_STOSQ:
            snapshot_accumulator_labels(pre_regs, width, result_labels);
            return DTA_TRANSFER_EXACT;
        default:
            return fill_incomplete_memory_result(
                pre_regs, meta, old_memory, source_memory, source_mem_valid, width,
                PROV_INCOMPLETE_UNSUPPORTED_INSTRUCTION, result_labels);
        }
    case DTA_FAMILY_COMPARE:
        return DTA_TRANSFER_NOT_APPLICABLE;
    case DTA_FAMILY_UNSUPPORTED:
    default:
        return fill_incomplete_memory_result(
            pre_regs, meta, old_memory, source_memory, source_mem_valid, width,
            PROV_INCOMPLETE_UNSUPPORTED_INSTRUCTION, result_labels);
    }
}

DtaTransferResult dta_compute_mem_write_taint(const RegShadow *pre_regs, const InsnMeta *meta,
                                              uint8_t old_mem_taint, bool source_mem_valid,
                                              uint8_t source_mem_taint, uint8_t width,
                                              uint8_t *result_taint) {
    if (!pre_regs || !meta || !result_taint || width == 0 || width > MAX_REG_BYTES) {
        return DTA_TRANSFER_NOT_APPLICABLE;
    }
    ProvLabelId old_mem_labels[MAX_REG_BYTES];
    ProvLabelId source_mem_labels[MAX_REG_BYTES];
    ProvLabelId result_labels[MAX_REG_BYTES];
    //old mem mask to label
    taint_mask_to_labels(pre_regs, old_mem_taint, width, old_mem_labels);
    if (source_mem_valid) {
        taint_mask_to_labels(pre_regs, source_mem_taint, width, source_mem_labels);
    } else {
        label_array_fill(source_mem_labels, width, PROV_LABEL_CLEAN);
    }
    DtaTransferResult result = dta_compute_mem_write_labels(
        pre_regs, meta, old_mem_labels, source_mem_valid, source_mem_labels, width, result_labels);
    if (result == DTA_TRANSFER_NOT_APPLICABLE) {
        return result;
    }
    //labels to old bool mask
    *result_taint = labels_to_taint_mask(pre_regs, result_labels, width);
    return result;
}

static GHashTable *g_meta_by_id = NULL;
static GHashTable *g_meta_latest_by_pc = NULL;
static MetaId g_next_meta_id = 1;
static GMutex g_meta_lock;
static bool g_meta_lock_initialized = false;

void meta_init(void) {
    if (g_meta_by_id || g_meta_latest_by_pc)
        return;
    g_mutex_init(&g_meta_lock);
    g_meta_lock_initialized = true;
    g_meta_by_id = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, g_free);
    g_meta_latest_by_pc = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, NULL);
    g_next_meta_id = 1;
}

void meta_free(void) {
    if (!g_meta_lock_initialized)
        return;
    g_mutex_lock(&g_meta_lock);
    if (g_meta_latest_by_pc) {
        g_hash_table_destroy(g_meta_latest_by_pc);
        g_meta_latest_by_pc = NULL;
    }
    if (g_meta_by_id) {
        g_hash_table_destroy(g_meta_by_id);
        g_meta_by_id = NULL;
    }
    g_next_meta_id = 1;
    g_mutex_unlock(&g_meta_lock);
    g_mutex_clear(&g_meta_lock);
    g_meta_lock_initialized = false;
}

const InsnMeta *meta_store(uint64_t pc, InsnMeta *meta) {
    if (!meta)
        return NULL;
    if (!g_meta_lock_initialized || meta->size == 0 || meta->size > MAX_INSN_BYTES) {
        g_free(meta);
        return NULL;
    }
    g_mutex_lock(&g_meta_lock);
    if (!g_meta_by_id || !g_meta_latest_by_pc) {
        g_mutex_unlock(&g_meta_lock);
        g_free(meta);
        return NULL;
    }
    gint64 pc_lookup_key = (gint64)pc;
    const InsnMeta *latest = g_hash_table_lookup(g_meta_latest_by_pc, &pc_lookup_key);
    if (latest && latest->size == meta->size &&
        memcmp(latest->instr_bytes, meta->instr_bytes, meta->size) == 0) {
        g_mutex_unlock(&g_meta_lock);
        g_free(meta);
        return latest;
    }
    if (g_next_meta_id == META_ID_INVALID) {
        g_mutex_unlock(&g_meta_lock);
        g_free(meta);
        return NULL;
    }

    meta->pc = pc;
    meta->meta_id = g_next_meta_id++;
    gint64 *id_key = g_new(gint64, 1);
    gint64 *pc_key = g_new(gint64, 1);
    *id_key = (gint64)meta->meta_id;
    *pc_key = (gint64)pc;

    g_hash_table_insert(g_meta_by_id, id_key, meta);
    g_hash_table_replace(g_meta_latest_by_pc, pc_key, meta);
    g_mutex_unlock(&g_meta_lock);
    return meta;
}

const InsnMeta *meta_lookup(uint64_t pc) {
    if (!g_meta_lock_initialized)
        return NULL;

    gint64 key = (gint64)pc;
    g_mutex_lock(&g_meta_lock);
    const InsnMeta *meta =
        g_meta_latest_by_pc ? g_hash_table_lookup(g_meta_latest_by_pc, &key) : NULL;
    g_mutex_unlock(&g_meta_lock);
    return meta;
}

const InsnMeta *meta_lookup_id(MetaId meta_id) {
    if (!g_meta_lock_initialized || meta_id == META_ID_INVALID) {
        return NULL;
    }
    gint64 key = (gint64)meta_id;
    g_mutex_lock(&g_meta_lock);
    const InsnMeta *meta = g_meta_by_id ? g_hash_table_lookup(g_meta_by_id, &key) : NULL;
    g_mutex_unlock(&g_meta_lock);
    return meta;
}

static bool same_reg_slice(const cs_x86_op *left, const cs_x86_op *right) {
    if (!left || !right || left->type != X86_OP_REG || right->type != X86_OP_REG) {
        return false;
    }
    if (left->size == 0 || left->size != right->size) {
        return false;
    }
    RegSlice left_slice = reg_slice_from_x86(left->reg, left->size);
    RegSlice right_slice = reg_slice_from_x86(right->reg, right->size);
    return reg_slice_equal(left_slice, right_slice);
}

static uint32_t x86_mem_address_reg_mask(const cs_x86_op *operand) {
    if (!operand || operand->type != X86_OP_MEM) {
        return 0;
    }
    uint32_t result = 0;
    int base = x86_reg_to_rid(operand->mem.base);
    int index = x86_reg_to_rid(operand->mem.index);
    if (base >= 0) {
        result |= 1U << base;
    }
    if (index >= 0) {
        result |= 1U << index;
    }
    return result;
}

static void append_reg_slice(RegSlice slices[MAX_INSN_REG_SLICES], uint8_t *count, RegSlice slice,
                             bool *truncated) {
    if (!count || !reg_slice_is_valid(slice)) {
        return;
    }
    for (uint8_t index = 0; index < *count; index++) {
        if (reg_slice_equal(slices[index], slice)) {
            return;
        }
    }
    if (*count >= MAX_INSN_REG_SLICES) {
        *truncated = true;
        return;
    }
    slices[*count] = slice;
    (*count)++;
}

static DtaInsnFamily classify_x86_insn(uint16_t insn_id) {
    switch (insn_id) {
    case X86_INS_MOV:
    case X86_INS_MOVZX:
    case X86_INS_MOVSX:
    case X86_INS_LEA:
    case X86_INS_XCHG:
        return DTA_FAMILY_DATA_MOVEMENT;
    case X86_INS_XOR:
    case X86_INS_AND:
    case X86_INS_OR:
    case X86_INS_NOT:
        return DTA_FAMILY_LOGICAL;
    case X86_INS_ADD:
    case X86_INS_SUB:
    case X86_INS_ADC:
    case X86_INS_SBB:
    case X86_INS_INC:
    case X86_INS_DEC:
    case X86_INS_NEG:
        return DTA_FAMILY_ARITHMETIC;
    case X86_INS_CMP:
    case X86_INS_TEST:
        return DTA_FAMILY_COMPARE;
    case X86_INS_SHL:
    case X86_INS_SAL:
    case X86_INS_SHR:
    case X86_INS_SAR:
    case X86_INS_ROL:
    case X86_INS_ROR:
    case X86_INS_RCL:
    case X86_INS_RCR:
    case X86_INS_SHLD:
    case X86_INS_SHRD:
        return DTA_FAMILY_SHIFT_ROTATE;
    case X86_INS_PUSH:
    case X86_INS_POP:
    case X86_INS_PUSHF:
    case X86_INS_PUSHFD:
    case X86_INS_PUSHFQ:
    case X86_INS_PUSHAL:
    case X86_INS_POPAL:
    case X86_INS_ENTER:
    case X86_INS_LEAVE:
    case X86_INS_CALL:
    case X86_INS_RET:
        return DTA_FAMILY_STACK;
    case X86_INS_MOVSB:
    case X86_INS_MOVSW:
    case X86_INS_MOVSD:
    case X86_INS_MOVSQ:
    case X86_INS_STOSB:
    case X86_INS_STOSW:
    case X86_INS_STOSD:
    case X86_INS_STOSQ:
    case X86_INS_LODSB:
    case X86_INS_LODSW:
    case X86_INS_LODSD:
    case X86_INS_LODSQ:
        return DTA_FAMILY_STRING;
    default:
        return DTA_FAMILY_UNSUPPORTED;
    }
}

static X86ConditionCode x86_condition_code(uint16_t insn_id) {
    switch (insn_id) {
    case X86_INS_JO:
    case X86_INS_CMOVO:
    case X86_INS_SETO:
        return X86_CC_O;
    case X86_INS_JNO:
    case X86_INS_CMOVNO:
    case X86_INS_SETNO:
        return X86_CC_NO;
    case X86_INS_JB:
    case X86_INS_CMOVB:
    case X86_INS_SETB:
        return X86_CC_B;
    case X86_INS_JAE:
    case X86_INS_CMOVAE:
    case X86_INS_SETAE:
        return X86_CC_AE;
    case X86_INS_JE:
    case X86_INS_CMOVE:
    case X86_INS_SETE:
        return X86_CC_E;
    case X86_INS_JNE:
    case X86_INS_CMOVNE:
    case X86_INS_SETNE:
        return X86_CC_NE;
    case X86_INS_JBE:
    case X86_INS_CMOVBE:
    case X86_INS_SETBE:
        return X86_CC_BE;
    case X86_INS_JA:
    case X86_INS_CMOVA:
    case X86_INS_SETA:
        return X86_CC_A;
    case X86_INS_JS:
    case X86_INS_CMOVS:
    case X86_INS_SETS:
        return X86_CC_S;
    case X86_INS_JNS:
    case X86_INS_CMOVNS:
    case X86_INS_SETNS:
        return X86_CC_NS;
    case X86_INS_JP:
    case X86_INS_CMOVP:
    case X86_INS_SETP:
        return X86_CC_P;
    case X86_INS_JNP:
    case X86_INS_CMOVNP:
    case X86_INS_SETNP:
        return X86_CC_NP;
    case X86_INS_JL:
    case X86_INS_CMOVL:
    case X86_INS_SETL:
        return X86_CC_L;
    case X86_INS_JGE:
    case X86_INS_CMOVGE:
    case X86_INS_SETGE:
        return X86_CC_GE;
    case X86_INS_JLE:
    case X86_INS_CMOVLE:
    case X86_INS_SETLE:
        return X86_CC_LE;
    case X86_INS_JG:
    case X86_INS_CMOVG:
    case X86_INS_SETG:
        return X86_CC_G;
    default:
        return X86_CC_NONE;
    }
}

static uint8_t x86_condition_flag_mask(X86ConditionCode condition) {
    switch (condition) {
    case X86_CC_O:
    case X86_CC_NO:
        return X86_FLAG_OF;
    case X86_CC_B:
    case X86_CC_AE:
        return X86_FLAG_CF;
    case X86_CC_E:
    case X86_CC_NE:
        return X86_FLAG_ZF;
    case X86_CC_BE:
    case X86_CC_A:
        return X86_FLAG_CF | X86_FLAG_ZF;
    case X86_CC_S:
    case X86_CC_NS:
        return X86_FLAG_SF;
    case X86_CC_P:
    case X86_CC_NP:
        return X86_FLAG_PF;
    case X86_CC_L:
    case X86_CC_GE:
        return X86_FLAG_SF | X86_FLAG_OF;
    case X86_CC_LE:
    case X86_CC_G:
        return X86_FLAG_ZF | X86_FLAG_SF | X86_FLAG_OF;
    case X86_CC_NONE:
    default:
        return 0;
    }
}

static bool x86_is_conditional_branch(uint16_t insn_id) {
    switch (insn_id) {
    case X86_INS_JO:
    case X86_INS_JNO:
    case X86_INS_JB:
    case X86_INS_JAE:
    case X86_INS_JE:
    case X86_INS_JNE:
    case X86_INS_JBE:
    case X86_INS_JA:
    case X86_INS_JS:
    case X86_INS_JNS:
    case X86_INS_JP:
    case X86_INS_JNP:
    case X86_INS_JL:
    case X86_INS_JGE:
    case X86_INS_JLE:
    case X86_INS_JG:
        return true;
    default:
        return false;
    }
}

static uint8_t x86_written_flag_mask(uint16_t insn_id) {
    switch (insn_id) {
    case X86_INS_ADD:
    case X86_INS_ADC:
    case X86_INS_SUB:
    case X86_INS_SBB:
    case X86_INS_CMP:
    case X86_INS_NEG:
        return X86_FLAG_TRACKED;
    case X86_INS_AND:
    case X86_INS_OR:
    case X86_INS_XOR:
    case X86_INS_TEST:
        return X86_FLAG_TRACKED;
    case X86_INS_INC:
    case X86_INS_DEC:
        return X86_FLAG_PF | X86_FLAG_AF | X86_FLAG_ZF | X86_FLAG_SF | X86_FLAG_OF;
    case X86_INS_SHL:
    case X86_INS_SAL:
    case X86_INS_SHR:
    case X86_INS_SAR:
    case X86_INS_SHLD:
    case X86_INS_SHRD:
        return X86_FLAG_TRACKED;
    case X86_INS_ROL:
    case X86_INS_ROR:
    case X86_INS_RCL:
    case X86_INS_RCR:
        return X86_FLAG_CF | X86_FLAG_OF;
    case X86_INS_IMUL:
    case X86_INS_MUL:
        return X86_FLAG_TRACKED;
    case X86_INS_DIV:
    case X86_INS_IDIV:
        return X86_FLAG_TRACKED;
    default:
        return 0;
    }
}

static bool x86_is_legacy_prefix(uint8_t byte) {
    switch (byte) {
    case 0xf0:
    case 0xf2:
    case 0xf3:
    case 0x2e:
    case 0x36:
    case 0x3e:
    case 0x26:
    case 0x64:
    case 0x65:
    case 0x66:
    case 0x67:
        return true;
    default:
        return false;
    }
}

static uint8_t x86_string_element_size(const cs_insn *insn) {
    if (!insn || insn->size == 0) {
        return 0;
    }
    bool operand_size_16 = false;
    bool rex_w = false;
    bool allow_rex =
        insn->id == X86_INS_MOVSQ || insn->id == X86_INS_STOSQ || insn->id == X86_INS_LODSQ;
    size_t opcode_index = 0;
    while (opcode_index < insn->size) {
        uint8_t byte = insn->bytes[opcode_index];
        if (byte == 0x66) {
            operand_size_16 = true;
        }
        if (allow_rex && (byte & 0xf8U) == 0x48U) {
            rex_w = true;
        }
        if (!x86_is_legacy_prefix(byte) && (!allow_rex || (byte & 0xf0U) != 0x40U)) {
            break;
        }
        opcode_index++;
    }
    if (opcode_index >= insn->size) {
        return 0;
    }
    switch (insn->bytes[opcode_index]) {
    case 0xa4:
    case 0xaa:
    case 0xac:
        return 1;
    case 0xa5:
    case 0xab:
    case 0xad:
        return rex_w ? 8 : (operand_size_16 ? 2 : 4);
    default:
        return 0;
    }
}

InsnMeta *meta_decode(const uint8_t *bytes, size_t size, uint64_t pc, csh handle) {
    if (!bytes || size == 0)
        return NULL;
    //disasm 1 instr and write it into hashtable
    cs_insn *insn;
    size_t count = cs_disasm(handle, bytes, size, pc, 1, &insn);
    if (count == 0)
        return NULL;
    if (insn->size == 0 || insn->size > MAX_INSN_BYTES || insn->size > size) {
        cs_free(insn, count);
        return NULL;
    }

    InsnMeta *m = g_new0(InsnMeta, 1);
    m->pc = pc;
    m->size = (uint8_t)insn->size;
    memcpy(m->instr_bytes, bytes, m->size);
    m->insn_id = insn->id;
    m->branch_target_reg = REG_INVALID;
    m->branch_target_slice = reg_slice_invalid();
    m->family = classify_x86_insn(insn->id);
    m->condition_code = x86_condition_code(insn->id);
    m->flags_read_mask = x86_condition_flag_mask(m->condition_code);
    if (insn->id == X86_INS_ADC || insn->id == X86_INS_SBB || insn->id == X86_INS_RCL ||
        insn->id == X86_INS_RCR) {
        m->flags_read_mask = X86_FLAG_CF;
    }
    m->flags_write_mask = x86_written_flag_mask(insn->id);
    m->is_conditional_branch = x86_is_conditional_branch(insn->id);
    m->string_element_size = x86_string_element_size(insn);
    if (m->family == DTA_FAMILY_STRING && m->string_element_size == 0) {
        m->family = DTA_FAMILY_UNSUPPORTED;
    }
    if (insn->detail) {
        //lookup on W/R flag
        cs_x86 *x86 = &insn->detail->x86;
        m->writes_df = (x86->eflags &
                        (X86_EFLAGS_MODIFY_DF | X86_EFLAGS_RESET_DF | X86_EFLAGS_SET_DF)) != 0;
        cs_regs read_regs, write_regs;
        uint8_t read_count = 0, write_count = 0;
        if (cs_regs_access(handle, insn, read_regs, &read_count, write_regs, &write_count) == CS_ERR_OK)
            for (unsigned reg = 0; reg < write_count; ++reg)
                m->writes_es |= write_regs[reg] == X86_REG_ES;
        if (insn->id == X86_INS_LES || insn->id == X86_INS_IRET ||
            insn->id == X86_INS_IRETD || insn->id == X86_INS_IRETQ ||
            ((insn->id == X86_INS_MOV || insn->id == X86_INS_POP) && x86->op_count &&
             x86->operands[0].type == X86_OP_REG && x86->operands[0].reg == X86_REG_ES))
            m->writes_es = true;
        if (m->family == DTA_FAMILY_SHIFT_ROTATE && x86->op_count >= 2) {
            const cs_x86_op *count_op = &x86->operands[x86->op_count - 1];
            m->shift_operand_width = (uint8_t)(x86->operands[0].size * 8U);
            if (count_op->type == X86_OP_IMM) {
                m->shift_count_valid = true;
                m->shift_count_is_immediate = true;
                m->shift_count_imm = (uint8_t)count_op->imm;
            } else if (count_op->type == X86_OP_REG) {
                m->shift_count_reg = reg_slice_from_x86(count_op->reg, count_op->size);
                m->shift_count_valid = reg_slice_is_valid(m->shift_count_reg);
            }
        }
        if ((m->is_conditional_branch || insn->id == X86_INS_JMP || insn->id == X86_INS_CALL) &&
            x86->op_count > 0 && x86->operands[0].type == X86_OP_IMM) {
            m->direct_target_valid = true;
            m->direct_target = (uint64_t)x86->operands[0].imm;
        }
        for (unsigned prefix_index = 0;
             prefix_index < (sizeof(x86->prefix) / sizeof(x86->prefix[0])); prefix_index++) {
            if (x86->prefix[prefix_index] == 0xf2 || x86->prefix[prefix_index] == 0xf3) {
                m->has_rep_prefix = true;
            }
        }
        //clear taint for xor and sub
        if ((insn->id == X86_INS_XOR || insn->id == X86_INS_SUB) && x86->op_count == 2 &&
            same_reg_slice(&x86->operands[0], &x86->operands[1])) {
            m->is_self_zeroing = true;
        }
        for (int i = 0; i < x86->op_count; i++) {
            cs_x86_op *op = &x86->operands[i];
            if (op->type == X86_OP_MEM) {
                uint32_t address_reg_mask = x86_mem_address_reg_mask(op);
                m->mem_addr_reg_mask |= address_reg_mask;
                if (op->access & CS_AC_READ) {
                    m->has_mem_read = true;
                    m->mem_read_addr_reg_mask |= address_reg_mask;
                }
                if (op->access & CS_AC_WRITE) {
                    m->has_mem_write = true;
                    m->mem_write_addr_reg_mask |= address_reg_mask;
                }
            } else if (op->type == X86_OP_IMM) {
                m->has_imm_operand = true;
            } else if (op->type == X86_OP_REG) {
                RegSlice slice = reg_slice_from_x86(op->reg, op->size);
                if (!reg_slice_is_valid(slice))
                    continue;
                if (op->access & CS_AC_WRITE) {
                    m->regs_written_mask |= 1U << slice.reg_id;
                    append_reg_slice(m->reg_writes, &m->reg_write_count, slice,
                                     &m->reg_slice_detail_truncated);
                }
                if (op->access & CS_AC_READ) {
                    m->regs_read_mask |= 1U << slice.reg_id;
                    append_reg_slice(m->reg_reads, &m->reg_read_count, slice,
                                     &m->reg_slice_detail_truncated);
                }
            }
        }
        if (insn->id == X86_INS_LEA) {
            m->has_mem_read = false;
            m->has_mem_write = false;
            m->mem_read_addr_reg_mask = 0;
            m->mem_write_addr_reg_mask = 0;
        }
        if (m->is_self_zeroing && m->reg_write_count == 0) {
            RegSlice dst = reg_slice_from_x86(x86->operands[0].reg, x86->operands[0].size);
            if (reg_slice_is_valid(dst)) {
                append_reg_slice(m->reg_writes, &m->reg_write_count, dst,
                                 &m->reg_slice_detail_truncated);
                m->regs_written_mask |= 1U << dst.reg_id;
            }
        }
        // Implicit regs
        // READ registers
        for (int i = 0; i < insn->detail->regs_read_count; i++) {
            int rid = x86_reg_to_rid(insn->detail->regs_read[i]);
            if (rid >= 0) {
                m->regs_read_mask |= (1U << rid);
            }
            if (insn->detail->regs_read[i] == X86_REG_EFLAGS && insn->id != X86_INS_INC &&
                insn->id != X86_INS_DEC && m->flags_read_mask == 0) {
                m->flags_read_mask = X86_FLAG_TRACKED;
            }
        }
        //WRITE registers
        for (int i = 0; i < insn->detail->regs_write_count; i++) {
            int rid = x86_reg_to_rid(insn->detail->regs_write[i]);
            if (rid >= 0) {
                m->regs_written_mask |= (1U << rid);
            }
            if (insn->detail->regs_write[i] == X86_REG_EFLAGS && m->flags_write_mask == 0) {
                m->flags_write_mask = X86_FLAG_TRACKED;
            }
            if (insn->detail->regs_write[i] == X86_REG_EFLAGS &&
                m->family == DTA_FAMILY_UNSUPPORTED)
                m->writes_df = true;
        }
        if (insn->id == X86_INS_CLD || insn->id == X86_INS_STD) {
            m->writes_df = true;
            m->flags_read_mask = m->flags_write_mask = 0;
        }
        if (insn_meta_is_plain_scasd(m)) {
            /* SCAS reads DF and writes arithmetic flags; EFLAGS is a container.
             * Keep the DTA family incomplete until its label transfer is modeled. */
            m->writes_df = false;
            m->flags_read_mask = 0;
            m->flags_write_mask = X86_FLAG_TRACKED;
            m->has_mem_read = true;
            m->mem_addr_reg_mask |= UINT32_C(1) << REG_RDI;
            m->mem_read_addr_reg_mask |= UINT32_C(1) << REG_RDI;
            RegSlice accumulator = reg_slice_from_x86(X86_REG_EAX, 4);
            RegSlice index = reg_slice_from_x86(X86_REG_EDI, 4);
            append_reg_slice(m->reg_reads, &m->reg_read_count, accumulator,
                             &m->reg_slice_detail_truncated);
            append_reg_slice(m->reg_reads, &m->reg_read_count, index,
                             &m->reg_slice_detail_truncated);
            append_reg_slice(m->reg_writes, &m->reg_write_count, index,
                             &m->reg_slice_detail_truncated);
            m->regs_read_mask |= (UINT32_C(1) << REG_RAX) | (UINT32_C(1) << REG_RDI);
            m->regs_written_mask |= UINT32_C(1) << REG_RDI;
        }
        // implicit mem access
        switch (insn->id) {
        case X86_INS_PUSH:
            m->has_mem_write = true;
            m->mem_addr_reg_mask |= 1U << REG_RSP;
            m->mem_write_addr_reg_mask |= 1U << REG_RSP;
            if (x86->op_count > 0 && x86->operands[0].type == X86_OP_MEM) {
                uint32_t source_address = x86_mem_address_reg_mask(&x86->operands[0]);
                m->has_mem_read = true;
                m->mem_addr_reg_mask |= source_address;
                m->mem_read_addr_reg_mask |= source_address;
            }
            break;
        case X86_INS_PUSHF:
        case X86_INS_PUSHFD:
        case X86_INS_PUSHFQ:
            m->has_mem_write = true;
            m->mem_addr_reg_mask |= UINT32_C(1) << REG_RSP;
            m->mem_write_addr_reg_mask |= UINT32_C(1) << REG_RSP;
            m->regs_read_mask |= UINT32_C(1) << REG_RSP;
            m->regs_written_mask |= UINT32_C(1) << REG_RSP;
            m->flags_read_mask |= X86_FLAG_TRACKED;
            break;
        case X86_INS_CALL:
            m->has_mem_write = true;
            m->mem_addr_reg_mask |= 1U << REG_RSP;
            m->mem_write_addr_reg_mask |= 1U << REG_RSP;
            if (x86->op_count > 0 && x86->operands[0].type == X86_OP_MEM) {
                uint32_t source_address = x86_mem_address_reg_mask(&x86->operands[0]);
                m->has_mem_read = true;
                m->mem_addr_reg_mask |= source_address;
                m->mem_read_addr_reg_mask |= source_address;
            }
            break;
        case X86_INS_POP:
            m->has_mem_read = true;
            m->mem_addr_reg_mask |= 1U << REG_RSP;
            m->mem_read_addr_reg_mask |= 1U << REG_RSP;
            if (x86->op_count > 0 && x86->operands[0].type == X86_OP_MEM) {
                uint32_t destination_address = x86_mem_address_reg_mask(&x86->operands[0]);
                m->has_mem_write = true;
                m->mem_addr_reg_mask |= destination_address;
                m->mem_write_addr_reg_mask |= destination_address;
            }
            break;
        case X86_INS_RET:
            m->has_mem_read = true;
            m->mem_addr_reg_mask |= 1U << REG_RSP;
            m->mem_read_addr_reg_mask |= 1U << REG_RSP;
            break;
        case X86_INS_PUSHAL:
            m->has_mem_write = true;
            m->mem_addr_reg_mask |= 1U << REG_RSP;
            m->mem_write_addr_reg_mask |= 1U << REG_RSP;
            break;
        case X86_INS_POPAL:
            m->has_mem_read = true;
            m->mem_addr_reg_mask |= 1U << REG_RSP;
            m->mem_read_addr_reg_mask |= 1U << REG_RSP;
            break;
        case X86_INS_ENTER:
            m->has_mem_read = true;
            m->has_mem_write = true;
            m->mem_addr_reg_mask |= (1U << REG_RSP) | (1U << REG_RBP);
            m->mem_read_addr_reg_mask |= (1U << REG_RSP) | (1U << REG_RBP);
            m->mem_write_addr_reg_mask |= 1U << REG_RSP;
            break;
        case X86_INS_LEAVE:
            m->has_mem_read = true;
            m->mem_addr_reg_mask |= 1U << REG_RBP;
            m->mem_read_addr_reg_mask |= 1U << REG_RBP;
            break;
        case X86_INS_STOSB:
        case X86_INS_STOSW:
        case X86_INS_STOSD:
        case X86_INS_STOSQ:
            if (m->string_element_size != 0) {
                m->has_mem_write = true;
                m->mem_addr_reg_mask |= 1U << REG_RDI;
                m->mem_write_addr_reg_mask |= 1U << REG_RDI;
            }
            break;
        case X86_INS_LODSB:
        case X86_INS_LODSW:
        case X86_INS_LODSD:
        case X86_INS_LODSQ:
            if (m->string_element_size != 0) {
                m->has_mem_read = true;
                m->mem_addr_reg_mask |= UINT32_C(1) << REG_RSI;
                m->mem_read_addr_reg_mask |= UINT32_C(1) << REG_RSI;
                x86_reg accumulator = X86_REG_INVALID;
                switch (m->string_element_size) {
                case 1:
                    accumulator = X86_REG_AL;
                    break;
                case 2:
                    accumulator = X86_REG_AX;
                    break;
                case 4:
                    accumulator = X86_REG_EAX;
                    break;
                case 8:
                    accumulator = X86_REG_RAX;
                    break;
                default:
                    break;
                }
                RegSlice accumulator_write =
                    reg_slice_from_x86(accumulator, m->string_element_size);
                append_reg_slice(m->reg_writes, &m->reg_write_count, accumulator_write,
                                 &m->reg_slice_detail_truncated);
                m->regs_written_mask |= UINT32_C(1) << REG_RAX;
                RegSlice source_index = reg_slice_from_x86(X86_REG_ESI, 4);
                append_reg_slice(m->reg_reads, &m->reg_read_count, source_index,
                                 &m->reg_slice_detail_truncated);
                append_reg_slice(m->reg_writes, &m->reg_write_count, source_index,
                                 &m->reg_slice_detail_truncated);
                m->regs_read_mask |= UINT32_C(1) << REG_RSI;
                m->regs_written_mask |= UINT32_C(1) << REG_RSI;
            }
            break;
        default:
            break;
        }
        //movs mem, mem
        if (m->string_element_size != 0 &&
            (insn->id == X86_INS_MOVSB || insn->id == X86_INS_MOVSW || insn->id == X86_INS_MOVSD ||
             insn->id == X86_INS_MOVSQ)) {
            m->has_mem_read = true;
            m->has_mem_write = true;
            m->mem_addr_reg_mask |= (1U << REG_RSI) | (1U << REG_RDI);
            m->mem_read_addr_reg_mask |= 1U << REG_RSI;
            m->mem_write_addr_reg_mask |= 1U << REG_RDI;
        }
        //indirect jumps/calls/rets
        if (insn->id == X86_INS_RET) {
            m->is_indirect_branch = true;
            m->branch_target_reg = REG_INVALID;
        } else if (insn->id == X86_INS_JMP || insn->id == X86_INS_CALL) {
            if (x86->op_count > 0) {
                if (x86->operands[0].type == X86_OP_REG) {
                    m->is_indirect_branch = true;
                    m->branch_target_slice =
                        reg_slice_from_x86(x86->operands[0].reg, x86->operands[0].size);
                    m->branch_target_reg = reg_slice_is_valid(m->branch_target_slice)
                                               ? m->branch_target_slice.reg_id
                                               : REG_INVALID;
                } else if (x86->operands[0].type == X86_OP_MEM) {
                    uint32_t target_address = x86_mem_address_reg_mask(&x86->operands[0]);
                    m->is_indirect_branch = true;
                    m->branch_target_reg = REG_INVALID;
                    m->has_mem_read = true;
                    m->mem_addr_reg_mask |= target_address;
                    m->mem_read_addr_reg_mask |= target_address;
                }
            }
        }
    }
    cs_free(insn, count);
    return m;
}
