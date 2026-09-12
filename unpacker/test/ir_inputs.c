#include "ir_inputs.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

struct IrInputs {
    atomic_uint references;
    IrOrigin boundary;
    IrInputState *states;
    IrInputCell *cells;
    uint32_t *slots;
    uint32_t state_count, capacity, slot_capacity;
    ReplaySources *sources;
    IrInputLimits limits;
    IrInputInfo info;
    bool sealed;
};

struct IrInputBindings {
    IrInputs *inputs;
    IrBits *values;
};

IrInputLimits ir_input_default_limits(void) {
    return (IrInputLimits){
        .inputs = 65536U + 64U, .bytes = 32U * 1024U * 1024U, .work = UINT64_C(8000000)};
}

static bool work(IrInputs *in, uint64_t n) {
    if (n > in->limits.work - in->info.work) {
        in->info.status = IR_RESOURCE_LIMIT;
        return false;
    }
    in->info.work += n;
    return true;
}

static uint32_t hash_byte(IrStateId state, uint64_t address) {
    uint64_t x = address ^ ((uint64_t)state * UINT64_C(0x9e3779b97f4a7c15));
    x ^= x >> 30;
    x *= UINT64_C(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x *= UINT64_C(0x94d049bb133111eb);
    return (uint32_t)(x ^ (x >> 31));
}

IrInputs *ir_inputs_create(IrOrigin boundary, const IrInputState *states, uint32_t state_count,
                           uint32_t capacity, const ReplaySources *sources,
                           const IrInputLimits *limits, IrInputInfo *info) {
    IrInputInfo result = {.status = IR_INVALID};
    if (info)
        *info = result;
    if (!states || !state_count || state_count > 1024U)
        return NULL;
    IrInputLimits bound = limits ? *limits : ir_input_default_limits();
    if (capacity > bound.inputs || capacity > UINT32_C(0x1000000)) {
        if (info)
            info->status = IR_RESOURCE_LIMIT;
        return NULL;
    }
    uint32_t cap = 16;
    while (cap < (uint64_t)capacity * 2U)
        cap *= 2U;
    uint64_t bytes = sizeof(IrInputs) + (uint64_t)state_count * sizeof(IrInputState) +
                     (uint64_t)capacity * sizeof(IrInputCell) + (uint64_t)cap * sizeof(uint32_t);
    uint64_t scans = (uint64_t)state_count * state_count + capacity + cap;
    if (bytes > bound.bytes || bytes > SIZE_MAX || scans > bound.work) {
        if (info)
            info->status = IR_RESOURCE_LIMIT;
        return NULL;
    }
    for (uint32_t i = 0; i < state_count; ++i) {
        if (!states[i].state || !ir_type_valid(states[i].type) ||
            states[i].type.kind == IR_TYPE_VOID || states[i].first || states[i].count)
            return NULL;
        for (uint32_t j = 0; j < i; ++j)
            if (states[i].state == states[j].state || states[i].key == states[j].key)
                return NULL;
    }
    IrInputs *in = calloc(1, sizeof(*in));
    if (!in) {
        if (info)
            info->status = IR_OUT_OF_MEMORY;
        return NULL;
    }
    atomic_init(&in->references, 1U);
    in->states = malloc((size_t)state_count * sizeof(*in->states));
    in->cells = capacity ? calloc(capacity, sizeof(*in->cells)) : NULL;
    in->slots = calloc(cap, sizeof(*in->slots));
    if (!in->states || (capacity && !in->cells) || !in->slots) {
        if (info)
            info->status = IR_OUT_OF_MEMORY;
        ir_inputs_release(in);
        return NULL;
    }
    memcpy(in->states, states, (size_t)state_count * sizeof(*states));
    in->boundary = boundary;
    in->state_count = state_count;
    in->capacity = capacity;
    in->slot_capacity = cap;
    in->sources = replay_sources_retain(sources);
    in->limits = bound;
    in->info = (IrInputInfo){.status = IR_OK, .bytes = (size_t)bytes, .work = scans};
    if (info)
        *info = in->info;
    return in;
}

static IrInputState *find_state(const IrInputs *in, IrStateId state) {
    for (uint32_t i = 0; i < in->state_count; ++i)
        if (in->states[i].state == state)
            return &in->states[i];
    return NULL;
}

IrInputId ir_inputs_add(IrInputs *in, IrInputCell cell) {
    if (!in || in->sealed || in->info.status != IR_OK)
        return 0;
    if (in->info.count == in->capacity || !work(in, in->state_count + 1U)) {
        in->info.status = IR_RESOURCE_LIMIT;
        return 0;
    }
    IrInputState *state = find_state(in, cell.state);
    if (!state || !cell.width || cell.width > 8 || (cell.issues & ~IR_INPUT_PROVENANCE_CONFLICT))
        goto invalid;
    uint64_t mask = ir_width_mask(cell.width);
    if (cell.observed.known_mask & ~mask)
        goto invalid;
    cell.observed.value &= cell.observed.known_mask;
    uint32_t slot = 0;
    IrInputId id = in->info.count + 1U;
    if (cell.kind == IR_INPUT_STATE_SLICE) {
        if (state->type.kind != IR_TYPE_BV || cell.address ||
            (unsigned)cell.bit_offset + cell.width > state->type.bits)
            goto invalid;
        if (!state->count) {
            if (cell.bit_offset)
                goto invalid;
            state->first = id;
        } else {
            const IrInputCell *previous = &in->cells[id - 2U];
            if (state->first + state->count != id || previous->state != cell.state ||
                cell.bit_offset != previous->bit_offset + previous->width)
                goto invalid;
        }
        ++state->count;
    } else if (cell.kind == IR_INPUT_MEMORY_BYTE) {
        if (state->type.kind != IR_TYPE_MEM || cell.width != 8 || cell.bit_offset ||
            cell.address > ir_width_mask(state->type.bits))
            goto invalid;
        slot = hash_byte(cell.state, cell.address) & (in->slot_capacity - 1U);
        do {
            if (!work(in, 1))
                return 0;
            uint32_t old = in->slots[slot];
            if (!old)
                break;
            if (in->cells[old - 1U].state == cell.state &&
                in->cells[old - 1U].address == cell.address)
                goto invalid;
            slot = (slot + 1U) & (in->slot_capacity - 1U);
        } while (true);
        in->slots[slot] = id;
    } else
        goto invalid;
    in->cells[in->info.count++] = cell;
    return id;
invalid:
    in->info.status = IR_INVALID;
    return 0;
}

static bool root_resolved(const ReplaySources *sources, ProvRootId id) {
    const ReplaySourceRoot *root = replay_sources_root(sources, id);
    if (!root || !root->valid)
        return false;
    if (root->key.kind != PROV_ROOT_RESOURCE_BYTE)
        return true;
    if (!root->key.source_id || root->key.source_id > UINT32_MAX)
        return false;
    const ReplaySourceResource *resource =
        replay_sources_resource(sources, (ProvResourceId)root->key.source_id);
    return resource && resource->valid;
}

bool ir_inputs_seal(IrInputs *in) {
    if (!in || in->info.status != IR_OK)
        return false;
    if (in->sealed)
        return true;
    if (!work(in, in->state_count))
        return false;
    for (uint32_t i = 0; i < in->state_count; ++i) {
        const IrInputState *state = &in->states[i];
        if (state->type.kind != IR_TYPE_BV)
            continue;
        if (!state->count) {
            in->info.status = IR_INVALID;
            return false;
        }
        const IrInputCell *last = &in->cells[state->first + state->count - 2U];
        if (last->bit_offset + last->width != state->type.bits) {
            in->info.status = IR_INVALID;
            return false;
        }
    }
    for (uint32_t i = 0; i < in->info.count; ++i) {
        if (!work(in, 1))
            return false;
        IrInputCell *cell = &in->cells[i];
        if (!ir_bits_complete(cell->observed, cell->width)) {
            cell->issues |= IR_INPUT_OBSERVATION_MISSING;
            ++in->info.missing_observations;
        }
        if (!cell->label_present || (cell->issues & IR_INPUT_PROVENANCE_CONFLICT)) {
            cell->issues |= IR_INPUT_PROVENANCE_MISSING;
            ++in->info.missing_provenance;
            continue;
        }
        const ReplaySourceLabel *label = replay_sources_label(in->sources, cell->label);
        if (!label || !label->valid)
            cell->issues |= IR_INPUT_SOURCE_UNRESOLVED;
        else {
            if (label->view.complete_mask != PROV_COMPLETE_ALL || label->view.incomplete_reasons)
                cell->issues |= IR_INPUT_PROVENANCE_INCOMPLETE;
            uint64_t n = (uint64_t)label->data_count + label->address_count;
            if (n)
                cell->issues |= IR_INPUT_DERIVATION_MISSING;
            if (!work(in, n))
                return false;
            for (uint32_t j = 0; j < label->data_count; ++j)
                if (!root_resolved(in->sources, label->data[j]))
                    cell->issues |= IR_INPUT_SOURCE_UNRESOLVED;
            for (uint32_t j = 0; j < label->address_count; ++j)
                if (!root_resolved(in->sources, label->address[j]))
                    cell->issues |= IR_INPUT_SOURCE_UNRESOLVED;
        }
        if (cell->issues & IR_INPUT_SOURCE_UNRESOLVED)
            ++in->info.unresolved_sources;
        if (cell->issues & IR_INPUT_PROVENANCE_INCOMPLETE)
            ++in->info.incomplete_provenance;
        if (cell->issues & IR_INPUT_DERIVATION_MISSING)
            ++in->info.dependent_inputs;
    }
    in->sealed = true;
    return true;
}

IrInputs *ir_inputs_retain(const IrInputs *in) {
    IrInputs *p = (IrInputs *)in;
    if (p)
        atomic_fetch_add_explicit(&p->references, 1U, memory_order_relaxed);
    return p;
}

void ir_inputs_release(IrInputs *in) {
    if (!in || atomic_fetch_sub_explicit(&in->references, 1U, memory_order_acq_rel) != 1U)
        return;
    replay_sources_release(in->sources);
    free(in->states);
    free(in->cells);
    free(in->slots);
    free(in);
}

IrInputInfo ir_inputs_info(const IrInputs *in) {
    return in ? in->info : (IrInputInfo){.status = IR_INVALID};
}

bool ir_inputs_ready(const IrInputs *in) {
    return in && in->sealed && in->info.status == IR_OK;
}

uint32_t ir_inputs_state_count(const IrInputs *in) {
    return ir_inputs_ready(in) ? in->state_count : 0;
}

const IrInputState *ir_inputs_state_at(const IrInputs *in, uint32_t index) {
    return index < ir_inputs_state_count(in) ? &in->states[index] : NULL;
}

size_t ir_inputs_bytes(const IrInputs *in) {
    return in ? in->info.bytes + replay_sources_bytes(in->sources) : 0;
}

IrOrigin ir_inputs_boundary(const IrInputs *in) {
    return in ? in->boundary : (IrOrigin){0};
}

const IrInputState *ir_inputs_state(const IrInputs *in, IrStateId state) {
    return in && in->sealed ? find_state(in, state) : NULL;
}

const IrInputCell *ir_inputs_cell(const IrInputs *in, IrInputId input) {
    return in && in->sealed && input && input <= in->info.count ? &in->cells[input - 1U] : NULL;
}

IrInputId ir_inputs_find_byte(const IrInputs *in, IrStateId state, uint64_t address) {
    if (!in || !in->sealed)
        return 0;
    uint32_t slot = hash_byte(state, address) & (in->slot_capacity - 1U);
    while (in->slots[slot]) {
        IrInputId id = in->slots[slot];
        if (in->cells[id - 1U].state == state && in->cells[id - 1U].address == address)
            return id;
        slot = (slot + 1U) & (in->slot_capacity - 1U);
    }
    return 0;
}

const ReplaySources *ir_inputs_sources(const IrInputs *in) {
    return in ? in->sources : NULL;
}

const ReplaySourceLabel *ir_inputs_label(const IrInputs *in, IrInputId input) {
    const IrInputCell *cell = ir_inputs_cell(in, input);
    return cell && cell->label_present && !(cell->issues & IR_INPUT_PROVENANCE_CONFLICT)
               ? replay_sources_label(in->sources, cell->label)
               : NULL;
}

IrInputBindings *ir_inputs_bindings_create(const IrInputs *in, const IrInputAssignment *assignments,
                                           uint32_t count, const IrInputLimits *limits,
                                           IrInputInfo *info) {
    IrInputInfo result = {.status = IR_INVALID};
    if (info)
        *info = result;
    if (!in || !in->sealed || (count && !assignments))
        return NULL;
    IrInputLimits bound = limits ? *limits : ir_input_default_limits();
    uint32_t n = in->info.count;
    uint64_t bytes = sizeof(IrInputBindings) + (uint64_t)n * (sizeof(IrBits) + 1U);
    if (n > bound.inputs || bytes > bound.bytes || bytes > SIZE_MAX ||
        (uint64_t)n + count > bound.work) {
        if (info)
            info->status = IR_RESOURCE_LIMIT;
        return NULL;
    }
    IrInputBindings *b = calloc(1, sizeof(*b));
    if (!b) {
        if (info)
            info->status = IR_OUT_OF_MEMORY;
        return NULL;
    }
    b->values = n ? malloc((size_t)n * sizeof(*b->values)) : NULL;
    uint8_t *seen = n ? calloc(n, 1) : NULL;
    if (n && (!b->values || !seen)) {
        free(seen);
        ir_inputs_bindings_destroy(b);
        if (info)
            info->status = IR_OUT_OF_MEMORY;
        return NULL;
    }
    for (uint32_t i = 0; i < n; ++i)
        b->values[i] = in->cells[i].observed;
    for (uint32_t i = 0; i < count; ++i) {
        IrInputId id = assignments[i].input;
        if (!id || id > n || seen[id - 1U])
            goto invalid;
        IrBits bits = assignments[i].bits;
        if (bits.known_mask & ~ir_width_mask(in->cells[id - 1U].width))
            goto invalid;
        bits.value &= bits.known_mask;
        b->values[id - 1U] = bits;
        seen[id - 1U] = 1;
    }
    free(seen);
    b->inputs = ir_inputs_retain(in);
    if (info)
        *info = (IrInputInfo){
            .status = IR_OK, .count = n, .bytes = (size_t)bytes, .work = (uint64_t)n + count};
    return b;
invalid:
    free(seen);
    ir_inputs_bindings_destroy(b);
    return NULL;
}

void ir_inputs_bindings_destroy(IrInputBindings *b) {
    if (!b)
        return;
    ir_inputs_release(b->inputs);
    free(b->values);
    free(b);
}

static const IrInputState *binding_state(const IrInputs *in, uint64_t key) {
    for (uint32_t i = 0; i < in->state_count; ++i)
        if (in->states[i].key == key)
            return &in->states[i];
    return NULL;
}

static IrBits read_bv(void *user, IrBindingKind kind, uint64_t key, uint8_t width) {
    const IrInputBindings *b = user;
    const IrInputState *state = binding_state(b->inputs, key);
    if (kind != IR_BIND_STATE || !state || state->type.kind != IR_TYPE_BV ||
        state->type.bits != width)
        return ir_bits_unknown(IR_REASON_UNBOUND_STATE);
    IrBits out = {0};
    for (uint32_t i = 0; i < state->count; ++i) {
        uint32_t index = state->first + i - 1U;
        const IrInputCell *cell = &b->inputs->cells[index];
        IrBits bits = b->values[index];
        out.value |= bits.value << cell->bit_offset;
        out.known_mask |= bits.known_mask << cell->bit_offset;
        out.reasons |= bits.reasons;
    }
    return out;
}

static IrBits read_byte(void *user, IrBindingKind kind, uint64_t key, uint64_t address) {
    const IrInputBindings *b = user;
    const IrInputState *state = binding_state(b->inputs, key);
    if (kind != IR_BIND_STATE || !state || state->type.kind != IR_TYPE_MEM)
        return ir_bits_unknown(IR_REASON_MEMORY);
    IrInputId id = ir_inputs_find_byte(b->inputs, state->state, address);
    return id ? b->values[id - 1U] : ir_bits_unknown(IR_REASON_MEMORY);
}

IrBindings ir_inputs_bindings(IrInputBindings *b) {
    return b ? (IrBindings){.user = b, .read_bv = read_bv, .read_byte = read_byte}
             : (IrBindings){0};
}
