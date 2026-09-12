#include "ir_replay.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    uint32_t address;
    uint8_t initial;
    bool occupied, written, known;
    bool read_before_write, source_valid, source_conflict;
    ProvLabelId source_label;
    IrOrigin read_origin;
} ReplayByte;

struct IrReplay {
    IrModule *module;
    IrX86State state;
    IrReplayOptions options;
    IrReplayBuildInfo info;
    IrBits initial_gpr[IR_X86_GPR_COUNT];
    IrBits initial_flags[IR_X86_FLAG_COUNT];
    IrReplayObservation *observations;
    uint32_t observation_count, observation_capacity;
    ReplayByte *memory;
    uint32_t memory_count, memory_capacity;
    uint32_t undefined_flags; /* Architectural status along the unrolled path. */
    bool allocation_failed;
    uint64_t trigger_seq;
    IrInputs *inputs;
    IrStatus input_status;
    uint64_t input_scan_work;
};

size_t ir_replay_allocated_bytes(const IrReplay *r) {
    if (!r)
        return 0;
    return sizeof(*r) + ir_module_allocated_bytes(r->module) +
           (size_t)r->observation_capacity * sizeof(*r->observations) +
           (size_t)r->memory_capacity * sizeof(*r->memory) + ir_inputs_bytes(r->inputs);
}

static const unsigned flag_bit[IR_X86_FLAG_COUNT] = {0, 2, 4, 6, 7, 11, 10};

IrReplayOptions ir_replay_default_options(void) {
    IrReplayOptions options = {.module = ir_default_limits(),
                               .max_steps = 4096,
                               .max_observations = 131072,
                               .max_memory_bytes = 65536};
    /* Up to 15 state observations per boundary, four per RMW and one per Jcc. */
    options.module.outputs = options.max_observations;
    options.inputs = ir_input_default_limits();
    return options;
}

void ir_replay_destroy(IrReplay *r) {
    if (!r)
        return;
    ir_module_destroy(r->module);
    ir_inputs_release(r->inputs);
    free(r->observations);
    free(r->memory);
    free(r);
}

IrModule *ir_replay_module(IrReplay *r) {
    return r ? r->module : NULL;
}

const IrX86State *ir_replay_state(const IrReplay *r) {
    return r ? &r->state : NULL;
}

const IrInputs *ir_replay_inputs(const IrReplay *r) {
    return r ? r->inputs : NULL;
}

IrInputInfo ir_replay_input_info(const IrReplay *r) {
    IrInputInfo info = ir_inputs_info(r ? r->inputs : NULL);
    if (r)
        info.work += r->input_scan_work;
    return info;
}

const IrInputState *ir_replay_boundary_value(const IrReplay *r, IrValueId value) {
    if (!r || !ir_module_is_trace_ssa(r->module))
        return NULL;
    const IrValue *v = ir_module_value(r->module, value);
    const IrInst *inst = v ? ir_module_inst(r->module, v->definition) : NULL;
    return inst && !inst->removed && inst->spec.op == IR_OP_READ_STATE
               ? ir_inputs_state(r->inputs, inst->spec.state)
               : NULL;
}

IrReplayBuildInfo ir_replay_info(const IrReplay *r) {
    return r ? r->info : (IrReplayBuildInfo){.status = IR_REPLAY_INVALID};
}

uint32_t ir_replay_observation_count(const IrReplay *r) {
    return r ? r->observation_count : 0;
}

const IrReplayObservation *ir_replay_observation(const IrReplay *r, uint32_t i) {
    return r && i < r->observation_count ? &r->observations[i] : NULL;
}

static IrOrigin origin_of(const ReplayStep *step) {
    if (!step)
        return (IrOrigin){0};
    const TraceEntry *e = &step->entry;
    return (IrOrigin){.seq_id = e->seq_id,
                      .descriptor_id = e->insn_desc_id,
                      .pc = e->pc,
                      .code_generation = e->code_generation,
                      .vcpu_id = e->vcpu_index,
                      .has_trace_identity = true,
                      .provenance_label = e->target_label};
}

static uint32_t identity_issues(const ReplayStep *s, uint32_t vcpu) {
    if (!s || !s->descriptor_valid)
        return IR_REPLAY_IDENTITY;
    const TraceEntry *e = &s->entry;
    const InsnDesc *d = &s->descriptor;
    const InsnOccurrence *o = &s->occurrence;
    if (s->issues & (REPLAY_INPUT_ENTRY_MISSING | REPLAY_INPUT_DESCRIPTOR_MISMATCH |
                     REPLAY_INPUT_META_MISMATCH | REPLAY_INPUT_VCPU_MISMATCH))
        return IR_REPLAY_IDENTITY;
    if (!e->seq_id || e->vcpu_index != vcpu || !e->insn_desc_id || !e->size ||
        e->size > MAX_INSN_BYTES || d->desc_id != e->insn_desc_id || d->meta_id != e->meta_id ||
        d->pc != e->pc || d->size != e->size || d->code_generation != e->code_generation ||
        d->bytes_hash != e->bytes_hash || memcmp(d->bytes, e->instr_bytes, e->size) ||
        e->bytes_hash != trace_instruction_bytes_hash(e->instr_bytes, e->size) ||
        o->seq_id != e->seq_id || o->vcpu_index != e->vcpu_index || o->desc_id != e->insn_desc_id ||
        o->meta_id != e->meta_id || o->pc != e->pc || o->code_generation != e->code_generation ||
        o->bytes_hash != e->bytes_hash)
        return IR_REPLAY_IDENTITY;
    if (d->arch != TRACE_ARCH_X86 || d->mode != TRACE_MODE_32 || e->pc > UINT32_MAX)
        return IR_REPLAY_MODE;
    return 0;
}

static const InsnAux *saved_aux(const ReplayInput *input, const ReplayStep *s) {
    const InsnAux *a = replay_input_aux(input, s->entry.seq_id);
    return a && a->valid && a->seq_id == s->entry.seq_id && a->meta_id == s->entry.meta_id &&
                   a->pc == s->entry.pc && a->execution_complete == s->occurrence.execution_complete
               ? a
               : NULL;
}

static uint32_t core_reasons(uint32_t issues) {
    uint32_t reasons = 0;
    if (issues & (IR_REPLAY_IDENTITY | IR_REPLAY_GAP | IR_REPLAY_PENDING |
                  IR_REPLAY_OBSERVATION_MISSING | IR_REPLAY_CONTROL_MISMATCH))
        reasons |= IR_REASON_TRACE_GAP;
    if (issues & (IR_REPLAY_UNSUPPORTED | IR_REPLAY_MODE | IR_REPLAY_MEMORY_MODEL))
        reasons |= IR_REASON_UNSUPPORTED;
    if (issues & IR_REPLAY_OBSERVATION_SHAPE)
        reasons |= IR_REASON_MEMORY;
    if (issues & IR_REPLAY_BUDGET)
        reasons |= IR_REASON_BUDGET;
    return reasons;
}

static void note(IrReplay *r, uint32_t issues) {
    if (!issues)
        return;
    r->info.issues |= issues;
    r->info.status = IR_REPLAY_UNKNOWN;
    IrQuality q = {0};
    q.semantic =
        core_reasons(issues & (IR_REPLAY_IDENTITY | IR_REPLAY_MODE | IR_REPLAY_UNSUPPORTED |
                               IR_REPLAY_PENDING | IR_REPLAY_MEMORY_MODEL | IR_REPLAY_BUDGET));
    q.control =
        core_reasons(issues & (IR_REPLAY_IDENTITY | IR_REPLAY_GAP | IR_REPLAY_CONTROL_MISMATCH));
    q.observation = core_reasons(
        issues & (IR_REPLAY_PENDING | IR_REPLAY_OBSERVATION_MISSING | IR_REPLAY_OBSERVATION_SHAPE));
    ir_module_note_quality(r->module, q);
}

static void stop(IrReplay *r, IrBlockId b, uint32_t issues, IrOrigin origin) {
    note(r, issues);
    r->info.stopped_seq = origin.seq_id;
    uint32_t reasons = core_reasons(issues);
    (void)ir_emit_effect(
        r->module, b,
        (IrInstSpec){
            .op = IR_OP_BARRIER, .type = ir_type_void(), .immediate = reasons, .origin = origin});
    (void)ir_block_terminate(
        r->module, b,
        (IrTerminator){.kind = IR_TERM_UNKNOWN, .reasons = reasons, .origin = origin});
}

static bool add_observation(IrReplay *r, IrReplayObservation o) {
    if (!o.value && !o.architectural_undefined)
        return false;
    if (r->observation_count == r->options.max_observations)
        return false;
    if (r->observation_count == r->observation_capacity) {
        uint32_t cap = r->observation_capacity ? r->observation_capacity : 16;
        if (cap < r->options.max_observations / 2)
            cap *= 2;
        else
            cap = r->options.max_observations;
        if (cap > r->options.max_observations)
            cap = r->options.max_observations;
        IrReplayObservation *p = realloc(r->observations, (size_t)cap * sizeof(*p));
        if (!p) {
            r->allocation_failed = true;
            return false;
        }
        r->observations = p;
        r->observation_capacity = cap;
    }
    if (!o.architectural_undefined && !ir_module_add_output(r->module, o.value))
        return false;
    o.expected &= ir_width_mask(o.width);
    r->observations[r->observation_count++] = o;
    if (!o.expected_valid && !o.architectural_undefined)
        note(r, IR_REPLAY_OBSERVATION_MISSING);
    return true;
}

static bool checkpoint(IrReplay *r, IrBlockId b, IrOrigin origin, const InsnAux *aux) {
    for (unsigned i = 0; i < IR_X86_GPR_COUNT + IR_X86_FLAG_COUNT; ++i) {
        bool flag = i >= IR_X86_GPR_COUNT;
        unsigned index = flag ? i - IR_X86_GPR_COUNT : i;
        IrReplayObservation o = {.origin = origin,
                                 .index = index,
                                 .kind = flag ? IR_REPLAY_FLAG : IR_REPLAY_GPR,
                                 .width = flag ? 1 : 32};
        IrStateId state = flag ? r->state.flags[index] : r->state.gpr[index];
        o.architectural_undefined = flag && (r->undefined_flags & (UINT32_C(1) << index));
        if (!o.architectural_undefined)
            o.value = ir_emit_value(r->module, b,
                                    (IrInstSpec){.op = IR_OP_READ_STATE,
                                                 .type = ir_type_bv(o.width),
                                                 .state = state,
                                                 .origin = origin});
        if (aux) {
            o.expected_valid = flag ? aux->eflags_valid
                                    : (aux->reg_value_valid_mask & (UINT32_C(1) << index)) != 0;
            o.expected = flag ? (aux->eflags_before >> flag_bit[index]) & 1U : aux->reg_vals[index];
        }
        if (!add_observation(r, o))
            return false;
    }
    return true;
}

static uint32_t byte_hash(uint32_t address) {
    address ^= address >> 16;
    address *= UINT32_C(0x7feb352d);
    address ^= address >> 15;
    address *= UINT32_C(0x846ca68b);
    return address ^ (address >> 16);
}

static uint32_t byte_slot(const ReplayByte *table, uint32_t cap, uint32_t address) {
    uint32_t slot = byte_hash(address) & (cap - 1U);
    while (table[slot].occupied && table[slot].address != address)
        slot = (slot + 1U) & (cap - 1U);
    return slot;
}

static ReplayByte *byte_insert(IrReplay *r, uint32_t address) {
    if (r->memory_capacity) {
        ReplayByte *found = &r->memory[byte_slot(r->memory, r->memory_capacity, address)];
        if (found->occupied)
            return found;
    }
    if (r->memory_count == r->options.max_memory_bytes)
        return NULL;
    if (!r->memory_capacity || r->memory_count >= r->memory_capacity / 2U) {
        uint32_t cap = r->memory_capacity ? r->memory_capacity * 2U : 16;
        ReplayByte *table = calloc(cap, sizeof(*table));
        if (!table) {
            r->allocation_failed = true;
            return NULL;
        }
        for (uint32_t i = 0; i < r->memory_capacity; ++i)
            if (r->memory[i].occupied)
                table[byte_slot(table, cap, r->memory[i].address)] = r->memory[i];
        free(r->memory);
        r->memory = table;
        r->memory_capacity = cap;
    }
    ReplayByte *entry = &r->memory[byte_slot(r->memory, r->memory_capacity, address)];
    *entry = (ReplayByte){.address = address, .occupied = true};
    ++r->memory_count;
    return entry;
}

static bool observe_memory(IrReplay *r, IrOrigin origin, IrX86LiftResult lift,
                           const InsnOccurrence *o, const InsnAux *aux) {
    /* RMW reads seed immutable initial bytes BEFORE its write is recorded. */
    for (unsigned pass = 0; pass < 2; ++pass) {
        bool write = pass != 0;
        if (write ? !lift.writes_memory : !lift.reads_memory)
            continue;
        const TraceMemoryEffect *event = write ? &o->mem_writes[0] : &o->mem_reads[0];
        IrReplayObservation address = {.origin = origin,
                                       .value = lift.address,
                                       .width = 32,
                                       .kind =
                                           write ? IR_REPLAY_WRITE_ADDRESS : IR_REPLAY_READ_ADDRESS,
                                       .expected_valid = true,
                                       .expected = event->address};
        IrReplayObservation data = {.origin = origin,
                                    .value = write ? lift.write_data : lift.read_data,
                                    .width = (uint8_t)(lift.memory_bytes * 8U),
                                    .kind = write ? IR_REPLAY_WRITE_VALUE : IR_REPLAY_READ_VALUE,
                                    .expected_valid = event->value_valid,
                                    .expected = event->value};
        if (!add_observation(r, address) || !add_observation(r, data))
            return false;
        for (unsigned i = 0; i < lift.memory_bytes; ++i) {
            ReplayByte *byte = byte_insert(r, (uint32_t)(event->address + i));
            if (!byte)
                return false;
            if (write)
                byte->written = true;
            else if (!byte->written) {
                const DseMemRead *read =
                    aux && aux->mem_read_count == 1 ? &aux->mem_reads[0] : NULL;
                const DseSourceObservation *sources = dse_aux_sources(aux);
                bool source_valid = read && read->addr == event->address &&
                                    read->size == lift.memory_bytes && sources &&
                                    (sources->read_valid[0] & (1U << i));
                ProvLabelId label = source_valid ? sources->read_labels[0][i] : PROV_LABEL_UNKNOWN;
                if (!byte->read_before_write) {
                    byte->read_before_write = true;
                    byte->read_origin = origin;
                    byte->source_valid = source_valid;
                    byte->source_label = label;
                } else if (!source_valid || !byte->source_valid || byte->source_label != label) {
                    /* Never replace historical uncertainty with a later label. */
                    byte->source_conflict = true;
                }
                if (!byte->known && event->value_valid) {
                    byte->known = true;
                    byte->initial = (uint8_t)(event->value >> (i * 8U));
                }
            }
        }
    }
    return true;
}

static uint32_t memory_shape(IrX86LiftResult lift, const InsnOccurrence *o) {
    unsigned reads = lift.reads_memory ? 1 : 0, writes = lift.writes_memory ? 1 : 0;
    if (!o->dynamic_effects_available ||
        (o->incomplete_reasons & (TRACE_OCCURRENCE_READ_OVERFLOW | TRACE_OCCURRENCE_WRITE_OVERFLOW |
                                  TRACE_OCCURRENCE_RANGE_UNKNOWN)) ||
        o->mem_read_count != reads || o->mem_write_count != writes || o->mem_read_total != reads ||
        o->mem_write_total != writes)
        return IR_REPLAY_OBSERVATION_SHAPE;
    if (reads &&
        (o->mem_reads[0].kind != TRACE_MEM_READ || o->mem_reads[0].size != lift.memory_bytes ||
         o->mem_reads[0].address > UINT32_MAX))
        return IR_REPLAY_OBSERVATION_SHAPE;
    if (writes &&
        (o->mem_writes[0].kind != TRACE_MEM_WRITE || o->mem_writes[0].size != lift.memory_bytes ||
         o->mem_writes[0].address > UINT32_MAX))
        return IR_REPLAY_OBSERVATION_SHAPE;
    return 0;
}

static uint32_t lift_issues(IrX86LiftStatus status) {
    switch (status) {
    case IR_X86_LIFT_MODE:
        return IR_REPLAY_MODE;
    case IR_X86_LIFT_IDENTITY:
        return IR_REPLAY_IDENTITY;
    case IR_X86_LIFT_MEMORY_MODEL:
        return IR_REPLAY_MEMORY_MODEL;
    default:
        return IR_REPLAY_UNSUPPORTED;
    }
}

static IrReplayBuildStatus fatal_status(const IrReplay *r) {
    if (r->allocation_failed)
        return IR_REPLAY_OUT_OF_MEMORY;
    if (r->input_status == IR_RESOURCE_LIMIT)
        return IR_REPLAY_RESOURCE_LIMIT;
    if (r->input_status == IR_OUT_OF_MEMORY)
        return IR_REPLAY_OUT_OF_MEMORY;
    switch (ir_module_status(r->module)) {
    case IR_RESOURCE_LIMIT:
        return IR_REPLAY_RESOURCE_LIMIT;
    case IR_OUT_OF_MEMORY:
        return IR_REPLAY_OUT_OF_MEMORY;
    default:
        return IR_REPLAY_INVALID;
    }
}

static bool build_inputs(IrReplay *r, const ReplayInput *input, const ReplayStep *first) {
    IrOrigin boundary = origin_of(first);
    const InsnAux *aux =
        identity_issues(first, first->entry.vcpu_index) ? NULL : saved_aux(input, first);
    const DseSourceObservation *sources = dse_aux_sources(aux);
    IrInputState states[IR_X86_GPR_COUNT + IR_X86_FLAG_COUNT + 1U];
    uint32_t nstates = 0, count = IR_X86_GPR_COUNT * 4U + IR_X86_FLAG_COUNT;
    for (unsigned i = 0; i < IR_X86_GPR_COUNT; ++i)
        states[nstates++] = (IrInputState){
            .state = r->state.gpr[i], .type = ir_type_bv(32), .key = IR_X86_GPR_KEY_BASE + i};
    for (unsigned i = 0; i < IR_X86_FLAG_COUNT; ++i)
        states[nstates++] = (IrInputState){
            .state = r->state.flags[i], .type = ir_type_bv(1), .key = IR_X86_FLAG_KEY_BASE + i};
    states[nstates++] =
        (IrInputState){.state = r->state.memory, .type = ir_type_mem(32), .key = IR_X86_MEMORY_KEY};
    /* Account both hash-table scans separately from catalogue operations. */
    IrInputLimits limits = r->options.inputs;
    uint64_t scan_work = (uint64_t)r->memory_capacity * 2U;
    if (scan_work > limits.work) {
        r->input_status = IR_RESOURCE_LIMIT;
        return false;
    }
    limits.work -= scan_work;
    r->input_scan_work = scan_work;
    for (uint32_t i = 0; i < r->memory_capacity; ++i)
        if (r->memory[i].occupied && r->memory[i].read_before_write)
            ++count;
    IrInputInfo info;
    r->inputs = ir_inputs_create(boundary, states, nstates, count, replay_input_sources(input),
                                 &limits, &info);
    if (!r->inputs) {
        r->input_status = info.status;
        return false;
    }
    for (unsigned reg = 0; reg < IR_X86_GPR_COUNT; ++reg) {
        for (unsigned byte = 0; byte < 4; ++byte) {
            IrInputCell cell = {
                .kind = IR_INPUT_STATE_SLICE,
                .state = r->state.gpr[reg],
                .bit_offset = (uint8_t)(byte * 8U),
                .width = 8,
                .observation_origin = boundary,
                .observed = {.value = (r->initial_gpr[reg].value >> (byte * 8U)) & 255U,
                             .known_mask = (r->initial_gpr[reg].known_mask >> (byte * 8U)) & 255U,
                             .reasons = r->initial_gpr[reg].reasons}};
            if (sources && (sources->reg_source_valid[reg] & (1U << byte))) {
                cell.label_present = true;
                cell.label = sources->reg_source_labels[reg][byte];
            }
            if (!ir_inputs_add(r->inputs, cell))
                goto fail;
        }
    }
    for (unsigned flag = 0; flag < IR_X86_FLAG_COUNT; ++flag) {
        IrInputCell cell = {.kind = IR_INPUT_STATE_SLICE,
                            .state = r->state.flags[flag],
                            .width = 1,
                            .observation_origin = boundary,
                            .observed = r->initial_flags[flag]};
        /* DTA currently tracks six arithmetic flags; DF provenance is missing. */
        if (sources && flag < DTA_FLAG_SLOT_COUNT && (sources->flag_source_valid & (1U << flag))) {
            cell.label_present = true;
            cell.label = sources->flag_source_labels[flag];
        }
        if (!ir_inputs_add(r->inputs, cell))
            goto fail;
    }
    for (uint32_t i = 0; i < r->memory_capacity; ++i) {
        const ReplayByte *byte = &r->memory[i];
        if (!byte->occupied || !byte->read_before_write)
            continue;
        IrInputCell cell = {.kind = IR_INPUT_MEMORY_BYTE,
                            .state = r->state.memory,
                            .address = byte->address,
                            .width = 8,
                            .observation_origin = byte->read_origin,
                            .observed = byte->known ? ir_bits_known(byte->initial, 8)
                                                    : ir_bits_unknown(IR_REASON_MEMORY),
                            .label = byte->source_label,
                            .label_present = byte->source_valid,
                            .issues = byte->source_conflict ? IR_INPUT_PROVENANCE_CONFLICT : 0};
        if (!ir_inputs_add(r->inputs, cell))
            goto fail;
    }
    if (ir_inputs_seal(r->inputs))
        return true;
fail:
    r->input_status = ir_inputs_info(r->inputs).status;
    return false;
}

IrReplay *ir_replay_x86_build(const ReplayInput *input, const IrReplayOptions *options,
                              IrReplayBuildInfo *info) {
    if (info)
        *info = (IrReplayBuildInfo){.status = IR_REPLAY_INVALID};
    const ReplayStep *trigger = replay_input_trigger(input);
    if (!input || !trigger)
        return NULL;
    IrReplayOptions opts = options ? *options : ir_replay_default_options();
    /* Explicit upper bounds also keep growth arithmetic valid on 32-bit hosts. */
    if (opts.max_memory_bytes > UINT32_C(0x1000000) ||
        opts.max_observations > UINT32_C(0x1000000) || opts.module.instructions == UINT32_MAX ||
        opts.module.values == UINT32_MAX || opts.module.blocks == UINT32_MAX ||
        opts.module.states == UINT32_MAX || opts.module.outputs == UINT32_MAX ||
        (uint64_t)opts.max_observations * sizeof(IrReplayObservation) > SIZE_MAX)
        return NULL;
    IrReplay *r = calloc(1, sizeof(*r));
    if (!r) {
        if (info)
            info->status = IR_REPLAY_OUT_OF_MEMORY;
        return NULL;
    }
    r->options = opts;
    r->info.selected_steps = replay_input_count(input);
    r->trigger_seq = trigger->entry.seq_id;
    r->module = ir_module_create(&opts.module);
    if (!r->module) {
        if (info)
            info->status = IR_REPLAY_OUT_OF_MEMORY;
        ir_replay_destroy(r);
        return NULL;
    }
    IrX86Frontend *frontend = ir_x86_frontend_create(r->module, &opts.x86);
    if (!frontend)
        goto fatal;
    r->state = *ir_x86_frontend_state(frontend);
    IrBlockId block = ir_block_add(r->module);
    if (!block)
        goto fatal;
    uint32_t vcpu = trigger->entry.vcpu_index;
    uint32_t issues = identity_issues(trigger, vcpu);
    const ReplayStep *first = r->info.selected_steps ? replay_input_step(input, 0) : trigger;
    issues |= identity_issues(first, vcpu);
    for (unsigned i = 0; i < IR_X86_GPR_COUNT; ++i)
        r->initial_gpr[i] = ir_bits_unknown(IR_REASON_UNBOUND_STATE);
    for (unsigned i = 0; i < IR_X86_FLAG_COUNT; ++i)
        r->initial_flags[i] = ir_bits_unknown(IR_REASON_UNBOUND_STATE);
    if (issues) {
        stop(r, block, issues, origin_of(first));
        goto complete;
    }
    const InsnAux *initial = saved_aux(input, first);
    if (initial) {
        for (unsigned i = 0; i < IR_X86_GPR_COUNT; ++i)
            if (initial->reg_value_valid_mask & (UINT32_C(1) << i))
                r->initial_gpr[i] = ir_bits_known(initial->reg_vals[i], 32);
        if (initial->eflags_valid)
            for (unsigned i = 0; i < IR_X86_FLAG_COUNT; ++i)
                r->initial_flags[i] =
                    ir_bits_known((initial->eflags_before >> flag_bit[i]) & 1U, 1);
    }
    for (uint32_t i = 0; i < r->info.selected_steps; ++i) {
        const ReplayStep *step = replay_input_step(input, i);
        IrOrigin origin = origin_of(step);
        if (i >= opts.max_steps) {
            stop(r, block, IR_REPLAY_BUDGET, origin);
            goto complete;
        }
        issues = identity_issues(step, vcpu);
        if (issues) {
            stop(r, block, issues, origin);
            goto complete;
        }
        if (!step->occurrence.execution_complete ||
            (step->issues & REPLAY_INPUT_EXECUTION_PENDING)) {
            stop(r, block, IR_REPLAY_PENDING, origin);
            goto complete;
        }
        const InsnAux *aux = saved_aux(input, step);
        if (!checkpoint(r, block, origin, aux)) {
            if (r->allocation_failed || ir_module_status(r->module) != IR_OK)
                goto fatal;
            stop(r, block, IR_REPLAY_BUDGET, origin);
            goto complete;
        }
        IrX86LiftResult lift = ir_x86_lift(frontend, block, &step->descriptor, origin);
        if (lift.status == IR_X86_LIFT_ERROR)
            goto fatal;
        if (lift.status != IR_X86_LIFT_OK) {
            stop(r, block, lift_issues(lift.status), origin);
            goto complete;
        }
        ++r->info.lifted_steps;
        r->undefined_flags = (r->undefined_flags & ~lift.flags_written) | lift.flags_undefined;
        issues = memory_shape(lift, &step->occurrence);
        if (issues) {
            stop(r, block, issues, origin);
            goto complete;
        }
        if (!observe_memory(r, origin, lift, &step->occurrence, aux)) {
            if (r->allocation_failed || ir_module_status(r->module) != IR_OK)
                goto fatal;
            stop(r, block, IR_REPLAY_BUDGET, origin);
            goto complete;
        }
        const ReplayStep *next =
            i + 1U < r->info.selected_steps ? replay_input_step(input, i + 1U) : trigger;
        issues = identity_issues(next, vcpu);
        if (issues) {
            stop(r, block, issues, origin_of(next));
            goto complete;
        }
        uint64_t fallthrough = (uint32_t)(step->entry.pc + step->entry.size);
        if (step->entry.seq_id == UINT64_MAX || next->entry.seq_id != step->entry.seq_id + 1U) {
            stop(r, block, IR_REPLAY_GAP, origin_of(next));
            goto complete;
        }
        if (!step->occurrence.next_pc_valid) {
            stop(r, block, IR_REPLAY_GAP, origin);
            goto complete;
        }
        const InsnOccurrence *occ = &step->occurrence;
        uint64_t successor = fallthrough;
        bool taken = false;
        if (occ->incomplete_reasons & TRACE_OCCURRENCE_BRANCH_MISMATCH) {
            stop(r, block, IR_REPLAY_CONTROL_MISMATCH, origin);
            goto complete;
        }
        if (lift.control == IR_X86_CONDITIONAL) {
            if (!occ->branch_event_valid || !occ->branch_event_id ||
                (occ->branch_outcome != BRANCH_OUTCOME_TAKEN &&
                 occ->branch_outcome != BRANCH_OUTCOME_NOT_TAKEN)) {
                stop(r, block, IR_REPLAY_CONTROL_MISMATCH | IR_REPLAY_OBSERVATION_MISSING, origin);
                goto complete;
            }
            taken = occ->branch_outcome == BRANCH_OUTCOME_TAKEN;
            successor = taken ? lift.direct_target : fallthrough;
            if (occ->observed_branch_target != occ->next_pc) {
                stop(r, block, IR_REPLAY_CONTROL_MISMATCH, origin);
                goto complete;
            }
        } else {
            if (occ->branch_event_valid || occ->branch_outcome != BRANCH_OUTCOME_UNKNOWN ||
                (lift.control == IR_X86_FALLTHROUGH && occ->control_transfer_valid)) {
                stop(r, block, IR_REPLAY_CONTROL_MISMATCH, origin);
                goto complete;
            }
            if (lift.control == IR_X86_DIRECT_JUMP)
                successor = lift.direct_target;
        }
        if (occ->next_pc != successor || next->entry.pc != successor ||
            (aux && aux->next_pc_valid && aux->next_pc != occ->next_pc)) {
            stop(r, block, IR_REPLAY_CONTROL_MISMATCH, origin);
            goto complete;
        }
        if (lift.control != IR_X86_FALLTHROUGH) {
            if (lift.control == IR_X86_CONDITIONAL &&
                !add_observation(r, (IrReplayObservation){.kind = IR_REPLAY_BRANCH_CONDITION,
                                                          .origin = origin,
                                                          .value = lift.condition,
                                                          .width = 1,
                                                          .expected_valid = true,
                                                          .expected = taken})) {
                if (r->allocation_failed || ir_module_status(r->module) != IR_OK)
                    goto fatal;
                stop(r, block, IR_REPLAY_BUDGET, origin);
                goto complete;
            }
            IrBlockId following = ir_block_add(r->module);
            if (!following)
                goto fatal;
            IrTarget local = {.kind = IR_TARGET_BLOCK, .block = following};
            IrTerminator term = {.kind = IR_TERM_JUMP,
                                 .origin = origin,
                                 .successors = {local},
                                 .has_observation = true,
                                 .observed_taken = true,
                                 .observed_target = successor};
            if (lift.control == IR_X86_CONDITIONAL) {
                term.kind = IR_TERM_CJUMP;
                term.condition = lift.condition;
                term.observed_taken = taken;
                term.successors[0] =
                    (IrTarget){.kind = IR_TARGET_ADDRESS, .address = lift.direct_target};
                term.successors[1] = (IrTarget){.kind = IR_TARGET_ADDRESS, .address = fallthrough};
                term.successors[taken ? 0 : 1] = local;
                /* A zero displacement has one semantic next occurrence even
                 * when its condition differs. Keep the condition observation. */
                if (lift.direct_target == fallthrough)
                    term.successors[0] = term.successors[1] = local;
            }
            if (!ir_block_terminate(r->module, block, term))
                goto fatal;
            block = following;
        }
    }
    if (!checkpoint(r, block, origin_of(trigger), saved_aux(input, trigger))) {
        if (r->allocation_failed || ir_module_status(r->module) != IR_OK)
            goto fatal;
        stop(r, block, IR_REPLAY_BUDGET, origin_of(trigger));
        goto complete;
    }
    (void)ir_block_terminate(
        r->module, block,
        (IrTerminator){.kind = IR_TERM_FRAGMENT_END, .origin = origin_of(trigger)});
complete:
    if (!ir_validate(r->module, NULL) || r->allocation_failed)
        goto fatal;
    if (!build_inputs(r, input, first))
        goto fatal;
    ir_x86_frontend_destroy(frontend);
    if (info)
        *info = r->info;
    return r;
fatal:
    if (info) {
        *info = r->info;
        info->status = fatal_status(r);
        if (r->input_status == IR_RESOURCE_LIMIT)
            info->issues |= IR_REPLAY_INPUT_BUDGET;
    }
    ir_x86_frontend_destroy(frontend);
    ir_replay_destroy(r);
    return NULL;
}

static IrBits observed_bv(void *user, IrBindingKind kind, uint64_t key, uint8_t width) {
    const IrReplay *r = user;
    if (kind == IR_BIND_STATE && key >= IR_X86_GPR_KEY_BASE &&
        key < IR_X86_GPR_KEY_BASE + IR_X86_GPR_COUNT && width == 32)
        return r->initial_gpr[key - IR_X86_GPR_KEY_BASE];
    if (kind == IR_BIND_STATE && key >= IR_X86_FLAG_KEY_BASE &&
        key < IR_X86_FLAG_KEY_BASE + IR_X86_FLAG_COUNT && width == 1)
        return r->initial_flags[key - IR_X86_FLAG_KEY_BASE];
    return ir_bits_unknown(IR_REASON_UNBOUND_STATE);
}

static IrBits observed_byte(void *user, IrBindingKind kind, uint64_t key, uint64_t address) {
    const IrReplay *r = user;
    if (kind != IR_BIND_STATE || key != IR_X86_MEMORY_KEY || address > UINT32_MAX ||
        !r->memory_capacity)
        return ir_bits_unknown(IR_REASON_MEMORY);
    const ReplayByte *b = &r->memory[byte_slot(r->memory, r->memory_capacity, (uint32_t)address)];
    return b->occupied && b->known ? ir_bits_known(b->initial, 8)
                                   : ir_bits_unknown(IR_REASON_MEMORY);
}

IrBindings ir_replay_observed_bindings(IrReplay *r) {
    return r ? (IrBindings){.user = r, .read_bv = observed_bv, .read_byte = observed_byte}
             : (IrBindings){0};
}

IrReplayCheckResult ir_replay_check_gpr_candidate(IrReplay *r, const IrEvalLimits *limits,
                                                  const IrReplayGprCandidate *candidate) {
    IrReplayCheckResult check = {.status = IR_REPLAY_CHECK_ERROR,
                                 .candidate_requested = candidate != NULL,
                                 .candidate_status = IR_REPLAY_CHECK_UNKNOWN,
                                 .candidate_actual = ir_bits_unknown(IR_REASON_NOT_EXECUTED)};
    if (!r)
        return check;
    if (candidate &&
        (candidate->trigger_seq != r->trigger_seq || candidate->gpr_index >= IR_X86_GPR_COUNT))
        return check;
    IrBindings bindings = ir_replay_observed_bindings(r);
    IrEval *eval = ir_eval_create(r->module, &bindings, limits);
    if (!eval)
        return check;
    check.execution = ir_eval_run(eval);
    check.evaluator_bytes = ir_eval_allocated_bytes(eval);
    if (check.execution.status == IR_EVAL_INVALID ||
        check.execution.status == IR_EVAL_OUT_OF_MEMORY) {
        ir_eval_destroy(eval);
        return check;
    }
    for (uint32_t i = 0; i < r->observation_count; ++i) {
        const IrReplayObservation *o = &r->observations[i];
        if (o->architectural_undefined) {
            ++check.skipped_undefined;
            continue;
        }
        IrEvalValue actual = ir_eval_value(eval, o->value);
        if (!o->expected_valid || actual.type.kind != IR_TYPE_BV || actual.type.bits != o->width) {
            ++check.unknown;
            continue;
        }
        uint64_t known = actual.bits.known_mask & ir_width_mask(o->width);
        if ((actual.bits.value ^ o->expected) & known) {
            ++check.mismatches;
            if (!check.has_first_mismatch) {
                check.has_first_mismatch = true;
                check.first_mismatch = *o;
                check.actual = actual.bits;
            }
        } else if (known != ir_width_mask(o->width))
            ++check.unknown;
        else
            ++check.checked;
    }
    if (candidate && r->info.status == IR_REPLAY_READY && r->info.selected_steps &&
        check.execution.status == IR_EVAL_FRAGMENT_END) {
        IrEvalValue value = ir_eval_state(eval, r->state.gpr[candidate->gpr_index]);
        if (value.type.kind == IR_TYPE_BV && value.type.bits == 32) {
            check.candidate_actual = value.bits;
            if ((value.bits.value ^ candidate->expected_target) & value.bits.known_mask &
                UINT32_MAX)
                check.candidate_status = IR_REPLAY_CHECK_MISMATCH;
            else if (ir_bits_complete(value.bits, 32))
                check.candidate_status = IR_REPLAY_CHECK_MATCH;
        }
    }
    if (check.mismatches || (candidate && check.candidate_status == IR_REPLAY_CHECK_MISMATCH))
        check.status = IR_REPLAY_CHECK_MISMATCH;
    else if (check.unknown || r->info.status != IR_REPLAY_READY ||
             check.execution.status != IR_EVAL_FRAGMENT_END || check.execution.quality.semantic ||
             check.execution.quality.control || check.execution.quality.observation ||
             (candidate && check.candidate_status != IR_REPLAY_CHECK_MATCH))
        check.status = IR_REPLAY_CHECK_UNKNOWN;
    else
        check.status = IR_REPLAY_CHECK_MATCH;
    ir_eval_destroy(eval);
    return check;
}

IrReplayCheckResult ir_replay_check(IrReplay *r, const IrEvalLimits *limits) {
    return ir_replay_check_gpr_candidate(r, limits, NULL);
}
