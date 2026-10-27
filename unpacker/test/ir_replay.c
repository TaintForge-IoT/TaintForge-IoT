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
    IrOrigin current_origin;
    IrX86State state;
    IrReplayOptions options;
    IrReplayBuildInfo info;
    IrEnvironment *environment;
    IrStateId executable_state;
    uint8_t *executable_bytes;
    uint32_t executable_size;
    uint64_t executable_identity;
    uint16_t executable_link_size;
    uint8_t executable_link[DSE_SYSCALL_PATH_BYTES];
    IrOrigin executable_origin;
    IrStateId stdin_state;
    uint8_t *stdin_bytes;
    uint32_t stdin_size, stdin_count, stdin_done;
    IrReplayStdinRead stdin_reads[IR_REPLAY_STDIN_MAX_READS];
    IrOrigin stdin_origin;
    uint64_t stdin_boundary;
    IrBits initial_gpr[IR_X86_GPR_COUNT];
    IrBits initial_flags[IR_X86_FLAG_COUNT];
    IrBits initial_tls[IR_X86_TLS_COUNT];
    IrReplayObservation *observations;
    uint32_t observation_count, observation_capacity;
    ReplayByte *memory;
    uint32_t memory_count, memory_capacity;
    IrValueId flag_defined[IR_X86_FLAG_COUNT];
    IrStateId flag_defined_state[IR_X86_FLAG_COUNT];
    IrReplayTarget target;
    uint32_t undefined_flags; /* Architectural status along the unrolled path. */
    bool allocation_failed;
    uint64_t trigger_seq;
    IrInputs *inputs;
    IrStatus input_status;
    uint64_t input_scan_work;
    /* Builder-only, same-block state versions; no extra x86/syscall semantics. */
    IrBlockId checkpoint_block;
    IrInstId checkpoint_cursor;
    IrValueId checkpoint_values[IR_X86_GPR_COUNT + IR_X86_FLAG_COUNT];
};

size_t ir_replay_allocated_bytes(const IrReplay *r) {
    if (!r)
        return 0;
    return sizeof(*r) + ir_module_allocated_bytes(r->module) +
           (size_t)r->observation_capacity * sizeof(*r->observations) +
           (size_t)r->memory_capacity * sizeof(*r->memory) + ir_inputs_bytes(r->inputs) +
           ir_environment_bytes(r->environment) + r->executable_size + r->stdin_size;
}

static const unsigned flag_bit[IR_X86_FLAG_COUNT] = {0, 2, 4, 6, 7, 11, 10};

IrReplayOptions ir_replay_default_options(void) {
    IrReplayOptions options = {.module = ir_default_limits(),
                               .max_steps = 4096,
                               .max_observations = 131072,
                               .max_memory_bytes = 65536,
                               .max_repeat_iterations = 65536,
                               .max_file_objects = IR_ENV_MAX_FILES,
                               .max_file_content_cells = 65536,
                               .max_executable_bytes = 65536};
    /* Up to 15 state observations per boundary, four per RMW and one per Jcc. */
    options.module.outputs = options.max_observations;
    options.inputs = ir_input_default_limits();
    return options;
}

void ir_replay_destroy(IrReplay *r) {
    if (!r)
        return;
    ir_environment_destroy(r->environment);
    ir_module_destroy(r->module);
    ir_inputs_release(r->inputs);
    free(r->observations);
    free(r->memory);
    free(r->executable_bytes);
    free(r->stdin_bytes);
    free(r);
}

IrModule *ir_replay_module(IrReplay *r) {
    return r ? r->module : NULL;
}

const IrX86State *ir_replay_state(const IrReplay *r) {
    return r ? &r->state : NULL;
}

IrStateId ir_replay_stdin_state(const IrReplay *r) {
    return r ? r->stdin_state : 0;
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
    if (issues &
        (IR_REPLAY_IDENTITY | IR_REPLAY_GAP | IR_REPLAY_PENDING | IR_REPLAY_OBSERVATION_MISSING |
         IR_REPLAY_CONTROL_MISMATCH | IR_REPLAY_SYSCALL_OBSERVATION))
        reasons |= IR_REASON_TRACE_GAP;
    if (issues &
        (IR_REPLAY_UNSUPPORTED | IR_REPLAY_MODE | IR_REPLAY_MEMORY_MODEL | IR_REPLAY_SYSCALL_MODEL))
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
    q.semantic = core_reasons(
        issues & (IR_REPLAY_IDENTITY | IR_REPLAY_MODE | IR_REPLAY_UNSUPPORTED | IR_REPLAY_PENDING |
                  IR_REPLAY_MEMORY_MODEL | IR_REPLAY_BUDGET | IR_REPLAY_SYSCALL_MODEL));
    q.control =
        core_reasons(issues & (IR_REPLAY_IDENTITY | IR_REPLAY_GAP | IR_REPLAY_CONTROL_MISMATCH));
    q.observation =
        core_reasons(issues & (IR_REPLAY_PENDING | IR_REPLAY_OBSERVATION_MISSING |
                               IR_REPLAY_OBSERVATION_SHAPE | IR_REPLAY_SYSCALL_OBSERVATION));
    ir_module_note_quality(r->module, q);
}

static void replay_budget(IrReplay *r, IrBudgetKind kind, uint64_t used, uint64_t limit,
                          uint64_t requested, IrOrigin origin) {
    if (r->info.replay_budget.kind != IR_BUDGET_NONE) return;
    IrBuildPhase phase = ir_module_build_phase(r->module, IR_BUILD_OTHER);
    ir_module_build_phase(r->module, phase);
    r->info.replay_budget = (IrBudgetFailure){kind, used, limit, requested, origin, phase};
}

static void snapshot_build(IrReplay *r) {
    r->info.construction = ir_module_build_metrics(r->module);
    r->info.observations = r->observation_count;
    r->info.memory_bytes = r->memory_count;
    r->info.files = ir_environment_stats(r->environment);
}

static void stop(IrReplay *r, IrBlockId b, uint32_t issues, IrOrigin origin) {
    note(r, issues);
    r->info.stopped_seq = origin.seq_id;
    r->info.stopped_origin = origin;
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
    if (r->observation_count == r->options.max_observations) {
        replay_budget(r, IR_BUDGET_OBSERVATIONS, r->observation_count,
                      r->options.max_observations, (uint64_t)r->observation_count + 1, o.origin);
        return false;
    }
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
    if (o.defined_when && !ir_module_add_output(r->module, o.defined_when))
        return false;
    if (!o.architectural_undefined && !ir_module_add_output(r->module, o.value))
        return false;
    o.expected &= ir_width_mask(o.width);
    r->observations[r->observation_count++] = o;
    if (!o.expected_valid && !o.architectural_undefined)
        note(r, IR_REPLAY_OBSERVATION_MISSING);
    return true;
}

/* Scan each newly appended instruction once. READ_STATE/WRITE_STATE are the
 * shared contract for both the frontend and environment. A GUARD changes no
 * state: the checkpoint marker below enforces reachability across it. A BARRIER
 * invalidates conservatively; no value is imported from a predecessor block. */
static void checkpoint_sync(IrReplay *r, IrBlockId block) {
    const IrBlock *b = ir_module_block(r->module, block);
    if (r->checkpoint_block != block) {
        r->checkpoint_block = block;
        r->checkpoint_cursor = 0;
        memset(r->checkpoint_values, 0, sizeof(r->checkpoint_values));
    }
    IrInstId next = r->checkpoint_cursor
        ? ir_module_inst(r->module, r->checkpoint_cursor)->next : b->first;
    for (IrInstId id = next; id; id = ir_module_inst(r->module, id)->next) {
        const IrInst *inst = ir_module_inst(r->module, id);
        r->checkpoint_cursor = id;
        if (inst->spec.op == IR_OP_BARRIER) {
            memset(r->checkpoint_values, 0, sizeof(r->checkpoint_values));
            continue;
        }
        if (inst->spec.op != IR_OP_READ_STATE && inst->spec.op != IR_OP_WRITE_STATE)
            continue;
        for (unsigned i = 0; i < IR_X86_GPR_COUNT + IR_X86_FLAG_COUNT; ++i) {
            IrStateId state = i < IR_X86_GPR_COUNT ? r->state.gpr[i]
                : r->state.flags[i - IR_X86_GPR_COUNT];
            if (inst->spec.state == state) {
                r->checkpoint_values[i] = inst->spec.op == IR_OP_READ_STATE
                    ? inst->result : inst->spec.args[0];
                break;
            }
        }
    }
}

static bool checkpoint_profiled_body(IrReplay *r, IrBlockId b, IrOrigin origin, const InsnAux *aux) {
    checkpoint_sync(r, b);
    /* One marker replaces up to fifteen execution-position READ_STATEs. Keep
     * it exported so SSA/DCE cannot erase the checkpoint. Never infer that an
     * observation ran merely because its reused value is already available. */
    IrValueId reached = ir_emit_value(r->module, b, (IrInstSpec){
        .op = IR_OP_CONST, .type = ir_type_bv(1), .immediate = 1, .origin = origin});
    if (!reached || !ir_module_add_output(r->module, reached))
        return false;
    for (unsigned i = 0; i < IR_X86_GPR_COUNT + IR_X86_FLAG_COUNT; ++i) {
        bool flag = i >= IR_X86_GPR_COUNT;
        unsigned index = flag ? i - IR_X86_GPR_COUNT : i;
        IrReplayObservation o = {.origin = origin,
                                 .index = index,
                                 .kind = flag ? IR_REPLAY_FLAG : IR_REPLAY_GPR,
                                 .width = flag ? 1 : 32, .reached = reached};
        IrStateId state = flag ? r->state.flags[index] : r->state.gpr[index];
        o.architectural_undefined = flag && (r->undefined_flags & (UINT32_C(1) << index));
        o.defined_when = flag ? r->flag_defined[index] : 0;
        if (!o.architectural_undefined) {
            if (!r->checkpoint_values[i])
                r->checkpoint_values[i] = ir_emit_value(r->module, b,
                    (IrInstSpec){.op = IR_OP_READ_STATE, .type = ir_type_bv(o.width),
                                 .state = state, .origin = origin});
            o.value = r->checkpoint_values[i];
        }
        if (o.defined_when && !o.architectural_undefined) {
            /* The observation is conditional; architectural state is not.
             * Keep undefined flags available to later branch semantics, while
             * not requiring an undefined checkpoint value as an output. */
            IrValueId zero = ir_emit_value(
                r->module, b,
                (IrInstSpec){.op = IR_OP_CONST, .type = ir_type_bv(1), .origin = origin});
            o.value = ir_emit_value(r->module, b,
                                    (IrInstSpec){.op = IR_OP_ITE,
                                                 .type = ir_type_bv(1),
                                                 .args = {o.defined_when, o.value, zero},
                                                 .origin = origin});
        }
        if (aux) {
            o.expected_valid = flag ? aux->eflags_valid
                                    : (aux->reg_value_valid_mask & (UINT32_C(1) << index)) != 0;
            o.expected = flag ? (aux->eflags_before >> flag_bit[index]) & 1U : aux->reg_vals[index];
        }
        if (!add_observation(r, o))
            return false;
    }
    r->checkpoint_cursor = ir_module_block(r->module, b)->last;
    return true;
}
static bool checkpoint(IrReplay *r, IrBlockId b, IrOrigin origin, const InsnAux *aux) {
    IrBuildPhase previous = ir_module_build_phase(r->module, IR_BUILD_OBSERVATIONS);
    bool result = checkpoint_profiled_body(r, b, origin, aux);
    ir_module_build_phase(r->module, previous);
    return result;
}


/* Segment state is observed only when used, so an unavailable unused FS does
 * not spoil a GS-only fragment. The first boundary remains the sole binding. */
static bool observe_tls_profiled_body(IrReplay *r, IrBlockId block, IrOrigin origin, const InsnAux *aux,
                        uint8_t used) {
    for (unsigned i = 0; i < IR_X86_TLS_COUNT; ++i) {
        if (!(used & (1U << i)))
            continue;
        IrValueId value = ir_emit_value(r->module, block,
                                        (IrInstSpec){.op = IR_OP_READ_STATE,
                                                     .type = ir_type_bv(32),
                                                     .state = r->state.tls_base[i],
                                                     .origin = origin});
        if (!add_observation(
                r, (IrReplayObservation){.kind = IR_REPLAY_TLS_BASE,
                                         .origin = origin,
                                         .value = value,
                                         .width = 32,
                                         .index = i,
                                         .expected_valid = aux && (aux->tls_valid_mask & (1U << i)),
                                         .expected = aux ? aux->tls_base[i] : 0}))
            return false;
    }
    return true;
}
static bool observe_tls(IrReplay *r, IrBlockId block, IrOrigin origin, const InsnAux *aux, uint8_t used) {
    IrBuildPhase previous = ir_module_build_phase(r->module, IR_BUILD_OBSERVATIONS);
    bool result = observe_tls_profiled_body(r, block, origin, aux, used);
    ir_module_build_phase(r->module, previous);
    return result;
}


static bool syscall_instruction(const InsnDesc *d) {
    return d->native_insn_id == X86_INS_INT || d->native_insn_id == X86_INS_SYSENTER ||
           d->native_insn_id == X86_INS_SYSCALL;
}

static bool observe_memory(IrReplay *r, IrOrigin origin, IrX86LiftResult lift,
                           const InsnOccurrence *o, const InsnAux *aux);

static IrValueId replay_constant(IrReplay *r, IrBlockId b, IrOrigin o, unsigned bits, uint64_t n) {
    return ir_emit_value(r->module,b,(IrInstSpec){.op=IR_OP_CONST,.type=ir_type_bv(bits),
                                                .immediate=n,.origin=o});
}
static void replay_guard(IrReplay *r,IrBlockId b,IrOrigin o,IrValueId value,unsigned bits,uint64_t n) {
    IrValueId expected=replay_constant(r,b,o,bits,n);
    IrValueId equal=ir_emit_value(r->module,b,(IrInstSpec){.op=IR_OP_EQ,.type=ir_type_bv(1),
                                                        .args={value,expected},.origin=o});
    (void)ir_emit_effect(r->module,b,(IrInstSpec){.op=IR_OP_GUARD,.type=ir_type_void(),
        .args={equal},.immediate=IR_REASON_GUARD,.origin=o});
}
static IrValueId kernel_read(IrReplay *r,IrX86Frontend *f,IrBlockId b,IrOrigin o,
                             uint32_t address,unsigned bytes,uint64_t observed) {
    IrValueId a=replay_constant(r,b,o,32,address);
    IrValueId value=ir_x86_memory_read(f,b,o,a,bytes);
    IrX86LiftResult lift={.memory_count=1,.memory={{false,(uint8_t)bytes,a,value}}};
    InsnOccurrence occurrence={.dynamic_effects_available=true,.execution_complete=true,
        .mem_read_count=1,.mem_read_total=1,
        .mem_reads={{.kind=TRACE_MEM_READ,.address=address,.size=(uint8_t)bytes,
                     .value=observed,.value_valid=true}}};
    /* Kernel payload observations have no invented provenance labels. */
    return value && observe_memory(r,o,lift,&occurrence,NULL)?value:0;
}
static bool kernel_write(IrReplay *r,IrX86Frontend *f,IrBlockId b,IrOrigin o,
                           uint32_t address,uint8_t value,uint8_t observed) {
    IrValueId a=replay_constant(r,b,o,32,address),v=replay_constant(r,b,o,8,value);
    if(!ir_x86_memory_write(f,b,o,a,1,v)) return false;
    IrX86LiftResult lift={.memory_count=1,.memory={{true,1,a,v}}};
    InsnOccurrence occurrence={.dynamic_effects_available=true,.execution_complete=true,
        .mem_write_count=1,.mem_write_total=1,
        .mem_writes={{.kind=TRACE_MEM_WRITE,.address=address,.size=1,.value=observed,.value_valid=true}}};
    return observe_memory(r,o,lift,&occurrence,NULL);
}

static uint32_t lift_stdin_read(IrReplay *r, IrX86Frontend *f, IrBlockId b,
                                const ReplayStep *step, const InsnAux *aux) {
    const DseSyscallObservation *s = aux->syscall;
    if (r->stdin_done >= r->stdin_count) {
        r->info.environment_reason = "stdin_read_not_in_ledger";
        return IR_REPLAY_SYSCALL_MODEL;
    }
    const IrReplayStdinRead *read = &r->stdin_reads[r->stdin_done];
    if (step->entry.seq_id != read->seq || s->number != 3 || s->args[0] ||
        s->args[1] != read->address || s->args[2] != read->requested ||
        s->result != read->returned) {
        r->info.environment_reason = "stdin_read_ledger_mismatch";
        return IR_REPLAY_SYSCALL_OBSERVATION;
    }
    /* The syscall's modeled architectural contract is independently observed
     * at the next instruction, not guessed from its return callback. */
    if (!aux->valid || aux->seq_id != step->entry.seq_id ||
        aux->meta_id != step->entry.meta_id || aux->pc != step->entry.pc ||
        !aux->execution_complete || !aux->next_pc_valid ||
        aux->next_pc != (uint32_t)(step->entry.pc + 2U) ||
        (aux->reg_value_valid_mask & 255U) != 255U ||
        !aux->eflags_valid || (aux->eflags_before & (1U << 17)) ||
        !s->post_observed || (s->post_valid_mask & 255U) != 255U ||
        !s->post_eflags_valid || s->post_eflags != aux->eflags_before ||
        s->post_regs[REG_RAX] != s->result || !s->boundary_id ||
        !s->boundary_ordered || (r->stdin_boundary &&
         (r->stdin_boundary == UINT64_MAX || s->boundary_id != r->stdin_boundary + 1U)) ||
        aux->has_mem_read || aux->has_mem_write || aux->mem_read_count ||
        aux->mem_write_count || aux->mem_read_total || aux->mem_write_total ||
        aux->mem_read_overflow || aux->mem_write_overflow) {
        r->info.environment_reason = "stdin_architectural_contract_missing";
        return IR_REPLAY_SYSCALL_OBSERVATION;
    }
    const unsigned regs[] = {REG_RAX, REG_RBX, REG_RCX, REG_RDX};
    const uint32_t expected[] = {3, 0, read->address, read->requested};
    for (unsigned i = 0; i < 4; ++i) {
        if (aux->reg_vals[regs[i]] != expected[i]) {
            r->info.environment_reason = "stdin_entry_register_mismatch";
            return IR_REPLAY_SYSCALL_OBSERVATION;
        }
    }
    for (unsigned i = 1; i < 8; ++i) {
        if (aux->reg_vals[i] != s->post_regs[i]) {
            r->info.environment_reason = "stdin_preserved_register_mismatch";
            return IR_REPLAY_SYSCALL_OBSERVATION;
        }
    }
    IrOrigin o = origin_of(step);
    for (unsigned i = 0; i < 4; ++i) {
        IrValueId value = ir_emit_value(r->module, b, (IrInstSpec){
            .op=IR_OP_READ_STATE, .type=ir_type_bv(32),
            .state=r->state.gpr[regs[i]], .origin=o});
        replay_guard(r, b, o, value, 32, expected[i]);
    }
    IrValueId source = 0;
    if (read->returned)
        source = ir_emit_value(r->module, b, (IrInstSpec){
            .op=IR_OP_READ_STATE, .type=ir_type_mem(32), .state=r->stdin_state, .origin=o});
    for (uint32_t i = 0; i < read->returned; ++i) {
        IrValueId offset = replay_constant(r, b, o, 32, read->offset+i);
        IrValueId byte = ir_emit_value(r->module, b, (IrInstSpec){
            .op=IR_OP_LOAD, .type=ir_type_bv(8), .args={source,offset},
            .endian=IR_ENDIAN_LE, .origin=o});
        IrValueId address = replay_constant(r, b, o, 32, read->address+i);
        if (!byte || !ir_x86_memory_write(f, b, o, address, 1, byte))
            return IR_REPLAY_BUDGET;
        /* Mark these as chronological stores. A later guest load must never
         * reintroduce a read's observed output as fresh boundary memory. */
        IrX86LiftResult lift = {.memory_count=1, .memory={{true,1,address,byte}}};
        InsnOccurrence occurrence = {.dynamic_effects_available=true, .execution_complete=true,
            .mem_write_count=1, .mem_write_total=1,
            .mem_writes={{.kind=TRACE_MEM_WRITE,.address=read->address+i,.size=1,
                .value=r->stdin_bytes[read->offset+i],.value_valid=true}}};
        if (!observe_memory(r, o, lift, &occurrence, NULL)) return IR_REPLAY_BUDGET;
    }
    IrValueId result = replay_constant(r, b, o, 32, read->returned);
    (void)ir_emit_effect(r->module, b, (IrInstSpec){.op=IR_OP_WRITE_STATE,
        .type=ir_type_void(), .state=r->state.gpr[REG_RAX], .args={result}, .origin=o});
    r->stdin_boundary = s->boundary_id;
    ++r->stdin_done;
    ++r->info.modeled_stdin_reads;
    r->info.stdin_bytes += read->returned;
    r->info.syscall_present = false;
    r->info.stopped_syscall = (DseSyscallObservation){0};
    return 0;
}

static uint32_t environment_failure(IrReplay *r) {
    r->info.environment_reason=ir_environment_issue(r->environment);
    return ir_environment_budget(r->environment)?IR_REPLAY_BUDGET:IR_REPLAY_SYSCALL_MODEL;
}
static uint32_t lift_file_syscall(IrReplay *r,IrX86Frontend *f,IrBlockId b,
                                  const ReplayStep *step,const InsnAux *aux) {
    const DseSyscallObservation *s=aux->syscall;
    bool create=s->number==356,resize=s->number==93,map=s->number==90 || s->number==192,
         writing=s->number==4,closing=s->number==6,sync=s->number==144,heap=s->number==45;
    uint32_t mapped[6]={0};
    const char *issue=create?dse_aux_memfd_issue(&step->entry,aux):
        resize?dse_aux_ftruncate_issue(&step->entry,aux):
        map?dse_aux_ir_mmap_issue(&step->entry,aux,mapped):
        writing?dse_aux_write_issue(&step->entry,aux):
        sync?dse_aux_msync_issue(&step->entry,aux):
        heap?dse_aux_brk_issue(&step->entry,aux):dse_aux_close_issue(&step->entry,aux);
    if(issue) { r->info.environment_reason=issue;return IR_REPLAY_SYSCALL_OBSERVATION; }
    if(resize && s->result) {r->info.environment_reason="truncate_not_successful";return IR_REPLAY_SYSCALL_MODEL;}
    if(!ir_environment_order(r->environment,s->boundary_id,step->entry.seq_id,
                              step->entry.vcpu_index,s->boundary_ordered)) return environment_failure(r);
    IrOrigin o=origin_of(step);
    const unsigned regs[]={REG_RAX,REG_RBX,REG_RCX,REG_RDX,REG_RSI,REG_RDI,REG_RBP};
    const uint32_t expected[]={s->number,s->args[0],s->args[1],s->args[2],s->args[3],s->args[4],s->args[5]};
    unsigned count=s->number==192?7U:map||closing||heap?2U:writing||sync?4U:3U;
    for(unsigned i=0;i<count;++i) {
        IrValueId value=ir_emit_value(r->module,b,(IrInstSpec){.op=IR_OP_READ_STATE,
            .type=ir_type_bv(32),.state=r->state.gpr[regs[i]],.origin=o});
        replay_guard(r,b,o,value,32,expected[i]);
    }
    bool ok=false;
    if(create) {
        for(unsigned i=0;i<s->name_size;++i) {
            IrValueId value=kernel_read(r,f,b,o,s->args[0]+i,1,s->name[i]);
            if(!value) return IR_REPLAY_BUDGET;
            replay_guard(r,b,o,value,8,s->name[i]);
        }
        ok=ir_environment_file_create(r->environment,b,o,s->result,s->args[1],s->boundary_id);
    } else if(resize) {
        ok=ir_environment_resize(r->environment,b,o,s->args[0],s->args[1]);
    } else if(map) {
        const uint32_t *a=mapped;
        uint64_t end=(uint64_t)s->result+(((uint64_t)a[1]+4095U)&~UINT64_C(4095));
        for(unsigned i=0;s->number==90 && i<6;++i) {
            IrValueId value=kernel_read(r,f,b,o,s->args[0]+i*4U,4,a[i]);
            if(!value) return IR_REPLAY_BUDGET;
            replay_guard(r,b,o,value,32,a[i]);
        }
        ok=ir_environment_map(r->environment,b,o,a[4],s->result,a[1],a[5],a[3],a[2]);
        if(ok) {
            IrStatus status=ir_x86_map_memory(f,s->result,end,a[2]);
            if(status!=IR_OK) return status==IR_RESOURCE_LIMIT?IR_REPLAY_BUDGET:IR_REPLAY_MEMORY_MODEL;
        }
    } else if(writing) {
        if(!ir_environment_write_check(r->environment,s->args[0],s->args[1],s->result))
            return environment_failure(r);
        IrValueId *values=s->result?calloc(s->result,sizeof(*values)):NULL;
        if(s->result && !values) {r->allocation_failed=true;return IR_REPLAY_BUDGET;}
        for(uint32_t i=0;i<s->result;++i) {
            values[i]=kernel_read(r,f,b,o,s->args[1]+i,1,s->write_values[i]);
            if(!values[i]) {free(values);return IR_REPLAY_BUDGET;}
        }
        ok=ir_environment_write(r->environment,b,o,s->args[0],values,s->result);
        free(values);
    } else if(closing) ok=ir_environment_close(r->environment,s->args[0]);
    else if(sync) ok=ir_environment_sync(r->environment,s->args[0],s->args[1],s->args[2]);
    else if(heap) {
        ok=ir_environment_brk(r->environment,b,o,s->brk_initial,s->brk_before,s->args[0],s->brk_after);
        if(ok) {
            uint64_t before=((uint64_t)s->brk_before+4095U)&~UINT64_C(4095);
            uint64_t after=((uint64_t)s->brk_after+4095U)&~UINT64_C(4095);
            IrStatus status=IR_OK;
            if(after>before) status=ir_x86_map_memory(f,(uint32_t)before,after,3);
            if(after<before) status=ir_x86_exclude_memory(f,(uint32_t)after,before);
            if(status!=IR_OK) return status==IR_RESOURCE_LIMIT?IR_REPLAY_BUDGET:IR_REPLAY_MEMORY_MODEL;
        }
    }
    if(!ok) return environment_failure(r);
    IrValueId result=replay_constant(r,b,o,32,s->result);
    (void)ir_emit_effect(r->module,b,(IrInstSpec){.op=IR_OP_WRITE_STATE,.type=ir_type_void(),
        .state=r->state.gpr[REG_RAX],.args={result},.origin=o});
    r->info.syscall_present=false;r->info.stopped_syscall=(DseSyscallObservation){0};
    return 0;
}

static uint32_t lift_proc_exe_syscall(IrReplay *r,IrX86Frontend *f,IrBlockId b,
                                     const ReplayStep *step,const InsnAux *aux) {
    const DseSyscallObservation *s=aux->syscall;
    bool opening=s->number==5;
    const char *issue=opening?dse_aux_open_executable_issue(&step->entry,aux):
                               dse_aux_readlink_executable_issue(&step->entry,aux);
    if(issue) {r->info.environment_reason=issue;return IR_REPLAY_SYSCALL_OBSERVATION;}
    if(!ir_environment_order(r->environment,s->boundary_id,step->entry.seq_id,
                             step->entry.vcpu_index,s->boundary_ordered)) return environment_failure(r);
    const DseSyscallFileObservation *src=s->file;
    if(r->executable_identity && (r->executable_identity!=src->source_identity ||
        r->executable_link_size!=src->link_size || memcmp(r->executable_link,src->link,src->link_size))) {
        r->info.environment_reason="executable_identity_or_link_changed";return IR_REPLAY_SYSCALL_MODEL;
    }
    r->executable_identity=src->source_identity;r->executable_link_size=src->link_size;
    memcpy(r->executable_link,src->link,src->link_size);
    IrOrigin o=origin_of(step);
    const unsigned regs[]={REG_RAX,REG_RBX,REG_RCX,REG_RDX};
    const uint32_t expected[]={s->number,s->args[0],s->args[1],s->args[2]};
    for(unsigned i=0;i<(opening?3U:4U);++i) {
        IrValueId value=ir_emit_value(r->module,b,(IrInstSpec){.op=IR_OP_READ_STATE,
            .type=ir_type_bv(32),.state=r->state.gpr[regs[i]],.origin=o});
        replay_guard(r,b,o,value,32,expected[i]);
    }
    for(unsigned i=0;i<src->path_size;++i) {
        IrValueId value=kernel_read(r,f,b,o,s->args[0]+i,1,src->path[i]);
        if(!value) return IR_REPLAY_BUDGET;
        replay_guard(r,b,o,value,8,src->path[i]);
    }
    if(opening) {
        if(src->content_size>r->options.max_executable_bytes) {
            r->info.environment_reason="executable_snapshot_budget";return IR_REPLAY_BUDGET;
        }
        if(r->executable_state) {
            if(r->executable_size!=src->content_size ||
                (src->content_size && memcmp(r->executable_bytes,src->contents,src->content_size))) {
                r->info.environment_reason="executable_contents_changed";return IR_REPLAY_SYSCALL_MODEL;
            }
        } else {
            r->executable_state=ir_state_add(r->module,ir_type_mem(32),IR_PROC_EXE_INPUT_KEY,false);
            if(!r->executable_state) return IR_REPLAY_BUDGET;
            r->executable_bytes=src->content_size?malloc(src->content_size):NULL;
            if(src->content_size && !r->executable_bytes) {r->allocation_failed=true;return IR_REPLAY_BUDGET;}
            if(src->content_size) memcpy(r->executable_bytes,src->contents,src->content_size);
            r->executable_size=src->content_size;r->executable_origin=o;
            r->info.executable_snapshot_bytes=src->content_size;
        }
        IrValueId source=ir_emit_value(r->module,b,(IrInstSpec){.op=IR_OP_READ_STATE,
            .type=ir_type_mem(32),.state=r->executable_state,.origin=o});
        if(!ir_environment_file_open(r->environment,b,o,s->result,s->args[1],src->source_identity,
                                     src->content_size,source)) return environment_failure(r);
    } else {
        for(uint32_t i=0;i<s->result;++i)
            if(!kernel_write(r,f,b,o,s->args[1]+i,src->link[i],src->reply[i])) return IR_REPLAY_BUDGET;
        ++r->info.modeled_readlink;r->info.readlink_bytes+=s->result;
    }
    IrValueId result=replay_constant(r,b,o,32,s->result);
    (void)ir_emit_effect(r->module,b,(IrInstSpec){.op=IR_OP_WRITE_STATE,.type=ir_type_void(),
        .state=r->state.gpr[REG_RAX],.args={result},.origin=o});
    r->info.syscall_present=false;r->info.stopped_syscall=(DseSyscallObservation){0};
    return 0;
}

/* A syscall observation is an environment contract, never a substitute for
 * instruction semantics. No generic "clobber EAX and continue" fallback. */
static uint32_t lift_syscall(IrReplay *r, IrX86Frontend *f, IrBlockId block, const ReplayStep *step,
                             const InsnAux *aux) {
    const DseSyscallObservation *e = aux ? aux->syscall : NULL;
    const TraceEntry *t = &step->entry;
    if (e) {
        r->info.syscall_present = true;
        r->info.stopped_syscall = *e;
        /* This diagnostic is a value-only header, not an owned replay input. */
        r->info.stopped_syscall.file = NULL;
        r->info.stopped_syscall.write_values = NULL;
        r->info.stopped_syscall.write_size = 0;
        r->info.stopped_syscall.write_valid = false;
    }
    if (!e || aux->syscall_metadata_lost || !e->returned || e->invalid || e->seq_id != t->seq_id ||
        e->pc != t->pc || e->vcpu_index != t->vcpu_index || e->descriptor_id != t->insn_desc_id ||
        e->bytes_hash != t->bytes_hash || e->code_generation != t->code_generation)
        return IR_REPLAY_SYSCALL_OBSERVATION;
    if (r->stdin_state && e->number == 3 && r->options.x86.flat32_ram &&
        step->descriptor.size == 2 && step->descriptor.bytes[0] == 0xcd &&
        step->descriptor.bytes[1] == 0x80)
        return lift_stdin_read(r, f, block, step, aux);
    if(r->options.observed_proc_exe && r->environment && (e->number==5 || e->number==85) &&
        r->options.x86.flat32_ram && step->descriptor.size==2 &&
        step->descriptor.bytes[0]==0xcd && step->descriptor.bytes[1]==0x80)
        return lift_proc_exe_syscall(r,f,block,step,aux);
    bool protect = e->number == 125 && r->options.observed_mprotect;
    bool unmap = e->number == 91 && r->options.observed_munmap;
    bool file = r->options.observed_files && (e->number==356 || e->number==93 ||
                                             e->number==90 || e->number==192 || e->number==144 || e->number==45 ||
                                             e->number==4 || e->number==6);
    if(file && r->options.x86.flat32_ram && step->descriptor.size==2 &&
       step->descriptor.bytes[0]==0xcd && step->descriptor.bytes[1]==0x80)
        return lift_file_syscall(r,f,block,step,aux);
    if ((!protect && !unmap) || !r->options.x86.flat32_ram || step->descriptor.size != 2 ||
        step->descriptor.bytes[0] != 0xcd || step->descriptor.bytes[1] != 0x80)
        return IR_REPLAY_SYSCALL_MODEL;
    unsigned regs[4] = {REG_RAX, REG_RBX, REG_RCX, REG_RDX};
    uint32_t expected[4] = {e->number, e->args[0], e->args[1], e->args[2]};
    unsigned count = protect ? 4 : 3;
    for (unsigned i = 0; i < count; ++i)
        if (!(aux->reg_value_valid_mask & (1U << regs[i])) || aux->reg_vals[regs[i]] != expected[i])
            return IR_REPLAY_SYSCALL_OBSERVATION;
    if (e->result != 0 && e->result < UINT32_C(0xfffff001))
        return IR_REPLAY_SYSCALL_OBSERVATION;
    /* A failed protection change is not generally an atomic no-op. Do not
     * continue from a guessed permission map, or infer implicit x86 rights. */
    if (protect && (e->result || (e->args[2] & ~IR_X86_ACCESS_ALL) ||
                    (e->args[2] && !(e->args[2] & IR_X86_ACCESS_READ))))
        return IR_REPLAY_SYSCALL_MODEL;
    if(r->environment && ir_environment_has_state(r->environment) &&
       !ir_environment_order(r->environment,e->boundary_id,t->seq_id,t->vcpu_index,e->boundary_ordered))
        return environment_failure(r);
    if (!e->result) {
        uint64_t length = ((uint64_t)e->args[1] + 4095U) & ~UINT64_C(4095);
        uint64_t end = (uint64_t)e->args[0] + length;
        if ((!protect && !e->args[1]) || (e->args[0] & 4095U) || end > (UINT64_C(1) << 32))
            return IR_REPLAY_SYSCALL_OBSERVATION;
        IrStatus status = IR_OK;
        if(length && r->environment && !(protect?
            ir_environment_protect(r->environment,e->args[0],end,e->args[2],false):
            ir_environment_unmap(r->environment,e->args[0],end,false))) return environment_failure(r);
        if (length)
            status = protect ? ir_x86_protect_memory(f, e->args[0], end, e->args[2])
                             : ir_x86_exclude_memory(f, e->args[0], end);
        if (status != IR_OK)
            return status == IR_RESOURCE_LIMIT ? IR_REPLAY_BUDGET : IR_REPLAY_MEMORY_MODEL;
        if(length && r->environment) {
            if(protect) (void)ir_environment_protect(r->environment,e->args[0],end,e->args[2],true);
            else (void)ir_environment_unmap(r->environment,e->args[0],end,true);
        }
    }
    IrOrigin origin = origin_of(step);
    for (unsigned i = 0; i < count; ++i) {
        IrValueId value = ir_emit_value(r->module, block,
                                        (IrInstSpec){.op = IR_OP_READ_STATE,
                                                     .type = ir_type_bv(32),
                                                     .state = r->state.gpr[regs[i]],
                                                     .origin = origin});
        IrValueId fixed = ir_emit_value(r->module, block,
                                        (IrInstSpec){.op = IR_OP_CONST,
                                                     .type = ir_type_bv(32),
                                                     .immediate = expected[i],
                                                     .origin = origin});
        IrValueId equal = ir_emit_value(
            r->module, block,
            (IrInstSpec){
                .op = IR_OP_EQ, .type = ir_type_bv(1), .args = {value, fixed}, .origin = origin});
        (void)ir_emit_effect(r->module, block,
                             (IrInstSpec){.op = IR_OP_GUARD,
                                          .type = ir_type_void(),
                                          .args = {equal},
                                          .immediate = IR_REASON_GUARD,
                                          .origin = origin});
    }
    IrValueId result = ir_emit_value(
        r->module, block,
        (IrInstSpec){
            .op = IR_OP_CONST, .type = ir_type_bv(32), .immediate = e->result, .origin = origin});
    (void)ir_emit_effect(r->module, block,
                         (IrInstSpec){.op = IR_OP_WRITE_STATE,
                                      .type = ir_type_void(),
                                      .state = r->state.gpr[REG_RAX],
                                      .args = {result},
                                      .origin = origin});
    if (protect)
        ++r->info.modeled_mprotect;
    else
        ++r->info.modeled_munmap;
    r->info.syscall_present = false;
    r->info.stopped_syscall = (DseSyscallObservation){0};
    return 0;
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
    if (r->memory_count == r->options.max_memory_bytes) {
        replay_budget(r, IR_BUDGET_MEMORY_BYTES, r->memory_count, r->options.max_memory_bytes,
                      (uint64_t)r->memory_count + 1, r->current_origin);
        return NULL;
    }
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
    unsigned reads = 0, writes = 0;
    for (unsigned pass = 0; pass < lift.memory_count; ++pass) {
        const IrX86MemoryEffect *effect = &lift.memory[pass];
        bool write = effect->write;
        unsigned index = write ? writes++ : reads++;
        const TraceMemoryEffect *event = write ? &o->mem_writes[index] : &o->mem_reads[index];
        IrReplayObservation address = {.origin = origin,
                                       .index = index,
                                       .value = effect->address,
                                       .width = 32,
                                       .kind =
                                           write ? IR_REPLAY_WRITE_ADDRESS : IR_REPLAY_READ_ADDRESS,
                                       .expected_valid = true,
                                       .expected = event->address};
        IrReplayObservation data = {.origin = origin,
                                    .index = index,
                                    .value = effect->data,
                                    .width = (uint8_t)(effect->bytes * 8U),
                                    .kind = write ? IR_REPLAY_WRITE_VALUE : IR_REPLAY_READ_VALUE,
                                    .expected_valid = event->value_valid,
                                    .expected = event->value};
        if (!add_observation(r, address) || !add_observation(r, data))
            return false;
        for (unsigned i = 0; i < effect->bytes; ++i) {
            /* A newly created mapping's bytes are produced by the file model,
             * not fresh symbolic boundary cells inferred from a later read. */
            if(ir_environment_mapped(r->environment,(uint32_t)(event->address+i))) continue;
            ReplayByte *byte = byte_insert(r, (uint32_t)(event->address + i));
            if (!byte)
                return false;
            if (write)
                byte->written = true;
            else if (!byte->written) {
                const DseMemRead *read =
                    aux && index < aux->mem_read_count ? &aux->mem_reads[index] : NULL;
                const DseSourceObservation *sources = dse_aux_sources(aux);
                bool source_valid = read && read->addr == event->address &&
                                    read->size == effect->bytes && sources &&
                                    (sources->read_valid[index] & (1U << i));
                ProvLabelId label =
                    source_valid ? sources->read_labels[index][i] : PROV_LABEL_UNKNOWN;
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
    unsigned reads = 0, writes = 0;
    if (lift.memory_count > sizeof(lift.memory) / sizeof(lift.memory[0]) ||
        !o->dynamic_effects_available ||
        (o->incomplete_reasons & (TRACE_OCCURRENCE_READ_OVERFLOW | TRACE_OCCURRENCE_WRITE_OVERFLOW |
                                  TRACE_OCCURRENCE_RANGE_UNKNOWN)))
        return IR_REPLAY_OBSERVATION_SHAPE;
    for (unsigned i = 0; i < lift.memory_count; ++i) {
        const IrX86MemoryEffect *effect = &lift.memory[i];
        unsigned index = effect->write ? writes++ : reads++;
        const TraceMemoryEffect *event =
            effect->write ? &o->mem_writes[index] : &o->mem_reads[index];
        if (event->kind != (effect->write ? TRACE_MEM_WRITE : TRACE_MEM_READ) ||
            event->size != effect->bytes || event->address > UINT32_MAX)
            return IR_REPLAY_OBSERVATION_SHAPE;
    }
    return o->mem_read_count == reads && o->mem_write_count == writes &&
                   o->mem_read_total == reads && o->mem_write_total == writes
               ? 0
               : IR_REPLAY_OBSERVATION_SHAPE;
}

typedef struct {
    IrReplay *replay;
    IrOrigin origin;
    const InsnAux *aux;
    const InsnOccurrence *occurrence;
    uint32_t issues;
} RepeatObservation;

static uint32_t repeat_shape(IrX86LiftResult lift, const InsnAux *a, const InsnOccurrence *o) {
    if (!a || !o->dynamic_effects_available || !a->execution_complete)
        return IR_REPLAY_OBSERVATION_MISSING;
    /* The current collector's exact string summary describes flat addr32.
     * Addr16/TLS bodies are supported by the frontend, but require a matching
     * collector contract before this adapter may consume them. */
    if (lift.string_address_bytes != 4) return IR_REPLAY_MEMORY_MODEL;
    const DseStringSummary *s = &a->string_summary;
    if (!(lift.string_move ? dse_aux_has_exact_movs(a) : dse_aux_has_exact_stos(a)) ||
        !s->has_rep_prefix || s->element_size != lift.string_bytes ||
        !(a->reg_value_valid_mask & (1U << REG_RCX)) ||
        a->reg_vals[REG_RCX] != s->expected_iterations ||
        o->mem_read_total != s->read_events || o->mem_write_total != s->write_events ||
        (o->incomplete_reasons & TRACE_OCCURRENCE_RANGE_UNKNOWN))
        return IR_REPLAY_OBSERVATION_SHAPE;
    uint64_t bytes = (uint64_t)s->expected_iterations * s->element_size;
    if (s->write_values_incomplete || s->write_bytes_captured != bytes ||
        s->write_capacity < bytes || (bytes && !s->write_values))
        return IR_REPLAY_OBSERVATION_MISSING;
    return 0;
}

static bool repeat_observe(void *user, uint32_t iteration, const IrX86LiftResult *lift) {
    RepeatObservation *context = user;
    const DseStringSummary *s = &context->aux->string_summary;
    unsigned bytes = s->element_size;
    uint32_t offset = iteration * bytes;
    uint32_t distance = s->direction > 0 ? offset : 0U - offset;
    InsnOccurrence one = {.dynamic_effects_available = true, .execution_complete = true,
        .mem_read_count = lift->string_move ? 1 : 0, .mem_read_total = lift->string_move ? 1 : 0,
        .mem_write_count = 1, .mem_write_total = 1};
    TraceMemoryEffect *write = &one.mem_writes[0], *read = &one.mem_reads[0];
    *write = (TraceMemoryEffect){.kind = TRACE_MEM_WRITE,
        .address = (uint32_t)(s->destination_first + distance), .size = (uint8_t)bytes,
        .value_valid = true};
    for (unsigned j = 0; j < bytes; ++j)
        write->value |= (uint64_t)s->write_values[offset + j] << (j * 8U);
    if (lift->string_move) {
        *read = (TraceMemoryEffect){.kind = TRACE_MEM_READ,
            .address = (uint32_t)(s->source_first + distance), .size = (uint8_t)bytes,
            .value_valid = true};
        for (unsigned j = 0; j < bytes; ++j)
            read->value |= (uint64_t)s->values[offset + j] << (j * 8U);
    }
    const InsnOccurrence *o = context->occurrence;
    for (unsigned kind = 0; kind < 2; ++kind) {
        bool writing = kind == 1;
        unsigned count = writing ? o->mem_write_count : o->mem_read_count;
        if (iteration >= count) continue;
        const TraceMemoryEffect *record = writing ? &o->mem_writes[iteration] : &o->mem_reads[iteration];
        const TraceMemoryEffect *expected = writing ? write : read;
        if (record->kind != expected->kind || record->address != expected->address ||
            record->size != bytes ||
            (record->value_valid && record->value != expected->value)) {
            context->issues = IR_REPLAY_OBSERVATION_SHAPE;
            return false;
        }
    }
    /* Missing per-byte source provenance stays unknown. In particular, summary
     * taint bits are not promoted to file identities. Writes never seed inputs. */
    if (!observe_memory(context->replay, context->origin, *lift, &one, NULL)) {
        context->issues = IR_REPLAY_BUDGET;
        return false;
    }
    return true;
}

static IrValueId flag_constant(IrReplay *r, IrBlockId b, IrOrigin origin, bool value) {
    return ir_emit_value(
        r->module, b,
        (IrInstSpec){
            .op = IR_OP_CONST, .type = ir_type_bv(1), .immediate = value, .origin = origin});
}

static void flag_definedness_profiled_body(IrReplay *r, IrBlockId b, IrOrigin origin, IrX86LiftResult lift) {
    for (unsigned i = 0; i < IR_X86_FLAG_COUNT; ++i) {
        uint32_t mask = 1U << i;
        if (!(lift.flags_written & mask))
            continue;
        if (lift.flags_preserved_when) {
            IrValueId old = r->flag_defined[i];
            if (!old)
                old = flag_constant(r, b, origin, !(r->undefined_flags & mask));
            IrValueId defined = lift.flags_defined[i];
            if (!defined)
                defined = flag_constant(r, b, origin, !(lift.flags_undefined & mask));
            r->flag_defined[i] =
                ir_emit_value(r->module, b,
                              (IrInstSpec){.op = IR_OP_ITE,
                                           .type = ir_type_bv(1),
                                           .args = {lift.flags_preserved_when, old, defined},
                                           .origin = origin});
            r->undefined_flags &= ~mask;
        } else {
            r->flag_defined[i] = lift.flags_defined[i];
            r->undefined_flags = (r->undefined_flags & ~mask) | (lift.flags_undefined & mask);
        }
    }
}
static void flag_definedness(IrReplay *r, IrBlockId b, IrOrigin origin, IrX86LiftResult lift) {
    IrBuildPhase previous = ir_module_build_phase(r->module, IR_BUILD_FLAG_DEFINEDNESS);
    flag_definedness_profiled_body(r, b, origin, lift);
    ir_module_build_phase(r->module, previous);
}


/* Stateful IR values are local to a block until trace SSA. Carry conditional
 * definedness as internal BV1 state, assigned before its first read. These are
 * derived facts, not externally bindable inputs or architectural flag values. */
static bool carry_flag_definedness_profiled_body(IrReplay *r, IrBlockId from, IrBlockId to, IrOrigin origin) {
    for (unsigned i = 0; i < IR_X86_FLAG_COUNT; ++i) {
        if (!r->flag_defined[i])
            continue;
        if (!r->flag_defined_state[i])
            r->flag_defined_state[i] =
                ir_state_add(r->module, ir_type_bv(1), UINT64_C(0x400) + i, false);
        IrStateId state = r->flag_defined_state[i];
        if (!state || !ir_emit_effect(r->module, from,
                                      (IrInstSpec){.op = IR_OP_WRITE_STATE,
                                                   .type = ir_type_void(),
                                                   .args = {r->flag_defined[i]},
                                                   .state = state,
                                                   .origin = origin}))
            return false;
        r->flag_defined[i] = ir_emit_value(
            r->module, to,
            (IrInstSpec){
                .op = IR_OP_READ_STATE, .type = ir_type_bv(1), .state = state, .origin = origin});
        if (!r->flag_defined[i])
            return false;
    }
    return true;
}
static bool carry_flag_definedness(IrReplay *r, IrBlockId from, IrBlockId to, IrOrigin origin) {
    IrBuildPhase previous = ir_module_build_phase(r->module, IR_BUILD_FLAG_DEFINEDNESS);
    bool result = carry_flag_definedness_profiled_body(r, from, to, origin);
    ir_module_build_phase(r->module, previous);
    return result;
}


static uint32_t lift_issues(IrX86LiftStatus status) {
    switch (status) {
    case IR_X86_LIFT_MODE:
        return IR_REPLAY_MODE;
    case IR_X86_LIFT_IDENTITY:
        return IR_REPLAY_IDENTITY;
    case IR_X86_LIFT_MEMORY_MODEL:
        return IR_REPLAY_MEMORY_MODEL;
    case IR_X86_LIFT_LIMIT:
        return IR_REPLAY_BUDGET;
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
    IrInputState states[IR_X86_GPR_COUNT + IR_X86_FLAG_COUNT + IR_X86_TLS_COUNT + 3U];
    uint32_t nstates = 0, count = IR_X86_GPR_COUNT * 4U + IR_X86_FLAG_COUNT;
    for (unsigned i = 0; i < IR_X86_GPR_COUNT; ++i)
        states[nstates++] = (IrInputState){
            .state = r->state.gpr[i], .type = ir_type_bv(32), .key = IR_X86_GPR_KEY_BASE + i};
    for (unsigned i = 0; i < IR_X86_FLAG_COUNT; ++i)
        states[nstates++] = (IrInputState){
            .state = r->state.flags[i], .type = ir_type_bv(1), .key = IR_X86_FLAG_KEY_BASE + i};
    states[nstates++] =
        (IrInputState){.state = r->state.memory, .type = ir_type_mem(32), .key = IR_X86_MEMORY_KEY};
    if (r->options.x86.tls32_ram) {
        count += IR_X86_TLS_COUNT * 4U;
        for (unsigned i = 0; i < IR_X86_TLS_COUNT; ++i)
            states[nstates++] = (IrInputState){.state = r->state.tls_base[i],
                                               .type = ir_type_bv(32),
                                               .key = IR_X86_TLS_KEY_BASE + i};
    }
    if(r->executable_state) {
        states[nstates++]=(IrInputState){.state=r->executable_state,.type=ir_type_mem(32),.key=IR_PROC_EXE_INPUT_KEY};
        count+=r->executable_size;
    }
    if (r->stdin_state) {
        states[nstates++] = (IrInputState){.state=r->stdin_state, .type=ir_type_mem(32),
                                           .key=IR_STDIN_INPUT_KEY};
        count += r->stdin_size;
    }
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
    if (r->options.x86.tls32_ram)
        for (unsigned i = 0; i < IR_X86_TLS_COUNT; ++i)
            for (unsigned byte = 0; byte < 4; ++byte) {
                IrBits bits = r->initial_tls[i];
                IrInputCell cell = {
                    .kind = IR_INPUT_STATE_SLICE,
                    .state = r->state.tls_base[i],
                    .bit_offset = (uint8_t)(byte * 8),
                    .width = 8,
                    .observation_origin = boundary,
                    .observed = {.value = (bits.value >> (byte * 8)) & 255U,
                                 .known_mask = (bits.known_mask >> (byte * 8)) & 255U,
                                 .reasons = bits.reasons}};
                /* A base snapshot supplies no provenance or external-input controllability. */
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
    for(uint32_t i=0;i<r->executable_size;++i) {
        IrInputCell cell={.kind=IR_INPUT_MEMORY_BYTE,.state=r->executable_state,.address=i,
            .width=8,.observed=ir_bits_known(r->executable_bytes[i],8),.observation_origin=r->executable_origin};
        /* Explicit environment boundary bytes. This does not equate them with
         * guest RAM cells, infer provenance or certify externally replayable inputs. */
        if(!ir_inputs_add(r->inputs,cell)) goto fail;
    }
    for (uint32_t i = 0; i < r->stdin_size; ++i) {
        IrInputCell cell = {.kind=IR_INPUT_MEMORY_BYTE, .state=r->stdin_state,
            .address=i, .width=8, .observed=ir_bits_known(r->stdin_bytes[i],8),
            .observation_origin=r->stdin_origin};
        if (!ir_inputs_add(r->inputs, cell)) goto fail;
    }
    if (ir_inputs_seal(r->inputs))
        return true;
fail:
    r->input_status = ir_inputs_info(r->inputs).status;
    return false;
}

static bool stdin_source_shape(const ReplayInput *input, const IrReplayOptions *options,
                                uint32_t *prefix) {
    const IrReplayStdinSource *source = options->stdin_source;
    *prefix = 0;
    if (!source) return true;
    if (!options->x86.flat32_ram || options->observed_files || options->observed_proc_exe ||
        options->observed_munmap || options->observed_mprotect || !source->bytes ||
        !source->size || source->size > IR_REPLAY_STDIN_MAX_FILE || !source->reads ||
        !source->count || source->count > IR_REPLAY_STDIN_MAX_READS ||
        !replay_input_count(input) || replay_input_count(input) > options->max_steps) return false;
    const ReplayStep *first = replay_input_step(input, 0);
    if (!first || first->entry.seq_id != source->reads[0].seq) return false;
    for (uint32_t i = 0; i < source->count; ++i) {
        const IrReplayStdinRead *read = &source->reads[i];
        if (!read->seq || read->seq == UINT64_MAX ||
            (i && read->seq <= source->reads[i-1U].seq) ||
            read->offset != *prefix || !read->requested ||
            read->requested > IR_REPLAY_STDIN_MAX_READ || read->returned > read->requested ||
            read->offset > source->size || read->returned > source->size-read->offset ||
            (uint64_t)read->address+read->requested > (UINT64_C(1)<<32) ||
            (uint64_t)*prefix+read->returned > IR_REPLAY_STDIN_MAX_BYTES) return false;
        const ReplayStep *occurrence = replay_input_find(input, read->seq);
        if (!occurrence || occurrence->entry.vcpu_index != first->entry.vcpu_index) return false;
        *prefix += read->returned;
        /* The frontend decodes saved descriptor bytes. This narrow source
         * model refuses copy-in over any executed instruction rather than
         * treating a changed future instruction as the old captured code.
         * Include the trigger boundary and full byte intervals, not only PCs. */
        uint64_t end = (uint64_t)read->address+read->returned;
        for (uint32_t j = 0; read->returned && j <= replay_input_count(input); ++j) {
            const ReplayStep *step = j == replay_input_count(input)
                ? replay_input_trigger(input) : replay_input_step(input, j);
            if (!step || step->entry.pc > UINT32_MAX ||
                step->entry.pc+(uint64_t)step->entry.size > (UINT64_C(1)<<32)) return false;
            if ((uint64_t)read->address < step->entry.pc+step->entry.size &&
                step->entry.pc < end) return false;
        }
    }
    return true;
}

IrReplay *ir_replay_x86_build(const ReplayInput *input, const IrReplayOptions *options,
                              IrReplayBuildInfo *info) {
    if (info)
        *info = (IrReplayBuildInfo){.status = IR_REPLAY_INVALID};
    const ReplayStep *trigger = replay_input_trigger(input);
    if (!input || !trigger)
        return NULL;
    IrReplayOptions opts = options ? *options : ir_replay_default_options();
    if (opts.compare_target && !opts.capture_target)
        return NULL;
    /* Explicit upper bounds also keep growth arithmetic valid on 32-bit hosts. */
    if (opts.observed_proc_exe && (!opts.observed_files || !opts.x86.flat32_ram)) return NULL;
    if (opts.max_executable_bytes>DSE_EXECUTABLE_SNAPSHOT_BYTES) return NULL;
    uint32_t stdin_prefix = 0;
    if (!stdin_source_shape(input, &opts, &stdin_prefix)) return NULL;
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
    r->target = (IrReplayTarget){.status = IR_X86_LIFT_UNSUPPORTED, .gpr_index = -1};
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
    r->current_origin = origin_of(replay_input_count(input) ? replay_input_step(input, 0) : trigger);
    ir_module_build_origin(r->module, r->current_origin);
    ir_module_build_phase(r->module, IR_BUILD_SETUP);
    IrX86Frontend *frontend = ir_x86_frontend_create(r->module, &opts.x86);
    if (!frontend)
        goto fatal;
    r->state = *ir_x86_frontend_state(frontend);
    if (opts.stdin_source) {
        r->stdin_state = ir_state_add(r->module, ir_type_mem(32), IR_STDIN_INPUT_KEY, false);
        if (!r->stdin_state) goto fatal;
        r->stdin_size = stdin_prefix;
        r->stdin_bytes = stdin_prefix ? malloc(stdin_prefix) : NULL;
        if (stdin_prefix && !r->stdin_bytes) { r->allocation_failed=true; goto fatal; }
        if (stdin_prefix) memcpy(r->stdin_bytes, opts.stdin_source->bytes, stdin_prefix);
        r->stdin_count = opts.stdin_source->count;
        memcpy(r->stdin_reads, opts.stdin_source->reads,
               (size_t)r->stdin_count*sizeof(*r->stdin_reads));
        r->stdin_origin = r->current_origin;
        /* No borrowed provider pointer escapes the build. */
        r->options.stdin_source = NULL;
    }
    if(opts.observed_files) {
        r->environment=ir_environment_create(r->module,r->state.memory,
                                               opts.max_file_objects,opts.max_file_content_cells);
        if(!r->environment) goto fatal;
        ir_x86_attach_environment(frontend,r->environment);
    }
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
    for (unsigned i = 0; i < IR_X86_TLS_COUNT; ++i)
        r->initial_tls[i] = ir_bits_unknown(IR_REASON_UNBOUND_STATE);
    if (issues) {
        stop(r, block, issues, origin_of(first));
        goto complete;
    }
    if (opts.capture_target) {
        IrX86LiftResult target =
            ir_x86_describe_target(frontend, block, &trigger->descriptor, origin_of(trigger));
        r->target.status = target.status;
        r->target.gpr_index = target.target_gpr;
    }
    const InsnAux *initial = saved_aux(input, first);
    if (initial) {
        for (unsigned i = 0; i < IR_X86_TLS_COUNT; ++i)
            if (initial->tls_valid_mask & (1U << i))
                r->initial_tls[i] = ir_bits_known(initial->tls_base[i], 32);
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
        r->current_origin = origin;
        ir_module_build_origin(r->module, origin);
        ir_module_build_phase(r->module, IR_BUILD_FETCH);
        if (i >= opts.max_steps) {
            replay_budget(r, IR_BUDGET_STEPS, i, opts.max_steps, (uint64_t)i + 1, origin);
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
        if (!ir_x86_range_permitted(frontend, (uint32_t)step->entry.pc, step->entry.size,
                                    IR_X86_ACCESS_EXEC)) {
            stop(r, block, IR_REPLAY_MEMORY_MODEL, origin);
            goto complete;
        }
        if(r->environment && !ir_environment_fetch(r->environment,block,origin,
                (uint32_t)step->entry.pc,step->descriptor.bytes,step->descriptor.size)) goto fatal;
        if (!checkpoint(r, block, origin, aux)) {
            if (r->allocation_failed || ir_module_status(r->module) != IR_OK)
                goto fatal;
            stop(r, block, IR_REPLAY_BUDGET, origin);
            goto complete;
        }
        ir_module_build_phase(r->module, IR_BUILD_X86);
        IrX86LiftResult lift;
        if (syscall_instruction(&step->descriptor)) {
            ir_module_build_phase(r->module, IR_BUILD_ENVIRONMENT);
            issues = lift_syscall(r, frontend, block, step, aux);
            if (issues) {
                stop(r, block, issues, origin);
                goto complete;
            }
            lift = (IrX86LiftResult){
                .status = ir_module_status(r->module) == IR_OK ? IR_X86_LIFT_OK : IR_X86_LIFT_ERROR,
                .target_gpr = -1};
        } else
            lift = ir_x86_lift(frontend, block, &step->descriptor, origin);
        bool repeated = lift.status == IR_X86_LIFT_REPEAT;
        if (repeated) {
            issues = repeat_shape(lift, aux, &step->occurrence);
            if (issues) { stop(r, block, issues, origin); goto complete; }
            if (aux->string_summary.expected_iterations > opts.max_repeat_iterations)
                replay_budget(r, IR_BUDGET_REPEAT_ITERATIONS, 0, opts.max_repeat_iterations,
                              aux->string_summary.expected_iterations, origin);
            RepeatObservation observer = {r, origin, aux, &step->occurrence, 0};
            lift = ir_x86_lift_repeat(frontend, block, &step->descriptor, origin,
                aux->string_summary.expected_iterations, opts.max_repeat_iterations,
                repeat_observe, &observer);
            if (lift.status == IR_X86_LIFT_CALLBACK) {
                if (r->allocation_failed || ir_module_status(r->module) != IR_OK) goto fatal;
                stop(r, block, observer.issues, origin); goto complete;
            }
        }
        if (lift.status == IR_X86_LIFT_ERROR)
            goto fatal;
        if (lift.status != IR_X86_LIFT_OK) {
            stop(r, block, lift_issues(lift.status), origin);
            goto complete;
        }
        if (!observe_tls(r, block, origin, aux, lift.segment_reads)) {
            if (r->allocation_failed || ir_module_status(r->module) != IR_OK)
                goto fatal;
            stop(r, block, IR_REPLAY_BUDGET, origin);
            goto complete;
        }
        ++r->info.lifted_steps;
        flag_definedness(r, block, origin, lift);
        issues = repeated ? 0 : memory_shape(lift, &step->occurrence);
        if (issues) {
            stop(r, block, issues, origin);
            goto complete;
        }
        if (!repeated && !observe_memory(r, origin, lift, &step->occurrence, aux)) {
            if (r->allocation_failed || ir_module_status(r->module) != IR_OK)
                goto fatal;
            stop(r, block, IR_REPLAY_BUDGET, origin);
            goto complete;
        }
        ir_module_build_phase(r->module, IR_BUILD_CONTROL);
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
            /* Existing collectors do not archive LOOP as a flag-based Jcc.
             * A distinct recorded successor identifies its outcome without
             * copying ECX or computing a second ISA model in this adapter.
             * Coincident successors still require an explicit branch event. */
            bool loop_edge = step->descriptor.native_insn_id == X86_INS_LOOP &&
                !occ->branch_event_valid && occ->branch_outcome == BRANCH_OUTCOME_UNKNOWN &&
                lift.direct_target != fallthrough &&
                (occ->next_pc == lift.direct_target || occ->next_pc == fallthrough);
            if (!loop_edge && (!occ->branch_event_valid || !occ->branch_event_id ||
                (occ->branch_outcome != BRANCH_OUTCOME_TAKEN &&
                 occ->branch_outcome != BRANCH_OUTCOME_NOT_TAKEN))) {
                stop(r, block, IR_REPLAY_CONTROL_MISMATCH | IR_REPLAY_OBSERVATION_MISSING, origin);
                goto complete;
            }
            taken = loop_edge ? occ->next_pc == lift.direct_target :
                               occ->branch_outcome == BRANCH_OUTCOME_TAKEN;
            successor = taken ? lift.direct_target : fallthrough;
            if (!loop_edge && occ->observed_branch_target != occ->next_pc) {
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
            else if (lift.control == IR_X86_INDIRECT)
                successor = occ->next_pc;
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
            if (lift.control == IR_X86_INDIRECT) {
                if (!add_observation(r, (IrReplayObservation){.kind = IR_REPLAY_TRANSFER_TARGET,
                                                              .origin = origin,
                                                              .value = lift.target,
                                                              .width = 32,
                                                              .expected_valid = true,
                                                              .expected = successor})) {
                    if (r->allocation_failed || ir_module_status(r->module) != IR_OK)
                        goto fatal;
                    stop(r, block, IR_REPLAY_BUDGET, origin);
                    goto complete;
                }
                IrValueId expected = ir_emit_value(r->module, block,
                                                   (IrInstSpec){.op = IR_OP_CONST,
                                                                .type = ir_type_bv(32),
                                                                .immediate = successor,
                                                                .origin = origin});
                IrValueId equal = ir_emit_value(r->module, block,
                                                (IrInstSpec){.op = IR_OP_EQ,
                                                             .type = ir_type_bv(1),
                                                             .args = {lift.target, expected},
                                                             .origin = origin});
                /* A recorded edge is usable only while the computed target agrees.
                 * Changed/unknown targets stop; no successor body is invented. */
                if (!ir_emit_effect(r->module, block,
                                    (IrInstSpec){.op = IR_OP_GUARD,
                                                 .type = ir_type_void(),
                                                 .args = {equal},
                                                 .immediate = IR_REASON_TARGET,
                                                 .origin = origin}))
                    goto fatal;
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
            if (!carry_flag_definedness(r, block, following, origin_of(next)) ||
                !ir_block_terminate(r->module, block, term))
                goto fatal;
            block = following;
        }
    }
    r->current_origin = origin_of(trigger);
    ir_module_build_origin(r->module, r->current_origin);
    ir_module_build_phase(r->module, IR_BUILD_FETCH);
    if (r->stdin_state && r->stdin_done != r->stdin_count) {
        r->info.environment_reason = "stdin_ledger_not_consumed";
        stop(r, block, IR_REPLAY_SYSCALL_OBSERVATION, origin_of(trigger));
        goto complete;
    }
    if (!ir_x86_range_permitted(frontend, (uint32_t)trigger->entry.pc, trigger->entry.size,
                                IR_X86_ACCESS_EXEC)) {
        stop(r, block, IR_REPLAY_MEMORY_MODEL, origin_of(trigger));
        goto complete;
    }
    if(r->environment && !ir_environment_fetch(r->environment,block,origin_of(trigger),
            (uint32_t)trigger->entry.pc,trigger->descriptor.bytes,trigger->descriptor.size)) goto fatal;
    if (!checkpoint(r, block, origin_of(trigger), saved_aux(input, trigger))) {
        if (r->allocation_failed || ir_module_status(r->module) != IR_OK)
            goto fatal;
        stop(r, block, IR_REPLAY_BUDGET, origin_of(trigger));
        goto complete;
    }
    if (opts.capture_target) {
        ir_module_build_phase(r->module, IR_BUILD_CONTROL);
        IrX86LiftResult target =
            ir_x86_lift_target(frontend, block, &trigger->descriptor, origin_of(trigger));
        r->target.status = target.status;
        if (target.status == IR_X86_LIFT_ERROR)
            goto fatal;
        if (target.status == IR_X86_LIFT_OK) {
            if (!observe_tls(r, block, origin_of(trigger), saved_aux(input, trigger),
                             target.segment_reads)) {
                if (r->allocation_failed || ir_module_status(r->module) != IR_OK)
                    goto fatal;
                stop(r, block, IR_REPLAY_BUDGET, origin_of(trigger));
                goto complete;
            }
            r->target.value = target.target;
            r->target.gpr_index = target.target_gpr;
            r->target.boundary = block;
            if (!ir_module_add_output(r->module, target.target))
                goto fatal;
            /* Only target reads belong to the boundary projection. The CALL's
             * stack write and the RET's stack update occur after this boundary. */
            InsnOccurrence observation = trigger->occurrence;
            observation.mem_write_count = 0;
            observation.mem_write_total = 0;
            if (memory_shape(target, &observation)) {
                note(r, IR_REPLAY_OBSERVATION_SHAPE);
            } else if (!observe_memory(r, origin_of(trigger), target, &observation,
                                       saved_aux(input, trigger))) {
                if (r->allocation_failed || ir_module_status(r->module) != IR_OK)
                    goto fatal;
                stop(r, block, IR_REPLAY_BUDGET, origin_of(trigger));
                goto complete;
            }
            if (opts.compare_target) {
                IrValueId expected = ir_emit_value(
                    r->module, block,
                    (IrInstSpec){.op = IR_OP_CONST, .type = ir_type_bv(32),
                                 .immediate = opts.target_candidate, .origin = origin_of(trigger)});
                r->target.matches_candidate = ir_emit_value(
                    r->module, block,
                    (IrInstSpec){.op = IR_OP_EQ, .type = ir_type_bv(1),
                                 .args = {target.target, expected}, .origin = origin_of(trigger)});
                if (!expected || !r->target.matches_candidate ||
                    !ir_module_add_output(r->module, r->target.matches_candidate))
                    goto fatal;
            }
        }
    }
    (void)ir_block_terminate(
        r->module, block,
        (IrTerminator){.kind = IR_TERM_FRAGMENT_END, .origin = origin_of(trigger)});
complete:
    snapshot_build(r);
    if (!ir_validate(r->module, NULL) || r->allocation_failed)
        goto fatal;
    if (!build_inputs(r, input, first))
        goto fatal;
    ir_x86_frontend_destroy(frontend);
    if (info)
        *info = r->info;
    return r;
fatal:
    snapshot_build(r);
    if (!r->info.stopped_seq) {
        r->info.stopped_origin = r->info.replay_budget.kind != IR_BUDGET_NONE
            ? r->info.replay_budget.origin : r->info.construction.failure.kind != IR_BUDGET_NONE
            ? r->info.construction.failure.origin : r->current_origin;
        r->info.stopped_seq = r->info.stopped_origin.seq_id;
    }
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
    if (kind == IR_BIND_STATE && key >= IR_X86_TLS_KEY_BASE &&
        key < IR_X86_TLS_KEY_BASE + IR_X86_TLS_COUNT && width == 32)
        return r->initial_tls[key - IR_X86_TLS_KEY_BASE];
    return ir_bits_unknown(IR_REASON_UNBOUND_STATE);
}

static IrBits observed_byte(void *user, IrBindingKind kind, uint64_t key, uint64_t address) {
    const IrReplay *r = user;
    if (kind==IR_BIND_STATE && key==IR_STDIN_INPUT_KEY && r->stdin_state)
        return address<r->stdin_size ? ir_bits_known(r->stdin_bytes[address],8)
                                    : ir_bits_unknown(IR_REASON_MEMORY);
    if(kind==IR_BIND_STATE && key==IR_PROC_EXE_INPUT_KEY && r->executable_state)
        return address<r->executable_size?ir_bits_known(r->executable_bytes[address],8):ir_bits_unknown(IR_REASON_MEMORY);
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

static IrReplayCheckResult check_candidate(IrReplay *r, const IrEvalLimits *limits,
                                           const IrReplayGprCandidate *candidate, bool projected) {
    IrReplayCheckResult check = {.status = IR_REPLAY_CHECK_ERROR,
                                 .candidate_requested = candidate != NULL,
                                 .candidate_status = IR_REPLAY_CHECK_UNKNOWN,
                                 .candidate_actual = ir_bits_unknown(IR_REASON_NOT_EXECUTED)};
    if (!r)
        return check;
    if (candidate && (candidate->trigger_seq != r->trigger_seq ||
                      (!projected && candidate->gpr_index >= IR_X86_GPR_COUNT)))
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
        if (o->reached) {
            IrBits reached = ir_eval_value(eval, o->reached).bits;
            if (!ir_bits_complete(reached, 1) || !reached.value) {
                ++check.unknown;
                continue;
            }
        }
        if (o->defined_when) {
            IrBits defined = ir_eval_value(eval, o->defined_when).bits;
            if (!ir_bits_complete(defined, 1)) {
                ++check.unknown;
                continue;
            }
            if (!defined.value) {
                ++check.skipped_undefined;
                continue;
            }
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
        IrEvalValue value = projected ? ir_eval_value(eval, r->target.value)
                                      : ir_eval_state(eval, r->state.gpr[candidate->gpr_index]);
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

IrReplayTarget ir_replay_target(const IrReplay *r) {
    return r ? r->target : (IrReplayTarget){.status = IR_X86_LIFT_ERROR, .gpr_index = -1};
}

IrReplayCheckResult ir_replay_check_gpr_candidate(IrReplay *r, const IrEvalLimits *limits,
                                                  const IrReplayGprCandidate *candidate) {
    return check_candidate(r, limits, candidate, false);
}

IrReplayCheckResult ir_replay_check_target(IrReplay *r, const IrEvalLimits *limits, uint64_t seq,
                                           uint32_t expected) {
    if (!r || r->target.status != IR_X86_LIFT_OK)
        return (IrReplayCheckResult){.status = IR_REPLAY_CHECK_UNKNOWN,
                                     .candidate_requested = true,
                                     .candidate_status = IR_REPLAY_CHECK_UNKNOWN};
    IrReplayGprCandidate request = {.trigger_seq = seq, .expected_target = expected};
    return check_candidate(r, limits, &request, true);
}

IrReplayCheckResult ir_replay_check(IrReplay *r, const IrEvalLimits *limits) {
    return ir_replay_check_gpr_candidate(r, limits, NULL);
}
