#ifndef TAINTFORGE_IR_FRONTEND_TEST_HELPERS_H
#define TAINTFORGE_IR_FRONTEND_TEST_HELPERS_H

#include "ir_replay.h"
#include "ir_opt.h"
#ifdef TF_IR_TRACE_SSA
#include "ir_ssa.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #c); exit(1); } } while (0)

typedef struct { csh decoder; TraceBuffer *trace; DseAuxRing *aux; } FrontFixture;
static inline FrontFixture ff_new(uint32_t capacity) {
    FrontFixture f = {0};
    CHECK(cs_open(CS_ARCH_X86, CS_MODE_32, &f.decoder) == CS_ERR_OK);
    CHECK(cs_option(f.decoder, CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK);
    meta_init(); f.trace = trace_buffer_create(capacity); f.aux = dse_aux_create(capacity);
    CHECK(f.trace && f.aux); return f;
}
static inline InsnAux ff_registers(void) {
    InsnAux a = {.reg_value_valid_mask = 0xff, .eflags_valid = true, .eflags_before = 0xcd7};
    for (unsigned i = 0; i < IR_X86_GPR_COUNT; ++i) a.reg_vals[i] = UINT32_C(0x12345678) + i;
    return a;
}
static inline void ff_read(InsnAux *a, uint32_t address, uint32_t value, uint8_t bytes, bool valid) {
    a->has_mem_read = true; a->mem_read_count = 1; a->mem_read_total = 1;
    a->mem_read_addr = address; a->mem_read_val = value; a->mem_read_value_valid = valid;
    a->mem_read_range_valid = true; a->mem_read_min_addr = address; a->mem_read_max_addr = (uint32_t)(address + bytes - 1U);
    a->mem_reads[0] = (DseMemRead){.addr = address, .value = value, .size = bytes, .value_valid = valid};
}
static inline void ff_write(InsnAux *a, uint32_t address, uint32_t value, uint8_t bytes, bool valid) {
    a->has_mem_write = true; a->mem_write_count = 1; a->mem_write_total = 1;
    a->mem_write_addr = address; a->mem_write_size = bytes;
    a->mem_write_range_valid = true; a->mem_write_min_addr = address; a->mem_write_max_addr = (uint32_t)(address + bytes - 1U);
    a->mem_writes[0] = (DseMemWrite){.addr = address, .value = value, .size = bytes, .value_valid = valid};
}
static inline uint64_t ff_emit(FrontFixture *f, uint64_t pc, const uint8_t *bytes, size_t size,
                               uint32_t generation, uint32_t vcpu, const InsnAux *a) {
    InsnMeta *decoded = meta_decode(bytes, size, pc, f->decoder); CHECK(decoded);
    const InsnMeta *meta = meta_store(pc, decoded); CHECK(meta);
    InsnDescId desc = trace_insn_desc_intern(f->trace, TRACE_ARCH_X86, TRACE_MODE_32,
        pc, generation, bytes, (uint8_t)size, meta); CHECK(desc);
    const TraceEntry *entry = trace_append(f->trace, &(TraceEntry){.pc = pc, .insn_desc_id = desc, .vcpu_index = vcpu});
    CHECK(entry && dse_aux_record(f->aux, f->trace, entry, a)); return entry->seq_id;
}
static inline void ff_finish(FrontFixture *f, uint64_t seq, uint64_t next_pc) {
    const TraceEntry *entry = trace_find_seq(f->trace, seq, NULL); CHECK(entry);
    InsnAux *a = (InsnAux *)dse_aux_for(f->aux, f->trace, entry); CHECK(a);
    dse_aux_finalize(a, next_pc, NULL, 0); CHECK(a->execution_complete);
    CHECK(dse_aux_archive_occurrence(f->aux, f->trace, NULL, seq));
}
static inline ReplayInput *ff_capture(FrontFixture *f, const uint64_t *seq, uint32_t count, uint64_t trigger) {
    ReplayInputStatus status;
    ReplayInput *input = replay_input_capture(f->trace, f->aux, seq, count, trigger, 16U * 1024U * 1024U, &status);
    CHECK(input && (status == REPLAY_INPUT_READY || status == REPLAY_INPUT_UNKNOWN)); return input;
}
static inline void ff_free(FrontFixture *f) {
    dse_aux_destroy(f->aux); trace_buffer_destroy(f->trace); meta_free(); cs_close(&f->decoder);
    memset(f, 0, sizeof(*f));
}
static inline IrReplay *ff_one(const uint8_t *code, size_t size, InsnAux before, InsnAux after,
                              const IrReplayOptions *options) {
    FrontFixture f = ff_new(8);
    uint64_t seq = ff_emit(&f, 0x1000, code, size, 3, 2, &before);
    ff_finish(&f, seq, 0x1000 + size);
    const uint8_t jump[] = {0xff, 0xe0};
    uint64_t trigger = ff_emit(&f, 0x1000 + size, jump, sizeof(jump), 3, 2, &after);
    ReplayInput *input = ff_capture(&f, &seq, 1, trigger);
    ff_free(&f); /* Real owned ReplayInput is the only remaining trace source. */
    IrReplayBuildInfo info;
    IrReplay *r = ir_replay_x86_build(input, options, &info);
    replay_input_destroy(input); CHECK(r); CHECK(ir_validate(ir_replay_module(r), NULL)); return r;
}
static inline void ff_match(IrReplay *r) {
    IrReplayCheckResult c = ir_replay_check(r, NULL);
    if (c.status != IR_REPLAY_CHECK_MATCH) fprintf(stderr,
        "check=%u issues=%x eval=%u mismatches=%u unknown=%u seq=%llu kind=%u expected=%llx actual=%llx mask=%llx\n",
        c.status, ir_replay_info(r).issues, c.execution.status, c.mismatches, c.unknown,
        (unsigned long long)c.first_mismatch.origin.seq_id, c.first_mismatch.kind,
        (unsigned long long)c.first_mismatch.expected, (unsigned long long)c.actual.value,
        (unsigned long long)c.actual.known_mask);
    CHECK(c.status == IR_REPLAY_CHECK_MATCH && c.checked > 0 && !c.mismatches && !c.unknown);
}
static inline void ff_opt_match(IrReplay *r) {
    ff_match(r);
#ifdef TF_IR_TRACE_SSA
    CHECK(ir_trace_ssa(ir_replay_module(r), NULL).analysis.status == IR_OK);
    ff_match(r);
#endif
    IrOptResult opt = ir_optimize(ir_replay_module(r), NULL); CHECK(opt.status == IR_OK);
    ff_match(r);
}
static inline uint32_t ff_gpr(IrEval *eval, IrReplay *r, unsigned index) {
    IrEvalValue v = ir_eval_state(eval, ir_replay_state(r)->gpr[index]);
    CHECK(ir_bits_complete(v.bits, 32)); return (uint32_t)v.bits.value;
}

#endif
