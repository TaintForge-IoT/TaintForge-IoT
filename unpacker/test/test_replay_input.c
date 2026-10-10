#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dse.h"

#define CAPTURE_BUDGET (2U * 1024U * 1024U)

typedef struct {
  csh cs;
  TraceBuffer *trace;
  DseAuxRing *ring;
} Fixture;

static Fixture fixture_create(uint32_t capacity) {
  Fixture f = {0};
  assert(cs_open(CS_ARCH_X86, CS_MODE_32, &f.cs) == CS_ERR_OK);
  assert(cs_option(f.cs, CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK);
  meta_init();
  f.trace = trace_buffer_create(capacity);
  f.ring = dse_aux_create(capacity);
  assert(f.trace && f.ring);
  return f;
}

static InsnAux registers_before(uint64_t eax) {
  InsnAux aux = {0};
  aux.reg_value_valid_mask = (1U << REG_COUNT) - 1U;
  aux.reg_vals[REG_RAX] = eax;
  aux.eflags_valid = true;
  aux.eflags_before = 2;
  return aux;
}

static uint64_t emit(Fixture *f, uint64_t pc, const uint8_t *bytes, size_t size,
                      uint32_t generation, uint32_t vcpu, const InsnAux *aux) {
  InsnMeta *decoded = meta_decode(bytes, size, pc, f->cs);
  assert(decoded);
  const InsnMeta *meta = meta_store(pc, decoded);
  assert(meta);
  InsnDescId id = trace_insn_desc_intern(f->trace, TRACE_ARCH_X86,
      TRACE_MODE_32, pc, generation, bytes, (uint8_t)size, meta);
  assert(id != INSN_DESC_ID_INVALID);
  TraceEntry entry = {.pc = pc, .insn_desc_id = id, .vcpu_index = vcpu};
  const TraceEntry *stored = trace_append(f->trace, &entry);
  assert(stored && dse_aux_record(f->ring, f->trace, stored, aux));
  return stored->seq_id;
}

static void finish(Fixture *f, uint64_t seq, uint64_t next_pc) {
  const TraceEntry *entry = trace_find_seq(f->trace, seq, NULL);
  InsnAux *aux = (InsnAux *)dse_aux_for(f->ring, f->trace, entry);
  assert(aux);
  dse_aux_finalize(aux, next_pc, NULL, 0);
  assert(aux->execution_complete);
  assert(dse_aux_archive_occurrence(f->ring, f->trace, NULL, seq));
}

static void release_sources(Fixture *f) {
  dse_lift_attach(NULL, NULL, &dse_arch_x86);
  dse_aux_destroy(f->ring);
  trace_buffer_destroy(f->trace);
  meta_free();
  f->ring = NULL;
  f->trace = NULL;
}

static void test_replay_after_source_destruction(void) {
  Fixture f = fixture_create(4);
  const uint8_t mov[] = {0xb8, 0x78, 0x00, 0x34, 0x12};
  const uint8_t ah[] = {0xb4, 0x56};
  const uint8_t jmp[] = {0xff, 0xe0};
  InsnAux aux = registers_before(0);
  uint64_t selected[2];
  selected[0] = emit(&f, 0x1000, mov, sizeof(mov), 1, 3, &aux);
  finish(&f, selected[0], 0x1005);
  aux.reg_vals[REG_RAX] = 0x12340078;
  aux.reg_taint[REG_RAX] = 0xf;
  selected[1] = emit(&f, 0x1005, ah, sizeof(ah), 1, 3, &aux);
  finish(&f, selected[1], 0x1007);
  aux.reg_vals[REG_RAX] = 0x12345678;
  uint64_t trigger = emit(&f, 0x1007, jmp, sizeof(jmp), 1, 3, &aux);

  ReplayInputStatus status;
  ReplayInput *input = replay_input_capture(f.trace, f.ring, selected, 2,
      trigger, CAPTURE_BUDGET, &status);
  assert(input && status == REPLAY_INPUT_READY);
  assert(replay_input_count(input) == 2 && replay_input_issues(input) == 0);
  assert(replay_input_trigger(input)->occurrence.incomplete_reasons &
         TRACE_OCCURRENCE_EXECUTION_PENDING);
  assert(replay_input_step(input, 0)->descriptor_valid);
  assert(replay_input_step(input, 2) == NULL);
  assert(replay_input_find(input, trigger)->entry.seq_id == trigger);
  assert(replay_input_aux(input, selected[1])->eflags_before == 2);

  /* The existing slicer requires a finalized trigger; the captured register
   * observation itself was already available before executing the jump. */
  finish(&f, trigger, 0x12345678);
  dse_lift_attach(f.trace, f.ring, &dse_arch_x86);
  DseVerifyResult result = dse_verify_oep_candidate(f.trace, f.ring, trigger,
      REG_RAX, 0x12345678, NULL, f.cs);
  assert(result.replay_valid && result.lifted_total == 3 && result.aux_miss == 0);

  /* Rewrite the same PC, with new bytes/generation, and evict all saved slots. */
  const uint8_t rewrite[] = {0x31, 0xc0};
  for (uint32_t i = 0; i < 6; i++)
    (void)emit(&f, 0x1000, rewrite, sizeof(rewrite), 2, 3, &aux);
  release_sources(&f);
  assert(replay_input_step(input, 0)->descriptor.code_generation == 1);
  assert(replay_input_step(input, 0)->descriptor.bytes[0] == 0xb8);
  assert(replay_input_meta(input, selected[0])->insn_id == X86_INS_MOV);

  DSECtx ctx;
  assert(dse_ctx_init(&ctx));
  dse_lift_begin(&ctx);
  assert(dse_lift_replay_step(&ctx, input, 0, f.cs));
  assert(dse_lift_replay_step(&ctx, input, 1, f.cs));
  SymExpr *target = dse_read_rid_fit(&ctx, replay_input_aux(input, trigger),
                                    REG_RAX, 32, 32);
  uint64_t value = 0;
  assert(target && dse_eval_expr_observed(&ctx, target, &value) == DSE_REPLAY_EVAL_OK);
  assert(value == 0x12345678);
  sym_expr_free(target);
  dse_ctx_free(&ctx);
  replay_input_destroy(input);
  cs_close(&f.cs);
}

static void test_rep_payload_and_budget(void) {
  Fixture f = fixture_create(4);
  /* Legacy replay now requires a DF producer, not an observed constant. */
  const uint8_t cld_bytes[] = {0xfc};
  InsnAux cld_aux = registers_before(0x401000);
  uint64_t cld_seq = emit(&f, 0x0fff, cld_bytes, sizeof(cld_bytes), 1, 0, &cld_aux);
  finish(&f, cld_seq, 0x1000);
  const uint8_t movs[] = {0xf3, 0xa4};
  const uint8_t jmp[] = {0xff, 0xe0};
  InsnAux aux = registers_before(0x401000);
  aux.reg_vals[REG_RCX] = 10;
  aux.reg_vals[REG_RSI] = 0x2000;
  aux.reg_vals[REG_RDI] = 0x3000;
  aux.execution_complete = true;
  aux.next_pc_valid = true;
  aux.next_pc = 0x1002;
  aux.has_mem_read = aux.has_mem_write = true;
  aux.mem_read_total = aux.mem_write_total = 10;
  aux.mem_read_count = aux.mem_write_count = DSE_MAX_MEM_ACCESSES;
  aux.mem_read_overflow = aux.mem_write_overflow = true;
  aux.mem_read_range_valid = aux.mem_write_range_valid = true;
  aux.mem_read_min_addr = 0x2000;
  aux.mem_read_max_addr = 0x2009;
  aux.mem_write_min_addr = 0x3000;
  aux.mem_write_max_addr = 0x3009;
  aux.string_summary = (DseStringSummary){
    .kind = DSE_STRING_MOVS, .active = true, .exact = true,
    .has_rep_prefix = true, .element_size = 1, .direction = 1,
    .expected_iterations = 10, .read_events = 10, .write_events = 10,
    .bytes_captured = 10, .capacity = 64,
    .source_first = 0x2000, .destination_first = 0x3000,
    .values = calloc(64, 1), .value_taint = calloc(64, 1),
    .write_values = calloc(64, 1), .write_capacity = 64,
    .write_bytes_captured = 10
  };
  assert(aux.string_summary.values && aux.string_summary.value_taint &&
         aux.string_summary.write_values);
  for (uint8_t i = 0; i < 10; i++) {
    aux.string_summary.values[i] = (uint8_t)(0x40 + i);
    aux.string_summary.value_taint[i] = 1;
    aux.string_summary.write_values[i] = (uint8_t)(0x40 + i);
    if (i < DSE_MAX_MEM_ACCESSES) {
      aux.mem_reads[i] = (DseMemRead){.addr = 0x2000U + i, .value = 0x40U + i,
          .value_valid = true, .size = 1, .taint = 1, .effective_taint = 1};
      aux.mem_writes[i] = (DseMemWrite){.addr = 0x3000U + i, .value = 0x40U + i,
          .value_valid = true, .size = 1};
    }
  }
  uint64_t seq = emit(&f, 0x1000, movs, sizeof(movs), 1, 0, &aux);
  f.ring->dynamic_bytes = 192; /* ownership transferred by dse_aux_record */
  assert(dse_aux_archive_occurrence(f.ring, f.trace, NULL, seq));
  InsnAux trigger_aux = registers_before(0x401000);
  uint64_t trigger = emit(&f, 0x1002, jmp, sizeof(jmp), 1, 0, &trigger_aux);
  ReplayInputStatus status;
  uint64_t selected[] = {cld_seq, seq};
  ReplayInput *input = replay_input_capture(f.trace, f.ring, selected, 2, trigger,
                                            CAPTURE_BUDGET, &status);
  assert(input && status == REPLAY_INPUT_READY);
  const InsnAux *saved = replay_input_aux(input, seq);
  assert(saved && dse_aux_has_exact_movs(saved));
  assert(saved->string_summary.values != aux.string_summary.values);
  assert(saved->string_summary.value_taint != aux.string_summary.value_taint);
  assert(saved->string_summary.write_values != aux.string_summary.write_values);
  assert(saved->string_summary.write_capacity == 10);
  assert(saved->string_summary.capacity == 10);
  assert(replay_input_step(input, 1)->occurrence.incomplete_reasons &
         TRACE_OCCURRENCE_READ_OVERFLOW); /* capture never hides trace quality */

  ReplayInput *limited = replay_input_capture(f.trace, f.ring, selected, 2, trigger,
      replay_input_bytes(input) - 1U, &status);
  assert(!limited && status == REPLAY_INPUT_RESOURCE_LIMIT);
  aux.string_summary.values[9] = 0;
  aux.string_summary.value_taint[9] = 0;
  aux.string_summary.write_values[9] = 0;
  release_sources(&f);
  assert(saved->string_summary.values[9] == 0x49);
  assert(saved->string_summary.value_taint[9] == 1);
  assert(saved->string_summary.write_values[9] == 0x49);
  assert(dse_aux_has_exact_movs(saved));
  DSECtx ctx;
  assert(dse_ctx_init(&ctx));
  dse_lift_begin(&ctx);
  assert(dse_lift_replay_step(&ctx, input, 0, f.cs));
  assert(dse_lift_replay_step(&ctx, input, 1, f.cs));
  assert(ctx.string_summaries == 1);
  dse_ctx_free(&ctx);
  replay_input_destroy(input);
  cs_close(&f.cs);
}

static void test_memory_target_replay(void) {
  Fixture f = fixture_create(4);
  const uint8_t store[] = {0xa3, 0x00, 0x30, 0x00, 0x00};
  const uint8_t jump[] = {0xff, 0x25, 0x00, 0x30, 0x00, 0x00};
  InsnAux writer = registers_before(0x401000);
  writer.reg_taint[REG_RAX] = 0xf;
  writer.has_mem_write = true;
  writer.mem_write_addr = 0x3000;
  writer.mem_write_size = 4;
  writer.mem_write_count = 1;
  writer.mem_write_total = 1;
  writer.mem_write_range_valid = true;
  writer.mem_write_min_addr = 0x3000;
  writer.mem_write_max_addr = 0x3003;
  writer.mem_writes[0] = (DseMemWrite){.addr = 0x3000, .value = 0x401000,
                                      .size = 4, .value_valid = true};
  uint64_t seq = emit(&f, 0x1000, store, sizeof(store), 1, 0, &writer);
  finish(&f, seq, 0x1005);
  InsnAux reader = registers_before(0x401000);
  reader.has_mem_read = true;
  reader.mem_read_addr = 0x3000;
  reader.mem_read_val = 0x401000;
  reader.mem_read_value_valid = true;
  reader.mem_read_taint = reader.mem_read_effective_taint = 0xf;
  reader.mem_read_count = reader.mem_read_total = 1;
  reader.mem_read_range_valid = true;
  reader.mem_read_min_addr = 0x3000;
  reader.mem_read_max_addr = 0x3003;
  reader.mem_reads[0] = (DseMemRead){.addr = 0x3000, .value = 0x401000,
      .size = 4, .value_valid = true, .taint = 0xf, .effective_taint = 0xf};
  uint64_t trigger = emit(&f, 0x1005, jump, sizeof(jump), 1, 0, &reader);
  finish(&f, trigger, 0x401000);
  dse_lift_attach(f.trace, f.ring, &dse_arch_x86);
  DseVerifyResult result = dse_verify_oep_candidate_mem(f.trace, f.ring,
      trigger, 0x3000, 0x401000, NULL, f.cs);
  assert(result.replay_valid && result.lifted_total == 2 && result.aux_miss == 0);

  ReplayInputStatus status;
  ReplayInput *input = replay_input_capture(f.trace, f.ring, &seq, 1, trigger,
                                            CAPTURE_BUDGET, &status);
  assert(input && status == REPLAY_INPUT_READY);
  release_sources(&f);
  DSECtx ctx;
  assert(dse_ctx_init(&ctx));
  dse_lift_begin(&ctx);
  assert(dse_lift_replay_step(&ctx, input, 0, f.cs));
  assert(dse_lift_replay_step(&ctx, input, 1, f.cs));
  SymExpr *target = dse_load_mem(&ctx, replay_input_aux(input, trigger), 32, false);
  uint64_t value = 0;
  assert(target && dse_eval_expr_observed(&ctx, target, &value) == DSE_REPLAY_EVAL_OK);
  assert(value == 0x401000);
  sym_expr_free(target);
  dse_ctx_free(&ctx);
  replay_input_destroy(input);
  cs_close(&f.cs);
}

static void test_unknown_and_identity(void) {
  Fixture f = fixture_create(4);
  const uint8_t nop[] = {0x90};
  InsnAux aux = registers_before(7);
  uint64_t seq = emit(&f, 0x1000, nop, sizeof(nop), 1, 1, &aux);
  uint64_t trigger = emit(&f, 0x1001, nop, sizeof(nop), 1, 1, &aux);
  ReplayInputStatus status;
  ReplayInput *input = replay_input_capture(f.trace, f.ring, &seq, 1, trigger,
                                            CAPTURE_BUDGET, &status);
  assert(input && status == REPLAY_INPUT_UNKNOWN);
  assert(replay_input_issues(input) & REPLAY_INPUT_EXECUTION_PENDING);
  replay_input_destroy(input);
  finish(&f, seq, 0x1001);

  TraceEntry *live = (TraceEntry *)trace_find_seq(f.trace, seq, NULL);
  live->bytes_hash ^= 1;
  input = replay_input_capture(f.trace, f.ring, &seq, 1, trigger,
                                CAPTURE_BUDGET, &status);
  assert(input && status == REPLAY_INPUT_UNKNOWN);
  assert(replay_input_issues(input) & REPLAY_INPUT_DESCRIPTOR_MISMATCH);
  replay_input_destroy(input);
  live->bytes_hash ^= 1;
  live->vcpu_index = 2;
  input = replay_input_capture(f.trace, f.ring, &seq, 1, trigger,
                                CAPTURE_BUDGET, &status);
  assert(input && status == REPLAY_INPUT_UNKNOWN);
  assert(replay_input_issues(input) & REPLAY_INPUT_VCPU_MISMATCH);
  replay_input_destroy(input);
  live->vcpu_index = 1;

  InsnAux *live_aux = (InsnAux *)dse_aux_for(f.ring, f.trace, live);
  live_aux->string_summary.bytes_captured = 1;
  input = replay_input_capture(f.trace, f.ring, &seq, 1, trigger,
                                CAPTURE_BUDGET, &status);
  assert(input && status == REPLAY_INPUT_UNKNOWN);
  assert(replay_input_issues(input) & REPLAY_INPUT_STRING_INVALID);
  assert(replay_input_aux(input, seq) == NULL);
  replay_input_destroy(input);
  live_aux->string_summary.bytes_captured = 0;

  uint64_t duplicates[] = {seq, seq};
  input = replay_input_capture(f.trace, f.ring, duplicates, 2, trigger,
                                CAPTURE_BUDGET, &status);
  assert(!input && status == REPLAY_INPUT_INVALID_REQUEST);
  input = replay_input_capture(f.trace, f.ring, &seq, 1, trigger, 0, &status);
  assert(!input && status == REPLAY_INPUT_RESOURCE_LIMIT);

  for (uint32_t i = 0; i < 6; i++) {
    trigger = emit(&f, 0x2000 + i, nop, sizeof(nop), 1, 1, &aux);
    finish(&f, trigger, 0x2001 + i);
  }
  input = replay_input_capture(f.trace, f.ring, &seq, 1, trigger,
                                CAPTURE_BUDGET, &status);
  assert(input && status == REPLAY_INPUT_UNKNOWN);
  assert(replay_input_step(input, 0)->descriptor_valid);
  assert(replay_input_step(input, 0)->occurrence.execution_complete);
  assert(replay_input_issues(input) & REPLAY_INPUT_AUX_MISSING);
  assert(replay_input_aux(input, seq) == NULL);
  replay_input_destroy(input);
  release_sources(&f);
  cs_close(&f.cs);
}

static void test_branch_event_snapshot(void) {
  Fixture f = fixture_create(4);
  const uint8_t jne[] = {0x75, 0x02};
  const uint8_t nop[] = {0x90};
  InsnAux aux = registers_before(0);
  aux.execution_complete = true;
  aux.next_pc_valid = true;
  aux.next_pc = 0x1004;
  uint64_t seq = emit(&f, 0x1000, jne, sizeof(jne), 1, 2, &aux);
  const TraceEntry *entry = trace_find_seq(f.trace, seq, NULL);
  BranchEventBuffer *events = branch_event_buffer_create(4);
  assert(events);
  BranchEvent branch = {.branch_seq_id = seq, .vcpu_index = 2,
    .meta_id = entry->meta_id, .pc = 0x1000, .fallthrough = 0x1002,
    .direct_target_valid = true, .direct_target = 0x1004,
    .observed_next_pc = 0x1004, .condition_code = X86_CC_NE,
    .outcome = BRANCH_OUTCOME_TAKEN, .condition_label = 42};
  assert(branch_event_append(events, &branch));
  assert(dse_aux_archive_occurrence(f.ring, f.trace, events, seq));
  aux = registers_before(0);
  uint64_t trigger = emit(&f, 0x1004, nop, sizeof(nop), 1, 2, &aux);
  ReplayInputStatus status;
  ReplayInput *input = replay_input_capture(f.trace, f.ring, &seq, 1, trigger,
                                            CAPTURE_BUDGET, &status);
  assert(input && status == REPLAY_INPUT_READY);
  branch_event_buffer_destroy(events);
  release_sources(&f);
  const InsnOccurrence *saved = &replay_input_step(input, 0)->occurrence;
  assert(saved->branch_event_valid && saved->condition_label == 42);
  assert(saved->branch_outcome == BRANCH_OUTCOME_TAKEN);
  assert(saved->observed_branch_target == 0x1004);
  DSECtx ctx;
  assert(dse_ctx_init(&ctx));
  dse_lift_begin(&ctx);
  assert(dse_lift_replay_step(&ctx, input, 0, f.cs));
  assert(ctx.path_constraints == 1 && ctx.replay_model_complete);
  dse_ctx_free(&ctx);
  replay_input_destroy(input);
  cs_close(&f.cs);
}

int main(void) {
  test_replay_after_source_destruction();
  test_rep_payload_and_budget();
  test_memory_target_replay();
  test_unknown_and_identity();
  test_branch_event_snapshot();
  puts("ReplayInput: lifetime, registers, memory, REP, UNKNOWN, identity, branches: PASS");
  return 0;
}
