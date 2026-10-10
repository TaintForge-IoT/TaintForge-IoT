#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dse.h"
#include "trace_deps_x86.h"

#define BIT(id) (UINT64_C(1) << (id))
#define FLAG(id) trace_special_state_bit(X86_SPECIAL_STATE_##id)

typedef struct { csh cs; TraceBuffer *trace; DseAuxRing *ring; } Fixture;

static Fixture fixture(void) {
  Fixture f = {0};
  assert(cs_open(CS_ARCH_X86, CS_MODE_32, &f.cs) == CS_ERR_OK);
  assert(cs_option(f.cs, CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK);
  meta_init();
  f.trace = trace_buffer_create(32);
  f.ring = dse_aux_create(32);
  assert(f.trace && f.ring);
  dse_lift_attach(f.trace, f.ring, &dse_arch_x86);
  return f;
}

static void destroy(Fixture *f) {
  dse_lift_attach(NULL, NULL, &dse_arch_x86);
  dse_aux_destroy(f->ring);
  trace_buffer_destroy(f->trace);
  meta_free();
  cs_close(&f->cs);
}

static InsnAux state(void) {
  InsnAux aux = {0};
  aux.reg_value_valid_mask = (1U << REG_COUNT) - 1U;
  aux.eflags_valid = true;
  aux.eflags_before = 2;
  return aux;
}

static uint64_t emit(Fixture *f, uint64_t pc, const uint8_t *bytes, uint8_t size,
                      uint32_t generation, uint32_t vcpu, const InsnAux *before) {
  InsnMeta *decoded = meta_decode(bytes, size, pc, f->cs);
  assert(decoded);
  const InsnMeta *meta = meta_store(pc, decoded);
  assert(meta);
  InsnDescId id = trace_insn_desc_intern(f->trace, TRACE_ARCH_X86, TRACE_MODE_32,
      pc, generation, bytes, size, meta);
  assert(id);
  TraceEntry entry = {.insn_desc_id = id, .vcpu_index = vcpu, .pc = pc};
  const TraceEntry *stored = trace_append(f->trace, &entry);
  assert(stored);
  InsnAux *aux = dse_aux_record(f->ring, f->trace, stored, before);
  assert(aux);
  if (!before->execution_complete) dse_aux_finalize(aux, pc + size, NULL, 0);
  return stored->seq_id;
}

static const TraceEntry *entry_at(Fixture *f, uint64_t seq) {
  const TraceEntry *entry = trace_find_seq(f->trace, seq, NULL);
  assert(entry);
  return entry;
}

static TraceDeps dependencies(Fixture *f, uint64_t seq) {
  const TraceEntry *entry = entry_at(f, seq);
  InsnOccurrence occ;
  assert(dse_aux_materialize_occurrence(f->ring, f->trace, entry, &occ));
  TraceDeps deps;
  assert(trace_deps_x86_build(entry, trace_insn_desc_get(f->trace, entry->insn_desc_id),
      meta_lookup_id(entry->meta_id), dse_aux_for(f->ring, f->trace, entry), &occ, 32, &deps));
  return deps;
}

static InsnOccurrence occurrence(const InsnDesc *desc) {
  InsnOccurrence occ = {.desc_id = desc->desc_id, .meta_id = desc->meta_id,
      .pc = desc->pc, .code_generation = desc->code_generation,
      .bytes_hash = desc->bytes_hash, .dynamic_effects_available = true,
      .execution_complete = true};
  return occ;
}

static void test_generic_slices_and_roles(void) {
  InsnDesc desc = {.desc_id = 17, .meta_id = 4, .pc = 0x1000};
  desc.effects = (EffectSummary){.register_value_uses = BIT(40),
      .register_defs = BIT(41), .register_address_uses = BIT(62),
      .register_memory_read_address_uses = BIT(62), .register_control_uses = BIT(63),
      .special_value_uses = BIT(60), .special_address_uses = BIT(61),
      .special_control_uses = BIT(62), .special_defs = BIT(63),
      .value_use_slices = {{40, 4, 4}}, .value_use_slice_count = 1,
      .def_slices = {{41, 8, 8}}, .def_slice_count = 1};
  InsnOccurrence occ = occurrence(&desc);
  TraceDeps deps;
  assert(trace_deps_build(&desc, &occ, 64, &deps));
  assert(deps.value_uses[40] == 0xf0 && deps.may_write[41] == 0xff00);
  assert(deps.must_write[41] == 0 && deps.special_must_write == 0);
  assert(deps.address_uses[62] == UINT64_MAX && deps.control_uses[63] == UINT64_MAX);
  assert(deps.special_value_uses == BIT(60) && deps.special_address_uses == BIT(61));
  assert(deps.special_control_uses == BIT(62) && deps.special_may_write == BIT(63));
  assert(trace_deps_bytes(0xf0, false) == 1 && trace_deps_bytes(0xf0, true) == 0);
  assert(trace_deps_bytes(0xff00, true) == 2);
  assert(trace_deps_bytes(UINT64_MAX, true) == 0xff);
  desc.effects.quality_flags = TRACE_EFFECT_SLICE_DETAIL_TRUNCATED;
  assert(!trace_deps_build(&desc, &occ, 64, &deps));
  assert(deps.incomplete_reasons & TRACE_DEPS_DETAIL_TRUNCATED);
  assert(deps.may_write[41] == UINT64_MAX && deps.must_write[41] == 0);
  desc.effects.quality_flags = 0;
  desc.effects.def_slices[0].reg_id = 64;
  assert(!trace_deps_build(&desc, &occ, 64, &deps));
  assert(deps.incomplete_reasons & TRACE_DEPS_INVALID_SLICE);
  assert(deps.may_write[0] == UINT64_MAX);
  assert(!trace_deps_build(NULL, &occ, 32, &deps));
  assert(deps.may_write[0] == UINT32_MAX && deps.special_may_write == UINT64_MAX);
  assert(!trace_deps_build(&desc, &occ, 0, &deps));
  assert(deps.incomplete_reasons & TRACE_DEPS_UNSUPPORTED_WIDTH);
  puts("PASS: generic bit slices, arbitrary IDs, roles, partial-byte kills, UNKNOWN");
}

static void test_memory_evidence(void) {
  InsnDesc desc = {.desc_id = 1};
  desc.effects.may_write_memory = true;
  InsnOccurrence occ = occurrence(&desc);
  occ.mem_write_count = occ.mem_write_total = 1;
  occ.mem_writes[0] = (TraceMemoryEffect){.kind = TRACE_MEM_WRITE,
      .address = 0x1000, .size = 4, .value_valid = false};
  occ.incomplete_reasons = TRACE_OCCURRENCE_VALUE_MISSING;
  TraceDeps deps;
  assert(trace_deps_build(&desc, &occ, 32, &deps));
  assert(trace_deps_memory_overlap(&deps, TRACE_MEM_WRITE, 0x1003, 2) == TRACE_DEP_YES);
  assert(trace_deps_memory_overlap(&deps, TRACE_MEM_WRITE, 0x1004, 1) == TRACE_DEP_NO);
  assert(trace_deps_memory_overlap(&deps, TRACE_MEM_READ, 0x1000, 4) == TRACE_DEP_NO);
  occ.mem_write_total = 10;
  occ.incomplete_reasons |= TRACE_OCCURRENCE_WRITE_OVERFLOW;
  occ.mem_write_range_valid = true;
  occ.mem_write_min_addr = 0x1000;
  occ.mem_write_max_addr = 0x1027;
  assert(trace_deps_build(&desc, &occ, 32, &deps));
  assert(trace_deps_memory_overlap(&deps, TRACE_MEM_WRITE, 0x1010, 1) == TRACE_DEP_UNKNOWN);
  assert(trace_deps_memory_overlap(&deps, TRACE_MEM_WRITE, 0x2000, 4) == TRACE_DEP_NO);
  occ.execution_complete = false;
  assert(!trace_deps_build(&desc, &occ, 32, &deps));
  assert(trace_deps_memory_overlap(&deps, TRACE_MEM_WRITE, 0x2000, 4) == TRACE_DEP_UNKNOWN);
  occ.execution_complete = true;
  occ.incomplete_reasons |= TRACE_OCCURRENCE_RANGE_UNKNOWN;
  assert(trace_deps_build(&desc, &occ, 32, &deps));
  assert(trace_deps_memory_overlap(&deps, TRACE_MEM_WRITE, 0x2000, 4) == TRACE_DEP_UNKNOWN);
  assert(trace_deps_memory_overlap(&deps, TRACE_MEM_WRITE, UINT64_MAX, 2) == TRACE_DEP_UNKNOWN);
  assert(trace_deps_memory_overlap(&deps, TRACE_MEM_WRITE, 0, 0) == TRACE_DEP_UNKNOWN);
  occ.mem_writes[0].size = 0;
  assert(trace_deps_build(&desc, &occ, 32, &deps));
  assert(trace_deps_memory_overlap(&deps, TRACE_MEM_WRITE, 0x1000, 1) == TRACE_DEP_UNKNOWN);
  occ = occurrence(&desc);
  occ.dynamic_effects_available = false;
  assert(!trace_deps_build(&desc, &occ, 32, &deps));
  assert(trace_deps_memory_overlap(&deps, TRACE_MEM_WRITE, 0x1000, 1) == TRACE_DEP_UNKNOWN);
  assert(trace_deps_memory_overlap(&deps, TRACE_MEM_READ, 0x1000, 1) == TRACE_DEP_NO);
  puts("PASS: memory overlap, missing values, bounded overflow, pending and malformed access");
}

static void test_x86_effects(void) {
  Fixture f = fixture();
  InsnAux aux = state();
  aux.reg_taint[REG_RAX] = 0xf;
  const uint8_t ah[] = {0xb4, 0x56}, selfzero[] = {0x31, 0xc0};
  const uint8_t inc[] = {0x40}, adc[] = {0x83, 0xd0, 0x00}, cld[] = {0xfc};
  const uint8_t sh0[] = {0xc1, 0xe0, 0}, sh32[] = {0xc1, 0xe0, 32};
  const uint8_t sh1[] = {0xd1, 0xe0}, sh2[] = {0xc1, 0xe0, 2};
  const uint8_t shcl[] = {0xd3, 0xe0}, sh8[] = {0xc0, 0xe0, 8};
  const uint8_t movs[] = {0xa4};
  const uint8_t lea[] = {0x8d, 0x44, 0x8b, 4};
  TraceDeps deps = dependencies(&f, emit(&f, 0x1000, ah, sizeof(ah), 1, 0, &aux));
  assert(deps.must_write[REG_RAX] == 0xff00 && deps.may_write[REG_RAX] == 0xff00);
  deps = dependencies(&f, emit(&f, 0x1002, selfzero, sizeof(selfzero), 1, 0, &aux));
  assert(deps.value_uses[REG_RAX] == 0 && deps.must_write[REG_RAX] == UINT32_MAX);
  assert(deps.special_unknown_write == FLAG(AF));
  deps = dependencies(&f, emit(&f, 0x1004, inc, sizeof(inc), 1, 0, &aux));
  assert(!(deps.special_may_write & FLAG(CF)) && (deps.special_must_write & FLAG(ZF)));
  deps = dependencies(&f, emit(&f, 0x1005, adc, sizeof(adc), 1, 0, &aux));
  assert(deps.special_value_uses == FLAG(CF));
  deps = dependencies(&f, emit(&f, 0x1008, cld, sizeof(cld), 1, 0, &aux));
  assert(deps.special_must_write == FLAG(DF));
  deps = dependencies(&f, emit(&f, 0x1009, movs, sizeof(movs), 1, 0, &aux));
  assert(deps.special_address_uses == FLAG(DF) && deps.special_value_uses == 0);
  deps = dependencies(&f, emit(&f, 0x1010, sh0, sizeof(sh0), 1, 0, &aux));
  assert(deps.may_write[REG_RAX] == 0 && deps.special_may_write == 0);
  deps = dependencies(&f, emit(&f, 0x1013, sh32, sizeof(sh32), 1, 0, &aux));
  assert(deps.may_write[REG_RAX] == 0 && deps.special_may_write == 0);
  deps = dependencies(&f, emit(&f, 0x1016, sh1, sizeof(sh1), 1, 0, &aux));
  assert(deps.must_write[REG_RAX] == UINT32_MAX && deps.special_unknown_write == FLAG(AF));
  deps = dependencies(&f, emit(&f, 0x1018, sh2, sizeof(sh2), 1, 0, &aux));
  assert(deps.special_unknown_write == (FLAG(AF) | FLAG(OF)));
  deps = dependencies(&f, emit(&f, 0x101b, sh8, sizeof(sh8), 1, 0, &aux));
  assert(deps.special_unknown_write == (FLAG(AF) | FLAG(OF) | FLAG(CF)));
  deps = dependencies(&f, emit(&f, 0x101e, shcl, sizeof(shcl), 1, 0, &aux));
  assert(deps.may_write[REG_RAX] == 0 && deps.special_may_write == 0);
  aux.reg_taint[REG_RCX] = 1;
  deps = dependencies(&f, emit(&f, 0x1020, shcl, sizeof(shcl), 1, 0, &aux));
  assert(deps.may_write[REG_RAX] == UINT32_MAX && deps.must_write[REG_RAX] == 0);
  assert(deps.special_may_write & FLAG(ZF));
  assert(deps.special_must_write == 0 && (deps.value_uses[REG_RCX] & 0xff));
  deps = dependencies(&f, emit(&f, 0x1022, lea, sizeof(lea), 1, 0, &aux));
  assert(deps.value_uses[REG_RBX] == UINT32_MAX && deps.value_uses[REG_RCX] == UINT32_MAX);
  assert(!deps.may_read_memory && !deps.may_write_memory);
  destroy(&f);
  puts("PASS: x86 AH, self-zeroing, INC/ADC, DF, masked and input-dependent shift counts");
}

static void check_slice(const DseSliceResult *result, const TraceEntry **slice,
                         const uint64_t *expected, uint32_t count) {
  if (result->status != DSE_SLICE_OK || result->len != count) {
    fprintf(stderr, "slice status=%d issues=0x%x len=%u expected=%u\n",
        result->status, result->dependency_unknown_reasons, result->len, count);
    for (uint32_t i = 0; i < result->len; i++)
      fprintf(stderr, " seq=%llu\n", (unsigned long long)slice[i]->seq_id);
  }
  assert(result->status == DSE_SLICE_OK && result->len == count);
  for (uint32_t i = 0; i < count; i++) assert(slice[i]->seq_id == expected[i]);
}

static void test_slice_shift_preservation(bool variable, bool undefined) {
  Fixture f = fixture();
  InsnAux aux = state();
  const uint8_t mov[] = {0xb8, 0x00, 0x10, 0x40, 0};
  const uint8_t cmp[] = {0x83, 0xfb, 0};
  const uint8_t shzero[] = {0xc1, 0xe2, 0}, shcl[] = {0xd3, 0xe2};
  const uint8_t shtwo[] = {0xc1, 0xe2, 2};
  const uint8_t jnz[] = {0x75, 1}, jo[] = {0x70, 1}, jmp[] = {0xff, 0xe0};
  uint64_t initial = emit(&f, 0x1000, mov, sizeof(mov), 1, 0, &aux);
  aux.reg_taint[REG_RAX] = 0xf;
  aux.reg_taint[REG_RBX] = 0xf;
  uint64_t compare = emit(&f, 0x1005, cmp, sizeof(cmp), 1, 0, &aux);
  aux.reg_taint[REG_RCX] = variable ? 1 : 0;
  uint64_t shift = emit(&f, 0x1008, undefined ? shtwo : variable ? shcl : shzero,
      variable ? sizeof(shcl) : sizeof(shzero), 1, 0, &aux);
  uint64_t branch = emit(&f, 0x100b, undefined ? jo : jnz, sizeof(jnz), 1, 0, &aux);
  uint64_t trigger = emit(&f, 0x100d, jmp, sizeof(jmp), 1, 0, &aux);
  const TraceEntry *slice[16] = {0};
  DseSliceResult result = dse_build_reg_slice(f.trace, f.ring, trigger, REG_RAX, slice, 16);
  if (undefined) {
    assert(result.status == DSE_SLICE_DEPENDENCY_UNKNOWN && !result.complete);
    assert(result.dependency_unknown_reasons & TRACE_DEPS_UNDEFINED_SPECIAL);
  } else if (variable) {
    uint64_t expected[] = {initial, compare, shift, branch, trigger};
    check_slice(&result, slice, expected, 5);
    assert(result.boundary_reg_bytes[REG_RCX] & 1);
  } else {
    uint64_t expected[] = {initial, compare, branch, trigger};
    check_slice(&result, slice, expected, 4);
  }
  destroy(&f);
}

static void test_slice_carry_and_partial_register(void) {
  Fixture f = fixture();
  InsnAux aux = state();
  const uint8_t add[] = {0x83, 0xc3, 1}, inc[] = {0x42};
  const uint8_t adc[] = {0x83, 0xd2, 0}, jmp[] = {0xff, 0xe2};
  uint64_t carry = emit(&f, 0x1000, add, sizeof(add), 1, 0, &aux);
  aux.reg_taint[REG_RDX] = 0xf;
  uint64_t increment = emit(&f, 0x1003, inc, sizeof(inc), 1, 0, &aux);
  uint64_t consume = emit(&f, 0x1004, adc, sizeof(adc), 1, 0, &aux);
  uint64_t trigger = emit(&f, 0x1007, jmp, sizeof(jmp), 1, 0, &aux);
  const TraceEntry *slice[16] = {0};
  DseSliceResult result = dse_build_reg_slice(f.trace, f.ring, trigger, REG_RDX, slice, 16);
  uint64_t expected[] = {carry, increment, consume, trigger};
  check_slice(&result, slice, expected, 4);
  assert(!(result.boundary_special & FLAG(CF)));
  destroy(&f);

  f = fixture();
  aux = state();
  const uint8_t mov[] = {0xb8, 0, 0, 0, 0}, ah[] = {0xb4, 0x12}, al[] = {0xb0, 0x34};
  const uint8_t jumpax[] = {0xff, 0xe0};
  uint64_t full = emit(&f, 0x2000, mov, sizeof(mov), 1, 0, &aux);
  aux.reg_taint[REG_RAX] = 0xf;
  uint64_t high = emit(&f, 0x2005, ah, sizeof(ah), 1, 0, &aux);
  uint64_t low = emit(&f, 0x2007, al, sizeof(al), 1, 0, &aux);
  /* An unrelated vCPU must never become a last writer. */
  (void)emit(&f, 0x2000, mov, sizeof(mov), 2, 1, &aux);
  trigger = emit(&f, 0x2009, jumpax, sizeof(jumpax), 1, 0, &aux);
  result = dse_build_reg_slice(f.trace, f.ring, trigger, REG_RAX, slice, 16);
  uint64_t partial[] = {full, high, low, trigger};
  check_slice(&result, slice, partial, 4);
  assert(result.boundary_reg_bytes[REG_RAX] == 0);
  destroy(&f);
  puts("PASS: slicer keeps the carry producer through INC and preserves AL/AH byte boundaries");
}

static void add_write(InsnAux *aux, uint64_t address, uint8_t size) {
  aux->has_mem_write = true;
  aux->mem_write_count = aux->mem_write_total = 1;
  aux->mem_write_addr = aux->mem_write_min_addr = address;
  aux->mem_write_size = size;
  aux->mem_write_max_addr = address + size - 1;
  aux->mem_write_range_valid = true;
  aux->mem_writes[0] = (DseMemWrite){.addr = address, .size = size, .value_valid = true};
}

static void add_read(InsnAux *aux, uint64_t address, uint8_t size) {
  aux->has_mem_read = true;
  aux->mem_read_count = aux->mem_read_total = 1;
  aux->mem_read_addr = aux->mem_read_min_addr = address;
  aux->mem_read_max_addr = address + size - 1;
  aux->mem_read_range_valid = aux->mem_read_value_valid = true;
  aux->mem_read_taint = aux->mem_read_effective_taint = (uint8_t)((1U << size) - 1);
  aux->mem_reads[0] = (DseMemRead){.addr = address, .size = size, .value_valid = true,
      .taint = aux->mem_read_taint, .effective_taint = aux->mem_read_taint};
}

static void test_slice_memory(bool overflow, bool outside) {
  Fixture f = fixture();
  InsnAux aux = state();
  const uint8_t store[] = {0xa3, 0x00, 0x30, 0, 0};
  uint8_t high[] = {0x66, 0x89, 0x1d, 0x02, 0x30, 0, 0};
  if (outside) { high[3] = 0; high[4] = 0x40; }
  const uint8_t jump[] = {0xff, 0x25, 0x00, 0x30, 0, 0};
  add_write(&aux, 0x3000, 4);
  uint64_t first = emit(&f, 0x1000, store, sizeof(store), 1, 0, &aux);
  aux = state();
  add_write(&aux, outside ? 0x4000 : 0x3002, 2);
  if (overflow) {
    aux.mem_write_overflow = true;
    aux.mem_write_total = 10;
    aux.mem_write_max_addr = outside ? 0x4013 : 0x3015;
  }
  uint64_t second = emit(&f, 0x1005, high, sizeof(high), 1, 0, &aux);
  aux = state();
  add_read(&aux, 0x3000, 4);
  uint64_t trigger = emit(&f, 0x100c, jump, sizeof(jump), 1, 0, &aux);
  const TraceEntry *slice[16] = {0};
  DseSliceResult result = dse_build_mem_slice(f.trace, f.ring, trigger, 0x3000, 4, slice, 16);
  if (overflow && !outside) {
    assert(result.status == DSE_SLICE_MEM_ACCESS_UNMODELED && !result.complete);
  } else if (outside) {
    uint64_t expected[] = {first, trigger};
    check_slice(&result, slice, expected, 2);
  } else {
    uint64_t expected[] = {first, second, trigger};
    check_slice(&result, slice, expected, 3);
  }
  destroy(&f);
}

static void test_identity_and_owned_input(void) {
  Fixture f = fixture();
  InsnAux aux = state();
  const uint8_t mov[] = {0xb8, 1, 0, 0, 0}, rewrite[] = {0xb4, 2}, jump[] = {0xff, 0xe0};
  uint64_t seq = emit(&f, 0x1000, mov, sizeof(mov), 1, 0, &aux);
  (void)emit(&f, 0x1000, rewrite, sizeof(rewrite), 2, 0, &aux);
  uint64_t trigger = emit(&f, 0x1005, jump, sizeof(jump), 1, 0, &aux);
  const TraceEntry *entry = entry_at(&f, seq);
  InsnOccurrence occ;
  assert(dse_aux_materialize_occurrence(f.ring, f.trace, entry, &occ));
  const InsnMeta *meta = meta_lookup_id(entry->meta_id);
  const InsnDesc *desc = trace_insn_desc_get(f.trace, entry->insn_desc_id);
  const InsnAux *saved_aux = dse_aux_for(f.ring, f.trace, entry);
  TraceDeps deps;
  occ.code_generation++;
  assert(!trace_deps_x86_build(entry, desc, meta, saved_aux, &occ, 32, &deps));
  assert(deps.incomplete_reasons & TRACE_DEPS_IDENTITY_MISMATCH);
  assert(deps.may_write[REG_RAX] == UINT32_MAX && deps.must_write[REG_RAX] == 0);
  occ.code_generation--;
  TraceEntry legacy = *entry;
  legacy.insn_desc_id = 0;
  occ.desc_id = 0;
  assert(trace_deps_x86_build(&legacy, NULL, meta, saved_aux, &occ, 32, &deps));
  assert(deps.must_write[REG_RAX] == UINT32_MAX);
  ReplayInputStatus status;
  ReplayInput *input = replay_input_capture(f.trace, f.ring, &seq, 1, trigger, 1024 * 1024, &status);
  assert(input && status == REPLAY_INPUT_READY);
  destroy(&f);
  const ReplayStep *step = replay_input_step(input, 0);
  assert(trace_deps_x86_build(&step->entry, &step->descriptor,
      replay_input_meta(input, seq), replay_input_aux(input, seq), &step->occurrence, 32, &deps));
  assert(deps.must_write[REG_RAX] == UINT32_MAX && deps.occurrence.code_generation == 1);
  replay_input_destroy(input);
  assert(deps.occurrence.pc == 0x1000); /* view owns all retained evidence */
  puts("PASS: generation identity, legacy adapter and dependencies after ReplayInput/source destruction");
}

static void test_rep_and_df(void) {
  Fixture f = fixture();
  InsnAux aux = state();
  const uint8_t cld[] = {0xfc}, movcount[] = {0xb9, 10, 0, 0, 0};
  const uint8_t stos[] = {0xf3, 0xaa}, jump[] = {0xff, 0x25, 0x06, 0x30, 0, 0};
  uint64_t df = emit(&f, 0x1000, cld, sizeof(cld), 1, 0, &aux);
  uint64_t count = emit(&f, 0x1001, movcount, sizeof(movcount), 1, 0, &aux);
  aux.reg_vals[REG_RCX] = 10;
  aux.reg_vals[REG_RDI] = 0x3000;
  aux.reg_taint[REG_RCX] = 0xf;
  aux.execution_complete = true;
  aux.next_pc_valid = true;
  aux.next_pc = 0x1008;
  aux.has_mem_write = aux.mem_write_range_valid = aux.mem_write_overflow = true;
  aux.mem_write_count = DSE_MAX_MEM_ACCESSES;
  aux.mem_write_total = 10;
  aux.mem_write_min_addr = 0x3000;
  aux.mem_write_max_addr = 0x3009;
  for (uint8_t i = 0; i < DSE_MAX_MEM_ACCESSES; i++)
    aux.mem_writes[i] = (DseMemWrite){.addr = 0x3000U + i, .size = 1, .value_valid = true};
  aux.string_summary = (DseStringSummary){.kind = DSE_STRING_STOS,
      .active = true, .exact = true, .has_rep_prefix = true, .element_size = 1,
      .direction = 1, .expected_iterations = 10, .write_events = 10,
      .destination_first = 0x3000};
  uint64_t rep = emit(&f, 0x1006, stos, sizeof(stos), 1, 0, &aux);
  TraceDeps deps = dependencies(&f, rep);
  assert(deps.must_write[REG_RDI] == 0 && deps.may_write[REG_RDI] == UINT32_MAX);
  assert(deps.special_address_uses == FLAG(DF));
  aux = state();
  add_read(&aux, 0x3006, 4); /* includes two accesses outside the retained array */
  uint64_t trigger = emit(&f, 0x1008, jump, sizeof(jump), 1, 0, &aux);
  const TraceEntry *slice[16] = {0};
  DseSliceResult result = dse_build_mem_slice(f.trace, f.ring, trigger, 0x3006, 4, slice, 16);
  uint64_t expected[] = {df, count, rep, trigger};
  check_slice(&result, slice, expected, 4);
  assert(result.string_summaries == 1 && result.boundary_special == 0);
  assert(result.boundary_reg_bytes[REG_RCX] == 0);
  InsnAux *rep_aux = (InsnAux *)dse_aux_for(f.ring, f.trace, entry_at(&f, rep));
  rep_aux->reg_taint[REG_RCX] = 0;
  deps = dependencies(&f, rep);
  assert(deps.must_write[REG_RDI] == UINT32_MAX);
  rep_aux->reg_vals[REG_RCX] = 0;
  rep_aux->mem_write_count = rep_aux->mem_write_total = 0;
  rep_aux->has_mem_write = rep_aux->mem_write_overflow = rep_aux->mem_write_range_valid = false;
  rep_aux->string_summary.expected_iterations = rep_aux->string_summary.write_events = 0;
  deps = dependencies(&f, rep);
  assert(deps.may_write[REG_RDI] == 0 && deps.special_address_uses == 0);
  destroy(&f);
  puts("PASS: exact REP beyond eight accesses, count dependencies, zero iterations and DF producer");
}

static void test_relevant_unknowns(void) {
  Fixture f = fixture();
  InsnAux aux = state();
  const uint8_t shift[] = {0xd3, 0xe0}, jump[] = {0xff, 0xe0};
  uint64_t seq = emit(&f, 0x1000, shift, sizeof(shift), 1, 0, &aux);
  aux.reg_taint[REG_RAX] = 0xf;
  uint64_t trigger = emit(&f, 0x1002, jump, sizeof(jump), 1, 0, &aux);
  InsnAux *shift_aux = (InsnAux *)dse_aux_for(f.ring, f.trace, entry_at(&f, seq));
  shift_aux->reg_value_valid_mask &= ~(1U << REG_RCX);
  const TraceEntry *slice[16] = {0};
  DseSliceResult result = dse_build_reg_slice(f.trace, f.ring, trigger, REG_RAX, slice, 16);
  assert(result.status == DSE_SLICE_DEPENDENCY_UNKNOWN);
  assert(result.dependency_unknown_reasons & TRACE_DEPS_STATE_MISSING);
  shift_aux->execution_complete = false;
  result = dse_build_reg_slice(f.trace, f.ring, trigger, REG_RAX, slice, 16);
  assert(result.status == DSE_SLICE_AUX_MISSING);
  shift_aux->execution_complete = true;
  shift_aux->reg_value_valid_mask |= 1U << REG_RCX;
  /* An identity fault cannot be discarded as an unrelated register write. */
  TraceEntry *bad = (TraceEntry *)entry_at(&f, seq);
  bad->code_generation++;
  result = dse_build_reg_slice(f.trace, f.ring, trigger, REG_RAX, slice, 16);
  assert(result.status == DSE_SLICE_DEPENDENCY_UNKNOWN);
  assert(result.dependency_unknown_reasons & TRACE_DEPS_IDENTITY_MISMATCH);
  destroy(&f);
  puts("PASS: demanded missing count, unfinished occurrence and generation mismatch stay UNKNOWN");
}

int main(void) {
  test_generic_slices_and_roles();
  test_memory_evidence();
  test_x86_effects();
  test_slice_shift_preservation(false, false);
  test_slice_shift_preservation(true, false);
  test_slice_shift_preservation(false, true);
  puts("PASS: CMP/shift/Jcc keeps old ZF for zero or symbolic count; demanded undefined OF is UNKNOWN");
  test_slice_carry_and_partial_register();
  test_slice_memory(false, false);
  test_slice_memory(true, false);
  test_slice_memory(true, true);
  puts("PASS: slicer overlapping stores and overflow inside/outside the needed range");
  test_rep_and_df();
  test_relevant_unknowns();
  test_identity_and_owned_input();
  puts("TraceDeps Group 7.3b: PASS");
  return 0;
}
