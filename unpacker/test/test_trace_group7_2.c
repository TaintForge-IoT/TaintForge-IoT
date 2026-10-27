#include <assert.h>
#include <string.h>

#include "trace.h"
#include "aux_trace.h"

static RegSlice slice(RegId reg, uint8_t offset, uint8_t width) {
	RegSlice result = {
		.reg_id = reg,
		.byte_offset = offset,
		.width = width,
		.mask = (uint8_t)(((1U << width) - 1U) << offset)
	};
	return result;
}

int main(void) {
	TraceBuffer *trace = trace_buffer_create(4);
	DseAuxRing *aux_ring = dse_aux_create(4);
	assert(trace && aux_ring);

	const uint8_t bytes[] = {0x39, 0xd8};
	InsnMeta meta = {0};
	meta.meta_id = 41;
	meta.pc = 0x401000;
	meta.size = sizeof(bytes);
	memcpy(meta.instr_bytes, bytes, sizeof(bytes));
	meta.insn_id = 99;
	meta.family = DTA_FAMILY_COMPARE;
	meta.regs_read_mask = (1U << DTA_REG_RAX) | (1U << DTA_REG_RBX);
	meta.reg_reads[0] = slice(DTA_REG_RAX, 0, 4);
	meta.reg_reads[1] = slice(DTA_REG_RBX, 0, 4);
	meta.reg_read_count = 2;
	meta.flags_write_mask = X86_FLAG_CF | X86_FLAG_ZF | X86_FLAG_OF;

	InsnDescId first = trace_insn_desc_intern(
		trace, TRACE_ARCH_X86, TRACE_MODE_32, meta.pc, 7,
		bytes, sizeof(bytes), &meta);
	InsnDescId duplicate = trace_insn_desc_intern(
		trace, TRACE_ARCH_X86, TRACE_MODE_32, meta.pc, 7,
		bytes, sizeof(bytes), &meta);
	InsnDescId next_generation = trace_insn_desc_intern(
		trace, TRACE_ARCH_X86, TRACE_MODE_32, meta.pc, 8,
		bytes, sizeof(bytes), &meta);
	assert(first != INSN_DESC_ID_INVALID);
	assert(first == duplicate);
	assert(next_generation != first);
	assert(trace_insn_desc_count(trace) == 2);
	const uint8_t rewritten_bytes[] = {0x31, 0xc0};
	InsnMeta rewritten = meta;
	rewritten.meta_id = 43;
	memcpy(rewritten.instr_bytes, rewritten_bytes, sizeof(rewritten_bytes));
	InsnDescId rewritten_generation = trace_insn_desc_intern(
		trace, TRACE_ARCH_X86, TRACE_MODE_32, rewritten.pc, 8,
		rewritten_bytes, sizeof(rewritten_bytes), &rewritten);
	assert(rewritten_generation != INSN_DESC_ID_INVALID);
	assert(rewritten_generation != first);
	assert(rewritten_generation != next_generation);
	assert(trace_insn_desc_count(trace) == 3);

	const InsnDesc *desc = trace_insn_desc_get(trace, first);
	assert(desc && desc->bytes_hash != 0 && desc->code_generation == 7);
	assert(desc->effects.register_value_uses == meta.regs_read_mask);
	assert(desc->effects.special_defs & trace_special_state_bit(X86_SPECIAL_STATE_ZF));
	assert(trace_special_state_bit(TRACE_SPECIAL_STATE_CAPACITY) == 0);
	assert(desc->effects.value_use_slice_count == 2);
	assert(desc->effects.value_use_slices[0].bit_width == 32);
	InsnMeta jcc = meta;
	const uint8_t jcc_bytes[] = {0x75, 0x10};
	jcc.meta_id = 42;
	jcc.size = sizeof(jcc_bytes);
	memcpy(jcc.instr_bytes, jcc_bytes, sizeof(jcc_bytes));
	jcc.is_conditional_branch = true;
	jcc.direct_target_valid = true;
	jcc.direct_target = 0x401012;
	jcc.flags_read_mask = X86_FLAG_ZF;
	jcc.flags_write_mask = 0;
	jcc.reg_read_count = 0;
	jcc.regs_read_mask = 0;
	jcc.family = DTA_FAMILY_UNSUPPORTED;
	InsnDescId jcc_id = trace_insn_desc_intern(
		trace, TRACE_ARCH_X86, TRACE_MODE_32, jcc.pc, 7,
		jcc_bytes, sizeof(jcc_bytes), &jcc);
	const InsnDesc *jcc_desc = trace_insn_desc_get(trace, jcc_id);
	assert(jcc_desc && jcc_desc->effects.branch_kind == TRACE_BRANCH_CONDITIONAL);
	assert(jcc_desc->effects.special_control_uses &
		trace_special_state_bit(X86_SPECIAL_STATE_ZF));
	assert(jcc_desc->effects.special_value_uses == 0);
	InsnMeta string_meta = meta;
	string_meta.family = DTA_FAMILY_STRING;
	string_meta.insn_id = X86_INS_MOVSB;
	EffectSummary string_effects;
	assert(trace_effect_summary_from_meta(&string_meta, &string_effects));
	assert(string_effects.special_address_uses &
		trace_special_state_bit(X86_SPECIAL_STATE_DF));
	/* Effect summaries consume decoded attributes, including writes_df. */
	InsnMeta std_meta = {.insn_id = X86_INS_STD, .writes_df = true,
		.size = 1, .instr_bytes = {0xfd}};
	EffectSummary std_effects;
	assert(trace_effect_summary_from_meta(&std_meta, &std_effects));
	assert(std_effects.special_defs &
		trace_special_state_bit(X86_SPECIAL_STATE_DF));

	TraceEntry entry = {
		.vcpu_index = 3,
		.insn_desc_id = first,
		.pc = meta.pc
	};
	const TraceEntry *stored = trace_append(trace, &entry);
	assert(stored && stored->seq_id == 1);
	assert(stored->meta_id == meta.meta_id);
	assert(stored->code_generation == 7);
	assert(stored->size == sizeof(bytes));
	assert(memcmp(stored->instr_bytes, bytes, sizeof(bytes)) == 0);

	InsnAux aux = {0};
	aux.execution_complete = true;
	aux.next_pc_valid = true;
	aux.next_pc = meta.pc + sizeof(bytes);
	aux.has_mem_read = true;
	aux.mem_read_value_valid = true;
	aux.mem_read_count = 1;
	aux.mem_read_total = 1;
	aux.mem_read_range_valid = true;
	aux.mem_read_min_addr = 0x5000;
	aux.mem_read_max_addr = 0x5003;
	aux.mem_reads[0].addr = 0x5000;
	aux.mem_reads[0].value = 0x11223344;
	aux.mem_reads[0].value_valid = true;
	aux.mem_reads[0].size = 4;
	InsnAux *stored_aux = dse_aux_record(aux_ring, trace, stored, &aux);
	assert(stored_aux);

	InsnOccurrence occurrence;
	assert(dse_aux_materialize_occurrence(aux_ring, trace, stored, &occurrence));
	assert(occurrence.desc_id == first);
	assert(occurrence.execution_complete);
	assert(occurrence.incomplete_reasons == 0);
	assert(occurrence.mem_read_count == 1);
	assert(occurrence.mem_reads[0].value_valid);
	assert(occurrence.mem_reads[0].value == 0x11223344);

	TraceEntry invalid_entry = {
		.vcpu_index = 3,
		.insn_desc_id = 9999,
		.pc = meta.pc
	};
	assert(!trace_append(trace, &invalid_entry));
	assert(trace_get_last(trace, 0) == stored);

	BranchEventBuffer *events = branch_event_buffer_create(4);
	assert(events);
	BranchEvent branch = {
		.branch_seq_id = stored->seq_id,
		.vcpu_index = stored->vcpu_index,
		.meta_id = stored->meta_id,
		.pc = stored->pc,
		.observed_next_pc = 0x402000,
		.outcome = BRANCH_OUTCOME_TAKEN,
		.condition_label = 9
	};
	const BranchEvent *stored_branch = branch_event_append(events, &branch);
	assert(stored_branch);
	assert(branch_event_find_seq(events, stored->seq_id, stored->vcpu_index) == stored_branch);
	assert(trace_occurrence_apply_branch_event(&occurrence, stored_branch));
	assert(occurrence.branch_event_valid);
	assert(occurrence.branch_outcome == BRANCH_OUTCOME_TAKEN);
	assert(occurrence.condition_label == 9);
	uint64_t archived_seq = stored->seq_id;
	assert(dse_aux_archive_occurrence(aux_ring, trace, events, archived_seq));
	assert(trace_occurrence_archive_count(trace) == 1);

	/* The hot ring overwrites seq=1, while the chunked archive keeps it. */
	uint64_t newest_seq = archived_seq;
	for (uint32_t index = 0; index < 6; index++) {
		TraceEntry rolling_entry = {
			.vcpu_index = 3,
			.insn_desc_id = first,
			.pc = meta.pc
		};
		const TraceEntry *rolling_stored = trace_append(trace, &rolling_entry);
		assert(rolling_stored);
		newest_seq = rolling_stored->seq_id;
		InsnAux rolling_aux = {0};
		rolling_aux.execution_complete = true;
		rolling_aux.next_pc_valid = true;
		rolling_aux.next_pc = meta.pc + sizeof(bytes);
		assert(dse_aux_record(aux_ring, trace, rolling_stored, &rolling_aux));
		assert(dse_aux_archive_occurrence(
			aux_ring,
			trace,
			events,
			rolling_stored->seq_id));
	}
	assert(trace_find_seq(trace, archived_seq, NULL) == NULL);
	assert(trace_find_seq(trace, newest_seq, NULL) != NULL);
	InsnOccurrence recovered;
	assert(trace_occurrence_archive_find(trace, archived_seq, &recovered));
	assert(recovered.seq_id == archived_seq);
	assert(recovered.desc_id == first);
	assert(recovered.mem_read_count == 1);
	assert(recovered.mem_reads[0].value == UINT64_C(0x11223344));
	assert(recovered.branch_event_valid);
	assert(recovered.branch_outcome == BRANCH_OUTCOME_TAKEN);
	assert(trace_occurrence_archive_count(trace) == 7);
	assert(trace_occurrence_archive_bytes(trace) <
		trace_occurrence_archive_count(trace) * sizeof(InsnOccurrence));
	assert(trace_occurrence_archive_incomplete(trace) == 0);
	assert(trace_occurrence_archive_dropped(trace) == 0);
	assert(trace_occurrence_archive_is_complete(trace));

	branch_event_buffer_destroy(events);
	dse_aux_destroy(aux_ring);
	trace_buffer_destroy(trace);
	return 0;
}
