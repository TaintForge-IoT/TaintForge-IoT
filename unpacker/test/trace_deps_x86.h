#ifndef TRACE_DEPS_X86_H
#define TRACE_DEPS_X86_H

#include "aux_trace.h"
#include "trace_deps.h"

/* Transitional 32-bit x86 adapter. Accepts either hot records or the owned
 * records from ReplayInput. A nonzero descriptor ID must resolve exactly;
 * legacy ID zero is reconstructed from matching entry/meta snapshots.
 * No pointers to any input survive this call. False leaves a conservative
 * view and explicit incomplete_reasons in out.
 */
bool trace_deps_x86_build(const TraceEntry *entry, const InsnDesc *desc, const InsnMeta *meta,
                          const InsnAux *aux, const InsnOccurrence *occurrence,
                          uint8_t register_width, TraceDeps *out);

uint64_t trace_deps_x86_forced_value_regs(const InsnMeta *meta, const uint8_t needed[REG_COUNT],
                                          uint8_t natural_mask);
uint8_t trace_deps_x86_legacy_flags(uint64_t special);

#endif
