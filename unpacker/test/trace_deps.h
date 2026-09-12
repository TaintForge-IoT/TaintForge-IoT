#ifndef TRACE_DEPS_H
#define TRACE_DEPS_H

#include "trace.h"

#define TRACE_DEPS_REG_CAPACITY 64U

typedef enum {
    TRACE_DEP_NO = 0,
    TRACE_DEP_YES,
    TRACE_DEP_UNKNOWN
} TraceDepRelation;

enum {
    TRACE_DEPS_DESC_MISSING = 1U << 0,
    TRACE_DEPS_INVALID_SLICE = 1U << 1,
    TRACE_DEPS_DETAIL_TRUNCATED = 1U << 2,
    TRACE_DEPS_IDENTITY_MISMATCH = 1U << 3,
    TRACE_DEPS_STATE_MISSING = 1U << 4,
    TRACE_DEPS_EXECUTION_PENDING = 1U << 5,
    TRACE_DEPS_UNDEFINED_SPECIAL = 1U << 6,
    TRACE_DEPS_UNSUPPORTED_WIDTH = 1U << 7,
    TRACE_DEPS_MEMORY_INCOMPLETE = 1U << 8
};

/* Register IDs and special-state IDs are interpreted only by the frontend.
 * Each register mask describes bits, not bytes. Static EffectSummary defs are
 * possible writes; only an occurrence-aware frontend may promote them to
 * must_write. An undefined result clobbers the old value but stays UNKNOWN.
 * This view owns its occurrence; it does not retain descriptor/aux pointers.
 */
typedef struct {
    uint64_t value_uses[TRACE_DEPS_REG_CAPACITY];
    uint64_t explicit_value_uses[TRACE_DEPS_REG_CAPACITY];
    uint64_t address_uses[TRACE_DEPS_REG_CAPACITY];
    uint64_t control_uses[TRACE_DEPS_REG_CAPACITY];
    uint64_t may_write[TRACE_DEPS_REG_CAPACITY];
    uint64_t must_write[TRACE_DEPS_REG_CAPACITY];
    uint64_t special_value_uses;
    uint64_t special_address_uses;
    uint64_t special_control_uses;
    uint64_t special_may_write;
    uint64_t special_must_write;
    uint64_t special_unknown_write;
    uint64_t address_regs;
    uint64_t read_address_regs;
    uint64_t write_address_regs;
    TraceBranchKind branch_kind;
    bool may_read_memory;
    bool may_write_memory;
    uint8_t register_width;
    uint32_t incomplete_reasons;
    InsnOccurrence occurrence;
} TraceDeps;

bool trace_deps_build(const InsnDesc *desc, const InsnOccurrence *occurrence,
                      uint8_t register_width, TraceDeps *out);

/* Projection for byte-granular clients. Uses/may-writes include every touched
 * byte; a must-write may kill a byte only if all eight bits are overwritten. */
uint8_t trace_deps_bytes(uint64_t bits, bool require_whole_byte);
uint64_t trace_deps_width_mask(uint8_t width);

/* YES: at least one recorded access overlaps. NO: a complete access list or
 * trustworthy total range excludes it. UNKNOWN: missing/overflowed evidence
 * can still overlap. Value validity is independent of address dependence.
 * No order between the separate read/write lists is inferred here.
 */
TraceDepRelation trace_deps_memory_overlap(const TraceDeps *deps, TraceMemoryEffectKind kind,
                                           uint64_t address, uint64_t size);

#endif
