#ifndef TAINTFORGE_IR_REPLAY_H
#define TAINTFORGE_IR_REPLAY_H

#include "ir_eval.h"
#include "ir_lift_x86.h"
#include "replay_input.h"
#include "ir_inputs.h"

typedef struct IrReplay IrReplay;
#define IR_PROC_EXE_API 1
#define IR_REPLAY_CHECKPOINT_REUSE_API 1
#define IR_PROC_EXE_INPUT_KEY UINT64_C(0x20000)
#define IR_REPLAY_STDIN_API 1
#define IR_STDIN_INPUT_KEY UINT64_C(0x20001)
#define IR_REPLAY_STDIN_MAX_READS 4U
#define IR_REPLAY_STDIN_MAX_READ 4096U
#define IR_REPLAY_STDIN_MAX_BYTES (IR_REPLAY_STDIN_MAX_READS * IR_REPLAY_STDIN_MAX_READ)
#define IR_REPLAY_STDIN_MAX_FILE (1024U * 1024U)

/* Explicit immutable regular-file stdin provider. This is a source relation
 * supplied by the caller, not inferred from provenance labels or guest RAM.
 * The caller must bind fd 0 identity, cursor and delivered bytes independently.
 * Reads start at file offset zero and advance consecutively. Each ledger item
 * must match the exact captured i386 INT 80 read boundary. All copy-in effects
 * execute chronologically, including overlapping guest buffers.
 * The provider is borrowed only during build; the replay owns the consumed
 * prefix and ledger after this call. Only consumed source offsets become IR
 * input cells. A retained/reused replay never dereferences these pointers. */
typedef struct {
    uint64_t seq;
    uint32_t address, offset, requested, returned;
} IrReplayStdinRead;
typedef struct {
    const uint8_t *bytes;
    uint32_t size, count;
    const IrReplayStdinRead *reads;
} IrReplayStdinSource;

typedef enum {
    IR_REPLAY_READY,
    IR_REPLAY_UNKNOWN,
    IR_REPLAY_INVALID,
    IR_REPLAY_RESOURCE_LIMIT,
    IR_REPLAY_OUT_OF_MEMORY
} IrReplayBuildStatus;

enum {
    IR_REPLAY_IDENTITY = 1U << 0,
    IR_REPLAY_MODE = 1U << 1,
    IR_REPLAY_GAP = 1U << 2,
    IR_REPLAY_UNSUPPORTED = 1U << 3,
    IR_REPLAY_PENDING = 1U << 4,
    IR_REPLAY_OBSERVATION_MISSING = 1U << 5,
    IR_REPLAY_OBSERVATION_SHAPE = 1U << 6,
    IR_REPLAY_CONTROL_MISMATCH = 1U << 7,
    IR_REPLAY_MEMORY_MODEL = 1U << 8,
    IR_REPLAY_BUDGET = 1U << 9,
    IR_REPLAY_INPUT_BUDGET = 1U << 10,
    IR_REPLAY_SYSCALL_OBSERVATION = 1U << 11,
    IR_REPLAY_SYSCALL_MODEL = 1U << 12
};

typedef struct {
    IrReplayBuildStatus status;
    uint32_t issues;
    uint32_t selected_steps, lifted_steps;
    uint64_t stopped_seq;
    IrOrigin stopped_origin; /* Also available after a fatal build/destroy. */
    IrBuildMetrics construction;
    IrBudgetFailure replay_budget; /* Replay-owned limits, distinct from module limits. */
    uint32_t observations, memory_bytes;
    uint32_t modeled_munmap;
    uint32_t modeled_mprotect;
    IrEnvironmentStats files;
    uint32_t modeled_readlink, readlink_bytes, executable_snapshot_bytes;
    uint32_t modeled_stdin_reads, stdin_bytes;
    const char *environment_reason; /* Static reason; never an owned pointer. */
    bool syscall_present;
    DseSyscallObservation stopped_syscall;
} IrReplayBuildInfo;

typedef struct {
    IrX86Options x86;
    IrLimits module;
    uint32_t max_steps;
    uint32_t max_observations;
    uint32_t max_memory_bytes;
    uint32_t max_repeat_iterations; /* Per REP occurrence; guarded exact trace count. */
    IrInputLimits inputs;
    bool capture_target; /* Project the exact trigger's pre-transfer destination. */
    /* Optional query predicate emitted at the trigger, after every prefix
     * effect/guard. It is an output, never a constraint on execution.
     * Requires capture_target; both equality and inequality can be queried. */
    bool compare_target;
    uint32_t target_candidate;
    /* Linux i386 INT 80 munmap only, 4 KiB pages, serialized execution and
     * fixed observed environment result. Argument changes stop at a GUARD.
     * Successful ranges stay inaccessible until an explicit modeled mapping. */
    bool observed_munmap;
    /* Successful Linux i386 INT 80 mprotect, 4 KiB pages, ordinary RAM with
     * explicit R/W/X permissions (no implicit EXEC or protection keys).
     * Only NONE, R, RW, RX, RWX are modeled. Errors remain UNKNOWN. */
    bool observed_mprotect;
    /* Serialized Linux i386 memfd/create/resize/map/write/close model, fixed
     * anonymous/shared remap, mmap2, MS_SYNC and provider-observed brk;
     * fixed observed syscall outcomes and arguments, symbolic buffer contents.
     * Requires flat32_ram; no external files, aliases or unobserved history. */
    bool observed_files;
    /* Explicit immutable /proc/self/exe provider; requires observed_files.
     * No arbitrary host path lookup or success inferred from an fd alone. */
    bool observed_proc_exe;
    uint32_t max_executable_bytes;
    uint32_t max_file_objects, max_file_content_cells;
    /* Opt-in one immutable regular stdin source, at most four serialized
     * read(0,buffer,1..4096) calls, fixed observed read geometry and outcomes.
     * Requires flat32_ram and a fragment starting at the first read. Source
     * bytes remain original MEM32 leaves; guest copy-in is never a new initial
     * RAM premise. No lseek, writes, pipes, sockets or mixed syscall models. */
    const IrReplayStdinSource *stdin_source;
} IrReplayOptions;

typedef enum {
    IR_REPLAY_GPR,
    IR_REPLAY_FLAG,
    IR_REPLAY_READ_ADDRESS,
    IR_REPLAY_READ_VALUE,
    IR_REPLAY_WRITE_ADDRESS,
    IR_REPLAY_WRITE_VALUE,
    IR_REPLAY_BRANCH_CONDITION,
    IR_REPLAY_TRANSFER_TARGET,
    IR_REPLAY_TLS_BASE
} IrReplayObservationKind;

typedef struct {
    IrReplayObservationKind kind;
    /* Exported BV1 CONST at this checkpoint, never a path constraint. A shared
     * value is observable only after this marker executes. Zero for non-state observations. */
    IrValueId reached;
    IrOrigin origin;
    IrValueId value;
    uint8_t width;
    uint32_t index; /* GPR/flag index, or index within the read/write observations. */
    bool expected_valid;
    uint64_t expected;
    /* ISA-undefined flag at this boundary: value is zero (no required
     * export). The semantic flag state is still UNKNOWN and can be read. */
    bool architectural_undefined;
    IrValueId defined_when; /* Optional BV1: false skips ISA-undefined flags. */
} IrReplayObservation;

typedef struct {
    IrX86LiftStatus status;
    IrValueId value;
    int gpr_index;
    IrBlockId boundary;
    IrValueId matches_candidate; /* BV1, only with options.compare_target. */
} IrReplayTarget;

typedef enum {
    IR_REPLAY_CHECK_MATCH,
    IR_REPLAY_CHECK_MISMATCH,
    IR_REPLAY_CHECK_UNKNOWN,
    IR_REPLAY_CHECK_ERROR
} IrReplayCheckStatus;

typedef struct {
    IrReplayCheckStatus status;
    IrEvalResult execution;
    uint32_t checked, mismatches, unknown, skipped_undefined;
    bool has_first_mismatch;
    IrReplayObservation first_mismatch;
    IrBits actual;
    size_t evaluator_bytes; /* Allocated capacity at end of this check. */
    bool candidate_requested;
    IrReplayCheckStatus candidate_status;
    IrBits candidate_actual;
} IrReplayCheckResult;

typedef struct {
    uint64_t trigger_seq;
    uint32_t gpr_index; /* IR_X86_GPR_* index, full 32-bit register. */
    uint32_t expected_target;
} IrReplayGprCandidate;

IrReplayOptions ir_replay_default_options(void);
/* Builds an owned, bounded fragment from selected steps, ending BEFORE trigger.
 * Only adjacent same-vCPU occurrences with verified semantic successors are
 * connected. Jcc needs an exact BranchEvent in the owned occurrence. LOOP
 * may also use an unambiguous next_pc (distinct taken/fallthrough addresses).
 * Coincident LOOP successors still require an explicit event. Other
 * Indirect transfers guard the computed destination before following an
 * observed adjacent occurrence. Unobserved conditional successors remain ADDRESS exits; following them evaluates to UNKNOWN.
 * Repeated PCs get distinct dynamic blocks, not an invented CFG merge.
 * A sparse slice/unsupported instruction ends in UNKNOWN, never
 * in an invented edge or a NOP. NULL means a fatal request/allocation/builder
 * failure; a non-NULL UNKNOWN result is valid IR and can be inspected.
 * Capture owners and ReplayInput may be destroyed after this call returns.
 * Flat memory must be enabled explicitly in options.x86.flat32_ram.
 * Post-state observations are exports for differential checks, not constraints
 * or constants in the semantic computation. They deliberately restrict DCE. */
IrReplay *ir_replay_x86_build(const ReplayInput *input, const IrReplayOptions *options,
                              IrReplayBuildInfo *info);
void ir_replay_destroy(IrReplay *replay);
IrModule *ir_replay_module(IrReplay *replay);
const IrX86State *ir_replay_state(const IrReplay *replay);
/* Zero unless an explicit stdin provider was accepted. Select source bytes by
 * this state and original file offset, never by overwritten guest addresses. */
IrStateId ir_replay_stdin_state(const IrReplay *replay);
const IrInputs *ir_replay_inputs(const IrReplay *replay);
IrInputInfo ir_replay_input_info(const IrReplay *replay);
/* Query the current module, never a cached ValueId map. Requires trace SSA
 * and an active initial READ_STATE. COPY/computed/dead values return NULL.
 * Returned state describes BV input slices or the sparse initial MEM domain.
 * Same module pointer survives SSA; catalogue InputIds do not change. */
const IrInputState *ir_replay_boundary_value(const IrReplay *replay, IrValueId value);
IrReplayBuildInfo ir_replay_info(const IrReplay *replay);
uint32_t ir_replay_observation_count(const IrReplay *replay);
/* Owned replay + module allocations. Excludes capture, frontend temporaries,
 * evaluator, allocator overhead and QEMU's own allocations. */
size_t ir_replay_allocated_bytes(const IrReplay *replay);
const IrReplayObservation *ir_replay_observation(const IrReplay *replay, uint32_t index);
/* Bindings use ONLY the first boundary register snapshot. Initial memory is
 * inferred from valid reads before any recorded write to each byte; post-store
 * observations never become initial memory. Unseen bytes are UNKNOWN. This
 * adapter is for replay validation; root/source-aware symbolic inputs follow.
 * The returned callbacks borrow replay. Callers can instead supply their own
 * immutable IrBindings to execute the same module with different inputs. */
IrBindings ir_replay_observed_bindings(IrReplay *replay);
/* A MATCH means this modeled fragment agrees with its saved observations.
 * It is not an OEP proof, a complete CFG, or full-program equivalence. */
IrReplayCheckResult ir_replay_check(IrReplay *replay, const IrEvalLimits *limits);
/* Also compare the computed register at the exact trigger boundary with the
 * observed destination. Does not execute the indirect transfer or prove OEP.
 * Incomplete/unreached/empty fragments cannot produce a candidate MATCH.
 * Caller must verify that the actual transfer uses this full register. */
IrReplayCheckResult ir_replay_check_gpr_candidate(IrReplay *replay, const IrEvalLimits *limits,
                                                  const IrReplayGprCandidate *candidate);
IrReplayTarget ir_replay_target(const IrReplay *replay);
/* Requires capture_target. Checks the projected exact trigger destination;
 * target reads are observations, while CALL/RET state updates are excluded. */
IrReplayCheckResult ir_replay_check_target(IrReplay *replay, const IrEvalLimits *limits,
                                           uint64_t trigger_seq, uint32_t expected_target);

#endif
