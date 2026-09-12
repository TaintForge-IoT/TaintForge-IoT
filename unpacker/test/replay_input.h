#ifndef REPLAY_INPUT_H
#define REPLAY_INPUT_H

#include <stddef.h>
#include "aux_trace.h"
#include "replay_sources.h"

/* An owned, bounded snapshot of a selected trace and its observation point.
 * The caller must serialize capture with trace/aux/meta mutations; this API
 * does not pause vCPUs or make the existing collector thread-safe. After
 * capture, none of those owners are
 * needed to lift the saved instructions. This is not a full-trace archive.
 */
typedef struct ReplayInput ReplayInput;

typedef enum {
    REPLAY_INPUT_READY = 0,
    REPLAY_INPUT_UNKNOWN,
    REPLAY_INPUT_INVALID_REQUEST,
    REPLAY_INPUT_RESOURCE_LIMIT
} ReplayInputStatus;

enum {
    REPLAY_INPUT_ENTRY_MISSING = 1U << 0,
    REPLAY_INPUT_DESCRIPTOR_MISMATCH = 1U << 1,
    REPLAY_INPUT_META_MISSING = 1U << 2,
    REPLAY_INPUT_META_MISMATCH = 1U << 3,
    REPLAY_INPUT_AUX_MISSING = 1U << 4,
    REPLAY_INPUT_EXECUTION_PENDING = 1U << 5,
    REPLAY_INPUT_STRING_INVALID = 1U << 6,
    REPLAY_INPUT_VCPU_MISMATCH = 1U << 7
};

typedef struct {
    TraceEntry entry;
    InsnOccurrence occurrence;
    InsnDesc descriptor;
    bool descriptor_valid;
    uint32_t issues;
} ReplayStep;

/* seq_ids must be strictly increasing and precede trigger_seq_id. The trigger
 * is an observation point: its aux may still be execution_pending. Missing
 * records/state produce an inspectable UNKNOWN input, not invented values.
 * READY means capture succeeded; occurrence/aux validity and semantic coverage
 * still have to be checked by the consumer. Legacy entries with desc_id == 0
 * retain their bytes/meta and descriptor_valid == false.
 * max_bytes covers the owner, fixed records and copied REP payloads.
 */
ReplayInput *replay_input_capture(const TraceBuffer *trace, const DseAuxRing *aux,
                                  const uint64_t *seq_ids, uint32_t count, uint64_t trigger_seq_id,
                                  size_t max_bytes, ReplayInputStatus *status);
void replay_input_destroy(ReplayInput *input);
/* Optional transactional provenance capture. Use the SAME registry that
 * produced the aux labels, while serialized. Call before destroying that
 * registry. A failed capture publishes no partial source graph; the owned
 * concrete replay remains usable. A snapshot can be attached only once. */
ReplaySourceInfo replay_input_capture_sources(ReplayInput *input, ProvRegistry *registry,
                                              const ReplaySourceLimits *limits);
const ReplaySources *replay_input_sources(const ReplayInput *input);
ReplaySourceInfo replay_input_source_info(const ReplayInput *input);
uint32_t replay_input_count(const ReplayInput *input);
size_t replay_input_bytes(const ReplayInput *input);
uint32_t replay_input_issues(const ReplayInput *input);
const ReplayStep *replay_input_step(const ReplayInput *input, uint32_t index);
const ReplayStep *replay_input_trigger(const ReplayInput *input);
const ReplayStep *replay_input_find(const ReplayInput *input, uint64_t seq_id);

/* Transitional x86/DSE adapter. The full IR consumer will use the descriptor
 * and occurrence above; these owned legacy snapshots keep current replay
 * operational during that migration. No pointers into the live ring escape.
 */
const InsnAux *replay_input_aux(const ReplayInput *input, uint64_t seq_id);
const InsnMeta *replay_input_meta(const ReplayInput *input, uint64_t seq_id);

#endif
