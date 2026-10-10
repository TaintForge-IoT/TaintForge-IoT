#ifndef TAINTFORGE_IR_CONCOLIC_H
#define TAINTFORGE_IR_CONCOLIC_H

#include "ir_branches.h"
#include "ir_replay.h"
#include "dcfg.h"
#include <stdio.h>

#define IR_CONCOLIC_MAX_BYTES 16U
#define IR_CONCOLIC_MAX_READ 4096U
#define IR_CONCOLIC_MAX_FILE (1024U * 1024U)

/* Exact bytes delivered by one completed read. Offsets are buffer-relative,
 * strictly increasing, and bounded by read_size. Other initial bytes remain
 * fixed. No provenance label is sufficient to construct this relation. */
typedef struct {
    uint64_t read_seq;
    uint32_t vcpu, address, read_size, count;
    uint32_t offsets[IR_CONCOLIC_MAX_BYTES];
    uint8_t bytes[IR_CONCOLIC_MAX_BYTES];
    bool completed_read, flags_verified;
} IrConcolicRead;

typedef struct {
    const char *status, *reason;
    uint32_t count;
    IrInputId inputs[IR_CONCOLIC_MAX_BYTES];
    uint8_t candidates[IR_CONCOLIC_MAX_BYTES];
    bool taken, target_known;
    uint64_t target;
    IrOrigin branch;
    uint32_t prefix_branches;
    char fixed_inputs_sha256[65];
} IrConcolicReadResult;

/* Unused bytes keep their observations and have input ID zero. The selected
 * branch is the final instruction. All returned arrays are owned by value. */
IrConcolicReadResult ir_concolic_read(const ReplayInput *input, const IrConcolicRead *source,
                                      bool solve, const IrInvertOptions *limits);

/* A collector-issued direct read relation, not a provenance label. The host
 * must separately pin fd 0 to offset zero of a one-byte regular file. */
typedef struct {
    uint64_t read_seq;
    uint32_t vcpu, address;
    uint8_t byte;
    bool completed_read, flags_verified;
} IrConcolicByte;

typedef struct {
    const char *status, *reason;
    IrInputId input;
    uint8_t candidate;
    bool taken, target_known;
    uint64_t target;
    IrOrigin branch;
    uint32_t prefix_branches;
    char fixed_inputs_sha256[65];
} IrConcolicResult;

/* The selected branch is the final selected instruction. No future suffix is
 * constrained. Returned values own no references into the capture or solver.
 * BOUNDARY_WITNESS still requires an external rerun; it never adds a DCFG edge. */
IrConcolicResult ir_concolic_byte(const ReplayInput *input, IrConcolicByte source, bool solve,
                                  const IrInvertOptions *limits);

typedef struct TfConcolic TfConcolic;
/* Optional concolic-* CLI. Disabled returns success with *out == NULL.
 * The report is created exclusively; existing results are never overwritten. */
bool tf_concolic_configure(TfConcolic **out, int argc, char **argv);
void tf_concolic_vcpu(TfConcolic *run, unsigned vcpu, unsigned previous_vcpus);
void tf_concolic_instruction(TfConcolic *run, const TraceBuffer *trace, const DseAuxRing *aux,
                             DcfgGraph *graph, uint64_t seq, bool flags_verified);
void tf_concolic_syscall(TfConcolic *run, const TraceBuffer *trace, uint64_t seq, unsigned vcpu,
                         int64_t number, uint64_t fd, uint64_t address, uint64_t count);
/* path is the complete guest string for open/openat, NULL otherwise. */
void tf_concolic_syscall_ex(TfConcolic *run, const TraceBuffer *trace, uint64_t seq, unsigned vcpu,
                            int64_t number, const uint64_t args[6], const char *path);
bool tf_concolic_read_span(const TfConcolic *run, int64_t returned, uint32_t *address,
                           uint32_t *size);
void tf_concolic_return_bytes(TfConcolic *run, unsigned vcpu, int64_t number, int64_t returned,
                              const uint8_t *bytes, uint32_t size);
bool tf_concolic_read_address(const TfConcolic *run, uint32_t *address);
void tf_concolic_return(TfConcolic *run, unsigned vcpu, int64_t number, int64_t returned,
                        bool byte_valid, uint8_t byte);
void tf_concolic_destroy(TfConcolic *run);
#endif
