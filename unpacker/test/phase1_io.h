#ifndef TAINTFORGE_PHASE1_IO_H
#define TAINTFORGE_PHASE1_IO_H

#include <glib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

/* Delivery I exports observations, never a restorable process checkpoint.
 * Regular-file transport has no reader backpressure. Storage latency and
 * protection from a hostile guest remain execution-backend responsibilities. */
typedef struct {
    bool enabled, storage_failed, profile_lost, finished, flags_required, analysis_incomplete;
    bool capture_at_entry;
    bool quiesced, retirement_enabled;
    char *session, *attempt, *instance;
    char *events_path, *manifest_path, *dump_path, *report_path, *ir_path;
    FILE *events;
    uint64_t event_seq, max_events, dropped_events, epoch, trace_seq, pc;
    uint64_t max_dump_bytes, selection_delay, max_candidates;
    uint64_t max_capture_bytes;
    uint32_t generation, vcpu;
    pid_t owner;
    const char *profile_reason;
} TfPhase1Io;

typedef struct {
    FILE *stream;
    char *temporary, *destination;
} TfAtomicFile;

bool tf_phase1_configure(TfPhase1Io *io, int argc, char **argv);
bool tf_phase1_start(TfPhase1Io *io, const char *target, bool system, unsigned plugin_api,
                     bool flags, bool ir_enabled);
bool tf_phase1_event(TfPhase1Io *io, const char *type, const char *status, const char *reason,
                     const char *payload);
void tf_phase1_profile_lost(TfPhase1Io *io, const char *reason);
bool tf_phase1_active(const TfPhase1Io *io);
bool tf_phase1_finish(TfPhase1Io *io, const char *capture_status);
void tf_phase1_destroy(TfPhase1Io *io);
char *tf_json_string(const char *utf8);
char *tf_json_bytes_field(const char *key, const char *bytes);
bool tf_atomic_open(TfAtomicFile *file, const char *destination);
bool tf_atomic_commit(TfAtomicFile *file);
void tf_atomic_abort(TfAtomicFile *file);
bool tf_write_all(FILE *stream, const void *bytes, size_t count);
bool tf_file_digest(const char *path, char digest[65], uint64_t *size);

#endif
