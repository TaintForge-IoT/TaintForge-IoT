#define _POSIX_C_SOURCE 200809L
#include "ir_concolic.h"
#include "ir_opt.h"
#include "ir_ssa.h"
#include <errno.h>
#include <glib.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CONCOLIC_MAX_STEPS 1024U
#define CONCOLIC_MAX_SYSCALLS 32U

typedef struct {
    uint64_t seq;
    uint32_t number, args[6], result;
    bool returned;
} ConcolicSyscall;

static IrConcolicReadResult unknown(const char *reason) {
    return (IrConcolicReadResult){.status = "UNKNOWN", .reason = reason};
}

/* The inversion policy is shared by post-read and chronological-source replay.
 * Only the selected catalogue cells vary; every other boundary cell stays fixed. */
static IrConcolicReadResult invert_replay(const ReplayInput *input, IrReplay *replay,
                                          IrReplayBuildInfo build,
                                          const IrConcolicRead *source,
                                          IrStateId source_state, bool solve,
                                          const IrInvertOptions *limits) {
    IrConcolicReadResult out;
    IrBranches *branches = NULL;
    IrInvertResult inverted = {.status = IR_INVERT_UNKNOWN};
    uint32_t count = replay_input_count(input);
    const ReplayStep *last = count ? replay_input_step(input, count - 1) : NULL;
    IrInputId ids[IR_CONCOLIC_MAX_BYTES] = {0}, symbolic[IR_CONCOLIC_MAX_BYTES] = {0};
    uint32_t symbolic_count = 0;
    out = unknown("replay_incomplete");
    if (!replay || build.status != IR_REPLAY_READY || build.lifted_steps != count)
        goto done;
    out = unknown("baseline_observations");
    if (ir_replay_check(replay, NULL).status != IR_REPLAY_CHECK_MATCH)
        goto done;
    const IrInputs *inputs = ir_replay_inputs(replay);
    for (uint32_t i = 0; i < source->count; ++i) {
        IrInputId id = ir_inputs_find_byte(inputs, source_state,
                                           source->address + source->offsets[i]);
        const IrInputCell *cell = ir_inputs_cell(inputs, id);
        /* An unused/overwritten byte has no boundary cell. Keep it fixed.
         * Missing observations on a used byte already fail the checker. */
        if (!cell)
            continue;
        out = unknown("direct_byte_not_in_boundary");
        if (cell->kind != IR_INPUT_MEMORY_BYTE || cell->width != 8 ||
            !ir_bits_complete(cell->observed, 8) || cell->observed.value != source->bytes[i])
            goto done;
        ids[i] = id;
        symbolic[symbolic_count++] = id;
    }
    out = unknown("direct_byte_not_in_boundary");
    if (!symbolic_count)
        goto done;
    out = unknown("ssa_or_optimization_limit");
    IrModule *module = ir_replay_module(replay);
    if (ir_trace_ssa(module, NULL).analysis.status != IR_OK ||
        ir_optimize(module, NULL).status != IR_OK)
        goto done;
    branches = ir_branches_build(module, inputs, NULL, NULL);
    out = unknown("branch_identity_or_evidence");
    if (!branches)
        goto done;
    IrOrigin origin = {.has_trace_identity = true,
                       .seq_id = last->entry.seq_id,
                       .pc = last->entry.pc,
                       .code_generation = last->entry.code_generation,
                       .descriptor_id = last->entry.insn_desc_id,
                       .vcpu_id = last->entry.vcpu_index};
    IrBranchId selected = ir_branches_find(branches, origin);
    const IrBranch *branch = ir_branches_at(branches, selected);
    if (!branch || !branch->has_observation || branch->issues)
        goto done;
    out = (IrConcolicReadResult){.status = "OBSERVED",
                                 .reason = "exact_branch_observation",
                                 .count = source->count,
                                 .branch = branch->origin,
                                 .taken = branch->observed_taken,
                                 .target_known = true,
                                 .target = branch->observed_target};
    memcpy(out.inputs, ids, sizeof(ids));
    memcpy(out.candidates, source->bytes, source->count);
    GChecksum *fixed = g_checksum_new(G_CHECKSUM_SHA256);
    if (!fixed) {
        out = unknown("allocation_limit");
        goto done;
    }
    for (IrInputId current = 1; current <= ir_inputs_info(inputs).count; ++current) {
        bool selected_input = false;
        for (uint32_t i = 0; i < symbolic_count; ++i)
            selected_input |= symbolic[i] == current;
        if (selected_input)
            continue;
        const IrInputCell *c = ir_inputs_cell(inputs, current);
        char text[256];
        int length =
            snprintf(text, sizeof(text), "%u:%u:%u:%" PRIu64 ":%u:%u:%" PRIu64 ":%" PRIu64 "\n",
                     current, c->kind, c->state, c->address, c->bit_offset, c->width,
                     c->observed.known_mask, c->observed.value & c->observed.known_mask);
        g_checksum_update(fixed, (const guchar *)text, (gssize)length);
    }
    memcpy(out.fixed_inputs_sha256, g_checksum_get_string(fixed), 65);
    g_checksum_free(fixed);
    if (!solve)
        goto done;
    IrInvertOptions invert_options = limits ? *limits : ir_invert_default_options();
    invert_options.smt.symbolic_inputs = symbolic;
    invert_options.smt.symbolic_count = symbolic_count;
    invert_options.smt.parameters = NULL;
    invert_options.smt.parameter_count = 0;
    inverted = ir_branch_invert(branches, selected, &invert_options);
    out.status = "UNKNOWN";
    out.reason = "inversion_incomplete";
    if (inverted.status == IR_INVERT_RESOURCE_LIMIT || inverted.status == IR_INVERT_OUT_OF_MEMORY)
        out.reason = "inversion_resource_limit";
    else if (inverted.status == IR_INVERT_MISMATCH)
        out.reason = "inversion_evaluation_mismatch";
    if (inverted.status == IR_INVERT_UNSAT) {
        out.status = "UNSAT";
        out.reason = "no_witness_in_selected_model";
    } else if (inverted.status == IR_INVERT_VERIFIED &&
               inverted.model.input_count == symbolic_count) {
        bool assigned[IR_CONCOLIC_MAX_BYTES] = {false}, changed = false;
        for (uint32_t j = 0; j < inverted.model.input_count; ++j) {
            const IrInputAssignment *assignment = &inverted.model.inputs[j];
            uint32_t i = 0;
            while (i < source->count && (!ids[i] || ids[i] != assignment->input))
                ++i;
            if (i == source->count || assigned[i] || !ir_bits_complete(assignment->bits, 8) ||
                assignment->bits.value > UINT8_MAX)
                goto done;
            assigned[i] = true;
            out.candidates[i] = (uint8_t)assignment->bits.value;
            changed |= out.candidates[i] != source->bytes[i];
        }
        if (!changed)
            goto done;
        out.status = "BOUNDARY_WITNESS";
        out.reason = "external_replay_required";
        out.prefix_branches = inverted.prefix_count;
        out.target_known = inverted.candidate.target_known;
        out.target = inverted.candidate.target_address;
    }

done:
    ir_invert_result_destroy(&inverted);
    ir_branches_destroy(branches);
    ir_replay_destroy(replay);
    return out;
}

IrConcolicReadResult ir_concolic_read(const ReplayInput *input, const IrConcolicRead *source,
                                      bool solve, const IrInvertOptions *limits) {
    IrConcolicReadResult out = unknown("direct_read_evidence_missing");
    uint32_t count = replay_input_count(input);
    if (!source || !source->completed_read || !source->read_seq || source->read_seq == UINT64_MAX ||
        !count || count > CONCOLIC_MAX_STEPS || !source->count ||
        source->count > IR_CONCOLIC_MAX_BYTES || !source->read_size ||
        source->read_size > IR_CONCOLIC_MAX_READ ||
        (uint64_t)source->address + source->read_size > (UINT64_C(1) << 32))
        return out;
    for (uint32_t i = 0; i < source->count; ++i) {
        if (source->offsets[i] >= source->read_size ||
            (i && source->offsets[i] <= source->offsets[i - 1]))
            return unknown("invalid_byte_selection");
    }
    if (!source->flags_verified)
        return unknown("flag_observations_unverified");
    const ReplayStep *first = replay_input_step(input, 0);
    const ReplayStep *last = replay_input_step(input, count - 1);
    if (first->entry.seq_id != source->read_seq + 1 || first->entry.vcpu_index != source->vcpu ||
        last->entry.vcpu_index != source->vcpu)
        return unknown("read_boundary_identity");
    IrReplayOptions options = ir_replay_default_options();
    options.x86.flat32_ram = true;
    options.max_steps = CONCOLIC_MAX_STEPS;
    IrReplayBuildInfo build;
    IrReplay *replay = ir_replay_x86_build(input, &options, &build);
    IrStateId state = replay ? ir_replay_state(replay)->memory : 0;
    return invert_replay(input, replay, build, source, state, solve, limits);
}

IrConcolicReadResult ir_concolic_stdin_sequence(const ReplayInput *input,
                                                const IrConcolicSequence *source,
                                                bool solve, const IrInvertOptions *limits) {
    if (!source || !source->flags_verified)
        return unknown("flag_observations_unverified");
    const IrReplayStdinSource *file = &source->source;
    uint32_t count = replay_input_count(input);
    if (!count || count > CONCOLIC_MAX_STEPS || !source->count ||
        source->count > IR_CONCOLIC_MAX_BYTES || !file->bytes || !file->size ||
        file->size > IR_CONCOLIC_MAX_FILE || !file->reads || !file->count ||
        file->count > IR_CONCOLIC_MAX_READS)
        return unknown("stdin_sequence_evidence_missing");
    const ReplayStep *first = replay_input_step(input, 0);
    const ReplayStep *last = replay_input_step(input, count - 1);
    if (!file->reads[0].seq || first->entry.seq_id != file->reads[0].seq ||
        first->entry.vcpu_index || last->entry.vcpu_index)
        return unknown("read_boundary_identity");
    uint64_t delivered = 0;
    for (uint32_t i = 0; i < file->count; ++i) {
        const IrReplayStdinRead *read = &file->reads[i];
        if (read->offset != delivered || read->returned > read->requested ||
            !read->requested || read->requested > IR_CONCOLIC_MAX_READ ||
            (uint64_t)read->offset + read->returned > file->size)
            return unknown("stdin_sequence_evidence_missing");
        delivered += read->returned;
    }
    IrConcolicRead selection = {.count = source->count};
    for (uint32_t i = 0; i < source->count; ++i) {
        uint32_t offset = source->offsets[i];
        if (offset >= delivered || (i && offset <= source->offsets[i - 1]))
            return unknown("mutable_byte_not_read");
        selection.offsets[i] = offset;
        selection.bytes[i] = file->bytes[offset];
    }
    IrReplayOptions options = ir_replay_default_options();
    options.x86.flat32_ram = true;
    options.max_steps = CONCOLIC_MAX_STEPS;
    options.stdin_source = file;
    IrReplayBuildInfo build;
    IrReplay *replay = ir_replay_x86_build(input, &options, &build);
    IrStateId state = replay ? ir_replay_stdin_state(replay) : 0;
    return invert_replay(input, replay, build, &selection, state, solve, limits);
}

IrConcolicResult ir_concolic_byte(const ReplayInput *input, IrConcolicByte source, bool solve,
                                  const IrInvertOptions *limits) {
    IrConcolicRead bytes = {.read_seq = source.read_seq,
                            .vcpu = source.vcpu,
                            .address = source.address,
                            .read_size = 1,
                            .count = 1,
                            .bytes = {source.byte},
                            .completed_read = source.completed_read,
                            .flags_verified = source.flags_verified};
    IrConcolicReadResult r = ir_concolic_read(input, &bytes, solve, limits);
    IrConcolicResult out = {.status = r.status,
                            .reason = r.reason,
                            .input = r.inputs[0],
                            .candidate = r.candidates[0],
                            .taken = r.taken,
                            .target_known = r.target_known,
                            .target = r.target,
                            .branch = r.branch,
                            .prefix_branches = r.prefix_branches};
    memcpy(out.fixed_inputs_sha256, r.fixed_inputs_sha256, sizeof(out.fixed_inputs_sha256));
    return out;
}

struct TfConcolic {
    FILE *report;
    uint32_t pc, occurrence, seen, max_steps, instructions;
    uint64_t first_seq, selected_seq;
    uint8_t expected;
    bool solve, pending, armed, finished;
    const char *failure;
    IrConcolicByte source;
    char *guest_file;
    uint8_t *file_bytes;
    uint32_t file_size, file_offsets[IR_CONCOLIC_MAX_BYTES], byte_count;
    char file_sha256[65];
    dev_t file_device;
    ino_t file_inode;
    bool opened, stdin_span, stdin_sequence;
    IrReplayStdinRead reads[IR_CONCOLIC_MAX_READS];
    uint32_t read_count;
    uint32_t fd, cursor, read_offset, requested;
    IrConcolicRead read;
    ConcolicSyscall syscalls[CONCOLIC_MAX_SYSCALLS];
    uint32_t syscall_count;
};

static void fail(TfConcolic *run, const char *reason) {
    if (run && !run->finished && !run->failure)
        run->failure = reason;
}

static bool number(const char *text, uint32_t maximum, uint32_t *out) {
    if (!text || !*text || *text == '+' || *text == '-' || *text == ' ' || *text == '\t')
        return false;
    errno = 0;
    char *end;
    unsigned long value = strtoul(text, &end, 0);
    if (errno || *end || value > maximum)
        return false;
    *out = (uint32_t)value;
    return true;
}

static bool guest_path_valid(const char *path) {
    if (!path || path[0] != '/' || !path[1] || strlen(path) > 1024)
        return false;
    const char *component = path + 1;
    for (const char *p = component;; ++p) {
        if (*p && ((unsigned char)*p < 32 || (unsigned char)*p > 126 || *p == ','))
            return false;
        if (*p && *p != '/')
            continue;
        size_t size = (size_t)(p - component);
        if (!size || (size == 1 && component[0] == '.') ||
            (size == 2 && component[0] == '.' && component[1] == '.'))
            return false;
        if (!*p)
            return true;
        component = p + 1;
    }
}

static bool seed_options(TfConcolic *run, const char *seed, const char *offsets) {
    if (!seed || !*seed || !offsets || !*offsets)
        return false;
    FILE *f = fopen(seed, "rb");
    if (!f)
        return false;
    struct stat st;
    bool ok = !fstat(fileno(f), &st) && S_ISREG(st.st_mode) && st.st_size > 0 &&
              st.st_size <= IR_CONCOLIC_MAX_FILE;
    if (ok) {
        run->file_size = (uint32_t)st.st_size;
        run->file_device = st.st_dev;
        run->file_inode = st.st_ino;
        run->file_bytes = malloc(run->file_size);
        ok = run->file_bytes &&
             fread(run->file_bytes, 1, run->file_size, f) == run->file_size && fgetc(f) == EOF &&
             !ferror(f);
    }
    if (fclose(f))
        ok = false;
    for (const char *p = offsets; ok && *p;) {
        const char *end = strchr(p, ':');
        size_t size = end ? (size_t)(end - p) : strlen(p);
        char text[32];
        uint32_t offset;
        if (!size || size >= sizeof(text) || run->byte_count == IR_CONCOLIC_MAX_BYTES) {
            ok = false;
            break;
        }
        memcpy(text, p, size);
        text[size] = 0;
        if (!number(text, run->file_size - 1, &offset) ||
            (run->byte_count && offset <= run->file_offsets[run->byte_count - 1])) {
            ok = false;
            break;
        }
        run->file_offsets[run->byte_count++] = offset;
        if (!end)
            break;
        p = end + 1;
        if (!*p)
            ok = false;
    }
    if (ok) {
        GChecksum *sum = g_checksum_new(G_CHECKSUM_SHA256);
        if (!sum)
            return false;
        g_checksum_update(sum, run->file_bytes, run->file_size);
        memcpy(run->file_sha256, g_checksum_get_string(sum), 65);
        g_checksum_free(sum);
    }
    return ok;
}

static bool file_options(TfConcolic *run, const char *guest, const char *seed,
                         const char *offsets) {
    if (!guest_path_valid(guest) || !seed_options(run, seed, offsets))
        return false;
    run->guest_file = strdup(guest);
    return run->guest_file != NULL;
}

/* This is a direct host-fd relation for serialized Linux-user execution.
 * A seed path or provenance label alone does not identify the guest input. */
static bool stdin_identity(const TfConcolic *run, off_t position) {
    struct stat st;
    return !fstat(STDIN_FILENO, &st) && S_ISREG(st.st_mode) &&
           st.st_dev == run->file_device && st.st_ino == run->file_inode &&
           st.st_size == run->file_size && lseek(STDIN_FILENO, 0, SEEK_CUR) == position;
}

bool tf_concolic_configure(TfConcolic **out, int argc, char **argv) {
    if (!out)
        return false;
    *out = NULL;
    TfConcolic options = {.occurrence = 1, .max_steps = 256, .solve = true};
    const char *path = NULL;
    const char *guest_file = NULL, *seed = NULL, *offsets = NULL, *stdin_seed = NULL,
               *stdin_sequence_seed = NULL;
    unsigned fields = 0;
    for (int i = 0; i < argc; ++i) {
        if (strncmp(argv[i], "concolic-", 9))
            continue;
        const char *eq = strchr(argv[i], '=');
        if (!eq)
            return false;
        size_t key = (size_t)(eq - argv[i]);
        const char *value = eq + 1;
        unsigned field = 0;
        uint32_t n;
#define OPTION(s) (key == sizeof(s) - 1 && !memcmp(argv[i], s, key))
        if (OPTION("concolic-report")) {
            field = 1;
            if (!*value)
                return false;
            path = value;
        } else if (OPTION("concolic-branch")) {
            field = 2;
            if (!number(value, UINT32_MAX, &options.pc))
                return false;
        } else if (OPTION("concolic-byte")) {
            field = 4;
            if (!number(value, UINT8_MAX, &n))
                return false;
            options.expected = (uint8_t)n;
        } else if (OPTION("concolic-mode")) {
            field = 8;
            if (strcmp(value, "solve") && strcmp(value, "observe"))
                return false;
            options.solve = !strcmp(value, "solve");
        } else if (OPTION("concolic-occurrence")) {
            field = 16;
            if (!number(value, CONCOLIC_MAX_STEPS, &options.occurrence) || !options.occurrence)
                return false;
        } else if (OPTION("concolic-max-steps")) {
            field = 32;
            if (!number(value, CONCOLIC_MAX_STEPS, &options.max_steps) || !options.max_steps)
                return false;
        } else if (OPTION("concolic-file")) {
            field = 64;
            guest_file = value;
        } else if (OPTION("concolic-seed")) {
            field = 128;
            seed = value;
        } else if (OPTION("concolic-offsets")) {
            field = 256;
            offsets = value;
        } else if (OPTION("concolic-stdin")) {
            field = 512;
            stdin_seed = value;
        } else if (OPTION("concolic-stdin-reads")) {
            field = 1024;
            stdin_sequence_seed = value;
        } else
            return false;
#undef OPTION
        if (fields & field)
            return false;
        fields |= field;
    }
    if (!fields)
        return true;
    unsigned file_fields = fields & (64 | 128);
    bool stdin_span = (fields & 512) != 0;
    bool stdin_sequence = (fields & 1024) != 0;
    if ((fields & 3) != 3 || (stdin_span && stdin_sequence) ||
        (stdin_span || stdin_sequence ? !(fields & 256) || file_fields || (fields & 4)
                    : file_fields ? file_fields != (64 | 128) || !(fields & 256) || (fields & 4)
                                  : !(fields & 4) || (fields & 256)))
        return false;
    TfConcolic *run = calloc(1, sizeof(*run));
    if (!run)
        return false;
    *run = options;
    run->stdin_span = stdin_span;
    run->stdin_sequence = stdin_sequence;
    if ((file_fields && !file_options(run, guest_file, seed, offsets)) ||
        (stdin_span && !seed_options(run, stdin_seed, offsets)) ||
        (stdin_sequence && !seed_options(run, stdin_sequence_seed, offsets))) {
        free(run->guest_file);
        free(run->file_bytes);
        free(run);
        return false;
    }
    run->report = fopen(path, "wx");
    if (!run->report) {
        free(run->guest_file);
        free(run->file_bytes);
        free(run);
        return false;
    }
    *out = run;
    return true;
}

void tf_concolic_vcpu(TfConcolic *run, unsigned vcpu, unsigned previous_vcpus) {
    if (vcpu || previous_vcpus)
        fail(run, "multiple_vcpus");
}

void tf_concolic_syscall(TfConcolic *run, const TraceBuffer *trace, uint64_t seq, unsigned vcpu,
                         int64_t num, uint64_t fd, uint64_t address, uint64_t count) {
    if (!run || run->finished || run->failure)
        return;
    const TraceEntry *entry = trace_find_seq(trace, seq, NULL);
    if (run->stdin_span || run->stdin_sequence || run->pending || run->armed || run->source.completed_read || num != 3 || fd != 0 ||
        count != 1 || address > UINT32_MAX || vcpu != 0 || !seq || !entry ||
        entry->vcpu_index != vcpu || entry->size != 2 || entry->instr_bytes[0] != 0xcd ||
        entry->instr_bytes[1] != 0x80) {
        fail(run, "unsupported_syscall_prefix");
        return;
    }
    run->source = (IrConcolicByte){.read_seq = seq, .vcpu = vcpu, .address = (uint32_t)address};
    run->pending = true;
}

bool tf_concolic_read_address(const TfConcolic *run, uint32_t *address) {
    if (!run || run->failure || !run->pending || run->finished)
        return false;
    *address = run->source.address;
    return true;
}

void tf_concolic_return(TfConcolic *run, unsigned vcpu, int64_t num, int64_t returned, bool valid,
                        uint8_t byte) {
    if (!run || run->finished || run->failure)
        return;
    if (!run->pending || vcpu != run->source.vcpu || num != 3 || returned != 1 || !valid ||
        byte != run->expected) {
        fail(run, "input_read_mismatch");
        return;
    }
    run->source.byte = byte;
    run->source.completed_read = true;
    run->pending = false;
    run->armed = true;
}

void tf_concolic_syscall_ex(TfConcolic *run, const TraceBuffer *trace, uint64_t seq, unsigned vcpu,
                            int64_t num, const uint64_t args[6], const char *path) {
    if (!run || run->finished || run->failure)
        return;
    if (!args) {
        fail(run, "syscall_arguments_missing");
        return;
    }
    if (run->stdin_sequence) {
        const TraceEntry *entry = trace_find_seq(trace, seq, NULL);
        if (run->pending || num != 3 || args[0] != 0 || !args[2] ||
            args[2] > IR_CONCOLIC_MAX_READ || args[1] > UINT32_MAX ||
            args[1] + args[2] > (UINT64_C(1) << 32) || vcpu || !seq || !entry ||
            entry->vcpu_index || entry->size != 2 || entry->instr_bytes[0] != 0xcd ||
            entry->instr_bytes[1] != 0x80) {
            fail(run, "unsupported_syscall_prefix");
            return;
        }
        if (run->read_count == IR_CONCOLIC_MAX_READS) {
            fail(run, "stdin_read_budget");
            return;
        }
        if (!stdin_identity(run, (off_t)run->cursor)) {
            fail(run, "stdin_resource_identity");
            return;
        }
        if (!run->source.read_seq)
            run->source.read_seq = seq;
        run->source.address = (uint32_t)args[1];
        run->requested = (uint32_t)args[2];
        run->read_offset = run->cursor;
        run->fd = 0;
        ConcolicSyscall *event = &run->syscalls[run->syscall_count++];
        *event = (ConcolicSyscall){.seq = seq, .number = 3};
        for (unsigned i = 0; i < 6; ++i)
            event->args[i] = (uint32_t)args[i];
        run->pending = true;
        return;
    }
    if (run->stdin_span) {
        const TraceEntry *entry = trace_find_seq(trace, seq, NULL);
        if (run->pending || run->armed || run->source.completed_read || run->syscall_count ||
            num != 3 || args[0] != 0 || !args[2] || args[2] > IR_CONCOLIC_MAX_READ ||
            args[1] > UINT32_MAX || args[1] + args[2] > (UINT64_C(1) << 32) || vcpu ||
            !seq || !entry || entry->vcpu_index || entry->size != 2 ||
            entry->instr_bytes[0] != 0xcd || entry->instr_bytes[1] != 0x80) {
            fail(run, "unsupported_syscall_prefix");
            return;
        }
        if (!stdin_identity(run, 0)) {
            fail(run, "stdin_resource_identity");
            return;
        }
        run->source = (IrConcolicByte){.read_seq = seq, .vcpu = vcpu,
                                       .address = (uint32_t)args[1]};
        run->requested = (uint32_t)args[2];
        run->fd = 0;
        run->read_offset = 0;
        ConcolicSyscall *event = &run->syscalls[run->syscall_count++];
        *event = (ConcolicSyscall){.seq = seq, .number = (uint32_t)num};
        for (unsigned i = 0; i < 6; ++i)
            event->args[i] = (uint32_t)args[i];
        run->pending = true;
        return;
    }
    if (!run->guest_file) {
        tf_concolic_syscall(run, trace, seq, vcpu, num, args[0], args[1], args[2]);
        return;
    }
    const TraceEntry *entry = trace_find_seq(trace, seq, NULL);
    if (run->pending || run->armed || vcpu || !seq || !entry || entry->vcpu_index ||
        entry->size != 2 || entry->instr_bytes[0] != 0xcd || entry->instr_bytes[1] != 0x80) {
        fail(run, "unsupported_syscall_prefix");
        return;
    }
    if (run->syscall_count == CONCOLIC_MAX_SYSCALLS) {
        fail(run, "syscall_budget");
        return;
    }
    if (num == 5 || num == 295) {
        uint32_t flags = (uint32_t)args[num == 5 ? 1 : 2];
        if (!path || strcmp(path, run->guest_file) || run->opened || (flags & ~UINT32_C(0x88000)) ||
            (num == 295 && (uint32_t)args[0] != (uint32_t)-100)) {
            fail(run, "file_open_contract");
            return;
        }
    } else if (num == 3 || num == 6 || num == 19) {
        if (!run->opened || (uint32_t)args[0] != run->fd) {
            fail(run, "file_descriptor_identity");
            return;
        }
        if (num == 3) {
            if (!args[2] || args[2] > IR_CONCOLIC_MAX_READ || args[1] > UINT32_MAX ||
                args[1] + args[2] > (UINT64_C(1) << 32)) {
                fail(run, "file_read_budget_or_range");
                return;
            }
            run->source.read_seq = seq;
            run->source.address = (uint32_t)args[1];
            run->requested = (uint32_t)args[2];
            run->read_offset = run->cursor;
        } else if (num == 19 && args[2] > 2) {
            fail(run, "file_seek_contract");
            return;
        }
    } else {
        fail(run, "unsupported_syscall_prefix");
        return;
    }
    ConcolicSyscall *event = &run->syscalls[run->syscall_count++];
    *event = (ConcolicSyscall){.seq = seq, .number = (uint32_t)num};
    for (unsigned i = 0; i < 6; ++i)
        event->args[i] = (uint32_t)args[i];
    run->pending = true;
}

bool tf_concolic_read_span(const TfConcolic *run, int64_t returned, uint32_t *address,
                           uint32_t *size) {
    if (!run || run->failure || run->finished || !run->pending || !address || !size ||
        returned <= 0 || returned > IR_CONCOLIC_MAX_READ)
        return false;
    if (run->guest_file || run->stdin_span || run->stdin_sequence) {
        if (!run->syscall_count || run->syscalls[run->syscall_count - 1].number != 3 ||
            (uint64_t)returned > run->requested)
            return false;
    } else if (returned != 1)
        return false;
    *address = run->source.address;
    *size = (uint32_t)returned;
    return true;
}

void tf_concolic_return_bytes(TfConcolic *run, unsigned vcpu, int64_t num, int64_t returned,
                              const uint8_t *bytes, uint32_t size) {
    if (!run || run->finished || run->failure)
        return;
    if (run->stdin_sequence) {
        if (!run->pending || !run->syscall_count || vcpu || num != 3 ||
            run->syscall_count != run->read_count + 1 ||
            run->syscalls[run->syscall_count - 1].number != 3 ||
            run->syscalls[run->syscall_count - 1].returned) {
            fail(run, "syscall_return_identity");
            return;
        }
        ConcolicSyscall *event = &run->syscalls[run->syscall_count - 1];
        event->result = (uint32_t)returned;
        event->returned = true;
        run->pending = false;
        if (returned < 0 || returned > run->requested || returned > IR_CONCOLIC_MAX_READ ||
            (uint64_t)run->cursor + (uint64_t)returned > run->file_size ||
            size != (uint64_t)returned || (size && (!bytes ||
            memcmp(bytes, run->file_bytes + run->cursor, size)))) {
            fail(run, "input_read_mismatch");
            return;
        }
        if (!stdin_identity(run, (off_t)((uint64_t)run->cursor + size))) {
            fail(run, "stdin_resource_identity");
            return;
        }
        run->reads[run->read_count++] = (IrReplayStdinRead){
            .seq = event->seq, .address = run->source.address, .offset = run->cursor,
            .requested = run->requested, .returned = size};
        run->cursor += size;
        run->source.completed_read = true;
        run->armed = true;
        return;
    }
    if (run->stdin_span) {
        if (!run->pending || run->syscall_count != 1 || vcpu || num != 3 ||
            run->syscalls[0].number != 3 || run->syscalls[0].returned) {
            fail(run, "syscall_return_identity");
            return;
        }
        ConcolicSyscall *event = &run->syscalls[0];
        event->result = (uint32_t)returned;
        event->returned = true;
        run->pending = false;
        if (returned <= 0 || returned > run->requested || returned > IR_CONCOLIC_MAX_READ ||
            (uint64_t)returned > run->file_size || size != (uint64_t)returned || !bytes ||
            memcmp(bytes, run->file_bytes, size)) {
            fail(run, "input_read_mismatch");
            return;
        }
        if (!stdin_identity(run, (off_t)returned)) {
            fail(run, "stdin_resource_identity");
            return;
        }
        run->read = (IrConcolicRead){.read_seq = event->seq,
                                     .address = run->source.address,
                                     .read_size = size,
                                     .count = run->byte_count,
                                     .completed_read = true};
        for (uint32_t i = 0; i < run->byte_count; ++i) {
            uint32_t offset = run->file_offsets[i];
            if (offset >= size) {
                fail(run, "mutable_byte_not_read");
                return;
            }
            run->read.offsets[i] = offset;
            run->read.bytes[i] = run->file_bytes[offset];
        }
        run->cursor = size;
        run->source.completed_read = true;
        run->armed = true;
        return;
    }
    if (!run->guest_file) {
        tf_concolic_return(run, vcpu, num, returned, bytes && size == 1,
                           bytes && size == 1 ? bytes[0] : 0);
        return;
    }
    if (!run->pending || !run->syscall_count || vcpu ||
        run->syscalls[run->syscall_count - 1].number != num) {
        fail(run, "syscall_return_identity");
        return;
    }
    ConcolicSyscall *event = &run->syscalls[run->syscall_count - 1];
    event->result = (uint32_t)returned;
    event->returned = true;
    run->pending = false;
    if (returned < 0 || returned > INT32_MAX) {
        fail(run, "file_syscall_failed");
        return;
    }
    if (num == 5 || num == 295) {
        struct stat st;
        if (fstat((int)returned, &st) || !S_ISREG(st.st_mode) || st.st_dev != run->file_device ||
            st.st_ino != run->file_inode || st.st_size != run->file_size) {
            fail(run, "file_resource_identity");
            return;
        }
        run->opened = true;
        run->fd = (uint32_t)returned;
        run->cursor = 0;
    } else if (num == 6) {
        if (returned != 0) {
            fail(run, "file_close_contract");
            return;
        }
        run->opened = false;
    } else if (num == 19) {
        int64_t base = event->args[2] == 0 ? 0 : event->args[2] == 1 ? run->cursor : run->file_size;
        int64_t expected = base + (int32_t)event->args[1];
        if (expected < 0 || expected > INT32_MAX || returned != expected) {
            fail(run, "file_seek_mismatch");
            return;
        }
        run->cursor = (uint32_t)returned;
    } else if (num == 3) {
        if (!bytes || !size || size != (uint64_t)returned || size > run->requested ||
            size > IR_CONCOLIC_MAX_READ || (uint64_t)run->cursor + size > run->file_size ||
            memcmp(bytes, run->file_bytes + run->cursor, size)) {
            fail(run, "input_read_mismatch");
            return;
        }
        run->read = (IrConcolicRead){.read_seq = event->seq,
                                     .address = run->source.address,
                                     .read_size = size,
                                     .count = run->byte_count,
                                     .completed_read = true};
        for (uint32_t i = 0; i < run->byte_count; ++i) {
            uint32_t offset = run->file_offsets[i];
            if (offset < run->cursor || (uint64_t)offset >= (uint64_t)run->cursor + size) {
                fail(run, "mutable_byte_not_read");
                return;
            }
            run->read.offsets[i] = offset - run->cursor;
            run->read.bytes[i] = run->file_bytes[offset];
        }
        run->cursor += size;
        run->source.completed_read = true;
        run->armed = true;
    }
}

static void entry_json(FILE *f, const TraceEntry *entry) {
    fprintf(f,
            "{\"pc\":%" PRIu64 ",\"seq\":%" PRIu64 ",\"vcpu\":%u,"
            "\"generation\":%u,\"descriptor\":%" PRIu64 ",\"bytes\":\"",
            entry->pc, entry->seq_id, entry->vcpu_index, entry->code_generation,
            (uint64_t)entry->insn_desc_id);
    for (unsigned i = 0; i < entry->size; ++i)
        fprintf(f, "%02x", entry->instr_bytes[i]);
    fputs("\"}", f);
}

/* Validate the whole observed instruction prefix, including the read setup.
 * Cross-run equality is checked later by PC/bytes/order, never local IDs. */
static bool prefix_valid(const TfConcolic *run, const TraceBuffer *trace, uint64_t trigger) {
    for (uint64_t seq = run->first_seq; seq < trigger; ++seq) {
        InsnOccurrence occurrence;
        const TraceEntry *entry = trace_find_seq(trace, seq, NULL);
        const TraceEntry *next = trace_find_seq(trace, seq + 1, NULL);
        if (!entry || !next || entry->vcpu_index || !entry->size ||
            !trace_insn_desc_get(trace, entry->insn_desc_id) ||
            !trace_occurrence_archive_find(trace, seq, &occurrence) ||
            !occurrence.execution_complete || !occurrence.next_pc_valid ||
            occurrence.next_pc != next->pc || occurrence.pc != entry->pc ||
            occurrence.bytes_hash != entry->bytes_hash ||
            occurrence.code_generation != entry->code_generation ||
            (occurrence.incomplete_reasons & TRACE_OCCURRENCE_BRANCH_MISMATCH))
            return false;
        const InsnDesc *desc = trace_insn_desc_get(trace, entry->insn_desc_id);
        if (desc->effects.branch_kind == TRACE_BRANCH_CONDITIONAL &&
            (!occurrence.branch_event_valid || !occurrence.branch_event_id ||
             occurrence.branch_outcome == BRANCH_OUTCOME_UNKNOWN ||
             occurrence.observed_branch_target != next->pc))
            return false;
    }
    return true;
}

static bool syscall_evidence(const TfConcolic *run, const TraceBuffer *trace,
                             const DseAuxRing *aux) {
    for (uint32_t i = 0; i < run->syscall_count; ++i) {
        const ConcolicSyscall *e = &run->syscalls[i];
        const TraceEntry *entry = trace_find_seq(trace, e->seq, NULL);
        const InsnAux *a = entry ? dse_aux_for(aux, trace, entry) : NULL;
        const DseSyscallObservation *o = a ? a->syscall : NULL;
        if (!entry || !a || a->syscall_metadata_lost || !o || o->invalid || !o->returned ||
            !e->returned || o->seq_id != e->seq || o->pc != entry->pc || o->vcpu_index ||
            o->bytes_hash != entry->bytes_hash || o->code_generation != entry->code_generation ||
            o->descriptor_id != entry->insn_desc_id || o->number != e->number ||
            o->result != e->result || memcmp(o->args, e->args, sizeof(e->args)))
            return false;
    }
    return true;
}

static void json_string(FILE *f, const char *text) {
    fputc('"', f);
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        if (*p == '"' || *p == '\\')
            fputc('\\', f);
        fputc(*p, f);
    }
    fputc('"', f);
}

static void report(TfConcolic *run, const TraceBuffer *trace, const DseAuxRing *aux,
                   DcfgGraph *graph, uint64_t trigger) {
    if (!prefix_valid(run, trace, trigger)) {
        fail(run, "prefix_observation_missing");
        return;
    }
    if ((run->guest_file || run->stdin_span || run->stdin_sequence) &&
        ((run->stdin_span && run->syscall_count != 1) ||
         (run->stdin_sequence && (!run->read_count || run->pending ||
                                  run->syscall_count != run->read_count)) ||
         !syscall_evidence(run, trace, aux))) {
        fail(run, "syscall_observation_missing");
        return;
    }
    InsnOccurrence branch;
    DcfgEdgeView edge;
    DcfgNodeView source_node, target_node;
    if (!trace_occurrence_archive_find(trace, run->selected_seq, &branch) ||
        !branch.branch_event_valid || !branch.dcfg_edge_id ||
        !dcfg_edge_get(graph, branch.dcfg_edge_id, &edge) ||
        !dcfg_node_get(graph, edge.source_node, &source_node) ||
        !dcfg_node_get(graph, edge.target_node, &target_node) ||
        edge.kind != (branch.branch_outcome == BRANCH_OUTCOME_TAKEN ? DCFG_EDGE_JCC_TAKEN
                                                                    : DCFG_EDGE_JCC_FALLTHROUGH) ||
        target_node.key.start_pc != branch.observed_branch_target) {
        fail(run, "observed_dcfg_edge_missing");
        return;
    }
    if (run->stdin_sequence &&
        run->file_offsets[run->byte_count - 1] >= run->cursor) {
        fail(run, "mutable_byte_not_read");
        return;
    }
    uint64_t seqs[CONCOLIC_MAX_STEPS];
    uint64_t start = run->source.read_seq + (run->stdin_sequence ? 0 : 1);
    uint64_t n = run->selected_seq - start + 1;
    if (!n || n > CONCOLIC_MAX_STEPS) {
        fail(run, "instruction_budget");
        return;
    }
    for (uint32_t i = 0; i < n; ++i)
        seqs[i] = start + i;
    ReplayInput *input =
        replay_input_capture(trace, aux, seqs, (uint32_t)n, trigger, 16U * 1024U * 1024U, NULL);
    IrConcolicRead source = run->guest_file || run->stdin_span
                                ? run->read
                                : (IrConcolicRead){.read_seq = run->source.read_seq,
                                                   .address = run->source.address,
                                                   .read_size = 1,
                                                   .count = 1,
                                                   .bytes = {run->source.byte},
                                                   .completed_read = run->source.completed_read};
    source.flags_verified = run->source.flags_verified;
    IrConcolicReadResult result;
    if (run->stdin_sequence) {
        IrConcolicSequence sequence = {
            .source = {.bytes = run->file_bytes, .size = run->file_size,
                       .count = run->read_count, .reads = run->reads},
            .count = run->byte_count, .flags_verified = run->source.flags_verified};
        memcpy(sequence.offsets, run->file_offsets, sizeof(sequence.offsets));
        result = ir_concolic_stdin_sequence(input, &sequence, run->solve, NULL);
        source.read_seq = run->reads[0].seq;
        source.address = run->reads[0].address;
    } else
        result = ir_concolic_read(input, &source, run->solve, NULL);
    replay_input_destroy(input);
    FILE *f = run->report;
    fprintf(f, "{\"schema\":%u,\"status\":\"%s\",\"reason\":\"%s\",",
            run->stdin_sequence ? 4U : run->stdin_span ? 3U : run->guest_file ? 2U : 1U,
            result.status, result.reason);
    if (run->stdin_sequence) {
        fprintf(f,
                "\"relation\":\"stdin_read_sequence_identity\",\"host_identity_verified\":true,"
                "\"stdin_file\":{\"sha256\":\"%s\",\"size\":%u},"
                "\"max_reads\":%u,\"read_count\":%u,\"fd\":0,\"reads\":[",
                run->file_sha256, run->file_size, IR_CONCOLIC_MAX_READS, run->read_count);
        for (uint32_t i = 0; i < run->read_count; ++i) {
            const IrReplayStdinRead *read = &run->reads[i];
            fprintf(f,
                    "%s{\"seq\":%" PRIu64 ",\"address\":%u,\"read_offset\":%u,"
                    "\"read_size\":%u,\"requested\":%u}",
                    i ? "," : "", read->seq, read->address, read->offset,
                    read->returned, read->requested);
        }
        fputs("],\"bindings\":[", f);
        for (uint32_t i = 0; i < run->byte_count; ++i) {
            fprintf(f,
                    "%s{\"offset\":%u,\"byte\":%u,\"candidate\":%u,\"input_id\":%u}",
                    i ? "," : "", run->file_offsets[i], run->file_bytes[run->file_offsets[i]],
                    result.candidates[i], result.inputs[i]);
        }
        fputs("],\"syscalls\":[", f);
        for (uint32_t i = 0; i < run->syscall_count; ++i) {
            const ConcolicSyscall *event = &run->syscalls[i];
            fprintf(f, "%s{\"seq\":%" PRIu64 ",\"number\":%u,\"args\":[",
                    i ? "," : "", event->seq, event->number);
            for (unsigned j = 0; j < 6; ++j)
                fprintf(f, "%s%u", j ? "," : "", event->args[j]);
            fprintf(f, "],\"result\":%u}", event->result);
        }
        fputs("],", f);
    } else if (run->guest_file || run->stdin_span) {
        if (run->stdin_span) {
            fputs("\"relation\":\"stdin_read_span_identity\",\"host_identity_verified\":true,"
                  "\"stdin_file\":{", f);
        } else {
            fputs("\"relation\":\"environment_file_read_identity\",\"host_identity_verified\":true,"
                  "\"file\":{\"guest_path\":", f);
            json_string(f, run->guest_file);
            fputc(',', f);
        }
        fprintf(f,
                "\"sha256\":\"%s\",\"size\":%u},\"read_offset\":%u,"
                "\"read_size\":%u,\"requested\":%u,\"fd\":%u,\"bindings\":[",
                run->file_sha256, run->file_size, run->read_offset, run->read.read_size,
                run->requested, run->fd);
        for (uint32_t i = 0; i < run->byte_count; ++i) {
            fprintf(f,
                    "%s{\"offset\":%u,\"address\":%u,\"byte\":%u,"
                    "\"candidate\":%u,\"input_id\":%u}",
                    i ? "," : "", run->file_offsets[i], source.address + source.offsets[i],
                    source.bytes[i], result.candidates[i], result.inputs[i]);
        }
        fputs("],\"syscalls\":[", f);
        for (uint32_t i = 0; i < run->syscall_count; ++i) {
            const ConcolicSyscall *e = &run->syscalls[i];
            fprintf(f, "%s{\"seq\":%" PRIu64 ",\"number\":%u,\"args\":[", i ? "," : "", e->seq,
                    e->number);
            for (unsigned j = 0; j < 6; ++j)
                fprintf(f, "%s%u", j ? "," : "", e->args[j]);
            fprintf(f, "],\"result\":%u}", e->result);
        }
        fputs("],", f);
    } else {
        fprintf(f,
                "\"relation\":\"stdin_read_byte_identity\",\"offset\":0,"
                "\"byte\":%u,\"candidate\":%u,\"input_id\":%u,",
                run->source.byte, result.candidates[0], result.inputs[0]);
    }
    fprintf(f,
            "\"read_seq\":%" PRIu64 ",\"address\":%u,\"flags_verified\":true,"
            "\"fixed_inputs_sha256\":\"%s\",\"branch_pc\":%u,\"occurrence\":%u,"
            "\"selected_seq\":%" PRIu64 ",\"taken\":%s,\"target_known\":%s,"
            "\"predicted_target\":%" PRIu64 ",\"prefix_branches\":%u,\"trace\":[",
            source.read_seq, source.address, result.fixed_inputs_sha256, run->pc, run->occurrence,
            run->selected_seq, branch.branch_outcome == BRANCH_OUTCOME_TAKEN ? "true" : "false",
            result.target_known ? "true" : "false", result.target, result.prefix_branches);
    for (uint64_t seq = run->first_seq; seq < trigger; ++seq) {
        if (seq != run->first_seq)
            fputc(',', f);
        fputs("{\"instruction\":", f);
        entry_json(f, trace_find_seq(trace, seq, NULL));
        InsnOccurrence occurrence;
        (void)trace_occurrence_archive_find(trace, seq, &occurrence);
        fprintf(f, ",\"next_pc\":%" PRIu64 ",\"branch_outcome\":%u}", occurrence.next_pc,
                occurrence.branch_outcome);
    }
    fputs("],\"successor\":", f);
    entry_json(f, trace_find_seq(trace, trigger, NULL));
    fprintf(f,
            ",\"dcfg_edge\":{\"id\":%u,\"kind\":\"%s\",\"source_pc\":%" PRIu64
            ",\"target_pc\":%" PRIu64 ",\"source_generation\":%u,\"target_generation\":%u}}\n",
            edge.edge_id, dcfg_edge_kind_name(edge.kind), source_node.key.start_pc,
            target_node.key.start_pc, source_node.key.code_generation,
            target_node.key.code_generation);
    if (fflush(f) || ferror(f))
        fprintf(stderr, "[CONCOLIC] report write failed\n");
    run->finished = true;
}

void tf_concolic_instruction(TfConcolic *run, const TraceBuffer *trace, const DseAuxRing *aux,
                             DcfgGraph *graph, uint64_t seq, bool flags_verified) {
    if (!run || run->finished || run->failure)
        return;
    if (!flags_verified) {
        fail(run, "flag_observations_unverified");
        return;
    }
    const TraceEntry *entry = trace_find_seq(trace, seq, NULL);
    if (!entry || entry->vcpu_index || !entry->insn_desc_id || !seq ||
        (run->instructions && seq != run->first_seq + run->instructions)) {
        fail(run, "trace_identity");
        return;
    }
    run->source.flags_verified = true;
    if (!run->instructions)
        run->first_seq = seq;
    if (run->selected_seq) {
        report(run, trace, aux, graph, seq);
        return;
    }
    if (run->instructions >= run->max_steps) {
        fail(run, "instruction_budget");
        return;
    }
    ++run->instructions;
    if (run->armed && entry->pc == run->pc && ++run->seen == run->occurrence)
        run->selected_seq = seq;
}

bool tf_concolic_finish(TfConcolic *run) {
    if (!run || !run->report)
        return true;
    bool ok = true;
    if (!run->finished &&
        fprintf(run->report, "{\"schema\":%u,\"status\":\"UNKNOWN\",\"reason\":\"%s\"}\n",
                run->stdin_sequence ? 4U : run->stdin_span ? 3U : run->guest_file ? 2U : 1U,
                run->failure ? run->failure : "selected_branch_not_reached") < 0)
        ok = false;
    if (fclose(run->report))
        ok = false;
    run->report = NULL;
    run->finished = true;
    return ok;
}

void tf_concolic_destroy(TfConcolic *run) {
    if (!run)
        return;
    if (!tf_concolic_finish(run))
        fprintf(stderr, "[CONCOLIC] report close failed\n");
    free(run->guest_file);
    free(run->file_bytes);
    free(run);
}
