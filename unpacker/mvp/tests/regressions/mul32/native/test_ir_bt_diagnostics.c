#define _POSIX_C_SOURCE 200809L
#include "ir_concolic.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct { csh decoder; TraceBuffer *trace; DseAuxRing *aux; } Fixture;
static Fixture fixture(void) {
    Fixture f = {0};
    assert(cs_open(CS_ARCH_X86, CS_MODE_32, &f.decoder) == CS_ERR_OK);
    assert(cs_option(f.decoder, CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK);
    meta_init();
    f.trace = trace_buffer_create(16); f.aux = dse_aux_create(16);
    assert(f.trace && f.aux);
    return f;
}
static uint64_t emit(Fixture *f, uint64_t pc, const uint8_t *code, uint8_t size) {
    InsnMeta *decoded = meta_decode(code, size, pc, f->decoder); assert(decoded);
    const InsnMeta *meta = meta_store(pc, decoded); assert(meta);
    InsnDescId id = trace_insn_desc_intern(f->trace, TRACE_ARCH_X86, TRACE_MODE_32,
        pc, 1, code, size, meta); assert(id);
    TraceEntry e = {.pc = pc, .insn_desc_id = id};
    const TraceEntry *entry = trace_append(f->trace, &e); assert(entry);
    InsnAux aux = {.reg_value_valid_mask = (1U << REG_COUNT) - 1U,
        .eflags_valid = true, .eflags_before = 2};
    assert(dse_aux_record(f->aux, f->trace, entry, &aux));
    InsnAux *stored = (InsnAux *)dse_aux_for(f->aux, f->trace, entry); assert(stored);
    dse_aux_finalize(stored, pc + size, aux.reg_vals, aux.reg_value_valid_mask);
    assert(dse_aux_archive_occurrence(f->aux, f->trace, NULL, entry->seq_id));
    return entry->seq_id;
}
static void cleanup(Fixture *f) {
    dse_aux_destroy(f->aux); trace_buffer_destroy(f->trace);
    meta_free(); cs_close(&f->decoder);
}
static void build_diagnostics(void) {
    const uint8_t nop[] = {0x90}, bt[] = {0x0f,0xa3,0xd8}, bts[] = {0x0f,0xab,0xd8};
    for (unsigned supported = 0; supported < 2; ++supported) {
        Fixture f = fixture();
        uint64_t read = emit(&f, 0x1000, nop, 1);
        uint64_t seqs[2] = {emit(&f, 0x1001, nop, 1), 0};
        seqs[1] = emit(&f, 0x1002, supported ? bt : bts, 3);
        uint64_t trigger = emit(&f, 0x1005, nop, 1);
        ReplayInputStatus status;
        ReplayInput *input = replay_input_capture(f.trace, f.aux, seqs, 2, trigger,
            2U * 1024U * 1024U, &status);
        assert(input && status == REPLAY_INPUT_READY);
        IrConcolicRead source = {.read_seq = read, .address = 0x2000, .read_size = 1,
            .count = 1, .bytes = {0x41}, .completed_read = true, .flags_verified = true};
        IrConcolicReadResult result = ir_concolic_read(input, &source, false, NULL);
        replay_input_destroy(input);
        cleanup(&f);
        assert(!strcmp(result.status, "UNKNOWN") && result.replay_build_attempted);
        assert(result.replay_selected_steps == 2);
        if (supported) {
            assert(result.replay_build_status == IR_REPLAY_READY);
            assert(result.replay_lifted_steps == 2 && !result.replay_build_issues);
            assert(!result.replay_stopped_origin.has_trace_identity && !result.replay_stopped_size);
        } else {
            assert(!strcmp(result.reason, "replay_incomplete"));
            assert(result.replay_build_status == IR_REPLAY_UNKNOWN);
            assert(result.replay_build_issues & IR_REPLAY_UNSUPPORTED);
            assert(result.replay_lifted_steps == 1);
            assert(result.replay_stopped_origin.has_trace_identity);
            assert(result.replay_stopped_origin.seq_id == seqs[1]);
            assert(result.replay_stopped_origin.pc == 0x1002);
            assert(result.replay_stopped_origin.code_generation == 1);
            assert(result.replay_stopped_size == 3);
            assert(!memcmp(result.replay_stopped_bytes, bts, 3));
        }
    }
    puts("replay_build_diagnostics=2/2");
}
static void collector(const char *path, bool reject) {
    Fixture f = fixture();
    char report[4096];
    assert(snprintf(report, sizeof(report), "concolic-report=%s", path) < (int)sizeof(report));
    char *options[] = {report, "concolic-branch=0x2000", "concolic-byte=0x41",
        "concolic-occurrence=2"};
    TfConcolic *run = NULL;
    assert(tf_concolic_configure(&run, 4, options) && run);
    const uint8_t syscall[] = {0xcd,0x80}, jz[] = {0x74,0};
    uint64_t read = emit(&f, 0x1000, syscall, 2);
    tf_concolic_instruction(run, f.trace, f.aux, NULL, read, true);
    tf_concolic_syscall(run, f.trace, read, 0, 3, 0, 0x3000, 1);
    tf_concolic_return(run, 0, 3, 1, true, 0x41);
    uint64_t branch = emit(&f, 0x2000, jz, 2);
    tf_concolic_instruction(run, f.trace, f.aux, NULL, branch, true);
    if (reject) {
        uint64_t write = emit(&f, 0x2002, syscall, 2);
        tf_concolic_instruction(run, f.trace, f.aux, NULL, write, true);
        const uint64_t args[] = {1,0x4000,0,0,0,0};
        tf_concolic_syscall_ex(run, f.trace, write, 0, 4, args, NULL);
        tf_concolic_syscall_ex(run, f.trace, write + 1, 0, 99, args, NULL);
    }
    assert(tf_concolic_finish(run)); tf_concolic_destroy(run); cleanup(&f);
}
int main(int argc, char **argv) {
    assert(argc == 3);
    build_diagnostics(); collector(argv[1], true); collector(argv[2], false);
    puts("BT_DIAGNOSTICS_PASS");
    return 0;
}
