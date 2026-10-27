/* Actual native trigger/configuration code; no QEMU scheduling is simulated. */
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../../unpacker/test/phase1_retire.h"

int main(int argc, char **argv) {
    assert(argc == 2);
    TfPhase1Io io = {.enabled = true, .owner = getpid(), .session = "s", .attempt = "a",
        .instance = "i", .max_events = 100, .pc = 4100, .trace_seq = 23, .epoch = 4, .generation = 7};
    char *options[] = {"retire-socket=/unit-test", "retire-nonce=12345678901234567890123456789012",
        "retire-controller=1", "retire-trigger=verdict", "retire-max-insns=2", "retire-boundary=8192"};
    TfRetire r;
    assert(!tf_retire_configure(&r, &io, 4, options, 6, "i386", false)); /* missing budget */
    assert(!tf_retire_configure(&r, &io, 6, options, 6, "i386", false)); /* both triggers */
    assert(!tf_retire_configure(&r, &io, 5, options, 7, "i386", false));
    io.capture_at_entry = true;
    assert(!tf_retire_configure(&r, &io, 5, options, 6, "i386", false));
    assert(tf_retire_configure(&r, &io, 0, NULL, 6, "i386", false));
    io.capture_at_entry = false;
    assert(tf_retire_configure(&r, &io, 5, options, 6, "i386", false));
    io.events = tmpfile();
    assert(io.events && r.boundary == 0 && r.on_verdict);
    assert(!tf_retire_due(&r));
    assert(!tf_retire_due(&r));
    if (!strcmp(argv[1], "budget")) {
        tf_retire_due(&r);
        abort();
    }
    tf_retire_verdict(&r, &io, 1, 4096);
    assert(io.event_seq == 0); /* The decision instruction has not executed. */
    assert(tf_retire_due(&r)); /* A decision on the last budgeted instruction is valid. */
    if (!strcmp(argv[1], "epoch")) ++io.epoch;
    if (!strcmp(argv[1], "generation")) ++io.generation;
    if (!strcmp(argv[1], "trace")) ++io.trace_seq;
    if (!strcmp(argv[1], "replaced")) tf_retire_verdict(&r, &io, 2, 4096);
    uint64_t pc = !strcmp(argv[1], "other-pc") ? 12288 : 8192;
    tf_retire_bind_continuation(&r, &io, pc);
    assert(r.boundary == pc && io.pc == pc && io.event_seq == 1 && r.state == TF_RETIRE_ACTIVE);
    rewind(io.events);
    char line[2048];
    assert(fgets(line, sizeof(line), io.events));
    assert(strstr(line, "\"trigger\":\"next_instruction_after_selection\""));
    assert(strstr(line, "\"decision_pc\":4100"));
    fputs(line, stdout);
    r.state = TF_RETIRE_REQUESTED;
    assert(!tf_retire_due(&r));
    fclose(io.events);
    return 0;
}
