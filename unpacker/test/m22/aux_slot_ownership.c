#include "aux_trace.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    TraceEntry entries[2] = {{.seq_id = 1}, {.seq_id = 2}};
    TraceBuffer trace = {.entries = entries, .capacity = 2};
    DseAuxRing *ring = dse_aux_create(2);
    assert(ring);
    uint8_t bytes[256];
    memset(bytes, 19, sizeof(bytes));
    DseSyscallObservation syscall = {.number = 4, .write_size = sizeof(bytes), .write_values = bytes};
    InsnAux aux = {.syscall = &syscall};
    assert(dse_aux_record(ring, &trace, &entries[1], &aux));
    size_t one = ring->dynamic_bytes;
    assert(one == sizeof(syscall) + sizeof(bytes));
    for (unsigned i = 0; i < 10000; i++) {
        assert(dse_aux_record(ring, &trace, &entries[0], &aux));
        assert(ring->dynamic_bytes == 2 * one);
        const InsnAux *old = dse_aux_for(ring, &trace, &entries[0]);
        assert(old && old->syscall && old->syscall->write_values != bytes);
        assert(!memcmp(old->syscall->write_values, bytes, sizeof(bytes)));
        entries[0].seq_id += 2; /* the ordinary instruction overwrites this slot */
        assert(dse_aux_discard(ring, &trace, &entries[0]));
        assert(ring->dynamic_bytes == one);
        assert(!ring->entries[0].valid && !ring->entries[0].syscall);
        assert(!dse_aux_for(ring, &trace, &entries[0]));
        assert(dse_aux_for(ring, &trace, &entries[1]));
        assert(dse_aux_discard(ring, &trace, &entries[0]));
        assert(ring->dynamic_bytes == one);
    }
    TraceEntry foreign = {.seq_id = 999};
    assert(!dse_aux_discard(ring, &trace, &foreign));
    assert(!dse_aux_discard(NULL, &trace, &entries[1]));
    assert(dse_aux_discard(ring, &trace, &entries[1]));
    assert(ring->dynamic_bytes == 0);
    dse_aux_destroy(ring);
    puts("{\"status\":\"PASS\",\"replacements\":10000,\"live_dynamic_bytes\":0}");
    return 0;
}
