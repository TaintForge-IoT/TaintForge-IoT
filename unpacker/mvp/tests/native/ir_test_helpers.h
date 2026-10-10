#ifndef TAINTFORGE_IR_TEST_HELPERS_H
#define TAINTFORGE_IR_TEST_HELPERS_H

#include "ir.h"
#include "ir_eval.h"
#include "ir_opt.h"
#include <stdlib.h>
#include <string.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #c); exit(1); } } while (0)

typedef struct { IrModule *m; IrBlockId b; } TestIr;
static inline TestIr ti_new(void) {
    TestIr t = {ir_module_create(NULL), 0}; CHECK(t.m); t.b = ir_block_add(t.m); CHECK(t.b); return t;
}
static inline IrValueId ti_emit(TestIr t, IrInstSpec s) {
    IrValueId id = ir_emit_value(t.m, t.b, s);
    if (!id) fprintf(stderr, "builder: %s\n", ir_module_error(t.m));
    CHECK(id); return id;
}
static inline IrValueId ti_const(TestIr t, uint8_t w, uint64_t bits) {
    return ti_emit(t, (IrInstSpec){.op = IR_OP_CONST, .type = ir_type_bv(w), .immediate = bits});
}
static inline IrValueId ti_input(TestIr t, uint8_t w, uint64_t key) {
    return ti_emit(t, (IrInstSpec){.op = IR_OP_INPUT, .type = ir_type_bv(w), .immediate = key});
}
static inline IrValueId ti_unknown(TestIr t, uint8_t w, uint32_t reasons) {
    return ti_emit(t, (IrInstSpec){.op = IR_OP_UNKNOWN, .type = ir_type_bv(w), .immediate = reasons});
}
static inline IrValueId ti_op(TestIr t, IrOpcode op, uint8_t w, IrValueId a, IrValueId b, IrValueId c, uint64_t imm) {
    return ti_emit(t, (IrInstSpec){.op = op, .type = ir_type_bv(w), .args = {a, b, c}, .immediate = imm});
}
static inline IrValueId ti_mem(TestIr t, uint8_t w, uint64_t key) {
    return ti_emit(t, (IrInstSpec){.op = IR_OP_INPUT, .type = ir_type_mem(w), .immediate = key});
}
static inline IrValueId ti_store(TestIr t, IrValueId mem, IrValueId address, IrValueId data, IrEndian endian) {
    return ti_emit(t, (IrInstSpec){.op = IR_OP_STORE, .type = ir_module_value(t.m, mem)->type,
        .args = {mem, address, data}, .endian = endian});
}
static inline IrValueId ti_load(TestIr t, IrValueId mem, IrValueId address, uint8_t w, IrEndian endian) {
    return ti_emit(t, (IrInstSpec){.op = IR_OP_LOAD, .type = ir_type_bv(w), .args = {mem, address, 0}, .endian = endian});
}
static inline IrValueId ti_read(TestIr t, IrStateId state) {
    return ti_emit(t, (IrInstSpec){.op = IR_OP_READ_STATE, .type = ir_module_state(t.m, state)->type, .state = state});
}
static inline void ti_write(TestIr t, IrStateId state, IrValueId value) {
    CHECK(ir_emit_effect(t.m, t.b, (IrInstSpec){.op = IR_OP_WRITE_STATE, .type = ir_type_void(), .state = state, .args = {value, 0, 0}}));
}
static inline void ti_end(TestIr t) { CHECK(ir_block_terminate(t.m, t.b, (IrTerminator){.kind = IR_TERM_FRAGMENT_END})); }
static inline void ti_output(TestIr t, IrValueId id) { CHECK(ir_module_add_output(t.m, id)); }
static inline IrEval *ti_eval(TestIr t, const IrBindings *bindings, IrEvalStatus expected) {
    CHECK(ir_validate(t.m, NULL));
    IrEval *e = ir_eval_create(t.m, bindings, NULL); CHECK(e);
    IrEvalResult r = ir_eval_run(e);
    if (r.status != expected) fprintf(stderr, "eval status=%u expected=%u reasons=%x block=%u inst=%u\n",
        (unsigned)r.status, (unsigned)expected, r.reasons, r.block, r.instruction);
    CHECK(r.status == expected); return e;
}
static inline uint64_t ti_value(IrEval *e, IrValueId id) {
    IrEvalValue v = ir_eval_value(e, id); CHECK(v.type.kind == IR_TYPE_BV); CHECK(ir_bits_complete(v.bits, v.type.bits)); return v.bits.value;
}
static inline IrBits ti_zero_byte(void *user, IrBindingKind kind, uint64_t key, uint64_t addr) {
    (void)user; (void)kind; (void)key; (void)addr; return ir_bits_known(0, 8);
}

#endif
