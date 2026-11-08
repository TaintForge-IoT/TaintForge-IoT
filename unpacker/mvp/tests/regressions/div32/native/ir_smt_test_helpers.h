#ifndef TAINTFORGE_IR_SMT_TEST_HELPERS_H
#define TAINTFORGE_IR_SMT_TEST_HELPERS_H
#include "ir_test_helpers.h"
#include "ir_smt.h"
#include "ir_ssa.h"

static inline IrSmt *sm_build(TestIr t, const IrInputs *inputs, const IrSmtOptions *o) {
    IrSmtInfo info;
    IrSmt *s = ir_smt_build(t.m, inputs, o, &info);
    if (!s) fprintf(stderr, "SMT build: status=%u %s seq=%llu\n", info.status, info.message,
        (unsigned long long)info.origin.seq_id);
    CHECK(s && info.status == IR_OK); return s;
}
static inline void sm_status(IrSmtAnswer *a, IrSmtStatus expected) {
    if (a->status != expected) fprintf(stderr, "SMT status=%u expected=%u %s reasons=%x\n",
        a->status, expected, a->diagnostic, a->reasons);
    CHECK(a->status == expected);
    if (expected != IR_SMT_SAT) CHECK(!a->inputs && !a->parameters && !a->samples && !a->catalogue);
}
static inline IrSmtAnswer sm_query(IrSmt *s, IrValueId value, unsigned w, uint64_t expected, IrSmtStatus status) {
    IrSmtConstraint c = {value, expected, ir_width_mask(w)};
    IrSmtAnswer a = ir_smt_query(s, &c, 1, &value, 1, NULL); sm_status(&a, status); return a;
}
static inline void sm_expect(IrSmt *s, IrValueId value, unsigned w, uint64_t expected, IrSmtStatus status) {
    IrSmtAnswer a = sm_query(s, value, w, expected, status); ir_smt_answer_destroy(&a);
}
static inline void sm_same_bits(IrBits actual, IrBits expected, const char *op, unsigned width) {
    if (actual.value != expected.value || actual.known_mask != expected.known_mask)
        fprintf(stderr, "%s BV%u: smt=%llx/%llx eval=%llx/%llx\n", op, width,
            (unsigned long long)actual.value, (unsigned long long)actual.known_mask,
            (unsigned long long)expected.value, (unsigned long long)expected.known_mask);
    CHECK(actual.value == expected.value && actual.known_mask == expected.known_mask);
}
static inline IrBits sm_parameter_binding(void *user, IrBindingKind kind, uint64_t key, uint8_t width) {
    const IrSmtParameter *p = user; CHECK(kind == IR_BIND_INPUT);
    for (unsigned i = 0; i < 3; ++i) if (p[i].key == key && p[i].width == width) return p[i].observed;
    return ir_bits_unknown(IR_REASON_UNBOUND_INPUT);
}
static inline uint64_t sm_random(uint64_t *seed) {
    *seed ^= *seed << 13; *seed ^= *seed >> 7; *seed ^= *seed << 17; return *seed;
}
static inline IrInputs *sm_catalogue(const IrModule *m, const IrInputCell *cells, unsigned count) {
    unsigned n = ir_module_state_count(m); CHECK(n && n <= 16);
    IrInputState states[16] = {0};
    for (unsigned i = 0; i < n; ++i) {
        const IrState *state = ir_module_state(m, i + 1);
        states[i] = (IrInputState){.state = i + 1, .type = state->type, .key = state->key};
    }
    IrInputs *in = ir_inputs_create((IrOrigin){.seq_id = 42, .has_trace_identity = true}, states, n, count, NULL, NULL, NULL);
    CHECK(in && !ir_inputs_ready(in) && !ir_inputs_state_count(in));
    for (unsigned i = 0; i < count; ++i) CHECK(ir_inputs_add(in, cells[i]) == i + 1);
    CHECK(ir_inputs_seal(in) && ir_inputs_ready(in) && ir_inputs_state_count(in) == n);
    CHECK(!ir_inputs_state_at(in, n)); return in;
}
typedef struct { IrBindings states; IrSmtParameter parameters[3]; } SmBindings;
static inline IrBits sm_read_bv(void *user, IrBindingKind kind, uint64_t key, uint8_t width) {
    SmBindings *b = user;
    if (kind == IR_BIND_INPUT) return sm_parameter_binding(b->parameters, kind, key, width);
    return b->states.read_bv ? b->states.read_bv(b->states.user, kind, key, width) : ir_bits_unknown(IR_REASON_UNBOUND_STATE);
}
static inline IrBits sm_read_byte(void *user, IrBindingKind kind, uint64_t key, uint64_t address) {
    SmBindings *b = user;
    return b->states.read_byte ? b->states.read_byte(b->states.user, kind, key, address) : ir_bits_unknown(IR_REASON_MEMORY);
}
static inline void sm_compare(TestIr t, IrSmtAnswer *a, const IrInputs *in, const IrSmtParameter p[3]) {
    IrInputBindings *owner = in ? ir_inputs_bindings_create(in, a->inputs, a->input_count, NULL, NULL) : NULL;
    CHECK(!in || owner);
    SmBindings context = {.states = ir_inputs_bindings(owner)};
    memcpy(context.parameters, p, sizeof(context.parameters));
    for (unsigned i = 0; i < a->parameter_count; ++i) for (unsigned j = 0; j < 3; ++j)
        if (context.parameters[j].key == a->parameters[i].key)
            context.parameters[j].observed = ir_bits_known(a->parameters[i].value, a->parameters[i].width);
    IrBindings bindings = {.user = &context, .read_bv = sm_read_bv, .read_byte = sm_read_byte};
    IrEval *e = ir_eval_create(t.m, &bindings, NULL); CHECK(e);
    IrEvalResult result = ir_eval_run(e); CHECK(result.status == IR_EVAL_FRAGMENT_END || result.status == IR_EVAL_UNKNOWN);
    for (unsigned i = 0; i < a->sample_count; ++i) {
        const IrValue *v = ir_module_value(t.m, a->samples[i].value);
        const IrInst *ins = ir_module_inst(t.m, v->definition);
        sm_same_bits(a->samples[i].bits, ir_eval_value(e, a->samples[i].value).bits, ir_opcode_name(ins->spec.op), v->type.bits);
    }
    ir_eval_destroy(e); ir_inputs_bindings_destroy(owner);
}

#endif
