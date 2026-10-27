/* Source-constrained producer DAG -> existing IR/SMT backend.
 * The caller authenticates leaf kinds/keys against original inputs/contracts.
 * Candidate addresses occur only in goals, never in source bindings.
 */
#define _POSIX_C_SOURCE 200809L
#include "ir.h"
#include "ir_eval.h"
#include "ir_smt.h"
#include <z3.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_NODES 2000000U
#define MAX_INPUTS 262144U
#define MAX_GOALS 262144U

typedef struct {
    uint16_t op, bits;
    uint32_t a, b, c;
    uint64_t immediate, origin;
} Producer;
typedef struct { uint32_t id; uint64_t value, mask; } Binding;
typedef struct { uint32_t id; uint64_t expected; } Goal;

static const char *diagnostic = "ok";
static bool resource_failure;
static bool allow_lemma_inputs;

static bool reject(const char *message) { diagnostic = message; return false; }
static uint16_t le16(const unsigned char *p) { return p[0] | (uint16_t)p[1] << 8; }
static uint32_t le32(const unsigned char *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static uint64_t le64(const unsigned char *p) { return le32(p) | (uint64_t)le32(p + 4) << 32; }
static bool source_op(unsigned op) {
    return (op >= 100 && op <= 109) || (allow_lemma_inputs && op == 110);
}
static uint64_t width_mask(unsigned bits) { return bits == 64 ? UINT64_MAX : (UINT64_C(1) << bits) - 1; }

static bool read_nodes(const char *path, Producer **out, uint32_t *count) {
    FILE *f = fopen(path, "rb");
    if (!f) return reject("Cannot open producer slice");
    unsigned char header[16], record[32];
    bool ok = fread(header, 1, sizeof(header), f) == sizeof(header) &&
              !memcmp(header, "TFPROD1\0", 8) && le32(header + 8) == 1 && le32(header + 12) == 32;
    if (!ok) { fclose(f); return reject("Invalid producer slice header"); }
    if (fseek(f, 0, SEEK_END)) { fclose(f); return reject("Cannot size producer slice"); }
    long size = ftell(f);
    if (size < 16 || (size - 16) % 32) { fclose(f); return reject("Invalid producer slice extent"); }
    uint64_t n = (uint64_t)(size - 16) / 32;
    if (!n || n > MAX_NODES) {
        resource_failure = n > MAX_NODES;
        fclose(f); return reject(resource_failure ? "Producer node budget" : "Empty producer slice");
    }
    Producer *nodes = calloc((size_t)n + 1, sizeof(*nodes));
    if (!nodes) { resource_failure = true; fclose(f); return reject("Producer allocation"); }
    if (fseek(f, 16, SEEK_SET)) { free(nodes); fclose(f); return reject("Cannot read producer slice"); }
    for (uint32_t i = 1; i <= n; ++i) {
        if (fread(record, 1, sizeof(record), f) != sizeof(record)) { ok = false; break; }
        Producer p = {le16(record), le16(record + 2), le32(record + 4), le32(record + 8),
                      le32(record + 12), le64(record + 16), le64(record + 24)};
        if (!p.bits || p.bits > 64 || p.op == IR_OP_INPUT ||
            (p.op > IR_OP_ITE && !source_op(p.op))) { ok = false; break; }
        if (source_op(p.op)) {
            if (p.c || p.immediate & ~width_mask(p.bits)) { ok = false; break; }
        } else {
            unsigned arity = ir_opcode_arity((IrOpcode)p.op);
            uint32_t args[] = {p.a, p.b, p.c};
            for (unsigned j = 0; j < 3; ++j)
                if ((j < arity && (!args[j] || args[j] >= i)) || (j >= arity && args[j])) ok = false;
            if (p.op == IR_OP_CONST && p.immediate & ~width_mask(p.bits)) ok = false;
            if (!ok) break;
        }
        nodes[i] = p;
    }
    if (ferror(f)) ok = false;
    fclose(f);
    if (!ok) { free(nodes); return reject("Invalid producer opcode, width or dependency"); }
    *out = nodes; *count = (uint32_t)n; return true;
}

static bool number(const char *token, unsigned base, uint64_t *value) {
    if (!*token || *token == '-' || *token == '+') return false;
    char *end; errno = 0;
    unsigned long long parsed = strtoull(token, &end, base);
    if (errno || *end) return false;
    *value = parsed; return true;
}

static bool read_rows(const char *path, const Producer *nodes, uint32_t node_count,
                      bool bindings, void **out, uint32_t *count) {
    FILE *f = fopen(path, "r");
    if (!f) return reject(bindings ? "Cannot open source premises" : "Cannot open proof goals");
    uint32_t capacity = bindings ? MAX_INPUTS : MAX_GOALS, n = 0;
    size_t stride = bindings ? sizeof(Binding) : sizeof(Goal);
    void *items = calloc(capacity, stride);
    unsigned char *seen = calloc((size_t)node_count + 1, 1);
    if (!items || !seen) {
        free(items); free(seen); fclose(f); resource_failure = true; return reject("Proof row allocation");
    }
    char line[256]; bool ok = true;
    while (fgets(line, sizeof(line), f)) {
        char id_text[80], value_text[80], mask_text[80], extra;
        int fields = bindings ? sscanf(line, "%79s %79s %79s %c", id_text, value_text, mask_text, &extra)
                              : sscanf(line, "%79s %79s %c", id_text, value_text, &extra);
        if (fields == EOF) continue;
        uint64_t id, value, mask = 0;
        if (!strchr(line, '\n') && !feof(f)) { ok = false; break; }
        if (fields != (bindings ? 3 : 2) || !number(id_text, 10, &id) ||
            !number(value_text, 16, &value) || (bindings && !number(mask_text, 16, &mask)) ||
            !id || id > node_count || seen[id] || value & ~width_mask(nodes[id].bits)) { ok = false; break; }
        if (n == capacity) { resource_failure = true; ok = false; break; }
        if (bindings && (!source_op(nodes[id].op) || mask != width_mask(nodes[id].bits) ||
                         value != nodes[id].immediate)) { ok = false; break; }
        seen[id] = 1;
        if (bindings) ((Binding *)items)[n] = (Binding){(uint32_t)id, value, mask};
        else ((Goal *)items)[n] = (Goal){(uint32_t)id, value};
        ++n;
    }
    if (ferror(f)) ok = false;
    fclose(f);
    if (bindings && ok)
        for (uint32_t i = 1; i <= node_count; ++i)
            if (source_op(nodes[i].op) && !seen[i]) { ok = false; break; }
    free(seen);
    if (!ok || (!bindings && !n)) {
        free(items); return reject(resource_failure ? "Proof row budget" :
            bindings ? "Invalid, duplicate or missing source premise" : "Invalid, duplicate or empty proof goal");
    }
    *out = items; *count = n; return true;
}

static IrValueId emit(IrModule *m, IrBlockId block, IrOpcode op, unsigned bits,
                      IrValueId a, IrValueId b, IrValueId c, uint64_t immediate, uint64_t origin) {
    return ir_emit_value(m, block, (IrInstSpec){.op = op, .type = ir_type_bv(bits), .args = {a, b, c},
        .immediate = immediate, .origin = {.seq_id = origin >> 32, .pc = (uint32_t)origin,
                                         .has_trace_identity = origin != 0}});
}
static IrValueId constant(IrModule *m, IrBlockId b, unsigned bits, uint64_t value) {
    return emit(m, b, IR_OP_CONST, bits, 0, 0, 0, value, 0);
}
/* Keep conjunction/disjunction depth logarithmic. A long left-associated BV1
 * chain causes repeated flattening in the solver before source equalities can
 * propagate through the producer graph. This changes only association. */
static IrValueId reduce_terms(IrModule *m, IrBlockId block, IrOpcode op,
                              IrValueId *terms, uint32_t count) {
    if (!count) return constant(m, block, 1, op == IR_OP_AND);
    while (count > 1) {
        uint32_t next = 0;
        for (uint32_t i = 0; i < count; i += 2)
            terms[next++] = i + 1 == count ? terms[i] :
                emit(m, block, op, 1, terms[i], terms[i + 1], 0, 0, 0);
        count = next;
    }
    return terms[0];
}

static void json_string(FILE *f, const char *text) {
    fputc('"', f);
    for (const unsigned char *p = (const unsigned char *)(text ? text : ""); *p; ++p) {
        if (*p == '"' || *p == '\\') { fputc('\\', f); fputc(*p, f); }
        else if (*p < 32) fprintf(f, "\\u%04x", *p);
        else fputc(*p, f);
    }
    fputc('"', f);
}
static const char *query_status(IrSmtStatus status) {
    static const char *names[] = {"SAT", "UNSAT", "UNKNOWN", "RESOURCE_LIMIT", "INVALID", "OUT_OF_MEMORY"};
    return (unsigned)status < sizeof(names) / sizeof(*names) ? names[status] : "INVALID";
}
static void query_json(FILE *f, const IrSmtAnswer *answer, bool attempted) {
    if (!attempted) { fputs("null", f); return; }
    fputs("{\"status\":", f); json_string(f, query_status(answer->status));
    fprintf(f, ",\"solver_checks\":%u,\"diagnostic\":", answer->solver_checks);
    json_string(f, answer->diagnostic);
    fputs(",\"checks\":", f); ir_smt_checks_report_json(f, answer);
    if (answer->sample_count) fprintf(f, ",\"sampled_target\":{\"value\":%" PRIu64 ",\"known\":%" PRIu64 "}",
                                    answer->samples[0].bits.value, answer->samples[0].bits.known_mask);
    fputc('}', f);
}

typedef struct { const Producer *nodes; uint32_t count; } EvaluationSources;
static IrBits evaluation_source(void *user, IrBindingKind kind, uint64_t key, uint8_t width) {
    const EvaluationSources *sources = user;
    if (kind != IR_BIND_INPUT || !key || key > sources->count ||
        !source_op(sources->nodes[key].op) || sources->nodes[key].bits != width)
        return ir_bits_unknown(IR_REASON_UNBOUND_INPUT);
    return ir_bits_known(sources->nodes[key].immediate, width);
}
static bool write_le(FILE *file, uint64_t value, unsigned bytes) {
    unsigned char encoded[8];
    for (unsigned i = 0; i < bytes; ++i) encoded[i] = (unsigned char)(value >> (8 * i));
    return fwrite(encoded, 1, bytes, file) == bytes;
}

/* These values are proposed intermediate lemmas, never proof premises by
 * themselves. The caller must first prove every topological chunk and may use
 * only already proved values as SOURCE110 in a later --lemma-chunk query. */
static int evaluate_values(const char *slice, const char *premises,
                           const char *values_path, const char *report_path) {
    Producer *nodes = NULL; Binding *bindings = NULL; IrValueId *ids = NULL;
    IrModule *module = NULL; IrEval *evaluation = NULL;
    uint32_t count = 0, binding_count = 0, known_count = 0;
    const char *status = "INVALID";
    IrEvalResult result = {.status = IR_EVAL_INVALID};
    bool written = false, report_ok = true;
    if (!read_nodes(slice, &nodes, &count) ||
        !read_rows(premises, nodes, count, true, (void **)&bindings, &binding_count)) goto finish;
    IrLimits limits = {count + 1, count + 1, 1, 1, 1};
    module = ir_module_create(&limits);
    ids = calloc((size_t)count + 1, sizeof(*ids));
    if (!module || !ids) { resource_failure = true; reject("Evaluation allocation"); goto finish; }
    IrBlockId block = ir_block_add(module);
    if (!block || !ir_module_set_entry(module, block)) { reject("Evaluation block"); goto finish; }
    for (uint32_t i = 0; i < binding_count; ++i) {
        uint32_t id = bindings[i].id;
        ids[id] = emit(module, block, IR_OP_INPUT, nodes[id].bits, 0, 0, 0, id, nodes[id].origin);
    }
    for (uint32_t i = 1; i <= count; ++i) {
        Producer p = nodes[i];
        if (source_op(p.op)) continue;
        uint64_t immediate = p.op == IR_OP_UNKNOWN && !p.immediate ? IR_REASON_UNDEFINED : p.immediate;
        ids[i] = emit(module, block, (IrOpcode)p.op, p.bits, ids[p.a], ids[p.b], ids[p.c], immediate, p.origin);
    }
    if (!ir_block_terminate(module, block, (IrTerminator){.kind = IR_TERM_FRAGMENT_END}) ||
        !ir_validate(module, NULL)) { reject("Evaluation producer validation"); goto finish; }
    EvaluationSources sources = {nodes, count};
    IrBindings source_bindings = {.user = &sources, .read_bv = evaluation_source};
    IrEvalLimits eval_limits = ir_eval_default_limits();
    eval_limits.steps = (uint64_t)count + 2;
    evaluation = ir_eval_create(module, &source_bindings, &eval_limits);
    if (!evaluation) { resource_failure = true; reject("Evaluation owner allocation"); goto finish; }
    result = ir_eval_run(evaluation);
    if (result.status != IR_EVAL_FRAGMENT_END) {
        status = "UNKNOWN"; reject("Original-source evaluation did not finish"); goto finish;
    }
    for (uint32_t i = 1; i <= count; ++i)
        if (ir_bits_complete(ir_eval_value(evaluation, ids[i]).bits, nodes[i].bits)) ++known_count;
    if (known_count != count) {
        status = "UNKNOWN"; reject("Proposed lemma values include undefined bits"); goto finish;
    }
    FILE *file = fopen(values_path, "wb");
    if (!file) { reject("Cannot write evaluated values"); goto finish; }
    written = fwrite("TFVALUES", 1, 8, file) == 8 && write_le(file, 1, 4) && write_le(file, count, 4);
    for (uint32_t i = 1; i <= count && written; ++i)
        written = write_le(file, ir_eval_value(evaluation, ids[i]).bits.value, 8);
    if (fclose(file)) written = false;
    if (!written) { reject("Cannot finish evaluated values"); goto finish; }
    status = "EVALUATED";
finish:
    if (module && (ir_module_status(module) == IR_RESOURCE_LIMIT ||
                   ir_module_status(module) == IR_OUT_OF_MEMORY)) resource_failure = true;
    if (resource_failure) status = "UNKNOWN";
    FILE *report = fopen(report_path, "w");
    if (!report) report_ok = false;
    else {
        fputs("{\"schema_version\":1,\"status\":", report); json_string(report, status);
        fputs(",\"diagnostic\":", report); json_string(report, diagnostic);
        fprintf(report, ",\"producer_nodes\":%u,\"source_premises\":%u,\"fully_known_nodes\":%u,"
            "\"eval_status\":%u,\"eval_steps\":%" PRIu64 ",\"values_are_proposed_lemmas_only\":true,"
            "\"source_leaf_authentication\":\"caller\",\"observed_checkpoint_used_as_premise\":false}\n",
            count, binding_count, known_count, result.status, result.steps);
        if (fclose(report)) report_ok = false;
    }
    ir_eval_destroy(evaluation); ir_module_destroy(module);
    free(nodes); free(bindings); free(ids);
    return report_ok && (written || !strcmp(status, "UNKNOWN")) ? 0 : 1;
}

int main(int argc, char **argv) {
    if (argc == 6 && !strcmp(argv[1], "--evaluate"))
        return evaluate_values(argv[2], argv[3], argv[4], argv[5]);
    if (argc == 6 && !strcmp(argv[1], "--lemma-chunk")) {
        allow_lemma_inputs = true; --argc; ++argv;
    }
    if (argc != 5) { fprintf(stderr, "Usage: oep-smt SLICE.bin INPUTS.txt GOALS.txt OUTPUT.json\n"); return 1; }
    Producer *nodes = NULL; Binding *bindings = NULL; Goal *goals = NULL;
    IrValueId *values = NULL, *terms = NULL; IrSmtParameter *parameters = NULL;
    IrModule *module = NULL; IrSmt *smt = NULL;
    IrSmtInfo info = {.status = IR_INVALID, .message = "not built"};
    IrSmtAnswer baseline = {0}, counterexample = {0};
    uint32_t node_count = 0, binding_count = 0, goal_count = 0;
    bool baseline_attempted = false, counterexample_attempted = false, valid = false;
    const char *status = "INVALID";
    if (!read_nodes(argv[1], &nodes, &node_count) ||
        !read_rows(argv[2], nodes, node_count, true, (void **)&bindings, &binding_count) ||
        !read_rows(argv[3], nodes, node_count, false, (void **)&goals, &goal_count)) goto done;
    uint64_t maximum = (uint64_t)node_count + 3 * (uint64_t)binding_count + 4 * (uint64_t)goal_count + 4;
    if (maximum > UINT32_MAX) { resource_failure = true; reject("IR node budget overflow"); goto done; }
    IrLimits limits = {(uint32_t)maximum, (uint32_t)maximum, 1, 1, 4};
    module = ir_module_create(&limits);
    values = calloc((size_t)node_count + 1, sizeof(*values));
    terms = calloc((size_t)(goal_count > binding_count ? goal_count : binding_count) + 1, sizeof(*terms));
    parameters = calloc((size_t)binding_count + 1, sizeof(*parameters));
    if (!module || !values || !terms || !parameters) { resource_failure = true; reject("IR allocation"); goto done; }
    IrBlockId block = ir_block_add(module);
    if (!block || !ir_module_set_entry(module, block)) { reject("IR block allocation"); goto done; }
    /* Predeclare source inputs to avoid searching a large body for INPUT keys. */
    for (uint32_t i = 0; i < binding_count; ++i) {
        Binding binding = bindings[i]; Producer node = nodes[binding.id];
        values[binding.id] = emit(module, block, IR_OP_INPUT, node.bits, 0, 0, 0, binding.id, node.origin);
        parameters[i] = (IrSmtParameter){.key = binding.id, .width = node.bits,
            .observed = {.value = binding.value, .known_mask = binding.mask},
            /* The wrapper admits SOURCE110 only after the corresponding
             * original producer equality has passed an UNSAT proof. */
            .symbolic = node.op != 110};
        if (!values[binding.id]) { reject("IR source input build"); goto done; }
    }
    for (uint32_t i = 1; i <= node_count; ++i) {
        Producer p = nodes[i];
        if (source_op(p.op)) continue;
        uint64_t immediate = p.op == IR_OP_UNKNOWN && !p.immediate ? IR_REASON_UNDEFINED : p.immediate;
        values[i] = emit(module, block, (IrOpcode)p.op, p.bits, values[p.a], values[p.b], values[p.c], immediate, p.origin);
        if (!values[i]) { reject("IR producer build"); goto done; }
    }
    for (uint32_t i = 0; i < binding_count; ++i) {
        Binding p = bindings[i];
        IrValueId expected = constant(module, block, nodes[p.id].bits, p.value);
        terms[i] = emit(module, block, IR_OP_EQ, 1, values[p.id], expected, 0, 0, 0);
    }
    IrValueId premise = reduce_terms(module, block, IR_OP_AND, terms, binding_count);
    for (uint32_t i = 0; i < goal_count; ++i) {
        Goal goal = goals[i];
        IrValueId expected = constant(module, block, nodes[goal.id].bits, goal.expected);
        IrValueId equal = emit(module, block, IR_OP_EQ, 1, values[goal.id], expected, 0, 0, 0);
        terms[i] = emit(module, block, IR_OP_NOT, 1, equal, 0, 0, 0, 0);
    }
    IrValueId bad = reduce_terms(module, block, IR_OP_OR, terms, goal_count);
    if (!premise || !bad || !ir_block_terminate(module, block, (IrTerminator){.kind = IR_TERM_FRAGMENT_END}) ||
        !ir_validate(module, NULL)) { reject("IR producer validation"); goto done; }
    IrValueId retained[] = {premise, bad, values[goals[0].id]};
    IrSmtOptions options = ir_smt_default_options();
    options.parameters = parameters; options.parameter_count = binding_count;
    options.retained_values_only = true; options.retained_values = retained; options.retained_value_count = 3;
    options.limits.work = UINT64_C(500000000);
    options.limits.constructors = UINT64_C(60000000);
    options.limits.bytes = (size_t)512 * 1024 * 1024;
    smt = ir_smt_build(module, NULL, &options, &info);
    if (!smt) {
        resource_failure = info.status == IR_RESOURCE_LIMIT || info.status == IR_OUT_OF_MEMORY;
        reject(info.message ? info.message : "SMT build failure"); goto done;
    }
    IrSmtQueryLimits query = ir_smt_default_query_limits();
    query.work = UINT64_C(10000000); query.timeout_ms = 120000; query.rlimit = 500000000;
    query.bytes = (size_t)32 * 1024 * 1024;
    IrSmtConstraint constraints[] = {{premise, 1, 1}, {bad, 1, 1}};
    baseline_attempted = true;
    baseline = ir_smt_query(smt, constraints, 1, &retained[2], 1, &query);
    if (baseline.status != IR_SMT_SAT) {
        status = baseline.status == IR_SMT_UNSAT ? "INVALID" : "UNKNOWN";
        reject(baseline.status == IR_SMT_UNSAT ? "Contradictory source premises" : "Source-premise query did not return SAT");
        valid = true; goto done;
    }
    counterexample_attempted = true;
    counterexample = ir_smt_query(smt, constraints, 2, &retained[2], 1, &query);
    status = counterexample.status == IR_SMT_UNSAT ? "PROVED" :
             counterexample.status == IR_SMT_SAT ? "COUNTEREXAMPLE" : "UNKNOWN";
    if (counterexample.status != IR_SMT_UNSAT) reject(counterexample.status == IR_SMT_SAT ?
        "Source-constrained producer counterexample exists" : "Counterexample query did not return UNSAT");
    valid = true;
done:
    if (smt) info = ir_smt_info(smt);
    if (!valid && module && (ir_module_status(module) == IR_RESOURCE_LIMIT ||
                            ir_module_status(module) == IR_OUT_OF_MEMORY)) {
        resource_failure = true; diagnostic = ir_module_error(module);
    }
    if (!valid && resource_failure) status = "UNKNOWN";
    FILE *report = fopen(argv[4], "w");
    if (!report) { fprintf(stderr, "Cannot write SMT report\n"); valid = false; }
    else {
        fprintf(report, "{\"schema_version\":1,\"status\":"); json_string(report, status);
        fputs(",\"diagnostic\":", report); json_string(report, diagnostic);
        fputs(",\"z3_version\":", report); json_string(report, Z3_get_full_version());
        uint32_t lemma_count = 0;
        for (uint32_t i = 0; nodes && i < binding_count; ++i)
            if (nodes[bindings[i].id].op == 110) ++lemma_count;
        fprintf(report, ",\"producer_nodes\":%u,\"source_premises\":%u,\"goals\":%u,"
            "\"original_source_premises\":%u,\"previously_proved_lemma_premises\":%u,\"proof_mode\":\"%s\","
            "\"original_source_inputs_symbolic_before_premises\":true,"
            "\"proved_lemma_values_substituted\":%s,\"lemma_inputs_symbolic\":false,"
            "\"source_leaf_authentication\":\"caller\","
            "\"candidate_only_in_goals\":true,\"observed_checkpoint_used_as_premise\":false,"
            "\"model_built_by_existing_ir_smt\":%s,\"baseline\":", node_count, binding_count, goal_count,
            binding_count - lemma_count, lemma_count, allow_lemma_inputs ? "lemma_chunk" : "source_dag",
            allow_lemma_inputs ? "true" : "false",
            smt ? "true" : "false");
        query_json(report, &baseline, baseline_attempted);
        fputs(",\"counterexample\":", report); query_json(report, &counterexample, counterexample_attempted);
        fprintf(report, ",\"smt_build\":{\"status\":%u,\"work\":%" PRIu64 ",\"constructors\":%" PRIu64
            ",\"lowered_values\":%u,\"symbolic_parameters\":%u,\"message\":", info.status, info.work,
            info.constructors, info.lowered_values, info.symbolic_parameters);
        json_string(report, info.message); fputs("},\"z3_error\":", report);
        ir_smt_z3_error_report_json(report, &info.z3_error);
        fputs(",\"smt_lifetime\":", report); ir_smt_lifetime_report_json(report, &info);
        fputs(",\"opcode_counts\":{", report);
        uint32_t counts[111] = {0};
        for (uint32_t i = 1; nodes && i <= node_count; ++i) ++counts[nodes[i].op];
        bool comma = false;
        for (unsigned op = 0; op <= 110; ++op) {
            if (counts[op]) { fprintf(report, "%s\"%u\":%u", comma ? "," : "", op, counts[op]); comma = true; }
        }
        fputc('}', report);
        fputs("}\n", report);
        if (fclose(report)) valid = false;
    }
    ir_smt_answer_destroy(&baseline); ir_smt_answer_destroy(&counterexample);
    ir_smt_destroy(smt); ir_module_destroy(module);
    free(nodes); free(bindings); free(goals); free(values); free(terms); free(parameters);
    if (!valid && !resource_failure) fprintf(stderr, "%s\n", diagnostic);
    return valid || resource_failure ? 0 : 1;
}
