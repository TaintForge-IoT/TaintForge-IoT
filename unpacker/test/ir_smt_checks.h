#ifndef TAINTFORGE_IR_SMT_CHECKS_H
#define TAINTFORGE_IR_SMT_CHECKS_H
static uint64_t smt_monotonic_ns(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) return UINT64_MAX;
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}
static void smt_memory_snapshot(IrSmtMemory *m) {
    IrSmtZ3Error e = {0};
    smt_process_memory(&e);
    *m = (IrSmtMemory){e.vm_size_kib, e.vm_peak_kib, e.vm_rss_kib, e.vm_hwm_kib,
                       e.vm_swap_kib, Z3_get_estimated_alloc_size()};
}
static bool smt_statistics(IrSmt *s, Z3_solver solver, IrSmtStatistics *out) {
    Z3_stats stats = Z3_solver_get_statistics(s->ctx, solver);
    if (!z3_result(s, stats != NULL, "Z3_solver_get_statistics")) return false;
    Z3_stats_inc_ref(s->ctx, stats);
    if (!z3_ok(s, "Z3_stats_inc_ref")) return false;
    out->total = Z3_stats_size(s->ctx, stats);
    if (!z3_ok(s, "Z3_stats_size")) goto done;
    out->truncated = out->total > IR_SMT_STATS_CAPACITY;
    for (uint32_t i = 0; i < out->total && i < IR_SMT_STATS_CAPACITY; ++i) {
        IrSmtStatistic *v = &out->entries[i];
        const char *key = Z3_stats_get_key(s->ctx, stats, i);
        if (!z3_result(s, key != NULL, "Z3_stats_get_key")) goto done;
        v->key_truncated = smt_copy_text(v->key, sizeof(v->key), key);
        v->is_uint = Z3_stats_is_uint(s->ctx, stats, i);
        if (!z3_ok(s, "Z3_stats_is_uint")) goto done;
        if (v->is_uint) {
            v->uint_value = Z3_stats_get_uint_value(s->ctx, stats, i);
            if (!z3_ok(s, "Z3_stats_get_uint_value")) goto done;
        } else {
            bool is_double = Z3_stats_is_double(s->ctx, stats, i);
            if (!z3_ok(s, "Z3_stats_is_double")) goto done;
            if (!is_double) { fail(s, IR_INVALID, "unknown Z3 statistic type"); goto done; }
            v->double_value = Z3_stats_get_double_value(s->ctx, stats, i);
            if (!z3_ok(s, "Z3_stats_get_double_value")) goto done;
        }
        ++out->count;
    }
    out->available = true;
done:
    Z3_stats_dec_ref(s->ctx, stats);
    return s->info.status == IR_OK && z3_ok(s, "Z3_stats_dec_ref");
}
static bool smt_stat_uint(const IrSmtStatistics *s, const char *key, uint64_t *value) {
    if (!s->available) return false;
    for (uint32_t i = 0; i < s->count; ++i)
        if (!s->entries[i].key_truncated && s->entries[i].is_uint && !strcmp(s->entries[i].key, key)) {
            *value = s->entries[i].uint_value;
            return true;
        }
    return false;
}
static void smt_check_indicators(IrSmtCheck *c) {
    uint64_t before, after;
    if (smt_stat_uint(&c->statistics_before, "rlimit count", &before) &&
        smt_stat_uint(&c->statistics_after, "rlimit count", &after) && after >= before) {
        c->rlimit_delta_available = true;
        c->rlimit_delta = after - before;
        c->rlimit_delta_reached = c->rlimit_delta >= c->rlimit;
    }
    c->timeout_elapsed = c->clock_available && c->elapsed_ns >= (uint64_t)c->timeout_ms * 1000000;
}
static void smt_memory_json(FILE *f, const IrSmtMemory *m) {
    fputs("{\"units\":\"KiB_except_z3_bytes\"", f);
    smt_json_metric(f, "vm_size_kib", m->vm_size_kib);
    smt_json_metric(f, "vm_peak_kib", m->vm_peak_kib);
    smt_json_metric(f, "vm_rss_kib", m->vm_rss_kib);
    smt_json_metric(f, "vm_hwm_kib", m->vm_hwm_kib);
    smt_json_metric(f, "vm_swap_kib", m->vm_swap_kib);
    smt_json_metric(f, "z3_estimated_alloc_bytes", m->z3_estimated_alloc_bytes);
    fputc('}', f);
}
static void smt_statistics_json(FILE *f, const IrSmtStatistics *s) {
    fprintf(f, "{\"available\":%s,\"total\":%u,\"truncated\":%s,\"entries\":[",
            s->available ? "true" : "false", s->total, s->truncated ? "true" : "false");
    for (uint32_t i = 0; i < s->count; ++i) {
        const IrSmtStatistic *v = &s->entries[i];
        if (i) fputc(',', f);
        fputs("{\"key\":", f); smt_json_string(f, v->key);
        fprintf(f, ",\"key_truncated\":%s,\"kind\":\"%s\",\"value\":",
                v->key_truncated ? "true" : "false", v->is_uint ? "uint" : "double");
        if (v->is_uint) fprintf(f, "%" PRIu64, v->uint_value);
        else if (isfinite(v->double_value)) fprintf(f, "%.17g", v->double_value);
        else fputs("null", f);
        fputc('}', f);
    }
    fputs("]}", f);
}
bool ir_smt_checks_report_json(FILE *f, const IrSmtAnswer *a) {
    if (!f || !a) return false;
    fputc('[', f); bool comma = false;
    for (unsigned i = 0; i < 2; ++i) {
        const IrSmtCheck *c = &a->checks[i];
        if (!c->recorded) continue;
        if (comma) fputc(',', f);
        comma = true;
        fprintf(f, "{\"pass\":\"%s\",\"returned\":%s,\"result\":", i ? "possible" : "certain", c->returned ? "true" : "false");
        if (!c->returned) fputs("null", f);
        else smt_json_string(f, !c->api_ok ? "API_ERROR" : c->result == 1 ? "SAT" : c->result == -1 ? "UNSAT" : "UNKNOWN");
        fprintf(f, ",\"timeout_ms\":%u,\"rlimit\":%u", c->timeout_ms, c->rlimit);
        smt_json_metric(f, "elapsed_ns", c->clock_available ? c->elapsed_ns : UINT64_MAX);
        fputs(",\"reason_unknown\":", f); smt_json_string(f, c->reason_unknown);
        fprintf(f, ",\"reason_truncated\":%s,\"timeout_elapsed\":%s,\"rlimit_delta_reached\":%s",
                c->reason_truncated ? "true" : "false", c->timeout_elapsed ? "true" : "false",
                c->rlimit_delta_reached ? "true" : "false");
        smt_json_metric(f, "rlimit_delta", c->rlimit_delta_available ? c->rlimit_delta : UINT64_MAX);
        fputs(",\"memory_before\":", f); smt_memory_json(f, &c->before);
        fputs(",\"memory_after\":", f); smt_memory_json(f, &c->after);
        fputs(",\"statistics_before\":", f); smt_statistics_json(f, &c->statistics_before);
        fputs(",\"statistics_after\":", f); smt_statistics_json(f, &c->statistics_after);
        fputc('}', f);
    }
    fputc(']', f);
    return !ferror(f);
}
bool ir_smt_lifetime_report_json(FILE *f, const IrSmtInfo *s) {
    if (!f || !s) return false;
    fprintf(f, "{\"reference_counted\":%s,\"retained_values_only\":%s,"
            "\"references_acquired\":%" PRIu64 ",\"references_released\":%" PRIu64
            ",\"temporary_peak\":%" PRIu64 ",\"values_live\":%" PRIu64
            ",\"values_peak\":%" PRIu64 ",\"values_released\":%" PRIu64
            ",\"values_compacted\":%s,\"value_table_bytes\":%" PRIu64 ",\"value_index_bytes\":%" PRIu64 "}",
            s->reference_counted ? "true" : "false", s->retained_values_only ? "true" : "false",
            s->references_acquired, s->references_released, s->temporary_peak,
            s->values_live, s->values_peak, s->values_released,
            s->values_compacted ? "true" : "false", s->value_table_bytes, s->value_index_bytes);
    return !ferror(f);
}
#endif
