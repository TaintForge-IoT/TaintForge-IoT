#include "runtime_diag.h"

#include <inttypes.h>
#include <limits.h>
#include <string.h>
#include <sys/resource.h>

static const char *const phase_names[TF_PHASE_COUNT] = {"instruction_callback",
                                                        "memory_callback",
                                                        "code_write_callback",
                                                        "translation_callback",
                                                        "syscall_callback",
                                                        "syscall_return_callback",
                                                        "control_flow",
                                                        "register_snapshot",
                                                        "archive",
                                                        "trace_capture",
                                                        "register_dta",
                                                        "initial_seed",
                                                        "ir_check",
                                                        "legacy_dse",
                                                        "dump",
                                                        "event_log",
                                                        "shutdown"};

void tf_runtime_diag_init(TfRuntimeDiag *diag) {
    if (!diag)
        return;
    memset(diag, 0, sizeof(*diag));
    diag->options.log = TF_LOG_SUMMARY;
    diag->start_us = (uint64_t)g_get_monotonic_time();
}

const char *tf_runtime_log_name(TfRuntimeLog level) {
    switch (level) {
    case TF_LOG_SUMMARY:
        return "summary";
    case TF_LOG_EVENTS:
        return "events";
    case TF_LOG_ROOTS:
        return "roots";
    }
    return "invalid";
}

const char *tf_runtime_phase_name(TfRuntimePhase phase) {
    return (unsigned)phase < TF_PHASE_COUNT ? phase_names[phase] : "invalid";
}

static bool parse_count(const char *s, uint64_t *value) {
    if (!s || !*s)
        return false;
    uint64_t n = 0;
    for (; *s; ++s) {
        if (*s < '0' || *s > '9' || n > (UINT64_MAX - (unsigned)(*s - '0')) / 10)
            return false;
        n = n * 10 + (unsigned)(*s - '0');
    }
    *value = n;
    return true;
}

bool tf_runtime_diag_options(TfRuntimeDiag *diag, int argc, char **argv, FILE *errors) {
    if (!diag || argc < 0 || (argc && !argv))
        return false;
    TfRuntimeDiagOptions options = diag->options;
    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg)
            return false;
        if (strncmp(arg, "runtime-", 8))
            continue;
        if (!strncmp(arg, "runtime-log=", 12)) {
            const char *value = arg + 12;
            if (!strcmp(value, "summary"))
                options.log = TF_LOG_SUMMARY;
            else if (!strcmp(value, "events"))
                options.log = TF_LOG_EVENTS;
            else if (!strcmp(value, "roots"))
                options.log = TF_LOG_ROOTS;
            else
                goto invalid;
        } else if (!strcmp(arg, "runtime-profile=on")) {
            options.profile = true;
        } else if (!strcmp(arg, "runtime-profile=off")) {
            options.profile = false;
        } else if (!strncmp(arg, "runtime-progress=", 17)) {
            if (!parse_count(arg + 17, &options.progress_interval))
                goto invalid;
        } else {
            goto invalid;
        }
        continue;
    invalid:
        if (errors)
            fprintf(errors, "[RUNTIME] invalid option: %s\n", arg);
        return false;
    }
    diag->options = options;
    diag->next_progress = options.progress_interval;
    return true;
}

static void counter_add(uint64_t *counter, uint64_t n) {
    uint64_t old = __atomic_load_n(counter, __ATOMIC_RELAXED);
    for (;;) {
        uint64_t value = n > UINT64_MAX - old ? UINT64_MAX : old + n;
        if (__atomic_compare_exchange_n(counter, &old, value, true, __ATOMIC_RELAXED,
                                        __ATOMIC_RELAXED))
            return;
    }
}

void tf_runtime_scope_end(TfRuntimeScope *scope) {
    if (!scope || !scope->diag || (unsigned)scope->phase >= TF_PHASE_COUNT)
        return;
    uint64_t now = (uint64_t)g_get_monotonic_time();
    uint64_t elapsed = now >= scope->start_us ? now - scope->start_us : 0;
    TfRuntimeMetric *metric = &scope->diag->phases[scope->phase];
    counter_add(&metric->calls, 1);
    counter_add(&metric->total_us, elapsed);
    uint64_t old = __atomic_load_n(&metric->max_us, __ATOMIC_RELAXED);
    while (old < elapsed && !__atomic_compare_exchange_n(&metric->max_us, &old, elapsed, true,
                                                         __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
    }
    scope->diag = NULL;
}

bool tf_runtime_progress_due(TfRuntimeDiag *diag, uint64_t instructions) {
    if (!diag || !diag->options.progress_interval)
        return false;
    uint64_t next = __atomic_load_n(&diag->next_progress, __ATOMIC_RELAXED);
    while (next && instructions >= next) {
        uint64_t future = diag->options.progress_interval > UINT64_MAX - instructions
                              ? 0
                              : instructions + diag->options.progress_interval;
        if (__atomic_compare_exchange_n(&diag->next_progress, &next, future, true, __ATOMIC_RELAXED,
                                        __ATOMIC_RELAXED))
            return true;
    }
    return false;
}

bool tf_runtime_profile_json(FILE *out, const TfRuntimeDiag *diag) {
    if (!out || !diag)
        return false;
    uint64_t now = (uint64_t)g_get_monotonic_time();
    fprintf(out,
            "{\"schema\":1,\"event\":\"runtime_profile\",\"enabled\":%s,"
            "\"timing\":\"inclusive_wall_us\",\"log\":\"%s\",\"wall_us\":%" PRIu64,
            diag->options.profile ? "true" : "false", tf_runtime_log_name(diag->options.log),
            now >= diag->start_us ? now - diag->start_us : 0);
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        fprintf(out,
                ",\"process_user_us\":%" PRIu64 ",\"process_system_us\":%" PRIu64
                ",\"process_max_rss_kib\":%ld",
                (uint64_t)usage.ru_utime.tv_sec * UINT64_C(1000000) + usage.ru_utime.tv_usec,
                (uint64_t)usage.ru_stime.tv_sec * UINT64_C(1000000) + usage.ru_stime.tv_usec,
                usage.ru_maxrss);
    }
    fputs(",\"phases\":{", out);
    for (unsigned i = 0; i < TF_PHASE_COUNT; ++i) {
        const TfRuntimeMetric *metric = &diag->phases[i];
        fprintf(out,
                "%s\"%s\":{\"calls\":%" PRIu64 ",\"total_us\":%" PRIu64 ",\"max_us\":%" PRIu64 "}",
                i ? "," : "", phase_names[i], __atomic_load_n(&metric->calls, __ATOMIC_RELAXED),
                __atomic_load_n(&metric->total_us, __ATOMIC_RELAXED),
                __atomic_load_n(&metric->max_us, __ATOMIC_RELAXED));
    }
    fputs("}}\n", out);
    return !ferror(out);
}
