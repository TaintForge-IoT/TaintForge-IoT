#define _GNU_SOURCE
#include "phase1_io.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef TF_PHASE1_BUILD_ID
#define TF_PHASE1_BUILD_ID "unidentified-build"
#endif

char *tf_json_string(const char *text) {
    if (!text)
        return g_strdup("null");
    /* Public text is UTF-8; arbitrary guest bytes use tf_json_bytes_field. */
    if (!g_utf8_validate(text, -1, NULL))
        return g_strdup("null");
    GString *out = g_string_new("\"");
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        if (*p == '"' || *p == '\\')
            g_string_append_c(out, '\\');
        if (*p < 32)
            g_string_append_printf(out, "\\u%04x", *p);
        else
            g_string_append_c(out, *p);
    }
    g_string_append_c(out, '"');
    return g_string_free(out, FALSE);
}

char *tf_json_bytes_field(const char *key, const char *bytes) {
    char *quoted_key = tf_json_string(key);
    char *value = tf_json_string(bytes);
    char *out;
    if (bytes && !g_utf8_validate(bytes, -1, NULL)) {
        char *encoded = g_base64_encode((const guchar *)bytes, strlen(bytes));
        out = g_strdup_printf("%s:null,\"%s_bytes_base64\":\"%s\"", quoted_key, key, encoded);
        g_free(encoded);
    } else {
        out = g_strdup_printf("%s:%s", quoted_key, value);
    }
    g_free(value);
    g_free(quoted_key);
    return out;
}

bool tf_write_all(FILE *stream, const void *bytes, size_t count) {
    return stream && fwrite(bytes, 1, count, stream) == count && !ferror(stream);
}

bool tf_atomic_open(TfAtomicFile *file, const char *destination) {
    memset(file, 0, sizeof(*file));
    struct stat st;
    if (lstat(destination, &st) == 0 || errno != ENOENT)
        return false;
    file->destination = g_strdup(destination);
    file->temporary = g_strdup_printf("%s.part.XXXXXX", destination);
    int fd = g_mkstemp_full(file->temporary, O_RDWR | O_CLOEXEC, 0600);
    if (fd >= 0)
        file->stream = fdopen(fd, "wb");
    if (!file->stream) {
        if (fd >= 0)
            close(fd);
        tf_atomic_abort(file);
        return false;
    }
    return true;
}

void tf_atomic_abort(TfAtomicFile *file) {
    if (file->stream)
        fclose(file->stream);
    if (file->temporary)
        unlink(file->temporary);
    g_free(file->temporary);
    g_free(file->destination);
    memset(file, 0, sizeof(*file));
}

bool tf_atomic_commit(TfAtomicFile *file) {
    if (!file->stream)
        return false;
    bool ok = !ferror(file->stream);
    if (fflush(file->stream) != 0 || fsync(fileno(file->stream)) != 0)
        ok = false;
    if (fclose(file->stream) != 0)
        ok = false;
    file->stream = NULL;
    /* link publishes without overwriting any existing destination, including
     * a symlink. A failed commit never advertises the temporary as ready. */
    if (ok && link(file->temporary, file->destination) != 0)
        ok = false;
    tf_atomic_abort(file);
    return ok;
}

bool tf_file_digest(const char *path, char digest[65], uint64_t *size) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    struct stat st;
    if (fd < 0)
        return false;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode)) {
        close(fd);
        return false;
    }
    GChecksum *sum = g_checksum_new(G_CHECKSUM_SHA256);
    unsigned char data[16384];
    uint64_t count = 0;
    ssize_t got;
    while ((got = read(fd, data, sizeof(data))) > 0) {
        g_checksum_update(sum, data, got);
        count += (uint64_t)got;
    }
    bool ok = got == 0;
    if (close(fd))
        ok = false;
    if (ok) {
        memcpy(digest, g_checksum_get_string(sum), 65);
        *size = count;
    }
    g_checksum_free(sum);
    return ok;
}

static bool valid_id(const char *s) {
    if (!s || !*s || strlen(s) > 120)
        return false;
    for (; *s; ++s)
        if (!g_ascii_isalnum(*s) && *s != '-' && *s != '_' && *s != '.')
            return false;
    return true;
}

static bool number(const char *value, uint64_t *out, uint64_t maximum) {
    if (!*value || !g_ascii_isdigit(*value))
        return false;
    char *end;
    errno = 0;
    guint64 n = g_ascii_strtoull(value, &end, 10);
    if (errno || *end || n == 0 || n > maximum)
        return false;
    *out = n;
    return true;
}

bool tf_phase1_configure(TfPhase1Io *io, int argc, char **argv) {
    memset(io, 0, sizeof(*io));
    io->owner = getpid();
    io->max_events = 10000;
    io->max_dump_bytes = UINT64_C(256) * 1024 * 1024;
    io->max_candidates = 1024;
    io->selection_delay = 200000;
    io->max_capture_bytes = UINT64_C(64) * 1024 * 1024;
    for (int i = 0; i < argc; ++i) {
        if (!g_str_has_prefix(argv[i], "tf-"))
            continue;
        io->enabled = true;
        const char *eq = strchr(argv[i], '=');
        if (!eq || !eq[1])
            goto invalid;
        size_t len = eq - argv[i];
        const char *value = eq + 1;
#define OPTION(name) (len == sizeof(name) - 1 && !memcmp(argv[i], name, len))
        char **slot = NULL;
        if (OPTION("tf-session-id"))
            slot = &io->session;
        else if (OPTION("tf-attempt-id"))
            slot = &io->attempt;
        else if (OPTION("tf-instance-id"))
            slot = &io->instance;
        else if (OPTION("tf-events"))
            slot = &io->events_path;
        else if (OPTION("tf-manifest"))
            slot = &io->manifest_path;
        else if (OPTION("tf-dump"))
            slot = &io->dump_path;
        else if (OPTION("tf-report"))
            slot = &io->report_path;
        else if (OPTION("tf-ir-report"))
            slot = &io->ir_path;
        else if (OPTION("tf-capture")) {
            if (strcmp(value, "entry") && strcmp(value, "exit"))
                goto invalid;
            io->capture_at_entry = !strcmp(value, "entry");
        } else if (OPTION("tf-max-capture-bytes")) {
            if (!number(value, &io->max_capture_bytes, UINT64_C(1024) * 1024 * 1024))
                goto invalid;
        }
        else if (OPTION("tf-require-flags")) {
            if (strcmp(value, "on") && strcmp(value, "off"))
                goto invalid;
            io->flags_required = !strcmp(value, "on");
        } else if (OPTION("tf-max-events")) {
            if (!number(value, &io->max_events, 1000000))
                goto invalid;
        } else if (OPTION("tf-max-dump-bytes")) {
            if (!number(value, &io->max_dump_bytes, UINT64_C(1024) * 1024 * 1024))
                goto invalid;
        } else if (OPTION("tf-max-candidates")) {
            if (!number(value, &io->max_candidates, 10000))
                goto invalid;
        } else if (OPTION("tf-selection-delay")) {
            if (!number(value, &io->selection_delay, 100000000))
                goto invalid;
        } else
            goto invalid;
        if (slot) {
            if (*slot)
                goto invalid;
            *slot = g_strdup(value);
        }
#undef OPTION
    }
    if (!io->enabled) {
        io->dump_path = g_strdup("unpacked.bin");
        io->report_path = g_strdup("unpacked.json");
        return true;
    }
    if (!valid_id(io->session) || !valid_id(io->attempt) || !valid_id(io->instance))
        goto invalid;
    char *paths[] = {io->events_path, io->manifest_path, io->dump_path, io->report_path,
                     io->ir_path};
    for (size_t i = 0; i < G_N_ELEMENTS(paths); ++i) {
        if (!paths[i] || !g_path_is_absolute(paths[i]) || !g_utf8_validate(paths[i], -1, NULL))
            goto invalid;
        char *canonical = g_canonicalize_filename(paths[i], NULL);
        bool same = !strcmp(canonical, paths[i]);
        g_free(canonical);
        if (!same)
            goto invalid;
        struct stat st;
        if (lstat(paths[i], &st) == 0 || errno != ENOENT)
            goto invalid;
        for (size_t j = 0; j < i; ++j)
            if (!strcmp(paths[i], paths[j]))
                goto invalid;
    }
    int fd = open(io->events_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0)
        goto invalid;
    io->events = fdopen(fd, "w");
    if (!io->events) {
        close(fd);
        goto invalid;
    }
    return true;
invalid:
    fprintf(stderr,
            "[PHASE1] invalid identity, output path, limit or unavailable output directory\n");
    io->storage_failed = true;
    return false;
}

bool tf_phase1_event(TfPhase1Io *io, const char *type, const char *status, const char *reason,
                     const char *payload) {
    if (!io->enabled)
        return true;
    if (getpid() != io->owner || !io->events || io->finished)
        return false;
    bool terminal = !strcmp(type, "analysis_finished") || !strcmp(type, "data_loss");
    if (!terminal && io->event_seq >= io->max_events) {
        ++io->dropped_events;
        if (io->dropped_events == 1)
            tf_phase1_event(io, "data_loss", "partial", "event_budget_exhausted",
                            "{\"dropped_events_at_least\":1}");
        return false;
    }
    char *qreason = tf_json_string(reason);
    GString *line = g_string_new(NULL);
    g_string_append_printf(
        line,
        "{\"schema_version\":1,\"event_type\":\"%s\",\"session_id\":\"%s\","
        "\"attempt_id\":\"%s\",\"analysis_instance_id\":\"%s\","
        "\"event_id\":\"%s:%" PRIu64 "\",\"event_seq\":%" PRIu64 ","
        "\"guest_asid\":null,\"vcpu_id\":%u,\"guest_tid\":null,"
        "\"trace_seq\":%" PRIu64 ",\"code_generation\":%u,\"analysis_epoch\":%" PRIu64 ","
        "\"current_pc\":%" PRIu64 ",\"monotonic_us\":%" G_GINT64_FORMAT ","
        "\"evidence_refs\":[],\"status\":\"%s\",\"incomplete_reasons\":[%s],\"data\":%s}\n",
        type, io->session, io->attempt, io->instance, io->instance, io->event_seq + 1,
        io->event_seq + 1, io->vcpu, io->trace_seq, io->generation, io->epoch, io->pc,
        g_get_monotonic_time(), status, reason ? qreason : "", payload ? payload : "{}");
    g_free(qreason);
    bool ok = line->len <= 32768 && tf_write_all(io->events, line->str, line->len);
    if (ok && fflush(io->events))
        ok = false;
    g_string_free(line, TRUE);
    if (!ok)
        io->storage_failed = true;
    else
        ++io->event_seq;
    return ok;
}

bool tf_phase1_start(TfPhase1Io *io, const char *target, bool system, unsigned api, bool flags,
                     bool ir) {
    if (!io->enabled)
        return true;
    bool supported = !strcmp(target, "i386") && !system;
    const char *reason = !supported                     ? "unsupported_profile"
                         : io->flags_required && !flags ? "flag_observations_unverified"
                                                        : NULL;
    if (ir && !flags)
        io->analysis_incomplete = true;
    char *qtarget = tf_json_string(target);
    char *payload = g_strdup_printf(
        "{\"build_id\":\"%s\",\"target\":%s,\"mode\":\"%s\",\"plugin_api\":%u,"
        "\"profile\":\"linux-i386-single-thread-v1\",\"flags_contract\":\"%s\","
        "\"ir_enabled\":%s,\"runtime_load\":\"observed\",\"register_observation\":\"pending\","
        "\"max_guest_processes\":1,\"max_guest_threads\":1,\"event_schema\":1,\"report_schema\":1,"
        "\"checkpoint\":\"unsupported\",\"external_memory_write\":\"unsupported\","
        "\"provenance_export\":\"unsupported\",\"analysis_detach\":\"unsupported\","
        "\"control_channel_protection\":\"unverified\",\"capture_scope\":\"tracked_program_pages\","
        "\"event_transport\":\"regular_file\",\"callback_storage_io\":\"synchronous\","
        "\"ir_match_scope\":\"selected_trace_window_only\",\"oep_policy\":\"heuristic_candidate\"}",
        TF_PHASE1_BUILD_ID, qtarget, system ? "system" : "linux-user", api,
        flags ? "taintforge_x86_flags_v1" : "unverified", ir ? "true" : "false");
    bool written = tf_phase1_event(io, "analysis_started", reason ? "unsupported" : "observing",
                                   reason, payload);
    g_free(qtarget);
    g_free(payload);
    return written && !reason;
}

bool tf_phase1_active(const TfPhase1Io *io) {
    return !io->enabled ||
           (getpid() == io->owner && !__atomic_load_n(&io->profile_lost, __ATOMIC_ACQUIRE));
}

void tf_phase1_profile_lost(TfPhase1Io *io, const char *reason) {
    if (!io->enabled || getpid() != io->owner)
        return;
    const char *expected = NULL;
    if (!__atomic_compare_exchange_n(&io->profile_reason, &expected, reason, false,
                                     __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return;
    /* A second-vCPU callback may call here. It must not touch the first
     * collector's coordinates or event stream. Finalization reports the loss. */
    __atomic_store_n(&io->profile_lost, true, __ATOMIC_RELEASE);
}

bool tf_phase1_finish(TfPhase1Io *io, const char *capture_status) {
    if (!io->enabled || getpid() != io->owner)
        return true;
    if (io->profile_lost)
        tf_phase1_event(io, "profile_lost", "unsupported", io->profile_reason, NULL);
    if (io->dropped_events) {
        char *payload = g_strdup_printf("{\"dropped_events\":%" PRIu64 "}", io->dropped_events);
        tf_phase1_event(io, "data_loss", "partial", "event_budget_exhausted", payload);
        g_free(payload);
    }
    char *payload =
        g_strdup_printf("{\"capture_status\":\"%s\",\"storage_status\":\"%s\","
                        "\"dropped_events\":%" PRIu64 "}",
                        capture_status, io->storage_failed ? "error" : "ok", io->dropped_events);
    bool ok = tf_phase1_event(io, "analysis_finished",
                              io->storage_failed ? "error"
                              : io->profile_lost || io->dropped_events || io->analysis_incomplete
                                  ? "partial"
                                  : "completed",
                              io->profile_reason, payload);
    g_free(payload);
    io->finished = true;
    if (io->events) {
        if (fflush(io->events) || fsync(fileno(io->events)))
            ok = false;
        if (fclose(io->events))
            ok = false;
        io->events = NULL;
    }
    if (!ok)
        io->storage_failed = true;
    return ok;
}

void tf_phase1_destroy(TfPhase1Io *io) {
    if (io->events)
        fclose(io->events);
    g_free(io->session);
    g_free(io->attempt);
    g_free(io->instance);
    g_free(io->events_path);
    g_free(io->manifest_path);
    g_free(io->dump_path);
    g_free(io->report_path);
    g_free(io->ir_path);
    memset(io, 0, sizeof(*io));
}
