/* Tests the actual Phase 1 owners and destructor, without a QEMU scheduler.
 * Unused guest/QEMU paths are removed by --gc-sections, not stubbed to succeed. */
#include <assert.h>
#include <fcntl.h>
#include "../../unpacker/test/qemu_unpacker.c"

int main(int argc, char **argv) {
    char concolic_report[] = "/tmp/tf-concolic-report-XXXXXX";
    char concolic_seed[] = "/tmp/tf-concolic-seed-XXXXXX";
    char digest_before[65], digest_after[65];
    uint64_t size_before = 0, size_after = 0;
    bool partial = argc > 1 && strstr(argv[1], "partial");
    bool m4 = argc > 1 && !strncmp(argv[1], "m4-", 3);
    if (m4) {
        char *options[] = {"m4-memory-bytes=536870912"};
        assert(tf_resources_configure(1, options));
    }
    g_phase1.owner = getpid();
    g_phase1.session = g_strdup("release-test");
    g_phase1.dump_path = g_strdup("owned-path");
    g_phase1.events = tmpfile();
    int owned_fd = fileno(g_phase1.events);
    int guest_fd = open("/dev/null", O_RDONLY);
    assert(guest_fd >= 0);
    assert(provenance_runtime_init(32));
    PluginVcpuState *vcpu = plugin_vcpu_state_get(0);
    assert(vcpu);
    vcpu->register_scratch = g_byte_array_new();
    vcpu->flags_scratch = g_byte_array_new();
    g_byte_array_append(vcpu->register_scratch, (const guint8 *)"REGS", 4);
    g_byte_array_append(vcpu->flags_scratch, (const guint8 *)"FLAG", 4);
    pages = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, page_destroy);
    for (unsigned i = 1; i <= 3; i++) {
        page_t *page = g_new0(page_t, 1);
        page->wbitmap = g_malloc0(page_size / 8U);
        memset(page->wbitmap, 0xab, page_size / 8U);
        g_hash_table_insert(pages, GUINT_TO_POINTER(i * 4096), page);
    }
    /* Removing a page now and destroying the table later must free once. */
    assert(g_hash_table_remove(pages, GUINT_TO_POINTER(4096)));
    assert(g_released_pages == 1 && g_released_bitmaps == 1);
    g_oep_scoring = g_string_new("final scoring");
    saved_reg = g_string_new("captured region");
    g_capture_gaps = g_string_new("[]");
    if (!partial) {
        assert(cs_open(CS_ARCH_X86, CS_MODE_32, &cs_handle) == CS_ERR_OK);
        meta_init();
        InsnMeta *meta = g_new0(InsnMeta, 1);
        meta->size = 1;
        assert(meta_store(0x1000, meta));
        assert(insn_exec_contexts_init());
        g_ptr_array_add(g_insn_exec_contexts, g_new0(InsnExecCtx, 1));
        g_trace = trace_buffer_create(16);
        g_aux = dse_aux_create(16);
        g_branch_events = branch_event_buffer_create(16);
        g_dcfg = dcfg_graph_create(g_prov_registry);
        assert(g_trace && g_aux && g_branch_events && g_dcfg);
        dse_lift_attach(g_trace, g_aux, &dse_arch_x86);
        file_fd = g_hash_table_new(g_direct_hash, g_direct_equal);
        file_dep_t *file = g_new0(file_dep_t, 1);
        file->path = g_strdup("guest-file");
        file_deps = g_list_append(NULL, file);
        g_hash_table_insert(file_fd, GINT_TO_POINTER(guest_fd), file);
        lib_mapping_t *library = g_new0(lib_mapping_t, 1);
        library->path = g_strdup("guest-library");
        lib_deps = g_list_append(NULL, library);
        resolved_import_t *import = g_new0(resolved_import_t, 1);
        import->module = library->path;
        resolved_imports = g_list_append(NULL, import);
        resolved_imports_by_slot = g_hash_table_new(g_direct_hash, g_direct_equal);
        unmapped_pages = g_hash_table_new(g_direct_hash, g_direct_equal);
        g_sockets = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, net_dep_destroy);
        net_dep_t *reused = g_new0(net_dep_t, 1);
        reused->payload_hex = g_strdup("replaced metadata");
        g_hash_table_insert(g_sockets, GINT_TO_POINTER(guest_fd), reused);
        net_dep_t *socket = g_new0(net_dep_t, 1), *event = g_new0(net_dep_t, 1);
        socket->payload_hex = g_strdup("0011");
        event->payload_hex = g_strdup("2233");
        g_hash_table_insert(g_sockets, GINT_TO_POINTER(guest_fd), socket);
        net_deps = g_list_append(NULL, event);
        oep_cands = g_list_append(NULL, g_new0(oep_cand_t, 1));
        g_selected_candidate = oep_cands->data;
        g_selected_candidate->capture.path = g_strdup("unpublished-candidate");
        g_selected_candidate->capture.regions = g_string_new("[]");
        g_selected_candidate->capture.gaps = g_string_new("[]");
        int report_fd = mkstemp(concolic_report), seed_fd = mkstemp(concolic_seed);
        assert(report_fd >= 0 && seed_fd >= 0);
        assert(close(report_fd) == 0 && unlink(concolic_report) == 0);
        assert(write(seed_fd, "AB", 2) == 2 && close(seed_fd) == 0);
        char report_option[256], seed_option[256];
        snprintf(report_option, sizeof(report_option), "concolic-report=%s", concolic_report);
        snprintf(seed_option, sizeof(seed_option), "concolic-seed=%s", concolic_seed);
        char *options[] = {report_option, "concolic-branch=4096", "concolic-file=/input.bin",
                           seed_option, "concolic-offsets=0:1"};
        assert(tf_concolic_configure(&g_concolic, 5, options) && g_concolic);
        assert(tf_concolic_finish(g_concolic) && tf_concolic_finish(g_concolic));
        assert(tf_file_digest(concolic_report, digest_before, &size_before) && size_before > 0);
        pending_open_path = g_strdup("pending-guest-path");
    }
    phase1_release_owned();
    if (m4) assert(tf_resources_remaining() == 0);
    assert(phase1_owner_roots_remaining() == 0);
    assert(!g_selected_candidate && !g_tls_vcpu_state && !g_cur_aux);
    assert(!g_concolic);
    if (!partial) {
        assert(tf_file_digest(concolic_report, digest_after, &size_after));
        assert(size_before == size_after && !strcmp(digest_before, digest_after));
        assert(unlink(concolic_report) == 0 && unlink(concolic_seed) == 0);
    }
    assert(g_released_pages == 3 && g_released_bitmaps == 3);
    assert(g_released_register_buffers == 2);
    assert(fcntl(owned_fd, F_GETFD) == -1 && errno == EBADF);
    assert(fcntl(guest_fd, F_GETFD) >= 0);
    uint64_t wiped = g_explicitly_wiped_bytes;
    assert(wiped >= 3 * (page_size / 8U + sizeof(page_t)) + 8 + sizeof(PluginVcpuState));
    phase1_release_owned();
    assert(g_released_pages == 3 && g_explicitly_wiped_bytes == wiped);
    close(guest_fd);
    puts(partial ? "partial release OK" : "full release OK");
    return 0;
}
