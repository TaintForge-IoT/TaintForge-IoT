#ifndef TAINTFORGE_PROVENANCE_H
#define TAINTFORGE_PROVENANCE_H

#ifndef TF_CAPTURE_FASTPATH
#define TF_CAPTURE_FASTPATH 1
#endif
#if TF_CAPTURE_FASTPATH != 0 && TF_CAPTURE_FASTPATH != 1
#error "TF_CAPTURE_FASTPATH must be zero or one"
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
typedef uint32_t ProvResourceId;
typedef uint32_t ProvRootId;
typedef uint32_t ProvRootSetId;
typedef uint32_t ProvLabelId;
typedef uint32_t ProvOpenFileDescriptionId;

#define PROV_RESOURCE_ID_INVALID ((ProvResourceId)0)
#define PROV_ROOT_ID_INVALID ((ProvRootId)0)
#define PROV_ROOT_SET_EMPTY ((ProvRootSetId)0)
#define PROV_ROOT_SET_ID_INVALID UINT32_MAX
#define PROV_LABEL_CLEAN ((ProvLabelId)0)
#define PROV_LABEL_UNKNOWN ((ProvLabelId)1)
#define PROV_LABEL_ID_INVALID UINT32_MAX
#define PROV_OFD_ID_INVALID ((ProvOpenFileDescriptionId)0)

#define PROV_DEFAULT_MAX_ROOTS_PER_SET UINT32_C(4096)

#ifndef TF_PROV_FASTPATH
#define TF_PROV_FASTPATH 1
#endif

typedef enum {
    PROV_RESOURCE_INVALID = 0,
    PROV_RESOURCE_FILE,
    PROV_RESOURCE_STREAM,
    PROV_RESOURCE_DATAGRAM,
    PROV_RESOURCE_MEMORY_BUFFER,
    PROV_RESOURCE_PROCESS_INPUT,
    PROV_RESOURCE_SYSTEM_VALUE
} ProvResourceKind;

enum {
    PROV_RESOURCE_ROLE_NONE = 0,
    PROV_RESOURCE_ROLE_MAIN_IMAGE = 1U << 0,
    PROV_RESOURCE_ROLE_LIBRARY_IMAGE = 1U << 1,
    PROV_RESOURCE_ROLE_FUZZ_INPUT = 1U << 2,
    PROV_RESOURCE_ROLE_ENVIRONMENT = 1U << 3,
    PROV_RESOURCE_ROLE_NETWORK = 1U << 4,
    PROV_RESOURCE_ROLE_GENERATED = 1U << 5
};

typedef struct {
    ProvResourceKind kind;
    uint64_t scope_id;
    uint64_t object_id;
    uint64_t semantic_version;
} ProvResourceKey;

typedef struct {
    ProvResourceKey key;
    uint32_t roles;
    const char *display_name;
} ProvResourceView;

typedef enum {
    PROV_ROOT_INVALID = 0,
    PROV_ROOT_RESOURCE_BYTE,
    PROV_ROOT_ARGV_BYTE,
    PROV_ROOT_ENV_BYTE,
    PROV_ROOT_AUXV_BYTE,
    PROV_ROOT_SYSCALL_VALUE_BYTE,
    PROV_ROOT_INITIAL_REGISTER_BYTE,
    PROV_ROOT_BOUNDARY_MEMORY_BYTE
} ProvRootKind;

typedef struct {
    ProvRootKind kind;
    uint64_t source_id;
    uint32_t discriminator;
    uint64_t offset;
    uint64_t semantic_instance;
} ProvRootKey;

typedef enum {
    PROV_CHANNEL_DATA = 0,
    PROV_CHANNEL_ADDRESS = 1
} ProvChannel;

enum {
    PROV_COMPLETE_NONE = 0,
    PROV_COMPLETE_DATA = 1U << 0,
    PROV_COMPLETE_ADDRESS = 1U << 1,
    PROV_COMPLETE_ALL = PROV_COMPLETE_DATA | PROV_COMPLETE_ADDRESS
};

enum {
    PROV_INCOMPLETE_NONE = UINT64_C(0),
    PROV_INCOMPLETE_UNKNOWN = UINT64_C(1) << 0,
    PROV_INCOMPLETE_UNSUPPORTED_INSTRUCTION = UINT64_C(1) << 1,
    PROV_INCOMPLETE_IMPLICIT_OPERAND = UINT64_C(1) << 2,
    PROV_INCOMPLETE_UNRESOLVED_MEMORY = UINT64_C(1) << 3,
    PROV_INCOMPLETE_UNMODELED_SYSCALL = UINT64_C(1) << 4,
    PROV_INCOMPLETE_SOURCE_IDENTITY = UINT64_C(1) << 5,
    PROV_INCOMPLETE_ROOT_SET_BUDGET = UINT64_C(1) << 6,
    PROV_INCOMPLETE_UNDEFINED_FLAG = UINT64_C(1) << 7,
    PROV_INCOMPLETE_TRACE_TRUNCATED = UINT64_C(1) << 8,
    PROV_INCOMPLETE_CROSS_THREAD_STATE = UINT64_C(1) << 9
};

typedef struct {
    ProvRootSetId data_roots;
    ProvRootSetId address_roots;
    uint8_t complete_mask;
    uint64_t incomplete_reasons;
} ProvLabelView;

typedef struct {
    const ProvRootId *roots;
    uint32_t count;
} ProvRootSetView;

typedef struct {
    uint32_t max_roots_per_set;
} ProvRegistryConfig;

typedef struct {
    uint32_t resource_count;
    uint32_t root_count;
    uint32_t root_set_count;
    uint32_t label_count;
    uint64_t root_set_union_requests;
    uint64_t root_set_union_cache_hits;
    uint64_t root_set_truncations;
    uint32_t max_roots_per_set;
    bool union_fastpath_enabled;
    uint64_t union_cache_entries;
    uint64_t union_cache_capacity;
    uint64_t union_temp_allocations;
    uint64_t union_merge_iterations;
    uint64_t union_retained_prefix_hits;
    uint64_t registry_semantic_digest;
    uint64_t resource_records_bytes;
    uint64_t root_records_bytes;
    uint64_t root_set_records_bytes;
    uint64_t label_records_bytes;
    uint64_t index_bytes;
    uint64_t union_cache_bytes;
    uint64_t root_set_payload_bytes;
    uint64_t resource_name_bytes;
    uint64_t union_scratch_bytes;
    /* Requested live allocations only: excludes malloc overhead, QEMU and DTA. */
    uint64_t registry_accounted_bytes;
} ProvRegistryStats;

typedef struct ProvRegistry ProvRegistry;
typedef struct ProvFdTable ProvFdTable;

ProvRegistry *prov_registry_create(const ProvRegistryConfig *config);
void prov_registry_destroy(ProvRegistry *registry);
/* Nonzero process-local lifetime identity. Detects accidentally interpreting
 * IDs from a destroyed/different registry. Not a persistent resource ID. */
uint64_t prov_registry_instance(const ProvRegistry *registry);
void prov_registry_get_stats(ProvRegistry *registry, ProvRegistryStats *out_stats);

ProvResourceId prov_resource_intern(ProvRegistry *registry, const ProvResourceKey *key,
                                    const char *display_name, uint32_t roles);
bool prov_resource_get(ProvRegistry *registry, ProvResourceId resource_id,
                       ProvResourceView *out_resource);

ProvRootId prov_root_intern(ProvRegistry *registry, const ProvRootKey *key);
bool prov_root_get(ProvRegistry *registry, ProvRootId root_id, ProvRootKey *out_key);

ProvRootSetId prov_root_set_singleton(ProvRegistry *registry, ProvRootId root_id);
ProvRootSetId prov_root_set_intern(ProvRegistry *registry, const ProvRootId *roots, uint32_t count,
                                   bool *out_truncated);
ProvRootSetId prov_root_set_union(ProvRegistry *registry, ProvRootSetId left, ProvRootSetId right,
                                  bool *out_truncated);
bool prov_root_set_get(ProvRegistry *registry, ProvRootSetId set_id, ProvRootSetView *out_set);
bool prov_root_set_contains(ProvRegistry *registry, ProvRootSetId set_id, ProvRootId root_id);
bool prov_root_sets_intersect(ProvRegistry *registry, ProvRootSetId left, ProvRootSetId right);

ProvLabelId prov_label_unknown(ProvRegistry *registry);
ProvLabelId prov_label_intern(ProvRegistry *registry, const ProvLabelView *label);
ProvLabelId prov_label_from_root(ProvRegistry *registry, ProvRootId root_id, ProvChannel channel);
ProvLabelId prov_label_join(ProvRegistry *registry, ProvLabelId left, ProvLabelId right);
ProvLabelId prov_label_join_many(ProvRegistry *registry, const ProvLabelId *labels, uint32_t count);
ProvLabelId prov_label_as_address_dependency(ProvRegistry *registry, ProvLabelId label_id);
ProvLabelId prov_label_mark_incomplete(ProvRegistry *registry, ProvLabelId label_id,
                                       uint8_t incomplete_channels, uint64_t reasons);
bool prov_label_get(ProvRegistry *registry, ProvLabelId label_id, ProvLabelView *out_label);
bool prov_label_is_valid(ProvRegistry *registry, ProvLabelId label_id);
bool prov_label_has_known_roots(ProvRegistry *registry, ProvLabelId label_id);
bool prov_label_channel_may_be_tainted(ProvRegistry *registry, ProvLabelId label_id,
                                       ProvChannel channel);
bool prov_label_may_be_tainted(ProvRegistry *registry, ProvLabelId label_id);
/* CLEAN is the unique complete label with no roots. All other IDs, including
 * invalid IDs, and unavailable registries are conservatively tainted. */
bool prov_label_may_be_tainted_conservative(ProvRegistry *registry, ProvLabelId label_id);
bool prov_label_is_complete(ProvRegistry *registry, ProvLabelId label_id, uint8_t channels);

typedef struct {
    ProvOpenFileDescriptionId ofd_id;
    ProvResourceId resource_id;
    uint64_t current_offset;
    uint32_t flags;
    uint32_t reference_count;
    bool active;
} ProvOpenFileDescriptionView;

ProvFdTable *prov_fd_table_create(ProvRegistry *registry);
void prov_fd_table_destroy(ProvFdTable *table);
bool prov_fd_table_bind_new(ProvFdTable *table, int32_t fd, ProvResourceId resource_id,
                            uint64_t initial_offset, uint32_t flags,
                            ProvOpenFileDescriptionId *out_ofd_id);
bool prov_fd_table_dup(ProvFdTable *table, int32_t old_fd, int32_t new_fd,
                       ProvOpenFileDescriptionId *out_ofd_id);
bool prov_fd_table_close(ProvFdTable *table, int32_t fd);
bool prov_fd_table_lookup(ProvFdTable *table, int32_t fd,
                          ProvOpenFileDescriptionView *out_description);
bool prov_fd_table_advance(ProvFdTable *table, int32_t fd, uint64_t byte_count);
bool prov_fd_table_set_offset(ProvFdTable *table, int32_t fd, uint64_t offset);

#ifdef __cplusplus
}
#endif

#endif
