#ifndef TAINTFORGE_REPLAY_SOURCES_H
#define TAINTFORGE_REPLAY_SOURCES_H

#include "provenance.h"

/* Immutable, reference-counted copy of referenced provenance records. Numeric
 * IDs are local to this snapshot's registry namespace, never global identities.
 * A root is a dependency, NOT a formula or a proof of source controllability. */
typedef struct ReplaySources ReplaySources;

typedef struct {
    size_t bytes;
    uint64_t work;
} ReplaySourceLimits;

typedef enum {
    REPLAY_SOURCES_NOT_CAPTURED,
    REPLAY_SOURCES_READY,
    REPLAY_SOURCES_UNKNOWN,
    REPLAY_SOURCES_RESOURCE_LIMIT,
    REPLAY_SOURCES_OUT_OF_MEMORY,
    REPLAY_SOURCES_INVALID
} ReplaySourceStatus;

enum {
    REPLAY_SOURCE_INVALID_LABEL = 1U << 0,
    REPLAY_SOURCE_INVALID_ROOT = 1U << 1,
    REPLAY_SOURCE_INVALID_RESOURCE = 1U << 2,
    REPLAY_SOURCE_INCOMPLETE = 1U << 3,
    REPLAY_SOURCE_REGISTRY_MISMATCH = 1U << 4,
    REPLAY_SOURCE_HISTORY_MISSING = 1U << 5
};

typedef struct {
    ReplaySourceStatus status;
    uint32_t issues, labels, roots, resources;
    uint64_t registry_instance;
    uint64_t work;
    size_t bytes; /* Peak own + temporary allocations, excluding registry. */
} ReplaySourceInfo;

typedef struct {
    ProvLabelId id;
    bool valid;
    ProvLabelView view;
    const ProvRootId *data, *address;
    uint32_t data_count, address_count;
} ReplaySourceLabel;

typedef struct {
    ProvRootId id;
    bool valid;
    ProvRootKey key;
} ReplaySourceRoot;

typedef struct {
    ProvResourceId id;
    bool valid;
    ProvResourceView view; /* display_name is owned by this snapshot. */
} ReplaySourceResource;

ReplaySourceLimits replay_source_default_limits(void);
/* Caller serializes the registry for the entire capture. Invalid references
 * produce inspectable UNKNOWN; budget/OOM returns NULL, no partial snapshot.
 * No pointer into registry survives. Resource names are copied with a budget. */
ReplaySources *replay_sources_capture(ProvRegistry *registry, const ProvLabelId *labels,
                                      uint32_t count, const ReplaySourceLimits *limits,
                                      ReplaySourceInfo *info);
ReplaySources *replay_sources_retain(const ReplaySources *sources);
void replay_sources_release(ReplaySources *sources);
size_t replay_sources_bytes(const ReplaySources *sources);
ReplaySourceInfo replay_sources_info(const ReplaySources *sources);
const ReplaySourceLabel *replay_sources_label(const ReplaySources *sources, ProvLabelId id);
const ReplaySourceRoot *replay_sources_root(const ReplaySources *sources, ProvRootId id);
const ReplaySourceResource *replay_sources_resource(const ReplaySources *sources,
                                                    ProvResourceId id);

#endif
