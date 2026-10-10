#ifndef TAINTFORGE_DCFG_H
#define TAINTFORGE_DCFG_H

#include <stdbool.h>
#include <stdint.h>

#include "provenance.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t DcfgNodeId;
typedef uint32_t DcfgEdgeId;

#define DCFG_NODE_ID_INVALID ((DcfgNodeId)0)
#define DCFG_EDGE_ID_INVALID ((DcfgEdgeId)0)

typedef enum {
    DCFG_EDGE_INVALID = 0,
    DCFG_EDGE_JCC_TAKEN,
    DCFG_EDGE_JCC_FALLTHROUGH,
    DCFG_EDGE_JCC_UNKNOWN,
    DCFG_EDGE_DIRECT_JMP,
    DCFG_EDGE_INDIRECT_JMP,
    DCFG_EDGE_CALL,
    DCFG_EDGE_RET
} DcfgEdgeKind;

typedef enum {
    DCFG_RELEVANCE_IRRELEVANT = 0,
    DCFG_RELEVANCE_RELEVANT,
    DCFG_RELEVANCE_UNKNOWN
} DcfgRelevance;

typedef struct {
    uint64_t start_pc;
    uint32_t code_generation;
    uint64_t bytes_hash;
} DcfgNodeKey;

typedef struct {
    DcfgNodeId node_id;
    DcfgNodeKey key;
} DcfgNodeView;

typedef struct {
    DcfgEdgeId edge_id;
    DcfgNodeId source_node;
    DcfgNodeId target_node;
    DcfgEdgeKind kind;
    uint64_t occurrence_count;
    uint64_t first_seq_id;
    uint64_t last_seq_id;
    uint32_t first_vcpu_index;
    uint32_t last_vcpu_index;

    ProvLabelId condition_summary;
    ProvLabelId target_summary;
} DcfgEdgeView;

typedef struct {
    DcfgNodeKey source;
    DcfgNodeKey target;
    DcfgEdgeKind kind;
    uint64_t branch_seq_id;
    uint32_t vcpu_index;

    ProvLabelId condition_label;
    ProvLabelId target_label;
} DcfgBranchObservation;

typedef struct {
    uint32_t node_count;
    uint32_t edge_count;
    uint64_t branch_occurrence_count;
} DcfgStats;

typedef struct DcfgGraph DcfgGraph;

DcfgGraph *dcfg_graph_create(ProvRegistry *registry);
void dcfg_graph_destroy(DcfgGraph *graph);
bool dcfg_record_branch(DcfgGraph *graph, const DcfgBranchObservation *observation,
                        DcfgEdgeId *out_edge_id);
DcfgNodeId dcfg_find_node(DcfgGraph *graph, const DcfgNodeKey *key);
DcfgEdgeId dcfg_find_edge(DcfgGraph *graph, DcfgNodeId source_node, DcfgNodeId target_node,
                          DcfgEdgeKind kind);
bool dcfg_node_get(DcfgGraph *graph, DcfgNodeId node_id, DcfgNodeView *out_node);
bool dcfg_edge_get(DcfgGraph *graph, DcfgEdgeId edge_id, DcfgEdgeView *out_edge);

DcfgRelevance dcfg_labels_data_relevance(DcfgGraph *graph, ProvLabelId condition_label,
                                         ProvLabelId target_label);
DcfgRelevance dcfg_edge_data_relevance(DcfgGraph *graph, DcfgEdgeId edge_id,
                                       ProvLabelId target_label);

void dcfg_graph_get_stats(DcfgGraph *graph, DcfgStats *out_stats);
const char *dcfg_edge_kind_name(DcfgEdgeKind kind);
const char *dcfg_relevance_name(DcfgRelevance relevance);

#define DCFG_REGION_MAX_NODES 512U

typedef enum {
    DCFG_REGION_UNKNOWN = 0,
    DCFG_REGION_NO,
    DCFG_REGION_YES
} DcfgRegionRelation;

enum {
    DCFG_REGION_OPEN = 1U << 0,
    DCFG_REGION_CYCLE = 1U << 1,
    DCFG_REGION_OPAQUE = 1U << 2,
    DCFG_REGION_BUDGET = 1U << 3,
    DCFG_REGION_INVALID = 1U << 4
};

/* IDs are 1..count; successor 0 is an UNKNOWN continuation, never an exit.
 * The caller supplies exhaustive successors, including unobserved direct arms.
 * An opaque node may have additional effects or continuations. */
typedef struct {
    uint32_t successors[2];
    uint8_t successor_count;
    bool terminal;
    bool opaque;
    uint64_t register_writes, special_writes;
} DcfgRegionNode;

typedef struct {
    DcfgRegionRelation postdominates, control_dependent;
    uint32_t issues, visited;
    uint64_t register_writes, special_writes;
    /* First failing node, or source and successor slot for an unresolved edge.
     * A node-only witness has successor UINT32_MAX. Zero issue means absent. */
    uint32_t witness_issue, witness_node, witness_successor;
} DcfgRegionResult;

/* On-demand postdominance for one boundary. Stop before its effects; accumulate
 * may-writes on every arm. Cycles stay UNKNOWN, including cycles with exits.
 * nodes[0] is unused. The function does not infer CFG completeness from DCFG. */
DcfgRegionResult dcfg_region_analyze(const DcfgRegionNode *nodes, uint32_t count, uint32_t branch,
                                     uint32_t boundary, uint32_t budget);

#ifdef __cplusplus
}
#endif

#endif
