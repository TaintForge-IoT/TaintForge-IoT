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

#ifdef __cplusplus
}
#endif

#endif
