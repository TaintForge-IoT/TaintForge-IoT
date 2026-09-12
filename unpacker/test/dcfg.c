#include "dcfg.h"

#include <glib.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    DcfgNodeId source_node;
    DcfgNodeId target_node;
    DcfgEdgeKind kind;
} DcfgEdgeKey;

struct DcfgGraph {
    ProvRegistry *registry;
    GMutex lock;
    GHashTable *nodes_by_key;
    GHashTable *edges_by_key;
    GArray *nodes;
    GArray *edges;
    uint64_t branch_occurrence_count;
};

static uint64_t dcfg_mix64(uint64_t value) {
    value ^= value >> 30;
    value *= UINT64_C(0xbf58476d1ce4e5b9);
    value ^= value >> 27;
    value *= UINT64_C(0x94d049bb133111eb);
    value ^= value >> 31;
    return value;
}

static uint64_t dcfg_hash_combine(uint64_t hash, uint64_t value) {
    return dcfg_mix64(hash ^ (value + UINT64_C(0x9e3779b97f4a7c15) + (hash << 6) + (hash >> 2)));
}

static guint dcfg_fold_hash(uint64_t hash) {
    return (guint)(hash ^ (hash >> 32));
}

static guint dcfg_node_key_hash(gconstpointer pointer) {
    const DcfgNodeKey *key = pointer;
    uint64_t hash = dcfg_mix64(key->start_pc);
    hash = dcfg_hash_combine(hash, key->code_generation);
    hash = dcfg_hash_combine(hash, key->bytes_hash);
    return dcfg_fold_hash(hash);
}

static gboolean dcfg_node_key_equal(gconstpointer left_pointer, gconstpointer right_pointer) {
    const DcfgNodeKey *left = left_pointer;
    const DcfgNodeKey *right = right_pointer;
    return left->start_pc == right->start_pc && left->code_generation == right->code_generation &&
           left->bytes_hash == right->bytes_hash;
}

static guint dcfg_edge_key_hash(gconstpointer pointer) {
    const DcfgEdgeKey *key = pointer;
    uint64_t hash = dcfg_mix64(key->source_node);
    hash = dcfg_hash_combine(hash, key->target_node);
    hash = dcfg_hash_combine(hash, (uint64_t)key->kind);
    return dcfg_fold_hash(hash);
}

static gboolean dcfg_edge_key_equal(gconstpointer left_pointer, gconstpointer right_pointer) {
    const DcfgEdgeKey *left = left_pointer;
    const DcfgEdgeKey *right = right_pointer;
    return left->source_node == right->source_node && left->target_node == right->target_node &&
           left->kind == right->kind;
}

static DcfgNodeId dcfg_find_node_locked(DcfgGraph *graph, const DcfgNodeKey *key) {
    gpointer encoded = g_hash_table_lookup(graph->nodes_by_key, key);
    return encoded ? (DcfgNodeId)GPOINTER_TO_UINT(encoded) : DCFG_NODE_ID_INVALID;
}

static DcfgEdgeId dcfg_find_edge_locked(DcfgGraph *graph, DcfgNodeId source_node,
                                        DcfgNodeId target_node, DcfgEdgeKind kind) {
    DcfgEdgeKey key = {.source_node = source_node, .target_node = target_node, .kind = kind};
    gpointer encoded = g_hash_table_lookup(graph->edges_by_key, &key);
    return encoded ? (DcfgEdgeId)GPOINTER_TO_UINT(encoded) : DCFG_EDGE_ID_INVALID;
}

static DcfgNodeId dcfg_intern_node_locked(DcfgGraph *graph, const DcfgNodeKey *key) {
    DcfgNodeId existing = dcfg_find_node_locked(graph, key);
    if (existing != DCFG_NODE_ID_INVALID) {
        return existing;
    }
    if (graph->nodes->len >= UINT32_MAX - 1U) {
        return DCFG_NODE_ID_INVALID;
    }
    DcfgNodeKey *stored_key = g_try_new(DcfgNodeKey, 1);
    if (!stored_key) {
        return DCFG_NODE_ID_INVALID;
    }
    *stored_key = *key;
    DcfgNodeView node = {.node_id = (DcfgNodeId)graph->nodes->len + 1U, .key = *key};
    g_array_append_val(graph->nodes, node);
    g_hash_table_insert(graph->nodes_by_key, stored_key, GUINT_TO_POINTER(node.node_id));
    return node.node_id;
}

static bool dcfg_update_edge_locked(DcfgGraph *graph, DcfgEdgeView *edge,
                                    const DcfgBranchObservation *observation) {
    if (edge->occurrence_count == UINT64_MAX || graph->branch_occurrence_count == UINT64_MAX) {
        return false;
    }
    ProvLabelId joined_condition =
        prov_label_join(graph->registry, edge->condition_summary, observation->condition_label);
    ProvLabelId joined_target =
        prov_label_join(graph->registry, edge->target_summary, observation->target_label);
    if (joined_condition == PROV_LABEL_ID_INVALID || joined_target == PROV_LABEL_ID_INVALID) {
        return false;
    }
    edge->condition_summary = joined_condition;
    edge->target_summary = joined_target;
    edge->occurrence_count++;
    edge->last_seq_id = observation->branch_seq_id;
    edge->last_vcpu_index = observation->vcpu_index;
    graph->branch_occurrence_count++;
    return true;
}

static DcfgEdgeId dcfg_insert_edge_locked(DcfgGraph *graph, DcfgNodeId source_node,
                                          DcfgNodeId target_node,
                                          const DcfgBranchObservation *observation) {
    if (graph->edges->len >= UINT32_MAX - 1U || graph->branch_occurrence_count == UINT64_MAX) {
        return DCFG_EDGE_ID_INVALID;
    }
    DcfgEdgeKey *stored_key = g_try_new(DcfgEdgeKey, 1);
    if (!stored_key)
        return DCFG_EDGE_ID_INVALID;
    stored_key->source_node = source_node;
    stored_key->target_node = target_node;
    stored_key->kind = observation->kind;
    DcfgEdgeView edge = {.edge_id = (DcfgEdgeId)graph->edges->len + 1U,
                         .source_node = source_node,
                         .target_node = target_node,
                         .kind = observation->kind,
                         .occurrence_count = UINT64_C(1),
                         .first_seq_id = observation->branch_seq_id,
                         .last_seq_id = observation->branch_seq_id,
                         .first_vcpu_index = observation->vcpu_index,
                         .last_vcpu_index = observation->vcpu_index,
                         .condition_summary = observation->condition_label,
                         .target_summary = observation->target_label};

    g_array_append_val(graph->edges, edge);
    g_hash_table_insert(graph->edges_by_key, stored_key, GUINT_TO_POINTER(edge.edge_id));
    graph->branch_occurrence_count++;
    return edge.edge_id;
}

DcfgGraph *dcfg_graph_create(ProvRegistry *registry) {
    if (!registry)
        return NULL;
    DcfgGraph *graph = g_try_new0(DcfgGraph, 1);
    if (!graph)
        return NULL;
    graph->registry = registry;
    g_mutex_init(&graph->lock);
    graph->nodes_by_key =
        g_hash_table_new_full(dcfg_node_key_hash, dcfg_node_key_equal, g_free, NULL);
    graph->edges_by_key =
        g_hash_table_new_full(dcfg_edge_key_hash, dcfg_edge_key_equal, g_free, NULL);
    graph->nodes = g_array_sized_new(FALSE, TRUE, sizeof(DcfgNodeView), 16);
    graph->edges = g_array_sized_new(FALSE, TRUE, sizeof(DcfgEdgeView), 16);
    if (!graph->nodes_by_key || !graph->edges_by_key || !graph->nodes || !graph->edges) {
        dcfg_graph_destroy(graph);
        return NULL;
    }
    return graph;
}

void dcfg_graph_destroy(DcfgGraph *graph) {
    if (!graph)
        return;
    if (graph->edges)
        g_array_unref(graph->edges);
    if (graph->nodes)
        g_array_unref(graph->nodes);
    if (graph->edges_by_key)
        g_hash_table_destroy(graph->edges_by_key);
    if (graph->nodes_by_key)
        g_hash_table_destroy(graph->nodes_by_key);
    g_mutex_clear(&graph->lock);
    g_free(graph);
}

bool dcfg_record_branch(DcfgGraph *graph, const DcfgBranchObservation *observation,
                        DcfgEdgeId *out_edge_id) {
    if (out_edge_id) {
        *out_edge_id = DCFG_EDGE_ID_INVALID;
    }
    if (!graph || !observation || observation->branch_seq_id == 0 ||
        observation->kind <= DCFG_EDGE_INVALID || observation->kind > DCFG_EDGE_RET ||
        !prov_label_is_valid(graph->registry, observation->condition_label) ||
        !prov_label_is_valid(graph->registry, observation->target_label)) {
        return false;
    }
    g_mutex_lock(&graph->lock);
    DcfgNodeId source_node = dcfg_intern_node_locked(graph, &observation->source);
    DcfgNodeId target_node = dcfg_intern_node_locked(graph, &observation->target);
    if (source_node == DCFG_NODE_ID_INVALID || target_node == DCFG_NODE_ID_INVALID) {
        g_mutex_unlock(&graph->lock);
        return false;
    }
    DcfgEdgeId edge_id = dcfg_find_edge_locked(graph, source_node, target_node, observation->kind);
    bool success;
    if (edge_id != DCFG_EDGE_ID_INVALID) {
        success = dcfg_update_edge_locked(
            graph, &g_array_index(graph->edges, DcfgEdgeView, edge_id - 1U), observation);
    } else {
        edge_id = dcfg_insert_edge_locked(graph, source_node, target_node, observation);
        success = edge_id != DCFG_EDGE_ID_INVALID;
    }
    if (success && out_edge_id) {
        *out_edge_id = edge_id;
    }
    g_mutex_unlock(&graph->lock);
    return success;
}

DcfgNodeId dcfg_find_node(DcfgGraph *graph, const DcfgNodeKey *key) {
    if (!graph || !key) {
        return DCFG_NODE_ID_INVALID;
    }
    g_mutex_lock(&graph->lock);
    DcfgNodeId node_id = dcfg_find_node_locked(graph, key);
    g_mutex_unlock(&graph->lock);
    return node_id;
}

DcfgEdgeId dcfg_find_edge(DcfgGraph *graph, DcfgNodeId source_node, DcfgNodeId target_node,
                          DcfgEdgeKind kind) {
    if (!graph || source_node == DCFG_NODE_ID_INVALID || target_node == DCFG_NODE_ID_INVALID ||
        kind <= DCFG_EDGE_INVALID || kind > DCFG_EDGE_RET) {
        return DCFG_EDGE_ID_INVALID;
    }
    g_mutex_lock(&graph->lock);
    DcfgEdgeId edge_id = dcfg_find_edge_locked(graph, source_node, target_node, kind);
    g_mutex_unlock(&graph->lock);
    return edge_id;
}

bool dcfg_node_get(DcfgGraph *graph, DcfgNodeId node_id, DcfgNodeView *out_node) {
    if (!graph || !out_node || node_id == DCFG_NODE_ID_INVALID) {
        return false;
    }
    g_mutex_lock(&graph->lock);
    bool valid = node_id <= graph->nodes->len;
    if (valid) {
        *out_node = g_array_index(graph->nodes, DcfgNodeView, node_id - 1U);
    }
    g_mutex_unlock(&graph->lock);
    return valid;
}

bool dcfg_edge_get(DcfgGraph *graph, DcfgEdgeId edge_id, DcfgEdgeView *out_edge) {
    if (!graph || !out_edge || edge_id == DCFG_EDGE_ID_INVALID) {
        return false;
    }
    g_mutex_lock(&graph->lock);
    bool valid = edge_id <= graph->edges->len;
    if (valid) {
        *out_edge = g_array_index(graph->edges, DcfgEdgeView, edge_id - 1U);
    }
    g_mutex_unlock(&graph->lock);
    return valid;
}

static bool dcfg_label_has_no_roots(const ProvLabelView *label) {
    return label && label->data_roots == PROV_ROOT_SET_EMPTY &&
           label->address_roots == PROV_ROOT_SET_EMPTY;
}

static bool dcfg_labels_have_known_intersection(ProvRegistry *registry,
                                                const ProvLabelView *condition,
                                                const ProvLabelView *target) {
    if (!registry || !condition || !target)
        return false;
    return prov_root_sets_intersect(registry, condition->data_roots, target->data_roots) ||
           prov_root_sets_intersect(registry, condition->data_roots, target->address_roots) ||
           prov_root_sets_intersect(registry, condition->address_roots, target->data_roots) ||
           prov_root_sets_intersect(registry, condition->address_roots, target->address_roots);
}

DcfgRelevance dcfg_labels_data_relevance(DcfgGraph *graph, ProvLabelId condition_label,
                                         ProvLabelId target_label) {
    if (!graph || !prov_label_is_valid(graph->registry, condition_label) ||
        !prov_label_is_valid(graph->registry, target_label)) {
        return DCFG_RELEVANCE_UNKNOWN;
    }
    ProvLabelView condition;
    ProvLabelView target;
    if (!prov_label_get(graph->registry, condition_label, &condition) ||
        !prov_label_get(graph->registry, target_label, &target)) {
        return DCFG_RELEVANCE_UNKNOWN;
    }
    if (dcfg_labels_have_known_intersection(graph->registry, &condition, &target)) {
        return DCFG_RELEVANCE_RELEVANT;
    }

    bool condition_complete = (condition.complete_mask & PROV_COMPLETE_ALL) == PROV_COMPLETE_ALL;
    bool target_complete = (target.complete_mask & PROV_COMPLETE_ALL) == PROV_COMPLETE_ALL;
    if ((condition_complete && dcfg_label_has_no_roots(&condition)) ||
        (target_complete && dcfg_label_has_no_roots(&target)) ||
        (condition_complete && target_complete)) {
        return DCFG_RELEVANCE_IRRELEVANT;
    }
    return DCFG_RELEVANCE_UNKNOWN;
}

DcfgRelevance dcfg_edge_data_relevance(DcfgGraph *graph, DcfgEdgeId edge_id,
                                       ProvLabelId target_label) {
    DcfgEdgeView edge;
    if (!dcfg_edge_get(graph, edge_id, &edge)) {
        return DCFG_RELEVANCE_UNKNOWN;
    }
    if (edge.kind != DCFG_EDGE_JCC_TAKEN && edge.kind != DCFG_EDGE_JCC_FALLTHROUGH &&
        edge.kind != DCFG_EDGE_JCC_UNKNOWN) {
        return DCFG_RELEVANCE_IRRELEVANT;
    }
    return dcfg_labels_data_relevance(graph, edge.condition_summary, target_label);
}

void dcfg_graph_get_stats(DcfgGraph *graph, DcfgStats *out_stats) {
    if (!out_stats)
        return;
    memset(out_stats, 0, sizeof(*out_stats));
    if (!graph)
        return;
    g_mutex_lock(&graph->lock);
    out_stats->node_count = graph->nodes->len;
    out_stats->edge_count = graph->edges->len;
    out_stats->branch_occurrence_count = graph->branch_occurrence_count;
    g_mutex_unlock(&graph->lock);
}

const char *dcfg_edge_kind_name(DcfgEdgeKind kind) {
    switch (kind) {
    case DCFG_EDGE_JCC_TAKEN:
        return "jcc-taken";
    case DCFG_EDGE_JCC_FALLTHROUGH:
        return "jcc-fallthrough";
    case DCFG_EDGE_JCC_UNKNOWN:
        return "jcc-unknown";
    case DCFG_EDGE_DIRECT_JMP:
        return "direct-jmp";
    case DCFG_EDGE_INDIRECT_JMP:
        return "indirect-jmp";
    case DCFG_EDGE_CALL:
        return "call";
    case DCFG_EDGE_RET:
        return "ret";
    case DCFG_EDGE_INVALID:
    default:
        return "invalid";
    }
}

const char *dcfg_relevance_name(DcfgRelevance relevance) {
    switch (relevance) {
    case DCFG_RELEVANCE_IRRELEVANT:
        return "irrelevant";
    case DCFG_RELEVANCE_RELEVANT:
        return "relevant";
    case DCFG_RELEVANCE_UNKNOWN:
    default:
        return "unknown";
    }
}
