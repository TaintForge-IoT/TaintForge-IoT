#include "aux_trace.h"
#include "dta.h"
#include "trace.h"
#include <capstone/capstone.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool es_preserving_instruction(const InsnMeta *meta, const TraceEntry *entry,
                                      const InsnAux *before, const InsnAux *after);

void dse_aux_set_es(InsnAux *aux, const uint32_t words[8], bool read_ok, bool provider_verified) {
    if (!aux)
        return;
    aux->es_before = (DseEsObservation){0};
    if (!words || !read_ok || !provider_verified || words[0] != UINT32_C(0x45530101) ||
        words[1] > UINT16_MAX || words[6] > UINT16_MAX || words[7] ||
        (words[4] & ~UINT32_C(0x00f0ff00)) || (words[5] & ~UINT32_C(63)))
        return;
    aux->es_before = (DseEsObservation){.selector = words[1], .base = words[2],
        .limit = words[3], .access = words[4], .mode = words[5], .cs_selector = words[6],
        .valid = true};
}

const char *dse_aux_es_contract_issue(const InsnAux *aux) {
    if (!aux || !aux->es_before.valid)
        return "observation_unverified";
    const DseEsObservation *s = &aux->es_before;
    if (!s->entry_preserved)
        return "entry_state_not_preserved";
    if ((s->mode & ~UINT32_C(32)) != 7 || (s->cs_selector & 3U) != 3U)
        return "unsupported_mode";
    if (s->selector <= 3 || (s->selector & 3U) != 3U ||
        (s->access & UINT32_C(0x00e0fe00)) != UINT32_C(0x00c0f200))
        return "segment_attributes_unsupported";
    if (s->base != 0 || s->limit != UINT32_MAX)
        return "segment_not_flat32";
    return NULL;
}

void dse_aux_carry_x86_es(InsnAux *current, const TraceEntry *entry,
                         const TraceBuffer *trace, const InsnAux *previous) {
    if (!current)
        return;
    current->es_before.entry_preserved = false;
    if (!entry || !trace || !current->es_before.valid)
        return;
    const InsnDesc *current_desc = trace_insn_desc_get(trace, entry->insn_desc_id);
    if (!current_desc || current_desc->arch != TRACE_ARCH_X86 ||
        current_desc->mode != TRACE_MODE_32 || current_desc->pc != entry->pc ||
        current_desc->meta_id != entry->meta_id || current_desc->bytes_hash != entry->bytes_hash ||
        current_desc->code_generation != entry->code_generation || current_desc->size != entry->size)
        return;
    if (entry->seq_id == 1 && entry->vcpu_index == 0 && !previous) {
        current->es_before.entry_preserved = true;
        return;
    }
    if (!previous || !previous->valid || !previous->execution_complete ||
        !previous->es_before.valid || !previous->es_before.entry_preserved ||
        !previous->next_pc_valid || previous->next_pc != entry->pc ||
        !previous->seq_id || previous->seq_id == UINT64_MAX || previous->seq_id + 1 != entry->seq_id)
        return;
    const TraceEntry *prior = trace_find_seq(trace, previous->seq_id, NULL);
    if (!prior || prior->vcpu_index != entry->vcpu_index || prior->pc != previous->pc ||
        prior->meta_id != previous->meta_id)
        return;
    const InsnDesc *desc = trace_insn_desc_get(trace, prior->insn_desc_id);
    const InsnMeta *meta = meta_lookup_id(prior->meta_id);
    if (!desc || !meta || meta->writes_es || desc->arch != TRACE_ARCH_X86 ||
        desc->mode != TRACE_MODE_32 || desc->pc != prior->pc || desc->meta_id != prior->meta_id ||
        desc->code_generation != prior->code_generation || desc->bytes_hash != prior->bytes_hash ||
        desc->size != prior->size || memcmp(desc->bytes, prior->instr_bytes, desc->size) ||
        meta->size != desc->size || memcmp(meta->instr_bytes, desc->bytes, desc->size))
        return;
    if (!es_preserving_instruction(meta, prior, previous, current))
        return;
    uint64_t fallthrough = (uint32_t)(prior->pc + prior->size);
    bool loop = meta->insn_id == X86_INS_LOOP && desc->size == 2 && desc->bytes[0] == 0xe2;
    if (loop && entry->pc != fallthrough &&
        entry->pc != (uint32_t)(fallthrough + (int8_t)desc->bytes[1]))
        return;
    if (!loop && desc->effects.branch_kind == TRACE_BRANCH_NONE && entry->pc != fallthrough)
        return;
    if (desc->effects.direct_target_valid && entry->pc != (uint32_t)desc->effects.direct_target &&
        !(meta->is_conditional_branch && entry->pc == fallthrough))
        return;
    const DseEsObservation *a = &current->es_before, *b = &previous->es_before;
    current->es_before.entry_preserved = a->selector == b->selector && a->base == b->base &&
        a->limit == b->limit && a->access == b->access && a->mode == b->mode &&
        a->cs_selector == b->cs_selector;
}

void dse_aux_capture_sources(DseSourceObservation *aux, const DtaVcpuState *state,
                             uint8_t register_bytes) {
    if (!aux)
        return;
    memset(aux, 0, sizeof(*aux));
    if (!state || !state->regs.registry || !register_bytes || register_bytes > MAX_REG_BYTES)
        return;
    aux->registry_instance = prov_registry_instance(state->regs.registry);
    for (unsigned reg = 0; reg < REG_COUNT; ++reg) {
        for (unsigned byte = 0; byte < register_bytes; ++byte) {
            aux->reg_source_labels[reg][byte] = state->regs.bytes[reg][byte];
            aux->reg_source_valid[reg] |= (uint8_t)(1U << byte);
        }
    }
    for (unsigned flag = 0; flag < DTA_FLAG_SLOT_COUNT; ++flag) {
        aux->flag_source_labels[flag] = state->flags.labels[flag];
        aux->flag_source_valid |= state->flags.valid_mask & (1U << flag);
    }
}

const DseSourceObservation *dse_aux_sources(const InsnAux *aux) {
    return aux && !aux->source_metadata_lost && aux->sources && aux->sources->seq_id == aux->seq_id
               ? aux->sources
               : NULL;
}

DseSourceObservation *dse_aux_sources_mut(InsnAux *aux) {
    return (DseSourceObservation *)dse_aux_sources(aux);
}

bool dse_aux_set_source_limit(DseAuxRing *ring, size_t bytes) {
    if (!ring || ring->source_history)
        return false;
    ring->max_source_bytes = bytes;
    return true;
}

size_t dse_aux_source_bytes(const DseAuxRing *ring) {
    return ring ? (size_t)ring->source_capacity * sizeof(DseSourceObservation) : 0;
}

bool dse_aux_record_sources(DseAuxRing *ring, InsnAux *aux, const DseSourceObservation *source) {
    if (!ring || !aux || !aux->seq_id)
        return false;
    aux->sources = NULL;
    if (!source)
        return true;
    aux->source_metadata_lost = true;
    if (!ring->source_history) {
        size_t capacity = ring->max_source_bytes / sizeof(DseSourceObservation);
        if (capacity > ring->capacity)
            capacity = ring->capacity;
        if (!capacity)
            return false;
        ring->source_history = calloc(capacity, sizeof(*ring->source_history));
        if (!ring->source_history)
            return false;
        ring->source_capacity = (uint32_t)capacity;
    }
    DseSourceObservation *slot = &ring->source_history[aux->seq_id % ring->source_capacity];
    *slot = *source;
    slot->seq_id = aux->seq_id;
    aux->sources = slot;
    aux->source_metadata_lost = false;
    return true;
}

void dse_aux_set_eflags(InsnAux *aux, uint32_t value, bool read_ok, bool provider_verified) {
    if (!aux)
        return;
    aux->eflags_valid = read_ok && provider_verified;
    aux->eflags_before = aux->eflags_valid ? value : 0;
}

void dse_aux_set_tls(InsnAux *aux, unsigned segment, uint32_t base, uint32_t selector,
                     bool read_ok) {
    if (!aux || segment >= DSE_TLS_SEGMENTS)
        return;
    uint8_t bit = (uint8_t)(1U << segment);
    bool valid =
        read_ok && selector <= UINT16_MAX && (selector & 3U) == 3U && (selector & ~3U) != 0;
    aux->tls_valid_mask = (aux->tls_valid_mask & ~bit) | (valid ? bit : 0);
    aux->tls_base[segment] = valid ? base : 0;
    aux->tls_selector[segment] = valid ? (uint16_t)selector : 0;
}

size_t dse_aux_syscall_owned_bytes(const DseSyscallObservation *s) {
    if (!s || s->write_size > DSE_SYSCALL_WRITE_BYTES ||
        (s->file && s->file->content_size > DSE_EXECUTABLE_SNAPSHOT_BYTES)) return 0;
    return sizeof(*s) + s->write_size + (s->file ? sizeof(*s->file) + s->file->content_size : 0);
}

DseSyscallObservation *dse_aux_syscall_copy(const DseSyscallObservation *s, size_t limit) {
    size_t size = dse_aux_syscall_owned_bytes(s);
    if (!size || size > limit || (s->write_size && !s->write_values) ||
        (s->file && s->file->content_size && !s->file->contents)) return NULL;
    DseSyscallObservation *copy = malloc(sizeof(*copy));
    if (!copy) return NULL;
    *copy = *s; copy->write_values = NULL; copy->file = NULL;
    if (s->write_size) {
        copy->write_values = malloc(s->write_size);
        if (!copy->write_values) goto fail;
        memcpy(copy->write_values, s->write_values, s->write_size);
    }
    if (s->file) {
        copy->file = malloc(sizeof(*copy->file));
        if (!copy->file) goto fail;
        *copy->file = *s->file; copy->file->contents = NULL;
        if (s->file->content_size) {
            copy->file->contents = malloc(s->file->content_size);
            if (!copy->file->contents) goto fail;
            memcpy(copy->file->contents, s->file->contents, s->file->content_size);
        }
    }
    return copy;
fail:
    dse_aux_syscall_free(copy);
    return NULL;
}

void dse_aux_syscall_free(DseSyscallObservation *s) {
    if (s) {
        free(s->write_values);
        if (s->file) free(s->file->contents);
        free(s->file);
    }
    free(s);
}

static bool syscall_allocate(DseAuxRing *ring, InsnAux *aux) {
    if (!ring || !aux || ring->dynamic_bytes > ring->max_dynamic_bytes ||
        sizeof(*aux->syscall) > ring->max_dynamic_bytes - ring->dynamic_bytes)
        return false;
    aux->syscall = calloc(1, sizeof(*aux->syscall));
    if (!aux->syscall)
        return false;
    ring->dynamic_bytes += sizeof(*aux->syscall);
    return true;
}

bool dse_aux_syscall_enter(DseAuxRing *ring, InsnAux *aux, const TraceEntry *entry, uint32_t number,
                           const uint32_t args[6]) {
    /* Count even an unrecordable boundary: a later file fact must not bridge it. */
    if (!ring)
        return false;
    if (ring->syscall_boundary_id == UINT64_MAX)
        ring->syscall_order_lost = true;
    else
        ring->syscall_boundary_id++;
    if (!aux || !entry || !args || !aux->valid || aux->seq_id != entry->seq_id ||
        aux->pc != entry->pc || aux->meta_id != entry->meta_id || aux->execution_complete)
        return false;
    if (aux->syscall || aux->syscall_metadata_lost) {
        if (aux->syscall)
            aux->syscall->invalid = true;
        return false;
    }
    aux->syscall_metadata_lost = true;
    if (!syscall_allocate(ring, aux))
        return false;
    *aux->syscall = (DseSyscallObservation){.seq_id = entry->seq_id,
                                            .pc = entry->pc,
                                            .bytes_hash = entry->bytes_hash,
                                            .code_generation = entry->code_generation,
                                            .vcpu_index = entry->vcpu_index,
                                            .descriptor_id = entry->insn_desc_id,
                                            .number = number,
                                            .boundary_id = ring->syscall_order_lost ? 0
                                                              : ring->syscall_boundary_id};
    memcpy(aux->syscall->args, args, sizeof(aux->syscall->args));
    aux->syscall_metadata_lost = false;
    return true;
}

bool dse_aux_syscall_return(InsnAux *aux, uint64_t seq_id, uint32_t vcpu_index, uint32_t number,
                            uint32_t result) {
    if (!aux || !aux->syscall || aux->syscall_metadata_lost)
        return false;
    DseSyscallObservation *event = aux->syscall;
    if (event->invalid || event->returned || aux->execution_complete || aux->seq_id != seq_id ||
        event->seq_id != seq_id || event->vcpu_index != vcpu_index || event->number != number) {
        event->invalid = true;
        return false;
    }
    event->result = result;
    event->returned = true;
    return true;
}

void dse_aux_syscall_post_flags(InsnAux *aux, uint32_t eflags, bool verified_read) {
    if (!aux || !aux->syscall || !aux->execution_complete || !aux->syscall->post_observed)
        return;
    aux->syscall->post_eflags = verified_read ? eflags : 0;
    aux->syscall->post_eflags_valid = verified_read;
}

bool dse_aux_syscall_name(InsnAux *aux, const uint8_t *name, size_t size) {
    DseSyscallObservation *s = aux ? aux->syscall : NULL;
    if (!s || s->number != 356 || s->invalid || s->returned || aux->execution_complete)
        return false;
    if (s->name_observed) {
        s->invalid = true;
        return false;
    }
    s->name_observed = true;
    if (!name || !size || size > DSE_MEMFD_NAME_BYTES || name[size - 1] ||
        memchr(name, 0, size - 1) || (uint64_t)s->args[0] + size > (UINT64_C(1) << 32))
        return false;
    memcpy(s->name, name, size);
    s->name_size = (uint16_t)size;
    return true;
}

bool dse_aux_syscall_mmap_args(InsnAux *aux, const uint8_t *bytes, size_t size) {
    DseSyscallObservation *s = aux ? aux->syscall : NULL;
    if (!s || s->number != 90 || s->invalid || s->returned || aux->execution_complete)
        return false;
    if (s->mmap_args_observed) {
        s->invalid = true;
        return false;
    }
    s->mmap_args_observed = true;
    if (!bytes || size != 24 || (uint64_t)s->args[0] + size > (UINT64_C(1) << 32))
        return false;
    for (unsigned i = 0; i < 6; ++i)
        s->mmap_args[i] = (uint32_t)bytes[i * 4] | (uint32_t)bytes[i * 4 + 1] << 8 |
                          (uint32_t)bytes[i * 4 + 2] << 16 | (uint32_t)bytes[i * 4 + 3] << 24;
    s->mmap_args_valid = true;
    return true;
}

bool dse_aux_syscall_write(DseAuxRing *ring, InsnAux *aux, const uint8_t *bytes, size_t size) {
    DseSyscallObservation *s = aux ? aux->syscall : NULL;
    if (!ring || !s || s->number != 4 || s->returned || s->invalid || aux->execution_complete)
        return false;
    if (s->write_observed) {
        s->invalid = true;
        return false;
    }
    s->write_observed = true;
    if (size != s->args[2] || size > DSE_SYSCALL_WRITE_BYTES || (size && !bytes) ||
        (uint64_t)s->args[1] + size > (UINT64_C(1) << 32) ||
        ring->dynamic_bytes > ring->max_dynamic_bytes ||
        size > ring->max_dynamic_bytes - ring->dynamic_bytes)
        return false;
    if (size) {
        s->write_values = malloc(size);
        if (!s->write_values)
            return false;
        memcpy(s->write_values, bytes, size);
        ring->dynamic_bytes += size;
    }
    s->write_size = (uint32_t)size;
    s->write_valid = true;
    return true;
}

bool dse_aux_syscall_path(DseAuxRing *ring, InsnAux *aux, const uint8_t *path, size_t size) {
    DseSyscallObservation *s = aux ? aux->syscall : NULL;
    if (!ring || !s || (s->number != 5 && s->number != 85) || s->invalid ||
        s->returned || aux->execution_complete) return false;
    if (s->file) { s->invalid = true; return false; }
    if (ring->dynamic_bytes > ring->max_dynamic_bytes ||
        sizeof(*s->file) > ring->max_dynamic_bytes - ring->dynamic_bytes) return false;
    s->file = calloc(1, sizeof(*s->file));
    if (!s->file) return false;
    ring->dynamic_bytes += sizeof(*s->file);
    s->file->path_observed = true;
    if (!path || !size || size > DSE_SYSCALL_PATH_BYTES || path[size-1] ||
        memchr(path, 0, size-1) || (uint64_t)s->args[0]+size > (UINT64_C(1)<<32)) return false;
    memcpy(s->file->path, path, size); s->file->path_size = (uint16_t)size;
    s->file->path_valid = true;
    return true;
}

bool dse_aux_syscall_executable(DseAuxRing *ring, InsnAux *aux, uint64_t identity,
                                 const uint8_t *link, size_t link_size,
                                 const uint8_t *contents, size_t content_size) {
    DseSyscallObservation *s = aux ? aux->syscall : NULL;
    if (!ring || !s || !s->file || (s->number != 5 && s->number != 85) || s->invalid ||
        s->returned || aux->execution_complete) return false;
    DseSyscallFileObservation *f = s->file;
    if (f->source_observed) { s->invalid = true; return false; }
    f->source_observed = true;
    if (!identity || !link || !link_size || link_size >= DSE_SYSCALL_PATH_BYTES ||
        link[0] != '/' || memchr(link,0,link_size) || content_size > DSE_EXECUTABLE_SNAPSHOT_BYTES ||
        (content_size && !contents) || (s->number == 85 && content_size) ||
        ring->dynamic_bytes > ring->max_dynamic_bytes ||
        content_size > ring->max_dynamic_bytes-ring->dynamic_bytes) return false;
    if (content_size) {
        f->contents = malloc(content_size);
        if (!f->contents) return false;
        memcpy(f->contents,contents,content_size); ring->dynamic_bytes += content_size;
    }
    f->content_size = (uint32_t)content_size; f->content_valid = s->number == 5;
    f->source_identity = identity; f->link_size = (uint16_t)link_size;
    memcpy(f->link,link,link_size); f->source_valid = true;
    return true;
}

bool dse_aux_syscall_readlink_reply(InsnAux *aux, const uint8_t *bytes, size_t size) {
    DseSyscallObservation *s = aux ? aux->syscall : NULL;
    if (!s || s->number != 85 || !s->file || s->invalid || !s->returned || aux->execution_complete)
        return false;
    DseSyscallFileObservation *f = s->file;
    if (f->reply_observed) { s->invalid = true; return false; }
    f->reply_observed = true;
    if (size != s->result || size > DSE_SYSCALL_PATH_BYTES || size > s->args[2] ||
        (size && !bytes) || (uint64_t)s->args[1]+size > (UINT64_C(1)<<32)) return false;
    if (size) memcpy(f->reply,bytes,size);
    f->reply_size = (uint32_t)size; f->reply_valid = true;
    return true;
}

void dse_aux_syscall_seal_order(const DseAuxRing *ring, InsnAux *aux) {
    DseSyscallObservation *s = aux ? aux->syscall : NULL;
    if (s)
        s->boundary_ordered = ring && !ring->syscall_order_lost && s->boundary_id &&
                              s->boundary_id == ring->syscall_boundary_id &&
                              !s->invalid && s->returned && aux->execution_complete;
}

static const char *int80_register_issue(const TraceEntry *entry, const InsnAux *aux,
                                       uint32_t number, unsigned argc) {
    const DseSyscallObservation *s = aux ? aux->syscall : NULL;
    if (!s || aux->syscall_metadata_lost)
        return "observation_missing";
    if (s->invalid || !s->returned)
        return "entry_return_invalid";
    if (!entry || !entry->size || entry->size > MAX_INSN_BYTES ||
        !aux->valid || aux->seq_id != entry->seq_id ||
        aux->meta_id != entry->meta_id || aux->pc != entry->pc ||
        s->seq_id != entry->seq_id || s->pc != entry->pc ||
        s->vcpu_index != entry->vcpu_index || s->descriptor_id != entry->insn_desc_id ||
        s->bytes_hash != entry->bytes_hash || s->code_generation != entry->code_generation ||
        entry->bytes_hash != trace_instruction_bytes_hash(entry->instr_bytes, entry->size))
        return "identity_mismatch";
    if (entry->size != 2 || entry->instr_bytes[0] != 0xcd || entry->instr_bytes[1] != 0x80 ||
        entry->pc > UINT32_MAX || s->number != number || !aux->eflags_valid ||
        (aux->eflags_before & (1U << 17)))
        return "unsupported_abi";
    if (!aux->execution_complete || !aux->next_pc_valid ||
        aux->next_pc != (uint32_t)(entry->pc + 2) || !s->post_observed)
        return "post_state_missing";
    if ((aux->reg_value_valid_mask & 255U) != 255U || (s->post_valid_mask & 255U) != 255U)
        return "register_snapshot_missing";
    if (!s->post_eflags_valid || s->post_eflags != aux->eflags_before)
        return "preserved_flags_unverified";
    if (aux->reg_vals[DTA_REG_RAX] != number || aux->reg_vals[DTA_REG_RBX] != s->args[0] ||
        (argc >= 2 && aux->reg_vals[DTA_REG_RCX] != s->args[1]) ||
        (argc >= 3 && aux->reg_vals[DTA_REG_RDX] != s->args[2]) ||
        (argc >= 4 && aux->reg_vals[DTA_REG_RSI] != s->args[3]) ||
        (argc >= 5 && aux->reg_vals[DTA_REG_RDI] != s->args[4]) ||
        (argc >= 6 && aux->reg_vals[DTA_REG_RBP] != s->args[5]))
        return "argument_mismatch";
    if (s->post_regs[DTA_REG_RAX] != s->result)
        return "return_mismatch";
    if (number != 356 && number != 90 && number != 192 && number != 45 &&
        number != 4 && number != 5 && number != 85 && s->result &&
        s->result < UINT32_C(0xfffff001))
        return "invalid_return_value";
    for (unsigned i = 1; i < 8; ++i)
        if (aux->reg_vals[i] != s->post_regs[i])
            return "preserved_register_mismatch";
    if (aux->has_mem_read || aux->has_mem_write || aux->mem_read_total || aux->mem_write_total ||
        aux->mem_read_count || aux->mem_write_count || aux->mem_read_overflow || aux->mem_write_overflow)
        return "unexpected_memory_access";
    return NULL;
}

static const char *executable_source_issue(const DseSyscallObservation *s) {
    const DseSyscallFileObservation *f = s->file;
    if (!s->boundary_id || !s->boundary_ordered) return "syscall_order_unverified";
    if (!f || !f->path_observed || !f->path_valid || !f->path_size ||
        f->path_size > DSE_SYSCALL_PATH_BYTES || f->path[f->path_size-1] ||
        memchr(f->path,0,f->path_size-1) ||
        (uint64_t)s->args[0]+f->path_size > (UINT64_C(1)<<32)) return "pathname_incomplete";
    static const char path[] = "/proc/self/exe";
    if (f->path_size != sizeof(path) || memcmp(f->path,path,sizeof(path)))
        return "pathname_unsupported";
    if (!f->source_observed || !f->source_valid || !f->source_identity || !f->link_size ||
        f->link_size >= DSE_SYSCALL_PATH_BYTES || f->link[0] != '/' || memchr(f->link,0,f->link_size))
        return "executable_source_unverified";
    return NULL;
}

const char *dse_aux_open_executable_issue(const TraceEntry *entry, const InsnAux *aux) {
    const char *issue = int80_register_issue(entry,aux,5,2);
    if (issue) return issue;
    const DseSyscallObservation *s = aux->syscall;
    if (s->result > INT32_MAX) return "open_not_successful";
    /* O_RDONLY plus the i386 O_LARGEFILE / O_CLOEXEC flags only. */
    if (s->args[1] & ~UINT32_C(0x88000)) return "open_flags_unsupported";
    issue = executable_source_issue(s);
    if (issue) return issue;
    const DseSyscallFileObservation *f = s->file;
    if (!f->content_valid || f->content_size > DSE_EXECUTABLE_SNAPSHOT_BYTES ||
        (f->content_size && !f->contents)) return "executable_contents_incomplete";
    return NULL;
}

const char *dse_aux_readlink_executable_issue(const TraceEntry *entry, const InsnAux *aux) {
    const char *issue = int80_register_issue(entry,aux,85,3);
    if (issue) return issue;
    const DseSyscallObservation *s = aux->syscall;
    if (s->result > INT32_MAX || !s->args[2] || s->args[2] > INT32_MAX)
        return "readlink_not_successful";
    issue = executable_source_issue(s);
    if (issue) return issue;
    const DseSyscallFileObservation *f = s->file;
    uint32_t expected = s->args[2] < f->link_size ? s->args[2] : f->link_size;
    if (s->result != expected || (uint64_t)s->args[1]+expected > (UINT64_C(1)<<32))
        return "readlink_result_or_range_mismatch";
    if (!f->reply_observed || !f->reply_valid || f->reply_size != expected ||
        memcmp(f->reply,f->link,expected)) return "readlink_output_mismatch";
    return NULL;
}

const char *dse_aux_close_issue(const TraceEntry *entry, const InsnAux *aux) {
    const char *issue = int80_register_issue(entry, aux, 6, 1);
    if (issue)
        return issue;
    const DseSyscallObservation *s = aux->syscall;
    if (!s->boundary_id || !s->boundary_ordered)
        return "syscall_order_unverified";
    /* Failed close can release an fd too. Do not guess its state from errno,
     * retry it, or treat an error as an effect-free transition. */
    if (s->result != 0)
        return "close_not_successful";
    return NULL;
}

const char *dse_aux_memfd_issue(const TraceEntry *entry, const InsnAux *aux) {
    const char *issue = int80_register_issue(entry, aux, 356, 2);
    if (issue)
        return issue;
    const DseSyscallObservation *s = aux->syscall;
    if (s->result > INT32_MAX)
        return "memfd_not_successful";
    if (!s->boundary_id || !s->boundary_ordered)
        return "syscall_order_unverified";
    if ((s->args[1] & ~UINT32_C(0x13)) || !(s->args[1] & 0x10U))
        return "memfd_flags_or_policy_unsupported";
    if (!s->name_observed || !s->name_size || s->name_size > DSE_MEMFD_NAME_BYTES ||
        s->name[s->name_size - 1] || memchr(s->name, 0, s->name_size - 1) ||
        (uint64_t)s->args[0] + s->name_size > (UINT64_C(1) << 32))
        return "memfd_name_incomplete";
    return NULL;
}

const char *dse_aux_old_mmap_issue(const TraceEntry *entry, const InsnAux *aux) {
    const char *issue = int80_register_issue(entry, aux, 90, 1);
    if (issue)
        return issue;
    const DseSyscallObservation *s = aux->syscall;
    if (!s->boundary_id || !s->boundary_ordered)
        return "syscall_order_unverified";
    if (!s->mmap_args_observed || !s->mmap_args_valid ||
        (uint64_t)s->args[0] + 24 > (UINT64_C(1) << 32))
        return "mmap_arguments_incomplete";
    if (s->result >= UINT32_C(0xfffff001))
        return "mmap_not_successful";
    const uint32_t *a = s->mmap_args;
    if (a[3] != 1 && a[3] != 2 && a[3] != 0x12)
        return "mmap_fixed_or_flags_unsupported";
    if (a[3] == 0x12 && (a[0] != s->result || (a[0] & 4095U)))
        return "mmap_fixed_address_mismatch";
    if ((a[2] & ~7U) || (a[2] && !(a[2] & 1U)))
        return "mmap_rights_unsupported";
    if (!a[1] || (s->result & 4095U) || (a[5] & 4095U) ||
        (uint64_t)s->result + (((uint64_t)a[1] + 4095U) & ~UINT64_C(4095)) >
            (UINT64_C(1) << 32))
        return "mmap_range_or_offset_unsupported";
    return NULL;
}

const char *dse_aux_ir_mmap_issue(const TraceEntry *entry,const InsnAux *aux,uint32_t out[6]) {
    const DseSyscallObservation *s=aux?aux->syscall:NULL;
    if(!s || (s->number!=90 && s->number!=192) || !out) return "mmap_abi_unsupported";
    const char *issue=int80_register_issue(entry,aux,s->number,s->number==90?1:6);
    if(issue) return issue;
    if(!s->boundary_id || !s->boundary_ordered) return "syscall_order_unverified";
    if(s->number==90) {
        if(!s->mmap_args_observed || !s->mmap_args_valid ||
           (uint64_t)s->args[0]+24>(UINT64_C(1)<<32)) return "mmap_arguments_incomplete";
        memcpy(out,s->mmap_args,24);
    } else {
        memcpy(out,s->args,24);
        uint64_t offset=(uint64_t)out[5]*4096U;
        if(offset>UINT32_MAX) return "mmap2_offset_unsupported";
        out[5]=(uint32_t)offset;
    }
    if(s->result>=UINT32_C(0xfffff001)) return "mmap_not_successful";
    if(out[3]!=1 && out[3]!=2 && out[3]!=0x11 && out[3]!=0x12 && out[3]!=0x32)
        return "mmap_fixed_or_flags_unsupported";
    if((out[3]&0x10U) && (out[0]!=s->result || (out[0]&4095U)))
        return "mmap_fixed_address_mismatch";
    if(out[3]==0x32 && (out[4]!=UINT32_MAX || out[5])) return "mmap_anonymous_contract";
    if((out[2]&~7U) || (out[2] && !(out[2]&1U))) return "mmap_rights_unsupported";
    if(!out[1] || (s->result&4095U) || (out[5]&4095U) ||
       (uint64_t)s->result+(((uint64_t)out[1]+4095U)&~UINT64_C(4095))>(UINT64_C(1)<<32))
        return "mmap_range_or_offset_unsupported";
    return NULL;
}
const char *dse_aux_msync_issue(const TraceEntry *entry,const InsnAux *aux) {
    const char *issue=int80_register_issue(entry,aux,144,3);
    if(issue) return issue;
    const DseSyscallObservation *s=aux->syscall;
    if(!s->boundary_id || !s->boundary_ordered) return "syscall_order_unverified";
    if(s->result) return "msync_not_successful";
    if((s->args[0]&4095U) || !s->args[1] || s->args[2]!=4 ||
       (uint64_t)s->args[0]+s->args[1]>(UINT64_C(1)<<32)) return "msync_range_or_flags";
    return NULL;
}
void dse_aux_syscall_brk_state(InsnAux *aux,const uint32_t words[4],bool valid,bool post) {
    DseSyscallObservation *s=aux?aux->syscall:NULL;
    if(!s || s->number!=45) return;
    valid=valid && words && words[0]==DSE_BRK_STATE_MAGIC && !words[3] &&
        words[1] && !(words[1]&4095U) && words[2]>=words[1];
    if(post) {
        s->brk_post_valid=valid && s->brk_entry_valid && words[1]==s->brk_initial;
        s->brk_after=s->brk_post_valid?words[2]:0;
    } else {
        s->brk_entry_valid=valid;s->brk_post_valid=false;
        s->brk_initial=valid?words[1]:0;s->brk_before=valid?words[2]:0;s->brk_after=0;
    }
}
const char *dse_aux_brk_issue(const TraceEntry *entry,const InsnAux *aux) {
    const char *issue=int80_register_issue(entry,aux,45,1);
    if(issue) return issue;
    const DseSyscallObservation *s=aux->syscall;
    if(!s->boundary_id || !s->boundary_ordered) return "syscall_order_unverified";
    if(!s->brk_entry_valid || !s->brk_post_valid) return "brk_state_unverified";
    if(!s->brk_initial || (s->brk_initial&4095U) || s->brk_before<s->brk_initial ||
       s->brk_after<s->brk_initial || s->result!=s->brk_after ||
       (s->args[0]<s->brk_initial && s->brk_after!=s->brk_before) ||
       (s->brk_after!=s->brk_before && s->brk_after!=s->args[0])) return "brk_transition_invalid";
    return NULL;
}

const char *dse_aux_write_issue(const TraceEntry *entry, const InsnAux *aux) {
    const char *issue = int80_register_issue(entry, aux, 4, 3);
    if (issue)
        return issue;
    const DseSyscallObservation *s = aux->syscall;
    if (!s->boundary_id || !s->boundary_ordered)
        return "syscall_order_unverified";
    if (s->result > INT32_MAX)
        return "write_not_successful";
    if (s->result > s->args[2])
        return "write_result_exceeds_count";
    if (!s->write_observed || !s->write_valid || s->write_size != s->args[2] ||
        s->write_size > DSE_SYSCALL_WRITE_BYTES || (s->write_size && !s->write_values) ||
        (uint64_t)s->args[1] + s->write_size > (UINT64_C(1) << 32))
        return "write_buffer_incomplete";
    return NULL;
}

const char *dse_aux_ftruncate_issue(const TraceEntry *entry, const InsnAux *aux) {
    return int80_register_issue(entry, aux, 93, 2);
}

const char *dse_aux_mprotect_issue(const TraceEntry *entry, const InsnAux *aux) {
    const char *issue = int80_register_issue(entry, aux, 125, 3);
    if (issue)
        return issue;
    const DseSyscallObservation *s = aux->syscall;
    /* A failed protection change is not an atomic no-op. The same restrictions
     * as IR's observed-mprotect contract exclude implicit x86 rights, growth
     * flags and wrapped intervals. Success changes permissions, not bytes. */
    if (s->result)
        return "mprotect_failed";
    if ((s->args[0] & 4095U) || (s->args[2] & ~7U) || (s->args[2] && !(s->args[2] & 1U)) ||
        (uint64_t)s->args[0] + (((uint64_t)s->args[1] + 4095U) & ~UINT64_C(4095)) >
            (UINT64_C(1) << 32))
        return "mprotect_range_or_rights_unsupported";
    return NULL;
}

static void dse_aux_mark_string_mismatch(InsnAux *aux, const char *reason, uint32_t event_index,
                                         uint64_t expected, uint64_t observed) {
    if (!aux)
        return;
    DseStringSummary *summary = &aux->string_summary;
    if (!summary->pattern_mismatch) {
        fprintf(stderr,
                "[DSE-STRING-MISMATCH] "
                "pc=0x%" PRIx64 " seq=%" PRIu64 " "
                "reason=%s event=%" PRIu32 " "
                "expected=0x%" PRIx64 " observed=0x%" PRIx64 "\n",
                aux->pc, aux->seq_id, reason ? reason : "unknown", event_index, expected, observed);
    }
    summary->pattern_mismatch = true;
}

static bool dse_aux_validate_string_address(InsnAux *aux, const char *reason,
                                            uint64_t first_address, uint32_t event_index,
                                            uint64_t observed_address) {
    if (!aux)
        return false;
    DseStringSummary *summary = &aux->string_summary;
    if (event_index == 0)
        return true;
    uint32_t first = (uint32_t)first_address;
    uint32_t observed = (uint32_t)observed_address;
    uint32_t distance = (uint32_t)((uint64_t)event_index * (uint64_t)summary->element_size);
    uint32_t forward = first + distance;
    uint32_t backward = first - distance;
    if (summary->direction == 0) {
        if (observed == forward) {
            summary->direction = 1;
            return true;
        }
        if (observed == backward) {
            summary->direction = -1;
            return true;
        }
        dse_aux_mark_string_mismatch(aux, reason, event_index, forward, observed);
        return false;
    }
    uint32_t expected = summary->direction > 0 ? forward : backward;
    if (observed != expected) {
        dse_aux_mark_string_mismatch(aux, reason, event_index, expected, observed);
        return false;
    }
    return true;
}

static void dse_aux_release_string(DseAuxRing *ring, InsnAux *aux) {
    if (!aux)
        return;
    DseStringSummary *summary = &aux->string_summary;
    uint64_t owned_bytes = (uint64_t)summary->capacity * 2U + summary->write_capacity;
    if (aux->syscall)
        owned_bytes += dse_aux_syscall_owned_bytes(aux->syscall);
    dse_aux_syscall_free(aux->syscall);
    aux->syscall = NULL;
    free(summary->values);
    free(summary->value_taint);
    free(summary->write_values);
    if (ring) {
        if (owned_bytes <= ring->dynamic_bytes) {
            ring->dynamic_bytes -= owned_bytes;
        } else {
            ring->dynamic_bytes = 0;
        }
    }
    memset(summary, 0, sizeof(*summary));
}

static bool dse_aux_string_reserve(DseAuxRing *ring, InsnAux *aux, uint32_t required) {
    if (!ring || !aux || required > DSE_MAX_STRING_BYTES_PER_INSN) {
        return false;
    }
    DseStringSummary *summary = &aux->string_summary;
    if (required <= summary->capacity) {
        return true;
    }
    uint32_t new_capacity = summary->capacity != 0 ? summary->capacity : 64U;
    while (new_capacity < required) {
        if (new_capacity >= DSE_MAX_STRING_BYTES_PER_INSN / 2U) {
            new_capacity = DSE_MAX_STRING_BYTES_PER_INSN;
            break;
        }
        new_capacity *= 2U;
    }
    uint64_t additional_bytes = (uint64_t)(new_capacity - summary->capacity) * 2U;
    if ((ring->dynamic_bytes > ring->max_dynamic_bytes) ||
        (additional_bytes > (ring->max_dynamic_bytes - ring->dynamic_bytes))) {
        return false;
    }
    uint8_t *new_values = malloc(new_capacity);
    uint8_t *new_taint = malloc(new_capacity);
    if (!new_values || !new_taint) {
        free(new_values);
        free(new_taint);
        return false;
    }
    if (summary->bytes_captured != 0) {
        memcpy(new_values, summary->values, summary->bytes_captured);
        memcpy(new_taint, summary->value_taint, summary->bytes_captured);
    }
    free(summary->values);
    free(summary->value_taint);
    summary->values = new_values;
    summary->value_taint = new_taint;
    summary->capacity = new_capacity;
    ring->dynamic_bytes += additional_bytes;
    return true;
}

DseAuxRing *dse_aux_create(uint32_t capacity) {
    if (!(capacity > 0 && (capacity & (capacity - 1)) == 0))
        return NULL;
    DseAuxRing *r = calloc(1, sizeof(*r));
    if (!r)
        return NULL;
    r->entries = calloc(capacity, sizeof(InsnAux));
    if (!r->entries) {
        free(r);
        return NULL;
    }
    r->capacity = capacity;
    r->dynamic_bytes = 0;
    r->max_dynamic_bytes = DSE_MAX_STRING_TRACE_BYTES;
    r->max_source_bytes = 8U * 1024U * 1024U;
    return r;
}

void dse_aux_destroy(DseAuxRing *ring) {
    if (!ring)
        return;
    if (ring->entries) {
        for (uint32_t index = 0; index < ring->capacity; index++) {
            dse_aux_release_string(ring, &ring->entries[index]);
        }
    }
    free(ring->entries);
    free(ring->source_history);
    free(ring);
}

static bool trace_entry_index(const TraceBuffer *tb, const TraceEntry *entry, uint32_t *out_idx) {
    if (!tb || !tb->entries || !entry || !out_idx)
        return false;
    uintptr_t base = (uintptr_t)tb->entries;
    uintptr_t ptr = (uintptr_t)entry;
    size_t bytes = (size_t)tb->capacity * sizeof(*tb->entries);
    if (ptr < base || ptr - base >= bytes)
        return false;
    uintptr_t offset = ptr - base;
    if (offset % sizeof(*tb->entries) != 0)
        return false;
    *out_idx = (uint32_t)(offset / sizeof(*tb->entries));
    return true;
}

InsnAux *dse_aux_record(DseAuxRing *r, const TraceBuffer *tb, const TraceEntry *entry,
                        const InsnAux *aux) {
    if (!r || !r->entries || !tb || !entry || !aux || entry->seq_id == 0)
        return NULL;
    uint32_t idx;
    if (!trace_entry_index(tb, entry, &idx) || idx >= r->capacity)
        return NULL;
    InsnAux *stored = &r->entries[idx];
    const DseSourceObservation *source = dse_aux_sources(aux);
    /* Copy before releasing the destination: aux may be that same ring slot. */
    DseSyscallObservation *syscall = dse_aux_syscall_copy(aux->syscall, r->max_dynamic_bytes);
    bool has_syscall = aux->syscall != NULL;
    bool source_lost = aux->source_metadata_lost || (aux->sources && !source);
    dse_aux_release_string(r, stored);
    *stored = *aux;
    stored->syscall = NULL;
    if (has_syscall) {
        size_t bytes = dse_aux_syscall_owned_bytes(syscall);
        if (syscall && r->dynamic_bytes <= r->max_dynamic_bytes &&
            bytes <= r->max_dynamic_bytes - r->dynamic_bytes) {
            stored->syscall = syscall;
            syscall = NULL;
            r->dynamic_bytes += bytes;
        } else {
            stored->syscall_metadata_lost = true;
        }
    }
    dse_aux_syscall_free(syscall);
    stored->valid = true;
    stored->seq_id = entry->seq_id;
    stored->meta_id = entry->meta_id;
    stored->pc = entry->pc;
    stored->source_metadata_lost = source_lost;
    (void)dse_aux_record_sources(r, stored, source);
    return stored;
}

bool dse_aux_discard(DseAuxRing *ring, const TraceBuffer *trace, const TraceEntry *entry) {
    uint32_t index;
    if (!ring || !ring->entries || !entry || !entry->seq_id ||
        !trace_entry_index(trace, entry, &index) || index >= ring->capacity)
        return false;
    InsnAux *stored = &ring->entries[index];
    if (stored->valid) {
        dse_aux_release_string(ring, stored);
        memset(stored, 0, sizeof(*stored));
    }
    return true;
}

static bool df_preserving_instruction(const InsnMeta *meta) {
    if (!meta || meta->writes_df)
        return false;
    if (meta->family != DTA_FAMILY_UNSUPPORTED || meta->is_conditional_branch ||
        insn_meta_is_plain_scasd(meta))
        return true;
    switch (meta->insn_id) {
    case X86_INS_JMP:
    case X86_INS_NOP:
    case X86_INS_CBW:
    case X86_INS_CWDE:
    case X86_INS_CWD:
    case X86_INS_CDQ:
    case X86_INS_BSWAP:
        return true;
    default:
        return false;
    }
}

static bool observed_int80_return(const TraceEntry *entry, const InsnAux *before,
                                   const InsnAux *after) {
    /* Narrow i386 Linux INT 80 contract. These ordinary returning calls do not
     * restore a CPU context. In particular, sigreturn/exec/clone and every
     * unlisted call remain barriers, even when their observed DF is unchanged. */
    const DseSyscallObservation *s = before->syscall;
    if (!s || before->syscall_metadata_lost || !s->returned || s->invalid ||
        entry->size != 2 || entry->instr_bytes[0] != 0xcd || entry->instr_bytes[1] != 0x80 ||
        s->seq_id != entry->seq_id || s->pc != entry->pc ||
        s->descriptor_id != entry->insn_desc_id || s->bytes_hash != entry->bytes_hash ||
        s->code_generation != entry->code_generation || s->vcpu_index != entry->vcpu_index ||
        ((before->eflags_before | after->eflags_before) & (UINT32_C(1) << 17)) != 0 ||
        !(before->reg_value_valid_mask & (UINT32_C(1) << DTA_REG_RAX)) ||
        !(after->reg_value_valid_mask & (UINT32_C(1) << DTA_REG_RAX)) ||
        (uint32_t)before->reg_vals[DTA_REG_RAX] != s->number ||
        (uint32_t)after->reg_vals[DTA_REG_RAX] != s->result)
        return false;
    return true;
}

static bool df_observed_syscall(const TraceEntry *entry, const InsnAux *before,
                                const InsnAux *after) {
    if (!observed_int80_return(entry, before, after))
        return false;
    const DseSyscallObservation *s = before->syscall;
    switch (s->number) {
    case 6:   /* close */
    case 90:  /* old_mmap */
    case 91:  /* munmap */
    case 144: /* msync */
        return true;
    default:
        return false;
    }
}

static bool es_preserving_instruction(const InsnMeta *meta, const TraceEntry *entry,
                                      const InsnAux *before, const InsnAux *after) {
    if (!meta || meta->writes_es)
        return false;
    if (meta->insn_id == X86_INS_INT) {
        if (!observed_int80_return(entry, before, after))
            return false;
        /* These i386 Linux calls do not restore a CPU context or load ES.
         * This certifies only ES preservation, not their memory/return model. */
        switch (before->syscall->number) {
        case 3: case 4: case 5: case 6: /* read, write, open, close */
        case 45: case 85: case 90: case 91: case 93: /* brk, readlink, mmap, munmap, ftruncate */
        case 125: case 144: case 192: case 356: /* mprotect, msync, mmap2, memfd_create */
            return true;
        default:
            return false; /* includes sigreturn, clone and exec */
        }
    }
    return df_preserving_instruction(meta) || meta->insn_id == X86_INS_CLD ||
        meta->insn_id == X86_INS_STD || meta->insn_id == X86_INS_LOOP ||
        meta->insn_id == X86_INS_ENDBR32 ||
        meta->insn_id == X86_INS_SCASB || meta->insn_id == X86_INS_SCASW ||
        meta->insn_id == X86_INS_SCASD;
}

void dse_aux_carry_x86_df(InsnAux *current, const TraceEntry *entry,
                         const TraceBuffer *trace, const InsnAux *previous) {
    if (!current)
        return;
    current->df_before = (DseDirectionFact){0};
    if (!entry || !trace || !current->eflags_valid || !previous || !previous->valid ||
        !previous->execution_complete || !previous->eflags_valid ||
        !previous->next_pc_valid || previous->next_pc != entry->pc ||
        previous->seq_id == 0 || previous->seq_id == UINT64_MAX ||
        previous->seq_id + 1 != entry->seq_id)
        return;
    const TraceEntry *prior = trace_find_seq(trace, previous->seq_id, NULL);
    if (!prior || prior->vcpu_index != entry->vcpu_index || prior->pc != previous->pc ||
        prior->meta_id != previous->meta_id)
        return;
    const InsnDesc *desc = trace_insn_desc_get(trace, prior->insn_desc_id);
    const InsnMeta *meta = meta_lookup_id(prior->meta_id);
    if (!desc || !meta || desc->arch != TRACE_ARCH_X86 || desc->mode != TRACE_MODE_32 ||
        desc->pc != prior->pc || desc->meta_id != prior->meta_id ||
        desc->code_generation != prior->code_generation ||
        desc->bytes_hash != prior->bytes_hash || desc->size != prior->size ||
        memcmp(desc->bytes, prior->instr_bytes, desc->size) != 0 ||
        meta->size != desc->size || memcmp(meta->instr_bytes, desc->bytes, desc->size) != 0)
        return;
    /* A discontinuity after an ordinary instruction may be an exception/signal.
     * Direct transfers must have one of their architectural successors. */
    uint64_t fallthrough = (uint32_t)(prior->pc + prior->size);
    bool loop = meta->insn_id == X86_INS_LOOP && desc->size == 2 && desc->bytes[0] == 0xe2;
    if (loop && entry->pc != fallthrough &&
        entry->pc != (uint32_t)(fallthrough + (int8_t)desc->bytes[1]))
        return;
    if (!loop && desc->effects.branch_kind == TRACE_BRANCH_NONE && entry->pc != fallthrough)
        return;
    if (desc->effects.direct_target_valid &&
        entry->pc != (uint32_t)desc->effects.direct_target &&
        !(meta->is_conditional_branch && entry->pc == fallthrough))
        return;
    DseDirectionFact fact = previous->df_before;
    bool syscall_step = meta->insn_id == X86_INS_INT &&
                        df_observed_syscall(prior, previous, current);
    if (desc->size == 1 &&
        ((meta->insn_id == X86_INS_CLD && desc->bytes[0] == 0xfc) ||
         (meta->insn_id == X86_INS_STD && desc->bytes[0] == 0xfd))) {
        fact = (DseDirectionFact){.writer_seq = prior->seq_id, .writer_pc = prior->pc,
            .writer_bytes_hash = prior->bytes_hash, .writer_descriptor = prior->insn_desc_id,
            .writer_generation = prior->code_generation, .vcpu_index = prior->vcpu_index,
            .value = meta->insn_id == X86_INS_STD, .valid = true};
    } else if ((!df_preserving_instruction(meta) && !loop && !syscall_step) || !fact.valid ||
               fact.boundary_seq != prior->seq_id || fact.vcpu_index != prior->vcpu_index ||
               fact.value > 1 || ((previous->eflags_before >> 10) & 1U) != fact.value) {
        return;
    }
    if (((current->eflags_before >> 10) & 1U) != fact.value)
        return;
    if (syscall_step) {
        if (fact.syscall_steps == UINT32_MAX)
            return;
        fact.syscall_steps++;
    }
    fact.boundary_seq = entry->seq_id;
    current->df_before = fact;
}

void dse_aux_prepare_string(InsnAux *aux, const InsnMeta *meta) {
    if (!aux || !meta || meta->string_element_size == 0) {
        return;
    }
    DseStringSummary *summary = &aux->string_summary;
    summary->element_size = meta->string_element_size;
    summary->has_rep_prefix = meta->has_rep_prefix;
    summary->pattern_mismatch = false;
    summary->expected_iterations = meta->has_rep_prefix ? (uint32_t)aux->reg_vals[DTA_REG_RCX] : 1U;
    summary->direction = 0;
    switch (meta->insn_id) {
    case X86_INS_MOVSB:
    case X86_INS_MOVSW:
    case X86_INS_MOVSD:
    case X86_INS_MOVSQ:
        summary->kind = DSE_STRING_MOVS;
        break;
    case X86_INS_STOSB:
    case X86_INS_STOSW:
    case X86_INS_STOSD:
    case X86_INS_STOSQ:
        summary->kind = DSE_STRING_STOS;
        break;
    default:
        return;
    }
    uint32_t required_registers = 1U << DTA_REG_RDI;
    if (summary->kind == DSE_STRING_MOVS) {
        required_registers |= 1U << DTA_REG_RSI;
    } else {
        required_registers |= 1U << DTA_REG_RAX;
    }
    if (summary->has_rep_prefix) {
        required_registers |= 1U << DTA_REG_RCX;
    }
    if ((aux->reg_value_valid_mask & required_registers) != required_registers) {
        dse_aux_mark_string_mismatch(aux, "register-snapshot-incomplete", 0, required_registers,
                                     aux->reg_value_valid_mask);
    }
    summary->active = true;
}

bool dse_aux_capture_string_read(DseAuxRing *ring, InsnAux *aux, uint64_t address, uint64_t value,
                                 bool value_valid, uint8_t value_taint, uint32_t size) {
    if (!ring || !aux)
        return false;
    DseStringSummary *summary = &aux->string_summary;
    if (!summary->active || summary->kind != DSE_STRING_MOVS) {
        return false;
    }
    if (!value_valid) {
        dse_aux_mark_string_mismatch(aux, "read-value-unavailable", summary->read_events, 1, 0);
        return false;
    }
    if (size == 0 || size != summary->element_size || size > 8U) {
        dse_aux_mark_string_mismatch(aux, "read-element-size", summary->read_events,
                                     summary->element_size, size);
        return false;
    }
    uint32_t event_index = summary->read_events;
    if (event_index == 0) {
        summary->source_first = address;
        if ((uint32_t)address != (uint32_t)aux->reg_vals[DTA_REG_RSI]) {
            dse_aux_mark_string_mismatch(aux, "source-base", event_index,
                                         (uint32_t)aux->reg_vals[DTA_REG_RSI], (uint32_t)address);
        }
    } else {
        (void)dse_aux_validate_string_address(aux, "source-sequence", summary->source_first,
                                              event_index, address);
    }
    if (summary->read_events != UINT32_MAX) {
        summary->read_events++;
    }
    if (summary->bytes_captured > (DSE_MAX_STRING_BYTES_PER_INSN - size) ||
        !dse_aux_string_reserve(ring, aux, summary->bytes_captured + size)) {
        summary->overflow = true;
        return false;
    }
    for (uint32_t byte = 0; byte < size; byte++) {
        uint32_t index = summary->bytes_captured + byte;
        summary->values[index] = (uint8_t)((value >> (8U * byte)) & UINT64_C(0xff));
        summary->value_taint[index] = (value_taint & (uint8_t)(1U << byte)) != 0;
    }
    summary->bytes_captured += size;
    return true;
}

void dse_aux_capture_string_write(InsnAux *aux, uint64_t address, uint32_t size) {
    if (!aux)
        return;
    DseStringSummary *summary = &aux->string_summary;
    if (!summary->active)
        return;
    if (size == 0 || size != summary->element_size) {
        dse_aux_mark_string_mismatch(aux, "write-element-size", summary->write_events,
                                     summary->element_size, size);
        return;
    }
    uint32_t event_index = summary->write_events;
    if (event_index == 0) {
        summary->destination_first = address;
        if ((uint32_t)address != (uint32_t)aux->reg_vals[DTA_REG_RDI]) {
            dse_aux_mark_string_mismatch(aux, "destination-base", event_index,
                                         (uint32_t)aux->reg_vals[DTA_REG_RDI], (uint32_t)address);
        }
    } else {
        (void)dse_aux_validate_string_address(aux, "destination-sequence",
                                              summary->destination_first, event_index, address);
    }
    if (summary->write_events != UINT32_MAX) {
        summary->write_events++;
    }
}

void dse_aux_capture_string_write_value(DseAuxRing *ring, InsnAux *aux, uint64_t address,
                                        uint32_t size, uint64_t value, bool value_valid) {
    if (!aux || !aux->string_summary.active) return;
    dse_aux_capture_string_write(aux, address, size);
    DseStringSummary *s = &aux->string_summary;
    if (!ring || s->write_values_incomplete || !value_valid || !size || size > 8 ||
        size != s->element_size || s->write_bytes_captured > DSE_MAX_STRING_BYTES_PER_INSN - size) {
        s->write_values_incomplete = true;
        return;
    }
    uint32_t required = s->write_bytes_captured + size;
    if (required > s->write_capacity) {
        uint32_t capacity = s->write_capacity ? s->write_capacity : 64;
        while (capacity < required) capacity *= 2;
        uint64_t extra = capacity - s->write_capacity;
        if (ring->dynamic_bytes > ring->max_dynamic_bytes ||
            extra > ring->max_dynamic_bytes - ring->dynamic_bytes) {
            s->write_values_incomplete = true;
            return;
        }
        uint8_t *p = realloc(s->write_values, capacity);
        if (!p) { s->write_values_incomplete = true; return; }
        s->write_values = p;
        s->write_capacity = capacity;
        ring->dynamic_bytes += extra;
    }
    for (unsigned i = 0; i < size; ++i)
        s->write_values[s->write_bytes_captured++] = (uint8_t)(value >> (i * 8U));
}

static int8_t dse_aux_direction_from_post_state(uint32_t before, uint32_t after,
                                                uint32_t byte_count) {
    if (byte_count == 0) {
        return after == before ? 1 : 0;
    }
    uint32_t forward = before + byte_count;
    uint32_t backward = before - byte_count;
    if (after == forward)
        return 1;
    if (after == backward)
        return -1;
    return 0;
}

static bool dse_aux_resolve_string_post_state(InsnAux *aux, const uint64_t post_reg_vals[REG_COUNT],
                                              uint32_t post_reg_value_valid_mask) {
    if (!aux)
        return false;
    DseStringSummary *summary = &aux->string_summary;
    uint64_t byte_count_64 =
        (uint64_t)summary->expected_iterations * (uint64_t)summary->element_size;
    if (byte_count_64 > UINT32_MAX) {
        dse_aux_mark_string_mismatch(aux, "string-byte-count-overflow", 0, UINT32_MAX,
                                     byte_count_64);
        return false;
    }
    uint32_t required_registers = UINT32_C(1) << DTA_REG_RDI;
    if (summary->kind == DSE_STRING_MOVS) {
        required_registers |= UINT32_C(1) << DTA_REG_RSI;
    }
    if (summary->has_rep_prefix) {
        required_registers |= UINT32_C(1) << DTA_REG_RCX;
    }
    if ((aux->reg_value_valid_mask & required_registers) != required_registers) {
        dse_aux_mark_string_mismatch(aux, "pre-register-snapshot-incomplete", 0, required_registers,
                                     aux->reg_value_valid_mask);
        return false;
    }
    if (!post_reg_vals || (post_reg_value_valid_mask & required_registers) != required_registers) {
        dse_aux_mark_string_mismatch(aux, "post-register-snapshot-incomplete", 0,
                                     required_registers, post_reg_value_valid_mask);
        return false;
    }

    uint32_t byte_count = (uint32_t)byte_count_64;
    uint32_t edi_before = (uint32_t)aux->reg_vals[DTA_REG_RDI];
    uint32_t edi_after = (uint32_t)post_reg_vals[DTA_REG_RDI];
    int8_t resolved_direction =
        dse_aux_direction_from_post_state(edi_before, edi_after, byte_count);
    if (resolved_direction == 0) {
        dse_aux_mark_string_mismatch(aux, "destination-post-state", 0, byte_count,
                                     (uint32_t)(edi_after - edi_before));
        return false;
    }
    if (summary->kind == DSE_STRING_MOVS) {
        uint32_t esi_before = (uint32_t)aux->reg_vals[DTA_REG_RSI];
        uint32_t esi_after = (uint32_t)post_reg_vals[DTA_REG_RSI];
        int8_t source_direction =
            dse_aux_direction_from_post_state(esi_before, esi_after, byte_count);
        if (source_direction == 0) {
            dse_aux_mark_string_mismatch(aux, "source-post-state", 0, byte_count,
                                         (uint32_t)(esi_after - esi_before));
            return false;
        }
        if (source_direction != resolved_direction) {
            dse_aux_mark_string_mismatch(aux, "source-destination-direction", 0,
                                         resolved_direction > 0 ? 1U : 0U,
                                         source_direction > 0 ? 1U : 0U);
            return false;
        }
    }
    if (summary->direction != 0 && summary->direction != resolved_direction) {
        dse_aux_mark_string_mismatch(aux, "address-post-direction", 0,
                                     summary->direction > 0 ? 1U : 0U,
                                     resolved_direction > 0 ? 1U : 0U);
        return false;
    }
    summary->direction = resolved_direction;
    if (summary->has_rep_prefix && (uint32_t)post_reg_vals[DTA_REG_RCX] != 0) {
        dse_aux_mark_string_mismatch(aux, "rep-count-post-state", 0, 0,
                                     (uint32_t)post_reg_vals[DTA_REG_RCX]);
        return false;
    }
    return true;
}

void dse_aux_finalize(InsnAux *aux, uint64_t next_pc, const uint64_t post_reg_vals[REG_COUNT],
                      uint32_t post_reg_value_valid_mask) {
    if (!aux)
        return;
    if (aux->syscall) {
        DseSyscallObservation *s = aux->syscall;
        if (aux->execution_complete || s->post_observed)
            s->invalid = true;
        s->post_observed = true;
        s->post_valid_mask = post_reg_vals ? post_reg_value_valid_mask & 255U : 0;
        for (unsigned i = 0; i < 8; ++i) {
            if (post_reg_vals && post_reg_vals[i] <= UINT32_MAX)
                s->post_regs[i] = (uint32_t)post_reg_vals[i];
            else
                s->post_valid_mask &= ~(1U << i);
        }
    }
    aux->next_pc = next_pc;
    aux->next_pc_valid = true;
    aux->execution_complete = true;
    DseStringSummary *summary = &aux->string_summary;
    if (!summary->active)
        return;
    uint64_t expected_bytes =
        (uint64_t)summary->expected_iterations * (uint64_t)summary->element_size;
    bool post_state_valid =
        dse_aux_resolve_string_post_state(aux, post_reg_vals, post_reg_value_valid_mask);
    if (summary->kind == DSE_STRING_MOVS) {
        summary->exact = post_state_valid && !summary->overflow && !summary->pattern_mismatch &&
                         summary->read_events == summary->expected_iterations &&
                         summary->write_events == summary->expected_iterations &&
                         expected_bytes == summary->bytes_captured;
    } else if (summary->kind == DSE_STRING_STOS) {
        summary->exact = post_state_valid && !summary->overflow && !summary->pattern_mismatch &&
                         summary->write_events == summary->expected_iterations &&
                         expected_bytes <= DSE_MAX_STRING_BYTES_PER_INSN;
    }
}

static bool dse_aux_has_exact_string_kind(const InsnAux *aux, DseStringKind expected_kind) {
    if (!aux || !aux->execution_complete) {
        return false;
    }
    const DseStringSummary *summary = &aux->string_summary;
    if (!summary->active || !summary->exact || summary->kind != expected_kind ||
        summary->overflow || summary->pattern_mismatch ||
        (summary->element_size != 1U && summary->element_size != 2U &&
         summary->element_size != 4U && summary->element_size != 8U) ||
        (summary->direction != 1 && summary->direction != -1) ||
        (!summary->has_rep_prefix && summary->expected_iterations != 1U)) {
        return false;
    }
    uint64_t total_bytes = (uint64_t)summary->expected_iterations * summary->element_size;
    if (total_bytes > DSE_MAX_STRING_BYTES_PER_INSN) {
        return false;
    }
    if (summary->expected_iterations == 0) {
        return summary->has_rep_prefix && summary->read_events == 0 && summary->write_events == 0 &&
               aux->mem_read_total == 0 && aux->mem_write_total == 0;
    }
    if (!aux->mem_write_range_valid || aux->mem_write_range_unknown ||
        aux->mem_write_total != summary->expected_iterations ||
        summary->write_events != summary->expected_iterations) {
        return false;
    }
    if (expected_kind == DSE_STRING_MOVS) {
        return (aux->mem_read_range_valid && !aux->mem_read_range_unknown &&
                aux->mem_read_total == summary->expected_iterations &&
                summary->read_events == summary->expected_iterations &&
                summary->bytes_captured == total_bytes &&
                summary->capacity >= summary->bytes_captured && summary->values != NULL &&
                summary->value_taint != NULL);
    }
    return aux->mem_read_total == 0 && summary->read_events == 0 && summary->bytes_captured == 0;
}

bool dse_aux_has_exact_movs(const InsnAux *aux) {
    return dse_aux_has_exact_string_kind(aux, DSE_STRING_MOVS);
}

bool dse_aux_has_exact_stos(const InsnAux *aux) {
    return dse_aux_has_exact_string_kind(aux, DSE_STRING_STOS);
}

const InsnAux *dse_aux_for(const DseAuxRing *r, const TraceBuffer *tb, const TraceEntry *entry) {
    if (!r || !r->entries || !tb || !entry || entry->seq_id == 0)
        return NULL;
    uint32_t idx;
    if (!trace_entry_index(tb, entry, &idx) || idx >= r->capacity)
        return NULL;
    const InsnAux *aux = &r->entries[idx];
    if (!aux->valid || aux->pc != entry->pc || aux->seq_id != entry->seq_id ||
        aux->meta_id != entry->meta_id) {
        return NULL;
    }
    return aux;
}

bool dse_aux_materialize_occurrence(const DseAuxRing *ring, const TraceBuffer *trace,
                                    const TraceEntry *entry, InsnOccurrence *out) {
    if (!trace || !entry || !out || !trace_occurrence_from_entry(entry, out)) {
        return false;
    }
    const InsnDesc *desc = trace_insn_desc_get(trace, entry->insn_desc_id);
    if (!desc || desc->meta_id != entry->meta_id || desc->pc != entry->pc ||
        desc->code_generation != entry->code_generation || desc->bytes_hash != entry->bytes_hash) {
        out->incomplete_reasons |= TRACE_OCCURRENCE_DESC_MISSING;
    } else {
        out->incomplete_reasons &= ~TRACE_OCCURRENCE_DESC_MISSING;
    }

    const InsnAux *aux = dse_aux_for(ring, trace, entry);
    if (!aux) {
        out->incomplete_reasons |= TRACE_OCCURRENCE_AUX_MISSING;
        return true;
    }
    out->dynamic_effects_available = true;
    out->execution_complete = aux->execution_complete;
    out->next_pc_valid = aux->next_pc_valid;
    out->next_pc = aux->next_pc;
    if (!aux->execution_complete) {
        out->incomplete_reasons |= TRACE_OCCURRENCE_EXECUTION_PENDING;
    }
    if (aux->mem_read_overflow) {
        out->incomplete_reasons |= TRACE_OCCURRENCE_READ_OVERFLOW;
    }
    if (aux->mem_write_overflow) {
        out->incomplete_reasons |= TRACE_OCCURRENCE_WRITE_OVERFLOW;
    }
    if (aux->mem_read_range_unknown || aux->mem_write_range_unknown) {
        out->incomplete_reasons |= TRACE_OCCURRENCE_RANGE_UNKNOWN;
    }
    out->mem_read_total = aux->mem_read_total;
    out->mem_write_total = aux->mem_write_total;
    out->mem_read_range_valid = aux->mem_read_range_valid;
    out->mem_write_range_valid = aux->mem_write_range_valid;
    out->mem_read_min_addr = aux->mem_read_min_addr;
    out->mem_read_max_addr = aux->mem_read_max_addr;
    out->mem_write_min_addr = aux->mem_write_min_addr;
    out->mem_write_max_addr = aux->mem_write_max_addr;
    out->mem_read_count =
        aux->mem_read_count <= TRACE_MAX_MEM_EFFECTS ? aux->mem_read_count : TRACE_MAX_MEM_EFFECTS;
    out->mem_write_count = aux->mem_write_count <= TRACE_MAX_MEM_EFFECTS ? aux->mem_write_count
                                                                         : TRACE_MAX_MEM_EFFECTS;

    for (uint8_t index = 0; index < out->mem_read_count; index++) {
        const DseMemRead *source = &aux->mem_reads[index];
        TraceMemoryEffect *target = &out->mem_reads[index];
        target->kind = TRACE_MEM_READ;
        target->address = source->addr;
        target->value = source->value;
        target->size = source->size;
        target->taint_mask = source->taint;
        target->effective_taint_mask = source->effective_taint;
        target->value_valid = source->value_valid;
        target->address_tainted = source->address_tainted;
        if (!source->value_valid) {
            out->incomplete_reasons |= TRACE_OCCURRENCE_VALUE_MISSING;
        }
    }
    for (uint8_t index = 0; index < out->mem_write_count; index++) {
        const DseMemWrite *source = &aux->mem_writes[index];
        TraceMemoryEffect *target = &out->mem_writes[index];
        target->kind = TRACE_MEM_WRITE;
        target->address = source->addr;
        target->value = source->value;
        target->size = source->size;
        target->value_valid = source->value_valid;
        target->address_tainted = source->address_tainted;
        if (!source->value_valid) {
            out->incomplete_reasons |= TRACE_OCCURRENCE_VALUE_MISSING;
        }
    }
    return true;
}

bool dse_aux_archive_occurrence(const DseAuxRing *ring, TraceBuffer *trace,
                                const BranchEventBuffer *branch_events, uint64_t seq_id) {
    if (!ring || !trace || seq_id == 0) {
        if (trace) {
            trace_occurrence_archive_note_loss(trace);
        }
        return false;
    }

    const TraceEntry *entry = trace_find_seq(trace, seq_id, NULL);

    if (!entry) {
        trace_occurrence_archive_note_loss(trace);
        return false;
    }

    InsnOccurrence occurrence;

    if (!dse_aux_materialize_occurrence(ring, trace, entry, &occurrence)) {
        trace_occurrence_archive_note_loss(trace);
        return false;
    }

    const BranchEvent *event =
        branch_event_find_seq(branch_events, occurrence.seq_id, occurrence.vcpu_index);

    if (event) {
        (void)trace_occurrence_apply_branch_event(&occurrence, event);
    } else if (occurrence.execution_complete) {
        const InsnDesc *desc = trace_insn_desc_get(trace, occurrence.desc_id);

        if (desc && desc->effects.branch_kind == TRACE_BRANCH_CONDITIONAL) {
            occurrence.incomplete_reasons |= TRACE_OCCURRENCE_BRANCH_MISMATCH;
        }
    }

    return trace_occurrence_archive_append(trace, &occurrence);
}
