#ifndef TAINTFORGE_IR_ENVIRONMENT_H
#define TAINTFORGE_IR_ENVIRONMENT_H

#include "ir.h"

/* A bounded, serialized fresh-file model. Contents and memory aliases are IR
 * values, so the concrete evaluator and SMT execute the same effects. This
 * module knows no x86 register IDs, syscall numbers, QEMU or observed bytes. */
#define IR_ENV_API 3
#define IR_ENV_MAX_FILES 64U
#define IR_ENV_MAX_MAPPINGS 64U
#define IR_ENV_STATE_KEY_BASE UINT64_C(0x10000)
typedef struct IrEnvironment IrEnvironment;
typedef struct {
    uint32_t files_created, files_live, descriptors_live, resizes, closes;
    uint32_t mappings_created, mappings_live, replacements, unmapped;
    uint32_t writes, bytes_stored, live_content_cells;
    uint32_t memory_loads, memory_stores, fetch_bytes;
    uint32_t external_opens;
    uint32_t anonymous_maps, shared_fixed_maps, syncs, brk_calls;
    uint32_t brk_initial, brk_current;
    bool brk_initialized;
} IrEnvironmentStats;

IrEnvironment *ir_environment_create(IrModule *module, IrStateId guest_memory,
                                     uint32_t max_files, uint32_t max_content_cells);
void ir_environment_destroy(IrEnvironment *environment);
IrEnvironmentStats ir_environment_stats(const IrEnvironment *environment);
const char *ir_environment_issue(const IrEnvironment *environment);
bool ir_environment_budget(const IrEnvironment *environment);
size_t ir_environment_bytes(const IrEnvironment *environment);
bool ir_environment_has_files(const IrEnvironment *environment);
bool ir_environment_has_state(const IrEnvironment *environment);
bool ir_environment_mapped(const IrEnvironment *environment, uint32_t address);
/* First accepted event establishes the boundary; subsequent syscall boundaries
 * must be adjacent while an object is live. Instruction sequence is monotonic. */
bool ir_environment_order(IrEnvironment *environment, uint64_t boundary, uint64_t seq,
                           uint32_t vcpu, bool ordered);

bool ir_environment_file_create(IrEnvironment *environment, IrBlockId block, IrOrigin origin,
                                 uint32_t fd, uint32_t flags, uint64_t identity);
/* Open an explicitly supplied immutable array through a read-only descriptor.
 * Normalize bytes beyond size to zero; contents remain IR values. */
bool ir_environment_file_open(IrEnvironment *environment, IrBlockId block, IrOrigin origin,
                               uint32_t fd, uint32_t flags, uint64_t identity,
                               uint32_t size, IrValueId contents);
bool ir_environment_resize(IrEnvironment *environment, IrBlockId block, IrOrigin origin,
                            uint32_t fd, uint32_t size);
bool ir_environment_close(IrEnvironment *environment, uint32_t fd);
/* Mapping flags: 1=shared, 2=private, 0x11=fixed shared, 0x32=fixed anonymous,
 * 0x12=exact shared-to-private replacement.
 * File range must be within size, though the final partial page is mapped.
 * One mapping per object; resizing after the first mapping is unsupported. */
bool ir_environment_map(IrEnvironment *environment, IrBlockId block, IrOrigin origin,
                         uint32_t fd, uint32_t base, uint32_t length, uint32_t offset,
                         uint32_t flags, uint32_t permissions);
bool ir_environment_protect(IrEnvironment *environment, uint32_t base, uint64_t end,
                             uint32_t permissions, bool apply);
bool ir_environment_unmap(IrEnvironment *environment, uint32_t base, uint64_t end, bool apply);
/* MS_SYNC only, one known shared memfd view covering the requested interval.
 * Shared stores already update file contents; this checks the synchronization
 * contract without adding independent evaluator/SMT semantics. */
bool ir_environment_sync(IrEnvironment *environment, uint32_t base, uint32_t length,
                          uint32_t flags);
/* Fixed observed process break. Caller supplies independently observed entry
 * and post values, guards syscall arguments and updates frontend permissions.
 * New heap pages are zero; page-aligned shrink releases anonymous views.
 * Initial heap bytes stay in the explicit entry RAM domain. */
bool ir_environment_brk(IrEnvironment *environment, IrBlockId block, IrOrigin origin,
                         uint32_t initial, uint32_t before, uint32_t requested,
                         uint32_t after);
/* Check before kernel buffer reads; then write the same BV8 values. Partial
 * writes consume only returned bytes. No file growth, private/executable
 * mapped mutation, or copy-in buffer alias with the destination file. */
bool ir_environment_write_check(IrEnvironment *environment, uint32_t fd,
                                 uint32_t address, uint32_t written);
bool ir_environment_write(IrEnvironment *environment, IrBlockId block, IrOrigin origin,
                           uint32_t fd, const IrValueId *bytes, uint32_t count);

/* These emit little-endian memory semantics. Caller emits access guards.
 * Mapping selection uses IR predicates, never observed address constants. */
IrValueId ir_environment_load(IrEnvironment *environment, IrBlockId block, IrOrigin origin,
                              IrValueId address, unsigned bytes);
void ir_environment_store(IrEnvironment *environment, IrBlockId block, IrOrigin origin,
                           IrValueId address, unsigned bytes, IrValueId value);
/* Constrain executed bytes in current modeled mappings, including anonymous
 * views and shared EOF tails. PC is a fixed occurrence: mapping and offset
 * selection are specialized in C, while each byte remains LOAD(current state)
 * == captured byte under a GUARD. No cached contents or observed-value folding.
 * Caller retains execute-permission and trace-control checks. */
bool ir_environment_fetch(IrEnvironment *environment, IrBlockId block, IrOrigin origin,
                           uint32_t pc, const uint8_t *bytes, unsigned size);

#endif
