#include "ir_lift_x86.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    uint32_t start;
    uint64_t end;
    unsigned access;
} ProtectedRange;

struct IrX86Frontend {
    IrModule *module;
    csh decoder;
    IrX86Options options;
    IrX86State state;
    IrEnvironment *environment; /* Borrowed; all effects are emitted into module. */

    struct {
        uint32_t start;
        uint64_t end;
    } unmapped[IR_X86_MAX_UNMAPPED_RANGES];

    unsigned unmapped_count;
    ProtectedRange protected[IR_X86_MAX_PROTECTED_RANGES];
    unsigned protected_count;
};

/* Decode register identity AND natural width. Do not infer an alias's width
 * solely from cs_x86_op.size (segment/control/SIMD registers are not GPRs). */
static RegSlice register_slice(unsigned reg) {
    static const unsigned r32[IR_X86_GPR_COUNT] = {X86_REG_EAX, X86_REG_ECX, X86_REG_EDX,
                                                   X86_REG_EBX, X86_REG_ESP, X86_REG_EBP,
                                                   X86_REG_ESI, X86_REG_EDI};
    static const unsigned r16[IR_X86_GPR_COUNT] = {X86_REG_AX, X86_REG_CX, X86_REG_DX, X86_REG_BX,
                                                   X86_REG_SP, X86_REG_BP, X86_REG_SI, X86_REG_DI};
    static const unsigned low[4] = {X86_REG_AL, X86_REG_CL, X86_REG_DL, X86_REG_BL};
    static const unsigned high[4] = {X86_REG_AH, X86_REG_CH, X86_REG_DH, X86_REG_BH};
    for (unsigned i = 0; i < IR_X86_GPR_COUNT; ++i) {
        if (reg == r32[i])
            return (RegSlice){(RegId)i, 0, 4, 15};
        if (reg == r16[i])
            return (RegSlice){(RegId)i, 0, 2, 3};
        if (i < 4 && reg == low[i])
            return (RegSlice){(RegId)i, 0, 1, 1};
        if (i < 4 && reg == high[i])
            return (RegSlice){(RegId)i, 1, 1, 2};
    }
    return (RegSlice){.reg_id = REG_INVALID};
}

IrX86Frontend *ir_x86_frontend_create(IrModule *m, const IrX86Options *options) {
    if (!m || ir_module_status(m) != IR_OK)
        return NULL;
    IrX86Frontend *f = calloc(1, sizeof(*f));
    if (!f)
        return NULL;
    f->module = m;
    if (options)
        f->options = *options;
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &f->decoder) != CS_ERR_OK ||
        cs_option(f->decoder, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK ||
        cs_option(f->decoder, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL) != CS_ERR_OK) {
        ir_x86_frontend_destroy(f);
        return NULL;
    }
    for (unsigned i = 0; i < IR_X86_GPR_COUNT; ++i)
        f->state.gpr[i] = ir_state_add(m, ir_type_bv(32), IR_X86_GPR_KEY_BASE + i, false);
    for (unsigned i = 0; i < IR_X86_FLAG_COUNT; ++i)
        f->state.flags[i] = ir_state_add(m, ir_type_bv(1), IR_X86_FLAG_KEY_BASE + i, false);
    f->state.memory = ir_state_add(m, ir_type_mem(32), IR_X86_MEMORY_KEY, false);
    if (f->options.tls32_ram)
        for (unsigned i = 0; i < IR_X86_TLS_COUNT; ++i)
            f->state.tls_base[i] = ir_state_add(m, ir_type_bv(32), IR_X86_TLS_KEY_BASE + i, false);
    if (ir_module_status(m) != IR_OK) {
        ir_x86_frontend_destroy(f);
        return NULL;
    }
    return f;
}

void ir_x86_frontend_destroy(IrX86Frontend *f) {
    if (!f)
        return;
    if (f->decoder)
        cs_close(&f->decoder);
    free(f);
}

const IrX86State *ir_x86_frontend_state(const IrX86Frontend *f) {
    return f ? &f->state : NULL;
}

void ir_x86_attach_environment(IrX86Frontend *f, IrEnvironment *environment) {
    if(f) f->environment=environment;
}

IrStatus ir_x86_exclude_memory(IrX86Frontend *f, uint32_t start, uint64_t end) {
    if (!f || end <= start || end > (UINT64_C(1) << 32))
        return IR_INVALID;
    for (unsigned i = 0; i < f->unmapped_count; ++i)
        if (start >= f->unmapped[i].start && end <= f->unmapped[i].end)
            return IR_OK;
    if (f->unmapped_count == IR_X86_MAX_UNMAPPED_RANGES)
        return IR_RESOURCE_LIMIT;
    f->unmapped[f->unmapped_count].start = start;
    f->unmapped[f->unmapped_count++].end = end;
    return IR_OK;
}

static bool range_intersects(uint32_t start, unsigned bytes, uint32_t low, uint64_t high) {
    if (!bytes)
        return false;
    uint64_t end = (uint64_t)start + bytes;
    return (start < high && end > low) ||
           (end > (UINT64_C(1) << 32) && end - (UINT64_C(1) << 32) > low);
}

bool ir_x86_range_excluded(const IrX86Frontend *f, uint32_t start, unsigned bytes) {
    if (!f)
        return true;
    for (unsigned i = 0; i < f->unmapped_count; ++i) {
        if (range_intersects(start, bytes, f->unmapped[i].start, f->unmapped[i].end))
            return true;
    }
    return false;
}

IrStatus ir_x86_map_memory(IrX86Frontend *f, uint32_t start, uint64_t end, unsigned access) {
    if (!f || end <= start || end > (UINT64_C(1) << 32))
        return IR_INVALID;
    IrX86Frontend next = *f;
    next.unmapped_count = 0;
    for (unsigned i = 0; i < f->unmapped_count; ++i) {
        uint64_t lo = f->unmapped[i].start, hi = f->unmapped[i].end;
        uint64_t pieces[2][2];
        unsigned count = 0;
        if (hi <= start || lo >= end) {
            pieces[count][0] = lo; pieces[count++][1] = hi;
        } else {
            if (lo < start) { pieces[count][0] = lo; pieces[count++][1] = start; }
            if (hi > end) { pieces[count][0] = end; pieces[count++][1] = hi; }
        }
        for (unsigned j = 0; j < count; ++j) {
            if (next.unmapped_count == IR_X86_MAX_UNMAPPED_RANGES)
                return IR_RESOURCE_LIMIT;
            next.unmapped[next.unmapped_count].start = (uint32_t)pieces[j][0];
            next.unmapped[next.unmapped_count++].end = pieces[j][1];
        }
    }
    IrStatus status = ir_x86_protect_memory(&next, start, end, access);
    if (status == IR_OK)
        *f = next;
    return status;
}

IrStatus ir_x86_protect_memory(IrX86Frontend *f, uint32_t start, uint64_t end, unsigned access) {
    if (!f || !f->options.flat32_ram || end <= start || end > (UINT64_C(1) << 32) ||
        (access & ~IR_X86_ACCESS_ALL))
        return IR_INVALID;
    for (unsigned i = 0; i < f->unmapped_count; ++i)
        if (start < f->unmapped[i].end && end > f->unmapped[i].start)
            return IR_INVALID;
    /* Overwriting an interval adds at most two boundaries. Keep the old map
     * intact until splitting and coalescing fit the fixed budget. */
    ProtectedRange next[IR_X86_MAX_PROTECTED_RANGES + 2U];
    unsigned count = 0;
    for (unsigned i = 0; i < f->protected_count; ++i) {
        ProtectedRange range = f->protected[i];
        if (range.end <= start || range.start >= end)
            next[count++] = range;
        else {
            if (range.start < start)
                next[count++] = (ProtectedRange){range.start, start, range.access};
            if (range.end > end)
                next[count++] = (ProtectedRange){(uint32_t)end, range.end, range.access};
        }
    }
    next[count++] = (ProtectedRange){start, end, access};
    for (unsigned i = 1; i < count; ++i) {
        ProtectedRange range = next[i];
        unsigned j = i;
        while (j && next[j - 1].start > range.start) {
            next[j] = next[j - 1];
            --j;
        }
        next[j] = range;
    }
    unsigned merged = 0;
    for (unsigned i = 0; i < count; ++i) {
        if (merged && next[merged - 1].end == next[i].start &&
            next[merged - 1].access == next[i].access)
            next[merged - 1].end = next[i].end;
        else
            next[merged++] = next[i];
    }
    if (merged > IR_X86_MAX_PROTECTED_RANGES)
        return IR_RESOURCE_LIMIT;
    memcpy(f->protected, next, merged * sizeof(*next));
    f->protected_count = merged;
    return IR_OK;
}

bool ir_x86_range_permitted(const IrX86Frontend *f, uint32_t start, unsigned bytes,
                            unsigned access) {
    if (!f || !access || (access & ~IR_X86_ACCESS_ALL) || ir_x86_range_excluded(f, start, bytes))
        return false;
    for (unsigned i = 0; i < f->protected_count; ++i) {
        const ProtectedRange *range = &f->protected[i];
        if ((range->access & access) != access &&
            range_intersects(start, bytes, range->start, range->end))
            return false;
    }
    return true;
}

static bool width_ok(unsigned bytes) {
    return bytes == 1 || bytes == 2 || bytes == 4;
}

static bool register_ok(const cs_x86_op *op) {
    RegSlice s = register_slice(op->reg);
    return op->type == X86_OP_REG && s.reg_id != REG_INVALID && s.width == op->size;
}

static bool address_ok(const cs_x86 *x, const cs_x86_op *op) {
    if (op->type != X86_OP_MEM || (x->addr_size != 2 && x->addr_size != 4))
        return false;
    const x86_op_mem *mem = &op->mem;
    if (mem->base != X86_REG_INVALID && register_slice(mem->base).width != x->addr_size)
        return false;
    if (mem->index != X86_REG_INVALID && register_slice(mem->index).width != x->addr_size)
        return false;
    return mem->scale == 1 ||
           (x->addr_size == 4 && (mem->scale == 2 || mem->scale == 4 || mem->scale == 8));
}

static bool ram_segment(const IrX86Frontend *f, unsigned segment) {
    return segment == X86_REG_INVALID || segment == X86_REG_DS || segment == X86_REG_ES ||
           segment == X86_REG_SS || segment == X86_REG_CS ||
           (f->options.tls32_ram && (segment == X86_REG_FS || segment == X86_REG_GS));
}

static bool supported_prefixes(const InsnDesc *d) {
    for (unsigned i = 0; i < d->size; ++i) {
        switch (d->bytes[i]) {
        case 0xf0:
        case 0xf2:
        case 0xf3:
            return false;
        case 0x66:
        case 0x67:
        case 0x26:
        case 0x2e:
        case 0x36:
        case 0x3e:
        case 0x64:
        case 0x65:
            break;
        default:
            return true;
        }
    }
    return false;
}

/* Intel condition encoding order, expressed only in the ISA frontend. */
static int condition_code(unsigned id) {
    switch (id) {
    case X86_INS_JO:
        return 0;
    case X86_INS_JNO:
        return 1;
    case X86_INS_JB:
        return 2;
    case X86_INS_JAE:
        return 3;
    case X86_INS_JE:
        return 4;
    case X86_INS_JNE:
        return 5;
    case X86_INS_JBE:
        return 6;
    case X86_INS_JA:
        return 7;
    case X86_INS_JS:
        return 8;
    case X86_INS_JNS:
        return 9;
    case X86_INS_JP:
        return 10;
    case X86_INS_JNP:
        return 11;
    case X86_INS_JL:
        return 12;
    case X86_INS_JGE:
        return 13;
    case X86_INS_JLE:
        return 14;
    case X86_INS_JG:
        return 15;
    default:
        return -1;
    }
}

static int set_condition_code(unsigned id) {
    switch (id) {
    case X86_INS_SETO:
        return 0;
    case X86_INS_SETNO:
        return 1;
    case X86_INS_SETB:
        return 2;
    case X86_INS_SETAE:
        return 3;
    case X86_INS_SETE:
        return 4;
    case X86_INS_SETNE:
        return 5;
    case X86_INS_SETBE:
        return 6;
    case X86_INS_SETA:
        return 7;
    case X86_INS_SETS:
        return 8;
    case X86_INS_SETNS:
        return 9;
    case X86_INS_SETP:
        return 10;
    case X86_INS_SETNP:
        return 11;
    case X86_INS_SETL:
        return 12;
    case X86_INS_SETGE:
        return 13;
    case X86_INS_SETLE:
        return 14;
    case X86_INS_SETG:
        return 15;
    default:
        return -1;
    }
}

static int move_condition_code(unsigned id) {
    switch (id) {
    case X86_INS_CMOVO:
        return 0;
    case X86_INS_CMOVNO:
        return 1;
    case X86_INS_CMOVB:
        return 2;
    case X86_INS_CMOVAE:
        return 3;
    case X86_INS_CMOVE:
        return 4;
    case X86_INS_CMOVNE:
        return 5;
    case X86_INS_CMOVBE:
        return 6;
    case X86_INS_CMOVA:
        return 7;
    case X86_INS_CMOVS:
        return 8;
    case X86_INS_CMOVNS:
        return 9;
    case X86_INS_CMOVP:
        return 10;
    case X86_INS_CMOVNP:
        return 11;
    case X86_INS_CMOVL:
        return 12;
    case X86_INS_CMOVGE:
        return 13;
    case X86_INS_CMOVLE:
        return 14;
    case X86_INS_CMOVG:
        return 15;
    default:
        return -1;
    }
}

static bool arithmetic(unsigned id) {
    return id == X86_INS_ADD || id == X86_INS_SUB || id == X86_INS_ADC || id == X86_INS_SBB ||
           id == X86_INS_CMP || id == X86_INS_AND ||
           id == X86_INS_OR || id == X86_INS_XOR || id == X86_INS_TEST;
}

static bool unary_arithmetic(unsigned id) {
    return id == X86_INS_NEG || id == X86_INS_INC || id == X86_INS_DEC;
}

static bool shift(unsigned id) {
    return id == X86_INS_SHL || id == X86_INS_SAL || id == X86_INS_SHR || id == X86_INS_SAR;
}

static bool scan(unsigned id) {
    return id == X86_INS_SCASB || id == X86_INS_SCASW || id == X86_INS_SCASD;
}

static bool string_load(unsigned id) {
    return id == X86_INS_LODSB || id == X86_INS_LODSW || id == X86_INS_LODSD;
}

static bool string_move(unsigned id) {
    return id == X86_INS_MOVSB || id == X86_INS_MOVSW || id == X86_INS_MOVSD;
}

static bool string_store(unsigned id) {
    return id == X86_INS_STOSB || id == X86_INS_STOSW || id == X86_INS_STOSD;
}

/* Accept one F3 and at most one prefix from each other group. F2, LOCK and
 * redundant/ambiguous prefixes are not silently stripped. */
static bool repeat_prefixes(const InsnDesc *d) {
    unsigned seen = 0;
    for (unsigned i = 0; i < d->size; ++i) {
        unsigned group;
        switch (d->bytes[i]) {
        case 0xf3: group = 1; break;
        case 0x66: group = 2; break;
        case 0x67: group = 4; break;
        case 0x26: case 0x2e: case 0x36: case 0x3e: case 0x64: case 0x65:
            group = 8; break;
        case 0xf0: case 0xf2: return false;
        default: return (seen & 1) != 0;
        }
        if (seen & group) return false;
        seen |= group;
    }
    return false;
}

static IrX86LiftStatus operand_status(const IrX86Frontend *f, const cs_x86 *x, const cs_x86_op *op,
                                      bool immediate) {
    if (!width_ok(op->size))
        return IR_X86_LIFT_UNSUPPORTED;
    if (op->type == X86_OP_REG)
        return register_ok(op) ? IR_X86_LIFT_OK : IR_X86_LIFT_UNSUPPORTED;
    if (op->type == X86_OP_IMM)
        return immediate ? IR_X86_LIFT_OK : IR_X86_LIFT_UNSUPPORTED;
    if (!address_ok(x, op))
        return IR_X86_LIFT_UNSUPPORTED;
    return f->options.flat32_ram && ram_segment(f, op->mem.segment) ? IR_X86_LIFT_OK
                                                                    : IR_X86_LIFT_MEMORY_MODEL;
}

static IrX86LiftStatus preflight(const IrX86Frontend *f, const cs_insn *insn) {
    const cs_x86 *x = &insn->detail->x86;
    if (insn->id == X86_INS_ENDBR32)
        return f->options.flat32_ram ? IR_X86_LIFT_OK : IR_X86_LIFT_MEMORY_MODEL;
    if (insn->id == X86_INS_NOP || insn->id == X86_INS_CLD || insn->id == X86_INS_STD)
        return IR_X86_LIFT_OK;
    if (unary_arithmetic(insn->id) || insn->id == X86_INS_NOT) {
        if (x->op_count != 1)
            return IR_X86_LIFT_UNSUPPORTED;
        return operand_status(f, x, &x->operands[0], false);
    }
    if (insn->id == X86_INS_BSWAP)
        return x->op_count == 1 && register_ok(&x->operands[0]) && x->operands[0].size == 4
            && x->prefix[2] != 0x66 ? IR_X86_LIFT_OK : IR_X86_LIFT_UNSUPPORTED;
    if (insn->id == X86_INS_LOOP)
        return x->prefix[2] != 0x66 && (x->addr_size == 2 || x->addr_size == 4) &&
            x->op_count == 1 && x->operands[0].type == X86_OP_IMM
            ? IR_X86_LIFT_OK : IR_X86_LIFT_UNSUPPORTED;
    if (insn->id == X86_INS_XCHG) {
        if (x->op_count != 2 || x->operands[0].size != x->operands[1].size ||
            (x->operands[0].type == X86_OP_MEM && x->operands[1].type == X86_OP_MEM))
            return IR_X86_LIFT_UNSUPPORTED;
        for (unsigned i = 0; i < 2; ++i) {
            IrX86LiftStatus status = operand_status(f, x, &x->operands[i], false);
            if (status != IR_X86_LIFT_OK) return status;
        }
        return IR_X86_LIFT_OK;
    }
    if (string_move(insn->id) || string_store(insn->id)) {
        bool move = string_move(insn->id);
        unsigned bytes = insn->id == X86_INS_MOVSB || insn->id == X86_INS_STOSB ? 1 :
            insn->id == X86_INS_MOVSW || insn->id == X86_INS_STOSW ? 2 : 4;
        const cs_x86_op *dst = &x->operands[0], *src = &x->operands[1];
        if (x->op_count != 2 || dst->size != bytes || src->size != bytes ||
            !address_ok(x, dst) || dst->mem.segment != X86_REG_ES ||
            dst->mem.base != (x->addr_size == 2 ? X86_REG_DI : X86_REG_EDI) ||
            dst->mem.index != X86_REG_INVALID || dst->mem.disp != 0)
            return IR_X86_LIFT_UNSUPPORTED;
        if (move) {
            if (!address_ok(x, src) || src->mem.base != (x->addr_size == 2 ? X86_REG_SI : X86_REG_ESI)
                || src->mem.index != X86_REG_INVALID || src->mem.disp != 0)
                return IR_X86_LIFT_UNSUPPORTED;
        } else if (!register_ok(src) || src->reg !=
                   (bytes == 1 ? X86_REG_AL : bytes == 2 ? X86_REG_AX : X86_REG_EAX))
            return IR_X86_LIFT_UNSUPPORTED;
        IrX86LiftStatus status = operand_status(f, x, dst, false);
        return status == IR_X86_LIFT_OK ? operand_status(f, x, src, false) : status;
    }
    if (set_condition_code(insn->id) >= 0) {
        if (x->op_count != 1 || x->operands[0].size != 1)
            return IR_X86_LIFT_UNSUPPORTED;
        return operand_status(f, x, &x->operands[0], false);
    }
    if (move_condition_code(insn->id) >= 0) {
        if (x->op_count != 2)
            return IR_X86_LIFT_UNSUPPORTED;
        const cs_x86_op *dst = &x->operands[0], *src = &x->operands[1];
        if (!register_ok(dst) || (dst->size != 2 && dst->size != 4) || dst->size != src->size)
            return IR_X86_LIFT_UNSUPPORTED;
        return operand_status(f, x, src, false);
    }
    if (condition_code(insn->id) >= 0) {
        return x->prefix[2] != 0x66 && x->op_count == 1 && x->operands[0].type == X86_OP_IMM
                   ? IR_X86_LIFT_OK
                   : IR_X86_LIFT_UNSUPPORTED;
    }
    if (insn->id == X86_INS_JMP || insn->id == X86_INS_CALL) {
        if (x->prefix[2] == 0x66 || x->op_count != 1 || x->operands[0].size != 4)
            return IR_X86_LIFT_UNSUPPORTED;
        if (insn->id == X86_INS_CALL && !f->options.flat32_ram)
            return IR_X86_LIFT_MEMORY_MODEL;
        return operand_status(f, x, &x->operands[0], true);
    }
    if (insn->id == X86_INS_RET) {
        if (x->prefix[2] == 0x66 || x->op_count > 1 ||
            (x->op_count && x->operands[0].type != X86_OP_IMM))
            return IR_X86_LIFT_UNSUPPORTED;
        return f->options.flat32_ram ? IR_X86_LIFT_OK : IR_X86_LIFT_MEMORY_MODEL;
    }
    if (insn->id == X86_INS_PUSH || insn->id == X86_INS_POP) {
        if (x->op_count != 1 || (x->operands[0].size != 2 && x->operands[0].size != 4))
            return IR_X86_LIFT_UNSUPPORTED;
        if (!f->options.flat32_ram)
            return IR_X86_LIFT_MEMORY_MODEL;
        return operand_status(f, x, &x->operands[0], insn->id == X86_INS_PUSH);
    }
    if (insn->id == X86_INS_LEAVE || insn->id == X86_INS_POPAL) {
        if (x->prefix[2] == 0x66)
            return IR_X86_LIFT_UNSUPPORTED;
        return f->options.flat32_ram ? IR_X86_LIFT_OK : IR_X86_LIFT_MEMORY_MODEL;
    }
    if (scan(insn->id)) {
        if (x->op_count != 2 || !address_ok(x, &x->operands[1]) || !register_ok(&x->operands[0]) ||
            x->operands[0].size != x->operands[1].size)
            return IR_X86_LIFT_UNSUPPORTED;
        return f->options.flat32_ram ? IR_X86_LIFT_OK : IR_X86_LIFT_MEMORY_MODEL;
    }
    if (string_load(insn->id)) {
        unsigned accumulator = insn->id == X86_INS_LODSB ? X86_REG_AL
                               : insn->id == X86_INS_LODSW ? X86_REG_AX : X86_REG_EAX;
        if (x->op_count != 2 || !register_ok(&x->operands[0]) ||
            x->operands[0].reg != accumulator ||
            !address_ok(x, &x->operands[1]) ||
            x->operands[0].size != x->operands[1].size ||
            x->operands[1].mem.base != (x->addr_size == 2 ? X86_REG_SI : X86_REG_ESI) ||
            x->operands[1].mem.index != X86_REG_INVALID || x->operands[1].mem.disp != 0)
            return IR_X86_LIFT_UNSUPPORTED;
        return operand_status(f, x, &x->operands[1], false);
    }
    if (shift(insn->id)) {
        if (x->op_count != 2 ||
            (x->operands[1].type != X86_OP_IMM &&
             !(x->operands[1].type == X86_OP_REG && x->operands[1].reg == X86_REG_CL)))
            return IR_X86_LIFT_UNSUPPORTED;
        return operand_status(f, x, &x->operands[0], false);
    }
    bool extend = insn->id == X86_INS_MOVZX || insn->id == X86_INS_MOVSX;
    bool lea = insn->id == X86_INS_LEA;
    if (insn->id != X86_INS_MOV && !extend && !lea && !arithmetic(insn->id))
        return IR_X86_LIFT_UNSUPPORTED;
    if (x->op_count != 2)
        return IR_X86_LIFT_UNSUPPORTED;
    const cs_x86_op *dst = &x->operands[0], *src = &x->operands[1];
    if (!width_ok(dst->size) || !width_ok(src->size))
        return IR_X86_LIFT_UNSUPPORTED;
    if (lea) {
        return register_ok(dst) && dst->size >= 2 && address_ok(x, src) ? IR_X86_LIFT_OK
                                                                        : IR_X86_LIFT_UNSUPPORTED;
    }
    if (extend) {
        if (!register_ok(dst) || dst->size <= src->size ||
            (src->type != X86_OP_REG && src->type != X86_OP_MEM))
            return IR_X86_LIFT_UNSUPPORTED;
    } else if (dst->size != src->size || (dst->type != X86_OP_REG && dst->type != X86_OP_MEM) ||
               (src->type != X86_OP_REG && src->type != X86_OP_MEM && src->type != X86_OP_IMM)) {
        return IR_X86_LIFT_UNSUPPORTED;
    }
    if (dst->type == X86_OP_MEM && src->type == X86_OP_MEM)
        return IR_X86_LIFT_UNSUPPORTED;
    for (unsigned i = 0; i < 2; ++i) {
        const cs_x86_op *op = &x->operands[i];
        if (op->type == X86_OP_REG && !register_ok(op))
            return IR_X86_LIFT_UNSUPPORTED;
        if (op->type == X86_OP_MEM) {
            if (!address_ok(x, op))
                return IR_X86_LIFT_UNSUPPORTED;
            if (!f->options.flat32_ram || !ram_segment(f, op->mem.segment))
                return IR_X86_LIFT_MEMORY_MODEL;
        }
    }
    return IR_X86_LIFT_OK;
}

typedef struct {
    IrX86Frontend *f;
    IrBlockId block;
    IrOrigin origin;
} Lift;

static IrValueId emit(Lift *l, IrInstSpec s) {
    s.origin = l->origin;
    return ir_emit_value(l->f->module, l->block, s);
}

static IrValueId constant(Lift *l, unsigned width, uint64_t bits) {
    return emit(l, (IrInstSpec){.op = IR_OP_CONST, .type = ir_type_bv(width), .immediate = bits});
}

static IrValueId unary(Lift *l, IrOpcode op, unsigned width, IrValueId a, uint64_t offset) {
    return emit(
        l, (IrInstSpec){.op = op, .type = ir_type_bv(width), .args = {a}, .immediate = offset});
}

static IrValueId binary(Lift *l, IrOpcode op, unsigned width, IrValueId a, IrValueId b) {
    return emit(l, (IrInstSpec){.op = op, .type = ir_type_bv(width), .args = {a, b}});
}

static IrValueId read_state(Lift *l, IrStateId id, IrType type) {
    return emit(l, (IrInstSpec){.op = IR_OP_READ_STATE, .type = type, .state = id});
}

static void write_state(Lift *l, IrStateId id, IrValueId v) {
    (void)ir_emit_effect(l->f->module, l->block,
                         (IrInstSpec){.op = IR_OP_WRITE_STATE,
                                      .type = ir_type_void(),
                                      .args = {v},
                                      .state = id,
                                      .origin = l->origin});
}

static IrValueId read_register_profiled_body(Lift *l, unsigned reg) {
    RegSlice s = register_slice(reg);
    IrValueId full = read_state(l, l->f->state.gpr[s.reg_id], ir_type_bv(32));
    return s.width == 4 ? full : unary(l, IR_OP_EXTRACT, s.width * 8U, full, s.byte_offset * 8U);
}
static IrValueId read_register(Lift *l, unsigned reg) {
    IrBuildPhase previous = ir_module_build_phase(l->f->module, IR_BUILD_REGISTERS);
    IrValueId result = read_register_profiled_body(l, reg);
    ir_module_build_phase(l->f->module, previous);
    return result;
}


static void write_register_profiled_body(Lift *l, unsigned reg, IrValueId value) {
    RegSlice s = register_slice(reg);
    IrStateId state = l->f->state.gpr[s.reg_id];
    if (s.width < 4) {
        unsigned bits = s.width * 8U, offset = s.byte_offset * 8U;
        /* Assemble preserved slices explicitly. Unlike (old & mask) | new,
         * this also preserves useful known bits when old is partly UNKNOWN. */
        IrValueId old = read_state(l, state, ir_type_bv(32));
        if (offset) {
            IrValueId low = unary(l, IR_OP_EXTRACT, offset, old, 0);
            value = binary(l, IR_OP_CONCAT, bits + offset, value, low);
        }
        unsigned upper = 32U - bits - offset;
        IrValueId high = unary(l, IR_OP_EXTRACT, upper, old, bits + offset);
        value = binary(l, IR_OP_CONCAT, 32, high, value);
    }
    write_state(l, state, value);
}
static void write_register(Lift *l, unsigned reg, IrValueId value) {
    IrBuildPhase previous = ir_module_build_phase(l->f->module, IR_BUILD_REGISTERS);
    write_register_profiled_body(l, reg, value);
    ir_module_build_phase(l->f->module, previous);
}


static IrValueId effective_address(Lift *l, const cs_x86 *x, const cs_x86_op *op) {
    unsigned bits = x->addr_size * 8U;
    IrValueId value = constant(l, bits, (uint64_t)op->mem.disp);
    if (op->mem.base != X86_REG_INVALID) {
        IrValueId base = read_register(l, op->mem.base);
        value = binary(l, IR_OP_ADD, bits, value, base);
    }
    if (op->mem.index != X86_REG_INVALID) {
        IrValueId index = read_register(l, op->mem.index);
        if (op->mem.scale != 1) {
            IrValueId scale = constant(l, bits, (unsigned)op->mem.scale);
            index = binary(l, IR_OP_MUL, bits, index, scale);
        }
        value = binary(l, IR_OP_ADD, bits, value, index);
    }
    return value;
}

static IrValueId linear_address(Lift *l, const cs_x86 *x, const cs_x86_op *op, IrX86LiftResult *r) {
    IrValueId value = effective_address(l, x, op);
    if (x->addr_size == 2)
        value = unary(l, IR_OP_ZEXT, 32, value, 0);
    if (op->mem.segment == X86_REG_FS || op->mem.segment == X86_REG_GS) {
        unsigned segment = op->mem.segment == X86_REG_GS;
        r->segment_reads |= (uint8_t)(1U << segment);
        IrValueId base = read_state(l, l->f->state.tls_base[segment], ir_type_bv(32));
        value = binary(l, IR_OP_ADD, 32, base, value);
    }
    return value;
}

static void guard_range(Lift *l, IrValueId address, unsigned bytes, uint32_t low, uint64_t high) {
    IrValueId outside = constant(l, 1, 1);
    IrValueId start = constant(l, 64, low);
    IrValueId end = constant(l, 64, high);
    for (unsigned byte = 0; byte < bytes; ++byte) {
        /* Each byte wraps in the modeled BV32 address space. */
        IrValueId a = byte ? binary(l, IR_OP_ADD, 32, address, constant(l, 32, byte)) : address;
        a = unary(l, IR_OP_ZEXT, 64, a, 0);
        IrValueId before = binary(l, IR_OP_ULT, 1, a, start);
        IrValueId after = unary(l, IR_OP_NOT, 1, binary(l, IR_OP_ULT, 1, a, end), 0);
        outside = binary(l, IR_OP_AND, 1, outside, binary(l, IR_OP_OR, 1, before, after));
    }
    (void)ir_emit_effect(l->f->module, l->block,
                         (IrInstSpec){.op = IR_OP_GUARD,
                                      .type = ir_type_void(),
                                      .args = {outside},
                                      .immediate = IR_REASON_MEMORY,
                                      .origin = l->origin});
}

static void guard_memory(Lift *l, IrValueId address, unsigned bytes, unsigned access) {
    for (unsigned i = 0; i < l->f->unmapped_count; ++i)
        guard_range(l, address, bytes, l->f->unmapped[i].start, l->f->unmapped[i].end);
    for (unsigned i = 0; i < l->f->protected_count; ++i) {
        const ProtectedRange *range = &l->f->protected[i];
        if ((range->access & access) != access)
            guard_range(l, address, bytes, range->start, range->end);
    }
}

static IrValueId load_memory_profiled_body(Lift *l, IrValueId address, unsigned bytes, IrX86LiftResult *r) {
    guard_memory(l, address, bytes, IR_X86_ACCESS_READ);
    IrValueId value;
    if(l->f->environment)
        value=ir_environment_load(l->f->environment,l->block,l->origin,address,bytes);
    else {
        IrValueId memory = read_state(l, l->f->state.memory, ir_type_mem(32));
        value = emit(l, (IrInstSpec){.op = IR_OP_LOAD,
                                           .type = ir_type_bv(bytes * 8U),
                                           .args = {memory, address},
                                           .endian = IR_ENDIAN_LE});
    }
    r->reads_memory = true;
    r->address = address;
    r->memory_bytes = bytes;
    r->data = r->read_data = value;
    r->memory[r->memory_count++] = (IrX86MemoryEffect){false, bytes, address, value};
    return value;
}
static IrValueId load_memory(Lift *l, IrValueId address, unsigned bytes, IrX86LiftResult *r) {
    IrBuildPhase previous = ir_module_build_phase(l->f->module, IR_BUILD_MEMORY);
    IrValueId result = load_memory_profiled_body(l, address, bytes, r);
    ir_module_build_phase(l->f->module, previous);
    return result;
}


IrValueId ir_x86_memory_read(IrX86Frontend *f, IrBlockId b, IrOrigin o,
                             IrValueId address, unsigned bytes) {
    if(!f || !f->options.flat32_ram || !bytes || bytes>8) return 0;
    Lift l={f,b,o};IrX86LiftResult result={0};
    return load_memory(&l,address,bytes,&result);
}

static void store_memory_profiled_body(Lift *l, IrValueId address, unsigned bytes, IrValueId value,
                         IrX86LiftResult *r) {
    guard_memory(l, address, bytes, IR_X86_ACCESS_WRITE);
    if(l->f->environment)
        ir_environment_store(l->f->environment,l->block,l->origin,address,bytes,value);
    else {
        IrValueId memory = read_state(l, l->f->state.memory, ir_type_mem(32));
        IrValueId updated = emit(l, (IrInstSpec){.op = IR_OP_STORE,
                                             .type = ir_type_mem(32),
                                             .args = {memory, address, value},
                                             .endian = IR_ENDIAN_LE});
        write_state(l, l->f->state.memory, updated);
    }
    r->writes_memory = true;
    if (!r->reads_memory)
        r->address = address;
    r->memory_bytes = bytes;
    r->data = r->write_data = value;
    r->memory[r->memory_count++] = (IrX86MemoryEffect){true, bytes, address, value};
}
static void store_memory(Lift *l, IrValueId address, unsigned bytes, IrValueId value, IrX86LiftResult *r) {
    IrBuildPhase previous = ir_module_build_phase(l->f->module, IR_BUILD_MEMORY);
    store_memory_profiled_body(l, address, bytes, value, r);
    ir_module_build_phase(l->f->module, previous);
}


bool ir_x86_memory_write(IrX86Frontend *f,IrBlockId b,IrOrigin o,IrValueId address,
                           unsigned bytes,IrValueId value) {
    if(!f || !f->options.flat32_ram || !bytes || bytes>8) return false;
    Lift l={.f=f,.block=b,.origin=o};
    IrX86LiftResult result={0};
    store_memory(&l,address,bytes,value,&result);
    return ir_module_status(f->module)==IR_OK;
}

static IrValueId read_operand(Lift *l, const cs_x86 *x, const cs_x86_op *op, IrX86LiftResult *r) {
    if (op->type == X86_OP_REG)
        return read_register(l, op->reg);
    if (op->type == X86_OP_IMM)
        return constant(l, op->size * 8U, (uint64_t)op->imm);
    return load_memory(l, linear_address(l, x, op, r), op->size, r);
}

static void write_operand(Lift *l, const cs_x86 *x, const cs_x86_op *op, IrValueId value,
                          IrX86LiftResult *r) {
    if (op->type == X86_OP_REG) {
        r->gpr_writes |= UINT32_C(1) << register_slice(op->reg).reg_id;
        write_register(l, op->reg, value);
    } else {
        store_memory(l, linear_address(l, x, op, r), op->size, value, r);
    }
}

static IrValueId choose(Lift *l, unsigned width, IrValueId condition, IrValueId yes, IrValueId no) {
    return emit(
        l, (IrInstSpec){.op = IR_OP_ITE, .type = ir_type_bv(width), .args = {condition, yes, no}});
}

static void stack_pointer(Lift *l, IrValueId value, IrX86LiftResult *r) {
    write_register(l, X86_REG_ESP, value);
    r->gpr_writes |= UINT32_C(1) << REG_RSP;
}

static void push(Lift *l, IrValueId value, unsigned bytes, IrX86LiftResult *r) {
    IrValueId sp = read_register(l, X86_REG_ESP);
    IrValueId next = binary(l, IR_OP_SUB, 32, sp, constant(l, 32, bytes));
    store_memory(l, next, bytes, value, r);
    stack_pointer(l, next, r);
}

static IrValueId bit(Lift *l, IrValueId a, unsigned index) {
    return unary(l, IR_OP_EXTRACT, 1, a, index);
}

static void arithmetic_flags_profiled_body(Lift *l, unsigned id, unsigned width, IrValueId a, IrValueId b,
                             IrValueId result, IrValueId carry, IrX86LiftResult *r) {
    IrValueId flags[6];
    bool add = id == X86_INS_ADD || id == X86_INS_ADC || id == X86_INS_INC;
    bool sub = id == X86_INS_SUB || id == X86_INS_SBB || id == X86_INS_CMP ||
               id == X86_INS_NEG || id == X86_INS_DEC;
    bool preserve_cf = id == X86_INS_INC || id == X86_INS_DEC;
    flags[X86_SPECIAL_STATE_ZF] = binary(l, IR_OP_EQ, 1, result, constant(l, width, 0));
    flags[X86_SPECIAL_STATE_SF] = bit(l, result, width - 1U);
    IrValueId parity = bit(l, result, 0);
    for (unsigned i = 1; i < 8; ++i)
        parity = binary(l, IR_OP_XOR, 1, parity, bit(l, result, i));
    flags[X86_SPECIAL_STATE_PF] = unary(l, IR_OP_NOT, 1, parity, 0);
    if (add || sub) {
        IrValueId different = binary(l, IR_OP_XOR, width, a, b);
        IrValueId changed = binary(l, IR_OP_XOR, width, a, result);
        if (!preserve_cf)
            flags[X86_SPECIAL_STATE_CF] = binary(l, IR_OP_ULT, 1, add ? result : a, add ? a : b);
        if (carry) {
            IrValueId equal = binary(l, IR_OP_EQ, 1, add ? result : a, add ? a : b);
            flags[X86_SPECIAL_STATE_CF] = binary(l, IR_OP_OR, 1, flags[X86_SPECIAL_STATE_CF],
                                                binary(l, IR_OP_AND, 1, carry, equal));
        }
        flags[X86_SPECIAL_STATE_AF] = bit(l, binary(l, IR_OP_XOR, width, different, result), 4);
        IrValueId sign_mask = add ? unary(l, IR_OP_NOT, width, different, 0) : different;
        flags[X86_SPECIAL_STATE_OF] =
            bit(l, binary(l, IR_OP_AND, width, sign_mask, changed), width - 1U);
    } else {
        flags[X86_SPECIAL_STATE_CF] = constant(l, 1, 0);
        flags[X86_SPECIAL_STATE_OF] = constant(l, 1, 0);
        flags[X86_SPECIAL_STATE_AF] = emit(l, (IrInstSpec){.op = IR_OP_UNKNOWN,
                                                           .type = ir_type_bv(1),
                                                           .immediate = IR_REASON_UNDEFINED});
        r->flags_undefined = UINT32_C(1) << X86_SPECIAL_STATE_AF;
    }
    r->flags_written = preserve_cf ? 0x3e : 0x3f;
    for (unsigned i = 0; i < 6; ++i)
        if (r->flags_written & (1U << i))
            write_state(l, l->f->state.flags[i], flags[i]);
    /* DF is preserved. No flags are copied from replay observations. */
}
static void arithmetic_flags(Lift *l, unsigned id, unsigned width, IrValueId a, IrValueId b, IrValueId result, IrValueId carry, IrX86LiftResult *r) {
    IrBuildPhase previous = ir_module_build_phase(l->f->module, IR_BUILD_ARITHMETIC_FLAGS);
    arithmetic_flags_profiled_body(l, id, width, a, b, result, carry, r);
    ir_module_build_phase(l->f->module, previous);
}


static IrValueId branch_condition(Lift *l, unsigned cc) {
    IrValueId value;
    unsigned flag;
    switch (cc >> 1U) {
    case 0:
        flag = X86_SPECIAL_STATE_OF;
        break;
    case 1:
        flag = X86_SPECIAL_STATE_CF;
        break;
    case 2:
        flag = X86_SPECIAL_STATE_ZF;
        break;
    case 4:
        flag = X86_SPECIAL_STATE_SF;
        break;
    case 5:
        flag = X86_SPECIAL_STATE_PF;
        break;
    default:
        flag = IR_X86_FLAG_COUNT;
        break;
    }
    if (flag < IR_X86_FLAG_COUNT)
        value = read_state(l, l->f->state.flags[flag], ir_type_bv(1));
    else if ((cc >> 1U) == 3) {
        IrValueId cf = read_state(l, l->f->state.flags[X86_SPECIAL_STATE_CF], ir_type_bv(1));
        IrValueId zf = read_state(l, l->f->state.flags[X86_SPECIAL_STATE_ZF], ir_type_bv(1));
        value = binary(l, IR_OP_OR, 1, cf, zf);
    } else {
        IrValueId sf = read_state(l, l->f->state.flags[X86_SPECIAL_STATE_SF], ir_type_bv(1));
        IrValueId of = read_state(l, l->f->state.flags[X86_SPECIAL_STATE_OF], ir_type_bv(1));
        value = binary(l, IR_OP_XOR, 1, sf, of);
        if ((cc >> 1U) == 7) {
            IrValueId zf = read_state(l, l->f->state.flags[X86_SPECIAL_STATE_ZF], ir_type_bv(1));
            value = binary(l, IR_OP_OR, 1, value, zf);
        }
    }
    return cc & 1U ? unary(l, IR_OP_NOT, 1, value, 0) : value;
}

static void shifts(Lift *l, unsigned id, const cs_x86 *x, IrX86LiftResult *r) {
    const cs_x86_op *dst = &x->operands[0], *src = &x->operands[1];
    unsigned width = dst->size * 8U;
    IrValueId a = read_operand(l, x, dst, r);
    IrValueId raw =
        src->type == X86_OP_REG ? read_register(l, X86_REG_CL) : constant(l, 8, (uint64_t)src->imm);
    IrValueId count8 = binary(l, IR_OP_AND, 8, raw, constant(l, 8, 31));
    IrValueId count = width == 8 ? count8 : unary(l, IR_OP_ZEXT, width, count8, 0);
    IrValueId zero = binary(l, IR_OP_EQ, 1, count, constant(l, width, 0));
    IrValueId one = binary(l, IR_OP_EQ, 1, count, constant(l, width, 1));
    bool left = id == X86_INS_SHL || id == X86_INS_SAL, sar = id == X86_INS_SAR;
    IrValueId result = binary(l, left ? IR_OP_SHL : sar ? IR_OP_ASHR : IR_OP_LSHR, width, a, count);
    IrValueId flags[6];
    flags[X86_SPECIAL_STATE_ZF] = binary(l, IR_OP_EQ, 1, result, constant(l, width, 0));
    flags[X86_SPECIAL_STATE_SF] = bit(l, result, width - 1);
    IrValueId parity = bit(l, result, 0);
    for (unsigned i = 1; i < 8; ++i)
        parity = binary(l, IR_OP_XOR, 1, parity, bit(l, result, i));
    flags[X86_SPECIAL_STATE_PF] = unary(l, IR_OP_NOT, 1, parity, 0);
    IrValueId undefined = emit(
        l,
        (IrInstSpec){.op = IR_OP_UNKNOWN, .type = ir_type_bv(1), .immediate = IR_REASON_UNDEFINED});
    flags[X86_SPECIAL_STATE_AF] = undefined;
    IrValueId distance = left ? binary(l, IR_OP_SUB, width, constant(l, width, width), count)
                              : binary(l, IR_OP_SUB, width, count, constant(l, width, 1));
    IrValueId carry = bit(l, binary(l, sar ? IR_OP_ASHR : IR_OP_LSHR, width, a, distance), 0);
    IrValueId cf_defined =
        sar ? constant(l, 1, 1) : binary(l, IR_OP_ULT, 1, count, constant(l, width, width));
    flags[X86_SPECIAL_STATE_CF] = choose(l, 1, cf_defined, carry, undefined);
    IrValueId overflow = left  ? binary(l, IR_OP_XOR, 1, bit(l, result, width - 1), carry)
                         : sar ? constant(l, 1, 0)
                               : bit(l, a, width - 1);
    flags[X86_SPECIAL_STATE_OF] = choose(l, 1, one, overflow, undefined);
    r->flags_written = 0x3f;
    r->flags_preserved_when = zero;
    r->flags_defined[X86_SPECIAL_STATE_AF] = constant(l, 1, 0);
    r->flags_defined[X86_SPECIAL_STATE_CF] = cf_defined;
    r->flags_defined[X86_SPECIAL_STATE_OF] = one;
    for (unsigned i = 0; i < 6; ++i) {
        IrValueId old = read_state(l, l->f->state.flags[i], ir_type_bv(1));
        write_state(l, l->f->state.flags[i], choose(l, 1, zero, old, flags[i]));
    }
    write_operand(l, x, dst, result, r);
}

static IrX86LiftResult lift_instruction(IrX86Frontend *f, IrBlockId block, const InsnDesc *d,
                                        IrOrigin origin, unsigned target_only, bool repeat_body) {

    IrX86LiftResult r = {.status = IR_X86_LIFT_ERROR, .target_gpr = -1};
    if (!f || !d || !ir_module_block(f->module, block) || ir_module_status(f->module) != IR_OK)
        return r;
    if (d->arch != TRACE_ARCH_X86 || d->mode != TRACE_MODE_32) {
        r.status = IR_X86_LIFT_MODE;
        return r;
    }
    if (!d->desc_id || !origin.seq_id || !d->size || d->size > MAX_INSN_BYTES ||
        d->pc > UINT32_MAX || d->bytes_hash != trace_instruction_bytes_hash(d->bytes, d->size) ||
        !origin.has_trace_identity || origin.descriptor_id != d->desc_id || origin.pc != d->pc ||
        origin.code_generation != d->code_generation) {
        r.status = IR_X86_LIFT_IDENTITY;
        return r;
    }
    if (!ir_x86_range_permitted(f, (uint32_t)d->pc, d->size, IR_X86_ACCESS_EXEC)) {
        r.status = IR_X86_LIFT_MEMORY_MODEL;
        return r;
    }
    cs_insn *insn = NULL;
    size_t n = cs_disasm(f->decoder, d->bytes, d->size, d->pc, 1, &insn);
    if (n != 1 || !insn->detail || insn->size != d->size || insn->id != d->native_insn_id) {
        if (n)
            cs_free(insn, n);
        r.status = IR_X86_LIFT_IDENTITY;
        return r;
    }
    /* REP strings use an explicit expansion API. Other prefix exceptions stay
     * exact: ENDBR32 and F3 C3. No general prefix stripping. */
    static const uint8_t endbr32[] = {0xf3, 0x0f, 0x1e, 0xfb};
    bool exact_endbr32 = insn->id == X86_INS_ENDBR32 && d->size == sizeof(endbr32) &&
                         !memcmp(d->bytes, endbr32, sizeof(endbr32));
    bool exact_rep_ret = insn->id == X86_INS_RET && d->size == 2 &&
                         d->bytes[0] == 0xf3 && d->bytes[1] == 0xc3;
    bool repeated = (string_move(insn->id) || string_store(insn->id)) && repeat_prefixes(d);
    r.status =
        (exact_endbr32 || exact_rep_ret || repeated || supported_prefixes(d))
            ? preflight(f, insn) : IR_X86_LIFT_UNSUPPORTED;
    if (target_only && insn->id != X86_INS_JMP && insn->id != X86_INS_CALL &&
        insn->id != X86_INS_RET)
        r.status = IR_X86_LIFT_UNSUPPORTED;
    r.fallthrough = (uint32_t)(d->pc + d->size);
    if (r.status == IR_X86_LIFT_OK && repeated) {
        r.repeated = true;
        r.string_move = string_move(insn->id);
        r.string_bytes = insn->detail->x86.operands[0].size;
        r.string_address_bytes = insn->detail->x86.addr_size;
        if (!repeat_body) r.status = IR_X86_LIFT_REPEAT;
    }
    if (r.status != IR_X86_LIFT_OK || insn->id == X86_INS_NOP || exact_endbr32) {
        cs_free(insn, n);
        return r;
    }
    if (target_only == 2) {
        if (insn->id != X86_INS_RET && insn->detail->x86.operands[0].type == X86_OP_REG)
            r.target_gpr = register_slice(insn->detail->x86.operands[0].reg).reg_id;
        cs_free(insn, n);
        return r;
    }
    Lift l = {f, block, origin};
    const cs_x86 *x = &insn->detail->x86;
    int cc = condition_code(insn->id);
    int set_cc = set_condition_code(insn->id);
    int move_cc = move_condition_code(insn->id);
    if (insn->id == X86_INS_LOOP) {
        unsigned bits = x->addr_size * 8U, reg = bits == 16 ? X86_REG_CX : X86_REG_ECX;
        IrValueId count = binary(&l, IR_OP_SUB, bits, read_register(&l, reg), constant(&l, bits, 1));
        write_register(&l, reg, count);
        r.gpr_writes = 1U << REG_RCX;
        r.control = IR_X86_CONDITIONAL;
        r.direct_target = (uint32_t)x->operands[0].imm;
        r.condition = unary(&l, IR_OP_NOT, 1, binary(&l, IR_OP_EQ, 1, count, constant(&l, bits, 0)), 0);
    } else if (insn->id == X86_INS_NOT || insn->id == X86_INS_BSWAP) {
        const cs_x86_op *dst = &x->operands[0];
        IrValueId old = read_operand(&l, x, dst, &r), value;
        if (insn->id == X86_INS_NOT)
            value = unary(&l, IR_OP_NOT, dst->size * 8U, old, 0);
        else {
            value = unary(&l, IR_OP_EXTRACT, 8, old, 0);
            for (unsigned i = 1; i < 4; ++i)
                value = binary(&l, IR_OP_CONCAT, (i + 1) * 8U, value,
                               unary(&l, IR_OP_EXTRACT, 8, old, i * 8U));
        }
        write_operand(&l, x, dst, value, &r);
    } else if (insn->id == X86_INS_XCHG) {
        const cs_x86_op *a = &x->operands[0], *b = &x->operands[1];
        IrValueId av = read_operand(&l, x, a, &r), bv = read_operand(&l, x, b, &r);
        /* Store before modifying an address register, including XCHG [ESP], ESP.
         * Both old operands are read before either write. */
        if (a->type == X86_OP_MEM) {
            store_memory(&l, r.memory[0].address, a->size, bv, &r);
            write_operand(&l, x, b, av, &r);
        } else if (b->type == X86_OP_MEM) {
            store_memory(&l, r.memory[0].address, b->size, av, &r);
            write_operand(&l, x, a, bv, &r);
        } else {
            write_operand(&l, x, a, bv, &r);
            write_operand(&l, x, b, av, &r);
        }
    } else if (string_move(insn->id) || string_store(insn->id)) {
        bool move = string_move(insn->id);
        IrValueId value = read_operand(&l, x, &x->operands[1], &r);
        write_operand(&l, x, &x->operands[0], value, &r);
        unsigned bits = x->addr_size * 8U;
        IrValueId df = read_state(&l, f->state.flags[X86_SPECIAL_STATE_DF], ir_type_bv(1));
        IrValueId delta = constant(&l, bits, x->operands[0].size);
        unsigned indices[2] = {bits == 16 ? X86_REG_DI : X86_REG_EDI,
                               bits == 16 ? X86_REG_SI : X86_REG_ESI};
        for (unsigned i = 0; i < (move ? 2U : 1U); ++i) {
            IrValueId old = read_register(&l, indices[i]);
            write_register(&l, indices[i], choose(&l, bits, df,
                binary(&l, IR_OP_SUB, bits, old, delta), binary(&l, IR_OP_ADD, bits, old, delta)));
        }
        r.gpr_writes = (1U << REG_RDI) | (move ? 1U << REG_RSI : 0);
        if (repeated) {
            unsigned reg = bits == 16 ? X86_REG_CX : X86_REG_ECX;
            write_register(&l, reg, binary(&l, IR_OP_SUB, bits,
                                           read_register(&l, reg), constant(&l, bits, 1)));
            r.gpr_writes |= 1U << REG_RCX;
        }
    } else if (move_cc >= 0) {
        const cs_x86_op *dst = &x->operands[0], *src = &x->operands[1];
        /* The source load is unconditional, including a false condition.
         * Read both operands before writing an aliased destination/address. */
        IrValueId source = read_operand(&l, x, src, &r);
        IrValueId old =
            src->type == X86_OP_REG && src->reg == dst->reg ? source : read_register(&l, dst->reg);
        IrValueId condition = branch_condition(&l, (unsigned)move_cc);
        write_operand(&l, x, dst, choose(&l, dst->size * 8U, condition, source, old), &r);
    } else if (set_cc >= 0) {
        IrValueId condition = branch_condition(&l, (unsigned)set_cc);
        write_operand(&l, x, &x->operands[0], unary(&l, IR_OP_ZEXT, 8, condition, 0), &r);
    } else if (cc >= 0 || insn->id == X86_INS_JMP || insn->id == X86_INS_CALL ||
               insn->id == X86_INS_RET) {
        r.call = insn->id == X86_INS_CALL;
        if (cc >= 0) {
            r.control = IR_X86_CONDITIONAL;
            r.direct_target = (uint32_t)x->operands[0].imm;
            r.condition = branch_condition(&l, (unsigned)cc);
        } else if (insn->id == X86_INS_RET) {
            r.control = IR_X86_INDIRECT;
            IrValueId sp = read_register(&l, X86_REG_ESP);
            r.target = load_memory(&l, sp, 4, &r);
            if (!target_only) {
                uint32_t adjust = 4U + (x->op_count ? (uint16_t)x->operands[0].imm : 0U);
                stack_pointer(&l, binary(&l, IR_OP_ADD, 32, sp, constant(&l, 32, adjust)), &r);
            }
        } else {
            r.control = x->operands[0].type == X86_OP_IMM ? IR_X86_DIRECT_JUMP : IR_X86_INDIRECT;
            r.target = read_operand(&l, x, &x->operands[0], &r);
            if (r.control == IR_X86_DIRECT_JUMP)
                r.direct_target = (uint32_t)x->operands[0].imm;
            if (x->operands[0].type == X86_OP_REG)
                r.target_gpr = register_slice(x->operands[0].reg).reg_id;
            if (r.call && !target_only)
                push(&l, constant(&l, 32, r.fallthrough), 4, &r);
        }
    } else if (insn->id == X86_INS_PUSH) {
        IrValueId value = read_operand(&l, x, &x->operands[0], &r);
        push(&l, value, x->operands[0].size, &r);
    } else if (insn->id == X86_INS_POPAL) {
        static const unsigned registers[8] = {X86_REG_EDI,     X86_REG_ESI, X86_REG_EBP,
                                              X86_REG_INVALID, X86_REG_EBX, X86_REG_EDX,
                                              X86_REG_ECX,     X86_REG_EAX};
        IrValueId sp = read_register(&l, X86_REG_ESP);
        for (unsigned slot = 0; slot < 8; ++slot) {
            if (slot == 3) /* Saved ESP is skipped, not loaded. */
                continue;
            IrValueId address = binary(&l, IR_OP_ADD, 32, sp, constant(&l, 32, slot * 4));
            write_register(&l, registers[slot], load_memory(&l, address, 4, &r));
        }
        stack_pointer(&l, binary(&l, IR_OP_ADD, 32, sp, constant(&l, 32, 32)), &r);
        r.gpr_writes = 0xff;
    } else if (insn->id == X86_INS_POP || insn->id == X86_INS_LEAVE) {
        bool leave = insn->id == X86_INS_LEAVE;
        unsigned bytes = leave ? 4 : x->operands[0].size;
        IrValueId sp = read_register(&l, leave ? X86_REG_EBP : X86_REG_ESP);
        IrValueId value = load_memory(&l, sp, bytes, &r);
        stack_pointer(&l, binary(&l, IR_OP_ADD, 32, sp, constant(&l, 32, bytes)), &r);
        if (leave) {
            write_register(&l, X86_REG_EBP, value);
            r.gpr_writes |= 1U << REG_RBP;
        } else
            write_operand(&l, x, &x->operands[0], value, &r);
    } else if (shift(insn->id)) {
        shifts(&l, insn->id, x, &r);
    } else if (unary_arithmetic(insn->id)) {
        const cs_x86_op *dst = &x->operands[0];
        unsigned width = dst->size * 8U;
        IrValueId old = read_operand(&l, x, dst, &r);
        bool negate = insn->id == X86_INS_NEG;
        IrValueId a = negate ? constant(&l, width, 0) : old;
        IrValueId b = negate ? old : constant(&l, width, 1);
        IrValueId value = negate ? unary(&l, IR_OP_NEG, width, old, 0)
            : binary(&l, insn->id == X86_INS_INC ? IR_OP_ADD : IR_OP_SUB, width, a, b);
        arithmetic_flags(&l, insn->id, width, a, b, value, 0, &r);
        write_operand(&l, x, dst, value, &r);
    } else if (string_load(insn->id)) {
        /* Load from the old source index; AL/AX preserve the upper accumulator.
         * DF controls the index update and is itself unchanged. */
        IrValueId value = read_operand(&l, x, &x->operands[1], &r);
        write_operand(&l, x, &x->operands[0], value, &r);
        unsigned index = x->addr_size == 2 ? X86_REG_SI : X86_REG_ESI;
        unsigned bits = x->addr_size * 8U;
        IrValueId si = read_register(&l, index);
        IrValueId delta = constant(&l, bits, x->operands[0].size);
        IrValueId df = read_state(&l, f->state.flags[X86_SPECIAL_STATE_DF], ir_type_bv(1));
        write_register(&l, index,
                       choose(&l, bits, df, binary(&l, IR_OP_SUB, bits, si, delta),
                              binary(&l, IR_OP_ADD, bits, si, delta)));
        r.gpr_writes |= 1U << REG_RSI;
    } else if (scan(insn->id)) {
        unsigned width = x->operands[0].size * 8U;
        IrValueId a = read_operand(&l, x, &x->operands[0], &r);
        IrValueId b = read_operand(&l, x, &x->operands[1], &r);
        arithmetic_flags(&l, X86_INS_CMP, width, a, b, binary(&l, IR_OP_SUB, width, a, b), 0, &r);
        unsigned index = x->addr_size == 2 ? X86_REG_DI : X86_REG_EDI, bits = x->addr_size * 8U;
        IrValueId di = read_register(&l, index), delta = constant(&l, bits, width / 8);
        IrValueId df = read_state(&l, f->state.flags[X86_SPECIAL_STATE_DF], ir_type_bv(1));
        write_register(&l, index,
                       choose(&l, bits, df, binary(&l, IR_OP_SUB, bits, di, delta),
                              binary(&l, IR_OP_ADD, bits, di, delta)));
        r.gpr_writes |= 1U << REG_RDI;
    } else if (insn->id == X86_INS_CLD || insn->id == X86_INS_STD) {
        write_state(&l, f->state.flags[X86_SPECIAL_STATE_DF],
                    constant(&l, 1, insn->id == X86_INS_STD));
        r.flags_written = 1U << X86_SPECIAL_STATE_DF;
    } else {
        const cs_x86_op *dst = &x->operands[0], *src = &x->operands[1];
        IrValueId value;
        if (arithmetic(insn->id)) {
            IrValueId a = read_operand(&l, x, dst, &r);
            /* Identical aliases are one semantic read (self-XOR/CMP included). */
            IrValueId b = dst->type == X86_OP_REG && src->type == X86_OP_REG && dst->reg == src->reg
                              ? a
                              : read_operand(&l, x, src, &r);
            IrOpcode op = IR_OP_AND;
            switch (insn->id) {
            case X86_INS_ADD:
            case X86_INS_ADC:
                op = IR_OP_ADD;
                break;
            case X86_INS_SUB:
            case X86_INS_SBB:
            case X86_INS_CMP:
                op = IR_OP_SUB;
                break;
            case X86_INS_OR:
                op = IR_OP_OR;
                break;
            case X86_INS_XOR:
                op = IR_OP_XOR;
                break;
            default:
                break;
            }
            value = binary(&l, op, dst->size * 8U, a, b);
            IrValueId carry = 0;
            if (insn->id == X86_INS_ADC || insn->id == X86_INS_SBB) {
                carry = read_state(&l, f->state.flags[X86_SPECIAL_STATE_CF], ir_type_bv(1));
                value = binary(&l, op, dst->size * 8U, value,
                               unary(&l, IR_OP_ZEXT, dst->size * 8U, carry, 0));
            }
            arithmetic_flags(&l, insn->id, dst->size * 8U, a, b, value, carry, &r);
        } else if (insn->id == X86_INS_LEA) {
            value = effective_address(&l, x, src);
            if (x->addr_size < dst->size)
                value = unary(&l, IR_OP_ZEXT, dst->size * 8U, value, 0);
            if (x->addr_size > dst->size)
                value = unary(&l, IR_OP_EXTRACT, dst->size * 8U, value, 0);
        } else {
            value = read_operand(&l, x, src, &r);
            if (insn->id == X86_INS_MOVZX || insn->id == X86_INS_MOVSX)
                value = unary(&l, insn->id == X86_INS_MOVZX ? IR_OP_ZEXT : IR_OP_SEXT,
                              dst->size * 8U, value, 0);
        }
        if (insn->id != X86_INS_CMP && insn->id != X86_INS_TEST)
            write_operand(&l, x, dst, value, &r);
    }
    if (ir_module_status(f->module) != IR_OK)
        r.status = IR_X86_LIFT_ERROR;
    cs_free(insn, n);
    return r;
}

IrX86LiftResult ir_x86_lift(IrX86Frontend *f, IrBlockId b, const InsnDesc *d, IrOrigin o) {
    return lift_instruction(f, b, d, o, false, false);
}

IrX86LiftResult ir_x86_lift_target(IrX86Frontend *f, IrBlockId b, const InsnDesc *d, IrOrigin o) {
    return lift_instruction(f, b, d, o, true, false);
}

IrX86LiftResult ir_x86_describe_target(IrX86Frontend *f, IrBlockId b, const InsnDesc *d,
                                       IrOrigin o) {
    return lift_instruction(f, b, d, o, 2, false);
}

IrX86LiftResult ir_x86_lift_repeat(IrX86Frontend *f, IrBlockId block, const InsnDesc *d,
    IrOrigin origin, uint32_t iterations, uint32_t max_iterations,
    IrX86RepeatObserver observer, void *user) {
    if (!d || (!string_move(d->native_insn_id) && !string_store(d->native_insn_id)) ||
        d->size > MAX_INSN_BYTES || !repeat_prefixes(d))
        return (IrX86LiftResult){.status = IR_X86_LIFT_UNSUPPORTED, .target_gpr = -1};
    IrX86LiftResult result = lift_instruction(f, block, d, origin, 0, false);
    if (result.status != IR_X86_LIFT_REPEAT) return result;
    if (iterations > max_iterations ||
        (result.string_address_bytes == 2 && iterations > UINT16_MAX)) {
        result.status = IR_X86_LIFT_LIMIT;
        return result;
    }
    Lift l = {f, block, origin};
    unsigned bits = result.string_address_bytes * 8U;
    IrValueId count = read_register(&l, bits == 16 ? X86_REG_CX : X86_REG_ECX);
    IrValueId equal = binary(&l, IR_OP_EQ, 1, count, constant(&l, bits, iterations));
    if (!ir_emit_effect(f->module, block, (IrInstSpec){.op = IR_OP_GUARD,
        .type = ir_type_void(), .args = {equal}, .immediate = IR_REASON_GUARD, .origin = origin})) {
        result.status = IR_X86_LIFT_ERROR;
        return result;
    }
    result.status = IR_X86_LIFT_OK;
    for (uint32_t i = 0; i < iterations; ++i) {
        IrX86LiftResult one = lift_instruction(f, block, d, origin, 0, true);
        if (one.status != IR_X86_LIFT_OK) return one;
        result.gpr_writes |= one.gpr_writes;
        result.segment_reads |= one.segment_reads;
        result.reads_memory |= one.reads_memory;
        result.writes_memory |= one.writes_memory;
        if (observer && !observer(user, i, &one)) {
            result.status = IR_X86_LIFT_CALLBACK;
            return result;
        }
    }
    return result;
}
