"""Bind a computed payload-entry boundary to the restored ELF and live model.

The caller authenticates execution, memory, frontend and mapping receipts. This
module checks their consistency; computed IR mappings are not Linux observations.
"""

import hashlib
import re
import struct

try:
    from .oep_entry import parse_elf32
except ImportError:
    from oep_entry import parse_elf32


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _integer(value, name, maximum=0xffffffff):
    _require(type(value) is int and 0 <= value <= maximum, name)
    return value


def _digest(value, name):
    _require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), name)
    return value


def _hex(value, name):
    _require(isinstance(value, str) and len(value) % 2 == 0
             and re.fullmatch(r"[0-9a-f]*", value) is not None, name)
    return bytes.fromhex(value)


class _Image:
    def __init__(self, regions):
        _require(isinstance(regions, (list, tuple)), "RAM region list")
        self.regions = []
        for row in regions:
            _require(isinstance(row, dict), "RAM region record")
            address = _integer(row["address"], "RAM address")
            data, known = row["data"], row["known"]
            _require(isinstance(data, bytes) and isinstance(known, bytes)
                     and data and len(data) == len(known), "RAM value/mask extent")
            _require(address + len(data) <= 0x100000000, "RAM wraps")
            _require(all(v & ~k == 0 for v, k in zip(data, known)),
                     "RAM unknown bits are not canonical")
            self.regions.append((address, address + len(data), data, known))
        self.regions.sort()
        _require(all(a[1] <= b[0] for a, b in zip(self.regions, self.regions[1:])),
                 "Overlapping RAM regions")

    def read(self, address, size):
        _integer(address, "RAM read address")
        _integer(size, "RAM read size")
        _require(size and address + size <= 0x100000000, "RAM read wraps")
        chunks = []
        end = address + size
        for lo, hi, data, known in self.regions:
            if lo <= address < hi:
                take = min(hi, end) - address
                offset = address - lo
                _require(known[offset:offset + take] == b"\xff" * take,
                         "Required boundary bytes are UNKNOWN")
                chunks.append(data[offset:offset + take])
                address += take
                if address == end:
                    return b"".join(chunks)
        raise ValueError("Required boundary bytes are absent")


def _current_vmas(rows, page_size):
    _require(isinstance(rows, list), "Live VMA list")
    result = []
    for row in rows:
        _require(isinstance(row, dict), "Live VMA record")
        start = _integer(row["start"], "VMA start")
        end = _integer(row["end"], "VMA end", 0x100000000)
        permissions = _integer(row["permissions"], "VMA permissions", 7)
        _require(start < end and start % page_size == end % page_size == 0,
                 "VMA geometry")
        result.append((start, end, permissions))
    result.sort()
    _require(all(a[1] <= b[0] for a, b in zip(result, result[1:])),
             "Overlapping live VMAs")
    return result


def _executable(vmas, address, size):
    end = address + size
    for lo, hi, permissions in vmas:
        if lo <= address < hi:
            _require(permissions & 4, "Boundary fetch is NX in current model")
            address = min(hi, end)
            if address == end:
                return
    raise ValueError("Boundary fetch is unmapped in current model")


def _validate_ir_node(node, pc, encoded):
    _require(isinstance(node, dict), "Boundary IR record")
    _require(node.get("pc") == pc and node.get("size") == len(encoded)
             and _hex(node.get("bytes"), "IR bytes") == encoded, "IR byte identity")
    _require(node.get("ir_validator_passed") is True
             and node.get("ir_semantics_modeled") is True
             and node.get("lift_status") == 0, "Unsupported boundary IR")
    dump = node.get("original_ir_dump")
    _require(isinstance(dump, str), "IR dump missing")
    _require(hashlib.sha256(dump.encode()).hexdigest()
             == _digest(node.get("original_ir_sha256"), "IR digest"), "IR dump digest")


def _register_jump(encoded):
    instruction = encoded[1:] if encoded[:1] == b"\x3e" else encoded
    _require(len(instruction) == 2 and instruction[0] == 0xff
             and 0xe0 <= instruction[1] <= 0xe7,
             "Boundary transfer is not a supported near register JMP")
    return instruction[1] & 7


def _auxv_values(auxv):
    _require(isinstance(auxv, (dict, list, tuple)), "Auxv table")
    pairs = auxv.items() if isinstance(auxv, dict) else auxv
    result = {}
    for pair in pairs:
        _require(isinstance(pair, (list, tuple)) and len(pair) == 2, "Auxv pair")
        tag, value = pair
        _integer(tag, "Auxv tag")
        _integer(value, "Auxv value")
        if tag in (3, 4, 5, 6, 9):
            _require(tag not in result, "Duplicate critical auxv tag")
            result[tag] = value
    return result


def audit_boundary(regions, execution, *, header_address=0x08048000,
                   final_auxv=None, boundary=None, last_ir_node=None,
                   original_elf=None, image_provenance=None, page_size=4096):
    """Check one restored ET_EXEC entry; missing receipts stay explicitly OPEN.

    regions contains {address, data: bytes, known: bytes}. boundary is the
    source-built oep_execute boundary.json, bound to execution by step/path.
    last_ir_node is the catalogue node selected by boundary.transition.pc.
    final_auxv contains integer tag/value pairs, including allowed duplicate
    noncritical entries. original_elf is optional independent reference content;
    its pre-pack origin is authenticated by the caller, not inferred here.
    """
    _integer(header_address, "ELF header address")
    _require(isinstance(execution, dict), "Execution record")
    _integer(page_size, "Page size")
    _require(page_size and page_size & (page_size - 1) == 0, "Page size power of two")
    image = _Image(regions)
    header = image.read(header_address, 52)
    phoff = struct.unpack_from("<I", header, 28)[0]
    phentsize, phnum = struct.unpack_from("<HH", header, 42)
    header_size = max(52, phoff + phentsize * phnum)
    _require(header_size <= 65536, "ELF header table budget")
    header = image.read(header_address, header_size)
    elf = parse_elf32(header, require_file_bytes=False)
    target = _integer(execution.get("pc"), "Computed final PC")
    _require(target == elf["entry"], "Computed target differs from restored e_entry")
    segments = elf["program_headers"]
    load = [p for p in segments if p["type"] == 1]
    executable = [p for p in load if p["flags"] & 1
                  and p["vaddr"] <= target < p["vaddr"] + p["filesz"]]
    _require(executable, "Target is outside executable file-backed PT_LOAD")
    table_end = elf["phoff"] + elf["phnum"] * elf["phentsize"]
    phdr_addresses = {p["vaddr"] + elf["phoff"] - p["offset"] for p in load
                      if p["offset"] <= elf["phoff"]
                      and table_end <= p["offset"] + p["filesz"]}
    _require(len(phdr_addresses) == 1, "Ambiguous or unmapped ELF PHDR table")
    checks = {"derived_e_entry_equals_computed_target": True,
              "target_in_executable_file_backed_PT_LOAD": True,
              "computed_image_lineage_bound": False,
              "final_auxv_matches_restored_ELF": False,
              "computed_last_indirect_transfer_bound": False,
              "live_model_execute_permissions_checked": False,
              "current_known_target_fetch_lifted": False}
    missing = []
    path = _digest(execution.get("path_sha256"), "Execution path digest")
    instructions = _integer(execution.get("instructions"), "Execution instruction count", 2**64 - 1)
    _require(execution.get("checkpoint_used_as_seed") is False,
             "Boundary execution was seeded from checkpoint")
    _require(execution.get("target_instruction_executed") is False,
             "Expected a stop before payload instruction execution")
    if image_provenance is None:
        missing.append("COMPUTED_IMAGE_LINEAGE_NOT_SUPPLIED")
    else:
        _require(isinstance(image_provenance, dict), "Image lineage record")
        _require(image_provenance.get("source_kind") == "computed_IR_model"
                 and image_provenance.get("path_sha256") == path
                 and image_provenance.get("checkpoint_used_as_seed") is False,
                 "Computed image lineage mismatch")
        _digest(image_provenance.get("source_elf_sha256"), "Packed ELF digest")
        checks["computed_image_lineage_bound"] = True
    if final_auxv is None:
        missing.append("FINAL_AUXV_NOT_SUPPLIED")
    else:
        values = _auxv_values(final_auxv)
        expected = {3: next(iter(phdr_addresses)), 4: elf["phentsize"],
                    5: elf["phnum"], 6: page_size, 9: target}
        _require(all(values.get(k) == v for k, v in expected.items()),
                 "Final auxv differs from restored ELF")
        checks["final_auxv_matches_restored_ELF"] = True
    if boundary is None:
        missing.extend(("DYNAMIC_LAST_TRANSFER_RECEIPT_NOT_SUPPLIED",
                        "CURRENT_MODEL_VMAS_NOT_SUPPLIED", "TARGET_FETCH_RECEIPT_NOT_SUPPLIED"))
    else:
        _require(isinstance(boundary, dict), "Boundary receipt")
        _require(boundary.get("schema_version") == 1
                 and boundary.get("source_kind") == "computed_IR_model"
                 and boundary.get("pc") == target
                 and boundary.get("instructions") == instructions
                 and boundary.get("path_sha256") == path, "Boundary receipt identity")
        _require(boundary.get("guest_permissions_independently_observed") is False
                 and boundary.get("kernel_implementation_verified") is False
                 and boundary.get("independent_entry_origins_proven") is False
                 and boundary.get("target_instruction_executed") is False
                 and boundary.get("oep_proof") == "NOT_ESTABLISHED",
                 "Computed boundary receipt promoted independent proof scope")
        transition = boundary.get("transition")
        if transition is None:
            missing.append("DYNAMIC_LAST_TRANSFER_RECEIPT_NOT_SUPPLIED")
        else:
            _require(isinstance(transition, dict), "Last transfer record")
            pc = _integer(transition.get("pc"), "Last transfer PC")
            encoded = _hex(transition.get("bytes_hex"), "Last transfer bytes")
            _require(transition.get("size") == len(encoded)
                     and transition.get("control") == 3
                     and transition.get("computed_target") == target
                     and transition.get("computed_target_known") is True
                     and transition.get("instruction_ordinal") == instructions,
                     "Last transfer computation identity")
            register = _register_jump(encoded)
            _require(image.read(pc, len(encoded)) == encoded,
                     "Last transfer differs from current RAM")
            registers = execution.get("registers")
            _require(isinstance(registers, list) and len(registers) == 8,
                     "Final register file")
            reg = registers[register]
            _require(reg.get("known") == 0xffffffff and reg.get("value") == target,
                     "Indirect target register is unknown or differs")
            if register == 0:
                _require(transition.get("eax") == reg, "Transfer EAX receipt differs")
            if last_ir_node is None:
                missing.append("LAST_TRANSFER_ORIGINAL_IR_NODE_NOT_SUPPLIED")
            else:
                _validate_ir_node(last_ir_node, pc, encoded)
                target_id = last_ir_node.get("target_value_id")
                ops = last_ir_node.get("instructions")
                _require(last_ir_node.get("control") == 3
                         and last_ir_node.get("call") is False
                         and last_ir_node.get("gpr_writes") == 0
                         and last_ir_node.get("flags_written") == 0
                         and type(target_id) is int and target_id > 0
                         and isinstance(ops, list) and len(ops) == 1
                         and ops[0].get("opcode") == "READ_STATE"
                         and ops[0].get("bits") == 32
                         and ops[0].get("state_key") == 256 + register
                         and ops[0].get("value_id") == target_id
                         and transition.get("original_ir_sha256") == last_ir_node["original_ir_sha256"]
                         and transition.get("target_value_id") == target_id,
                         "Original IR does not bind the register JMP")
                checks["computed_last_indirect_transfer_bound"] = True
        vmas = boundary.get("vmas")
        if vmas is None:
            missing.append("CURRENT_MODEL_VMAS_NOT_SUPPLIED")
        else:
            vmas = _current_vmas(vmas, page_size)
            _executable(vmas, target, 1)
            if transition is not None:
                _executable(vmas, transition["pc"], transition["size"])
            checks["live_model_execute_permissions_checked"] = True
        fetch = boundary.get("fetch")
        if fetch is None:
            missing.append("TARGET_FETCH_RECEIPT_NOT_SUPPLIED")
        else:
            _require(isinstance(fetch, dict), "Target fetch record")
            size = _integer(fetch.get("size"), "Target instruction size", 15)
            _require(size > 0 and fetch.get("pc") == target, "Target fetch identity")
            encoded = _hex(fetch.get("bytes_hex"), "Target fetch bytes")
            _require(len(encoded) == size
                     and _hex(fetch.get("known_hex"), "Target fetch mask") == b"\xff" * size
                     and image.read(target, size) == encoded, "Target fetch bytes/masks differ")
            node = dict(fetch, bytes=fetch["bytes_hex"])
            _validate_ir_node(node, target, encoded)
            _require(fetch.get("target_instruction_executed") is False,
                     "Fetch receipt must not claim payload execution")
            if vmas is not None:
                _executable(vmas, target, size)
            checks["current_known_target_fetch_lifted"] = True
    original = None
    originality_missing = ["INDEPENDENT_PREPACK_REFERENCE_NOT_SUPPLIED"]
    if original_elf is not None:
        _require(isinstance(original_elf, bytes), "Original ELF reference type")
        reference = parse_elf32(original_elf)
        _require(reference["entry"] == target and reference["program_headers"] == segments,
                 "Original ELF geometry differs from restored image")
        _require(image.read(header_address, header_size) == original_elf[:header_size],
                 "Original ELF header differs from restored image")
        for segment in load:
            size = segment["filesz"]
            if size:
                _require(image.read(segment["vaddr"], size)
                         == original_elf[segment["offset"]:segment["offset"] + size],
                         "Restored PT_LOAD bytes differ from original reference")
            zero_size = segment["memsz"] - size
            if zero_size:
                _require(image.read(segment["vaddr"] + size, zero_size) == b"\0" * zero_size,
                         "Restored BSS differs from original reference")
        original = {"sha256": hashlib.sha256(original_elf).hexdigest(),
                    "PT_LOAD_file_and_zero_fill_bytes_match": True,
                    "reference_prepack_origin_authenticated_by_this_module": False}
        originality_missing = ["REFERENCE_PREPACK_ORIGIN_REQUIRES_CALLER_AUTHENTICATION"]
    verified = all(checks.values())
    return {"schema_version": 1,
            "status": "VERIFIED_RESTORED_IMAGE_ENTRY_BOUNDARY" if verified else "OPEN_ENTRY_BOUNDARY_OBLIGATIONS",
            "entry": target, "restored_header_address": header_address,
            "restored_program_headers": segments,
            "checks": checks, "restored_entry_boundary_verified": verified,
            "open_boundary_obligations": missing,
            "original_reference": original,
            "open_originality_obligations": originality_missing,
            "original_reference_image_matches": original is not None,
            "guest_permissions_independently_observed": False,
            "trusted_inputs_require_caller_authentication": True,
            "claim_scope": "RESTORED_IMAGE_ENTRY_UNDER_SUPPLIED_IR_MODEL",
            "oep_proof": "NOT_ESTABLISHED"}
