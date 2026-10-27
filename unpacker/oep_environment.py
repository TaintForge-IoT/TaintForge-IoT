"""Audit the observed x86-32 syscall chain without promoting kernel premises.

The ledger checks consequences of a small explicit Linux ABI model.  Capture
records establish observations; a consistent ledger is not a proof of Linux or
of unobserved page-cache, mapping, or initial-process state.
"""

import hashlib
import json


PAGE_SIZE = 4096
U32_LIMIT = 1 << 32
MAX_PAGES = 65536
ARG_REGISTERS = ("ebx", "ecx", "edx", "esi", "edi", "ebp")
PRESERVED_REGISTERS = ARG_REGISTERS + ("esp", "eflags")
SELECTED_SYSCALLS = (
    356, 93, 90, 4, 90, 6, 5, 85, 91, 90, 125, 356, 93,
    90, 144, 91, 90, 6, 90, 125, 90, 45, 91, 192, 6, 91,
)


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _u32(value, label):
    _require(type(value) is int and 0 <= value < U32_LIMIT, label)
    return value


def _hex(value, label):
    _require(type(value) is str and len(value) % 2 == 0, label)
    _require(len(value) <= 64 * 1024 * 1024, label + " exceeds bound")
    try:
        result = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(label) from exc
    _require(len(result) * 2 == len(value), label + " contains whitespace")
    return result


def syscall_arity(number, flags=0):
    """Number of consumed scalar ABI arguments; old_mmap has a memory array."""
    if number in (356, 93, 91):
        return 2
    if number in (4, 85, 125, 144):
        return 3
    if number in (6, 45, 90):
        return 1
    if number == 192:
        return 6
    if number == 5:
        return 3 if flags & 0x40 or flags & 0x410000 == 0x410000 else 2
    raise ValueError("Unsupported syscall ABI: " + str(number))


def _pairs(rows, expected_syscall_count):
    calls = []
    pending = None
    returned = None
    for index, row in enumerate(rows):
        _require(type(row) is dict, "Capture row must be an object")
        kind = row.get("kind")
        if pending is not None and kind in ("tail_insn", "tail_memory"):
            raise ValueError("Guest execution interposed inside syscall observation boundary")
        if kind == "syscall_enter":
            _require(pending is None, "Overlapping or missing syscall return/post")
            _require(row.get("ordinal") == len(calls) + 1, "Syscall ordinal order")
            _u32(row.get("number"), "Syscall number")
            _u32(row.get("pc"), "Syscall PC")
            args = row.get("args")
            _require(type(args) is list and len(args) == 6, "Six captured ABI registers required")
            for value in args:
                _u32(value, "Syscall argument")
            registers = row.get("registers")
            _require(type(registers) is dict, "Syscall entry registers missing")
            _require(_u32(registers.get("eax"), "Entry EAX") == row["number"], "Entry syscall number differs")
            arity = syscall_arity(row["number"], args[1] if row["number"] == 5 else 0)
            for key, argument in zip(ARG_REGISTERS[:arity], args[:arity]):
                _require(_u32(registers.get(key), "Entry " + key) == argument, "Consumed argument register differs: " + key)
            for key in PRESERVED_REGISTERS:
                _u32(registers.get(key), "Entry " + key)
            pending = (row, index)
        elif kind == "syscall_return":
            _require(pending is not None and returned is None, "Unexpected or duplicate syscall return")
            entry = pending[0]
            _require(all(row.get(k) == entry[k] for k in ("ordinal", "number", "pc")), "Return identity differs")
            _u32(row.get("result_u32"), "Syscall result")
            returned = (row, index)
        elif kind == "syscall_post":
            _require(pending is not None and returned is not None, "Unexpected syscall post")
            entry, entry_index = pending
            result, return_index = returned
            _require(all(row.get(k) == entry[k] for k in ("ordinal", "number")), "Post identity differs")
            _require(row.get("pc") == entry["pc"] + 2, "Post PC is not after selected int80")
            registers = row.get("registers")
            _require(type(registers) is dict, "Syscall post registers missing")
            _require(_u32(registers.get("eax"), "Post EAX") == result["result_u32"], "Post result differs")
            for key in PRESERVED_REGISTERS:
                _require(_u32(registers.get(key), "Post " + key) == entry["registers"][key], "Observed syscall clobber: " + key)
            snapshots = [r for r in rows[return_index + 1:index] if r.get("kind") == "snapshot"]
            _require(all(r.get("syscall_ordinal") == entry["ordinal"] for r in snapshots), "Snapshot syscall ordinal differs")
            calls.append((entry, result, snapshots))
            pending = returned = None
    _require(pending is None and returned is None, "Incomplete syscall chain")
    if expected_syscall_count is not None:
        _require(len(calls) == expected_syscall_count, "Syscall count differs")
    if expected_syscall_count == len(SELECTED_SYSCALLS):
        _require(tuple(e["number"] for e, _, _ in calls) == SELECTED_SYSCALLS, "Selected syscall sequence differs")
    return calls


def compare_contracts(rows, contracts_text):
    """Match native contracts only on ABI-consumed arguments and mmap arrays."""
    calls = _pairs(rows, 26)
    _require(type(contracts_text) is str, "Contracts must be text")
    lines = iter(contracts_text.splitlines())
    for entry, result, _ in calls:
        try:
            fields = next(lines).split()
            _require(len(fields) == 10, "Contract field count")
            address = int(fields[0], 16)
            number = int(fields[1], 10)
            arguments = [int(v, 16) for v in fields[2:8]]
            outcome = int(fields[8], 16)
        except (StopIteration, ValueError) as exc:
            raise ValueError("Malformed or missing native contract") from exc
        _require(address == entry["pc"] and number == entry["number"], "Native contract identity differs")
        arity = syscall_arity(number, entry["args"][1] if number == 5 else 0)
        _require(arguments[:arity] == entry["args"][:arity], "Native consumed ABI arguments differ")
        _require(outcome == result["result_u32"], "Native result differs")
        reply = "-" if result.get("reply_hex") in (None, "") else result["reply_hex"].lower()
        _require(fields[9].lower() == reply, "Native reply differs")
        if number in (90, 192):
            expected = entry["mmap_args"] if number == 90 else entry["args"]
            try:
                array = [int(v, 16) for v in next(lines).split()]
            except (StopIteration, ValueError) as exc:
                raise ValueError("Missing native mmap array") from exc
            _require(array == expected, "Native mmap array differs")
    _require(next(lines, None) is None, "Trailing native contracts")
    return {"contracts": len(calls), "ABI_consumed_arguments_match": True,
            "unused_captured_arguments_not_constrained": True}


def _extent(start, length, page_size=PAGE_SIZE):
    _u32(start, "Mapping start")
    _u32(length, "Mapping length")
    _require(length > 0 and start % page_size == 0, "Empty or unaligned mapping extent")
    end = (start + length + page_size - 1) // page_size * page_size
    _require(end <= U32_LIMIT and (end - start) // page_size <= MAX_PAGES, "Mapping extent overflow or budget")
    return range(start, end, page_size)


def _regions(pages):
    result = []
    for address, page in sorted(pages.items()):
        if (result and result[-1]["end"] == address
                and result[-1]["prot"] == page["prot"]
                and result[-1]["file_id"] == page["file_id"]
                and result[-1]["offset"] + address - result[-1]["start"] == page["offset"]):
            result[-1]["end"] += PAGE_SIZE
        else:
            result.append({"start": address, "end": address + PAGE_SIZE,
                           "prot": page["prot"], "file_id": page["file_id"], "offset": page["offset"]})
    return result


def audit_environment(rows, initial_profile=None, effect_observations=None, expected_syscall_count=26):
    """Return observed checks, a conditional ledger and remaining obligations.

    ``initial_profile`` is a declared input with optional ``fds``, ``vmas`` and
    ``brk``.  It is never treated as an independently proved OS state. Optional
    ``effect_observations`` has a matching canonical ``capture_rows_sha256`` and
    ``vma_snapshots``. Each snapshot has ``ordinal`` and complete ``vmas`` with
    start/end/prot. Their provenance remains an explicit caller trust boundary.
    """
    _require(type(rows) is list, "Capture rows must be a list")
    calls = _pairs(rows, expected_syscall_count)
    canonical_digest = hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    profile = initial_profile if initial_profile is not None else {}
    _require(type(profile) is dict, "Initial profile must be an object")
    _require(profile.get("page_size", PAGE_SIZE) == PAGE_SIZE, "Only explicit 4096-byte page profile is modeled")
    descriptors, files, pages = {}, {}, {}
    known_unmapped = set()
    checks, requirements = [], []
    inherited_uses = []
    for item in profile.get("fds", []):
        fd = _u32(item.get("fd"), "Initial fd")
        _require(fd not in descriptors and type(item.get("file_id")) is str, "Duplicate initial fd or missing file identity")
        key = item["file_id"]
        size = item.get("size")
        if size is not None:
            _u32(size, "Initial file size")
        access = item.get("access")
        _require(access in (None, "read", "write", "read_write"), "Initial fd access mode")
        descriptors[fd] = {"file_id": key, "position": _u32(item.get("position", 0), "Initial fd position"),
                           "origin": "profile", "access": access}
        files.setdefault(key, {"kind": "initial", "size": size,
                               "may_have_shared_writes": False, "may_have_file_writes": True})
    for item in profile.get("vmas", []):
        start, end = _u32(item.get("start"), "Initial VMA start"), item.get("end")
        _require(type(end) is int and start < end <= U32_LIMIT and end % PAGE_SIZE == 0, "Initial VMA end")
        prot = _u32(item.get("prot"), "Initial VMA protection")
        _require(prot <= 7, "Unsupported initial protection bits")
        for address in _extent(start, end - start):
            _require(address not in pages, "Overlapping initial VMA")
            pages[address] = {"prot": prot, "file_id": item.get("file_id"), "offset": item.get("offset", 0) + address - start}
    observations = {}
    if effect_observations is not None:
        _require(type(effect_observations) is dict, "Effect observations must be an object")
        _require(effect_observations.get("capture_rows_sha256") == canonical_digest, "Effect observations belong to a different capture")
        for snapshot in effect_observations.get("vma_snapshots", []):
            ordinal = snapshot.get("ordinal")
            _require(type(ordinal) is int and 0 <= ordinal <= len(calls) and ordinal not in observations, "Effect snapshot ordinal")
            observations[ordinal] = snapshot

    def observe_vmas(ordinal):
        if ordinal not in observations:
            return False
        observed = {}
        for item in observations[ordinal].get("vmas", []):
            start, end, prot = item.get("start"), item.get("end"), item.get("prot")
            _u32(start, "Observed VMA start")
            _require(type(end) is int and start < end <= U32_LIMIT and end % PAGE_SIZE == 0, "Observed VMA end")
            _require(type(prot) is int and 0 <= prot <= 7, "Observed VMA protection")
            for address in _extent(start, end - start):
                _require(address not in observed, "Overlapping observed VMA")
                observed[address] = prot
        for address, page in pages.items():
            _require(observed.get(address) == page["prot"], "Observed VMA differs from modeled mapping/protection")
        _require(not known_unmapped.intersection(observed), "Observed VMA still contains unmapped pages")
        checks.append({"kind": "supplied_VMA_presence_and_protection_match_model", "ordinal": ordinal,
                       "known_pages": len(pages), "observation_provenance_is_external_premise": True})
        return True

    observe_vmas(0)
    initial_source = next((r for r in rows if r.get("kind") == "snapshot" and r.get("label") == "initial_source"), None)
    source_bytes = _hex(initial_source["bytes_hex"], "Initial source snapshot") if initial_source else None
    last_mapped_images = {}
    fd_events, mapping_events = [], []
    observed_mapping_ordinals = []
    relevant_mapping_ordinals = []
    brk = profile.get("brk")
    if brk is not None:
        _u32(brk, "Initial brk")

    for entry, returned, snapshots in calls:
        ordinal, number, args = entry["ordinal"], entry["number"], entry["args"]
        result = returned["result_u32"]
        _require(result < 0xFFFFF001, "Selected replay contains a failed syscall")
        fd = args[0]
        mapped = None
        if number in (356, 5):
            _require(result < (1 << 31) and result not in descriptors, "Invalid or occupied allocated fd")
            path = _hex(entry.get("path_hex"), "Captured path")
            _require(path and b"\0" not in path and len(path) < 4096, "Invalid captured path")
            key = "memfd:" + str(ordinal) if number == 356 else "open:" + str(ordinal)
            kind = "memfd" if number == 356 else "source" if path == b"/proc/self/exe" else "external"
            files[key] = {"kind": kind, "size": 0 if number == 356 else None,
                          "may_have_shared_writes": False, "may_have_file_writes": False}
            access = "read_write" if number == 356 else {0: "read", 1: "write", 2: "read_write"}.get(args[1] & 3)
            _require(access is not None, "Invalid open access mode")
            descriptors[result] = {"file_id": key, "position": 0, "origin": "syscall:" + str(ordinal), "access": access}
            fd_events.append({"ordinal": ordinal, "operation": "create", "fd": result, "file_id": key, "kind": kind})
        elif number in (93, 4, 6):
            _require(fd in descriptors, "Unknown fd consumed by syscall")
            descriptor = descriptors[fd]
            file = files[descriptor["file_id"]]
            if descriptor["origin"] == "profile":
                inherited_uses.append(ordinal)
            if number in (93, 4):
                _require(descriptor["access"] != "read", "Read-only fd consumed by writing syscall")
            if number == 93:
                _require(result == 0, "ftruncate success result")
                file["size"] = args[1]
            elif number == 4:
                _require(result <= args[2], "write exceeds requested count")
                _require(args[1] + result <= U32_LIMIT, "write buffer overflow")
                old_position = descriptor["position"]
                descriptor["position"] += result
                if file["size"] is not None:
                    file["size"] = max(file["size"], descriptor["position"])
                file["may_have_file_writes"] |= result != 0
                requirements.append({"id": "write_buffer_and_file_visibility", "ordinal": ordinal,
                                     "file_id": descriptor["file_id"], "offset": old_position, "bytes": result})
            else:
                _require(result == 0, "close success result")
                del descriptors[fd]
                fd_events.append({"ordinal": ordinal, "operation": "close", "fd": fd})
        elif number == 85:
            reply = _hex(returned.get("reply_hex"), "readlink reply")
            _require(len(reply) == result <= args[2] and args[1] + result <= U32_LIMIT, "readlink reply extent")
            checks.append({"kind": "observed_readlink_reply", "ordinal": ordinal, "address": args[1],
                           "bytes": result, "sha256": hashlib.sha256(reply).hexdigest()})
            requirements.append({"id": "readlink_reply_written_to_guest_RAM", "ordinal": ordinal})
        elif number in (90, 192):
            array = entry.get("mmap_args") if number == 90 else args
            _require(type(array) is list and len(array) == 6, "mmap array missing")
            for value in array:
                _u32(value, "mmap array value")
            requested, length, prot, flags, mmap_fd, offset = array
            _require(prot <= 7 and flags & 3 in (1, 2) and flags & ~0x33 == 0, "Unmodeled mmap protection/flags")
            if flags & 0x10:
                _require(result == requested and requested % PAGE_SIZE == 0, "MAP_FIXED result differs")
            mapping_pages = _extent(result, length)
            offset = offset * PAGE_SIZE if number == 192 else offset
            _require(offset % PAGE_SIZE == 0 and offset < U32_LIMIT, "Unmodeled or unaligned file offset")
            file_id = None
            if not flags & 0x20:
                _require(mmap_fd in descriptors, "Unknown mmap fd")
                descriptor = descriptors[mmap_fd]
                file_id = descriptor["file_id"]
                _require(descriptor["access"] != "write", "Write-only fd cannot supply file mapping")
                _require(not (flags & 1 and prot & 2) or descriptor["access"] != "read",
                         "Read-only fd cannot supply shared writable mapping")
                if descriptor["origin"] == "profile":
                    inherited_uses.append(ordinal)
            for address in mapping_pages:
                _require(flags & 0x10 or address not in pages, "Non-fixed mmap overlaps live mapping")
                pages[address] = {"prot": prot, "file_id": file_id, "offset": offset + address - result}
                known_unmapped.discard(address)
            _require(len(pages) <= MAX_PAGES, "Mapping ledger page budget")
            mapped = {"ordinal": ordinal, "start": result, "end": mapping_pages.stop,
                      "requested_length": length, "prot": prot, "flags": flags,
                      "file_id": file_id, "offset": offset}
            mapping_events.append(mapped)
            relevant_mapping_ordinals.append(ordinal)
            if file_id is not None and files[file_id]["may_have_shared_writes"]:
                requirements.append({"id": "shared_file_and_partial_last_page_cache_visibility", "ordinal": ordinal,
                                     "file_id": file_id, "offset": offset, "length": length})
        elif number in (91, 125, 144):
            _require(result == 0, "Memory syscall success result")
            extent = _extent(args[0], args[1])
            if number == 91:
                for address in extent:
                    pages.pop(address, None)
                    known_unmapped.add(address)
            elif number == 125:
                _require(args[2] <= 7, "Unmodeled mprotect bits")
                for address in extent:
                    _require(address in pages, "mprotect coverage absent from ledger")
                    pages[address]["prot"] = args[2]
            else:
                _require(args[2] in (1, 2, 4, 5, 6), "Unmodeled msync flags")
                _require(all(address in pages for address in extent), "msync coverage absent from ledger")
                requirements.append({"id": "msync_memory_file_effects", "ordinal": ordinal})
            relevant_mapping_ordinals.append(ordinal)
        elif number == 45:
            if brk is not None:
                _require(result in (brk, args[0]), "brk result inconsistent with declared current brk")
            brk = result
            requirements.append({"id": "brk_mapping_effects", "ordinal": ordinal})

        for snapshot in snapshots:
            blob = _hex(snapshot.get("bytes_hex"), "Post-syscall snapshot")
            start = _u32(snapshot.get("address"), "Snapshot address")
            _require(snapshot.get("size") == len(blob) and start + len(blob) <= U32_LIMIT, "Snapshot extent")
            if mapped and start == mapped["start"] and len(blob) == mapped["end"] - start:
                file = files.get(mapped["file_id"])
                within_file_pages = file is not None and file["size"] is not None and (
                    mapped["offset"] + len(blob) <= (file["size"] + PAGE_SIZE - 1) // PAGE_SIZE * PAGE_SIZE)
                expected_zero = file is None or (file["kind"] == "memfd" and within_file_pages
                    and not file["may_have_shared_writes"] and not file["may_have_file_writes"])
                if expected_zero:
                    _require(not any(blob), "Observed new mapping is not zero-filled")
                    checks.append({"kind": "observed_zero_mapping", "ordinal": ordinal, "address": start, "bytes": len(blob)})
                if file and file["kind"] == "source" and source_bytes is not None:
                    expected = source_bytes[mapped["offset"]:mapped["offset"] + len(blob)]
                    _require(len(expected) == len(blob) and blob == expected, "Observed source-file mapping differs")
                    checks.append({"kind": "observed_source_file_mapping", "ordinal": ordinal, "bytes": len(blob)})
            key = (start, len(blob))
            if number == 6 and key in last_mapped_images:
                _require(blob == last_mapped_images[key], "Observed mapping bytes changed across close")
                checks.append({"kind": "observed_mapping_survives_close", "ordinal": ordinal, "address": start, "bytes": len(blob)})
            last_mapped_images[key] = blob
        if mapped and mapped["file_id"] is not None and mapped["flags"] & 1 and mapped["prot"] & 2:
            files[mapped["file_id"]]["may_have_shared_writes"] = True
        if observe_vmas(ordinal):
            observed_mapping_ordinals.append(ordinal)

    open_obligations = [
        {"id": "initial_process_profile_origin", "reason": "Absent" if initial_profile is None else "Supplied profile remains an explicit external admission"},
        {"id": "observations_are_bound_to_actual_execution_by_caller", "reason": "This module checks data consistency, not capture authenticity"},
        {"id": "no_outside_mutation_or_signal_effects", "reason": "Not independently established by syscall boundary records"},
    ]
    missing = sorted(set(relevant_mapping_ordinals) - set(observed_mapping_ordinals))
    if missing:
        open_obligations.append({"id": "mapping_and_permission_effect_observations", "ordinals": missing})
    open_obligations.extend(requirements)
    return {
        "status": "PASS_WITH_OBSERVED_SYSCALLS_AND_EXPLICIT_ENVIRONMENT_PREMISES",
        "capture_rows_sha256": canonical_digest, "syscall_count": len(calls),
        "ABI_consumed_register_arguments_consistent": True,
        "syscall_results_and_non_EAX_register_preservation_observed": True,
        "selected_int80_instruction_width": 2, "page_size_profile": PAGE_SIZE,
        "declared_initial_profile_provided": initial_profile is not None,
        "initial_profile_independently_proven": False,
        "inherited_descriptor_use_ordinals": sorted(set(inherited_uses)),
        "fd_events": fd_events, "mapping_events": mapping_events,
        "modeled_final_vmas": _regions(pages),
        "modeled_final_unmapped_ranges": [{"start": item["start"], "end": item["end"]}
            for item in _regions({address: {"prot": 0, "file_id": None, "offset": address}
                                  for address in known_unmapped})],
        "modeled_final_fds": [{"fd": fd, **value} for fd, value in sorted(descriptors.items())],
        "effect_checks": checks, "open_obligations": open_obligations,
        "kernel_implementation_verified": False,
        "all_relevant_effects_independently_observed": False,
        "oep_proof": "NOT_ESTABLISHED",
    }
