from pathlib import Path
import struct

from experiments.execution_capsule_probe import controller as p
from taintforge_env.input_retirement import inspect_input

HERE = Path(__file__).resolve().parent
CASES = {
    "normal": {"source": "guest.S", "base": 0x08048000, "defines": (0, 0, 0),
               "exits": [0], "stdout": "M3_INPUT_OK\n"},
    "repair": {"source": "guest.S", "base": 0x08048000, "defines": (1, 0, 0),
               "exits": [42, 0], "stdout": "M3_INPUT_OK\n"},
    "relocated-branch": {"source": "branch.S", "base": 0x09000000,
                         "exits": [0], "stdout": "M3_BRANCH_OK\n"},
    "page-offset": {"source": "offset.S", "base": 0x0b000000,
                    "exits": [0], "stdout": "M3_OFFSET_OK\n"},
    "missing-verdict": {"source": "guest.S", "base": 0x08048000, "defines": (0, 1, 0),
                        "exits": [89], "stdout": None},
    "fork-after": {"source": "guest.S", "base": 0x08048000, "defines": (0, 0, 1),
                   "exits": [126], "stdout": None},
}


def is_stripped(path):
    data = Path(path).read_bytes()
    p.require(len(data) >= 52 and data[:6] == b"\x7fELF\x01\x01", "Expected little-endian ELF32")
    offset = struct.unpack_from("<I", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 46)
    p.require(size >= 40 and count > 0 and offset + size * count <= len(data),
              "Invalid ELF section table")
    return not any(struct.unpack_from("<I", data, offset + i * size + 4)[0] in (2, 11)
                   for i in range(count))


def build_guests(directory):
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=False)
    guests = {}
    for name, case in CASES.items():
        source = HERE / case["source"]
        obj, binary = directory / (name + ".o"), directory / name
        flags = []
        for key, value in zip(("NEED_DIRECTORY", "NO_VERDICT", "FORK_AFTER"), case.get("defines", ())):
            flags += ["--defsym", f"{key}={value}"]
        p.command("as", "--32", *flags, source, "-o", obj)
        p.command("ld", "-m", "elf_i386", "-Ttext-segment=" + hex(case["base"]),
                  "-z", "noexecstack", "--build-id=none", obj, "-o", binary)
        symbol = "payload_entry" if case["source"] != "guest.S" else "payload_page"
        expected = [int(line.split()[2], 16) for line in p.command("nm", "-P", binary).splitlines()
                    if line.startswith(symbol + " ")]
        p.require(len(expected) == 1, "Missing guest oracle: " + name)
        p.command("strip", "--strip-all", binary)
        p.require(is_stripped(binary), "Guest retains a symbol table: " + name)
        guests[name] = {"path": str(binary), "input": inspect_input(binary), "stripped": True,
                        "expected_oep": expected[0] if name != "missing-verdict" else None,
                        "expected_stdout": case["stdout"], "expected_exits": case["exits"],
                        "source": case["source"], "source_sha256": p.sha(source),
                        "load_base": case["base"]}
    positive = [guests[name] for name in ("normal", "relocated-branch", "page-offset")]
    p.require(len({g["input"]["entry_point"] for g in positive}) == 3 and
              len({g["expected_oep"] for g in positive}) == 3 and
              len({g["source_sha256"] for g in positive}) == 3,
              "M3 guests must cover three source bodies and address layouts")
    p.write_json(directory / "build.json", {"schema": 1, "matrix_version": 2, "guests": guests})
    return guests
