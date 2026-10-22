import json
from pathlib import Path

from taintforge_env.parser import load_taint_log


DATA_DIR = Path(__file__).parent / "data"


def test_parse_static_x86_fixture() -> None:
    taint = load_taint_log(
        DATA_DIR / "static.json"
    )

    assert taint.arch == "x86"
    assert taint.oep == "0x804ae0c"
    assert taint.base == "0x8048000"

    assert len(taint.regions) == 4
    assert taint.library_dependencies == []

    assert len(taint.network_events) == 2
    assert len(taint.network_dependencies) == 1

    socket_event = taint.network_events[0]
    assert socket_event.op == "socket"
    assert socket_event.fd == 3
    assert socket_event.domain == "AF_INET"
    assert socket_event.socket_type == "tcp"
    assert not socket_event.has_remote_endpoint()

    connect_event = taint.network_events[1]
    assert connect_event.op == "connect"
    assert connect_event.fd == 3
    assert connect_event.ip == "127.0.0.1"
    assert connect_event.port == 80
    assert connect_event.has_remote_endpoint()

    endpoint = taint.network_dependencies[0]
    assert endpoint.ip == "127.0.0.1"
    assert endpoint.port == 80
    assert endpoint.type == "tcp"

    tmp_dependency = next(
        dependency
        for dependency in taint.file_dependencies
        if dependency.path == "/tmp/testfile.txt"
    )
    assert tmp_dependency.write is True


def test_parse_dynamic_x86_fixture() -> None:
    taint = load_taint_log(
        DATA_DIR / "dynamic.json"
    )

    assert taint.arch == "x86"
    assert taint.oep == "0x4010fb"
    assert taint.base == "0x400000"

    assert len(taint.regions) == 11
    assert len(taint.library_dependencies) == 2

    loader = taint.library_dependencies[0]

    assert loader.name == "ld-linux.so.2"
    assert loader.path == "/lib/ld-linux.so.2"
    assert loader.observed_base == "0x40805000"
    assert loader.observed_size == 230584

    libc = taint.library_dependencies[1]

    assert libc.name == "libc.so.6"
    assert libc.path == "/usr/lib32/libc.so.6"
    assert libc.observed_base == "0x4088e000"
    assert libc.observed_size == 2179072

    assert len(taint.network_events) == 2
    assert len(taint.network_dependencies) == 1

    endpoint = taint.network_dependencies[0]

    assert endpoint.ip == "127.0.0.1"
    assert endpoint.port == 80
    assert endpoint.type == "tcp"

    tmp_dependency = next(
        dependency
        for dependency in taint.file_dependencies
        if dependency.path == "/tmp/testfile.txt"
    )
    assert tmp_dependency.write is True


def test_dynamic_fixture_library_addresses_are_observations(tmp_path: Path) -> None:
    # Preserve the original regression: observed library mappings need not be
    # the first/code mapping. The current fixture records whole-library ranges.
    raw = json.loads((DATA_DIR / "dynamic.json").read_text(encoding="utf-8"))
    raw["library_dependencies"][0].update(base="0x4083b000", size=9400)
    raw["library_dependencies"][1].update(base="0x40a9f000", size=12288)
    path = tmp_path / "partial_library_observations.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    taint = load_taint_log(path)

    loader = taint.library_dependencies[0]
    libc = taint.library_dependencies[1]

    assert loader.observed_base == "0x4083b000"
    assert loader.observed_size == 9400
    assert libc.observed_base == "0x40a9f000"
    assert libc.observed_size == 12288

    region_starts = {
        int(region.addr, 16)
        for region in taint.regions
    }

    assert int(loader.observed_base, 16) not in region_starts
    assert int(libc.observed_base, 16) in region_starts

    libc_code_region = next(
        region
        for region in taint.regions
        if region.addr == "0x4088e000"
    )

    assert int(libc_code_region.addr, 16) < int(
        libc.observed_base,
        16,
    )
