# TaintForge-IoT

TaintForge-IoT is a research project for unpacking and analyzing Linux programs
in a prepared environment. Phase 1 tracks unpacking and original entry point
(OEP) candidates. Phase 2 observes file and network access, identifies missing
dependencies, and plans environment changes. Fuzzing integration is still ahead.

The unified runner starts the original ELF under QEMU with the plugin active
from the first instruction. Execution continues in the same process within an
attempt, with no restart at OEP. An environment repair starts a new clean attempt.

## Requirements

- Linux x86-64 with glibc, namespaces, and `sudo` access. Use a dedicated VM
  for unknown samples: the current sandbox does not replace host isolation.
- Python 3.11+, GCC, binutils, pkg-config, GLib, Capstone, and Z3.
- **Dynamically linked `qemu-i386` with plugin support** and its matching
  `qemu-plugin.h`. Static QEMU is not supported by the unified runner.
- The Phase 1 runtime, DNS/UDP, and unified runner integration packages.
  If your checkout lacks `scripts/run_unified_pipeline.py`, install the
  integration packages first. The commands below require those changes.

On Arch Linux, install the dependencies, including test tools:

```bash
sudo pacman -S --needed base-devel python python-pytest \
  qemu-user qemu-common glib2 capstone z3 \
  sudo coreutils util-linux inetutils iproute2 iptables strace jq
```

Dynamic i386 ELF files need a compatible sysroot with a 32-bit loader and
libraries. For the `--dynamic-sysroot /` test below on Arch, install
[lib32-glibc](https://archlinux.org/packages/core/x86_64/lib32-glibc/):

```bash
sudo pacman -S --needed lib32-glibc
```

## Build the plugin

Run all remaining commands **from the repository root**. On Arch,
`/usr/include/qemu-plugin.h` comes from
[qemu-common](https://archlinux.org/packages/extra/x86_64/qemu-common/files/).
The installed `qemu-user` and `qemu-common` versions must match.

```bash
mkdir -p build &&
TF_QEMU_INCLUDE=/usr/include \
  bash unpacker/test/build_group7_4c1_plugin.sh \
    unpacker/test build/libtaintforge_ir.so &&
PYTHONPATH=. python3 scripts/run_unified_pipeline.py check-runtime \
  --qemu /usr/bin/qemu-i386 \
  --plugin "$PWD/build/libtaintforge_ir.so"
```

The build produces both the `.so` and its `.runtime.json`. Rebuild them after
changing the plugin sources or QEMU. `check-runtime` verifies the input files;
an actual QEMU run is needed to check plugin loading. Unit tests do not build
the QEMU plugin.

## First run: test_stat

```bash
tf_run_out="$PWD/workdir/test_stat_$(date +%Y%m%d_%H%M%S)"
sudo -v &&
PYTHONPATH=. python3 scripts/run_unified_pipeline.py run \
  --binary "$PWD/unpacker/test/test_stat" \
  --qemu /usr/bin/qemu-i386 \
  --plugin "$PWD/build/libtaintforge_ir.so" \
  --sysroot / --network none --timeout 60 --max-steps 1 \
  --target-spec "$PWD/examples/targets/test_stat_stdout.json" \
  --out "$tf_run_out"
```

This runs one attempt and collects its results. `test_stat` should print its
greeting and create `/tmp/testfile.txt` inside the guest rootfs. A failed
`connect` is expected with networking disabled. The supplied
target specification checks stdout and a successful `write`; check
`rootfs_diff` separately for file creation.

To run your own ELF, change `--binary` and remove the `test_stat` target
specification, or supply your own success criterion. `--sysroot` selects the
source of guest libraries. Each new run needs a fresh `--out` directory.

Read the results in the same terminal:

```bash
jq . "$tf_run_out/unified_report.json"
tf_run_dir="$(jq -er '.run_dir' "$tf_run_out/unified_report.json")" &&
cat "$tf_run_dir/report.md" &&
jq . "$tf_run_dir/config/rootfs_diff.json"
```

`unified_report.json` contains the overall outcome, guest exit status, Phase 1
verification, and finalization results. The detailed Phase 2 reports are
`report.md` and `report.json` under `run_dir`. That directory also contains
`logs/syscall_events.jsonl`, `logs/phase1/`,
`config/runtime_requirements.json`, and `config/repair_plan.json`.
An exit code of 0 or a reached target does not replace checking `phase1` and
`finalization`.

## Tests

Check the modules and artifact publication:

```bash
bash tests/run_phase1_tests.sh &&
PYTHONPATH=. python3 -m pytest -q
```

Run the static and dynamic i386 fixtures inside the sandbox:

```bash
sudo -v &&
PYTHONPATH=. python3 scripts/run_unified_local_e2e.py \
  --qemu /usr/bin/qemu-i386 \
  --plugin "$PWD/build/libtaintforge_ir.so" \
  --dynamic-sysroot / \
  --out "workdir/unified_e2e_$(date +%Y%m%d_%H%M%S)"
```

Omit `--dynamic-sysroot /` to test only the static fixtures.

Record TCP/UDP/DNS traffic, import it, and replay it after stopping the mock servers:

```bash
sudo -v &&
PYTHONPATH=. python3 scripts/run_dns_udp_replay_e2e.py \
  --sandbox --out "workdir/dns_udp_e2e_$(date +%Y%m%d_%H%M%S)"
```

The network test builds a static client for the host, so static libc is required.
The unified runner supports `none`, `controlled`, `record`, and `replay`.
The last three require `--network-policy`; replay also needs `--replay-store`.
Destinations must be explicitly allowed. DNS replies do not expand the policy.

## Limitations

- The unified profile supports **Linux i386, one process and one thread**.
  Static and dynamic ELF files work with suitable libraries; arbitrary firmware
  does not automatically get a working environment.
- `unpacked.bin` is a memory dump. Rebuilding a standalone ELF, including its
  dynamic headers and relocations, and restoring a process from a checkpoint
  are not implemented yet.
- `syscall_events.jsonl` describes the guest process, including its loader and
  libc. Calls are not yet attributed separately to the packer or payload.
- Networking is limited to IPv4 and supported exchanges. Generic UDP supports
  one request and one response; DNS supports UDP/TCP with fallback. There is no
  general model for multistep C2 protocols or TLS. Replay misses never contact
  an upstream server.
- Execution Capsule, strict analyzer memory isolation, a protected artifact
  channel, and state reset for fuzzing are still planned. `memory_isolation`
  remains `not_implemented` and `fuzzing_ready` remains `false`. Selecting an OEP
  candidate does not establish a proven starting point for fuzzing.

More details: [unified runner](docs/UNIFIED_PIPELINE_V1.md),
[Phase 1 contract](docs/PHASE1_RUNTIME_V1.md),
[networking and capture format](docs/NETWORK_DNS_UDP_V1.md).
