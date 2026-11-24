# TaintForge-IoT

TaintForge-IoT analyzes standalone packed Linux ELF binaries when the original IoT firmware and network services are unavailable. It reconstructs enough of the environment to run the unpacked code under AFL++.

## Current MVP

The end-to-end demos use bundled, statically linked Linux/i386 programs.

1. **Unpacking.** A QEMU user-mode plugin tracks execution of newly written code, identifies a candidate original entry point (OEP), and exports a memory dump and JSON report.
2. **Environment reconstruction.** Phase 2 builds a minimal root filesystem from observed dependencies and retries execution after repairs. The network emulator supports stateful TCP sessions and offline TCP, UDP and DNS replay.
3. **Fuzzing.** The execution capsule resumes the guest after the unpacker unloads. AFL++ reuses the prepared state across file inputs. Hybrid mode uses dynamic taint analysis to find input bytes that influence branches and dynamic symbolic execution to generate new seeds.

## Quick start

Use Bash on x86-64 Linux with Git, Python 3.12 and GCC. Run the examples from the repository root in the same shell.

```bash
git clone https://github.com/TaintForge-IoT/TaintForge-IoT.git
cd TaintForge-IoT
export PYTHONPATH="$PWD"
run_dir="$(mktemp -d "$HOME/tf.XXXXXX")"
```

**Phase 1 and the full pipeline** use a patched QEMU 11.0.1 and matching plugin. Build them once with binutils, Ninja, pkg-config and the GLib, Capstone and Z3 development libraries. Source `environment.sh` in each new shell.

```bash
bash scripts/build_afl_dse_runtime.sh
source "$HOME/.local/opt/taintforge/qemu-11.0.1-warm-v3/share/taintforge/environment.sh"
```

### Phase 1 only — unpack an ELF

Unpack the bundled UPX-packed `jsmn` parser using its empty-stdin regression case.

```bash
printf '%s\n' '[{"id":"recorded-input"}]' > "$run_dir/jsmn-cases.json"
python3 -m unpacker.unpack unpacker/mvp/corpus/jsmn.upx \
  --cases "$run_dir/jsmn-cases.json" --qemu "$TF_WARM_QEMU" \
  --plugin "$TF_PHASE1_PLUGIN" --output "$run_dir/phase1"
```

The reconstructed ELF is `$run_dir/phase1/rebuilt.elf`. On success, `$run_dir/phase1/summary.json` records the selected entry address and `"all_selected_cases_match": true` for the supplied input.

### Phase 2 only — reconstruct the environment and replay traffic

These examples run as a regular user. The TCP client needs GCC with static libc.

```bash
python3 -m scripts.reconstruct_env --taint examples/mock.json --out "$run_dir/env"
python3 -m scripts.run_c2_replay_local_e2e --out "$run_dir/replay"
```

Inspect `$run_dir/env/rootfs` for the generated filesystem. The replay demo returns `world` after the original TCP server stops and writes `"status": "passed"` to `$run_dir/replay/report.json`.

With `sudo`, iproute2 and network namespaces, the same client can run inside the prepared root filesystem.

```bash
sudo -v
python3 -m scripts.run_c2_replay_local_e2e --sandbox --out "$run_dir/replay-guest"
```

### Full pipeline — Phase 1, Phase 2 and AFL++

Use a development VM with `sudo`, mount/PID/network namespaces, systemd, cgroup v2 and `afl-fuzz` on `PATH`. The demo builds its own i386 ELF and invokes `scripts.run_afl_file campaign`. Phase 1 runs once, AFL++ reuses the guest state, and Phase 2 records each child execution.

```bash
sudo -v
python3 -m scripts.verify_afl_phase2_e2e --qemu "$TF_WARM_QEMU" --out "$run_dir/full"
```

In `$run_dir/full/acceptance.json`, look for `"status": "passed"`, `"phase1_runs": 1` and a `phase2_cases` count equal to `children`.

For hybrid fuzzing on the bundled prefix parser, run this on the same VM.

```bash
python3 -m experiments.hybrid_prefix_v1.run --mode hybrid --out "$run_dir/hybrid"
```

On success, `$run_dir/hybrid/acceptance.json` reports `passed_fixed_fixture_live_hybrid`. The warm campaign runs Phase 1 once. The taint and symbolic analyses use additional executions. [Hybrid demo and result files](experiments/hybrid_prefix_v1/README.md)

## Next steps

- Harden host isolation and verify cleanup after interrupted runs.
- Expand the test corpus and compare plain AFL++ with hybrid mode using the same seeds and time budget.
- Validate the full pipeline on ARM and MIPS Linux targets.
