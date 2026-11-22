# TaintForge-IoT

TaintForge-IoT analyzes standalone packed Linux ELF binaries when the original IoT firmware and network services are unavailable. It reconstructs enough of the environment to run the unpacked code under AFL++.

## Current MVP

The end-to-end demo uses a bundled, statically linked Linux/i386 parser.

1. **Unpacking.** A QEMU user-mode plugin tracks execution of newly written code, identifies a candidate original entry point (OEP), and exports a memory dump and JSON report.
2. **Environment reconstruction.** Phase 2 builds a minimal root filesystem from observed dependencies and retries execution after repairs. The network emulator supports stateful TCP sessions and offline TCP, UDP and DNS replay.
3. **Fuzzing.** The execution capsule resumes the guest after the unpacker unloads. AFL++ reuses the prepared state across file inputs. Hybrid mode uses dynamic taint analysis to find input bytes that influence branches and dynamic symbolic execution to generate new seeds.

## Quick start

These two Phase 2 examples run as a regular user on x86-64 Linux with Python 3.12, GCC and static libc.

```bash
git clone https://github.com/TaintForge-IoT/TaintForge-IoT.git
cd TaintForge-IoT
run_dir="$(mktemp -d)"
python3 -m scripts.reconstruct_env --taint examples/mock.json --out "$run_dir/env"
python3 -m scripts.run_c2_replay_local_e2e --out "$run_dir/replay"
```

Inspect `$run_dir/env/rootfs` for the filesystem generated from the sample trace. The replay demo returns `world` after the original TCP server stops and writes `"status": "passed"` to `$run_dir/replay/report.json`.

### Run the i386 fuzzing demo

Use an x86-64 Linux development VM with `sudo`, systemd, cgroup v2 and AFL++ (`afl-fuzz` on `PATH`). Build the patched QEMU 11.0.1 once, using GCC, binutils, Ninja, pkg-config and the development libraries for GLib, Capstone and Z3.

```bash
bash scripts/build_afl_dse_runtime.sh
source "$HOME/.local/opt/taintforge/qemu-11.0.1-warm-v3/share/taintforge/environment.sh"
warm_dir="$(mktemp -d "$HOME/tf.XXXXXX")"
python3 -m experiments.hybrid_prefix_v1.run --mode afl --out "$warm_dir/run"
```

Check `$warm_dir/run/acceptance.json` for `"status": "passed_fixed_fixture_afl_only"` and `"campaign_Phase1_runs": 1`. [Hybrid mode and result files](experiments/hybrid_prefix_v1/README.md)

## Next steps

- Harden host isolation and verify cleanup after interrupted runs.
- Expand the test corpus and compare plain AFL++ with hybrid mode using the same seeds and time budget.
- Validate the full pipeline on ARM and MIPS Linux targets.
