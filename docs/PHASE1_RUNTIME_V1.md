# Phase 1 runtime integration, delivery I

This implementation is based on `d7a8176a774a375ab8ab5b8e166b0622d0733bf1`.
It supplies the initial runtime/artifact/event interface. It does **not** claim
completion of the strict memory or isolation acceptance requirements.

## Delivered

- The existing `unpacker/test/build_group7_4c1_plugin.sh` remains the only source
  list. It builds the new IO adapter and emits `<plugin>.runtime.json` with the
  source/header/compiler/flags fingerprint, plugin digest and compiled profile.
- The launcher selects the explicit plugin or `build/libtaintforge_ir.so` and
  requires its matching sidecar. A missing explicit plugin or invalid manifest
  cannot fall back to another `.so`. An explicit QEMU source/header takes
  precedence over the system header.
- `Phase1Run` accepts the controller's session, attempt and analysis-instance
  identity. Each output is explicit, distinct and exclusive. IDs are scoped to
  that instance; a candidate ID alone is not globally meaningful.
- Live JSONL reports startup capabilities, actual vCPU/instruction callbacks,
  candidate observation/evaluation/selection/invalidation, code-generation
  changes, analysis limitations, export status, data loss and termination.
- Candidate observation sequence and generation are separate from selection
  sequence. Selection does not rewind PC. Post-selection tracking continues.
  Writes to executed code invalidate previous candidates conservatively.
- Binary extents and region metadata come from the **same reads**. Each extent
  carries its actual offset, size and SHA-256. Inaccessible/budget-limited
  ranges are gaps. Success means the selected tracked pages were saved; it does
  not mean the complete process was captured.
- All dump/report writes check opening, byte count, stream state, flush, fsync
  and close. An immutable capture manifest is published only after the streams
  close successfully. Partial files never constitute a committed capture.
- The Python consumer verifies build identity, hashes, event ordering and
  identities, region extents and stream completion. Guest stdout is never
  parsed as analysis evidence. `require_protected_channel=True` is rejected.
- Unsupported process/thread transitions stop further collector mutation and
  invalidate the analysis guarantee. The first profile is i386 linux-user,
  one process and one vCPU. A failed fork/exec request conservatively loses
  this guarantee as well; failure does not restore it automatically.

## Build

Dependencies: GCC, Python 3.11+, pkg-config, GLib, Capstone, Z3 and the exact
plugin header belonging to the QEMU executable to be used. QEMU 10.2.0 exposes
plugin API 5. Header identity is recorded; loading still needs a real check.

From the repository root, with a QEMU source tree at `~/qemu`:

```bash
mkdir -p build
TF_QEMU_INCLUDE="$HOME/qemu/include/qemu" \
  bash unpacker/test/build_group7_4c1_plugin.sh \
  unpacker/test build/libtaintforge_ir.so
bash tests/run_phase1_tests.sh
TF_PHASE1_SANITIZE=1 bash tests/run_phase1_tests.sh
```

Older QEMU trees may place the header in `include/`; set `TF_QEMU_INCLUDE` to
the directory that actually contains the matching `qemu-plugin.h`.

The package installer preserves extra sources already present in the recipe,
including the 7.4f.2 branch-inversion sources. It does not install or replace
the user's 7.4f.2/7.4f.3 implementation.

## Real execution acceptance

The validation command builds only the bundled benign assembly fixture. The
fixture copies and rewrites its own small payload, preserves a stack marker,
and prints a deliberately fake JSON event to guest stdout. No arbitrary
sample is accepted by this validation command.

```bash
PYTHONPATH=. python3 scripts/validate_phase1_runtime.py \
  --plugin build/libtaintforge_ir.so \
  --qemu "$HOME/qemu/build/qemu-i386" \
  --out workdir/phase1-runtime-validation
```

Use a fresh output directory for every validation. The tests cover two
simultaneous attempts, live selection before exit, repeated PC after code
rewrite, exact region hashes, event and capture budgets, required EFLAGS,
fork, SIGKILL, changed artifacts and incorrect region offsets.

The existing launcher now accepts `--phase1-only`. It writes `run_binding.json`
before execution and `runtime_evidence.json` after verification. Its normal
Phase 2 path still restarts the original ELF. The single natural execution in
Phase 1 continues after OEP selection; this is not a cross-process handoff.

## Outputs and interpretation

| Output | Interpretation |
| --- | --- |
| `events.jsonl` | Live, ordered observations scoped to one analysis instance |
| `ir_runtime.jsonl` | Existing IR diagnostics; linked through the capture manifest, not a new IR ABI |
| `unpacked.bin` | Concatenated captured tracked-program extents |
| `unpacked.json` | Actual extents, gaps, candidate history and dependencies |
| `capture_manifest.json` | Commit marker and hashes after successful stream closure |
| `run_binding.json` | Controller-side sample/QEMU/runtime identity before execution |
| `runtime_evidence.json` | Verification outcome; separate analysis, storage and capture status |

`checkpoint_id` is null. The capture ID identifies an export, not a paused or
restorable guest state. `capture_pc`/`trace_seq` refer to the last observed
pre-instruction callback; they are not asserted to be final architectural PC.
`capture_consistency=best_effort_no_backend_safepoint` remains explicit.

`IR MATCH` is limited to the selected trace window. `runtime_observed` and
`artifact_integrity=verified` do not establish OEP correctness, input
controllability, payload stability, process checkpoint or fuzzing readiness.

Arbitrary byte strings are represented by a UTF-8 field when valid, otherwise
by null plus `<field>_bytes_base64`. The legacy collector still filters the
paths it records; delivery I does not claim complete syscall/path coverage.

## Remaining integration dependencies

1. **Dynamic-QEMU execution backend.** The current Phase 2 prebuilt runner
   insists on static QEMU. QEMU 10.2.0 `configure` rejects `--static` together
   with `--enable-plugins`. A new backend must explicitly provision dynamic
   QEMU, its host loader/dependencies and the plugin in the controlled
   execution environment. This implementation rejects static QEMU; it does
   not silently run the guest without instrumentation.
2. **Protected service channel.** Output paths/FDs in a linux-user process do
   not isolate analyzer files or descriptors from a hostile guest. This
   transport reports `control_channel_protection=unverified`. Hash verification
   detects corruption relative to the recorded manifest, not an attacker who
   can forge the entire channel. Strict evidence acceptance remains blocked.
3. **Nonblocking backend transport.** Events are bounded, flushed regular-file
   records, so there is no pipe-reader backpressure. Host storage IO is
   synchronous and its latency is not bounded. A strict nonblocking callback
   transport is still a backend integration task.
4. **Deliveries II/III.** No cooperative safe point, complete mapping registry,
   process capsule, external memory update protocol, portable provenance
   snapshot, detach protocol or Residue Oracle is implemented here. These
   capabilities are explicitly unsupported.
5. **Full collector resource bounds.** Event records, event count, candidate
   count and dump bytes have limits. Existing global trace/metadata/page and
   dependency storage retain their original policies. A bounded export is not
   a proof that every allocation in the analyzer is bounded.

The EFLAGS extension is never fabricated. Stock QEMU reports unverified flags;
`tf-require-flags=on` refuses that combination. With flags optional, affected
IR/DSE guarantees remain unavailable and appear in public diagnostics.

## Validation scope

The package includes a validation record with exact source and artifact
identities. Native IO error tests and their ASan/UBSan run cover the new IO
adapter. QEMU execution tests use stock QEMU 10.2.0 and Capstone 5. They do not
replace the user's complete 7.4f.2 test suite or a privileged acceptance run
of the future dynamic-QEMU Phase 2 backend.
