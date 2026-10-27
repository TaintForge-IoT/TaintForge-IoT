# Isolated file DSE analysis worker

`python3 -B -m scripts.run_dse_analysis --help` describes the worker CLI.
The `dse-file-analysis-v1` profile accepts one static little-endian i386 ET_EXEC,
one seed of 1–4096 bytes, its absolute guest file path, a selected branch PC and
occurrence, and 1–16 distinct increasing file offsets. The file must be an
ordinary non-executable resource with no hard-link aliases. A flags-validation
receipt is required. The branch PC accepts decimal or `0x` hexadecimal notation.
Occurrence counts visits to that PC after the modeled input read. It is not
interchangeable with a DTA diagnostic occurrence counted across the entire run.

The target runs as `/bin/sample.elf`. Up to 32 guest arguments are passed
literally, without a shell or placeholder expansion. The input path is not
automatically added to the arguments. Defaults are occurrence 1, a 128-step
bounded prefix, 30 CPU seconds per case and 1024 MiB per service. The output
directory must be new and independent of all input files.

The selected QEMU and Phase 1 plugin need matching plugin APIs and verified
build metadata. The host requires sudo, systemd, cgroup v2 and mount/PID/network/
UTS/IPC namespace support. Authenticate sudo from the invoking terminal before
launching the CLI. The worker does not fall back to an unisolated execution.

The kernel directly executes the bundled QEMU. Its supported ELF interpreter
is bound read-only at the required chroot path; the fixed analyzer library
directory supplies its shared libraries. The host-only library environment is
removed from the emulated guest. `/proc/self/exe` therefore identifies QEMU,
which lets the native flags checker verify the receipt against the actual
executing binary. The receipt is copied verbatim and bound read-only; it is
never rewritten to describe the loader. The executable and input file also
receive read-only bind mounts for these cases.
The input cannot occupy analyzer-control or native loader-control paths; this
profile rejects guest preload/cache files that could alter analyzer startup.

The worker provisions the executable and original file bytes once, captures an
immutable environment snapshot, and builds the analyzer runtime bundle. Its
solve case starts from a fresh clone of that snapshot and runs the file-backed
concolic adapter. Only the selected offsets may be assigned by the model. A
`BOUNDARY_WITNESS` is a proposal: the worker validates its file/read identity and
bounded prefix, materializes the candidate bytes, then starts an independent
observe case from another clone of the original snapshot. The observe case gets
the candidate file directly; it does not resume a checkpoint or reuse the solve
case's filesystem. No AFL campaign, retirement or warm checkpoint is involved.

Each case uses a chroot, UID/GID 65534, cleared capabilities, NoNewPrivs, a
read-only analyzer runtime, CPU and file-size limits, a native analysis
allocation budget, and systemd memory/task/lifetime limits. The worker checks
saved resource, namespace and service evidence, including empty process-tree
cleanup. It binds the receipts and native reports to the executable, exact file
bytes, flags receipt and original snapshot, and rechecks source identities.
Normal guest exits 0–127 are supported; signal and resource-limit stops fail the
case. The target executable and selected input must retain their supplied bytes.

`summary.json` preserves the explicit `dse_status`:

| DSE status | Meaning | Accepted seed |
| --- | --- | --- |
| `VERIFIED` | The concrete rerun preserved the validated prefix and inverted the selected branch. | Published only after all evidence is rechecked. |
| `UNSAT` | The selected bounded model had no witness, with its observed prefix validated. | None. |
| `UNKNOWN` | The adapter could not establish a witness or the required verification did not complete. | None. |

`UNSAT` does not establish unreachability outside the selected file bytes and
bounded model. `UNKNOWN` is not success at branch inversion. Consumers must
require both `status: passed` and `dse_status: VERIFIED`, together with the bound
evidence, before importing a seed from `accepted-seeds/`. A passed execution
receipt alone never authorizes candidate publication.

The global Phase 1 trace can remain `partial`, for example when the final exit
instruction has no following callback. Those statuses and incomplete counters
are retained. Only the separately exported native concolic prefix is admitted
by the existing complete file/read and instruction-route validators. No claim
of whole-run IR completeness follows from a verified selected inversion.
The successor callback establishes an observed instruction boundary;
`successor_execution_proven` remains false.

Successful inversion proves one observed edge change for this concrete rerun.
It does not establish complete CFG recovery, universal equivalence, historical
payload/OEP origins, a protected control channel, or hostile-sample readiness.
The report keeps `protected_control_channel` and `universal_equivalence` false.
The isolated-adapter claim requires verified evidence from both cases. Dynamic
ELF dependencies, stdin, networking and additional mutable resources require a
separate profile.
