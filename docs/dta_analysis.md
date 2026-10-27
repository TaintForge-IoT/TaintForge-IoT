# Isolated file DTA analysis worker

`python3 -B -m scripts.run_dta_analysis --help` describes the worker CLI.
The first profile accepts one static little-endian i386 ET_EXEC, one seed of
1–4096 bytes, its absolute guest file path, and up to 32 explicit guest arguments.
The target runs as `/bin/sample.elf`; arguments are passed literally, without a
shell or automatic placeholder expansion. An input path is not automatically an
argument. Supply it through `--arg` when the program expects a filename.

The selected QEMU and Phase 1 plugin must have matching plugin APIs and verified
build metadata. The host needs the same sudo, systemd, cgroup v2 and namespace
support used by the warm-fuzzer host checks. Authenticate sudo from the invoking
terminal before launching this CLI. There is no direct-QEMU fallback.

The worker provisions the original ELF and file seed once, captures an immutable
environment snapshot, and builds the existing analyzer runtime bundle. Every
analysis case uses a fresh snapshot clone. The program runs through its input
processing with DTA active; no retirement, warm checkpoint, AFL process or solver
is started by this worker.

Each case uses mount/PID/network/UTS/IPC namespaces, a chroot, a read-only analyzer
runtime, UID/GID 65534, cleared capabilities, NoNewPrivs, a systemd memory/task
limit, native analysis allocation budget, CPU limit and file-size limits. Runtime
namespace IDs and cgroup settings are checked, and service cleanup must confirm
an empty cgroup. The aggregate diagnostic size is checked after execution; the
per-file kernel limit applies during execution. No disk quota or protected
diagnostic channel is claimed.

The native global analysis can remain `partial` when flags are unverified or an
ordinary ELF has no OEP image to capture. The worker preserves those statuses.
It accepts only its narrower DTA diagnostic scope: complete artifact storage,
the supported runtime profile, no lost events, no lost trace/shadow knowledge,
and no unexpected runtime error. An empty OEP image is irrelevant to this corpus
operation. DSE/SMT/OEP proof status is never promoted by this admission policy.

Two baseline executions must agree on the observed input-dependent branch
outcomes and exit status. The existing offline corpus generator then proposes
candidates. Each candidate runs in another fresh capsule. The accepted corpus
contains the baseline plus candidates adding observed `(PC, outcome)` pairs.
These diagnostic observations are not an AFL coverage bitmap or a whole-program
equivalence proof. They also do not prove historical payload/OEP origins.

The new output directory contains `summary.json`, `runtime/`, `snapshots/`,
`baseline/`, `repeat/`, `corpus/`, `replays/` and, only after successful validation,
`accepted-seeds/`. Each case has a request binding, input copy, trace, stdout,
Phase 1 artifacts, resource/namespace evidence and `receipt.json`.

Consumers must require `summary.json` status `passed` before importing accepted
seeds. Failure records remain available for diagnosis and do not authorize seed
publication. Normal target exits 0–127 are supported; signal/resource stops fail
this first profile. The target executable and selected input must retain their
initial contents within each case. A target that modifies either resource needs
a separate explicit profile. Stdin, networking, extra environment resources and
dynamic ELF dependencies are outside this first worker profile.

The teammate can consume `accepted-seeds/` using the existing corpus import API.
Future DSE jobs should select sites from these runs, obtain exact instruction/IR
origins through a dedicated export, solve the selected predicate, and pass the
existing concrete rerun checks before the new input is treated as verified.
