# Fixed prefix parser: AFL and hybrid modes

This experiment connects the existing isolated DTA/DSE adapters and warm AFL
transport for one bundled, harmless i386 parser. There is no external target
argument. One DSE job is admitted per run.

The `hybrid` mode runs this automatic sequence:

1. Build the bundled ELF and an additional Phase 1 plugin.
2. Run DTA and audit its handoff. Derive the input-offset mask from observed sites.
3. Start one warm campaign with a C custom-mutator adapter.
4. For each mutation, change one bit at an offset in the current DTA mask.
5. Bind the returned bytes to a completed case and the bitmap delivered to AFL.
6. After consecutive mutations without new bitmap hitcount buckets, invoke DSE.
7. Audit the fresh DSE job and its concrete rerun, then return its input through
   the custom callback of the same live AFL process.
8. Verify that input's execution and fresh coverage, repeat DTA for the new path,
   and update the mutation mask.
9. After shutdown, independently verify capsule completion, per-child Phase 2
   evidence, the single ELF identity, and the DSE input in AFL's own queue.

The experiment entry point is `python3 -B -u -m experiments.hybrid_prefix_v1.run`.
It accepts `--mode afl|hybrid`, `--out`, `--qemu`, `--qemu-include`,
`--flags-receipt`, `--afl-bin`, `--seconds`, `--executions`, and `--stall-cases`.
`hybrid` is the default for compatibility with earlier runs. Runtime paths default to the
variables exported by the installed `environment.sh`. `--out` must be new and
short enough for Unix-domain sockets. Default limits are 128 AFL executions,
600 AFL seconds, and a plateau threshold of 16 delivered mutations.

In `afl` mode the same bundled ELF, warm QEMU transport, and Phase 1 setup
run with stock AFL mutations from one initial seed. DTA, DSE, the masked
mutator, and the plateau controller do not start. This mode records
`passed_fixed_fixture_afl_only` only after completing the campaign and
verifying the case and capsule evidence; its report explicitly records
`DTA_executed=false`, `DSE_executed=false`, and
`automatic_cycle_verified=false`. `--stall-cases` applies only to `hybrid`.
Both modes retain the bundled ELF restriction and reject an external binary.

Use `python3 -B -m experiments.hybrid_prefix_v1.tests` for local checks. Those
checks exercise a compiled C adapter over a real socketpair, with synthetic
case receipts and substitute DTA/DSE workers. They also compile the initial
page callback, check the file-prefix validator, and test mutation and coverage
rules. They do not establish actual QEMU/AFL/DSE acceptance.

## Runtime changes

The installed QEMU and plugin are preserved. The experiment copies the current
Phase 1 sources under the output directory and builds another plugin using the
matching installed QEMU header. The copy receives two guarded edits:

- Register initial page permissions from the already validated PT_LOAD records
  before any guest STORE. ELF PF flags are converted to Linux PROT bits. Overlap,
  unsupported page sizes, address overflow and more than 4096 pages are refused.
- Accept one successful, aligned i386 mprotect as the first concrete file-prefix
  syscall. Record it alongside open/read and compare its arguments and result
  across the fresh observation, solve and concrete rerun.

The Python file-prefix validator receives the matching narrow mprotect rule.
The bundled ELF uses this startup call in all three stages. It also provides a
pre-checkpoint syscall observation required by the existing M5 admission check.
The existing input-before-retirement barrier, M5 admission and resource checks
remain active.

`campaign_Phase1_runs=1` applies to the live warm campaign. DTA and DSE workers
perform additional fresh analysis executions outside that campaign.

## Evidence and limits

`acceptance.json` is successful only after real runtime checks. `events.jsonl`
records causal ordering in `hybrid` mode. `hybrid-result.json` binds the DSE trigger, returned
input, executed case and updated mask. `campaign/afl/default/queue` supplies the
separate queue-membership evidence. `runtime/build.log`, `initial-dta.log`,
`prepare.log`, `campaign.log`, and `failure.log` retain failure details.

The plateau metric uses hitcount classes of the actual post-input guest bitmap
delivered to AFL. It does not read AFL's private queue accounting and inherits
bitmap collisions. The mutator deliberately uses a bounded single-bit schedule
to make a DSE handoff reproducible on this parser; it is not a general mutation
strategy. The test-only RWX payload segment is retained. Success covers this
one parser, one DSE job, and one refreshed mask; it does not establish readiness
for hostile samples or arbitrary ELF inputs.

The C adapter uses AFL++'s documented custom-mutator interface:
https://aflplus.plus/docs/custom_mutators/ . The returned buffer stays owned by
the adapter, input length is fixed at 32 bytes, and trimming/splicing are disabled.
