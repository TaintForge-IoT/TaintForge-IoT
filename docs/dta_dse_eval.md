# File DTA/DSE measurement

`python3 -B -m scripts.evaluate_dta_dse --help` describes a fresh evaluation of
one target and one guest-file launch profile. Supply one to four distinct seed
files, each 1–64 bytes, and the calibrated project QEMU, plugin and flags
receipt. Existing queue/controller behavior is unchanged.

The evaluator captures DTA and palette mutations for every seed, audits their
original evidence, then admits all compatible sources to a persistent queue.
It processes one job at a time, retaining UNKNOWN, UNSAT and unstarted tasks.
The start budget is explicit; total wall time is a soft limit checked between
operations. Native worker CPU, memory, occurrence and instruction budgets
remain enforced by the isolated worker. Native evidence cannot be inferred
from elapsed time or from a free queue lock.

Every DSE candidate is run twice to normal guest exit through fresh isolated
DTA launches, with no additional mutations. Both runs must have identical
diagnostic branch-outcome sets, stdout and exit status. Both must retain each
job's selected branch PC, diagnostic occurrence, source offsets and desired
outcome. Saved source and replay snapshots must retain every resource other
than the selected input bytes, including dependency libraries. Full DTA
evidence and the original queue are reaudited before final
corpus publication. The final `seeds` directory contains the original audited
DTA seeds and candidates that passed these extra full-run checks.

`summary.json` records source identities, all timings, per-job reasons,
validated candidates and new outcomes relative to the union of every original
DTA run. `jobs.csv` provides a compact job table. Full saved worker summaries
and native reports remain at their original paths in the queue. Reason strings
are diagnostics from those audited reports, not independently proved causes.
Per-job new-outcome counts each use the complete original DTA union as their
reference and can overlap. Use the summary's deduplicated outcome list rather
than adding the job counts.

`COMPLETED_BOUNDED_DTA_DSE_EVALUATION` means the measurement completed.
Its separate `gain_status` is `VERIFIED_NEW_FULL_RUN_OUTCOMES` only if at least
one verified inversion and a new diagnostic PC/outcome pair survived full
repeated execution. `NONPROOF_NO_NEW_FULL_RUN_OUTCOMES` records a completed
measurement with no such improvement. Pending work remains in the original
queue and is reported separately. The CLI exits 0 for either completed
measurement and 1 on an error; an acceptance harness must inspect gain status
and its own domain criteria, not interpret exit 0 as a successful inversion.

Only complete file-data-root diagnostic PC/outcome pairs are counted. These
are not all machine branches, AFL coverage or source line coverage. The test
does not prove parser correctness, universal input equivalence, protected
control-channel integrity or historical instruction identity. It does not
execute AFL or alter the teammate's fuzzer integration.
