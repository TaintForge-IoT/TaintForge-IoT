# DTA/DSE phase profiling

The concolic JSON report includes a `phase_profile` object when processing
reaches replay input capture. It records monotonic wall-time intervals in
nanoseconds. A skipped or unavailable interval is `null`. Collector-only
reports retain their existing fields.

The prefix total encloses input capture, lifting, concrete replay, SSA and IR
optimization, branch catalogue construction, SMT encoding, query construction
and checking, and prefix or witness verification. `smt_query` includes
`query_constraints` and the Z3 checks. The per-check records reuse the timings
of `Z3_solver_check_assumptions` for the certain and possible passes. Use the
Python profiler in `scripts/profile_dta_dse.py` for the enclosing evaluator
and host stages.

## Reference experiment

The November 10, 2026 reference run used a pinned experimental i386 backend
with SSE128 replay, a 2048-instruction prefix limit, and one FIFO evaluation
per target. Each target used three baseline inputs and a budget of 16 DSE
starts. Candidate inputs passed concrete prefix validation and two full
guest reruns before contributing coverage.

| Target | Baseline inputs | Verified | Bounded UNSAT | Unknown | New parser branch outcomes |
| --- | --- | ---: | ---: | ---: | ---: |
| PicoHTTPParser, an HTTP request and response parser | GET, POST, Host | 16 | 0 | 0 | 20 |
| inih, an INI configuration parser | value, section, multiline | 5 | 11 | 0 | 6 |

Both runs matched the saved FIFO baselines for request inventory, job order,
results, and new branch outcomes. The report status was
`PASS_DSE_PHASE_PROFILE`.

| Wall time | PicoHTTPParser | inih |
| --- | ---: | ---: |
| Evaluator | 271.35 s | 261.65 s |
| Audit spans within the evaluator, exclusive | 190.78 s | 193.90 s |
| Guest cases within the evaluator | 44.78 s | 31.96 s |
| Native prefix analysis within guest cases | 304 ms | 372 ms |
| Z3 checks within native prefix analysis | 21 ms | 40 ms |
| Separate final audits | 121.13 s | 118.28 s |

Audits accounted for 72.2% of the measured evaluator wall time. Repeated
queue history audits before starts 2 through 16 accounted for 58.5 s on HTTP
and 63.1 s on INI. These numbers describe the profiled build and workloads.

The experiment delivery `taintforge_dse_phase_profile.zip` has SHA-256
`5a890ce87b69c390355422b837bfbdb61b8ccab0e64a97acddfefe3eb6a7c4e6`.
The saved report `dse_phase_profile_reports.zip` has SHA-256
`6124c63ff9c9ea6f967da31b37c36af8fddabe90afed637d72ab7aac53ed6230`.
