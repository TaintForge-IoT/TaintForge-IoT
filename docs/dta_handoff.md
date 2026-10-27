# Audited DTA corpus handoff

`python3 -B -m scripts.export_dta_handoff --analysis ANALYSIS --out NEW_OUTPUT`
reads an original, completed Stage 2 analysis directory without launching a guest,
solver, AFL process, privileged command or namespace. Keep its original absolute
paths: this version intentionally rejects relocated request bindings.

The audit verifies the immutable snapshot and runtime bundle, regenerates the
deterministic candidate plan, rechecks every case's input, request, namespace and
resource records, and applies the original Phase 1 diagnostic admission policy
to the actual stored artifacts. It parses every recorded trace again, repeats
the ordered novelty selection, and requires exact corpus membership and hashes.
An audit checks saved evidence consistency; it does not independently repeat
historical kernel measurements or authenticate the shared diagnostic channel.
Source ELF/seed files outside the analysis directory need not remain present:
the verified snapshot contains their bound copies.

The output is published only after all checks pass. `seeds/` contains only the
accepted binary inputs, ready for the teammate's existing corpus import API.
`manifest.json` binds the source evidence and records the limited audit scope.
`recapture-requests.json` retains every selected data-dependent branch occurrence
in the accepted runs, with its seed, snapshot, argv, file offsets and diagnostic
event identity. Sites whose opposite outcome was not observed are listed first.
These hints do not change the fuzzer or authorize solver execution.

The requests deliberately have no executable selector, instruction bytes, exact
instruction generation or IR origin. A DCFG source generation describes a basic
block. The logged branch occurrence counts all logged conditional events at its
PC; the native concolic occurrence starts after a modeled input read. They cannot
be substituted for each other. A later adapter must obtain a fresh exact IR
prefix, map the occurrence, validate the file read and x86 flags, solve, then
concretely verify prefix preservation and branch inversion. All current requests
remain `NEEDS_FRESH_IR_AND_FLAGS`, `dse_eligible=false`, `dse_status=NOT_RUN`.

The default site budget is 256, with an explicit maximum of 4096. Exceeding the
budget fails without publishing a partial output. The controlled four-branch
fixture can cover both outcomes already; zero unseen opposite outcomes is valid
and is not reported as new DSE coverage. Future requests still require recapture.
