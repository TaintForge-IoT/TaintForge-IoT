# DTA to isolated DSE corpus controller

`python3 -B -m scripts.run_dta_dse --help` describes the controller CLI.
It takes an original completed Stage 2 analysis directory, a corrected QEMU,
the matching Phase 1 plugin and flags receipt, and a new output directory.
The original analysis must retain its recorded absolute paths. Branch PCs,
file offsets, input path and guest arguments are derived from its audited
evidence; the CLI does not accept replacement selectors.

The controller regenerates the Stage 3 handoff from the original analysis,
including the deterministic candidate plan, saved runtime and snapshot
evidence, case receipts and accepted corpus. A separately supplied request
JSON or a rehashed request ID does not authorize execution. It selects hints
whose opposite branch outcome was not observed in that DTA corpus. Requests
beyond the job budget remain explicitly deferred.

Each selected hint supplies an accepted seed, target identity and diagnostic
site. The controller enumerates bounded native occurrences in fresh isolated
observe cases. DTA counts all logged conditional events at the PC per vCPU;
native concolic counts visits to the PC after its modeled input read. These
ordinals cannot be copied or inferred from the number of tainted DTA groups.
For example, a branch visited before and after the read can have DTA occurrence
2 and native occurrence 1.

A mapping requires a complete flags-verified native file/read prefix and a
unique matching group in the same fresh case's DTA trace. The selected sequence,
PC, outcome, successor, offsets and DCFG edge must agree. The native instruction
bytes, descriptor and generation remain fresh run-local evidence. DCFG source
generation describes a basic block and cannot replace instruction generation.
Historical diagnostic IDs are retained as hints rather than promoted to exact
historical instruction origins.

The mapped native occurrence is passed to the isolated Stage 5 solve worker.
Its baseline must match the freshly observed prefix and source bindings. A
solver witness is accepted only after another independent isolated concrete
run preserves the prefix and inverts the selected branch. The worker rechecks
its request, sources, flags, namespace separation, resource limits and empty
process-tree cleanup. The controller audits saved worker evidence again before
publishing a corpus.

Old and fresh runtime and snapshot identities remain distinct. The fresh
minimal file environment must match the original snapshot entry inventory and
metadata, except for the selected input's hash when using a different accepted
seed. An arbitrary historical environment is not silently replaced by the
minimal profile. This stage supports the existing static little-endian i386
ET_EXEC, one-file, one-read bounded DSE profile.

`seeds/` contains a deduplicated union of audited DTA seeds and newly verified
DSE candidates. Its manifest records which evidence admitted each input.
`summary.json` records jobs, mappings, outcomes and explicit budgets. Defaults
are four jobs, eight native occurrences per hint, a 128-step prefix, 256 handoff
sites, 30 CPU seconds per case and 1024 MiB per service. Bounded `UNKNOWN` or
`UNSAT` results add no new seed; completing a bounded controller run does not
mean every requested inversion was established.

No AFL campaign is launched or changed. A teammate can import the published
seed directory through the existing corpus interface. The controller keeps
the shared diagnostic/control channel, universal equivalence and historical
instruction originality claims unproved. Global Phase 1 partial statuses and
incomplete counters remain explicit; only the separately validated native
prefix is used. The successor callback establishes an observed boundary, while
`successor_execution_proven` remains false. Real namespace/cgroup acceptance
requires the intended host; unit simulations and direct native smoke runs do
not establish isolation.
