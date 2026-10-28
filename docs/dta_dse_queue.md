# Durable DTA to isolated DSE queue

`python3 -B -m scripts.run_dta_dse_queue --help` describes the queue CLI. The
queue schedules one audited DTA recapture request per job. The existing
controller still establishes the fresh native occurrence, invokes the isolated
worker and requires a separate concrete rerun before accepting a candidate.
A stored diagnostic occurrence never becomes an executable IR selector.

The queue supports several completed DTA analyses for one target, guest argument
list, input path and compatible environment. Input data may differ; unrelated
environment resources and the target must retain their bound identities.
Admission regenerates and audits each analysis's handoff. Re-enqueuing the same
source request does not create another job. Seed bytes are deduplicated by
SHA256 inside that queue's target/launch scope.

## Create and populate a queue

Use the calibrated project runtime and retain its build attempt and flags
receipt. These commands use the successful runtime and DTA analysis from the
controlled host check:

```bash
cd -- "$HOME/project/mine/iotproject/TaintForge-IoT"
source "$HOME/Downloads/tfr.W6ekJ4BW/probe/runtime/share/taintforge/environment.sh"

tf_queue_root=$(mktemp -d "$HOME/Downloads/tfdq.XXXXXXXX")
tf_queue="$tf_queue_root/queue"

python3 -B -m scripts.run_dta_dse_queue init \
    --queue "$tf_queue" \
    --qemu "$TF_OBSERVER_QEMU" \
    --plugin "$TF_PHASE1_PLUGIN" \
    --flags-receipt "$TF_X86_FLAGS_RECEIPT"

python3 -B -m scripts.run_dta_dse_queue enqueue \
    --queue "$tf_queue" \
    --analysis "$HOME/Downloads/tfda.vn3dSVDo/probe/evaluation/analysis"

python3 -B -m scripts.run_dta_dse_queue status --queue "$tf_queue"
```

Repeat `--analysis` to admit several analyses in one command, up to 64 source
analyses per queue. Original evidence
must remain at its recorded absolute paths. An externally supplied request JSON
does not authorize a job. Queue identities bind audited source requests, the
exact runtime, policy and the project Python source inventory. The latter
includes `taintforge_env/*.py` and the execution-capsule probe modules. Changing
those bindings requires a new queue rather than silently resetting an existing
one.

## Process and resume

```bash
sudo -v

python3 -B -m scripts.run_dta_dse_queue run \
    --queue "$tf_queue" --max-jobs 1 --wall-seconds 900

python3 -B -m scripts.run_dta_dse_queue run \
    --queue "$tf_queue" --max-jobs 4 --wall-seconds 900

python3 -B -m scripts.run_dta_dse_queue audit --queue "$tf_queue"
```

Each invocation audits its bindings and previously completed evidence before
reusing accepted results. It continues pending work without solving completed
jobs again. A completed controller result that was not committed to queue state
can be adopted only after the same source, worker, concrete rerun and cleanup
audits pass. Candidate files are admitted through those audited results and
published into the queue corpus by content hash.

Defaults bind a queue to at most 128 total starts and 512 queued jobs. The total
start count persists across invocations. `run --max-jobs` limits new starts in
that invocation; it does not reset the queue-wide budget. The wall-time option
is a soft scheduling limit checked between jobs. The scheduler does not abort
an active guest at that deadline. Worker CPU, memory, occurrence and prefix
budgets remain explicit: eight recapture occurrences, 128 prefix steps, 256
handoff sites, 30 CPU seconds per case and 1024 MiB per service by default.

`UNKNOWN` and `UNSAT` remain nonproof results and contribute no new DSE seed.
They are completed bounded attempts, not pending work implicitly retried under
larger limits. A completed queue does not imply that every branch was inverted.

## Stop between jobs

From another terminal, set `tf_queue` to the same queue path and request a stop:

```bash
python3 -B -m scripts.run_dta_dse_queue stop --queue "$tf_queue"
```

The request does not need the running controller's exclusive queue lock. The
active job finishes and is audited before the scheduler stops launching jobs.
The next `run` acknowledges the prior stop request and resumes pending work.
A newer stop request arriving during resume remains effective.
Only one processing controller may own the queue at a time; the persistent
lock file uses a process-held filesystem lock.

A hard interruption is different from a cooperative stop. An incomplete attempt
remains blocked for recovery; the queue does not infer guest cleanup from an
expired process or a free lock, nor automatically retry unknown live work.
If a complete result is available, resume can adopt it after a full audit.
Missing cleanup or partial solver evidence cannot authorize publication.

`status` reads a scheduler snapshot. It does not repeat source or proof audits
and is not an acceptance certificate. `audit` performs the evidence checks
without launching a guest. `run` and `audit` return exit 2 when the queue is
blocked or its total-start budget prevents pending work; paused, cooperatively
stopped and complete states return exit 0. Errors return exit 1; an interrupted
CLI returns exit 130.

No AFL campaign, parallel worker integration or fuzzer queue insertion is
performed. A teammate can consume the audited corpus and its manifest through
the later integration interface. The shared control channel remains
unprotected; universal equivalence, historical instruction originality and
execution beyond the observed successor boundary remain unproved. Native
namespace/cgroup acceptance still requires the intended host; orchestration
unit tests do not establish isolation or fresh SMT execution.
