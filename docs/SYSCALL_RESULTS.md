# Syscall results and offline target evaluation

Native strace and QEMU events share `return_value`, `errno` and `success`:

| Evidence | `success` |
| --- | --- |
| Numeric, nonnegative return without errno, including hexadecimal addresses | `true` |
| Reported errno, including QEMU `errno=N` | `false` |
| Unknown/unavailable result or negative return without errno | `null` |

Unknown is not failure and is not success. Signals and process exits do not
prove syscall success. Unfinished/resumed lines remain unsupported and are
skipped. Negative returns without errno are conservative: some syscalls return
negative data. A successful syscall return does not guarantee a complete write
or that a requested application-level operation succeeded.

Oracle version 2 derives missing legacy `success` fields in memory, including
errno and hexadecimal returns that older parsers omitted. Explicit `success`
values (including null) are preserved. JSON booleans are matched strictly:
numeric 0/1 are not false/true. Guest filtering remains unchanged; it does not
distinguish guest loader, packer and payload activity.

For a saved run, use the read-only reevaluation command. It reads the saved
target specification by default; `--spec` can select another specification.
`--out` must name a new JSON file outside the original run/session.

```bash
cd "$HOME/taintforge" &&
PYTHONPATH=. python3 scripts/reevaluate_target_state.py \
  --run-dir "$HOME/taintforge/workdir/test_stat_20260916_104626/session/iterations/0000/run" \
  --out "$HOME/taintforge/workdir/test_stat_goal_$(date +%Y%m%d_%H%M%S).json"
```

Exit status: 0 = goal reached; 1 = evaluated but not reached; 2 = invalid input
or output. The JSON contains `goal_reached` and the full `evaluation`, including
the oracle version, specification hash and per-rule evidence. Source logs and
the original attempt/session reports are not rewritten. A new run will use the
fixed parser and oracle through the existing runner automatically.

`goal_reached` only establishes the supplied target. It does not verify Phase 1
capture completeness, a proven OEP, memory isolation or fuzzing readiness.

The regression fixture `tests/fixtures/test_stat_qemu_returns.log` contains eight
syscall lines from the supplied 2026-09-16 test_stat run. It exercises three
writes, hexadecimal mmap2, ENOSYS and an unresolved refused connect. Tests also
cover native strace, legacy JSONL, host filtering and unchanged source files.
