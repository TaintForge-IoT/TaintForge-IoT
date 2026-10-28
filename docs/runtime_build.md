# Source-built warm and DSE runtime

Run `bash scripts/build_afl_warm_qemu.sh` from the project checkout. Optional
arguments select a QEMU source directory and installation prefix. Defaults are
`$HOME/.cache/taintforge/qemu-11.0.1-warm-source` and
`$HOME/.local/opt/taintforge/qemu-11.0.1-warm`. Neither may overlap the project,
each other, or contain the home directory. Paths must not traverse symlinks or
contain commas/newlines. A prefix can be reused; it must be writable.

Requirements are Python 3.11 or newer, Git, GCC, GNU as/ld/nm, Ninja,
`pkg-config`, and development packages for GLib, Capstone and Z3. QEMU configure
also checks its usual host build dependencies. No sudo or AFL campaign is
required for runtime construction. `TF_BUILD_JOBS` defaults to four. `TF_PYTHON`
selects the Python executable; the existing plugin build overrides remain
available through `TF_IR_CC`, `TF_PLUGIN_CPPFLAGS`, `TF_PLUGIN_LIBS` and
`TF_PLUGIN_LDFLAGS`.

The source must have exact QEMU 11.0.1 commit
`6e9a825c1d4e7b62d072e99a89ecd1a74c7f0d55`. A missing source directory is cloned
from tag `v11.0.1`, then its commit is checked. Staged source changes and tracked
changes outside the installer's explicit file inventory are rejected. The
installer checks complete source-file hashes, keeps backups and accepts only
the clean baseline or supported exact warm/EFLAGS variants. Unknown edits are
not overwritten. Concurrent builds using the same source or prefix are refused.

The x86 fix is a backport of upstream
`e7ae490e0cf8c712fad6e39984a57a14e9cc400f`, `target/i386: fix EFLAGS reads in TCG
plugin callbacks`. It materializes the split flags during TCG callbacks,
synchronizes lazy condition-code state at instruction boundaries and keeps the
normal stopped-GDB representation outside TCG. The previous standalone fix is
upgraded to the upstream host-state placement when its exact bytes are found.
The private warm-fork ABI and target futex-mask build repair are retained.

The builder configures only i386 linux-user with plugins and without default
features, builds QEMU, copies its patched SDK header, then builds the full Phase
1 plugin against that exact header. It verifies both exported warm ABI entry
points. Build commands, logs, source diff, tool/dependency versions and critical
project source hashes are retained under
`PREFIX/share/taintforge/build.XXXXXXXX/`.

Installed artifacts are `PREFIX/bin/qemu-i386`,
`PREFIX/lib/taintforge/libtaintforge_ir.so` and its `.runtime.json`, and
`PREFIX/include/taintforge/qemu-plugin.h`. They are replaced atomically as
individual files. Previous readiness metadata is removed immediately before
installation starts. A failure after that point leaves no ready manifest or
environment file; existing binaries are not silently described by old metadata.
There is no automatic rollback of a partly installed prefix. Use a new prefix
when an existing runtime must remain available throughout the build.

The installed QEMU runs 32 normal and 32 single-instruction-per-TB PUSHFL checks.
A further bounded run loads the full Phase 1 plugin with the exact-binary flags
receipt. Ready publication requires successful flags calibration, actual plugin
loading, verified flags, unchanged artifact/source/tool hashes and the known
guest output. The receipt is not reused for another QEMU executable. Failures
retain their logs, while no readiness metadata is published.

Successful output is `READY_TAINTFORGE_DSE_RUNTIME`. The final files are
`PREFIX/share/taintforge/runtime.json` and
`PREFIX/share/taintforge/environment.sh`. Source the environment file to obtain
`TF_OBSERVER_QEMU`, `TF_WARM_QEMU`, `TF_PHASE1_PLUGIN`,
`TAINTFORGE_QEMU_PLUGIN`, `TF_QEMU_INCLUDE`, `TF_X86_FLAGS_RECEIPT` and
`TF_RUNTIME_MANIFEST`. DTA/DSE CLIs accept the corresponding explicit paths.
The receipt and calibration evidence are under that build attempt; retain the
attempt directory while using its environment and manifest.

`scripts/build_afl_warm_only.sh` reuses the calibrated plugin and SDK from this
runtime. `scripts/build_run_afl_warm.sh` honors an explicitly selected
`TF_QEMU_INCLUDE`; otherwise it prefers the SDK beside the selected installed
QEMU, with the legacy vendor header only as a compatibility fallback.

This is a reproducible source-selection/build/calibration procedure, not a
cross-host bit-identical build claim. The bounded flags/load probes establish
neither guest isolation nor hostile-sample readiness, complete x86 correctness,
universal equivalence or OEP originality. Namespace/cgroup and DTA/DSE acceptance
remain separate checks.
