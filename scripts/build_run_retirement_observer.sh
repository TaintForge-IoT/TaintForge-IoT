#!/usr/bin/env bash
set -euo pipefail
cd -- "$(git rev-parse --show-toplevel)"
tf_observer_qemu=${1:-$HOME/.local/opt/taintforge/qemu-11.0.1/bin/qemu-i386}
tf_observer_out=${2:-workdir/retirement-observer-m2-$(date +%Y%m%d-%H%M%S)}
if [[ $# -gt 2 ]]; then
    printf 'Usage: %s [qemu-i386-11.0.1] [new-output-directory]\n' "$0" >&2
    exit 2
fi
python3 - "$tf_observer_qemu" <<'PY'
import re, subprocess, sys
version = subprocess.check_output([sys.argv[1], '--version'], text=True).splitlines()[0]
print(version)
if not re.search(r'\bversion 11\.0\.1(?:\s|$)', version):
    raise SystemExit('M2 requires QEMU 11.0.1 / plugin API 6')
PY
mkdir -p build/retirement-observer-m2
tf_observer_build=$(mktemp -d "$PWD/build/retirement-observer-m2/build.XXXXXXXX")
tf_observer_plugin="$tf_observer_build/libtaintforge_ir.so"
export TF_QEMU_INCLUDE="$PWD/experiments/execution_capsule_probe/vendor"
export TF_OBSERVER_QEMU="$tf_observer_qemu"
bash unpacker/test/build_group7_4c1_plugin.sh unpacker/test "$tf_observer_plugin"
python3 -m unittest -v tests.test_phase1_retirement tests.test_phase1_retirement_integration \
    tests.test_phase1_verdict_retirement tests.test_phase1_runtime tests.test_execution_capsule \
    tests.test_capsule_unified_lifecycle tests.test_phase1_retirement_evidence tests.test_retirement_observer \
    tests.test_retirement_observer_launch tests.test_retirement_observer_pc \
    tests.test_retirement_observer_handoff
# Controlled built-in benign ELFs only. This is the unprivileged technical M2
# prototype, not the unified/systemd/cgroup route and not a malware sandbox.
python3 -m experiments.retirement_observer.local_check \
    --qemu "$tf_observer_qemu" --plugin "$tf_observer_plugin" --out "$tf_observer_out" --fail-fast
