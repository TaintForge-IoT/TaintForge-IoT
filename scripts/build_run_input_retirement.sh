#!/usr/bin/env bash
set -euo pipefail
cd -- "$(git rev-parse --show-toplevel)"
tf_m3_qemu=${1:-$HOME/.local/opt/taintforge/qemu-11.0.1/bin/qemu-i386}
tf_m3_out=${2:-workdir/input-retirement-m3-$(date +%Y%m%d-%H%M%S)}
if [[ $# -gt 2 ]]; then
    printf 'Usage: %s [qemu-i386-11.0.1] [new-output-directory]\n' "$0" >&2
    exit 2
fi
tf_m3_out=$(python3 - "$tf_m3_out" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1]).resolve()
path.mkdir(parents=True, exist_ok=False)
(path / 'validation').mkdir()
print(path)
PY
)
tf_m3_collect() {
    local tf_m3_code=$?
    trap - EXIT
    if ! python3 -m scripts.collect_input_retirement_evidence --out "$tf_m3_out" --exit-code "$tf_m3_code"; then
        if [[ $tf_m3_code -eq 0 ]]; then tf_m3_code=1; fi
    fi
    exit "$tf_m3_code"
}
trap tf_m3_collect EXIT
python3 - "$tf_m3_qemu" <<'PY' 2>&1 | tee "$tf_m3_out/validation/preflight.log"
import re, subprocess, sys
from taintforge_env.capsule_resources import preflight
version=subprocess.check_output([sys.argv[1],'--version'],text=True).splitlines()[0]
print(version)
if not re.search(r'\bversion 11\.0\.1(?:\s|$)',version):
    raise SystemExit('M3 requires QEMU 11.0.1 / plugin API 6')
preflight()
PY
mkdir -p build/input-retirement-m3
tf_m3_build=$(mktemp -d "$PWD/build/input-retirement-m3/build.XXXXXXXX")
tf_m3_plugin="$tf_m3_build/libtaintforge_ir.so"
export TF_QEMU_INCLUDE="$PWD/experiments/execution_capsule_probe/vendor"
export TF_OBSERVER_QEMU="$tf_m3_qemu"
bash unpacker/test/build_group7_4c1_plugin.sh unpacker/test "$tf_m3_plugin" 2>&1 | tee "$tf_m3_out/validation/build.log"
python3 -m scripts.run_input_retirement_tests --out "$tf_m3_out/validation/tests.json" \
    2>&1 | tee "$tf_m3_out/validation/tests.log"
sudo -v
python3 -m scripts.run_input_retirement_e2e --qemu "$tf_m3_qemu" --plugin "$tf_m3_plugin" --out "$tf_m3_out/e2e" \
    2>&1 | tee "$tf_m3_out/validation/e2e.log"
