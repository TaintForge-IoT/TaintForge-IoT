#!/usr/bin/env bash
set -euo pipefail
cd -- "$(git rev-parse --show-toplevel)"
tf_m5_qemu=${1:-$HOME/.local/opt/taintforge/qemu-11.0.1/bin/qemu-i386}
tf_m5_out=${2:-workdir/capsule-control-m5-$(date +%Y%m%d-%H%M%S)}
if [[ $# -gt 2 ]]; then
    printf 'Usage: %s [qemu-i386-11.0.1] [new-output-directory]\n' "$0" >&2
    exit 2
fi
tf_m5_out=$(python3 - "$tf_m5_out" <<'PY'
from pathlib import Path
import sys
path=Path(sys.argv[1]).absolute()
path.mkdir(parents=True,exist_ok=False)
(path/'validation').mkdir()
print(path)
PY
)
tf_m5_collect() {
    local tf_m5_code=$?
    trap - EXIT
    if ! python3 -m scripts.collect_capsule_control_evidence --out "$tf_m5_out" --exit-code "$tf_m5_code"; then
        if [[ $tf_m5_code -eq 0 ]]; then tf_m5_code=1; fi
    fi
    exit "$tf_m5_code"
}
trap tf_m5_collect EXIT
export TF_OBSERVER_QEMU="$tf_m5_qemu"
python3 -m scripts.run_capsule_control_tests --out "$tf_m5_out/validation/control-tests.json" \
    2>&1 | tee "$tf_m5_out/validation/control-tests.log"
python3 -m scripts.verify_capsule_control --qemu "$tf_m5_qemu" --out "$tf_m5_out/components" \
    2>&1 | tee "$tf_m5_out/validation/components.log"
bash scripts/build_run_capsule_hardening.sh "$tf_m5_qemu" "$tf_m5_out/m4" \
    2>&1 | tee "$tf_m5_out/validation/m4.log"
tf_m5_plugin=$(python3 - "$tf_m5_out/m4" <<'PY'
from pathlib import Path
import json,sys
root=Path(sys.argv[1])/'e2e/normal/session/iterations/0000/run/config/analyzer_runtime'
manifest=json.loads((root/'bundle.json').read_text())
print(root/manifest['plugin'])
PY
)
python3 -m scripts.run_capsule_control_e2e --qemu "$tf_m5_qemu" --plugin "$tf_m5_plugin" --out "$tf_m5_out/e2e" \
    2>&1 | tee "$tf_m5_out/validation/e2e.log"
