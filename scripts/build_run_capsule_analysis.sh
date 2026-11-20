#!/usr/bin/env bash
set -euo pipefail
cd -- "$(git rev-parse --show-toplevel)"
tf_analysis_qemu=${1:-$HOME/.local/opt/taintforge/qemu-11.0.1/bin/qemu-i386}
tf_analysis_out=${2:-workdir/capsule-analysis-$(date +%Y%m%d-%H%M%S)}
if [[ $# -gt 2 ]]; then
    printf 'Usage: %s [qemu-i386-11.0.1] [new-output-directory]\n' "$0" >&2
    exit 2
fi
tf_analysis_out=$(python3 - "$tf_analysis_out" <<'PY'
from pathlib import Path
import sys
path=Path(sys.argv[1]).absolute()
path.mkdir(parents=True,exist_ok=False)
(path/'validation').mkdir()
print(path)
PY
)
tf_analysis_collect() {
    local tf_analysis_code=$?
    trap - EXIT
    if ! python3 -m scripts.collect_capsule_analysis_evidence --out "$tf_analysis_out" --exit-code "$tf_analysis_code"; then
        if [[ $tf_analysis_code -eq 0 ]]; then tf_analysis_code=1; fi
    fi
    exit "$tf_analysis_code"
}
trap tf_analysis_collect EXIT
python3 -m scripts.run_capsule_analysis_tests --out "$tf_analysis_out/validation/analysis-tests.json" \
    2>&1 | tee "$tf_analysis_out/validation/analysis-tests.log"
bash scripts/build_run_capsule_control.sh "$tf_analysis_qemu" "$tf_analysis_out/m5" \
    2>&1 | tee "$tf_analysis_out/validation/m5.log"
tf_analysis_plugin=$(python3 - "$tf_analysis_out/m5/m4" <<'PY'
from pathlib import Path
import json,sys
root=Path(sys.argv[1])/'e2e/normal/session/iterations/0000/run/config/analyzer_runtime'
manifest=json.loads((root/'bundle.json').read_text())
print(root/manifest['plugin'])
PY
)
python3 -m scripts.run_capsule_analysis_e2e --qemu "$tf_analysis_qemu" --plugin "$tf_analysis_plugin" --out "$tf_analysis_out/e2e" \
    2>&1 | tee "$tf_analysis_out/validation/e2e.log"
