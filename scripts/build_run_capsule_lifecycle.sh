#!/usr/bin/env bash
set -euo pipefail
cd -- "$(git rev-parse --show-toplevel)"
tf_lifecycle_qemu=${1:-$HOME/.local/opt/taintforge/qemu-11.0.1/bin/qemu-i386}
tf_lifecycle_out=${2:-workdir/capsule-lifecycle-$(date +%Y%m%d-%H%M%S)}
if [[ $# -gt 2 ]]; then
    printf 'Usage: %s [qemu-i386-11.0.1] [new-output-directory]\n' "$0" >&2
    exit 2
fi
tf_lifecycle_out=$(python3 - "$tf_lifecycle_out" <<'PY'
from pathlib import Path
import sys
path=Path(sys.argv[1]).absolute()
path.mkdir(parents=True,exist_ok=False)
(path/'validation').mkdir()
print(path)
PY
)
tf_lifecycle_collect() {
    local tf_lifecycle_code=$?
    trap - EXIT
    if ! python3 -m scripts.collect_capsule_lifecycle_evidence --out "$tf_lifecycle_out" --exit-code "$tf_lifecycle_code"; then
        if [[ $tf_lifecycle_code -eq 0 ]]; then tf_lifecycle_code=1; fi
    fi
    exit "$tf_lifecycle_code"
}
trap tf_lifecycle_collect EXIT
python3 -m scripts.run_capsule_lifecycle_tests --out "$tf_lifecycle_out/validation/lifecycle-tests.json" \
    2>&1 | tee "$tf_lifecycle_out/validation/lifecycle-tests.log"
bash scripts/build_run_capsule_analysis.sh "$tf_lifecycle_qemu" "$tf_lifecycle_out/analysis" \
    2>&1 | tee "$tf_lifecycle_out/validation/analysis.log"
tf_lifecycle_plugin=$(python3 - "$tf_lifecycle_out/analysis/m5/m4" <<'PY'
from pathlib import Path
import json,sys
root=Path(sys.argv[1])/'e2e/normal/session/iterations/0000/run/config/analyzer_runtime'
manifest=json.loads((root/'bundle.json').read_text())
print(root/manifest['plugin'])
PY
)
python3 -m scripts.run_capsule_lifecycle_e2e --qemu "$tf_lifecycle_qemu" --plugin "$tf_lifecycle_plugin" --out "$tf_lifecycle_out/e2e" \
    2>&1 | tee "$tf_lifecycle_out/validation/e2e.log"
python3 - "$tf_lifecycle_out" <<'PY'
from pathlib import Path
import sys
from experiments.execution_capsule_probe.controller import write_json
from scripts.audit_capsule_strict_evidence import audit
from taintforge_env.phase1_runtime import read_json
root=Path(sys.argv[1])
report=read_json(root/'analysis/e2e/report.json')
proof=root/'analysis/e2e/research-normal/session/iterations/0000/run/retirement-evidence'
write_json(root/'validation/strict-audit.json',audit(proof,report['cases'][0]['attempts'][0]['bundle_sha256']))
PY
