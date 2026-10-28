#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
if [[ $# -ne 0 ]]; then
    printf 'Usage: %s\n' "$0" >&2
    exit 2
fi
pkg-config --exists glib-2.0 capstone z3
mkdir -p -- "$PWD/workdir"
tf_build_out=$(mktemp -d "$PWD/workdir/afl-warm-build.XXXXXXXX")
printf 'Build directory: %s\n' "$tf_build_out"
trap 'printf "Build stopped. Logs: %s\n" "$tf_build_out" >&2' ERR

tf_build_prefix=${TF_WARM_QEMU_PREFIX:-$HOME/.local/opt/taintforge/qemu-11.0.1-warm}
bash scripts/build_afl_warm_qemu.sh \
    "${TF_WARM_QEMU_SOURCE:-$HOME/.cache/taintforge/qemu-11.0.1-warm-source}" \
    "$tf_build_prefix" \
    2>&1 | tee "$tf_build_out/qemu-build.log"

tf_build_prefix=$(realpath -- "$tf_build_prefix")
source "$tf_build_prefix/share/taintforge/environment.sh"
cp -- "$TF_PHASE1_PLUGIN" "$tf_build_out/libtaintforge_ir.so"
cp -- "$TF_PHASE1_PLUGIN.runtime.json" "$tf_build_out/libtaintforge_ir.so.runtime.json"
python3 -B - "$tf_build_out/libtaintforge_ir.so" <<'PY' 2>&1 | tee "$tf_build_out/phase1-build.log"
from pathlib import Path
import sys
from taintforge_env.phase1_runtime import Phase1Runtime
runtime = Phase1Runtime.load(Path(sys.argv[1]))
print('Reused calibrated Phase 1 plugin:', runtime.plugin)
PY

python3 - "$tf_build_out" <<'PY' 2>&1 | tee "$tf_build_out/native-build.log"
import json
import sys
from pathlib import Path
from taintforge_env.afl_file import build

root = Path(sys.argv[1])
result = build(root / 'native')
(root / 'native-build.json').write_text(
    json.dumps(result, indent=2) + '\n', encoding='utf-8'
)
print(json.dumps(result, indent=2))
PY

printf '\nBuild completed. Artifacts and logs: %s\n' "$tf_build_out"
