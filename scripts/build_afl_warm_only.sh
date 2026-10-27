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

bash scripts/build_afl_warm_qemu.sh \
    "${TF_WARM_QEMU_SOURCE:-$HOME/.cache/taintforge/qemu-11.0.1-warm-source}" \
    "${TF_WARM_QEMU_PREFIX:-$HOME/.local/opt/taintforge/qemu-11.0.1-warm}" \
    2>&1 | tee "$tf_build_out/qemu-build.log"

export TF_QEMU_INCLUDE="$PWD/experiments/execution_capsule_probe/vendor"
bash unpacker/test/build_group7_4c1_plugin.sh \
    unpacker/test "$tf_build_out/libtaintforge_ir.so" \
    2>&1 | tee "$tf_build_out/phase1-build.log"

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
