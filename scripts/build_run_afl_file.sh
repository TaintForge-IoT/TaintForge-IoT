#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
if [[ $# -gt 3 ]]; then
    printf 'Usage: %s [qemu-i386-11.0.1] [new-output-directory] [afl-bin-directory]\n' "$0" >&2
    exit 2
fi
tf_afl_qemu=${1:-$HOME/.local/opt/taintforge/qemu-11.0.1/bin/qemu-i386}
tf_afl_out=${2:-workdir/afl-file-$(date +%Y%m%d-%H%M%S)}
tf_afl_bin=${3:-$(dirname -- "$(command -v afl-fuzz)")}
tf_afl_out=$(python3 - "$tf_afl_out" <<'PY'
from pathlib import Path
import sys
path=Path(sys.argv[1]).resolve()
path.mkdir(parents=True,exist_ok=False)
print(path)
PY
)
mkdir "$tf_afl_out/build"
export TF_QEMU_INCLUDE="$PWD/experiments/execution_capsule_probe/vendor"
export TF_OBSERVER_QEMU="$tf_afl_qemu"
export TF_AFL_BIN="$tf_afl_bin"
sudo -v
python3 -m unittest -v tests.test_afl_file tests.test_afl_transport tests.test_afl_campaign tests.test_afl_qemu \
    2>&1 | tee "$tf_afl_out/tests.log"
bash unpacker/test/build_group7_4c1_plugin.sh unpacker/test "$tf_afl_out/build/libtaintforge_ir.so" \
    2>&1 | tee "$tf_afl_out/build.log"
python3 -m scripts.verify_afl_file_e2e --qemu "$tf_afl_qemu" \
    --plugin "$tf_afl_out/build/libtaintforge_ir.so" --afl-bin "$tf_afl_bin" \
    --out "$tf_afl_out/e2e" 2>&1 | tee "$tf_afl_out/e2e.log"
