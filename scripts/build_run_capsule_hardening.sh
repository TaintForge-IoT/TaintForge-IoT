#!/usr/bin/env bash
set -euo pipefail
cd -- "$(git rev-parse --show-toplevel)"
tf_m4_qemu=${1:-$HOME/.local/opt/taintforge/qemu-11.0.1/bin/qemu-i386}
tf_m4_out=${2:-workdir/capsule-hardening-m4-$(date +%Y%m%d-%H%M%S)}
if [[ $# -gt 2 ]]; then
    printf 'Usage: %s [qemu-i386-11.0.1] [new-output-directory]\n' "$0" >&2
    exit 2
fi
tf_m4_out=$(python3 - "$tf_m4_out" <<'PY'
from pathlib import Path
import sys
path=Path(sys.argv[1]).absolute()
path.mkdir(parents=True,exist_ok=False)
(path/'validation').mkdir()
print(path)
PY
)
tf_m4_collect() {
    local tf_m4_code=$?
    trap - EXIT
    if ! python3 -m scripts.collect_capsule_hardening_evidence --out "$tf_m4_out" --exit-code "$tf_m4_code"; then
        if [[ $tf_m4_code -eq 0 ]]; then tf_m4_code=1; fi
    fi
    exit "$tf_m4_code"
}
trap tf_m4_collect EXIT
python3 - "$tf_m4_qemu" <<'PY' 2>&1 | tee "$tf_m4_out/validation/preflight.log"
import re,subprocess,sys
from taintforge_env.capsule_resources import preflight
version=subprocess.check_output([sys.argv[1],'--version'],text=True).splitlines()[0]
print(version)
if not re.search(r'\bversion 11\.0\.1(?:\s|$)',version):raise SystemExit('M4 requires QEMU 11.0.1 / API 6')
preflight()
PY
mkdir -p build/capsule-hardening-m4
tf_m4_build=$(mktemp -d "$PWD/build/capsule-hardening-m4/build.XXXXXXXX")
tf_m4_plugin="$tf_m4_build/libtaintforge_ir.so"
export TF_QEMU_INCLUDE="$PWD/experiments/execution_capsule_probe/vendor"
export TF_OBSERVER_QEMU="$tf_m4_qemu"
bash unpacker/test/build_group7_4c1_plugin.sh unpacker/test "$tf_m4_plugin" 2>&1 | tee "$tf_m4_out/validation/build.log"
python3 -m scripts.run_input_retirement_tests --out "$tf_m4_out/validation/tests.json" 2>&1 | tee "$tf_m4_out/validation/tests.log"
python3 -m scripts.run_capsule_hardening_tests --out "$tf_m4_out/validation/m4-tests.json" 2>&1 | tee "$tf_m4_out/validation/m4-tests.log"
python3 -m scripts.probe_linux_user_fd --qemu "$tf_m4_qemu" --out "$tf_m4_out/fd-probe"
sudo -v
python3 -m scripts.run_input_retirement_e2e --hardening --qemu "$tf_m4_qemu" --plugin "$tf_m4_plugin" --out "$tf_m4_out/e2e" 2>&1 | tee "$tf_m4_out/validation/e2e.log"
python3 -m scripts.run_capsule_hardening_e2e --qemu "$tf_m4_qemu" --plugin "$tf_m4_plugin" --out "$tf_m4_out/extra" 2>&1 | tee "$tf_m4_out/validation/extra.log"
printf 'Evidence: %s/acceptance.tar.gz\n' "$tf_m4_out"
