#!/usr/bin/env bash
set -euo pipefail
cd -- "$(git rev-parse --show-toplevel)"
tf_retire_qemu=${1:-$HOME/.local/opt/taintforge/qemu-11.0.1/bin/qemu-i386}
tf_retire_out=${2:-workdir/phase1-retirement-e2e-$(date +%Y%m%d-%H%M%S)}
if [[ $# -gt 2 ]]; then
    printf 'Usage: %s [qemu-i386-11.0.1] [new-output-directory]\n' "$0" >&2
    exit 2
fi
python3 - "$tf_retire_qemu" <<'PY'
import re, subprocess, sys
version = subprocess.check_output([sys.argv[1], '--version'], text=True).splitlines()[0]
print(version)
if not re.search(r'\bversion 11\.0\.1(?:\s|$)', version):
    raise SystemExit('This retirement profile requires QEMU 11.0.1 / plugin API 6')
PY
mkdir -p build/retirement-v1
tf_retire_build=$(mktemp -d "$PWD/build/retirement-v1/build.XXXXXXXX")
tf_retire_plugin="$tf_retire_build/libtaintforge_ir.so"
export TF_QEMU_INCLUDE="$PWD/experiments/execution_capsule_probe/vendor"
bash unpacker/test/build_group7_4c1_plugin.sh unpacker/test "$tf_retire_plugin"
python3 -m unittest tests.test_phase1_retirement tests.test_phase1_retirement_integration -v
sudo -v
python3 -m scripts.run_phase1_retirement_e2e \
    --qemu "$tf_retire_qemu" --plugin "$tf_retire_plugin" \
    --memory-mib 1024 --out "$tf_retire_out"
