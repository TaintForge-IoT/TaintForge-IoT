#!/usr/bin/env bash
set -euo pipefail
cd -- "$(git rev-parse --show-toplevel)"
tf_verdict_qemu=${1:-$HOME/.local/opt/taintforge/qemu-11.0.1/bin/qemu-i386}
tf_verdict_out=${2:-workdir/phase1-verdict-retirement-e2e-$(date +%Y%m%d-%H%M%S)}
if [[ $# -gt 2 ]]; then
    printf 'Usage: %s [qemu-i386-11.0.1] [new-output-directory]\n' "$0" >&2
    exit 2
fi
python3 - "$tf_verdict_qemu" <<'PY'
import re, subprocess, sys
version = subprocess.check_output([sys.argv[1], '--version'], text=True).splitlines()[0]
print(version)
if not re.search(r'\bversion 11\.0\.1(?:\s|$)', version):
    raise SystemExit('This retirement profile requires QEMU 11.0.1 / plugin API 6')
PY
mkdir -p build/retirement-verdict-v2
tf_verdict_build=$(mktemp -d "$PWD/build/retirement-verdict-v2/build.XXXXXXXX")
tf_verdict_plugin="$tf_verdict_build/libtaintforge_ir.so"
export TF_QEMU_INCLUDE="$PWD/experiments/execution_capsule_probe/vendor"
bash unpacker/test/build_group7_4c1_plugin.sh unpacker/test "$tf_verdict_plugin"
python3 -m unittest tests.test_phase1_retirement tests.test_phase1_retirement_integration \
    tests.test_phase1_verdict_retirement -v
sudo -v
python3 -m scripts.run_phase1_retirement_e2e \
    --trigger verdict --qemu "$tf_verdict_qemu" --plugin "$tf_verdict_plugin" \
    --memory-mib 1024 --out "$tf_verdict_out"
