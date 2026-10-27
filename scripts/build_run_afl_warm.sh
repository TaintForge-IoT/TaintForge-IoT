#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
if [[ $# -ne 3 ]]; then
    printf 'Usage: %s PATCHED_QEMU_I386 NEW_OUTPUT_DIRECTORY AFL_BIN_DIRECTORY\n' "$0" >&2
    exit 2
fi
tf_warm_qemu=$(realpath -- "$1")
tf_warm_output=$(realpath -m -- "$2")
tf_warm_afl_bin=$(realpath -- "$3")
mkdir -- "$tf_warm_output"
export TF_QEMU_INCLUDE="$PWD/experiments/execution_capsule_probe/vendor"
export TF_OBSERVER_QEMU="$tf_warm_qemu"
export TF_WARM_QEMU="$tf_warm_qemu"
export TF_AFL_BIN="$tf_warm_afl_bin"
sudo -v
python3 -m unittest -v tests.test_afl_warm tests.test_afl_file tests.test_afl_transport \
    tests.test_afl_campaign tests.test_afl_qemu tests.test_capsule_hardening \
    tests.test_capsule_hardening_integration 2>&1 | tee "$tf_warm_output/tests.log"
bash unpacker/test/build_group7_4c1_plugin.sh unpacker/test "$tf_warm_output/libtaintforge_ir.so" \
    2>&1 | tee "$tf_warm_output/phase1-build.log"
python3 -m scripts.verify_afl_warm_components --qemu "$tf_warm_qemu" \
    --afl-bin "$tf_warm_afl_bin" --out "$tf_warm_output/components" \
    2>&1 | tee "$tf_warm_output/components.log"
python3 -m scripts.verify_afl_warm_e2e --qemu "$tf_warm_qemu" \
    --plugin "$tf_warm_output/libtaintforge_ir.so" --afl-bin "$tf_warm_afl_bin" \
    --out "$tf_warm_output/e2e" 2>&1 | tee "$tf_warm_output/e2e.log"
