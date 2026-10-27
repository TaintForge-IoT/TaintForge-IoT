#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
if [[ $# -gt 2 ]]; then
    printf 'Usage: %s [QEMU_SOURCE_DIRECTORY] [INSTALL_PREFIX]\n' "$0" >&2
    exit 2
fi
tf_warm_source=${1:-$HOME/.cache/taintforge/qemu-11.0.1-warm-source}
tf_warm_prefix=${2:-$HOME/.local/opt/taintforge/qemu-11.0.1-warm}
tf_warm_source=$(realpath -m -- "$tf_warm_source")
tf_warm_prefix=$(realpath -m -- "$tf_warm_prefix")
tf_build_jobs=${TF_BUILD_JOBS:-4}
if [[ ! "$tf_build_jobs" =~ ^[1-9][0-9]*$ ]]; then
    printf 'TF_BUILD_JOBS must be a positive integer\n' >&2
    exit 2
fi
if [[ ! -e "$tf_warm_source" ]]; then
    mkdir -p -- "$(dirname -- "$tf_warm_source")"
    git clone --depth 1 --branch v11.0.1 https://gitlab.com/qemu-project/qemu.git "$tf_warm_source"
fi
python3 experiments/afl_file/qemu/apply.py --qemu-source "$tf_warm_source" --check
python3 experiments/afl_file/qemu/apply.py --qemu-source "$tf_warm_source"
mkdir -p -- "$tf_warm_source/build-taintforge-warm"
cd -- "$tf_warm_source/build-taintforge-warm"
../configure --target-list=i386-linux-user --enable-plugins --disable-docs \
    --disable-system --prefix="$tf_warm_prefix"
ninja -j "$tf_build_jobs" qemu-i386
ninja -j "$tf_build_jobs" install
tf_warm_symbols=$(nm -D --defined-only "$tf_warm_prefix/bin/qemu-i386")
for tf_warm_symbol in qemu_plugin_tf_warm_configure qemu_plugin_tf_warm_arm; do
    if ! awk -v symbol="$tf_warm_symbol" '$NF == symbol { found = 1 } END { exit !found }' <<< "$tf_warm_symbols"; then
        printf 'Required QEMU symbol missing: %s\n' "$tf_warm_symbol" >&2
        exit 1
    fi
done
printf 'QEMU built: %s/bin/qemu-i386\n' "$tf_warm_prefix"
