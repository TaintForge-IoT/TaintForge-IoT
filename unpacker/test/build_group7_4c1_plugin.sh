#!/usr/bin/env bash
set -euo pipefail

if [[ $# -gt 2 ]]; then
    printf 'Usage: %s [source-directory] [output.so]\nSet TF_QEMU_INCLUDE to the matching QEMU header directory.\n' "$0" >&2
    exit 2
fi
tf_runtime_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ $# -ge 1 ]]; then
    tf_runtime_src=$(cd -- "$1" && pwd)
elif [[ -f "$tf_runtime_dir/qemu_unpacker.c" ]]; then
    tf_runtime_src=$tf_runtime_dir
else
    tf_runtime_src=$tf_runtime_dir/src
fi
tf_runtime_out=${2:-$tf_runtime_dir/libtaintforge_ir.so}
if [[ -z ${TF_QEMU_INCLUDE:-} || ! -f "$TF_QEMU_INCLUDE/qemu-plugin.h" ]]; then
    printf 'TF_QEMU_INCLUDE must contain qemu-plugin.h from the QEMU build you will run.\n' >&2
    exit 2
fi
# Give the selected plugin API priority without adding unrelated QEMU headers
# to the include search path. A system-installed qemu-plugin.h may be newer.
tf_runtime_header_dir=$(mktemp -d "${TMPDIR:-/tmp}/taintforge-qemu-header.XXXXXXXX")
trap 'rm -rf -- "$tf_runtime_header_dir"' EXIT
cp -- "$TF_QEMU_INCLUDE/qemu-plugin.h" "$tf_runtime_header_dir/qemu-plugin.h"
tf_runtime_cc=${TF_IR_CC:-gcc}
if [[ -n ${TF_PLUGIN_CPPFLAGS:-} ]]; then
    read -r -a tf_runtime_cpp <<<"$TF_PLUGIN_CPPFLAGS"
else
    tf_runtime_detected=$(pkg-config --cflags glib-2.0 capstone z3)
    read -r -a tf_runtime_cpp <<<"$tf_runtime_detected"
fi
if [[ -n ${TF_PLUGIN_LIBS:-} ]]; then
    read -r -a tf_runtime_libs <<<"$TF_PLUGIN_LIBS"
else
    tf_runtime_detected=$(pkg-config --libs glib-2.0 capstone z3)
    read -r -a tf_runtime_libs <<<"$tf_runtime_detected -lm -pthread"
fi
read -r -a tf_runtime_ldflags <<<"${TF_PLUGIN_LDFLAGS:-}"
tf_runtime_sources=()
for tf_runtime_name in qemu_unpacker.c dta.c provenance.c dcfg.c trace.c aux_trace.c \
    trace_deps.c trace_deps_x86.c replay_input.c replay_sources.c dse.c dse_lift_x86.c \
    ir.c ir_eval.c ir_opt.c ir_lift_x86.c ir_environment.c ir_replay.c ir_inputs.c ir_runtime.c ir_ssa.c ir_smt.c \
    ir_branches.c ir_concolic.c ir_oep.c runtime_diag.c qemu_flags_contract.c elf_image.c phase1_io.c; do
    tf_runtime_sources+=("$tf_runtime_src/$tf_runtime_name")
done
export TF_BUILD_CPPFLAGS="${tf_runtime_cpp[*]}"
export TF_BUILD_LDFLAGS="${tf_runtime_ldflags[*]}"
export TF_BUILD_LIBS="${tf_runtime_libs[*]}"
tf_runtime_python=${TF_PYTHON:-python3}
tf_runtime_build_id=$("$tf_runtime_python" "$tf_runtime_src/phase1_build_manifest.py" identity \
    --header "$tf_runtime_header_dir/qemu-plugin.h" --plugin "$tf_runtime_out" \
    --compiler "$tf_runtime_cc" "${tf_runtime_sources[@]}")
# An old sidecar must never accompany a failed or incomplete rebuild.
rm -f -- "$tf_runtime_out.runtime.json"
# QEMU plugin symbols are resolved by the executable at load time.
"$tf_runtime_cc" -std=gnu11 -O2 -g -fPIC -shared -Wall -Wextra \
    -Werror=incompatible-pointer-types -Werror=implicit-function-declaration \
    "-DTF_PHASE1_BUILD_ID=\"$tf_runtime_build_id\"" \
    -I"$tf_runtime_header_dir" -I"$tf_runtime_src" "${tf_runtime_cpp[@]}" \
    "${tf_runtime_sources[@]}" "${tf_runtime_ldflags[@]}" "${tf_runtime_libs[@]}" \
    -o "$tf_runtime_out"
"$tf_runtime_python" "$tf_runtime_src/phase1_build_manifest.py" write \
    --header "$tf_runtime_header_dir/qemu-plugin.h" --plugin "$tf_runtime_out" \
    --compiler "$tf_runtime_cc" --expected-build-id "$tf_runtime_build_id" "${tf_runtime_sources[@]}"
printf 'Built: %s\n' "$tf_runtime_out"
