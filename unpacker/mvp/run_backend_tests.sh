#!/usr/bin/env bash
set -euo pipefail
if (( $# > 2 )); then
    printf 'Usage: %s [PROJECT] [RESULTS]\n' "$0" >&2
    exit 2
fi
tf_backend_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
tf_backend_source="$tf_backend_dir/source"
if (( $# >= 1 )); then
    tf_backend_project=$(cd -- "$1" && pwd)
    tf_backend_source="$tf_backend_project/unpacker/test"
fi
tf_backend_work=$(mktemp -d "${TMPDIR:-/tmp}/taintforge-backend-tests.XXXXXXXX")
trap 'rm -rf -- "$tf_backend_work"' EXIT
tf_backend_results=${2:-$tf_backend_work/reports}
mkdir -p -- "$tf_backend_results"
tf_backend_cc=${TF_IR_CC:-gcc}
tf_backend_flags=(-std=c11 -O2 -g -Wall -Wextra -Werror)
if [[ ${TF_IR_SANITIZE:-0} == 1 ]]; then
    tf_backend_flags+=(-O1 -fno-omit-frame-pointer -fsanitize=address,undefined -fno-pie -no-pie)
fi
tf_backend_cpp=${TF_IR_CPPFLAGS:-${TF_PLUGIN_CPPFLAGS:-}}
tf_backend_libs=${TF_IR_LIBS:-${TF_PLUGIN_LIBS:-}}
if [[ -z $tf_backend_cpp ]]; then
    tf_backend_cpp=$(pkg-config --cflags glib-2.0 capstone z3)
fi
if [[ -z $tf_backend_libs ]]; then
    tf_backend_libs="$(pkg-config --libs glib-2.0 capstone z3) -lm -pthread"
fi
read -r -a tf_backend_includes <<<"$tf_backend_cpp"
read -r -a tf_backend_libraries <<<"$tf_backend_libs"
read -r -a tf_backend_ldflags <<<"${TF_IR_LDFLAGS:-${TF_PLUGIN_LDFLAGS:-}}"
tf_backend_objects=()
for tf_backend_name in dcfg.c dta.c trace.c aux_trace.c provenance.c replay_input.c \
    replay_sources.c ir.c ir_eval.c ir_opt.c ir_lift_x86.c ir_environment.c ir_replay.c \
    ir_inputs.c ir_runtime.c ir_ssa.c ir_smt.c ir_branches.c ir_oep.c runtime_diag.c \
    qemu_flags_contract.c dse.c dse_lift_x86.c trace_deps.c trace_deps_x86.c; do
    tf_backend_object="$tf_backend_work/$tf_backend_name.o"
    "$tf_backend_cc" "${tf_backend_flags[@]}" -I"$tf_backend_source" \
        "${tf_backend_includes[@]}" -c "$tf_backend_source/$tf_backend_name" -o "$tf_backend_object"
    tf_backend_objects+=("$tf_backend_object")
done
for tf_backend_test in test_ir_oep test_ir_oep_legacy test_ir_oep_inputs test_ir_oep_lifetime test_dse_control; do
    "$tf_backend_cc" "${tf_backend_flags[@]}" -DTF_IR_TRACE_SSA -I"$tf_backend_source" \
        "${tf_backend_includes[@]}" "$tf_backend_dir/tests/native/$tf_backend_test.c" \
        "${tf_backend_objects[@]}" "${tf_backend_ldflags[@]}" "${tf_backend_libraries[@]}" \
        -o "$tf_backend_work/$tf_backend_test"
    "$tf_backend_work/$tf_backend_test" "$tf_backend_results/$tf_backend_test.jsonl"
    printf 'PASS: %s\n' "$tf_backend_test"
done
