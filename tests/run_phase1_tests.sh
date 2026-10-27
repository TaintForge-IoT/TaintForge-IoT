#!/usr/bin/env bash
set -euo pipefail
tf_test_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
tf_test_tmp=$(mktemp -d "${TMPDIR:-/tmp}/taintforge-phase1-tests.XXXXXXXX")
trap 'rm -rf -- "$tf_test_tmp"' EXIT
cd "$tf_test_root"
tf_test_cc=${CC:-gcc}
tf_test_flags=(-std=gnu11 -Wall -Wextra -Werror -g)
if [[ ${TF_PHASE1_SANITIZE:-0} == 1 ]]; then
    tf_test_flags+=(-fsanitize=address,undefined -fno-omit-frame-pointer)
fi
read -r -a tf_test_glib <<<"$(pkg-config --cflags --libs glib-2.0)"
"$tf_test_cc" "${tf_test_flags[@]}" -Iunpacker/test tests/test_phase1_io.c \
    unpacker/test/phase1_io.c "${tf_test_glib[@]}" -Wl,--wrap=fclose -o "$tf_test_tmp/test_phase1_io"
"$tf_test_tmp/test_phase1_io"
PYTHONPATH="$tf_test_root:$tf_test_root/tests${PYTHONPATH:+:$PYTHONPATH}" \
    "${TF_PYTHON:-python3}" -m unittest -q test_phase1_runtime test_attempt \
    test_environment_manifest test_execution_backend test_replay_store
