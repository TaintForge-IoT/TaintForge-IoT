#!/usr/bin/env bash
set -euo pipefail
if (( $# != 1 )); then
    printf 'Usage: %s PROJECT\nSource verified environment.sh first.\n' "$0" >&2
    exit 2
fi
tf_cv_package=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
tf_cv_project=$(cd -- "$1" && pwd)
if [[ ! -d "$tf_cv_project/unpacker" ]]; then
    printf 'Project unpacker directory is missing.\n' >&2
    exit 2
fi
tf_cv_output=$(mktemp -d "$tf_cv_project/unpacker/controlled-corpus.XXXXXXXX")
printf 'Results: %s\n' "$tf_cv_output"
exec python3 "$tf_cv_package/cv_runner.py" \
    --project "$tf_cv_project" --output "$tf_cv_output/probe"
