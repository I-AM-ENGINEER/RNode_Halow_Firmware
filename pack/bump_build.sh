#!/bin/sh
# Bump the per-build counter and regenerate inc/build_info_gen.h so every build
# carries a unique, monotonic build number. Invoked from the Makefile via
# $(shell ...) at parse time (before any target runs). Best-effort: never aborts
# the build -- on any failure the header is left as-is (stale number) and the
# build proceeds normally.
#
# Counter is persisted in build_number.txt (single integer). Only
# inc/build_info_gen.h changes per build, and only config_api_calls.c includes
# it, so exactly one translation unit recompiles each build -- incremental
# builds stay fast while the version string still updates.

NUM_FILE="build_number.txt"
HDR="inc/build_info_gen.h"

NUM=0
if [ -f "$NUM_FILE" ]; then
    read NUM < "$NUM_FILE" 2>/dev/null || NUM=0
fi
NUM=$((NUM + 1))
printf '%s\n' "$NUM" > "$NUM_FILE" 2>/dev/null || exit 0

DATE=$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "unknown")

cat > "$HDR" <<EOF
/* AUTO-REGENERATED on every build by pack/bump_build.sh - do not edit.
 * Build number: ${NUM} */
#ifndef __BUILD_INFO_GEN_H__
#define __BUILD_INFO_GEN_H__
#define FW_BUILD_NUMBER      ${NUM}
#define FW_BUILD_NUMBER_STR  "${NUM}"
#define FW_BUILD_DATE        "${DATE}"
#endif
EOF
