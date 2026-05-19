#!/usr/bin/env bash
# Reapply local vllm-mlx patches after a fresh pip install on studio1.
#
# Run from any directory on the Mac that hosts the vllm-mlx venv. Resolves
# the engine path via the venv's Python so it doesn't bake in a Python
# minor-version.
#
# Patches applied (in order):
#   1. multi_slot_lru_for_system_kv.patch
#        Replaces SimpleEngine's single-slot system-KV snapshot with an
#        OrderedDict LRU keyed by system-prefix hash. Capacity is
#        ``VLLM_MLX_SYSTEM_KV_SLOTS`` (default 4). Lets the main agent +
#        sub-agents coexist without thrashing the snapshot when Claude
#        Code (or any tool-calling client) alternates between system
#        prompts of different sizes.
#
# Usage:
#   bash deployment/vllm_mlx_patches/apply.sh /path/to/vllm-venv
#
# Reverts the touched file from a `.pre-multi-slot-lru` backup if the patch
# already applied cleanly once and you want to re-apply.

set -euo pipefail

VENV="${1:-${VLLM_MLX_VENV:-$HOME/vllm-venv}}"
PATCH_DIR="$(cd "$(dirname "$0")" && pwd)"

if [[ ! -x "$VENV/bin/python" ]]; then
  echo "ERROR: $VENV/bin/python not found. Pass the venv path as arg 1." >&2
  exit 1
fi

ENGINE_DIR=$("$VENV/bin/python" -c "import vllm_mlx.engine, os; print(os.path.dirname(vllm_mlx.engine.__file__))")
TARGET="$ENGINE_DIR/simple.py"

if [[ ! -f "$TARGET" ]]; then
  echo "ERROR: $TARGET not found." >&2
  exit 1
fi

BACKUP="$TARGET.pre-multi-slot-lru"
if [[ ! -f "$BACKUP" ]]; then
  cp "$TARGET" "$BACKUP"
  echo "Backed up original to $BACKUP"
fi

cd "$ENGINE_DIR"
if patch --dry-run -p1 < "$PATCH_DIR/multi_slot_lru_for_system_kv.patch" >/dev/null 2>&1; then
  patch -p1 < "$PATCH_DIR/multi_slot_lru_for_system_kv.patch"
  echo "Applied multi_slot_lru_for_system_kv.patch"
elif grep -q '_system_kv_cache: "OrderedDict' "$TARGET"; then
  echo "Patch already applied; skipping."
else
  echo "ERROR: patch does not apply cleanly. Inspect manually." >&2
  exit 2
fi

"$VENV/bin/python" -c "import ast; ast.parse(open('$TARGET').read()); print('post-patch syntax OK')"
