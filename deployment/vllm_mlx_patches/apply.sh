#!/usr/bin/env bash
# Apply local vllm-mlx patches to a vllm-mlx install.
#
# Idempotent: skips a patch if its marker is already present.
# Run on each Mac that hosts a vllm-mlx instance after installing or upgrading
# the vllm-mlx package. Re-run after every `pip install --upgrade vllm-mlx`.
#
# Usage:
#   ./apply.sh              # auto-detect site-packages from `python -c ...`
#   ./apply.sh /path/to/venv # use a specific venv
#
# Each patch lives next to this script as <name>.patch; see README in this
# directory for what each one does.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Resolve site-packages of the target vllm-mlx
if [[ $# -ge 1 ]]; then
  VENV_PYTHON="$1/bin/python"
else
  VENV_PYTHON="${VENV_PYTHON:-$(command -v python3)}"
fi

VLLM_MLX_DIR="$("$VENV_PYTHON" -c \
  'import os, vllm_mlx; print(os.path.dirname(vllm_mlx.__file__))')"

if [[ ! -d "$VLLM_MLX_DIR" ]]; then
  echo "vllm_mlx not found via $VENV_PYTHON" >&2
  exit 1
fi

echo "Patching vllm_mlx at: $VLLM_MLX_DIR"

apply_patch() {
  local patch_file="$1"
  local marker="$2"   # any unique substring the patch introduces
  local target="$3"   # path relative to $VLLM_MLX_DIR

  local target_full="$VLLM_MLX_DIR/$target"

  if grep -q -F "$marker" "$target_full"; then
    echo "  [skip] $(basename "$patch_file") — marker already present in $target"
    return
  fi

  cp "$target_full" "$target_full.pre-$(basename "$patch_file" .patch)"
  # Patch labels are `vllm_mlx/engine/simple.py`; cwd is the package root,
  # so -p1 strips the leading `vllm_mlx/` to match `engine/simple.py`.
  ( cd "$VLLM_MLX_DIR" && patch -p1 < "$patch_file" )
  # Drop stale bytecode so the new source is loaded
  find "$VLLM_MLX_DIR" -name "__pycache__" -type d -prune -exec rm -rf {} +
  echo "  [done] $(basename "$patch_file")"
}

apply_patch \
  "$SCRIPT_DIR/system_kv_cache_for_simple_engine.patch" \
  "System KV cache HIT (pure-LLM)" \
  "engine/simple.py"

echo "All patches applied. Restart the vllm-mlx launchctl agent to pick them up:"
echo "  launchctl bootout gui/\$(id -u)/com.ir.vllm-mlx-coder"
echo "  launchctl bootstrap gui/\$(id -u) ~/Library/LaunchAgents/com.ir.vllm-mlx-coder.plist"
