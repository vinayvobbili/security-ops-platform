#!/usr/bin/env python3
"""Wrapper to launch vllm-mlx server with tool call parsing and chat template overrides.

vllm-mlx has built-in tool parsers (qwen, llama, hermes, auto, etc.)
but doesn't expose them via CLI flags. This wrapper sets the internal
globals before calling main() so the server parses tool calls from
model output into OpenAI-compatible tool_calls format.

It also supports --chat-template to override the model's default chat
template (e.g. to disable thinking mode on GLM-4.7-Flash).

Usage:
    python deployment/vllm_mlx_server.py --tool-call-parser glm47 \
        --chat-template deployment/chat_templates/glm4_no_think.jinja \
        --model mlx-community/GLM-4.7-Flash-4bit --port 8000

    Accepts all standard vllm_mlx.server flags plus:
        --enable-auto-tool-choice   Enable tool call parsing (auto-set if --tool-call-parser given)
        --tool-call-parser NAME     Parser: auto, qwen, llama, hermes, deepseek, glm47, etc.
        --chat-template PATH        Override the model's chat template with a custom Jinja file
        --served-model-name NAME    Public model id reported via /v1/models and accepted in
                                    chat completion requests (defaults to the value of --model)
"""

import argparse
import os
import shutil
import sys


def _apply_chat_template(model_name, template_path):
    """Copy a custom chat template into the HuggingFace cache for the model.

    This runs before the server loads the model, so the tokenizer picks up
    the patched template instead of the upstream default.
    """
    from huggingface_hub import scan_cache_dir

    cache_info = scan_cache_dir()
    for repo in cache_info.repos:
        if repo.repo_id == model_name:
            for revision in repo.revisions:
                target = os.path.join(revision.snapshot_path, "chat_template.jinja")
                if os.path.exists(target):
                    shutil.copy2(template_path, target)
                    print(f"[wrapper] Chat template override: {template_path} -> {target}")
                    return True
    print(f"[wrapper] WARNING: Could not find cached model {model_name} to patch chat template")
    return False


def main():
    # Pre-parse our extra flags before vllm-mlx sees argv
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument("--enable-auto-tool-choice", action="store_true")
    pre_parser.add_argument("--tool-call-parser", type=str, default=None)
    pre_parser.add_argument("--chat-template", type=str, default=None)
    pre_parser.add_argument("--served-model-name", type=str, default=None)
    pre_args, remaining = pre_parser.parse_known_args()

    # Peek at --model without consuming it (vllm-mlx needs it too)
    model_parser = argparse.ArgumentParser(add_help=False)
    model_parser.add_argument("--model", type=str, default=None)
    model_args, _ = model_parser.parse_known_args()

    # Remove only our custom flags from sys.argv; keep everything vllm-mlx needs
    sys.argv = [sys.argv[0]] + remaining

    # Apply chat template override before model loads
    if pre_args.chat_template and model_args.model:
        template_path = os.path.abspath(pre_args.chat_template)
        if not os.path.exists(template_path):
            print(f"[wrapper] ERROR: Chat template not found: {template_path}")
            sys.exit(1)
        _apply_chat_template(model_args.model, template_path)

    # Import and configure vllm-mlx internals
    import vllm_mlx.server as server

    if pre_args.tool_call_parser or pre_args.enable_auto_tool_choice:
        server._enable_auto_tool_choice = True
        server._tool_call_parser = pre_args.tool_call_parser or "auto"
        print(f"[wrapper] Tool call parsing enabled: {server._tool_call_parser}")

    # vllm-mlx supports served_model_name internally (server.load_model accepts it)
    # but doesn't expose it via CLI. Wrap load_model to inject it.
    if pre_args.served_model_name:
        original_load_model = server.load_model

        def patched_load_model(*args, **kwargs):
            kwargs["served_model_name"] = pre_args.served_model_name
            return original_load_model(*args, **kwargs)

        server.load_model = patched_load_model
        print(f"[wrapper] Served model name: {pre_args.served_model_name}")

    # Run the standard server
    server.main()


if __name__ == "__main__":
    main()
