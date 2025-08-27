#!/usr/bin/env python3
"""
Model Switcher for Pokedex

Allows quick switching between different models for testing and performance tuning.
Usage: python switch_model.py [model_name]
"""

import sys
import os
import subprocess
import logging
from bot.utils.enhanced_config import ModelConfig

# Available model presets for easy switching
MODEL_PRESETS = {
    '70b': 'llama3.1:70b',       # Best quality, slowest startup
    '32b': 'qwen2.5:32b',        # Good quality, medium startup  
    '14b': 'qwen2.5:14b',        # Decent quality, faster startup
    '8b': 'llama3.1:8b',         # Basic quality, fast startup
    'nemo': 'mistral-nemo:latest', # Alternative 12B model
    'phi4': 'phi4:latest'        # Microsoft's efficient model
}

def show_available_models():
    """Show available models locally and presets"""
    print("\n🤖 Available Model Presets:")
    print("=" * 50)
    for preset, model_name in MODEL_PRESETS.items():
        print(f"  {preset:8} -> {model_name}")
    
    print(f"\n📦 Models Available Locally:")
    print("=" * 50)
    try:
        result = subprocess.run(['ollama', 'list'], capture_output=True, text=True)
        if result.returncode == 0:
            print(result.stdout)
        else:
            print("❌ Error listing models")
    except Exception as e:
        print(f"❌ Error checking ollama: {e}")
    
    print(f"\n🔄 Currently Loaded Models:")
    print("=" * 50)
    try:
        result = subprocess.run(['ollama', 'ps'], capture_output=True, text=True)
        if result.returncode == 0:
            if result.stdout.strip():
                print(result.stdout)
            else:
                print("No models currently loaded")
        else:
            print("❌ Error checking loaded models")
    except Exception as e:
        print(f"❌ Error checking ollama: {e}")

def switch_model(model_identifier: str):
    """Switch to the specified model"""
    
    # Resolve preset to actual model name
    if model_identifier in MODEL_PRESETS:
        model_name = MODEL_PRESETS[model_identifier]
        print(f"🔄 Using preset '{model_identifier}' -> {model_name}")
    else:
        model_name = model_identifier
        print(f"🔄 Using model: {model_name}")
    
    # Check if model exists locally
    try:
        result = subprocess.run(['ollama', 'list'], capture_output=True, text=True)
        if result.returncode == 0 and model_name not in result.stdout:
            print(f"📥 Model {model_name} not found locally. Pulling from registry...")
            pull_result = subprocess.run(['ollama', 'pull', model_name], capture_output=False)
            if pull_result.returncode != 0:
                print(f"❌ Failed to pull model {model_name}")
                return False
    except Exception as e:
        print(f"❌ Error checking model availability: {e}")
        return False
    
    # Update the configuration
    try:
        print(f"📝 Updating configuration to use {model_name}...")
        
        # Read current config
        config_file = os.path.join(os.path.dirname(__file__), "bot", "utils", "enhanced_config.py")
        
        with open(config_file, 'r') as f:
            content = f.read()
        
        # Replace the model name in the default configuration
        updated_content = content.replace(
            f'llm_model_name: str = "llama3.1:70b"',
            f'llm_model_name: str = "{model_name}"'
        )
        
        # Also update any other model references
        for old_model in MODEL_PRESETS.values():
            if old_model != model_name and old_model in updated_content:
                updated_content = updated_content.replace(
                    f'llm_model_name: str = "{old_model}"',
                    f'llm_model_name: str = "{model_name}"'
                )
        
        with open(config_file, 'w') as f:
            f.write(updated_content)
        
        print(f"✅ Configuration updated successfully!")
        print(f"🚀 Model switched to: {model_name}")
        
        # Try to preload the model
        print(f"🔥 Pre-loading {model_name}...")
        load_result = subprocess.run(['ollama', 'run', model_name, 'ping'], 
                                   capture_output=True, text=True, timeout=60)
        
        if load_result.returncode == 0:
            print(f"✅ Model {model_name} loaded successfully")
        else:
            print(f"⚠️ Model switched but may need manual loading")
        
        print(f"\n🔄 Restart Pokedex to use the new model:")
        print(f"   ./kill_pokedex.sh && ./run_pokedex_optimized.sh")
        
        return True
        
    except Exception as e:
        print(f"❌ Error updating configuration: {e}")
        return False

def get_current_model():
    """Get the currently configured model"""
    try:
        config = ModelConfig()
        return config.llm_model_name
    except Exception as e:
        print(f"❌ Error getting current model: {e}")
        return "Unknown"

def show_performance_comparison():
    """Show approximate performance comparison of models"""
    print("\n⚡ Performance Comparison (Approximate):")
    print("=" * 60)
    print("Model          Size    Quality   Startup    Memory   Response")
    print("-" * 60)
    print("llama3.1:70b   42GB    ★★★★★     ~45s      42GB     ~5-15s")
    print("qwen2.5:32b    19GB    ★★★★      ~15s      19GB     ~3-8s") 
    print("qwen2.5:14b    9GB     ★★★       ~8s       9GB      ~2-5s")
    print("llama3.1:8b    5GB     ★★★       ~5s       5GB      ~1-3s")
    print("mistral-nemo   7GB     ★★★       ~6s       7GB      ~2-4s")
    print("phi4           9GB     ★★★★      ~8s       9GB      ~2-5s")
    print("-" * 60)
    print("★ = Quality rating (subjective)")

def main():
    if len(sys.argv) < 2:
        print(f"🤖 Current Model: {get_current_model()}")
        show_available_models()
        show_performance_comparison()
        print(f"\nUsage: python {sys.argv[0]} <model_preset_or_name>")
        print(f"       python {sys.argv[0]} 8b          # Switch to llama3.1:8b")
        print(f"       python {sys.argv[0]} 70b         # Switch to llama3.1:70b") 
        print(f"       python {sys.argv[0]} qwen2.5:32b # Switch to specific model")
        return
    
    model_identifier = sys.argv[1]
    
    if model_identifier == "list":
        show_available_models()
        show_performance_comparison()
    elif model_identifier == "current":
        print(f"🤖 Current Model: {get_current_model()}")
    else:
        success = switch_model(model_identifier)
        if not success:
            sys.exit(1)

if __name__ == "__main__":
    main()