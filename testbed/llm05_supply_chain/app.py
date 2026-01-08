"""
LLM05: Supply Chain Vulnerabilities - Synthetic Vulnerable Application
This module contains intentional vulnerabilities for testing purposes.
"""

import os
import subprocess

# VULN:LLM05:CRITICAL:LINE=11 - Loading model from untrusted source
def vulnerable_load_huggingface_model(model_name: str):
    """Vulnerable: Loading model from Hugging Face without verification."""
    from transformers import AutoModelForCausalLM, AutoTokenizer
    # VULNERABLE - no checksum or signature verification
    model = AutoModelForCausalLM.from_pretrained(model_name, trust_remote_code=True)
    tokenizer = AutoTokenizer.from_pretrained(model_name, trust_remote_code=True)
    return model, tokenizer


# VULN:LLM05:HIGH:LINE=22 - Pickle model loading
def vulnerable_load_pickle_model(path: str):
    """Vulnerable: Loading model with pickle."""
    import pickle
    with open(path, "rb") as f:
        model = pickle.load(f)  # VULNERABLE - arbitrary code execution
    return model


# VULN:LLM05:HIGH:LINE=32 - torch.load without weights_only
def vulnerable_torch_load(path: str):
    """Vulnerable: Loading PyTorch model unsafely."""
    import torch
    # VULNERABLE - pickle under the hood
    model = torch.load(path)
    return model


# VULN:LLM05:MEDIUM:LINE=41 - Downloading model without HTTPS
def vulnerable_download_model(url: str) -> str:
    """Vulnerable: Downloading model over insecure connection."""
    import urllib.request
    # VULNERABLE - could be HTTP, no certificate verification
    local_path = "/tmp/model.bin"
    urllib.request.urlretrieve(url, local_path)
    return local_path


# VULN:LLM05:HIGH:LINE=52 - Installing packages at runtime
def vulnerable_dynamic_install(package_name: str):
    """Vulnerable: Installing packages dynamically without verification."""
    # VULNERABLE - arbitrary package installation
    subprocess.run(["pip", "install", package_name], check=True)
    return __import__(package_name)


# VULN:LLM05:MEDIUM:LINE=61 - Using unpinned dependencies
# Note: This vulnerability is in requirements.txt, not code
# requirements.txt contains: langchain, openai, transformers (no versions)


# VULN:LLM05:HIGH:LINE=67 - Executing third-party LangChain tools
def vulnerable_langchain_tools(tool_name: str):
    """Vulnerable: Loading arbitrary LangChain community tools."""
    from langchain_community.tools import load_tools
    # VULNERABLE - loading unverified community tools
    tools = load_tools([tool_name])
    return tools


# VULN:LLM05:CRITICAL:LINE=77 - eval in GGUF/GGML model loading
def vulnerable_gguf_config(config_path: str):
    """Vulnerable: Loading GGUF config with eval."""
    with open(config_path, "r") as f:
        config_str = f.read()
    # VULNERABLE - eval on config file
    config = eval(config_str)
    return config


# SAFE: Verified model loading (for comparison)
def safe_load_model(model_name: str, expected_sha256: str):
    """Safe: Load model with checksum verification."""
    import hashlib
    from transformers import AutoModelForCausalLM

    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        trust_remote_code=False,  # Don't trust remote code
        revision="main"
    )

    # Verify checksum (simplified)
    # In practice, verify model files against known checksums
    return model
