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


# =============================================================================
# CONFIRMER PATTERNS - Dynamic fetch + exec (should be HIGH/CRITICAL)
# =============================================================================

# VULN:LLM05:CRITICAL:LINE=83 - Download + exec pattern (strong confirmer)
def vulnerable_fetch_and_exec(script_url: str):
    """Vulnerable: Fetching and executing remote code."""
    import requests
    response = requests.get(script_url)
    code = response.text
    # VULNERABLE - fetching and executing remote code
    exec(code)


# VULN:LLM05:CRITICAL:LINE=93 - Download + subprocess pattern
def vulnerable_download_and_run(url: str):
    """Vulnerable: Downloading and running external script."""
    import requests
    response = requests.get(url)
    script_path = "/tmp/script.sh"
    with open(script_path, "w") as f:
        f.write(response.text)
    # VULNERABLE - executing downloaded script
    subprocess.run(["bash", script_path], check=True)


# VULN:LLM05:CRITICAL:LINE=105 - Dynamic import from network
def vulnerable_dynamic_import(module_url: str):
    """Vulnerable: Dynamically importing code from network."""
    import importlib.util
    import requests
    import tempfile

    response = requests.get(module_url)
    with tempfile.NamedTemporaryFile(suffix='.py', delete=False) as f:
        f.write(response.content)
        temp_path = f.name

    # VULNERABLE - loading and executing remote module
    spec = importlib.util.spec_from_file_location("remote_module", temp_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# =============================================================================
# SAFE PATTERNS - These should NOT be flagged (test FP reduction)
# =============================================================================

# SAFE: Verified model loading with checksum
def safe_load_model_with_checksum(model_name: str, expected_sha256: str):
    """Safe: Load model with SHA256 checksum verification."""
    import hashlib
    from transformers import AutoModelForCausalLM
    from huggingface_hub import hf_hub_download

    # Download with explicit checksum
    model_path = hf_hub_download(
        repo_id=model_name,
        filename="model.safetensors",
        revision="main"
    )

    # Verify checksum
    with open(model_path, "rb") as f:
        actual_sha256 = hashlib.sha256(f.read()).hexdigest()

    if actual_sha256 != expected_sha256:
        raise ValueError(f"Checksum mismatch: {actual_sha256} != {expected_sha256}")

    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        trust_remote_code=False,  # Don't trust remote code
    )
    return model


# SAFE: Using safetensors format instead of pickle
def safe_load_safetensors(model_path: str):
    """Safe: Loading model using safetensors (no code execution)."""
    from safetensors import safe_open

    # safetensors cannot execute code - only loads tensors
    tensors = {}
    with safe_open(model_path, framework="pt", device="cpu") as f:
        for key in f.keys():
            tensors[key] = f.get_tensor(key)
    return tensors


# SAFE: torch.load with weights_only=True
def safe_torch_load(model_path: str):
    """Safe: Loading PyTorch model with weights_only=True."""
    import torch

    # weights_only=True prevents pickle code execution
    model = torch.load(model_path, weights_only=True)
    return model


# SAFE: Verified download with HTTPS and checksum
def safe_download_with_verification(url: str, expected_sha256: str) -> str:
    """Safe: Download file with HTTPS and verify checksum."""
    import hashlib
    import requests
    from urllib.parse import urlparse

    # Ensure HTTPS
    parsed = urlparse(url)
    if parsed.scheme != 'https':
        raise ValueError("Only HTTPS URLs are allowed")

    # Download with verification
    response = requests.get(url, verify=True)
    response.raise_for_status()

    # Verify checksum before saving
    content = response.content
    actual_sha256 = hashlib.sha256(content).hexdigest()

    if actual_sha256 != expected_sha256:
        raise ValueError(f"Checksum mismatch: {actual_sha256} != {expected_sha256}")

    local_path = "/tmp/verified_model.bin"
    with open(local_path, "wb") as f:
        f.write(content)

    return local_path


# SAFE: Pinned package installation from allowlist
def safe_install_package(package_name: str):
    """Safe: Installing packages from allowlist with pinned versions."""
    ALLOWED_PACKAGES = {
        "numpy": "1.24.0",
        "pandas": "2.0.0",
        "scikit-learn": "1.3.0",
    }

    if package_name not in ALLOWED_PACKAGES:
        raise ValueError(f"Package {package_name} not in allowlist")

    version = ALLOWED_PACKAGES[package_name]
    # SAFE - installing pinned version from allowlist
    subprocess.run(
        ["pip", "install", f"{package_name}=={version}"],
        check=True
    )
    return __import__(package_name)


# SAFE: Loading model from verified local path only
def safe_load_local_model(model_dir: str):
    """Safe: Loading model from verified local directory."""
    import os
    from transformers import AutoModelForCausalLM

    # Validate path is within allowed directory
    ALLOWED_MODEL_DIR = "/opt/models"
    abs_path = os.path.abspath(model_dir)
    if not abs_path.startswith(ALLOWED_MODEL_DIR):
        raise ValueError(f"Model path must be within {ALLOWED_MODEL_DIR}")

    model = AutoModelForCausalLM.from_pretrained(
        abs_path,
        trust_remote_code=False,
        local_files_only=True  # Don't download anything
    )
    return model


# SAFE: JSON config instead of eval
def safe_json_config(config_path: str) -> dict:
    """Safe: Loading config as JSON instead of eval."""
    import json

    with open(config_path, "r") as f:
        # SAFE - json.load cannot execute code
        config = json.load(f)
    return config


# SAFE: Signature verification for downloads
def safe_download_with_signature(url: str, signature_url: str, public_key: str) -> str:
    """Safe: Download with GPG signature verification."""
    import requests
    import gnupg

    gpg = gnupg.GPG()

    # Download file and signature
    response = requests.get(url, verify=True)
    sig_response = requests.get(signature_url, verify=True)

    # Write to temp files
    content_path = "/tmp/downloaded_file"
    sig_path = "/tmp/downloaded_file.sig"

    with open(content_path, "wb") as f:
        f.write(response.content)
    with open(sig_path, "wb") as f:
        f.write(sig_response.content)

    # Verify signature
    with open(sig_path, "rb") as f:
        verified = gpg.verify_file(f, content_path)

    if not verified:
        raise ValueError("Signature verification failed")

    return content_path
