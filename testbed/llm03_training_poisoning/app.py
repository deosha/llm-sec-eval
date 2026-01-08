"""
LLM03: Training Data Poisoning - Synthetic Vulnerable Application
This module contains intentional vulnerabilities for testing purposes.
"""

import os
import pickle
import json
import requests
from typing import List, Dict

# VULN:LLM03:HIGH:LINE=14 - Loading training data from untrusted URL
def vulnerable_load_remote_data(url: str) -> List[Dict]:
    """Vulnerable: Loading training data from untrusted source."""
    response = requests.get(url)  # VULNERABLE - no validation
    data = response.json()
    return data


# VULN:LLM03:CRITICAL:LINE=23 - Pickle loading without verification
def vulnerable_load_dataset(path: str) -> object:
    """Vulnerable: Using pickle to load dataset without verification."""
    with open(path, "rb") as f:
        dataset = pickle.load(f)  # VULNERABLE - arbitrary code execution
    return dataset


# VULN:LLM03:HIGH:LINE=32 - No data validation before fine-tuning
def vulnerable_finetune_data(data_path: str) -> List[Dict]:
    """Vulnerable: Loading fine-tuning data without validation."""
    with open(data_path, "r") as f:
        training_data = json.load(f)  # VULNERABLE - no schema validation
    # No content filtering or validation
    return training_data


# VULN:LLM03:MEDIUM:LINE=43 - User-submitted data used in training
def vulnerable_user_feedback_training(feedback: str, response: str) -> Dict:
    """Vulnerable: User feedback directly used for training without review."""
    training_example = {
        "prompt": feedback,
        "completion": response  # VULNERABLE - no content moderation
    }
    save_to_training_queue(training_example)
    return training_example


# VULN:LLM03:HIGH:LINE=54 - Torch model loading without verification
def vulnerable_load_torch_model(url: str):
    """Vulnerable: Loading PyTorch model from untrusted source."""
    import torch
    # Download and load without verification
    model_path = download_file(url)
    model = torch.load(model_path)  # VULNERABLE - pickle under the hood
    return model


# VULN:LLM03:MEDIUM:LINE=65 - No provenance tracking
class VulnerableDataPipeline:
    """Vulnerable: No data provenance or integrity tracking."""

    def __init__(self):
        self.data = []

    def add_data(self, source: str):
        """Add data from any source without tracking."""
        data = self.fetch_data(source)
        self.data.extend(data)  # VULNERABLE - no provenance

    def fetch_data(self, source: str) -> List:
        return requests.get(source).json()


# Helper functions
def save_to_training_queue(example: Dict) -> None:
    """Save training example to queue."""
    pass

def download_file(url: str) -> str:
    """Download file from URL."""
    return "/tmp/model.pt"


# SAFE: Validated data loading (for comparison)
def safe_load_training_data(path: str, schema: Dict) -> List[Dict]:
    """Safe: Validate training data against schema."""
    import jsonschema
    with open(path, "r") as f:
        data = json.load(f)

    # Validate against schema
    for item in data:
        jsonschema.validate(item, schema)

    # Content filtering
    filtered = [item for item in data if is_safe_content(item)]
    return filtered


def is_safe_content(item: Dict) -> bool:
    """Check if content is safe for training."""
    # Implement content moderation
    return True
