"""
LLM10: Model Theft - Synthetic Vulnerable Application
This module contains intentional vulnerabilities for testing purposes.
"""

import os
from flask import Flask, request, jsonify
from openai import OpenAI

app = Flask(__name__)
client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))


# VULN:LLM10:HIGH:LINE=16 - No rate limiting on model API
@app.route("/api/generate", methods=["POST"])
def vulnerable_no_rate_limit():
    """Vulnerable: No rate limiting allows model extraction queries."""
    prompt = request.json.get("prompt", "")
    # VULNERABLE - unlimited queries for extraction
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    return jsonify({"response": response.choices[0].message.content})


# VULN:LLM10:HIGH:LINE=29 - Exposing model internals
@app.route("/api/model-info", methods=["GET"])
def vulnerable_model_info():
    """Vulnerable: Exposes model configuration and internals."""
    # VULNERABLE - leaking model details
    model_info = {
        "model": "gpt-4-custom-finetuned",
        "temperature": 0.7,
        "system_prompt": "You are a helpful financial advisor...",
        "fine_tuning_data": "internal_finance_corpus_v2",
        "embeddings_model": "text-embedding-ada-002"
    }
    return jsonify(model_info)


# VULN:LLM10:MEDIUM:LINE=44 - No authentication on API
@app.route("/api/chat", methods=["POST"])
def vulnerable_no_auth():
    """Vulnerable: API endpoint without authentication."""
    # VULNERABLE - no API key or auth required
    prompt = request.json.get("prompt", "")
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    return jsonify({"response": response.choices[0].message.content})


# VULN:LLM10:HIGH:LINE=58 - Returning embeddings directly
@app.route("/api/embeddings", methods=["POST"])
def vulnerable_embeddings():
    """Vulnerable: Returns raw embeddings, enabling model extraction."""
    text = request.json.get("text", "")
    # VULNERABLE - exposes embeddings
    response = client.embeddings.create(
        model="text-embedding-ada-002",
        input=text
    )
    return jsonify({"embedding": response.data[0].embedding})


# VULN:LLM10:HIGH:LINE=72 - Exposing logprobs for extraction
@app.route("/api/logprobs", methods=["POST"])
def vulnerable_logprobs():
    """Vulnerable: Returns logprobs enabling model distillation."""
    prompt = request.json.get("prompt", "")
    # VULNERABLE - logprobs can be used for distillation
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
        logprobs=True,
        top_logprobs=5
    )
    return jsonify({
        "response": response.choices[0].message.content,
        "logprobs": response.choices[0].logprobs  # Leak for extraction
    })


# VULN:LLM10:MEDIUM:LINE=90 - Model weights accessible via API
@app.route("/api/model-weights", methods=["GET"])
def vulnerable_weights_endpoint():
    """Vulnerable: Endpoint that could expose model weights."""
    # VULNERABLE - model weights accessible
    model_path = "/models/custom_model.pt"
    return {"path": model_path, "accessible": True}


# VULN:LLM10:HIGH:LINE=100 - No query logging for extraction detection
class VulnerableModelAPI:
    """Vulnerable: No logging to detect extraction attempts."""

    def __init__(self):
        self.model = self._load_model()

    def _load_model(self):
        return None  # Placeholder

    def query(self, prompt: str) -> str:
        # VULNERABLE - no logging of queries
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}]
        )
        return response.choices[0].message.content


# SAFE: Protected model API (for comparison)
@app.route("/api/protected/chat", methods=["POST"])
def safe_protected_api():
    """Safe: Properly protected model API."""
    # Authentication
    api_key = request.headers.get("X-API-Key")
    if not api_key or not validate_api_key(api_key):
        return jsonify({"error": "Unauthorized"}), 401

    # Rate limiting
    if is_rate_limited(api_key):
        return jsonify({"error": "Rate limited"}), 429

    # Log for anomaly detection
    log_query(api_key, request.json)

    prompt = request.json.get("prompt", "")
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )

    # Don't expose logprobs
    return jsonify({"response": response.choices[0].message.content})


def validate_api_key(key: str) -> bool:
    return True  # Placeholder


def is_rate_limited(key: str) -> bool:
    return False  # Placeholder


def log_query(key: str, data: dict) -> None:
    pass  # Placeholder
