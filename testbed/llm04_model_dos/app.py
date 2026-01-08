"""
LLM04: Model Denial of Service - Synthetic Vulnerable Application
This module contains intentional vulnerabilities for testing purposes.
"""

import os
from openai import OpenAI
from flask import Flask, request

app = Flask(__name__)
client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))


# VULN:LLM04:HIGH:LINE=17 - No input length limits
@app.route("/chat", methods=["POST"])
def vulnerable_no_input_limit():
    """Vulnerable: No limit on input size."""
    user_input = request.json.get("message", "")
    # VULNERABLE - accepts arbitrarily long input
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": user_input}]
    )
    return {"response": response.choices[0].message.content}


# VULN:LLM04:HIGH:LINE=29 - No output token limits
def vulnerable_no_output_limit(prompt: str) -> str:
    """Vulnerable: No max_tokens set, allows maximum generation."""
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
        # VULNERABLE - no max_tokens limit
    )
    return response.choices[0].message.content


# VULN:LLM04:MEDIUM:LINE=40 - No rate limiting
@app.route("/unlimited", methods=["POST"])
def vulnerable_no_rate_limit():
    """Vulnerable: No rate limiting on API endpoint."""
    # VULNERABLE - no rate limiting
    user_input = request.json.get("message", "")
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": user_input}]
    )
    return {"response": response.choices[0].message.content}


# VULN:LLM04:HIGH:LINE=53 - No timeout handling
def vulnerable_no_timeout(prompt: str) -> str:
    """Vulnerable: No timeout on LLM API call."""
    # VULNERABLE - no timeout, can hang indefinitely
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content


# VULN:LLM04:MEDIUM:LINE=64 - Recursive prompt generation
def vulnerable_recursive_generation(prompt: str, depth: int = 0) -> str:
    """Vulnerable: Allows recursive/chained prompt generation."""
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    result = response.choices[0].message.content

    # VULNERABLE - can recurse indefinitely
    if "CONTINUE" in result and depth < 100:
        return vulnerable_recursive_generation(result, depth + 1)
    return result


# VULN:LLM04:HIGH:LINE=79 - Unbounded context accumulation
class VulnerableConversation:
    """Vulnerable: Context grows without bounds."""

    def __init__(self):
        self.messages = []

    def chat(self, user_input: str) -> str:
        self.messages.append({"role": "user", "content": user_input})
        # VULNERABLE - context grows indefinitely
        response = client.chat.completions.create(
            model="gpt-4",
            messages=self.messages
        )
        assistant_msg = response.choices[0].message.content
        self.messages.append({"role": "assistant", "content": assistant_msg})
        return assistant_msg


# SAFE: Proper resource limits (for comparison)
def safe_chat_with_limits(prompt: str) -> str:
    """Safe: Proper limits on input/output and timeout."""
    # Input validation
    if len(prompt) > 4000:
        raise ValueError("Input too long")

    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=500,  # Limit output
        timeout=30  # Timeout
    )
    return response.choices[0].message.content
