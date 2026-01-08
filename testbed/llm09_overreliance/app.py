"""
LLM09: Overreliance - Synthetic Vulnerable Application
This module contains intentional vulnerabilities for testing purposes.
"""

import os
from openai import OpenAI

client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))


# VULN:LLM09:HIGH:LINE=14 - Auto-applying LLM-generated code
def vulnerable_auto_apply_code(description: str) -> str:
    """Vulnerable: Automatically applies LLM-generated code without review."""
    prompt = f"Write a Python function to: {description}"
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    code = response.choices[0].message.content

    # VULNERABLE - applying code without human review
    with open("generated_code.py", "w") as f:
        f.write(code)

    # Auto-import and use
    import importlib.util
    spec = importlib.util.spec_from_file_location("generated", "generated_code.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return "Code applied"


# VULN:LLM09:HIGH:LINE=35 - Medical/legal advice without disclaimer
def vulnerable_medical_advice(symptoms: str) -> str:
    """Vulnerable: Provides medical advice without proper disclaimers."""
    prompt = f"Based on these symptoms: {symptoms}, what is the diagnosis and treatment?"
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    # VULNERABLE - no disclaimer, presented as authoritative
    return response.choices[0].message.content


# VULN:LLM09:HIGH:LINE=48 - Security decisions based on LLM output
def vulnerable_security_decision(request: str) -> bool:
    """Vulnerable: Makes security decisions based on LLM recommendation."""
    prompt = f"Should I allow this request? {request}. Answer yes or no."
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    decision = response.choices[0].message.content.lower()

    # VULNERABLE - security decision based on LLM output
    if "yes" in decision:
        return True
    return False


# VULN:LLM09:MEDIUM:LINE=64 - No confidence indicators
def vulnerable_no_confidence(query: str) -> dict:
    """Vulnerable: Returns answers without confidence or uncertainty indicators."""
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": query}]
    )
    # VULNERABLE - no confidence score, presented as certain
    return {
        "answer": response.choices[0].message.content,
        # Missing: confidence, sources, uncertainty
    }


# VULN:LLM09:MEDIUM:LINE=78 - No source citations
def vulnerable_no_citations(question: str) -> str:
    """Vulnerable: Factual claims without source citations."""
    prompt = f"Answer this factual question: {question}"
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    # VULNERABLE - no sources provided
    return response.choices[0].message.content


# VULN:LLM09:HIGH:LINE=91 - Auto-publishing LLM content
def vulnerable_auto_publish(topic: str) -> str:
    """Vulnerable: Auto-publishes LLM-generated content without review."""
    prompt = f"Write a blog post about: {topic}"
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    content = response.choices[0].message.content

    # VULNERABLE - auto-publish without fact-checking
    publish_to_website(content)
    return "Published"


# VULN:LLM09:MEDIUM:LINE=107 - Critical decisions without verification
def vulnerable_critical_decision(data: dict) -> str:
    """Vulnerable: Makes critical business decisions based on LLM analysis."""
    prompt = f"Analyze this data and recommend: buy, sell, or hold. Data: {data}"
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    recommendation = response.choices[0].message.content

    # VULNERABLE - acting on LLM recommendation without verification
    execute_trade(recommendation)
    return recommendation


def publish_to_website(content: str) -> None:
    """Publish content to website."""
    pass


def execute_trade(recommendation: str) -> None:
    """Execute trading action."""
    pass


# SAFE: Proper verification (for comparison)
def safe_verified_response(query: str) -> dict:
    """Safe: Includes confidence, sources, and disclaimers."""
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": query}],
        # Using logprobs for confidence would be ideal
    )

    return {
        "answer": response.choices[0].message.content,
        "confidence": "medium",  # Assess confidence
        "disclaimer": "This is AI-generated content. Please verify with authoritative sources.",
        "requires_review": True,
        "sources": []  # Ideally populated via RAG
    }
