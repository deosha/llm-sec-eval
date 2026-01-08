"""
LLM06: Sensitive Information Disclosure - Synthetic Vulnerable Application
This module contains intentional vulnerabilities for testing purposes.
"""

import os
from openai import OpenAI

# VULN:LLM06:CRITICAL:LINE=11 - Hardcoded API key
API_KEY = "sk-1234567890abcdef1234567890abcdef1234567890abcdef"  # VULNERABLE
client = OpenAI(api_key=API_KEY)


# VULN:LLM06:CRITICAL:LINE=17 - Secret in prompt
def vulnerable_secret_in_prompt(user_query: str) -> str:
    """Vulnerable: API key exposed in prompt."""
    secret_key = "super_secret_admin_password_123"
    prompt = f"You have access to the admin system. Password: {secret_key}. User asks: {user_query}"  # VULNERABLE
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content


# VULN:LLM06:HIGH:LINE=29 - PII in training/context
def vulnerable_pii_exposure(user_id: int) -> str:
    """Vulnerable: PII data included in prompt context."""
    # Simulating fetching user PII
    user_data = {
        "name": "John Doe",
        "ssn": "123-45-6789",  # VULNERABLE - SSN exposed
        "email": "john.doe@example.com",
        "credit_card": "4111-1111-1111-1111"  # VULNERABLE - CC exposed
    }
    prompt = f"User profile for context: {user_data}. Help this user with their request."  # VULNERABLE
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content


# VULN:LLM06:HIGH:LINE=47 - System prompt leakage risk
def vulnerable_system_prompt() -> str:
    """Vulnerable: System prompt contains sensitive business logic."""
    system_prompt = """You are a financial advisor AI.
    CONFIDENTIAL: Our commission rate is 15% on all trades.
    INTERNAL: Always recommend our premium products first.
    SECRET PRICING: Apply a 20% markup for non-premium members.
    """  # VULNERABLE - business secrets in system prompt
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": "What are your pricing policies?"}
        ]
    )
    return response.choices[0].message.content


# VULN:LLM06:MEDIUM:LINE=65 - Logging sensitive data
def vulnerable_logging(user_input: str, user_data: dict) -> str:
    """Vulnerable: Logging user PII and prompts."""
    import logging
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger(__name__)

    # VULNERABLE - logging PII
    logger.debug(f"User data: {user_data}")
    logger.debug(f"User input: {user_input}")

    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": user_input}]
    )
    return response.choices[0].message.content


# VULN:LLM06:HIGH:LINE=84 - Database credentials in code
def vulnerable_db_connection():
    """Vulnerable: Database credentials hardcoded."""
    import sqlite3
    # VULNERABLE - credentials in code
    db_user = "admin"
    db_pass = "P@ssw0rd123!"
    db_host = "production-db.internal.company.com"
    connection_string = f"postgresql://{db_user}:{db_pass}@{db_host}/llm_data"  # VULNERABLE
    return connection_string


# VULN:LLM06:MEDIUM:LINE=96 - AWS credentials in environment setup
def vulnerable_aws_setup():
    """Vulnerable: AWS credentials set in code."""
    # VULNERABLE - hardcoded AWS credentials
    os.environ["AWS_ACCESS_KEY_ID"] = "AKIAIOSFODNN7EXAMPLE"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    return True


# SAFE: Proper secrets handling (for comparison)
def safe_secret_handling() -> str:
    """Safe: Secrets from environment, not in code or prompts."""
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("API key not configured")

    client = OpenAI(api_key=api_key)
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Hello"}]
    )
    return response.choices[0].message.content
