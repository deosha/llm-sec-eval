"""
System Prompt Injection Vulnerabilities
Tests α_s (system position decay factor)

These samples demonstrate vulnerabilities where user input influences
the system prompt of an LLM call, which has lower influence than direct
user prompts but can still be exploited.
"""
import openai


# VULNERABLE: Direct system prompt injection
def configurable_system_prompt_v1(user_persona: str, user_query: str):
    """
    Vulnerability: User controls persona in system prompt
    Tests: α_s decay (system position = 0.50)
    """
    system_prompt = f"You are a {user_persona}. Help the user with their request."

    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": system_prompt},  # User-influenced system
            {"role": "user", "content": user_query}
        ]
    )
    code = response.choices[0].message.content
    exec(code)  # SINK: Code execution from system-influenced output


# VULNERABLE: System prompt with instructions injection
def system_instruction_injection(custom_instructions: str, task: str):
    """
    Vulnerability: User provides custom instructions added to system prompt
    Tests: α_s decay for instruction injection
    """
    system = f"""You are a code assistant.
Additional instructions from user: {custom_instructions}
Always generate safe, validated code."""

    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": f"Generate code for: {task}"}
        ]
    )
    import subprocess
    subprocess.run(response.choices[0].message.content, shell=True)  # SINK


# VULNERABLE: System prompt template injection
def system_template_injection(template_vars: dict):
    """
    Vulnerability: User-controlled template variables in system prompt
    Tests: α_s with template-based injection
    """
    system_template = """You are an AI assistant for {company}.
Your role is: {role}
Your capabilities: {capabilities}
Generate SQL queries to help users."""

    system_prompt = system_template.format(**template_vars)

    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": "List all users"}
        ]
    )
    sql = response.choices[0].message.content
    # SINK: SQL from system-template-influenced output
    return execute_sql(sql)


def execute_sql(sql):
    import sqlite3
    conn = sqlite3.connect(':memory:')
    conn.execute(sql)


# VULNERABLE: Dynamic system prompt from config
def dynamic_system_from_config(config_override: str, query: str):
    """
    Vulnerability: Config override influences system behavior
    Tests: α_s for configuration injection
    """
    base_system = "You are a helpful assistant."
    if config_override:
        base_system = f"{base_system}\nConfig: {config_override}"

    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": base_system},
            {"role": "user", "content": query}
        ]
    )
    # SINK: Path traversal from config-influenced system
    file_path = response.choices[0].message.content.strip()
    with open(file_path) as f:
        return f.read()


# VULNERABLE: Multi-tenant system prompt
def multi_tenant_system_injection(tenant_config: str, user_request: str):
    """
    Vulnerability: Tenant-specific config in system prompt
    Tests: α_s for multi-tenant scenarios
    """
    system = f"""You are an assistant for tenant.
Tenant configuration: {tenant_config}
Follow tenant-specific rules when generating responses."""

    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user_request}
        ]
    )
    # SINK: Command execution from tenant-influenced output
    import os
    os.system(response.choices[0].message.content)


# COMBINED: System + Context injection
def combined_system_context_injection(system_addon: str, context_docs: str, query: str):
    """
    Vulnerability: User influences both system prompt AND context
    Tests: Combined α_s and α_c effects
    """
    system = f"You are an assistant. Additional rules: {system_addon}"

    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": f"Context: {context_docs}\n\nQuery: {query}"}
        ]
    )
    eval(response.choices[0].message.content)  # SINK
