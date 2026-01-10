"""
LLM02: Insecure Output Handling - Synthetic Vulnerable Application
This module contains intentional vulnerabilities for testing purposes.
"""

import os
import sqlite3
import subprocess
from flask import Flask, Response, request
from openai import OpenAI

app = Flask(__name__)
client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))


def get_llm_response(prompt: str) -> str:
    """Get response from LLM."""
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content


# VULN:LLM02:CRITICAL:LINE=29 - Eval with LLM output (helper function pattern)
def vulnerable_eval(user_request: str) -> str:
    """Vulnerable: Using eval() on LLM output via helper."""
    prompt = f"Generate a Python expression to calculate: {user_request}"
    llm_code = get_llm_response(prompt)
    result = eval(llm_code)  # VULNERABLE - arbitrary code execution
    return str(result)


# VULN:LLM02:CRITICAL:LINE=37 - Eval with direct LLM call
def vulnerable_eval_direct(user_request: str) -> str:
    """Vulnerable: eval() on direct LLM output."""
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Generate Python expression: {user_request}"}]
    )
    llm_code = response.choices[0].message.content
    result = eval(llm_code)  # VULNERABLE - eval on direct LLM output
    return str(result)


# VULN:LLM02:CRITICAL:LINE=51 - Exec with LLM output (helper pattern)
def vulnerable_exec(user_request: str) -> None:
    """Vulnerable: Using exec() on LLM-generated code via helper."""
    prompt = f"Write Python code to: {user_request}"
    llm_code = get_llm_response(prompt)
    exec(llm_code)  # VULNERABLE - arbitrary code execution


# VULN:LLM02:CRITICAL:LINE=59 - Exec with direct LLM call
def vulnerable_exec_direct(user_request: str) -> None:
    """Vulnerable: exec() on direct LLM output."""
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Write Python code: {user_request}"}]
    )
    code = response.choices[0].message.content
    exec(code)  # VULNERABLE - exec on direct LLM output


# VULN:LLM02:HIGH:LINE=49 - SQL Injection via LLM output
def vulnerable_sql(user_query: str) -> list:
    """Vulnerable: LLM output directly in SQL query."""
    prompt = f"Convert this to a SQL WHERE clause: {user_query}"
    where_clause = get_llm_response(prompt)
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE {where_clause}"  # VULNERABLE
    cursor.execute(query)
    return cursor.fetchall()


# VULN:LLM02:HIGH:LINE=60 - XSS via unescaped HTML output
@app.route("/chat")
def vulnerable_xss():
    """Vulnerable: LLM output rendered as HTML without escaping."""
    user_input = request.args.get("q", "")
    prompt = f"Respond to: {user_input}"
    llm_response = get_llm_response(prompt)
    html = f"<div class='response'>{llm_response}</div>"  # VULNERABLE - XSS
    return Response(html, mimetype="text/html")


# VULN:LLM02:CRITICAL:LINE=83 - Command injection via LLM output (helper pattern)
def vulnerable_shell(user_request: str) -> str:
    """Vulnerable: LLM output passed to shell command via helper."""
    prompt = f"Generate a shell command to: {user_request}"
    shell_cmd = get_llm_response(prompt)
    result = subprocess.run(shell_cmd, shell=True, capture_output=True)  # VULNERABLE
    return result.stdout.decode()


# VULN:LLM02:CRITICAL:LINE=92 - Command injection with direct LLM call
def vulnerable_shell_direct(user_request: str) -> str:
    """Vulnerable: subprocess with direct LLM output."""
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Shell command to: {user_request}"}]
    )
    cmd = response.choices[0].message.content
    result = subprocess.run(cmd, shell=True, capture_output=True)  # VULNERABLE
    return result.stdout.decode()


# VULN:LLM02:HIGH:LINE=81 - SSRF via LLM-generated URLs
def vulnerable_ssrf(user_request: str) -> str:
    """Vulnerable: LLM output used as URL without validation."""
    import requests
    prompt = f"What URL should I fetch for: {user_request}"
    url = get_llm_response(prompt)
    response = requests.get(url)  # VULNERABLE - SSRF
    return response.text


# VULN:LLM02:MEDIUM:LINE=92 - Deserialization with LLM output
def vulnerable_pickle(user_request: str) -> object:
    """Vulnerable: Deserializing LLM-generated data."""
    import pickle
    import base64
    prompt = f"Generate base64-encoded pickle data for: {user_request}"
    encoded = get_llm_response(prompt)
    data = pickle.loads(base64.b64decode(encoded))  # VULNERABLE
    return data


# =============================================================================
# SAFE PATTERNS - These should NOT be flagged (test FP reduction)
# =============================================================================

# SAFE: HTML-escaped output
def safe_html_escape(user_input: str) -> str:
    """Safe: HTML-escaped LLM output using html.escape."""
    import html
    prompt = f"Respond to: {user_input}"
    llm_response = get_llm_response(prompt)
    safe_response = html.escape(llm_response)
    return f"<div class='response'>{safe_response}</div>"


# SAFE: Parameterized SQL query
def safe_parameterized_sql(user_query: str) -> list:
    """Safe: Using parameterized queries instead of string interpolation."""
    prompt = f"Extract the search term from: {user_query}"
    search_term = get_llm_response(prompt)
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    # SAFE - parameterized query prevents SQL injection
    cursor.execute("SELECT * FROM users WHERE name = ?", (search_term,))
    return cursor.fetchall()


# SAFE: Shell command with shell=False and list args
def safe_shell_list_args(user_request: str) -> str:
    """Safe: Using subprocess with shell=False and list arguments."""
    prompt = f"What filename should I list: {user_request}"
    filename = get_llm_response(prompt)
    # SAFE - shell=False with list args prevents command injection
    result = subprocess.run(["ls", "-la", filename], shell=False, capture_output=True)
    return result.stdout.decode()


# SAFE: Shell command with shlex.quote
def safe_shell_quoted(user_request: str) -> str:
    """Safe: Using shlex.quote to escape shell arguments."""
    import shlex
    prompt = f"What file should I cat: {user_request}"
    filename = get_llm_response(prompt)
    # SAFE - shlex.quote escapes the argument
    safe_cmd = f"cat {shlex.quote(filename)}"
    result = subprocess.run(safe_cmd, shell=True, capture_output=True)
    return result.stdout.decode()


# SAFE: Jinja2 with autoescape enabled
@app.route("/chat_jinja")
def safe_jinja_autoescape():
    """Safe: Jinja2 template with autoescape enabled (default)."""
    from jinja2 import Environment, BaseLoader
    env = Environment(loader=BaseLoader(), autoescape=True)
    template = env.from_string("<div class='response'>{{ response }}</div>")

    user_input = request.args.get("q", "")
    prompt = f"Respond to: {user_input}"
    llm_response = get_llm_response(prompt)
    # SAFE - Jinja2 autoescape sanitizes the output
    return template.render(response=llm_response)


# SAFE: MarkupSafe for HTML output
def safe_markupsafe(user_input: str) -> str:
    """Safe: Using MarkupSafe.escape for HTML output."""
    from markupsafe import escape, Markup
    prompt = f"Respond to: {user_input}"
    llm_response = get_llm_response(prompt)
    # SAFE - MarkupSafe escapes HTML entities
    safe_response = escape(llm_response)
    return Markup(f"<div class='response'>{safe_response}</div>")


# SAFE: bleach.clean for rich text
def safe_bleach_clean(user_input: str) -> str:
    """Safe: Using bleach to sanitize HTML while allowing safe tags."""
    import bleach
    prompt = f"Generate HTML response for: {user_input}"
    llm_html = get_llm_response(prompt)
    # SAFE - bleach.clean removes dangerous tags/attributes
    safe_html = bleach.clean(
        llm_html,
        tags=['p', 'b', 'i', 'u', 'em', 'strong'],
        attributes={},
        strip=True
    )
    return f"<div class='response'>{safe_html}</div>"


# SAFE: ast.literal_eval for safe data parsing
def safe_literal_eval(user_request: str) -> dict:
    """Safe: Using ast.literal_eval instead of eval for data."""
    import ast
    prompt = f"Generate a Python dict for: {user_request}"
    llm_data = get_llm_response(prompt)
    # SAFE - literal_eval only parses literals, not arbitrary code
    data = ast.literal_eval(llm_data)
    return data


# SAFE: JSON parsing instead of eval
def safe_json_parse(user_request: str) -> dict:
    """Safe: Using json.loads instead of eval for data."""
    import json
    prompt = f"Generate a JSON object for: {user_request}. Return only valid JSON."
    llm_json = get_llm_response(prompt)
    # SAFE - json.loads only parses JSON, not code
    data = json.loads(llm_json)
    return data


# SAFE: URL validation before request
def safe_url_validation(user_request: str) -> str:
    """Safe: Validating URL against allowlist before fetching."""
    import requests
    from urllib.parse import urlparse

    ALLOWED_DOMAINS = ['api.example.com', 'data.example.org']

    prompt = f"What URL should I fetch for: {user_request}"
    url = get_llm_response(prompt)

    # SAFE - validate against allowlist
    parsed = urlparse(url)
    if parsed.netloc not in ALLOWED_DOMAINS:
        raise ValueError(f"Domain {parsed.netloc} not in allowlist")

    response = requests.get(url)
    return response.text
