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


# VULN:LLM02:CRITICAL:LINE=29 - Eval with LLM output
def vulnerable_eval(user_request: str) -> str:
    """Vulnerable: Using eval() on LLM output."""
    prompt = f"Generate a Python expression to calculate: {user_request}"
    llm_code = get_llm_response(prompt)
    result = eval(llm_code)  # VULNERABLE - arbitrary code execution
    return str(result)


# VULN:LLM02:CRITICAL:LINE=39 - Exec with LLM output
def vulnerable_exec(user_request: str) -> None:
    """Vulnerable: Using exec() on LLM-generated code."""
    prompt = f"Write Python code to: {user_request}"
    llm_code = get_llm_response(prompt)
    exec(llm_code)  # VULNERABLE - arbitrary code execution


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


# VULN:LLM02:CRITICAL:LINE=71 - Command injection via LLM output
def vulnerable_shell(user_request: str) -> str:
    """Vulnerable: LLM output passed to shell command."""
    prompt = f"Generate a shell command to: {user_request}"
    shell_cmd = get_llm_response(prompt)
    result = subprocess.run(shell_cmd, shell=True, capture_output=True)  # VULNERABLE
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


# SAFE: Escaped output (for comparison)
def safe_html_output(user_input: str) -> str:
    """Safe: HTML-escaped LLM output."""
    import html
    prompt = f"Respond to: {user_input}"
    llm_response = get_llm_response(prompt)
    safe_response = html.escape(llm_response)
    return f"<div class='response'>{safe_response}</div>"
