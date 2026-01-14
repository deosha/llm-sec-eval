"""
Multi-Hop LLM Chain Vulnerabilities
Tests γ (hop decay factor)

These samples demonstrate vulnerabilities where user input flows through
multiple LLM transformations before reaching a dangerous sink.
"""
import openai


# VULNERABLE: 2-hop chain (γ^2 = 0.81 at default)
def two_hop_code_execution(user_input: str):
    """
    Vulnerability: User input -> LLM1 (summarize) -> LLM2 (code gen) -> exec
    Tests: 2-hop decay (γ^2)
    """
    # Hop 1: Summarization
    summary_response = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Summarize: {user_input}"}]
    )
    summary = summary_response.choices[0].message.content

    # Hop 2: Code generation from summary
    code_response = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Write Python for: {summary}"}]
    )
    code = code_response.choices[0].message.content

    exec(code)  # SINK: 2-hop chain to code execution


# VULNERABLE: 3-hop chain (γ^3 = 0.729 at default)
def three_hop_command_injection(user_request: str):
    """
    Vulnerability: User -> LLM1 (translate) -> LLM2 (plan) -> LLM3 (command) -> shell
    Tests: 3-hop decay (γ^3)
    """
    # Hop 1: Translation
    translated = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Translate to English: {user_request}"}]
    ).choices[0].message.content

    # Hop 2: Task planning
    plan = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Create action plan for: {translated}"}]
    ).choices[0].message.content

    # Hop 3: Command generation
    command = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Generate shell command for: {plan}"}]
    ).choices[0].message.content

    import subprocess
    subprocess.run(command, shell=True)  # SINK: 3-hop chain


# VULNERABLE: 4-hop chain (γ^4 = 0.656 at default, below threshold)
def four_hop_sql_injection(user_query: str, db):
    """
    Vulnerability: User -> LLM1 -> LLM2 -> LLM3 -> LLM4 -> SQL
    Tests: 4-hop decay (should be below detection threshold)
    """
    # Hop 1
    step1 = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Rephrase: {user_query}"}]
    ).choices[0].message.content

    # Hop 2
    step2 = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Extract entities from: {step1}"}]
    ).choices[0].message.content

    # Hop 3
    step3 = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Structure as query spec: {step2}"}]
    ).choices[0].message.content

    # Hop 4
    sql = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Generate SQL: {step3}"}]
    ).choices[0].message.content

    db.execute(sql)  # SINK: 4-hop chain (may be below threshold)


# VULNERABLE: Branching multi-hop
def branching_multi_hop(user_data: str):
    """
    Vulnerability: User input branches into parallel LLM chains that merge
    Tests: Complex multi-hop topology
    """
    # Branch 1: Analysis path
    analysis = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Analyze: {user_data}"}]
    ).choices[0].message.content

    # Branch 2: Extraction path
    extracted = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Extract key points: {user_data}"}]
    ).choices[0].message.content

    # Merge: Combine both branches
    combined = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Combine:\n{analysis}\n{extracted}\nGenerate code:"}]
    ).choices[0].message.content

    exec(combined)  # SINK: Merged multi-hop


# VULNERABLE: Recursive/iterative chain
def iterative_refinement_chain(user_spec: str, iterations: int = 3):
    """
    Vulnerability: User spec refined through N iterations of LLM calls
    Tests: Iterative hop decay
    """
    current = user_spec

    for i in range(iterations):
        refined = openai.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": f"Refine and improve: {current}"}]
        ).choices[0].message.content
        current = refined

    # Final code generation
    code = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Convert to Python: {current}"}]
    ).choices[0].message.content

    exec(code)  # SINK: After N+1 hops
