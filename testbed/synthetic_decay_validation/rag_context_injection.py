"""
RAG Pipeline Context Injection Vulnerabilities
Tests α_c (context position decay factor)

These samples demonstrate vulnerabilities where user input flows through
RAG retrieval into the context window of an LLM call.
"""
import openai
from typing import List

# Simulated vector database
def retrieve_documents(query: str) -> List[str]:
    """Simulate RAG retrieval - returns documents matching query."""
    return [f"Document about {query}"]


# VULNERABLE: User query influences context via RAG
def rag_code_execution_v1(user_query: str):
    """
    Vulnerability: User query -> RAG retrieval -> LLM context -> code execution
    Attack: User crafts query to inject malicious content into retrieved docs
    Tests: α_c decay (context position)
    """
    retrieved_docs = retrieve_documents(user_query)
    context = "\n".join(retrieved_docs)

    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "Generate Python code based on context."},
            {"role": "user", "content": f"Context:\n{context}\n\nGenerate code:"}
        ]
    )
    code = response.choices[0].message.content
    exec(code)  # SINK: Code execution from RAG-influenced LLM output


# VULNERABLE: RAG context with SQL sink
def rag_sql_injection_v1(search_term: str, db_cursor):
    """
    Vulnerability: Search term -> RAG -> LLM -> SQL query
    Tests: α_c decay through context window
    """
    docs = retrieve_documents(search_term)

    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "Convert natural language to SQL."},
            {"role": "user", "content": f"Documents: {docs}\nGenerate SELECT query:"}
        ]
    )
    sql = response.choices[0].message.content
    db_cursor.execute(sql)  # SINK: SQL injection via RAG context


# VULNERABLE: RAG with file path sink
def rag_path_traversal_v1(document_request: str):
    """
    Vulnerability: Document request -> RAG -> LLM -> file access
    Tests: α_c decay for path traversal
    """
    context_docs = retrieve_documents(document_request)

    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "user", "content": f"Based on: {context_docs}\nWhat file should I read?"}
        ]
    )
    file_path = response.choices[0].message.content
    with open(file_path, 'r') as f:  # SINK: Path traversal
        return f.read()


# VULNERABLE: Multi-document RAG context
def rag_multi_doc_injection(queries: List[str]):
    """
    Vulnerability: Multiple user queries -> aggregated context -> LLM -> command
    Tests: α_c with aggregated context
    """
    all_docs = []
    for q in queries:
        all_docs.extend(retrieve_documents(q))

    combined_context = "\n---\n".join(all_docs)

    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a helpful shell assistant."},
            {"role": "user", "content": f"Context:\n{combined_context}\n\nGenerate shell command:"}
        ]
    )
    import subprocess
    subprocess.run(response.choices[0].message.content, shell=True)  # SINK
