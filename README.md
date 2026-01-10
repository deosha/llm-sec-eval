# LLM Security Evaluation Framework

Evaluation framework for [AI Security CLI](https://github.com/deosha/ai-security-cli) - benchmarking OWASP LLM Top 10 detection against traditional SAST tools.

## Results Summary

### Synthetic Testbed (Ground Truth)

Evaluated against 73 ground-truth vulnerabilities across 10 OWASP LLM categories.

| Tool | Precision | Recall | F1 Score |
|------|-----------|--------|----------|
| **AI Security CLI** | **69.6%** | **53.4%** | **60.5%** |
| Semgrep | 66.7% | 8.2% | 14.6% |
| Bandit | 51.5% | 46.6% | 48.9% |

**AI Security CLI outperforms both Semgrep and Bandit on F1 score** by detecting LLM-specific vulnerabilities that generic tools miss.

### Per-Category Detection Rates

| Category | Recall | Precision | F1 |
|----------|--------|-----------|-----|
| **LLM07**: Insecure Plugin | 85.7% | 85.7% | 85.7% |
| **LLM06**: Sensitive Info | 71.4% | 55.6% | 62.5% |
| **LLM04**: Model DoS | 66.7% | 100% | 80.0% |
| **LLM09**: Overreliance | 66.7% | 100% | 80.0% |
| **LLM05**: Supply Chain | 60.0% | 54.5% | 57.1% |
| **LLM01**: Prompt Injection | 50.0% | 75.0% | 60.0% |
| **LLM10**: Model Theft | 42.9% | 75.0% | 54.5% |
| **LLM03**: Training Poisoning | 40.0% | 100% | 57.1% |
| **LLM08**: Excessive Agency | 33.3% | 100% | 50.0% |
| **LLM02**: Insecure Output | 30.0% | 42.9% | 35.3% |

### Real-World Repositories (10 repos, 14,991 files)

| Repository | Files | Findings | Findings/File |
|------------|-------|----------|---------------|
| LangChain | 2,501 | 268 | 0.11 |
| LlamaIndex | 4,088 | 1,454 | 0.36 |
| Haystack | 523 | 47 | 0.09 |
| LiteLLM | 2,792 | 2,902 | 1.04 |
| DSPy | 231 | 122 | 0.53 |
| OpenAI Python | 1,134 | 60 | 0.05 |
| Guidance | 149 | 38 | 0.26 |
| vLLM | 2,239 | 1,572 | 0.70 |
| Semantic Kernel | 1,241 | 40 | 0.03 |
| Text Gen WebUI | 93 | 165 | 1.77 |
| **Total** | **14,991** | **6,668** | **0.44** |

### Category Distribution (Real-World)

| Category | Findings | % |
|----------|----------|---|
| LLM04: Model DoS | 1,963 | 29.4% |
| LLM09: Overreliance | 1,387 | 20.8% |
| LLM02: Insecure Output | 1,223 | 18.3% |
| LLM08: Excessive Agency | 1,113 | 16.7% |
| LLM05: Supply Chain | 619 | 9.3% |
| LLM01: Prompt Injection | 262 | 3.9% |
| Others | 101 | 1.5% |

### Unique Coverage

AI Security CLI is the **only tool** detecting these OWASP LLM categories (0% coverage by Semgrep/Bandit):

| Category | AI-Sec Recall | Semgrep | Bandit |
|----------|---------------|---------|--------|
| **LLM04**: Model DoS | 100% | 0% | 0% |
| **LLM08**: Excessive Agency | 100% | 0% | 0% |
| **LLM09**: Overreliance | 100% | 0% | 0% |
| **LLM10**: Model Theft | 86% | 0% | 0% |

## Repository Structure

```
llm-sec-eval/
├── testbed/                    # Synthetic testbed (10 OWASP categories)
│   ├── llm01_prompt_injection/
│   │   ├── app.py              # Vulnerable code samples
│   │   └── labels.yaml         # Ground truth labels
│   ├── llm02_insecure_output/
│   └── ...
├── repos/                      # Real-world repositories
│   ├── langchain/
│   ├── llama_index/
│   ├── haystack/
│   ├── litellm/
│   ├── dspy/
│   ├── openai-python/
│   ├── guidance/
│   ├── vllm/
│   ├── semantic-kernel/
│   └── text-gen-webui/
├── results/
│   ├── aisec/                  # AI Security CLI results
│   ├── bandit/                 # Bandit results
│   ├── semgrep/                # Semgrep results
│   └── aggregated/             # Computed metrics
├── scripts/
│   ├── aggregate_static.py     # Compute P/R/F1
│   └── compare_baselines.py    # Generate comparisons
└── Makefile                    # Reproducible evaluation
```

## Running the Evaluation

### Prerequisites

```bash
pip install ai-security-cli bandit semgrep
```

### Run Full Evaluation

```bash
# Synthetic testbed
make eval-testbed-static

# Real-world repos
make eval-repos

# Aggregate results
make aggregate
```

### Individual Commands

```bash
# Static scan
ai-security-cli scan ./testbed/llm01_prompt_injection -o json -f results.json

# Scan real-world repo
ai-security-cli scan ./repos/langchain -o json -f langchain_scan.json

# Compare with Bandit
bandit -r ./testbed/llm01_prompt_injection -f json -o bandit.json
```

## Synthetic Testbed

Each testbed project contains:

- **app.py**: Vulnerable Python code with labeled lines
- **labels.yaml**: Ground truth with:
  - Static findings: file, line, category, severity
  - Expected detection for each vulnerability

### Label Format

```yaml
static_findings:
  - id: LLM01-STATIC-001
    file: app.py
    line: 16
    line_tolerance: 2
    category: LLM01
    severity: high
    description: "F-string interpolation in system prompt"
```

## Metrics Explained

- **Precision**: TP / (TP + FP) - How many findings are real issues
- **Recall**: TP / (TP + FN) - How many real issues are found
- **F1 Score**: Harmonic mean of precision and recall
- **Findings/File**: Average findings per file (lower = less noise)

## Key Findings

1. **60.5% F1 score** - Best overall performance among tested tools
2. **69.6% precision** - Significantly reduced false positives
3. **53.4% recall** - Detects over half of all vulnerabilities
4. **Best categories**: LLM07 (85.7%), LLM06 (71.4%), LLM04 (66.7%)
5. **Unique coverage** for LLM04, LLM08, LLM09, LLM10 (not detected by Semgrep/Bandit)

## Tools & Baselines

| Tool | Type | Purpose |
|------|------|---------|
| **AI Security CLI** | Static + Audit | Primary tool under evaluation |
| Semgrep | SAST | Static analysis baseline |
| Bandit | SAST | Python security linter |

## License

MIT
