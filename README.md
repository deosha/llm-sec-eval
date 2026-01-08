# LLM Security Evaluation Framework

Evaluation framework for [AI Security CLI](https://github.com/deosha/ai-security-cli) - benchmarking OWASP LLM Top 10 detection against traditional SAST tools.

## Results Summary

### Synthetic Testbed (Ground Truth)

| Tool | Precision | Recall | F1 Score | TP | FP | FN |
|------|-----------|--------|----------|----|----|-----|
| **AI Security CLI** | 20.0% | **57.8%** | 29.7% | 37 | 148 | 27 |
| Semgrep | 83.3% | 7.8% | 14.3% | 5 | 1 | 59 |
| Bandit | 69.2% | 42.2% | 52.4% | 27 | 12 | 37 |

### Per-Category Detection Rates

| Category | Recall | Precision | F1 | Status |
|----------|--------|-----------|-----|--------|
| **LLM01**: Prompt Injection | 100% | 16.1% | 27.8% | Excellent |
| **LLM04**: Model DoS | 100% | 20.0% | 33.3% | Excellent |
| **LLM08**: Excessive Agency | 100% | 17.1% | 29.3% | Excellent |
| **LLM09**: Overreliance | 100% | 20.6% | 34.1% | Excellent |
| **LLM10**: Model Theft | 86% | 26.1% | 40.0% | Good |
| **LLM06**: Sensitive Info | 71% | 22.7% | 34.5% | Moderate |
| **LLM05**: Supply Chain | 14% | 100% | 25.0% | Improving |
| **LLM07**: Insecure Plugin | 14% | 50.0% | 22.2% | Improving |
| **LLM02**: Insecure Output | 0% | 0% | 0% | In Development |
| **LLM03**: Training Poisoning | 0% | 0% | 0% | In Development |

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

1. **100% recall** on Prompt Injection, Model DoS, Excessive Agency, Overreliance
2. **Unique coverage** for LLM04, LLM08, LLM09, LLM10 (not detected by any other tool)
3. **0.44 findings/file** on real-world repos (manageable for review)
4. **20% precision, 57.8% recall, 29.7% F1** overall
5. **In Development**: LLM02 (Insecure Output), LLM03 (Training Poisoning)

## Tools & Baselines

| Tool | Type | Purpose |
|------|------|---------|
| **AI Security CLI** | Static + Audit | Primary tool under evaluation |
| Semgrep | SAST | Static analysis baseline |
| Bandit | SAST | Python security linter |

## License

MIT
