# LLM Security Evaluation Framework

Evaluation framework for [AI Security CLI](https://github.com/deosha/ai-security-cli) - benchmarking OWASP LLM Top 10 detection against traditional SAST tools.

## Results Summary

### Synthetic Testbed (Ground Truth)

| Tool | Precision | Recall | F1 Score | TP | FP | FN |
|------|-----------|--------|----------|----|----|-----|
| **AI Security CLI** | 17.0% | **60.9%** | 26.5% | 39 | 191 | 25 |
| Semgrep | 83.3% | 7.8% | 14.3% | 5 | 1 | 59 |
| Bandit | 69.2% | 42.2% | 52.4% | 27 | 12 | 37 |

### Real-World Repositories

| Repository | AI-Sec Findings | Bandit (H+M) | Ratio | Audit Score | Maturity |
|------------|-----------------|--------------|-------|-------------|----------|
| LangChain | 313 | 6 | 52x | 33.1% | Developing |
| LlamaIndex | 499 | 6 | 83x | 37.6% | Developing |
| Haystack | 322 | 18 | 18x | 18.8% | Initial |
| LiteLLM | 5,661 | 73 | 78x | 28.3% | Developing |
| DSPy | 218 | 25 | 9x | 19.6% | Initial |
| **Total** | **7,013** | **128** | **55x** | | |

### Unique Coverage

AI Security CLI is the **only tool** detecting these OWASP LLM categories (0% coverage by Semgrep/Bandit):

| Category | AI-Sec F1 | Semgrep F1 | Bandit F1 |
|----------|-----------|------------|-----------|
| **LLM04**: Model DoS | 27.9% | 0% | 0% |
| **LLM09**: Overreliance | 31.8% | 0% | 0% |
| **LLM10**: Model Theft | 37.8% | 0% | 0% |

### Security Audit Accuracy

- **89.7%** control detection accuracy (26/29 exact matches)
- 3 over-detections, 0 under-detections

## Repository Structure

```
llm-sec-eval/
├── testbed/                    # Synthetic testbed (10 OWASP categories)
│   ├── llm01_prompt_injection/
│   │   ├── app.py              # Vulnerable code samples
│   │   └── labels.yaml         # Ground truth labels
│   ├── llm02_insecure_output/
│   └── ...
├── results/
│   ├── aisec/                  # AI Security CLI results
│   ├── bandit/                 # Bandit results
│   ├── semgrep/                # Semgrep results
│   ├── aggregated/             # Computed metrics
│   ├── summary.json            # Overall summary
│   └── full_comparison.txt     # Detailed comparison
├── scripts/
│   ├── aggregate_static.py     # Compute P/R/F1
│   ├── aggregate_audit.py      # Audit accuracy
│   └── compare_baselines.py    # Generate comparisons
├── Makefile                    # Reproducible evaluation
└── Dockerfile                  # Isolated environment
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
make eval-testbed-audit

# Real-world repos
make eval-langchain
make eval-llamaindex
make eval-haystack
make eval-litellm
make eval-dspy

# Aggregate results
make aggregate
```

### Individual Commands

```bash
# Static scan
ai-security-cli scan ./testbed/llm01_prompt_injection -o json -f results.json

# Security audit
ai-security-cli audit ./testbed/llm01_prompt_injection -o json -f audit.json

# Compare with Bandit
bandit -r ./testbed/llm01_prompt_injection -f json -o bandit.json
```

## Synthetic Testbed

Each testbed project contains:

- **app.py**: Vulnerable Python code with labeled lines
- **labels.yaml**: Ground truth with:
  - Static findings: file, line, category, severity
  - Live tests: prompts, expected behavior, vulnerable indicators
  - Audit expectations: control presence/level

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

audit_expectations:
  controls:
    - control_id: PS-01
      expected_level: none
```

## Metrics Explained

- **Precision**: TP / (TP + FP) - How many findings are real issues
- **Recall**: TP / (TP + FN) - How many real issues are found
- **F1 Score**: Harmonic mean of precision and recall
- **Audit Accuracy**: % of security controls correctly identified

## Key Findings

1. **AI Security CLI has highest recall (60.9%)** for LLM-specific vulnerabilities
2. **55x more findings** than Bandit on real-world LLM codebases
3. **Unique coverage** for LLM04, LLM09, LLM10 (not detected by any other tool)
4. **89.7% audit accuracy** for security posture assessment
5. **Precision tradeoff**: 17% precision (optimized for recall, reducing FPs in progress)

## Tools & Baselines

| Tool | Type | Purpose |
|------|------|---------|
| **AI Security CLI** | Static + Audit | Primary tool under evaluation |
| Semgrep | SAST | Static analysis baseline |
| Bandit | SAST | Python security linter |

## License

MIT
