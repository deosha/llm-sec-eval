# LLM Security Evaluation Framework

Evaluation framework for [aisentry](https://github.com/deosha/aisentry) - benchmarking OWASP LLM Top 10 detection against traditional SAST tools.

> **Important**: See [Comparison Analysis](results/aggregated/comparison_analysis.md) for full methodology context and limitations.

## Results Summary

### Synthetic Testbed (Ground Truth)

Evaluated against 73 ground-truth vulnerabilities across 10 OWASP LLM categories.

| Tool | Precision | Recall | F1 Score |
|------|-----------|--------|----------|
| **aisentry** | **74.5%** | **52.1%** | **61.3%** |
| Semgrep | 83.3% | 6.8% | 12.7% |
| Bandit | 58.3% | 38.4% | 46.3% |

**Note**: This comparison evaluates a specialized LLM scanner against general-purpose SAST tools. Low recall for Semgrep/Bandit on LLM-specific categories is **expected behavior** - they were not designed for these patterns. See [Limitations](#limitations) below.

### Per-Category Detection Rates

| Category | Recall | Precision | F1 |
|----------|--------|-----------|-----|
| **LLM07**: Insecure Plugin | 100% | 87.5% | 93.3% |
| **LLM06**: Sensitive Info | 71.4% | 55.6% | 62.5% |
| **LLM04**: Model DoS | 66.7% | 100% | 80.0% |
| **LLM09**: Overreliance | 66.7% | 100% | 80.0% |
| **LLM05**: Supply Chain | 60.0% | 54.5% | 57.1% |
| **LLM01**: Prompt Injection | 50.0% | 75.0% | 60.0% |
| **LLM08**: Excessive Agency | 50.0% | 75.0% | 60.0% |
| **LLM03**: Training Poisoning | 40.0% | 100% | 57.1% |
| **LLM10**: Model Theft | 28.6% | 100% | 44.4% |
| **LLM02**: Insecure Output | 10.0% | 100% | 18.2% |

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

### Tool Coverage by Pattern Type

#### LLM-Specific Patterns (Generic tools NOT expected to detect)

| Category | aisentry F1 | Semgrep | Bandit | Why Generic Tools Miss |
|----------|-----------|---------|--------|------------------------|
| **LLM01**: Prompt Injection | 60.0% | 0% | 15.4% | No rules for LLM prompt APIs |
| **LLM04**: Model DoS | 80.0% | 0% | 0% | No rules for rate limiting |
| **LLM06**: Sensitive Info | 62.5% | 0% | 0% | No LLM context awareness |
| **LLM10**: Model Theft | 44.4% | 0% | 0% | No model protection rules |

#### General Patterns (Generic tools SHOULD detect)

| Category | aisentry F1 | Semgrep | Bandit | Pattern Type |
|----------|-----------|---------|--------|--------------|
| **LLM02**: Insecure Output | 18.2% | 42.9% | **81.8%** | eval/exec/SQL |
| **LLM07**: Insecure Plugin | **93.3%** | 25.0% | 83.3% | shell/exec |
| **LLM03**: Training Poisoning | 57.1% | 0% | 60.0% | pickle.load |

Bandit excels at general patterns (eval/exec/shell) - **this is expected and appropriate**.

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
│   ├── aisec/                  # aisentry results
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
pip install aisentry bandit semgrep
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
aisentry scan ./testbed/llm01_prompt_injection -o json -f results.json

# Scan real-world repo
aisentry scan ./repos/langchain -o json -f langchain_scan.json

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

1. **61.3% F1 score** - Best overall performance on LLM-specific testbed
2. **74.5% precision** - Reduced false positives compared to Bandit
3. **52.1% recall** - Detects over half of all vulnerabilities
4. **Unique LLM coverage**: Only tool detecting LLM01, LLM04, LLM06, LLM10
5. **Complementary to Bandit**: Bandit excels at general patterns (LLM02, LLM07)

## Tools & Baselines

| Tool | Type | Purpose |
|------|------|---------|
| **aisentry** | Static + Audit | Primary tool under evaluation |
| Semgrep | SAST | Static analysis baseline |
| Bandit | SAST | Python security linter |

## Limitations

> **Mandatory disclosure for fair interpretation of results**

1. **Scope Mismatch**: Semgrep and Bandit are general-purpose Python security tools. They were **not designed** to detect LLM-specific vulnerability patterns such as prompt injection or missing rate limiting. Low recall on LLM-specific categories is expected behavior, not a deficiency.

2. **Rule Set Asymmetry**: aisentry includes custom detection rules for OWASP LLM Top 10 categories. Semgrep and Bandit were tested with default rule sets only. Results may differ with custom LLM-focused Semgrep rules.

3. **Testbed Composition**: ~60% of vulnerabilities in this testbed are LLM-specific patterns with no equivalent generic detection rules. The effective recall ceiling for generic tools is approximately 40%.

4. **Author-Curated Dataset**: This testbed was created by aisentry authors. External validation on third-party LLM codebases would strengthen findings.

5. **Complementary Tools**: This comparison demonstrates complementary coverage. **Use both generic SAST + specialized LLM scanning** for comprehensive security coverage.

For detailed methodology and context, see [Comparison Analysis](results/aggregated/comparison_analysis.md).

## License

MIT
