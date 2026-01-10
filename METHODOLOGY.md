# Evaluation Methodology

This document describes the evaluation methodology used to benchmark aisentry against other static analysis tools for LLM security vulnerabilities.

## Overview

The evaluation uses two complementary datasets:

1. **Synthetic Testbed** (`testbed/`) - Curated test cases with ground-truth labels
2. **Real-World Repositories** (`repos/`) - Popular open-source LLM frameworks

## Synthetic Testbed

### Structure

The testbed contains 10 directories corresponding to the OWASP LLM Top 10 categories:

| Category | Vulnerabilities | Description |
|----------|----------------|-------------|
| LLM01: Prompt Injection | 12 | Direct/indirect prompt injection patterns |
| LLM02: Insecure Output | 10 | Unsafe handling of LLM-generated content |
| LLM03: Training Poisoning | 5 | Data poisoning and model integrity issues |
| LLM04: Model DoS | 6 | Resource exhaustion vulnerabilities |
| LLM05: Supply Chain | 10 | Dependency and model provenance risks |
| LLM06: Sensitive Info | 7 | PII/secrets exposure through LLMs |
| LLM07: Insecure Plugin | 7 | Unsafe tool/plugin execution patterns |
| LLM08: Excessive Agency | 6 | Autonomous actions without oversight |
| LLM09: Overreliance | 3 | Missing human verification for critical decisions |
| LLM10: Model Theft | 7 | API extraction and model stealing risks |
| **Total** | **73** | |

### Ground Truth Labeling Process

Each category directory contains:

1. **`app.py`** - Python source file with intentionally vulnerable and safe code patterns
2. **`labels.yaml`** - Ground truth annotations with:
   - `id`: Unique identifier (e.g., `LLM01-STATIC-001`)
   - `file`: Source file name
   - `line`: Exact line number of vulnerability
   - `line_tolerance`: Acceptable deviation for matching (typically ±5 lines)
   - `category`: OWASP LLM category
   - `severity`: HIGH/MEDIUM/LOW
   - `confidence`: Expected confidence (0.0-1.0)
   - `description`: Human-readable description
   - `pattern`: Vulnerability pattern type
   - `vulnerable_code`: Code snippet for verification

### Labeling Methodology

1. **Pattern-based construction**: Test cases were written to represent common vulnerability patterns documented in OWASP LLM Top 10 and academic literature
2. **Positive and negative samples**: Each file contains both vulnerable patterns (should trigger findings) and safe patterns (should not trigger)
3. **Manual verification**: All labels were manually reviewed to ensure accuracy
4. **Line tolerance**: A ±5 line tolerance accounts for AST-based detectors reporting function definition vs. specific vulnerable line

### Metrics Calculation

For each tool, we compute:

- **True Positives (TP)**: Findings matching a ground-truth label within line tolerance
- **False Positives (FP)**: Findings not matching any ground-truth label
- **False Negatives (FN)**: Ground-truth labels with no matching finding

```
Precision = TP / (TP + FP)
Recall = TP / (TP + FN)
F1 = 2 * (Precision * Recall) / (Precision + Recall)
```

## Real-World Repositories

### Repository Selection Criteria

Repositories were selected based on:
1. Popularity (GitHub stars, downloads)
2. Active development
3. Representative of LLM application patterns
4. Python-based (primary detection target)

### Repositories Analyzed

| Repository | Description | Commit Hash | Date | Python Files |
|------------|-------------|-------------|------|--------------|
| [LangChain](https://github.com/langchain-ai/langchain) | LLM application framework | `d383f004` | 2026-01-08 | 2,501 |
| [LlamaIndex](https://github.com/run-llama/llama_index) | Data framework for LLMs | `32ab6648` | 2026-01-07 | 4,088 |
| [LiteLLM](https://github.com/BerriAI/litellm) | LLM API proxy | `1c1ee8de` | 2026-01-08 | 2,792 |
| [vLLM](https://github.com/vllm-project/vllm) | High-throughput inference | `75082432` | 2026-01-08 | 1,205 |
| [Haystack](https://github.com/deepset-ai/haystack) | NLP framework | `f1f6f5b4` | 2026-01-08 | 892 |
| [DSPy](https://github.com/stanfordnlp/dspy) | Programming with LMs | `c21f77bc` | 2026-01-08 | 487 |
| [Guidance](https://github.com/guidance-ai/guidance) | LLM control library | `bbb604d6` | 2026-01-06 | 312 |
| [OpenAI Python](https://github.com/openai/openai-python) | OpenAI API client | `d3e63217` | 2025-12-19 | 1,847 |
| [Semantic Kernel](https://github.com/microsoft/semantic-kernel) | LLM orchestration | `dc7c1c04` | 2025-12-23 | 156 |
| [text-generation-webui](https://github.com/oobabooga/text-generation-webui) | Web UI for LLMs | `a0b5599e` | 2025-12-20 | 712 |
| **Total** | | | | **14,992** |

### Real-World Scan Purpose

Real-world repository scans serve to:
1. Validate that detection patterns generalize beyond synthetic examples
2. Identify false positive rates in production codebases
3. Discover vulnerability patterns not covered in synthetic testbed
4. Demonstrate practical applicability

**Note**: Findings from real-world repositories are not used in precision/recall calculations due to lack of ground-truth labels. They are presented as case studies for qualitative analysis.

## Comparison Tools

### Tools Evaluated

| Tool | Version | Configuration |
|------|---------|---------------|
| **aisentry** | 1.0.0-beta | Default thresholds |
| **Semgrep** | Latest | `p/python` ruleset |
| **Bandit** | Latest | Default configuration |

### Why These Tools?

- **Semgrep**: Industry-standard SAST with custom rule support
- **Bandit**: Python-specific security linter, widely adopted

Neither tool has LLM-specific detection rules, making them baselines for comparison.

## Results Summary

### Synthetic Testbed (Ground Truth)

| Tool | Precision | Recall | F1 Score |
|------|-----------|--------|----------|
| **aisentry** | 75.4% | 63.0% | **68.7%** |
| Semgrep | 83.3% | 6.8% | 12.7% |
| Bandit | 58.3% | 38.4% | 46.3% |

### Per-Category Performance (aisentry)

| Category | Precision | Recall | F1 |
|----------|-----------|--------|-----|
| LLM01: Prompt Injection | 80% | 67% | 72.7% |
| LLM02: Insecure Output | 78% | 70% | 73.7% |
| LLM03: Training Poisoning | 100% | 40% | 57.1% |
| LLM04: Model DoS | 100% | 67% | 80.0% |
| LLM05: Supply Chain | 55% | 60% | 57.1% |
| LLM06: Sensitive Info | 56% | 71% | 62.5% |
| LLM07: Insecure Plugin | 88% | 100% | 93.3% |
| LLM08: Excessive Agency | 75% | 50% | 60.0% |
| LLM09: Overreliance | 100% | 67% | 80.0% |
| LLM10: Model Theft | 100% | 29% | 44.4% |

## Limitations

1. **Synthetic testbed bias**: Test cases may not represent all real-world vulnerability patterns
2. **No runtime analysis**: Static analysis cannot detect runtime-only vulnerabilities
3. **Python-only**: Current evaluation limited to Python codebases
4. **Evolving patterns**: LLM security patterns are rapidly evolving; testbed may become outdated
5. **No public LLM benchmark**: Unlike OWASP Benchmark for traditional web vulns, no standardized LLM security benchmark exists

## Reproducibility

To reproduce the evaluation:

```bash
# Clone the repository
git clone https://github.com/deosha/llm-sec-eval
cd llm-sec-eval

# Run testbed evaluation
make eval-testbed-static

# Aggregate results
python3 scripts/aggregate_static.py

# View results
cat results/aggregated/static_metrics.csv
```

## Future Work

1. Expand testbed with community contributions
2. Add JavaScript/TypeScript detection support
3. Create standardized LLM security benchmark for broader adoption
4. Integrate runtime testing with tools like Garak
5. Add manual validation of real-world findings for case studies
