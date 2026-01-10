# Tool Comparison Analysis

## Important Disclaimer

> **Scope Mismatch Warning**: This comparison evaluates a specialized LLM security scanner
> against general-purpose Python SAST tools on an LLM-focused testbed. This is analogous
> to comparing a cardiology specialist to general practitioners on heart disease diagnosis.
> The comparison is technically valid but contextually requires careful interpretation.

## What This Comparison Shows (and Doesn't Show)

| Shows | Does NOT Show |
|-------|---------------|
| Unique coverage of ai-security-cli for LLM patterns | Overall tool quality for general Python security |
| Baseline detection of generic SAST on LLM testbed | What tuned Semgrep rules could achieve |
| Complementary tool coverage | Superiority of one tool over another |

## Methodology Context

This comparison evaluates ai-security-cli (specialized LLM scanner) against generic SAST tools
(Semgrep, Bandit) on the OWASP LLM Top 10 testbed (73 labeled vulnerabilities).

**Critical caveats:**
- Generic SAST tools were **not designed** for LLM-specific patterns
- Low recall on LLM categories is **expected behavior**, not a deficiency
- Results represent a **lower bound** for generic tools on LLM categories
- ~60% of testbed vulnerabilities have no equivalent generic detection rules

## Tool Configurations

| Tool | Version | Configuration |
|------|---------|---------------|
| ai-security-cli | 1.0.0b4 | Default LLM detectors |
| Semgrep | 1.50+ | `semgrep --config=p/python` |
| Bandit | 1.7+ | `bandit -r . -f json` |

## Results by Category Type

### General Vulnerability Patterns (eval/exec/SQL/pickle)

Categories where generic SAST tools **should** perform well:

| Category | Pattern Type | ai-security-cli | Semgrep | Bandit | Generic Detectable? |
|----------|--------------|-----------------|---------|--------|---------------------|
| LLM02 | eval/exec/SQL | F1=0.35 | F1=0.43 | **F1=0.82** | ✅ Yes |
| LLM03 | pickle.load | F1=0.57 | F1=0.00 | F1=0.60 | ✅ Yes |
| LLM07 | shell/exec | F1=0.71 | F1=0.25 | **F1=0.83** | ✅ Yes |
| LLM08 | exec/subprocess | F1=0.50 | F1=0.29 | F1=0.50 | ✅ Yes |

**Observations:**
- Bandit excels at LLM02 (0.82 F1) and LLM07 (0.83 F1) - **expected for eval/exec patterns**
- Generic tools provide good baseline coverage for these categories
- This is fair territory for comparison - tools are designed for these patterns

### LLM-Specific Patterns

Categories where generic SAST tools are **not expected** to detect:

| Category | Pattern Type | ai-security-cli | Semgrep | Bandit | Generic Detectable? |
|----------|--------------|-----------------|---------|--------|---------------------|
| LLM01 | Prompt injection | **F1=0.60** | F1=0.00 | F1=0.15 | ❌ No rules exist |
| LLM04 | Model DoS | **F1=0.80** | F1=0.00 | F1=0.00 | ❌ No rules exist |
| LLM05 | Supply chain | **F1=0.57** | F1=0.00 | F1=0.39 | ⚠️ Partial (pickle) |
| LLM06 | Sensitive info | **F1=0.63** | F1=0.00 | F1=0.00 | ❌ No rules exist |
| LLM09 | Overreliance | F1=0.80 | F1=0.00 | F1=0.80 | ⚠️ Partial (exec) |
| LLM10 | Model theft | **F1=0.44** | F1=0.00 | F1=0.00 | ❌ No rules exist |

**Observations:**
- Low scores for Semgrep/Bandit here are **expected behavior, not deficiencies**
- ai-security-cli provides unique coverage for LLM01, LLM04, LLM06, LLM10
- LLM09 overlap is due to shared exec patterns, not LLM-specific awareness

## Overall Summary

| Metric | ai-security-cli | Semgrep | Bandit |
|--------|-----------------|---------|--------|
| Precision | 68.5% | 83.3% | 58.3% |
| Recall | 50.7% | 6.8% | 38.4% |
| F1 Score | 58.3% | 12.7% | 46.3% |

## Recommendations

1. **Use both tools together** - Generic SAST + specialized LLM scanning provides broader coverage
2. **Bandit for baseline** - Strong at eval/exec/pickle patterns
3. **ai-security-cli for LLM-specific** - Essential for prompt injection, model DoS, sensitive info
4. **Semgrep for custom rules** - Consider custom LLM rules to extend coverage

## Threats to Validity

1. **Testbed Design Bias**: The 73 vulnerabilities were labeled for LLM-specific issues.
   ~60% have no equivalent generic detection rules. This tests tools OUTSIDE their intended scope.

2. **Rule Set Asymmetry**: ai-security-cli has custom LLM rules; Semgrep/Bandit use default configs.
   A fairer test would include Semgrep with custom LLM-focused rules.

3. **Author-Curated Dataset**: Testbed was created by ai-security-cli authors.
   External validation on real-world LLM codebases would strengthen findings.

4. **Detection ≠ Actionability**: Results show detection rates, not false positive burden
   in production or remediation guidance quality.

## Future Enhancements

Per reviewer feedback, future versions may include:

1. **"Tuned Semgrep" row** - Custom LLM security rules to show what generic tools could achieve with investment
2. **Secrets/SCA baselines** - detect-secrets, gitleaks, pip-audit for supply chain categories
3. **Real-world validation** - Sampled human FP rate on production LLM repositories
4. **Reproducibility package** - Makefile/Dockerfile with pinned tool versions
