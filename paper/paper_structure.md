# AI Security CLI: A Unified Framework for LLM Application Security Assessment

## Paper Structure (Target: 12-15 pages)

---

## Abstract (250 words)

- Problem: LLM applications face unique security risks (OWASP LLM Top 10) not covered by traditional SAST tools
- Solution: AI Security CLI - unified static analysis, security posture audit, and live testing
- Contributions: (1) Novel LLM-specific detectors, (2) 61-control security posture framework, (3) 4-factor confidence scoring
- Results: Summary of P/R/F1 against baselines, audit accuracy, live testing ASR
- Availability: Open source, PyPI package

---

## 1. Introduction (1.5 pages)

### 1.1 Motivation
- Rapid adoption of LLMs in production applications
- Security risks unique to LLM systems (prompt injection, data leakage, excessive agency)
- Gap: Traditional SAST tools not designed for LLM-specific vulnerabilities

### 1.2 Problem Statement
- Need for comprehensive LLM security assessment covering:
  - Code-level vulnerabilities (static)
  - Security control maturity (audit)
  - Runtime behavior testing (live)

### 1.3 Contributions
1. **Static Analysis Pipeline**: 10 OWASP LLM-aligned detectors with confidence scoring
2. **Security Posture Audit**: 61 controls across 10 categories with maturity scoring
3. **Live Testing Engine**: 11 attack detectors with 4-factor confidence
4. **Empirical Evaluation**: Comparison against Semgrep, Bandit, promptfoo, garak on real-world repos

### 1.4 Paper Organization

---

## 2. Background & Related Work (1.5 pages)

### 2.1 OWASP LLM Top 10
- Overview of each category
- Real-world examples and impact

### 2.2 Existing LLM Security Tools
- Static: Semgrep rules for LLM, Bandit
- Red Team: promptfoo, garak, PyRIT
- Posture: OpenSSF Scorecard (general, not LLM-specific)

### 2.3 Gap Analysis
- No unified tool covering static + audit + live
- Limited LLM-specific pattern detection
- No maturity-based assessment framework

---

## 3. System Design (3 pages)

### 3.1 Architecture Overview
- Triple-pipeline design diagram
- CLI interface design

### 3.2 Static Analysis Pipeline
- Python AST parsing
- 10 OWASP detectors (patterns, examples)
- 7 category scorers
- Confidence scoring algorithm

### 3.3 Security Posture Audit Engine
- 3 analyzers (AST, Config, Dependencies)
- 10 control categories (61 controls)
- Evidence-based detection
- Maturity level calculation

### 3.4 Live Testing Engine
- 7 provider adapters
- 11 attack detectors
- 4-factor confidence scoring:
  - Response analysis (30%)
  - Detector logic (35%)
  - Evidence quality (25%)
  - Severity factor (10%)
- Testing modes (quick/standard/comprehensive)

### 3.5 Unified Reporting
- JSON/HTML/SARIF output
- Combined vulnerability + posture scores

---

## 4. Implementation (1 page)

### 4.1 Technology Stack
- Python 3.8+, Click CLI, Rich output
- OpenAI/Anthropic/Bedrock/Vertex/Azure/Ollama providers
- AST parsing with astunparse

### 4.2 Extensibility
- Plugin architecture for detectors
- Custom provider support
- Configurable thresholds

---

## 5. Evaluation Methodology (2 pages)

### 5.1 Research Questions
- RQ1: How does static detection compare to baseline SAST tools?
- RQ2: How accurate is the security posture audit?
- RQ3: How effective is live testing vs existing red-team tools?
- RQ4: What is the cost/performance profile?

### 5.2 Synthetic Testbed
- 10 projects (one per OWASP LLM category)
- Ground truth labels: static findings, live tests, audit expectations
- Total: X vulnerable code patterns, Y live test cases, Z controls

### 5.3 Real-World Repositories
| Repository | Subset | LOC | Description |
|------------|--------|-----|-------------|
| langchain | libs/langchain/ | ~150K | LLM framework |
| llama_index | core/ | ~80K | Data framework |
| haystack | core/ | ~50K | NLP framework |
| autogen | agents/ | ~40K | Multi-agent |
| chainlit | backend/ | ~25K | LLM app builder |
| open-webui | backend/ | ~30K | LLM interface |
| openai-cookbook | examples/ | ~15K | API examples |

### 5.4 Baseline Tools
- Static: Semgrep (p/python), Bandit
- Secrets: detect-secrets
- SCA: pip-audit
- Red Team: promptfoo, garak

### 5.5 Metrics
- Static: Precision, Recall, F1 (line-level matching with tolerance)
- Audit: Control detection accuracy, score correlation
- Live: Attack Success Rate (ASR), confidence calibration
- Engineering: Time (sec/KLoC), memory, API cost

---

## 6. Results (2.5 pages)

### 6.1 Static Analysis (RQ1)
- Table: P/R/F1 by OWASP category for AI Security CLI vs Semgrep vs Bandit
- Bar chart comparison
- Analysis: Where AI Security CLI excels (LLM-specific patterns)
- Analysis: Where baseline tools excel (general Python security)

### 6.2 Security Posture Audit (RQ2)
- Control detection accuracy on testbed
- Maturity score distribution on real repos
- Correlation with OpenSSF Scorecard (if applicable)

### 6.3 Live Testing (RQ3)
- ASR by attack vector and provider/model
- Comparison with promptfoo/garak coverage
- Confidence calibration analysis

### 6.4 Cost & Performance (RQ4)
- Scan time per KLoC
- API costs for live testing by mode
- Memory usage

### 6.5 Case Studies
- Case 1: Finding in langchain missed by baselines
- Case 2: False positive analysis
- Case 3: Hybrid detection (static + live)

---

## 7. Discussion (1 page)

### 7.1 Key Findings
- Unified approach provides complementary coverage
- LLM-specific detectors outperform generic SAST for LLM vulnerabilities
- Audit provides unique maturity-based view

### 7.2 Limitations
- Python-only for static analysis
- Live testing requires API access/costs
- Ground truth creation is manual effort

### 7.3 Threats to Validity
- Internal: Ground truth labeling bias
- External: Repository selection may not generalize
- Construct: Line-level matching tolerance

---

## 8. Future Work (0.5 pages)

- Multi-language support (JavaScript, Go)
- RAG-specific detectors
- Agent safety analysis
- Continuous monitoring mode
- Integration with IDE plugins

---

## 9. Conclusion (0.5 pages)

- Summary of contributions
- Key results
- Open source availability

---

## References

- OWASP LLM Top 10
- Related security tools
- LLM security research papers

---

## Appendix

### A. Complete Control List (61 controls)
### B. Detection Pattern Examples
### C. Reproducibility Checklist
### D. Artifact Links

---

## Figures

1. System architecture (triple-pipeline)
2. Static analysis flow
3. Audit engine flow
4. Live testing flow
5. P/R/F1 comparison bar chart
6. Audit accuracy pie chart
7. ASR by attack vector
8. Cost/time scatter plot

## Tables

1. OWASP LLM Top 10 summary
2. Control categories and counts
3. Static analysis P/R/F1 results
4. Live testing ASR by provider
5. Cost breakdown by testing mode
6. Repository characteristics
