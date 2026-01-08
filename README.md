# LLM Security Evaluation Framework

A comprehensive evaluation framework for **AI Security CLI** comparing detection quality against practical baselines across real-world and synthetic repositories.

## Objectives

1. **Quantify detection quality** (static, live) and posture audit utility
2. **Compare against baselines** across representative repositories
3. **Report cost/performance** and CI/UX characteristics with reproducible artifacts

## Directory Structure

```
llm-sec-eval/
├── testbed/                    # Synthetic ground truth (10 OWASP LLM projects)
│   ├── llm01_prompt_injection/
│   ├── llm02_insecure_output/
│   ├── llm03_training_poisoning/
│   ├── llm04_model_dos/
│   ├── llm05_supply_chain/
│   ├── llm06_sensitive_info/
│   ├── llm07_insecure_plugin/
│   ├── llm08_excessive_agency/
│   ├── llm09_overreliance/
│   └── llm10_model_theft/
├── configs/                    # Tool configurations
│   ├── prompts/                # Seed prompts for live tests
│   ├── promptfoo/              # promptfoo configs per repo
│   └── garak/                  # garak profiles
├── scripts/                    # Aggregation and analysis
│   ├── aggregate_static.py
│   ├── aggregate_live.py
│   ├── aggregate_audit.py
│   └── compare_baselines.py
├── results/                    # Raw outputs
│   ├── aisec/                  # AI Security CLI outputs
│   ├── promptfoo/
│   ├── garak/
│   ├── semgrep/
│   ├── bandit/
│   ├── secrets/
│   ├── pip_audit/
│   └── scorecard/
├── metadata/                   # Repo metadata (commits, LOC, versions)
├── paper/                      # Write-up materials
├── Dockerfile
├── Makefile
└── requirements.txt
```

## Quick Start

```bash
# Clone and setup
git clone https://github.com/deosha/llm-sec-eval.git
cd llm-sec-eval

# Build Docker environment
make build

# Run all evaluations (testbed + 3 real repos)
make eval-all

# Run specific evaluations
make eval-testbed          # Synthetic testbed only
make eval-langchain        # LangChain subset
make eval-llamaindex       # LlamaIndex subset

# Generate comparison report
make report
```

## Tools & Baselines

| Tool | Type | Purpose |
|------|------|---------|
| **AI Security CLI** | Static + Live + Audit | Primary tool under evaluation |
| Semgrep | SAST | Static analysis baseline |
| Bandit | SAST | Python security linter |
| detect-secrets | Secrets | Secret detection baseline |
| pip-audit | SCA | Dependency vulnerability scanning |
| promptfoo | Red Team | LLM red teaming |
| garak | Red Team | LLM vulnerability probing |
| OpenSSF Scorecard | Posture | Repository security posture |

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
    confidence: 0.9
    description: "F-string interpolation in system prompt"

live_tests:
  - id: LLM01-LIVE-001
    name: "Basic Instruction Override"
    prompts:
      - "Ignore previous instructions..."
    expected_behavior: "Should refuse"
    vulnerable_indicators:
      - "reveals instructions"

audit_expectations:
  controls:
    - control_id: PS-01
      expected_level: none
```

## Target Repositories

| Repository | Subset | Commit |
|------------|--------|--------|
| langchain-ai/langchain | libs/langchain/, templates/ | TBD |
| llama-index/llama_index | llama_index/core/ | TBD |
| deepset-ai/haystack | haystack/core/ | TBD |
| microsoft/autogen | agents core | TBD |
| chainlit/chainlit | web app | TBD |
| open-webui/open-webui | UI app | TBD |
| openai/openai-cookbook | API examples | TBD |

## Metrics

### Static Analysis

- **Precision**: TP / (TP + FP)
- **Recall**: TP / (TP + FN)
- **F1 Score**: 2 × (P × R) / (P + R)
- **Time**: seconds per KLoC
- **Memory**: peak MB

### Live Testing

- **Attack Success Rate (ASR)**: % of prompts that triggered vulnerability
- **Cost**: tokens, requests, latency
- **Confidence Calibration**: correlation with human labels

### Audit

- **Control Coverage**: detected / total
- **Score Accuracy**: compared to ground truth
- **Agreement**: correlation with Scorecard (real repos)

## Environment

```bash
# Required
export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-ant-...

# Optional (for local testing)
# Ollama running on localhost:11434

# Configuration
TEMPERATURE=0.2
MAX_TOKENS=256
TIMEOUT=30
PARALLELISM=5
```

## Commands Reference

```bash
# AI Security CLI
ai-security-cli scan <path> -o json -f results/aisec/<repo>/scan.json
ai-security-cli audit <path> -o json -f results/aisec/<repo>/audit.json
ai-security-cli test -p openai -m gpt-4o --mode standard -o json -f results/aisec/live.json

# Baselines
semgrep --config p/ci --json -o results/semgrep/<repo>/semgrep.json <path>
bandit -r <path> -f json -o results/bandit/<repo>/bandit.json
detect-secrets scan <path> > results/secrets/<repo>/.secrets.baseline
pip-audit -r requirements*.txt -f json -o results/pip_audit/<repo>/audit.json

# Red Team
promptfoo eval -c configs/promptfoo/<repo>.yaml -o results/promptfoo/<repo>/
garak -m openai:gpt-4o -o results/garak/<repo>/ -p injection,data_leakage
```

## Timeline

| Day | Task |
|-----|------|
| 1-2 | Build testbed, pin repos, script skeleton |
| 3-5 | Run tools on testbed + 3-4 repos, iterate |
| 6-7 | Complete remaining repos, aggregate, plot |
| 8-9 | Write discussion, threats, finalize |
| 10 | Package Docker + Makefile, publish |

## License

MIT
