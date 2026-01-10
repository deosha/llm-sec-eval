# LLM Security Evaluation Framework
# Makefile for reproducible evaluation runs

.PHONY: help build eval-all eval-testbed eval-langchain eval-llamaindex \
        eval-haystack report clean aggregate

# Configuration
SHELL := /bin/bash
PYTHON := python3
PARALLELISM := 5
TIMEOUT := 30
MODE := standard

# API configuration (set via environment)
# OPENAI_API_KEY, ANTHROPIC_API_KEY

help:
	@echo "LLM Security Evaluation Framework"
	@echo ""
	@echo "Setup:"
	@echo "  make build              Build Docker environment"
	@echo "  make install            Install dependencies locally"
	@echo ""
	@echo "Evaluation:"
	@echo "  make eval-all           Run all evaluations"
	@echo "  make eval-testbed       Evaluate synthetic testbed only"
	@echo "  make eval-langchain     Evaluate LangChain subset"
	@echo "  make eval-llamaindex    Evaluate LlamaIndex subset"
	@echo "  make eval-haystack      Evaluate Haystack subset"
	@echo ""
	@echo "Analysis:"
	@echo "  make aggregate          Aggregate all results"
	@echo "  make report             Generate comparison report"
	@echo "  make plots              Generate visualization plots"
	@echo ""
	@echo "Utilities:"
	@echo "  make clean              Remove all results"
	@echo "  make clean-results      Remove results only (keep testbed)"

# =============================================================================
# SETUP
# =============================================================================

build:
	docker build -t llm-sec-eval .

install:
	pip install -r requirements.txt
	npm install -g promptfoo

# =============================================================================
# SYNTHETIC TESTBED EVALUATION
# =============================================================================

eval-testbed: eval-testbed-static eval-testbed-audit
	@echo "Testbed evaluation complete"

eval-testbed-static:
	@echo "Running static analysis on testbed..."
	@for dir in testbed/llm*; do \
		name=$$(basename $$dir); \
		echo "  Scanning $$name..."; \
		mkdir -p results/aisec/testbed/$$name; \
		aisentry scan $$dir -o json -f results/aisec/testbed/$$name/scan.json 2>/dev/null || true; \
		aisentry scan $$dir -o sarif -f results/aisec/testbed/$$name/scan.sarif 2>/dev/null || true; \
	done
	@echo "Running Semgrep on testbed..."
	@for dir in testbed/llm*; do \
		name=$$(basename $$dir); \
		mkdir -p results/semgrep/testbed/$$name; \
		semgrep --config p/python --json -o results/semgrep/testbed/$$name/semgrep.json $$dir 2>/dev/null || true; \
	done
	@echo "Running Bandit on testbed..."
	@for dir in testbed/llm*; do \
		name=$$(basename $$dir); \
		mkdir -p results/bandit/testbed/$$name; \
		bandit -r $$dir -f json -o results/bandit/testbed/$$name/bandit.json 2>/dev/null || true; \
	done
	@echo "Running detect-secrets on testbed..."
	@for dir in testbed/llm*; do \
		name=$$(basename $$dir); \
		mkdir -p results/secrets/testbed/$$name; \
		detect-secrets scan $$dir > results/secrets/testbed/$$name/secrets.json 2>/dev/null || true; \
	done

eval-testbed-audit:
	@echo "Running security audit on testbed..."
	@for dir in testbed/llm*; do \
		name=$$(basename $$dir); \
		mkdir -p results/aisec/testbed/$$name; \
		aisentry audit $$dir -o json -f results/aisec/testbed/$$name/audit.json 2>/dev/null || true; \
	done

eval-testbed-live:
	@echo "Running live tests (requires API keys)..."
	@if [ -z "$$OPENAI_API_KEY" ]; then \
		echo "ERROR: OPENAI_API_KEY not set"; \
		exit 1; \
	fi
	mkdir -p results/aisec/testbed/live
	aisentry test -p openai -m gpt-4o --mode $(MODE) \
		--timeout $(TIMEOUT) -o json \
		-f results/aisec/testbed/live/openai.json

# =============================================================================
# REAL REPOSITORY EVALUATION
# =============================================================================

# LangChain
LANGCHAIN_PATH := repos/langchain
LANGCHAIN_SUBSET := libs/langchain/langchain templates

eval-langchain: clone-langchain
	@echo "Evaluating LangChain..."
	@mkdir -p results/aisec/langchain results/semgrep/langchain results/bandit/langchain
	@for subset in $(LANGCHAIN_SUBSET); do \
		if [ -d "$(LANGCHAIN_PATH)/$$subset" ]; then \
			aisentry scan $(LANGCHAIN_PATH)/$$subset -o json \
				-f results/aisec/langchain/scan_$$(echo $$subset | tr '/' '_').json 2>/dev/null || true; \
		fi; \
	done
	aisentry audit $(LANGCHAIN_PATH) -o json -f results/aisec/langchain/audit.json 2>/dev/null || true

clone-langchain:
	@if [ ! -d "$(LANGCHAIN_PATH)" ]; then \
		mkdir -p repos; \
		git clone --depth 1 https://github.com/langchain-ai/langchain.git $(LANGCHAIN_PATH); \
	fi

# LlamaIndex
LLAMAINDEX_PATH := repos/llama_index
LLAMAINDEX_SUBSET := llama_index/core

eval-llamaindex: clone-llamaindex
	@echo "Evaluating LlamaIndex..."
	@mkdir -p results/aisec/llamaindex
	aisentry scan $(LLAMAINDEX_PATH)/$(LLAMAINDEX_SUBSET) -o json \
		-f results/aisec/llamaindex/scan.json 2>/dev/null || true
	aisentry audit $(LLAMAINDEX_PATH) -o json \
		-f results/aisec/llamaindex/audit.json 2>/dev/null || true

clone-llamaindex:
	@if [ ! -d "$(LLAMAINDEX_PATH)" ]; then \
		mkdir -p repos; \
		git clone --depth 1 https://github.com/run-llama/llama_index.git $(LLAMAINDEX_PATH); \
	fi

# Haystack
HAYSTACK_PATH := repos/haystack
HAYSTACK_SUBSET := haystack/core

eval-haystack: clone-haystack
	@echo "Evaluating Haystack..."
	@mkdir -p results/aisec/haystack
	aisentry scan $(HAYSTACK_PATH)/$(HAYSTACK_SUBSET) -o json \
		-f results/aisec/haystack/scan.json 2>/dev/null || true
	aisentry audit $(HAYSTACK_PATH) -o json \
		-f results/aisec/haystack/audit.json 2>/dev/null || true

clone-haystack:
	@if [ ! -d "$(HAYSTACK_PATH)" ]; then \
		mkdir -p repos; \
		git clone --depth 1 https://github.com/deepset-ai/haystack.git $(HAYSTACK_PATH); \
	fi

# =============================================================================
# ALL EVALUATIONS
# =============================================================================

eval-all: eval-testbed eval-langchain eval-llamaindex eval-haystack
	@echo "All evaluations complete"

# =============================================================================
# ANALYSIS
# =============================================================================

aggregate:
	@echo "Aggregating results..."
	$(PYTHON) scripts/aggregate_static.py
	$(PYTHON) scripts/aggregate_audit.py
	@echo "Results aggregated to results/aggregated/"

report: aggregate
	@echo "Generating comparison report..."
	$(PYTHON) scripts/compare_baselines.py
	@echo "Report generated at results/report.html"

plots: aggregate
	@echo "Generating plots..."
	$(PYTHON) scripts/generate_plots.py
	@echo "Plots saved to results/plots/"

# =============================================================================
# UTILITIES
# =============================================================================

clean:
	rm -rf results/*
	rm -rf repos/*
	rm -rf metadata/*

clean-results:
	rm -rf results/*
	rm -rf metadata/*

versions:
	@echo "Tool Versions:"
	@echo "  aisentry: $$(aisentry --version 2>/dev/null || echo 'not installed')"
	@echo "  semgrep: $$(semgrep --version 2>/dev/null || echo 'not installed')"
	@echo "  bandit: $$(bandit --version 2>/dev/null || echo 'not installed')"
	@echo "  detect-secrets: $$(detect-secrets --version 2>/dev/null || echo 'not installed')"
	@echo "  pip-audit: $$(pip-audit --version 2>/dev/null || echo 'not installed')"
	@echo "  promptfoo: $$(promptfoo --version 2>/dev/null || echo 'not installed')"
	@echo "  garak: $$(garak --version 2>/dev/null || echo 'not installed')"
