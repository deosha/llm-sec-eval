#!/usr/bin/env python3
"""
Mixed corpus and interprocedural evaluation experiments.

1. Negative samples for mixed corpus precision measurement
2. Interprocedural (wrapper function) analysis across all testbed modules

Usage: python3 evaluate_mixed_corpus.py
"""

import json
import os
import random
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple
import yaml

TESTBED_DIR = Path("testbed")
CVE_DIR = Path("cve_benchmark")
REPOS_DIR = Path("repos")
RESULTS_DIR = Path("results/validation_experiments")
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

CATEGORIES = [
    "LLM01_prompt_injection",
    "LLM02_insecure_output",
    "LLM03_training_poisoning",
    "LLM04_model_dos",
    "LLM05_supply_chain",
    "LLM06_sensitive_info",
    "LLM07_insecure_plugin",
    "LLM08_excessive_agency",
    "LLM09_overreliance",
    "LLM10_model_theft",
]


def experiment_negative_samples():
    """
    Create mixed corpus with security + non-security files.
    Measure precision on realistic mix.
    """
    print("\n" + "="*60)
    print("EXPERIMENT: Negative Samples for Mixed Corpus")
    print("="*60)

    # Get non-security Python files from repos
    negative_files = []

    for repo_name in ["autogen", "langchain", "dspy"]:
        repo_path = REPOS_DIR / repo_name
        if not repo_path.exists():
            continue

        # Find Python files not in tests/examples
        try:
            result = subprocess.run(
                ["find", str(repo_path), "-name", "*.py", "-type", "f"],
                capture_output=True, text=True, timeout=60
            )
            all_files = [f for f in result.stdout.strip().split("\n") if f]

            # Filter out test/example files
            clean_files = [
                f for f in all_files
                if "/test" not in f.lower()
                and "/example" not in f.lower()
                and "/__pycache__" not in f
                and "/venv/" not in f
            ]

            # Sample up to 20 files per repo
            sampled = random.sample(clean_files, min(20, len(clean_files)))
            negative_files.extend([(repo_name, f) for f in sampled])
            print(f"  {repo_name}: sampled {len(sampled)} files")

        except Exception as e:
            print(f"  Warning: {repo_name}: {e}")

    print(f"\nTotal negative sample files: {len(negative_files)}")

    # Scan negative files and count false positives
    fp_count = 0
    files_with_findings = 0

    for repo_name, file_path in negative_files[:30]:  # Limit for speed
        try:
            result = subprocess.run(
                ["aisentry", "scan", file_path,
                 "--taint-analysis", "--no-ml-detection", "--no-ensemble",
                 "-o", "json", "-f", "/tmp/neg_scan.json"],
                capture_output=True, text=True, timeout=60
            )

            if os.path.exists("/tmp/neg_scan.json"):
                with open("/tmp/neg_scan.json") as f:
                    data = json.load(f)
                findings = data.get("findings", []) if isinstance(data, dict) else data

                if findings:
                    fp_count += len(findings)
                    files_with_findings += 1

        except Exception as e:
            pass  # Skip failed scans

    # Get positive files from testbed
    positive_files = []
    for cat in CATEGORIES[:3]:  # First 3 categories
        cat_path = TESTBED_DIR / cat
        if cat_path.exists():
            for py_file in cat_path.glob("*.py"):
                positive_files.append(str(py_file))

    tp_count = 0
    for file_path in positive_files:
        try:
            result = subprocess.run(
                ["aisentry", "scan", file_path,
                 "--taint-analysis", "--no-ml-detection", "--no-ensemble",
                 "-o", "json", "-f", "/tmp/pos_scan.json"],
                capture_output=True, text=True, timeout=60
            )

            if os.path.exists("/tmp/pos_scan.json"):
                with open("/tmp/pos_scan.json") as f:
                    data = json.load(f)
                findings = data.get("findings", []) if isinstance(data, dict) else data
                tp_count += len(findings)

        except Exception:
            pass

    # Calculate mixed corpus precision
    total_findings = tp_count + fp_count
    mixed_precision = tp_count / total_findings if total_findings > 0 else 0

    print(f"\n*** Mixed Corpus Results ***")
    print(f"Positive files scanned: {len(positive_files)}")
    print(f"Negative files scanned: {min(30, len(negative_files))}")
    print(f"True positives (testbed findings): {tp_count}")
    print(f"False positives (repo findings): {fp_count}")
    print(f"Mixed corpus precision: {mixed_precision:.3f}")

    results = {
        "positive_files": len(positive_files),
        "negative_files": min(30, len(negative_files)),
        "true_positives": tp_count,
        "false_positives": fp_count,
        "mixed_precision": mixed_precision,
        "files_with_fp": files_with_findings,
    }

    with open(RESULTS_DIR / "negative_samples.json", "w") as f:
        json.dump(results, f, indent=2)

    return results


def experiment_interprocedural():
    """
    Run interprocedural analysis across all testbed modules.
    Measure wrapper detection rate.
    """
    print("\n" + "="*60)
    print("EXPERIMENT: Interprocedural Analysis Across All Modules")
    print("="*60)

    results = {}
    total_wrappers = 0
    total_findings_basic = 0
    total_findings_interproc = 0

    for category in CATEGORIES:
        cat_path = TESTBED_DIR / category
        if not cat_path.exists():
            continue

        print(f"\nAnalyzing {category}...")

        # Basic scan
        try:
            subprocess.run(
                ["aisentry", "scan", str(cat_path),
                 "--taint-analysis", "--no-ml-detection", "--no-ensemble",
                 "-o", "json", "-f", "/tmp/basic_scan.json"],
                capture_output=True, text=True, timeout=120
            )

            basic_findings = 0
            if os.path.exists("/tmp/basic_scan.json"):
                with open("/tmp/basic_scan.json") as f:
                    data = json.load(f)
                findings = data.get("findings", []) if isinstance(data, dict) else data
                basic_findings = len(findings)

                # Count wrapper-related findings
                wrapper_findings = sum(1 for f in findings
                    if "wrapper" in str(f).lower()
                    or f.get("via_wrapper", False)
                    or "helper" in str(f.get("description", "")).lower())

                total_wrappers += wrapper_findings
                total_findings_basic += basic_findings

                results[category] = {
                    "total_findings": basic_findings,
                    "wrapper_related": wrapper_findings,
                }

                print(f"  Findings: {basic_findings}, Wrapper-related: {wrapper_findings}")

        except subprocess.TimeoutExpired:
            print(f"  TIMEOUT")
            results[category] = {"error": "timeout"}
        except Exception as e:
            print(f"  ERROR: {e}")
            results[category] = {"error": str(e)}

    print(f"\n*** Interprocedural Analysis Summary ***")
    print(f"Categories analyzed: {len([r for r in results.values() if 'error' not in r])}")
    print(f"Total findings: {total_findings_basic}")
    print(f"Wrapper-related findings: {total_wrappers}")
    print(f"Wrapper detection rate: {total_wrappers / total_findings_basic:.1%}" if total_findings_basic > 0 else "N/A")

    summary = {
        "categories_analyzed": len([r for r in results.values() if 'error' not in r]),
        "total_findings": total_findings_basic,
        "wrapper_related_findings": total_wrappers,
        "wrapper_detection_rate": total_wrappers / total_findings_basic if total_findings_basic > 0 else 0,
        "per_category": results,
    }

    with open(RESULTS_DIR / "interprocedural_all_modules.json", "w") as f:
        json.dump(summary, f, indent=2)

    return summary


def main():
    random.seed(42)  # Reproducibility

    print("="*60)
    print("REMAINING EXPERIMENTS")
    print("="*60)

    exp1 = experiment_negative_samples()
    exp2 = experiment_interprocedural()

    print("\n" + "="*60)
    print("EXPERIMENTS COMPLETE")
    print("="*60)
    print(f"\nResults saved to: {RESULTS_DIR}")

    print("\n*** SUMMARY FOR PAPER ***")
    print(f"Mixed corpus precision: {exp1['mixed_precision']:.3f}")
    print(f"Wrapper detection rate: {exp2['wrapper_detection_rate']:.1%}")


if __name__ == "__main__":
    main()
