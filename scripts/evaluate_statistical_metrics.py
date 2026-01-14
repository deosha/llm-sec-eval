#!/usr/bin/env python3
"""
Statistical validation experiments for semantic taint analysis.

1. Train/Test split validation (held-out categories)
2. Per-category breakdown with confidence intervals
3. Category A (semantic) vs Category B (traditional) analysis

Usage: python3 evaluate_statistical_metrics.py
"""

import json
import os
import random
import subprocess
import yaml
import math
from pathlib import Path
from typing import Dict, List, Set, Tuple
from collections import defaultdict

TESTBED_DIR = Path("testbed")
CVE_DIR = Path("cve_benchmark")
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


def load_all_labels() -> Dict[str, List[Dict]]:
    """Load ground truth from all categories."""
    labels = {}
    for cat in CATEGORIES:
        labels_path = TESTBED_DIR / cat / "labels.yaml"
        if labels_path.exists():
            with open(labels_path) as f:
                data = yaml.safe_load(f)
                labels[cat] = data.get("static_findings", [])
    return labels


def wilson_confidence_interval(successes: int, total: int, confidence: float = 0.95) -> Tuple[float, float]:
    """Calculate Wilson score confidence interval for proportions."""
    if total == 0:
        return (0.0, 0.0)

    z = 1.96 if confidence == 0.95 else 1.645  # 95% or 90% CI
    p = successes / total

    denominator = 1 + z**2 / total
    center = (p + z**2 / (2 * total)) / denominator
    margin = z * math.sqrt((p * (1 - p) + z**2 / (4 * total)) / total) / denominator

    return (max(0, center - margin), min(1, center + margin))


def scan_directory(path: Path) -> List[Dict]:
    """Run aisentry scan and return findings."""
    output_file = Path("/tmp/validation_scan.json")

    try:
        result = subprocess.run(
            ["aisentry", "scan", str(path),
             "--taint-analysis", "--no-ml-detection", "--no-ensemble",
             "-o", "json", "-f", str(output_file)],
            capture_output=True, text=True, timeout=300
        )

        if output_file.exists():
            with open(output_file) as f:
                data = json.load(f)
            return data.get("findings", []) if isinstance(data, dict) else data
    except Exception as e:
        print(f"  Warning: Scan failed: {e}")

    return []


def match_findings_to_labels(findings: List[Dict], labels: List[Dict], tolerance: int = 3) -> Tuple[int, int, int]:
    """Match findings to ground truth labels with line tolerance."""
    detected = set()
    for f in findings:
        file_path = f.get("file_path", "") or f.get("file", "")
        line = f.get("line_number", 0) or f.get("line", 0)
        if file_path and line:
            detected.add((Path(file_path).name, line))

    gt_set = {(l["file"], l["line"]) for l in labels}

    tp = 0
    matched_gt = set()
    for d_file, d_line in detected:
        for gt_file, gt_line in gt_set:
            if d_file == gt_file and abs(d_line - gt_line) <= tolerance:
                tp += 1
                matched_gt.add((gt_file, gt_line))
                break

    fp = len(detected) - tp
    fn = len(gt_set) - len(matched_gt)

    return tp, fp, fn


def experiment1_train_test_split():
    """Train/Test split validation."""
    print("\n" + "="*60)
    print("EXPERIMENT 1: Train/Test Split Validation")
    print("="*60)

    all_labels = load_all_labels()

    # Count per category
    counts = {cat: len(labels) for cat, labels in all_labels.items()}
    total = sum(counts.values())
    print(f"\nTotal ground truth vulnerabilities: {total}")

    # Random split: 7 train, 3 test
    random.seed(42)
    shuffled = CATEGORIES.copy()
    random.shuffle(shuffled)

    train_cats = shuffled[:7]
    test_cats = shuffled[7:]

    train_count = sum(counts[c] for c in train_cats)
    test_count = sum(counts[c] for c in test_cats)

    print(f"\nTrain set: {len(train_cats)} categories, {train_count} vulnerabilities")
    print(f"Test set: {len(test_cats)} categories, {test_count} vulnerabilities")

    results = {"train": {}, "test": {}}

    # Evaluate on train set
    print("\n--- Training Set ---")
    train_tp, train_fp, train_fn = 0, 0, 0
    for cat in train_cats:
        findings = scan_directory(TESTBED_DIR / cat)
        tp, fp, fn = match_findings_to_labels(findings, all_labels.get(cat, []))
        train_tp += tp
        train_fp += fp
        train_fn += fn
        print(f"  {cat}: TP={tp}, FP={fp}, FN={fn}")

    train_p = train_tp / (train_tp + train_fp) if (train_tp + train_fp) > 0 else 0
    train_r = train_tp / (train_tp + train_fn) if (train_tp + train_fn) > 0 else 0
    train_f1 = 2 * train_p * train_r / (train_p + train_r) if (train_p + train_r) > 0 else 0

    results["train"] = {
        "categories": train_cats,
        "tp": train_tp, "fp": train_fp, "fn": train_fn,
        "precision": train_p, "recall": train_r, "f1": train_f1
    }
    print(f"\nTrain: P={train_p:.3f}, R={train_r:.3f}, F1={train_f1:.3f}")

    # Evaluate on test set
    print("\n--- Test Set ---")
    test_tp, test_fp, test_fn = 0, 0, 0
    for cat in test_cats:
        findings = scan_directory(TESTBED_DIR / cat)
        tp, fp, fn = match_findings_to_labels(findings, all_labels.get(cat, []))
        test_tp += tp
        test_fp += fp
        test_fn += fn
        print(f"  {cat}: TP={tp}, FP={fp}, FN={fn}")

    test_p = test_tp / (test_tp + test_fp) if (test_tp + test_fp) > 0 else 0
    test_r = test_tp / (test_tp + test_fn) if (test_tp + test_fn) > 0 else 0
    test_f1 = 2 * test_p * test_r / (test_p + test_r) if (test_p + test_r) > 0 else 0

    results["test"] = {
        "categories": test_cats,
        "tp": test_tp, "fp": test_fp, "fn": test_fn,
        "precision": test_p, "recall": test_r, "f1": test_f1
    }
    print(f"\nTest: P={test_p:.3f}, R={test_r:.3f}, F1={test_f1:.3f}")

    # Calculate generalization gap
    gap = abs(train_f1 - test_f1)
    print(f"\n*** Generalization gap: {gap:.3f} ***")

    with open(RESULTS_DIR / "train_test_split.json", "w") as f:
        json.dump(results, f, indent=2)

    return results


def experiment2_confidence_intervals():
    """Calculate confidence intervals for precision estimates."""
    print("\n" + "="*60)
    print("EXPERIMENT 2: Confidence Intervals")
    print("="*60)

    all_labels = load_all_labels()

    total_tp, total_fp, total_fn = 0, 0, 0
    per_category = {}

    for cat in CATEGORIES:
        print(f"\nScanning {cat}...")
        findings = scan_directory(TESTBED_DIR / cat)
        tp, fp, fn = match_findings_to_labels(findings, all_labels.get(cat, []))

        total_tp += tp
        total_fp += fp
        total_fn += fn

        cat_p = tp / (tp + fp) if (tp + fp) > 0 else 0
        cat_r = tp / (tp + fn) if (tp + fn) > 0 else 0

        per_category[cat] = {
            "tp": tp, "fp": fp, "fn": fn,
            "precision": cat_p, "recall": cat_r,
            "n_findings": tp + fp
        }
        print(f"  TP={tp}, FP={fp}, FN={fn}, P={cat_p:.3f}, R={cat_r:.3f}")

    # Overall metrics with confidence intervals
    total_findings = total_tp + total_fp
    overall_precision = total_tp / total_findings if total_findings > 0 else 0
    overall_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0

    precision_ci = wilson_confidence_interval(total_tp, total_findings)
    recall_ci = wilson_confidence_interval(total_tp, total_tp + total_fn)

    print(f"\n*** Overall Results ***")
    print(f"Precision: {overall_precision:.3f} (95% CI: {precision_ci[0]:.3f}-{precision_ci[1]:.3f})")
    print(f"Recall: {overall_recall:.3f} (95% CI: {recall_ci[0]:.3f}-{recall_ci[1]:.3f})")

    results = {
        "overall": {
            "precision": overall_precision,
            "precision_ci_95": precision_ci,
            "recall": overall_recall,
            "recall_ci_95": recall_ci,
            "tp": total_tp, "fp": total_fp, "fn": total_fn,
            "total_findings": total_findings
        },
        "per_category": per_category
    }

    with open(RESULTS_DIR / "confidence_intervals.json", "w") as f:
        json.dump(results, f, indent=2)

    return results


def experiment3_category_a_vs_b():
    """Breakdown of Category A (semantic) vs Category B (traditional) findings."""
    print("\n" + "="*60)
    print("EXPERIMENT 3: Category A vs B Analysis")
    print("="*60)

    # Categories where semantic taint is required
    semantic_categories = ["LLM01_prompt_injection", "LLM02_insecure_output",
                          "LLM06_sensitive_info", "LLM08_excessive_agency"]

    # Categories with traditional vulnerabilities
    traditional_categories = ["LLM03_training_poisoning", "LLM04_model_dos",
                             "LLM05_supply_chain", "LLM07_insecure_plugin",
                             "LLM09_overreliance", "LLM10_model_theft"]

    all_labels = load_all_labels()

    cat_a_tp, cat_a_fp, cat_a_fn = 0, 0, 0
    cat_b_tp, cat_b_fp, cat_b_fn = 0, 0, 0

    print("\n--- Category A (Semantic Taint Required) ---")
    for cat in semantic_categories:
        if cat in all_labels:
            findings = scan_directory(TESTBED_DIR / cat)
            tp, fp, fn = match_findings_to_labels(findings, all_labels[cat])
            cat_a_tp += tp
            cat_a_fp += fp
            cat_a_fn += fn
            print(f"  {cat}: TP={tp}, FP={fp}")

    print("\n--- Category B (Traditional) ---")
    for cat in traditional_categories:
        if cat in all_labels:
            findings = scan_directory(TESTBED_DIR / cat)
            tp, fp, fn = match_findings_to_labels(findings, all_labels[cat])
            cat_b_tp += tp
            cat_b_fp += fp
            cat_b_fn += fn
            print(f"  {cat}: TP={tp}, FP={fp}")

    cat_a_precision = cat_a_tp / (cat_a_tp + cat_a_fp) if (cat_a_tp + cat_a_fp) > 0 else 0
    cat_b_precision = cat_b_tp / (cat_b_tp + cat_b_fp) if (cat_b_tp + cat_b_fp) > 0 else 0

    cat_a_ci = wilson_confidence_interval(cat_a_tp, cat_a_tp + cat_a_fp)
    cat_b_ci = wilson_confidence_interval(cat_b_tp, cat_b_tp + cat_b_fp)

    print(f"\n*** Category A (Semantic): P={cat_a_precision:.3f} (95% CI: {cat_a_ci[0]:.3f}-{cat_a_ci[1]:.3f})")
    print(f"*** Category B (Traditional): P={cat_b_precision:.3f} (95% CI: {cat_b_ci[0]:.3f}-{cat_b_ci[1]:.3f})")

    results = {
        "category_a": {
            "categories": semantic_categories,
            "tp": cat_a_tp, "fp": cat_a_fp, "fn": cat_a_fn,
            "precision": cat_a_precision,
            "precision_ci_95": cat_a_ci
        },
        "category_b": {
            "categories": traditional_categories,
            "tp": cat_b_tp, "fp": cat_b_fp, "fn": cat_b_fn,
            "precision": cat_b_precision,
            "precision_ci_95": cat_b_ci
        }
    }

    with open(RESULTS_DIR / "category_a_vs_b.json", "w") as f:
        json.dump(results, f, indent=2)

    return results


def main():
    print("="*60)
    print("STATISTICAL VALIDATION EXPERIMENTS")
    print("="*60)

    exp1 = experiment1_train_test_split()
    exp2 = experiment2_confidence_intervals()
    exp3 = experiment3_category_a_vs_b()

    print("\n" + "="*60)
    print("ALL EXPERIMENTS COMPLETE")
    print("="*60)
    print(f"\nResults saved to: {RESULTS_DIR}")

    # Summary for paper
    print("\n*** SUMMARY FOR PAPER ***")
    print(f"Train/Test F1 gap: {abs(exp1['train']['f1'] - exp1['test']['f1']):.3f}")
    print(f"Overall Precision: {exp2['overall']['precision']:.3f} ({exp2['overall']['precision_ci_95'][0]:.3f}-{exp2['overall']['precision_ci_95'][1]:.3f})")
    print(f"Category A Precision: {exp3['category_a']['precision']:.3f}")
    print(f"Category B Precision: {exp3['category_b']['precision']:.3f}")


if __name__ == "__main__":
    main()
