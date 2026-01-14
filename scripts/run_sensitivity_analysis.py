#!/usr/bin/env python3
"""
Run sensitivity analysis on decay parameters.

This script:
1. Modifies the taint_tracker.py decay parameters
2. Re-runs the scanner on the testbed
3. Computes precision/recall against ground truth
4. Outputs results for all parameter combinations
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Tuple

# Paths
AISENTRY_DIR = Path(__file__).parent.parent.parent / "aisentry"
TAINT_TRACKER = AISENTRY_DIR / "src" / "aisentry" / "utils" / "taint_tracker.py"
TESTBED_DIR = Path(__file__).parent.parent / "testbed"
RESULTS_DIR = Path(__file__).parent.parent / "results" / "sensitivity"

# Default values
DEFAULT_PARAMS = {
    "STRONG": 0.85,      # prompt
    "MODERATE": 0.70,    # context
    "WEAK": 0.50,        # system
    "HOP_DECAY": 0.90,   # multi-hop
}

# Parameter sweep ranges
SWEEP_RANGES = {
    "STRONG": [0.75, 0.80, 0.85, 0.90, 0.95],
    "MODERATE": [0.60, 0.65, 0.70, 0.75, 0.80],
    "WEAK": [0.40, 0.45, 0.50, 0.55, 0.60],
    "HOP_DECAY": [0.80, 0.85, 0.90, 0.95, 1.00],
}


def load_ground_truth() -> Dict[str, List[Dict]]:
    """Load ground truth labels from all testbed projects."""
    import yaml
    ground_truth = {}

    for project_dir in sorted(TESTBED_DIR.glob("llm*")):
        labels_file = project_dir / "labels.yaml"
        if labels_file.exists():
            with open(labels_file) as f:
                data = yaml.safe_load(f)
                ground_truth[project_dir.name] = data.get("static_findings", [])

    return ground_truth


def modify_taint_tracker(params: Dict[str, float]) -> str:
    """Modify taint_tracker.py with new parameter values. Returns original content."""
    with open(TAINT_TRACKER) as f:
        original = f.read()

    modified = original

    # Update InfluenceStrength enum values
    modified = re.sub(
        r'STRONG = [\d.]+',
        f'STRONG = {params["STRONG"]}',
        modified
    )
    modified = re.sub(
        r'MODERATE = [\d.]+',
        f'MODERATE = {params["MODERATE"]}',
        modified
    )
    modified = re.sub(
        r'WEAK = [\d.]+',
        f'WEAK = {params["WEAK"]}',
        modified
    )

    # Update hop decay
    modified = re.sub(
        r'llm_hop_decay = [\d.]+',
        f'llm_hop_decay = {params["HOP_DECAY"]}',
        modified
    )

    with open(TAINT_TRACKER, 'w') as f:
        f.write(modified)

    return original


def restore_taint_tracker(original: str):
    """Restore original taint_tracker.py content."""
    with open(TAINT_TRACKER, 'w') as f:
        f.write(original)


def run_scan(project_dir: Path, semantic_only: bool = True) -> List[Dict]:
    """Run aisentry scan on a project and return findings.

    Args:
        project_dir: Directory to scan
        semantic_only: If True, only return semantic taint findings
    """
    try:
        # Use lower threshold (0.5) to see effect of decay parameters
        result = subprocess.run(
            ["aisentry", "scan", str(project_dir), "-o", "json", "-q", "--taint-analysis", "-c", "0.5"],
            capture_output=True,
            text=True,
            timeout=120
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            findings = data.get("findings", [])

            if semantic_only:
                # Filter for semantic taint findings only
                findings = [f for f in findings
                           if "semantic" in f.get("category", "").lower()
                           or "taint" in f.get("category", "").lower()]

            return findings
    except Exception as e:
        print(f"  Error scanning {project_dir.name}: {e}")
    return []


def compute_metrics(findings: List[Dict], ground_truth: List[Dict], project_name: str) -> Tuple[int, int, int]:
    """Compute TP, FP, FN for a project."""
    tp = 0
    matched_gt = set()

    for finding in findings:
        finding_file = Path(finding.get("file_path", "")).name
        finding_line = finding.get("line_number", 0)

        for i, gt in enumerate(ground_truth):
            if i in matched_gt:
                continue
            gt_file = gt.get("file", "")
            gt_line = gt.get("line", 0)
            tolerance = gt.get("line_tolerance", 3)

            if finding_file == gt_file and abs(finding_line - gt_line) <= tolerance:
                tp += 1
                matched_gt.add(i)
                break

    fp = len(findings) - tp
    fn = len(ground_truth) - tp

    return tp, fp, fn


def run_evaluation(params: Dict[str, float], ground_truth: Dict, semantic_only: bool = True) -> Dict:
    """Run full evaluation with given parameters.

    Args:
        params: Decay parameters to use
        ground_truth: Ground truth labels by project
        semantic_only: If True, only evaluate semantic taint findings
    """
    total_tp, total_fp, total_fn = 0, 0, 0

    for project_name, gt_labels in ground_truth.items():
        if not gt_labels:
            continue

        project_dir = TESTBED_DIR / project_name
        findings = run_scan(project_dir, semantic_only=semantic_only)

        # Note: When semantic_only=True, findings are already filtered to
        # semantic taint category. When False, we still filter by project category.
        if not semantic_only:
            category = project_name.upper().split("_")[0]
            findings = [f for f in findings if category in f.get("category", "").upper()]

        tp, fp, fn = compute_metrics(findings, gt_labels, project_name)
        total_tp += tp
        total_fp += fp
        total_fn += fn

    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
    recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    return {
        "params": params.copy(),
        "tp": total_tp,
        "fp": total_fp,
        "fn": total_fn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
    }


def main():
    """Run sensitivity analysis."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    print("Loading ground truth...")
    ground_truth = load_ground_truth()
    total_gt = sum(len(v) for v in ground_truth.values())
    print(f"  Found {total_gt} ground truth labels across {len(ground_truth)} projects")

    # Read original file
    with open(TAINT_TRACKER) as f:
        original_content = f.read()

    results = []

    try:
        # Sweep each parameter independently
        for param_name, values in SWEEP_RANGES.items():
            print(f"\nSweeping {param_name}...")

            for value in values:
                # Use defaults for other params
                params = DEFAULT_PARAMS.copy()
                params[param_name] = value

                print(f"  {param_name}={value}...")

                # Modify and run
                modify_taint_tracker(params)
                result = run_evaluation(params, ground_truth)
                result["swept_param"] = param_name
                results.append(result)

                print(f"    P={result['precision']:.3f} R={result['recall']:.3f} F1={result['f1']:.3f}")

    finally:
        # Always restore original
        restore_taint_tracker(original_content)

    # Save results
    output_file = RESULTS_DIR / "sensitivity_results.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"\nResults saved to {output_file}")

    # Print summary table
    print("\n" + "=" * 70)
    print("SENSITIVITY ANALYSIS RESULTS")
    print("=" * 70)

    for param_name in SWEEP_RANGES.keys():
        print(f"\n{param_name}:")
        print(f"  {'Value':<10} {'Precision':<12} {'Recall':<12} {'F1':<12}")
        print(f"  {'-'*46}")

        param_results = [r for r in results if r["swept_param"] == param_name]
        for r in param_results:
            value = r["params"][param_name]
            default_marker = " (default)" if value == DEFAULT_PARAMS[param_name] else ""
            print(f"  {value:<10} {r['precision']:<12.3f} {r['recall']:<12.3f} {r['f1']:<12.3f}{default_marker}")


if __name__ == "__main__":
    os.chdir(Path(__file__).parent.parent)
    main()
