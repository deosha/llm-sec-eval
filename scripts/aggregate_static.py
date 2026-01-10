#!/usr/bin/env python3
"""
Aggregate static analysis results and compute P/R/F1 against ground truth.
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Tuple
import yaml

# Results directory
RESULTS_DIR = Path("results")
TESTBED_DIR = Path("testbed")
OUTPUT_DIR = RESULTS_DIR / "aggregated"


def load_ground_truth(testbed_path: Path) -> Dict:
    """Load ground truth labels from testbed."""
    labels_path = testbed_path / "labels.yaml"
    if labels_path.exists():
        with open(labels_path) as f:
            return yaml.safe_load(f)
    return {}


def load_aisec_results(results_path: Path) -> List[Dict]:
    """Load AI Security CLI scan results.

    NOTE: INFO severity findings are filtered out since they are advisory-only
    and should not count as findings for precision/recall calculations.
    """
    scan_path = results_path / "scan.json"
    if scan_path.exists():
        with open(scan_path) as f:
            data = json.load(f)
            findings = data.get("findings", [])
            # Filter out INFO severity (advisory-only findings)
            return [f for f in findings if f.get("severity", "").upper() != "INFO"]
    return []


def load_semgrep_results(results_path: Path) -> List[Dict]:
    """Load Semgrep results."""
    semgrep_path = results_path / "semgrep.json"
    if semgrep_path.exists():
        with open(semgrep_path) as f:
            data = json.load(f)
            return data.get("results", [])
    return []


def load_bandit_results(results_path: Path) -> List[Dict]:
    """Load Bandit results."""
    bandit_path = results_path / "bandit.json"
    if bandit_path.exists():
        with open(bandit_path) as f:
            data = json.load(f)
            return data.get("results", [])
    return []


def match_finding(finding: Dict, ground_truth: Dict, tool: str, tolerance: int = 2) -> bool:
    """Check if a finding matches a ground truth entry."""
    gt_file = ground_truth.get("file", "")
    gt_line = ground_truth.get("line", 0)
    gt_tolerance = ground_truth.get("line_tolerance", tolerance)

    if tool == "aisec":
        finding_file = finding.get("file_path", "") or finding.get("file", "")
        finding_line = finding.get("line_number", 0) or finding.get("line", 0)
    elif tool == "semgrep":
        finding_file = finding.get("path", "")
        finding_line = finding.get("start", {}).get("line", 0)
    elif tool == "bandit":
        finding_file = finding.get("filename", "")
        finding_line = finding.get("line_number", 0)
    else:
        return False

    # Normalize file paths
    finding_file = Path(finding_file).name
    gt_file = Path(gt_file).name

    # Check file and line match (with tolerance)
    if finding_file == gt_file:
        if abs(finding_line - gt_line) <= gt_tolerance:
            return True

    return False


def compute_metrics(
    findings: List[Dict],
    ground_truth: List[Dict],
    tool: str
) -> Tuple[float, float, float, int, int, int]:
    """Compute precision, recall, F1 for a set of findings."""
    true_positives = 0
    matched_gt = set()

    for finding in findings:
        for i, gt in enumerate(ground_truth):
            if i not in matched_gt and match_finding(finding, gt, tool):
                true_positives += 1
                matched_gt.add(i)
                break

    false_positives = len(findings) - true_positives
    false_negatives = len(ground_truth) - true_positives

    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    return precision, recall, f1, true_positives, false_positives, false_negatives


def aggregate_testbed():
    """Aggregate results for synthetic testbed."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    results = {
        "by_category": {},
        "by_tool": {
            "aisec": {"tp": 0, "fp": 0, "fn": 0},
            "semgrep": {"tp": 0, "fp": 0, "fn": 0},
            "bandit": {"tp": 0, "fp": 0, "fn": 0},
        },
        "details": []
    }

    # Process each testbed project
    for testbed_project in sorted(TESTBED_DIR.glob("llm*")):
        project_name = testbed_project.name
        category = project_name.upper().replace("_", " ").split()[0]  # LLM01, LLM02, etc.

        print(f"Processing {project_name}...")

        # Load ground truth
        ground_truth = load_ground_truth(testbed_project)
        gt_static = ground_truth.get("static_findings", [])

        if not gt_static:
            print(f"  No ground truth for {project_name}")
            continue

        # Load tool results
        aisec_findings = load_aisec_results(RESULTS_DIR / "aisec" / "testbed" / project_name)
        semgrep_findings = load_semgrep_results(RESULTS_DIR / "semgrep" / "testbed" / project_name)
        bandit_findings = load_bandit_results(RESULTS_DIR / "bandit" / "testbed" / project_name)

        # Compute metrics for each tool
        for tool, findings in [("aisec", aisec_findings), ("semgrep", semgrep_findings), ("bandit", bandit_findings)]:
            p, r, f1, tp, fp, fn = compute_metrics(findings, gt_static, tool)

            results["by_tool"][tool]["tp"] += tp
            results["by_tool"][tool]["fp"] += fp
            results["by_tool"][tool]["fn"] += fn

            if category not in results["by_category"]:
                results["by_category"][category] = {}
            if tool not in results["by_category"][category]:
                results["by_category"][category][tool] = {"tp": 0, "fp": 0, "fn": 0}

            results["by_category"][category][tool]["tp"] += tp
            results["by_category"][category][tool]["fp"] += fp
            results["by_category"][category][tool]["fn"] += fn

            results["details"].append({
                "project": project_name,
                "category": category,
                "tool": tool,
                "precision": round(p, 3),
                "recall": round(r, 3),
                "f1": round(f1, 3),
                "tp": tp,
                "fp": fp,
                "fn": fn,
                "total_findings": len(findings),
                "ground_truth_count": len(gt_static)
            })

    # Compute overall metrics per tool
    for tool in results["by_tool"]:
        tp = results["by_tool"][tool]["tp"]
        fp = results["by_tool"][tool]["fp"]
        fn = results["by_tool"][tool]["fn"]

        p = tp / (tp + fp) if (tp + fp) > 0 else 0
        r = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0

        results["by_tool"][tool]["precision"] = round(p, 3)
        results["by_tool"][tool]["recall"] = round(r, 3)
        results["by_tool"][tool]["f1"] = round(f1, 3)

    # Compute per-category metrics
    for category in results["by_category"]:
        for tool in results["by_category"][category]:
            tp = results["by_category"][category][tool]["tp"]
            fp = results["by_category"][category][tool]["fp"]
            fn = results["by_category"][category][tool]["fn"]

            p = tp / (tp + fp) if (tp + fp) > 0 else 0
            r = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0

            results["by_category"][category][tool]["precision"] = round(p, 3)
            results["by_category"][category][tool]["recall"] = round(r, 3)
            results["by_category"][category][tool]["f1"] = round(f1, 3)

    # Save results
    output_path = OUTPUT_DIR / "static_metrics.json"
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nResults saved to {output_path}")

    # Print summary
    print("\n" + "=" * 60)
    print("STATIC ANALYSIS SUMMARY")
    print("=" * 60)
    print(f"{'Tool':<15} {'Precision':<12} {'Recall':<12} {'F1':<12}")
    print("-" * 60)
    for tool, metrics in results["by_tool"].items():
        print(f"{tool:<15} {metrics['precision']:<12.3f} {metrics['recall']:<12.3f} {metrics['f1']:<12.3f}")

    # Export to CSV
    csv_path = OUTPUT_DIR / "static_metrics.csv"
    with open(csv_path, "w") as f:
        f.write("project,category,tool,precision,recall,f1,tp,fp,fn\n")
        for detail in results["details"]:
            f.write(f"{detail['project']},{detail['category']},{detail['tool']},"
                    f"{detail['precision']},{detail['recall']},{detail['f1']},"
                    f"{detail['tp']},{detail['fp']},{detail['fn']}\n")

    print(f"CSV exported to {csv_path}")


if __name__ == "__main__":
    aggregate_testbed()
