#!/usr/bin/env python3
"""
Aggregate security audit results and compare against ground truth.
"""

import json
import os
from pathlib import Path
from typing import Dict, List
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


def load_audit_results(results_path: Path) -> Dict:
    """Load AI Security CLI audit results."""
    audit_path = results_path / "audit.json"
    if audit_path.exists():
        with open(audit_path) as f:
            return json.load(f)
    return {}


def compare_control_level(expected: str, detected: str) -> str:
    """Compare expected vs detected control level."""
    levels = ["none", "basic", "intermediate", "advanced"]

    if expected == detected:
        return "exact"
    elif expected in levels and detected in levels:
        expected_idx = levels.index(expected)
        detected_idx = levels.index(detected)
        if detected_idx > expected_idx:
            return "over"  # Detected more than expected (optimistic)
        else:
            return "under"  # Detected less than expected (pessimistic)
    return "unknown"


def aggregate_testbed():
    """Aggregate audit results for synthetic testbed."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    results = {
        "by_project": {},
        "by_category": {},
        "control_accuracy": {
            "exact": 0,
            "over": 0,
            "under": 0,
            "unknown": 0,
            "total": 0
        },
        "details": []
    }

    # Process each testbed project
    for testbed_project in sorted(TESTBED_DIR.glob("llm*")):
        project_name = testbed_project.name
        category = project_name.upper().replace("_", " ").split()[0]

        print(f"Processing {project_name}...")

        # Load ground truth
        ground_truth = load_ground_truth(testbed_project)
        gt_audit = ground_truth.get("audit_expectations", {})
        gt_controls = gt_audit.get("controls", [])

        if not gt_controls:
            print(f"  No audit ground truth for {project_name}")
            continue

        # Load audit results
        audit_results = load_audit_results(RESULTS_DIR / "aisec" / "testbed" / project_name)

        if not audit_results:
            print(f"  No audit results for {project_name}")
            continue

        # Extract detected controls
        detected_controls = {}
        for cat_result in audit_results.get("categories", []):
            for control in cat_result.get("controls", []):
                control_id = control.get("control_id", "")
                level = control.get("level", "none")
                detected_controls[control_id] = level

        # Compare ground truth vs detected
        project_results = {
            "project": project_name,
            "category": category,
            "controls": [],
            "overall_score": audit_results.get("overall_score", 0),
            "maturity_level": audit_results.get("maturity_level", "unknown")
        }

        for gt_control in gt_controls:
            control_id = gt_control.get("control_id", "")
            expected_level = gt_control.get("expected_level", "none")
            detected_level = detected_controls.get(control_id, "none")
            comparison = compare_control_level(expected_level, detected_level)

            results["control_accuracy"][comparison] += 1
            results["control_accuracy"]["total"] += 1

            project_results["controls"].append({
                "control_id": control_id,
                "expected": expected_level,
                "detected": detected_level,
                "match": comparison
            })

        results["by_project"][project_name] = project_results
        results["details"].append(project_results)

        # Aggregate by OWASP category
        if category not in results["by_category"]:
            results["by_category"][category] = {
                "scores": [],
                "control_matches": {"exact": 0, "over": 0, "under": 0, "unknown": 0}
            }

        results["by_category"][category]["scores"].append(
            audit_results.get("overall_score", 0)
        )
        for control in project_results["controls"]:
            results["by_category"][category]["control_matches"][control["match"]] += 1

    # Compute summary statistics
    total = results["control_accuracy"]["total"]
    if total > 0:
        results["control_accuracy"]["exact_pct"] = round(
            results["control_accuracy"]["exact"] / total * 100, 1
        )
        results["control_accuracy"]["accuracy"] = round(
            results["control_accuracy"]["exact"] / total, 3
        )

    # Compute per-category averages
    for category in results["by_category"]:
        scores = results["by_category"][category]["scores"]
        if scores:
            results["by_category"][category]["avg_score"] = round(sum(scores) / len(scores), 2)

    # Save results
    output_path = OUTPUT_DIR / "audit_metrics.json"
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nResults saved to {output_path}")

    # Print summary
    print("\n" + "=" * 60)
    print("AUDIT ANALYSIS SUMMARY")
    print("=" * 60)
    print(f"Total controls evaluated: {total}")
    print(f"Exact matches: {results['control_accuracy']['exact']} ({results['control_accuracy'].get('exact_pct', 0)}%)")
    print(f"Over-detection: {results['control_accuracy']['over']}")
    print(f"Under-detection: {results['control_accuracy']['under']}")

    print("\n" + "-" * 60)
    print("Scores by OWASP Category:")
    print("-" * 60)
    for category, data in sorted(results["by_category"].items()):
        avg = data.get("avg_score", 0)
        print(f"  {category}: {avg:.1f}%")

    # Export to CSV
    csv_path = OUTPUT_DIR / "audit_metrics.csv"
    with open(csv_path, "w") as f:
        f.write("project,category,control_id,expected,detected,match,overall_score\n")
        for detail in results["details"]:
            for control in detail["controls"]:
                f.write(f"{detail['project']},{detail['category']},"
                        f"{control['control_id']},{control['expected']},"
                        f"{control['detected']},{control['match']},"
                        f"{detail['overall_score']}\n")

    print(f"CSV exported to {csv_path}")


if __name__ == "__main__":
    aggregate_testbed()
