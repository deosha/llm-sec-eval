#!/usr/bin/env python3
"""
Aggregate static analysis results and compute P/R/F1 against ground truth.

Methodology improvements based on peer review:
1. Testbed-relative path matching (not just basename)
2. Consistent severity filtering across all tools
3. Deduplication of findings before scoring
4. Span-aware matching for Semgrep
5. Both micro and macro averaging reported
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Tuple, Set
import yaml

# Results directory
RESULTS_DIR = Path("results")
TESTBED_DIR = Path("testbed")
OUTPUT_DIR = RESULTS_DIR / "aggregated"

# Severity levels to include (exclude INFO/LOW for consistency across tools)
INCLUDED_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM"}


def load_ground_truth(testbed_path: Path) -> Dict:
    """Load ground truth labels from testbed."""
    labels_path = testbed_path / "labels.yaml"
    if labels_path.exists():
        with open(labels_path) as f:
            return yaml.safe_load(f)
    return {}


def normalize_path(file_path: str, testbed_project: str) -> str:
    """Normalize file path to testbed-relative format.

    Returns: project/filename (e.g., 'llm01_prompt_injection/app.py')
    """
    path = Path(file_path)

    # If it's already just a filename, prepend project name
    if len(path.parts) == 1:
        return f"{testbed_project}/{path.name}"

    # Extract last two parts (project/file)
    parts = path.parts
    for i, part in enumerate(parts):
        if part.startswith("llm") and "_" in part:
            return "/".join(parts[i:i+2]) if i+1 < len(parts) else f"{part}/{parts[-1]}"

    # Fallback: use project name + filename
    return f"{testbed_project}/{path.name}"


def deduplicate_findings(findings: List[Dict], tool: str) -> List[Dict]:
    """Remove duplicate findings (same file + line).

    This prevents noisy tools from being unfairly penalized for
    reporting the same issue multiple times.
    """
    seen: Set[Tuple[str, int]] = set()
    deduped = []

    for finding in findings:
        if tool == "aisec":
            file_path = finding.get("file_path", "") or finding.get("file", "")
            line = finding.get("line_number", 0) or finding.get("line", 0)
        elif tool == "semgrep":
            file_path = finding.get("path", "")
            line = finding.get("start", {}).get("line", 0)
        elif tool == "bandit":
            file_path = finding.get("filename", "")
            line = finding.get("line_number", 0)
        else:
            deduped.append(finding)
            continue

        key = (Path(file_path).name, line)
        if key not in seen:
            seen.add(key)
            deduped.append(finding)

    return deduped


def filter_by_severity(findings: List[Dict], tool: str) -> List[Dict]:
    """Filter findings by severity for consistency across tools.

    All tools are filtered to include only CRITICAL, HIGH, MEDIUM.
    This prevents asymmetric FP inflation from low-severity noise.
    """
    filtered = []

    for finding in findings:
        if tool == "aisec":
            severity = finding.get("severity", "").upper()
        elif tool == "semgrep":
            # Semgrep uses: ERROR, WARNING, INFO
            severity_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
            semgrep_sev = finding.get("extra", {}).get("severity", "WARNING")
            severity = severity_map.get(semgrep_sev.upper(), "MEDIUM")
        elif tool == "bandit":
            # Bandit uses: HIGH, MEDIUM, LOW
            severity = finding.get("issue_severity", "MEDIUM").upper()
        else:
            severity = "MEDIUM"

        if severity in INCLUDED_SEVERITIES:
            filtered.append(finding)

    return filtered


def load_aisec_results(results_path: Path, category_filter: str = None) -> List[Dict]:
    """Load AI Security CLI scan results.

    Args:
        results_path: Path to results directory
        category_filter: If provided, only return findings matching this category (e.g., "LLM01")
    """
    scan_path = results_path / "scan.json"
    if scan_path.exists():
        with open(scan_path) as f:
            data = json.load(f)
            findings = data.get("findings", [])
            # Filter by category if specified (e.g., "LLM01: Prompt Injection" matches "LLM01")
            if category_filter:
                findings = [f for f in findings if f.get("category", "").upper().startswith(category_filter.upper())]
            return findings
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


def match_finding(finding: Dict, ground_truth: Dict, tool: str, testbed_project: str, tolerance: int = 2) -> bool:
    """Check if a finding matches a ground truth entry.

    Uses testbed-relative path matching and span-aware line matching.
    """
    gt_file = ground_truth.get("file", "")
    gt_line = ground_truth.get("line", 0)
    gt_tolerance = ground_truth.get("line_tolerance", tolerance)

    if tool == "aisec":
        finding_file = finding.get("file_path", "") or finding.get("file", "")
        finding_line = finding.get("line_number", 0) or finding.get("line", 0)
        finding_end_line = finding_line  # AI-Sec doesn't provide end line
    elif tool == "semgrep":
        finding_file = finding.get("path", "")
        finding_line = finding.get("start", {}).get("line", 0)
        # Span-aware: use end line if available
        finding_end_line = finding.get("end", {}).get("line", finding_line)
    elif tool == "bandit":
        finding_file = finding.get("filename", "")
        finding_line = finding.get("line_number", 0)
        # Bandit provides line_range for some findings
        line_range = finding.get("line_range", [finding_line])
        finding_end_line = line_range[-1] if line_range else finding_line
    else:
        return False

    # Normalize file paths to testbed-relative
    finding_file_norm = normalize_path(finding_file, testbed_project)
    gt_file_norm = normalize_path(gt_file, testbed_project)

    # Check file match
    if finding_file_norm != gt_file_norm:
        # Fallback: basename match (for backwards compatibility)
        if Path(finding_file).name != Path(gt_file).name:
            return False

    # Span-aware line matching:
    # Match if GT line is within [finding_start - tolerance, finding_end + tolerance]
    line_match = (
        (finding_line - gt_tolerance <= gt_line <= finding_end_line + gt_tolerance) or
        (abs(finding_line - gt_line) <= gt_tolerance)
    )

    return line_match


def compute_metrics(
    findings: List[Dict],
    ground_truth: List[Dict],
    tool: str,
    testbed_project: str
) -> Tuple[float, float, float, int, int, int]:
    """Compute precision, recall, F1 for a set of findings."""
    true_positives = 0
    matched_gt = set()

    for finding in findings:
        for i, gt in enumerate(ground_truth):
            if i not in matched_gt and match_finding(finding, gt, tool, testbed_project):
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
        "methodology": {
            "path_matching": "testbed-relative with basename fallback",
            "severity_filter": list(INCLUDED_SEVERITIES),
            "deduplication": "file+line before scoring",
            "span_matching": "semgrep uses [start,end] span",
            "averaging": "micro (summed) and macro (per-category mean)"
        },
        "by_category": {},
        "by_tool": {
            "aisec": {"tp": 0, "fp": 0, "fn": 0},
            "semgrep": {"tp": 0, "fp": 0, "fn": 0},
            "bandit": {"tp": 0, "fp": 0, "fn": 0},
        },
        "details": []
    }

    # Track per-category F1 for macro averaging
    category_f1s = {"aisec": [], "semgrep": [], "bandit": []}

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

        # Load tool results - filter aisec by category to avoid counting other detectors' findings
        aisec_findings = load_aisec_results(RESULTS_DIR / "aisec" / "testbed" / project_name, category_filter=category)
        semgrep_findings = load_semgrep_results(RESULTS_DIR / "semgrep" / "testbed" / project_name)
        bandit_findings = load_bandit_results(RESULTS_DIR / "bandit" / "testbed" / project_name)

        # Compute metrics for each tool
        for tool, findings in [("aisec", aisec_findings), ("semgrep", semgrep_findings), ("bandit", bandit_findings)]:
            # Apply consistent severity filtering
            findings = filter_by_severity(findings, tool)

            # Deduplicate before scoring
            original_count = len(findings)
            findings = deduplicate_findings(findings, tool)
            dedup_count = original_count - len(findings)

            p, r, f1, tp, fp, fn = compute_metrics(findings, gt_static, tool, project_name)

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

            # Track F1 for macro averaging
            category_f1s[tool].append(f1)

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
                "duplicates_removed": dedup_count,
                "ground_truth_count": len(gt_static)
            })

    # Compute overall metrics per tool (micro averaging)
    for tool in results["by_tool"]:
        tp = results["by_tool"][tool]["tp"]
        fp = results["by_tool"][tool]["fp"]
        fn = results["by_tool"][tool]["fn"]

        p = tp / (tp + fp) if (tp + fp) > 0 else 0
        r = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0

        # Macro F1 (average of per-category F1)
        macro_f1 = sum(category_f1s[tool]) / len(category_f1s[tool]) if category_f1s[tool] else 0

        results["by_tool"][tool]["precision"] = round(p, 3)
        results["by_tool"][tool]["recall"] = round(r, 3)
        results["by_tool"][tool]["f1_micro"] = round(f1, 3)
        results["by_tool"][tool]["f1_macro"] = round(macro_f1, 3)
        results["by_tool"][tool]["f1"] = round(f1, 3)  # Default to micro for backwards compat

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
