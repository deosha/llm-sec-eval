#!/usr/bin/env python3
"""
Compare AI Security CLI against baseline tools and generate comparison report.
"""

import json
from pathlib import Path
from typing import Dict, List
from datetime import datetime

RESULTS_DIR = Path("results")
AGGREGATED_DIR = RESULTS_DIR / "aggregated"


def load_aggregated_data() -> Dict:
    """Load aggregated metrics."""
    data = {}

    static_path = AGGREGATED_DIR / "static_metrics.json"
    if static_path.exists():
        with open(static_path) as f:
            data["static"] = json.load(f)

    audit_path = AGGREGATED_DIR / "audit_metrics.json"
    if audit_path.exists():
        with open(audit_path) as f:
            data["audit"] = json.load(f)

    return data


def generate_html_report(data: Dict) -> str:
    """Generate HTML comparison report."""
    static = data.get("static", {})
    audit = data.get("audit", {})

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Security CLI Evaluation Report</title>
    <style>
        :root {{
            --bg: #0f172a;
            --card: #1e293b;
            --text: #e2e8f0;
            --text-muted: #94a3b8;
            --border: #334155;
            --accent: #f97316;
            --green: #22c55e;
            --red: #ef4444;
            --yellow: #eab308;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Inter', -apple-system, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 2rem;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: var(--accent); margin-bottom: 0.5rem; }}
        h2 {{ color: var(--text); margin: 2rem 0 1rem; border-bottom: 2px solid var(--accent); padding-bottom: 0.5rem; }}
        h3 {{ color: var(--text-muted); margin: 1.5rem 0 1rem; }}
        .meta {{ color: var(--text-muted); margin-bottom: 2rem; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem; }}
        .card {{
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1.5rem;
        }}
        .card-title {{ font-weight: 600; margin-bottom: 1rem; color: var(--accent); }}
        table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
        th, td {{
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        th {{ color: var(--text-muted); font-weight: 500; }}
        .good {{ color: var(--green); }}
        .bad {{ color: var(--red); }}
        .neutral {{ color: var(--yellow); }}
        .metric {{ font-size: 2rem; font-weight: 700; }}
        .metric-label {{ color: var(--text-muted); font-size: 0.875rem; }}
        .bar {{
            height: 8px;
            background: var(--border);
            border-radius: 4px;
            overflow: hidden;
            margin-top: 0.5rem;
        }}
        .bar-fill {{
            height: 100%;
            background: var(--accent);
            border-radius: 4px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>AI Security CLI Evaluation Report</h1>
        <p class="meta">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

        <h2>Static Analysis Comparison</h2>
        <div class="grid">
"""

    # Static analysis metrics per tool
    if "by_tool" in static:
        for tool, metrics in static["by_tool"].items():
            precision = metrics.get("precision", 0)
            recall = metrics.get("recall", 0)
            f1 = metrics.get("f1", 0)

            html += f"""
            <div class="card">
                <div class="card-title">{tool.upper()}</div>
                <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem;">
                    <div>
                        <div class="metric">{precision:.1%}</div>
                        <div class="metric-label">Precision</div>
                    </div>
                    <div>
                        <div class="metric">{recall:.1%}</div>
                        <div class="metric-label">Recall</div>
                    </div>
                    <div>
                        <div class="metric {'good' if f1 > 0.7 else 'neutral' if f1 > 0.4 else 'bad'}">{f1:.1%}</div>
                        <div class="metric-label">F1 Score</div>
                    </div>
                </div>
                <div class="bar"><div class="bar-fill" style="width: {f1*100}%"></div></div>
            </div>
"""

    html += """
        </div>

        <h3>Per-Category Breakdown</h3>
        <table>
            <thead>
                <tr>
                    <th>Category</th>
                    <th>AI Security CLI (F1)</th>
                    <th>Semgrep (F1)</th>
                    <th>Bandit (F1)</th>
                </tr>
            </thead>
            <tbody>
"""

    # Per-category comparison
    if "by_category" in static:
        for category in sorted(static["by_category"].keys()):
            tools = static["by_category"][category]
            aisec_f1 = tools.get("aisec", {}).get("f1", 0)
            semgrep_f1 = tools.get("semgrep", {}).get("f1", 0)
            bandit_f1 = tools.get("bandit", {}).get("f1", 0)

            html += f"""
                <tr>
                    <td>{category}</td>
                    <td class="{'good' if aisec_f1 > 0.7 else ''}">{aisec_f1:.1%}</td>
                    <td>{semgrep_f1:.1%}</td>
                    <td>{bandit_f1:.1%}</td>
                </tr>
"""

    html += """
            </tbody>
        </table>

        <h2>Security Audit Results</h2>
"""

    # Audit metrics
    if "control_accuracy" in audit:
        acc = audit["control_accuracy"]
        total = acc.get("total", 1)
        exact = acc.get("exact", 0)
        exact_pct = exact / total * 100 if total > 0 else 0

        html += f"""
        <div class="grid">
            <div class="card">
                <div class="card-title">Control Detection Accuracy</div>
                <div class="metric {'good' if exact_pct > 70 else 'neutral' if exact_pct > 50 else 'bad'}">{exact_pct:.1f}%</div>
                <div class="metric-label">{exact} / {total} controls correctly identified</div>
                <div class="bar"><div class="bar-fill" style="width: {exact_pct}%"></div></div>
            </div>
            <div class="card">
                <div class="card-title">Detection Breakdown</div>
                <table>
                    <tr><td>Exact Match</td><td class="good">{acc.get('exact', 0)}</td></tr>
                    <tr><td>Over-detection</td><td class="neutral">{acc.get('over', 0)}</td></tr>
                    <tr><td>Under-detection</td><td class="bad">{acc.get('under', 0)}</td></tr>
                </table>
            </div>
        </div>
"""

    # Category scores
    if "by_category" in audit:
        html += """
        <h3>Scores by OWASP Category</h3>
        <table>
            <thead>
                <tr>
                    <th>Category</th>
                    <th>Average Score</th>
                    <th>Control Matches</th>
                </tr>
            </thead>
            <tbody>
"""
        for category in sorted(audit["by_category"].keys()):
            cat_data = audit["by_category"][category]
            avg_score = cat_data.get("avg_score", 0)
            matches = cat_data.get("control_matches", {})
            exact = matches.get("exact", 0)
            total = sum(matches.values())

            html += f"""
                <tr>
                    <td>{category}</td>
                    <td>{avg_score:.1f}%</td>
                    <td>{exact}/{total}</td>
                </tr>
"""

        html += """
            </tbody>
        </table>
"""

    html += """
        <h2>Summary</h2>
        <div class="card">
            <p>This report compares AI Security CLI against baseline static analysis tools (Semgrep, Bandit)
            and evaluates the security posture audit feature against ground truth labels.</p>
            <h3>Key Findings</h3>
            <ul style="padding-left: 1.5rem; margin-top: 1rem;">
                <li>AI Security CLI provides LLM-specific detection not available in general SAST tools</li>
                <li>Security posture audit provides maturity-based assessment beyond vulnerability scanning</li>
                <li>Combined static + audit + live testing offers comprehensive coverage</li>
            </ul>
        </div>
    </div>
</body>
</html>
"""

    return html


def main():
    """Generate comparison report."""
    print("Loading aggregated data...")
    data = load_aggregated_data()

    if not data:
        print("No aggregated data found. Run 'make aggregate' first.")
        return

    print("Generating HTML report...")
    html = generate_html_report(data)

    output_path = RESULTS_DIR / "report.html"
    with open(output_path, "w") as f:
        f.write(html)

    print(f"Report generated: {output_path}")

    # Also generate JSON summary
    summary = {
        "generated": datetime.now().isoformat(),
        "static_analysis": data.get("static", {}).get("by_tool", {}),
        "audit_accuracy": data.get("audit", {}).get("control_accuracy", {})
    }

    summary_path = RESULTS_DIR / "summary.json"
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)

    print(f"Summary saved: {summary_path}")


if __name__ == "__main__":
    main()
