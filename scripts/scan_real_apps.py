#!/usr/bin/env python3
"""
Scan real-world LLM applications for new vulnerabilities.
Focus on applications (not libraries) that use LLM APIs.
"""

import subprocess
import json
import tempfile
from pathlib import Path
from datetime import datetime

# Real LLM applications (not just libraries)
REAL_APPS = [
    # ChatGPT-like applications
    {"name": "open-webui", "repo": "https://github.com/open-webui/open-webui", "desc": "ChatGPT-like UI"},
    {"name": "chatgpt-web", "repo": "https://github.com/Chanzhaoyu/chatgpt-web", "desc": "ChatGPT web app"},
    {"name": "lobe-chat", "repo": "https://github.com/lobehub/lobe-chat", "desc": "Modern chat UI"},
    
    # AI Agents
    {"name": "AutoGPT", "repo": "https://github.com/Significant-Gravitas/AutoGPT", "desc": "Autonomous agent"},
    {"name": "gpt-engineer", "repo": "https://github.com/gpt-engineer-org/gpt-engineer", "desc": "Code generation agent"},
    {"name": "aider", "repo": "https://github.com/paul-gauthier/aider", "desc": "AI pair programmer"},
    {"name": "opendevin", "repo": "https://github.com/OpenDevin/OpenDevin", "desc": "AI software engineer"},
    
    # RAG Applications
    {"name": "quivr", "repo": "https://github.com/QuivrHQ/quivr", "desc": "Second brain with AI"},
    {"name": "privateGPT", "repo": "https://github.com/zylon-ai/private-gpt", "desc": "Private document Q&A"},
    {"name": "danswer", "repo": "https://github.com/danswer-ai/danswer", "desc": "Enterprise Q&A"},
    
    # Developer Tools
    {"name": "gpt-pilot", "repo": "https://github.com/Pythagora-io/gpt-pilot", "desc": "AI developer"},
    {"name": "chatgpt-retrieval-plugin", "repo": "https://github.com/openai/chatgpt-retrieval-plugin", "desc": "OpenAI plugin"},
    {"name": "embedchain", "repo": "https://github.com/embedchain/embedchain", "desc": "RAG framework"},
]

def clone_repo(repo_url: str, target_dir: Path) -> bool:
    """Shallow clone a repository."""
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, str(target_dir)],
            check=True,
            capture_output=True,
            timeout=120
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False

def count_python_files(directory: Path) -> int:
    """Count Python files in directory."""
    return len(list(directory.rglob("*.py")))

def scan_with_aisentry(directory: Path, output_file: Path) -> dict:
    """Run aisentry scan on directory."""
    try:
        result = subprocess.run(
            ["aisentry", "scan", str(directory), 
             "--ml-detection", "--taint-analysis", 
             "-o", "json", "-q"],
            capture_output=True,
            text=True,
            timeout=300
        )
        
        # Parse JSON output
        if result.stdout.strip():
            data = json.loads(result.stdout)
            # Save to file
            with open(output_file, "w") as f:
                json.dump(data, f, indent=2)
            return data
    except (subprocess.TimeoutExpired, json.JSONDecodeError, subprocess.CalledProcessError) as e:
        print(f"  Scan error: {e}")
    return {"findings": [], "files_scanned": 0}

def analyze_findings(findings: list) -> dict:
    """Analyze findings for potential new vulnerabilities."""
    critical = []
    high = []
    
    for f in findings:
        severity = f.get("severity", "").upper()
        category = f.get("category", "")
        
        # Focus on semantic taint findings (our novel detection)
        evidence = f.get("evidence", {})
        is_semantic = evidence.get("detection_method") == "semantic_taint"
        has_llm_flow = "LLM" in category or "Semantic" in category
        
        finding_info = {
            "file": f.get("file_path", ""),
            "line": f.get("line_number", 0),
            "category": category,
            "title": f.get("title", ""),
            "description": f.get("description", "")[:200],
            "is_semantic_taint": is_semantic or has_llm_flow,
        }
        
        if severity == "CRITICAL":
            critical.append(finding_info)
        elif severity == "HIGH":
            high.append(finding_info)
    
    return {
        "critical": critical,
        "high": high,
        "total_critical": len(critical),
        "total_high": len(high),
    }

def main():
    results_dir = Path("vulnerability_scan_results")
    results_dir.mkdir(exist_ok=True)
    
    all_results = []
    
    print("=" * 70)
    print("SCANNING REAL-WORLD LLM APPLICATIONS FOR VULNERABILITIES")
    print("=" * 70)
    print(f"Started: {datetime.now().isoformat()}")
    print()
    
    for app in REAL_APPS:
        print(f"\n{'='*60}")
        print(f"Scanning: {app['name']} ({app['desc']})")
        print(f"Repo: {app['repo']}")
        print("=" * 60)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_dir = Path(tmpdir) / app["name"]
            
            print("  Cloning repository...")
            if not clone_repo(app["repo"], repo_dir):
                print("  FAILED to clone")
                continue
            
            py_count = count_python_files(repo_dir)
            print(f"  Found {py_count} Python files")
            
            if py_count == 0:
                print("  Skipping (no Python files)")
                continue
            
            print("  Running security scan...")
            output_file = results_dir / f"{app['name']}_scan.json"
            scan_result = scan_with_aisentry(repo_dir, output_file)
            
            findings = scan_result.get("findings", [])
            files_scanned = scan_result.get("files_scanned", 0)
            
            print(f"  Scanned {files_scanned} files, found {len(findings)} findings")
            
            # Analyze for potential new vulns
            analysis = analyze_findings(findings)
            
            if analysis["total_critical"] > 0 or analysis["total_high"] > 0:
                print(f"  ⚠️  CRITICAL: {analysis['total_critical']}, HIGH: {analysis['total_high']}")
                
                # Show top findings
                for f in analysis["critical"][:3]:
                    print(f"    🔴 {f['category']}: {f['file']}:{f['line']}")
                for f in analysis["high"][:3]:
                    print(f"    🟠 {f['category']}: {f['file']}:{f['line']}")
            
            result = {
                "app": app["name"],
                "description": app["desc"],
                "repo": app["repo"],
                "python_files": py_count,
                "files_scanned": files_scanned,
                "total_findings": len(findings),
                "critical": analysis["total_critical"],
                "high": analysis["total_high"],
                "potential_vulns": analysis["critical"] + analysis["high"][:10],
            }
            all_results.append(result)
    
    # Save summary
    summary_file = results_dir / "scan_summary.json"
    with open(summary_file, "w") as f:
        json.dump({
            "scan_date": datetime.now().isoformat(),
            "apps_scanned": len(all_results),
            "results": all_results,
        }, f, indent=2)
    
    # Print summary
    print("\n" + "=" * 70)
    print("SCAN SUMMARY")
    print("=" * 70)
    print(f"{'Application':<25} {'Files':<8} {'Findings':<10} {'Critical':<10} {'High':<10}")
    print("-" * 70)
    
    total_critical = 0
    total_high = 0
    total_findings = 0
    
    for r in all_results:
        print(f"{r['app']:<25} {r['files_scanned']:<8} {r['total_findings']:<10} {r['critical']:<10} {r['high']:<10}")
        total_critical += r["critical"]
        total_high += r["high"]
        total_findings += r["total_findings"]
    
    print("-" * 70)
    print(f"{'TOTAL':<25} {'':<8} {total_findings:<10} {total_critical:<10} {total_high:<10}")
    print()
    print(f"Results saved to: {results_dir}")
    print(f"Summary: {summary_file}")

if __name__ == "__main__":
    main()
