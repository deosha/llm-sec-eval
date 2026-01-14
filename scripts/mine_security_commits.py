#!/usr/bin/env python3
"""
Mine security-related commits from LLM project git histories.

Finds vulnerability fixes that may not have CVE assignments.
"""

import subprocess
import json
import re
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional
from datetime import datetime

# LLM projects to mine
PROJECTS = [
    {"name": "langchain", "repo": "https://github.com/langchain-ai/langchain"},
    {"name": "llama_index", "repo": "https://github.com/run-llama/llama_index"},
    {"name": "haystack", "repo": "https://github.com/deepset-ai/haystack"},
    {"name": "semantic-kernel", "repo": "https://github.com/microsoft/semantic-kernel"},
    {"name": "autogen", "repo": "https://github.com/microsoft/autogen"},
    {"name": "dspy", "repo": "https://github.com/stanfordnlp/dspy"},
    {"name": "guidance", "repo": "https://github.com/guidance-ai/guidance"},
]

# Keywords indicating security fixes
SECURITY_KEYWORDS = [
    # Direct security terms
    r"security",
    r"vulnerab",
    r"exploit",
    r"CVE-\d{4}-\d+",
    r"injection",
    r"sanitiz",
    r"escap[ei]",
    r"validat",

    # Attack types
    r"prompt.?injection",
    r"code.?execution",
    r"command.?injection",
    r"sql.?injection",
    r"xss",
    r"ssrf",
    r"path.?traversal",
    r"arbitrary.?(code|file|command)",

    # Fix indicators
    r"fix.*(security|vuln|inject|exploit)",
    r"patch.*(security|vuln)",
    r"prevent.*(injection|attack|exploit)",
    r"block.*(malicious|attack)",
]


@dataclass
class SecurityCommit:
    """A potentially security-related commit."""
    project: str
    commit_hash: str
    author: str
    date: str
    message: str
    files_changed: List[str]
    keyword_matches: List[str]
    confidence: float  # How likely this is a security fix


def clone_or_pull(repo_url: str, target_dir: Path) -> bool:
    """Clone repo or pull if exists."""
    if target_dir.exists():
        try:
            subprocess.run(
                ["git", "pull"],
                cwd=target_dir,
                check=True,
                capture_output=True
            )
            return True
        except subprocess.CalledProcessError:
            return False
    else:
        try:
            subprocess.run(
                ["git", "clone", "--depth", "500", repo_url, str(target_dir)],
                check=True,
                capture_output=True
            )
            return True
        except subprocess.CalledProcessError:
            return False


def search_commits(repo_dir: Path, project_name: str) -> List[SecurityCommit]:
    """Search for security-related commits."""
    commits = []

    # Get commit log with full messages
    try:
        result = subprocess.run(
            ["git", "log", "--pretty=format:%H|%an|%ad|%s%n%b|||",
             "--date=short", "-500"],
            cwd=repo_dir,
            check=True,
            capture_output=True,
            text=True
        )
    except subprocess.CalledProcessError:
        return commits

    # Parse commits
    raw_commits = result.stdout.split("|||")

    for raw in raw_commits:
        raw = raw.strip()
        if not raw or "|" not in raw:
            continue

        lines = raw.split("\n")
        header = lines[0]
        parts = header.split("|")

        if len(parts) < 4:
            continue

        commit_hash = parts[0]
        author = parts[1]
        date = parts[2]
        subject = parts[3]
        body = "\n".join(lines[1:]) if len(lines) > 1 else ""

        full_message = f"{subject}\n{body}".lower()

        # Check for security keywords
        matches = []
        for pattern in SECURITY_KEYWORDS:
            if re.search(pattern, full_message, re.IGNORECASE):
                matches.append(pattern)

        if matches:
            # Get files changed
            try:
                files_result = subprocess.run(
                    ["git", "diff-tree", "--no-commit-id", "--name-only", "-r", commit_hash],
                    cwd=repo_dir,
                    check=True,
                    capture_output=True,
                    text=True
                )
                files = [f for f in files_result.stdout.strip().split("\n") if f]
            except subprocess.CalledProcessError:
                files = []

            # Filter to Python files
            py_files = [f for f in files if f.endswith(".py")]

            if py_files:
                # Calculate confidence based on keyword matches
                confidence = min(1.0, len(matches) * 0.2 + 0.3)

                # Boost confidence for explicit CVE mentions
                if any("CVE" in m.upper() for m in matches):
                    confidence = min(1.0, confidence + 0.3)

                # Boost for "security" or "vulnerability" in message
                if "security" in full_message or "vulnerab" in full_message:
                    confidence = min(1.0, confidence + 0.2)

                commits.append(SecurityCommit(
                    project=project_name,
                    commit_hash=commit_hash,
                    author=author,
                    date=date,
                    message=subject,
                    files_changed=py_files[:10],  # Limit files
                    keyword_matches=matches[:5],
                    confidence=confidence
                ))

    return commits


def extract_vulnerable_code(repo_dir: Path, commit: SecurityCommit, output_dir: Path):
    """Extract vulnerable code from before the fix."""
    for file_path in commit.files_changed:
        # Get parent commit (vulnerable version)
        try:
            parent = subprocess.run(
                ["git", "rev-parse", f"{commit.commit_hash}^"],
                cwd=repo_dir,
                check=True,
                capture_output=True,
                text=True
            ).stdout.strip()

            # Get file content at parent
            vuln_content = subprocess.run(
                ["git", "show", f"{parent}:{file_path}"],
                cwd=repo_dir,
                check=True,
                capture_output=True,
                text=True
            ).stdout

            # Save vulnerable version
            out_path = output_dir / commit.project / commit.commit_hash[:8] / Path(file_path).name
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(vuln_content)

        except subprocess.CalledProcessError:
            continue


def categorize_commit(commit: SecurityCommit) -> str:
    """Categorize commit by OWASP LLM Top 10."""
    message = commit.message.lower()
    matches = " ".join(commit.keyword_matches).lower()

    if "prompt" in message and "injection" in matches:
        return "LLM01"
    elif "code" in matches and ("execution" in matches or "exec" in message):
        return "LLM02"
    elif "sql" in matches or "database" in message:
        return "LLM02"
    elif "ssrf" in matches or "request" in message:
        return "LLM07"
    elif "path" in matches or "file" in message:
        return "LLM07"
    elif "api" in message and "key" in message:
        return "LLM06"
    elif "secret" in message or "credential" in message:
        return "LLM06"
    else:
        return "UNKNOWN"


def main():
    repos_dir = Path("repos")
    output_dir = Path("cve_benchmark") / "mined"
    repos_dir.mkdir(exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    all_commits = []

    print("Mining Security Commits from LLM Projects")
    print("=" * 60)

    for project in PROJECTS:
        print(f"\n{project['name']}...")

        repo_dir = repos_dir / project["name"]

        if not clone_or_pull(project["repo"], repo_dir):
            print(f"  Failed to clone/pull")
            continue

        commits = search_commits(repo_dir, project["name"])
        print(f"  Found {len(commits)} potential security commits")

        # Filter high-confidence commits
        high_conf = [c for c in commits if c.confidence >= 0.5]
        print(f"  High confidence (>=0.5): {len(high_conf)}")

        # Extract code for high-confidence commits
        for commit in high_conf[:20]:  # Limit to top 20
            extract_vulnerable_code(repo_dir, commit, output_dir)

        all_commits.extend(commits)

    # Sort by confidence
    all_commits.sort(key=lambda c: c.confidence, reverse=True)

    # Build ground truth for mined commits
    ground_truth = []
    for commit in all_commits:
        if commit.confidence >= 0.5:
            category = categorize_commit(commit)
            for f in commit.files_changed:
                ground_truth.append({
                    "source": "mined",
                    "project": commit.project,
                    "commit": commit.commit_hash,
                    "file": f"mined/{commit.project}/{commit.commit_hash[:8]}/{Path(f).name}",
                    "line": 1,  # Would need diff analysis for exact line
                    "category": category,
                    "severity": "HIGH" if commit.confidence >= 0.7 else "MEDIUM",
                    "description": commit.message,
                    "confidence": commit.confidence,
                })

    # Save results
    with open(output_dir / "mined_commits.json", "w") as f:
        json.dump({
            "total_commits_analyzed": len(all_commits),
            "high_confidence_commits": len([c for c in all_commits if c.confidence >= 0.5]),
            "commits": [
                {
                    "project": c.project,
                    "hash": c.commit_hash,
                    "date": c.date,
                    "message": c.message,
                    "files": c.files_changed,
                    "keywords": c.keyword_matches,
                    "confidence": c.confidence,
                    "category": categorize_commit(c),
                }
                for c in all_commits if c.confidence >= 0.4
            ]
        }, f, indent=2)

    with open(output_dir / "ground_truth.json", "w") as f:
        json.dump({"vulnerabilities": ground_truth}, f, indent=2)

    # Summary
    print("\n" + "=" * 60)
    print("MINING SUMMARY")
    print("=" * 60)
    print(f"Total commits analyzed: {len(all_commits)}")
    print(f"High confidence (>=0.5): {len([c for c in all_commits if c.confidence >= 0.5])}")
    print(f"Very high confidence (>=0.7): {len([c for c in all_commits if c.confidence >= 0.7])}")

    print("\nTop 10 Security Commits:")
    print("-" * 60)
    for commit in all_commits[:10]:
        print(f"[{commit.confidence:.2f}] {commit.project}: {commit.message[:50]}...")
        print(f"         Files: {', '.join(commit.files_changed[:3])}")

    print(f"\nOutput saved to: {output_dir}")


if __name__ == "__main__":
    main()
