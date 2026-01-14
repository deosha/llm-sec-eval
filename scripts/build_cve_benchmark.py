#!/usr/bin/env python3
"""
Build benchmark dataset from real LLM security CVEs.

Extracts vulnerable code from git history before patches were applied.
"""

import json
import subprocess
import tempfile
import shutil
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Optional
import re

# Known LLM security CVEs with fix commits
KNOWN_CVES = [
    {
        "cve_id": "CVE-2023-36258",
        "repo": "https://github.com/langchain-ai/langchain",
        "description": "Arbitrary code execution in PALChain",
        "category": "LLM02",  # Insecure Output Handling -> Code Exec
        "severity": "CRITICAL",
        "fix_commit": "4c97a10bd0d9385cfee234a63b5bd826a295e483",
        "vulnerable_files": ["libs/langchain/langchain/chains/pal/base.py"],
        "attack_vector": "indirect",
    },
    {
        "cve_id": "CVE-2023-39659",
        "repo": "https://github.com/langchain-ai/langchain",
        "description": "SSRF via SerpAPIWrapper",
        "category": "LLM07",  # Insecure Plugin Design
        "severity": "HIGH",
        "fix_commit": "e78a231b4b7d7c5e5f3e9e0a6e5c7f9b8a1d2c3e",  # Placeholder
        "vulnerable_files": ["langchain/utilities/serpapi.py"],
        "attack_vector": "direct",
    },
    {
        "cve_id": "CVE-2023-36095",
        "repo": "https://github.com/langchain-ai/langchain",
        "description": "SQL injection via SQLDatabaseChain",
        "category": "LLM02",
        "severity": "CRITICAL",
        "fix_commit": "8043ffb1c31e4a10c14f5f74de24e7ff98e5a7a2",
        "vulnerable_files": ["libs/langchain/langchain/chains/sql_database/base.py"],
        "attack_vector": "indirect",
    },
    {
        "cve_id": "CVE-2023-32786",
        "repo": "https://github.com/langchain-ai/langchain",
        "description": "Path traversal in document loaders",
        "category": "LLM07",
        "severity": "HIGH",
        "fix_commit": "b1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",  # Placeholder
        "vulnerable_files": ["langchain/document_loaders/directory.py"],
        "attack_vector": "stored",
    },
    {
        "cve_id": "CVE-2023-39631",
        "repo": "https://github.com/run-llama/llama_index",
        "description": "Code execution via PandasQueryEngine",
        "category": "LLM02",
        "severity": "CRITICAL",
        "fix_commit": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",  # Placeholder
        "vulnerable_files": ["llama_index/query_engine/pandas_query_engine.py"],
        "attack_vector": "indirect",
    },
    {
        "cve_id": "CVE-2024-28088",
        "repo": "https://github.com/langchain-ai/langchain",
        "description": "Prompt injection in experimental agents",
        "category": "LLM01",
        "severity": "HIGH",
        "fix_commit": "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1",  # Placeholder
        "vulnerable_files": ["libs/experimental/langchain_experimental/agents/"],
        "attack_vector": "direct",
    },
]


@dataclass
class VulnerableCodeSample:
    """A vulnerable code sample extracted from real CVE."""
    cve_id: str
    file_path: str
    vulnerable_code: str
    patched_code: str
    vulnerable_lines: List[int]
    category: str
    severity: str
    description: str
    attack_vector: str
    repo: str
    fix_commit: str


def clone_repo(repo_url: str, target_dir: Path) -> bool:
    """Clone a repository."""
    try:
        subprocess.run(
            ["git", "clone", "--depth", "100", repo_url, str(target_dir)],
            check=True,
            capture_output=True
        )
        return True
    except subprocess.CalledProcessError as e:
        print(f"Failed to clone {repo_url}: {e}")
        return False


def checkout_commit(repo_dir: Path, commit: str) -> bool:
    """Checkout a specific commit."""
    try:
        subprocess.run(
            ["git", "checkout", commit],
            cwd=repo_dir,
            check=True,
            capture_output=True
        )
        return True
    except subprocess.CalledProcessError:
        return False


def get_parent_commit(repo_dir: Path, commit: str) -> Optional[str]:
    """Get the parent commit (vulnerable version)."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", f"{commit}^"],
            cwd=repo_dir,
            check=True,
            capture_output=True,
            text=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return None


def get_file_at_commit(repo_dir: Path, commit: str, file_path: str) -> Optional[str]:
    """Get file contents at a specific commit."""
    try:
        result = subprocess.run(
            ["git", "show", f"{commit}:{file_path}"],
            cwd=repo_dir,
            check=True,
            capture_output=True,
            text=True
        )
        return result.stdout
    except subprocess.CalledProcessError:
        return None


def get_diff_lines(repo_dir: Path, parent: str, fix: str, file_path: str) -> List[int]:
    """Get line numbers that were changed in the fix."""
    try:
        result = subprocess.run(
            ["git", "diff", "-U0", parent, fix, "--", file_path],
            cwd=repo_dir,
            check=True,
            capture_output=True,
            text=True
        )

        # Parse diff to extract line numbers
        lines = []
        for line in result.stdout.split('\n'):
            # Match @@ -start,count +start,count @@ format
            match = re.match(r'^@@ -(\d+)', line)
            if match:
                lines.append(int(match.group(1)))

        return lines if lines else [1]  # Default to line 1 if no diff found
    except subprocess.CalledProcessError:
        return [1]


def extract_cve_samples(cve_info: dict, output_dir: Path) -> List[VulnerableCodeSample]:
    """Extract vulnerable and patched code for a CVE."""
    samples = []

    with tempfile.TemporaryDirectory() as tmpdir:
        repo_dir = Path(tmpdir) / "repo"

        print(f"  Cloning {cve_info['repo']}...")
        if not clone_repo(cve_info['repo'], repo_dir):
            return samples

        fix_commit = cve_info['fix_commit']
        parent_commit = get_parent_commit(repo_dir, fix_commit)

        if not parent_commit:
            print(f"  Could not find parent commit for {fix_commit}")
            return samples

        for file_path in cve_info['vulnerable_files']:
            print(f"  Extracting {file_path}...")

            # Get vulnerable version (parent of fix)
            vuln_code = get_file_at_commit(repo_dir, parent_commit, file_path)
            if not vuln_code:
                print(f"    File not found at {parent_commit}")
                continue

            # Get patched version
            patched_code = get_file_at_commit(repo_dir, fix_commit, file_path)
            if not patched_code:
                patched_code = ""

            # Get vulnerable line numbers
            vuln_lines = get_diff_lines(repo_dir, parent_commit, fix_commit, file_path)

            sample = VulnerableCodeSample(
                cve_id=cve_info['cve_id'],
                file_path=file_path,
                vulnerable_code=vuln_code,
                patched_code=patched_code,
                vulnerable_lines=vuln_lines,
                category=cve_info['category'],
                severity=cve_info['severity'],
                description=cve_info['description'],
                attack_vector=cve_info['attack_vector'],
                repo=cve_info['repo'],
                fix_commit=fix_commit,
            )
            samples.append(sample)

            # Save vulnerable file
            vuln_file = output_dir / "vulnerable" / cve_info['cve_id'] / Path(file_path).name
            vuln_file.parent.mkdir(parents=True, exist_ok=True)
            vuln_file.write_text(vuln_code)

            # Save patched file
            if patched_code:
                patch_file = output_dir / "patched" / cve_info['cve_id'] / Path(file_path).name
                patch_file.parent.mkdir(parents=True, exist_ok=True)
                patch_file.write_text(patched_code)

    return samples


def search_github_advisories(query: str = "langchain") -> List[dict]:
    """Search GitHub Security Advisories for LLM-related CVEs."""
    try:
        result = subprocess.run(
            ["gh", "api", f"/advisories?ecosystem=pip&keyword={query}"],
            check=True,
            capture_output=True,
            text=True
        )
        return json.loads(result.stdout)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("GitHub CLI not available or API call failed")
        return []


def search_nvd(keyword: str = "prompt injection") -> List[dict]:
    """Search NVD for relevant CVEs (requires API key for full results)."""
    import urllib.request
    import urllib.parse

    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = urllib.parse.urlencode({"keywordSearch": keyword, "resultsPerPage": 50})

    try:
        with urllib.request.urlopen(f"{base_url}?{params}", timeout=30) as response:
            data = json.loads(response.read())
            return data.get("vulnerabilities", [])
    except Exception as e:
        print(f"NVD search failed: {e}")
        return []


def build_ground_truth(samples: List[VulnerableCodeSample], output_dir: Path):
    """Build ground truth labels file."""
    ground_truth = {
        "metadata": {
            "description": "Real-world LLM security vulnerabilities from CVEs",
            "source": "GitHub Security Advisories, NVD",
            "total_cves": len(set(s.cve_id for s in samples)),
            "total_files": len(samples),
        },
        "vulnerabilities": []
    }

    for sample in samples:
        for line in sample.vulnerable_lines:
            ground_truth["vulnerabilities"].append({
                "cve_id": sample.cve_id,
                "file": f"vulnerable/{sample.cve_id}/{Path(sample.file_path).name}",
                "line": line,
                "category": sample.category,
                "severity": sample.severity,
                "description": sample.description,
                "attack_vector": sample.attack_vector,
            })

    output_file = output_dir / "ground_truth.json"
    with open(output_file, 'w') as f:
        json.dump(ground_truth, f, indent=2)

    print(f"\nGround truth saved to {output_file}")
    return ground_truth


def main():
    output_dir = Path("cve_benchmark")
    output_dir.mkdir(exist_ok=True)

    all_samples = []

    print("Building CVE Benchmark Dataset")
    print("=" * 50)

    # Step 1: Extract known CVEs
    print("\n1. Extracting known CVEs...")
    for cve in KNOWN_CVES:
        print(f"\nProcessing {cve['cve_id']}...")
        samples = extract_cve_samples(cve, output_dir)
        all_samples.extend(samples)
        print(f"  Extracted {len(samples)} files")

    # Step 2: Search for additional CVEs
    print("\n2. Searching for additional CVEs...")

    # Search GitHub advisories
    for project in ["langchain", "llama-index", "openai", "anthropic"]:
        advisories = search_github_advisories(project)
        print(f"  Found {len(advisories)} advisories for {project}")

    # Search NVD
    for keyword in ["prompt injection", "LLM vulnerability", "langchain"]:
        nvd_results = search_nvd(keyword)
        print(f"  Found {len(nvd_results)} NVD entries for '{keyword}'")

    # Step 3: Build ground truth
    print("\n3. Building ground truth...")
    ground_truth = build_ground_truth(all_samples, output_dir)

    # Summary
    print("\n" + "=" * 50)
    print("BENCHMARK SUMMARY")
    print("=" * 50)
    print(f"Total CVEs: {len(set(s.cve_id for s in all_samples))}")
    print(f"Total vulnerable files: {len(all_samples)}")
    print(f"Categories covered: {set(s.category for s in all_samples)}")
    print(f"Output directory: {output_dir}")

    # Save full dataset metadata
    metadata = {
        "samples": [asdict(s) for s in all_samples],
        "statistics": {
            "total_cves": len(set(s.cve_id for s in all_samples)),
            "by_category": {},
            "by_severity": {},
        }
    }

    for s in all_samples:
        metadata["statistics"]["by_category"][s.category] = \
            metadata["statistics"]["by_category"].get(s.category, 0) + 1
        metadata["statistics"]["by_severity"][s.severity] = \
            metadata["statistics"]["by_severity"].get(s.severity, 0) + 1

    with open(output_dir / "dataset_metadata.json", 'w') as f:
        json.dump(metadata, f, indent=2, default=str)


if __name__ == "__main__":
    main()
