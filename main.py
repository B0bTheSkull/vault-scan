#!/usr/bin/env python3
"""
vault-scan: Secret scanner for git repositories

Scans git history for leaked credentials, API keys, and other secrets.
Designed to be CI/CD friendly — JSON output, exits non-zero on findings.

Usage:
    python main.py                       # scan current dir (history + HEAD)
    python main.py --path /repo          # scan specific repo
    python main.py --output json         # JSON output for pipelines
    python main.py --no-history          # working tree only
    python main.py --show-secrets        # unredacted output
    python main.py --severity high       # filter by min severity
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Generator, Optional

import git
import yaml


# ── Data Models ───────────────────────────────────────────────────────────────

@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: str
    commit: str
    author: str
    date: str
    file: str
    line: int
    match: str
    context: str
    entropy: Optional[float] = None

    def redacted(self) -> Finding:
        m = self.match
        if len(m) > 8:
            safe = m[:4] + "*" * (len(m) - 8) + m[-4:]
        else:
            safe = "****"
        return Finding(**{**asdict(self), "match": safe})


@dataclass
class ScanResult:
    repo_path: str
    commits_scanned: int = 0
    files_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)


# ── Entropy ───────────────────────────────────────────────────────────────────

def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def is_high_entropy(value: str, threshold: float = 4.5, min_length: int = 20) -> tuple[bool, float]:
    value = value.strip("\"'` \t")
    if len(value) < min_length:
        return False, 0.0
    e = shannon_entropy(value)
    return e >= threshold, e


# ── Rules ─────────────────────────────────────────────────────────────────────

import re

def load_rules(path: Path) -> list[dict]:
    with open(path) as f:
        config = yaml.safe_load(f)

    entropy_cfg = config.get("entropy", {})
    compiled = []
    for rule in config.get("rules", []):
        try:
            compiled.append({
                **rule,
                "_pattern": re.compile(rule["pattern"]),
                "_entropy_cfg": entropy_cfg,
            })
        except re.error as e:
            print(f"[warn] Skipping rule {rule['id']}: {e}", file=sys.stderr)
    return compiled


# ── Ignore File ───────────────────────────────────────────────────────────────

def load_ignore_patterns(path: Path) -> list[re.Pattern]:
    if not path.exists():
        return []
    patterns = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Simple glob → regex conversion
        pat = re.escape(line).replace(r"\*\*", ".*").replace(r"\*", "[^/]*").replace(r"\?", ".")
        try:
            patterns.append(re.compile(pat))
        except re.error:
            pass
    return patterns


def is_ignored(text: str, patterns: list[re.Pattern]) -> bool:
    return any(p.search(text) for p in patterns)


# ── File Filtering ────────────────────────────────────────────────────────────

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svg",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar", ".xz",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".wasm",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac",
    ".pyc", ".pyo", ".class",
    ".lock", ".sum",  # package lockfiles — high false-positive rate
    ".min.js", ".min.css",
}

SKIP_FILENAMES = {
    "package-lock.json", "yarn.lock", "poetry.lock", "Pipfile.lock",
    "Cargo.lock", "composer.lock", "go.sum",
}


def should_skip(filepath: str) -> bool:
    p = Path(filepath)
    if p.name in SKIP_FILENAMES:
        return True
    # Check for compound extensions like .min.js
    suffixes = "".join(p.suffixes).lower()
    return p.suffix.lower() in SKIP_EXTENSIONS or suffixes in SKIP_EXTENSIONS


# ── Line Scanner ──────────────────────────────────────────────────────────────

def scan_line(
    line: str,
    line_num: int,
    filepath: str,
    commit: str,
    author: str,
    date: str,
    rules: list[dict],
    ignore: list[re.Pattern],
) -> Generator[Finding, None, None]:
    if is_ignored(line, ignore):
        return

    for rule in rules:
        for m in rule["_pattern"].finditer(line):
            # Prefer the first capture group if present, else the full match
            matched = m.group(1) if m.lastindex else m.group(0)

            if is_ignored(matched, ignore):
                continue

            entropy_val: Optional[float] = None
            if rule.get("entropy_check"):
                ecfg = rule["_entropy_cfg"]
                ok, entropy_val = is_high_entropy(
                    matched,
                    threshold=ecfg.get("threshold", 4.5),
                    min_length=ecfg.get("min_length", 20),
                )
                if not ok:
                    continue

            # Trim long context lines
            ctx = line.rstrip()
            if len(ctx) > 200:
                start = max(0, m.start() - 40)
                ctx = ctx[start : start + 200]

            yield Finding(
                rule_id=rule["id"],
                rule_name=rule["name"],
                severity=rule.get("severity", "medium"),
                commit=commit,
                author=author,
                date=date,
                file=filepath,
                line=line_num,
                match=matched,
                context=ctx,
                entropy=round(entropy_val, 3) if entropy_val is not None else None,
            )


# ── Git History Scanner ───────────────────────────────────────────────────────

def scan_commit(
    commit: git.Commit,
    rules: list[dict],
    ignore: list[re.Pattern],
) -> Generator[Finding, None, None]:
    if commit.parents:
        diffs = commit.parents[0].diff(commit, create_patch=True)
    else:
        diffs = commit.diff(git.NULL_TREE, create_patch=True)

    author = str(commit.author)
    date = commit.committed_datetime.isoformat()
    sha = commit.hexsha[:8]

    for diff in diffs:
        filepath = diff.b_path or diff.a_path
        if not filepath or should_skip(filepath) or is_ignored(filepath, ignore):
            continue

        try:
            patch = diff.diff.decode("utf-8", errors="replace")
        except Exception:
            continue

        for line_num, line in enumerate(patch.splitlines(), 1):
            if not line.startswith("+") or line.startswith("+++"):
                continue
            yield from scan_line(
                line=line[1:],  # strip leading '+'
                line_num=line_num,
                filepath=filepath,
                commit=sha,
                author=author,
                date=date,
                rules=rules,
                ignore=ignore,
            )


def scan_history(
    repo: git.Repo,
    rules: list[dict],
    ignore: list[re.Pattern],
    branch: Optional[str] = None,
    max_commits: int = 0,
) -> tuple[list[Finding], int, int]:
    rev = branch or "HEAD"
    commits = list(repo.iter_commits(rev, max_count=max_commits or None))

    findings: list[Finding] = []
    seen_files: set[str] = set()

    for commit in commits:
        for f in scan_commit(commit, rules, ignore):
            findings.append(f)
            seen_files.add(f.file)

    return findings, len(commits), len(seen_files)


# ── Working Tree Scanner ──────────────────────────────────────────────────────

def scan_working_tree(
    repo: git.Repo,
    rules: list[dict],
    ignore: list[re.Pattern],
) -> tuple[list[Finding], int]:
    root = Path(repo.working_dir)
    findings: list[Finding] = []
    seen_files: set[str] = set()

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = str(path.relative_to(root))
        if rel.startswith(".git") or should_skip(rel) or is_ignored(rel, ignore):
            continue
        try:
            content = path.read_text(errors="replace")
        except Exception:
            continue

        for line_num, line in enumerate(content.splitlines(), 1):
            for f in scan_line(
                line=line,
                line_num=line_num,
                filepath=rel,
                commit="HEAD",
                author="",
                date="",
                rules=rules,
                ignore=ignore,
            ):
                findings.append(f)
                seen_files.add(f.file)

    return findings, len(seen_files)


# ── Deduplication ─────────────────────────────────────────────────────────────

def deduplicate(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple] = set()
    unique: list[Finding] = []
    for f in findings:
        key = (f.file, f.rule_id, f.match)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


# ── Output ────────────────────────────────────────────────────────────────────

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

_COLORS = {
    "critical": "\033[1;91m",
    "high":     "\033[91m",
    "medium":   "\033[93m",
    "low":      "\033[94m",
    "reset":    "\033[0m",
    "bold":     "\033[1m",
    "dim":      "\033[2m",
}


def badge(severity: str, color: bool) -> str:
    label = f"[{severity.upper()}]"
    if not color:
        return label
    c = _COLORS.get(severity, "")
    return f"{c}{label}{_COLORS['reset']}"


def print_text(result: ScanResult, redact: bool, color: bool) -> None:
    B = _COLORS["bold"] if color else ""
    R = _COLORS["reset"] if color else ""
    D = _COLORS["dim"] if color else ""

    print(f"\n{B}vault-scan{R}  {D}{result.repo_path}{R}")
    print(f"{D}Commits scanned: {result.commits_scanned}  |  Files touched: {result.files_scanned}{R}\n")

    if not result.findings:
        print("No secrets found.\n")
        return

    sep = "─" * 72
    print(f"{B}Found {len(result.findings)} finding(s):{R}\n{sep}")

    for f in result.findings:
        d = f.redacted() if redact else f
        print(f"{badge(f.severity, color)} {B}{f.rule_name}{R}")
        print(f"  {D}file  :{R} {f.file}:{f.line}")
        if f.commit != "HEAD":
            print(f"  {D}commit:{R} {f.commit}  {f.author}  {f.date}")
        print(f"  {D}match :{R} {d.match}")
        if f.entropy is not None:
            print(f"  {D}entropy:{R} {f.entropy:.3f}")
        print(f"  {D}ctx   :{R} {d.context}")
        print(sep)

    counts: dict[str, int] = {}
    for f in result.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    parts = [f"{badge(s, color)} {counts[s]}" for s in ("critical", "high", "medium", "low") if s in counts]
    print(f"\nSummary: {' '.join(parts)}\n")


def print_json(result: ScanResult, redact: bool) -> None:
    findings = [asdict(f.redacted() if redact else f) for f in result.findings]
    print(json.dumps({
        "repo": result.repo_path,
        "commits_scanned": result.commits_scanned,
        "files_scanned": result.files_scanned,
        "total_findings": len(result.findings),
        "findings": findings,
    }, indent=2))


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vault-scan",
        description="Scan git repositories for leaked secrets and credentials.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  vault-scan                            scan current dir (history + HEAD)
  vault-scan --path /path/to/repo       scan a specific repo
  vault-scan --output json              JSON output for CI/CD pipelines
  vault-scan --no-history               scan working tree only
  vault-scan --branch main              scan a specific branch
  vault-scan --max-commits 50           limit to last 50 commits
  vault-scan --severity high            only report high/critical
  vault-scan --show-secrets             unredacted output (be careful)
  vault-scan --entropy-threshold 3.8    lower entropy bar
        """,
    )
    p.add_argument("--path", default=".", metavar="REPO",
                   help="Path to git repo (default: .)")
    p.add_argument("--output", choices=["text", "json"], default="text",
                   help="Output format (default: text)")
    p.add_argument("--branch", metavar="REF",
                   help="Branch/ref to scan (default: HEAD)")
    p.add_argument("--no-history", action="store_true",
                   help="Scan working tree only, skip git history")
    p.add_argument("--max-commits", type=int, default=0, metavar="N",
                   help="Limit to last N commits (default: all)")
    p.add_argument("--severity", choices=list(SEVERITY_ORDER),
                   help="Minimum severity to report")
    p.add_argument("--show-secrets", action="store_true",
                   help="Show unredacted secret values")
    p.add_argument("--ignore", default=".vaultscanignore", metavar="FILE",
                   help="Ignore file (default: .vaultscanignore)")
    p.add_argument("--rules", metavar="FILE",
                   help="Custom rules YAML (default: rules.yaml alongside this script)")
    p.add_argument("--entropy-threshold", type=float, metavar="N",
                   help="Override entropy threshold (default: 4.5)")
    p.add_argument("--no-dedup", action="store_true",
                   help="Disable deduplication")
    p.add_argument("--no-color", action="store_true",
                   help="Disable ANSI color output")
    return p


def main() -> int:
    args = build_parser().parse_args()

    repo_path = Path(args.path).resolve()

    # Locate rules file
    rules_path = Path(args.rules) if args.rules else Path(__file__).parent / "rules.yaml"
    if not rules_path.exists():
        print(f"Error: rules file not found: {rules_path}", file=sys.stderr)
        return 2

    try:
        rules = load_rules(rules_path)
    except Exception as e:
        print(f"Error loading rules: {e}", file=sys.stderr)
        return 2

    # Override entropy threshold if specified
    if args.entropy_threshold is not None:
        for rule in rules:
            rule["_entropy_cfg"]["threshold"] = args.entropy_threshold

    # Load ignore patterns
    ignore_file = Path(args.ignore)
    if not ignore_file.is_absolute():
        ignore_file = repo_path / ignore_file
    ignore = load_ignore_patterns(ignore_file)

    # Open repo
    try:
        repo = git.Repo(repo_path, search_parent_directories=True)
    except git.InvalidGitRepositoryError:
        print(f"Error: not a git repository: {repo_path}", file=sys.stderr)
        return 2

    result = ScanResult(repo_path=str(repo_path))
    all_findings: list[Finding] = []

    if args.no_history:
        findings, files = scan_working_tree(repo, rules, ignore)
        all_findings.extend(findings)
        result.files_scanned = files
    else:
        findings, commits, files = scan_history(
            repo, rules, ignore,
            branch=args.branch,
            max_commits=args.max_commits,
        )
        all_findings.extend(findings)
        result.commits_scanned = commits
        result.files_scanned = files

    # Filter by severity
    if args.severity:
        min_level = SEVERITY_ORDER[args.severity]
        all_findings = [f for f in all_findings if SEVERITY_ORDER.get(f.severity, 99) <= min_level]

    # Deduplicate
    if not args.no_dedup:
        all_findings = deduplicate(all_findings)

    # Sort: severity first, then file path
    all_findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.file))
    result.findings = all_findings

    redact = not args.show_secrets
    use_color = not args.no_color and sys.stdout.isatty()

    if args.output == "json":
        print_json(result, redact=redact)
    else:
        print_text(result, redact=redact, color=use_color)

    return 1 if result.has_findings else 0


if __name__ == "__main__":
    sys.exit(main())
