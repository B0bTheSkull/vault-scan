# Catching secrets before they leave the repo

> "The secret was removed from the code" is not the same as "the secret was removed from git." The diff is a permanent record. vault-scan reads the whole record.

## TL;DR

vault-scan is a Python secret scanner that walks git history and working trees looking for API keys, credentials, private keys, and connection strings. It pairs vendor-specific regexes (AWS, GitHub, Stripe, Slack, and about 25 other services) with Shannon entropy gating for broader patterns, so the signal-to-noise ratio stays usable without constant tuning. Exit code 1 on findings, JSON output mode, and a `.vaultscanignore` file make it a drop-in for any Python-capable CI pipeline.

---

## Why this problem is harder than it looks

Credentials end up in git in predictable ways: a developer hard-codes a key to test something, the test passes, the key ships in the commit. Or a `.env` gets committed by accident. Or a config file gets restructured and a secret rides along in the diff. The working tree might be clean afterward, but the key is still in every clone of the repo, every fork, every CI log that ran `git log --all`.

Three things make naive approaches fail:

1. **History walking.** A find-in-files approach only sees HEAD. Secrets removed from the working tree but still in commit history are invisible — and those are the ones attackers specifically look for.

2. **False positives.** The string `API_KEY=changeme` is not a secret. `password=test` is not a secret. A scanner that fires on either is useless within a week. You need a way to distinguish placeholder strings from real credentials.

3. **Vendor-specific formats.** AWS access key IDs start with a published prefix scheme (`AKIA`, `AGPA`, etc.). GitHub tokens are prefixed by type (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`). Stripe keys start with `sk_live_` or `sk_test_`. These prefixes are distinctive enough that a match is almost always real — no entropy calculation needed. A good scanner knows this.

vault-scan addresses all three.

---

## What's in the box

The project is a single `main.py` (~500 lines) and a `rules.yaml` that defines the detection logic. The core is a two-mode scanner:

**History scan** — uses GitPython to walk every commit on the target branch via `repo.iter_commits()`. For each commit, it diffs against the parent (`commit.parents[0].diff(commit, create_patch=True)`) and scans only the added lines (lines starting with `+` in the patch). This means a secret in commit 1 that's removed in commit 2 still shows up — because it was added in commit 1.

**Working tree scan** — `rglob("*")` from the repo root, skipping `.git/`, binary extensions, and lockfiles. Scans the current state of every text file.

Both modes feed line text through the same `scan_line()` function against all loaded rules.

### Detection strategy

Rules fall into two categories:

**Pattern-only** — vendor-specific regexes where the format is distinctive enough that a match is almost always real:
- `(?:A3T[A-Z0-9]|AKIA|AGPA|...)[A-Z0-9]{16}` for AWS access key IDs
- `ghp_[A-Za-z0-9]{36}` for GitHub classic PATs
- `-----BEGIN RSA PRIVATE KEY-----` for PEM headers

**Entropy-gated** — broader patterns (like `api_key=...` or `password=...`) where the regex captures the value and Shannon entropy filters out placeholders:

```python
def shannon_entropy(data: str) -> float:
    freq = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())
```

The default threshold is 4.5 bits per character. `changeme` scores around 2.5. A real 32-char random token typically scores above 5.0. The threshold is tunable at runtime with `--entropy-threshold`.

Findings are deduplicated by `(file, rule_id, match)` tuple before output — a secret present in 40 commits doesn't generate 40 findings.

---

## The demo

I set up a fake repo with two commits to demonstrate the history-walking behavior:

**Commit 1** planted:
- `config.py` — an AWS access key ID (`AKIAXXXXXXFAKEKEY0001`) and a GitHub PAT (`ghp_FaKeGitHubPAT...`)
- `.env` — a PostgreSQL connection string with embedded credentials
- `deploy.sh` — a Stripe live key in a comment
- `private_key.pem` — a fake RSA private key block

**Commit 2** "cleaned up" — removed the hardcoded credentials from `config.py` and `deploy.sh`, moving to `None` placeholders.

Result after running vault-scan against the two-commit history:

```
vault-scan  /tmp/vault-scan-target
Commits scanned: 2  |  Files touched: 4

Found 5 finding(s):
────────────────────────────────────────────────────────────────────────
[CRITICAL] AWS Access Key ID
  file  : config.py:5
  commit: 77486805  Demo User  2026-05-13T21:57:28-06:00
  match : AKIA************Y000
  ctx   : AWS_ACCESS_KEY_ID = "AKIAXXXXXXFAKEKEY0001"
────────────────────────────────────────────────────────────────────────
[CRITICAL] GitHub Personal Access Token
  file  : config.py:9
  commit: 77486805  Demo User  2026-05-13T21:57:28-06:00
  match : ghp_********************************xxxx
  ctx   : GITHUB_TOKEN = "ghp_FaKeGitHubPATxxxxxxxxxxxxxxxxxxxxxxxx"
────────────────────────────────────────────────────────────────────────
[CRITICAL] Stripe Live Secret Key
  file  : deploy.sh:7
  commit: 77486805  Demo User  2026-05-13T21:57:28-06:00
  match : sk_l**************************************XXXX
  ctx   : # STRIPE_SECRET_KEY was here: sk_live_**REDACTED-DEMO**
────────────────────────────────────────────────────────────────────────
[CRITICAL] RSA Private Key
  file  : private_key.pem:2
  commit: 77486805  Demo User  2026-05-13T21:57:28-06:00
  match : ----***********************----
  ctx   : -----BEGIN RSA PRIVATE KEY-----
────────────────────────────────────────────────────────────────────────
[HIGH] PostgreSQL Connection String
  file  : .env:3
  commit: 77486805  Demo User  2026-05-13T21:57:28-06:00
  match : post*******************************************************yapp
  ctx   : DATABASE_URL=postgresql://fakeuser:n0tAR3alPa55w0rd@db.example.invalid/myapp
────────────────────────────────────────────────────────────────────────

Summary: [CRITICAL] 4 [HIGH] 1
```

The scan caught all five secrets, including the two removed in commit 2. The matches are redacted by default — you can paste the output into a ticket without re-leaking the value. The commit SHA, author, and timestamp make it straightforward to trace when each secret was introduced and by whom.

Full output: [`screenshots/sample-scan.txt`](screenshots/sample-scan.txt)

---

## Where this fits: DevSecOps, pre-commit, forensics

Three natural deployment contexts:

**Pre-commit hook** — the fastest feedback loop. Running vault-scan locally before a push means secrets never reach the remote at all. The exit code 1 on findings makes it trivial to wire into `.pre-commit-config.yaml` or a simple git hook script. This is the gold standard; the roadmap includes a first-class `pre-commit` integration.

**CI gate** — vault-scan's `--output json` and non-zero exit make it a natural step in a pipeline. Drop it after the checkout step with `fetch-depth: 0` (full history required) and let it fail the build. Findings land in the job log as structured JSON, which most CI platforms can surface in a summary view or route to a SAST aggregator once SARIF output is added (roadmap item).

**Forensic audit** — post-incident or pre-open-sourcing a codebase, vault-scan with `--max-commits` removed and `--show-secrets` enabled gives an authoritative list of every secret that ever touched the repo's history. Useful for understanding blast radius and knowing which credentials actually need rotation.

---

## Comparing with truffleHog and gitleaks

vault-scan is intentionally not trying to beat either.

| | vault-scan | truffleHog | gitleaks |
|---|---|---|---|
| **Language** | Python, no compiled deps | Go binary | Go binary |
| **Rules** | ~30, in plain YAML | 700+ rules + ML entropy | 150+ rules in TOML |
| **History walking** | Yes | Yes | Yes |
| **Entropy** | Shannon, configurable | Shannon + ML | Shannon |
| **Verification** | None (roadmap) | Live API checks (some rules) | None |
| **CI integration** | Exit code + JSON | SARIF, JSON | SARIF, JSON, JUnit |
| **Custom rules** | Edit rules.yaml | Custom detectors via Go | Custom TOML |
| **Audit-ability** | ~500 lines, readable | Large Go codebase | Large Go codebase |

If you want maximum coverage and a production-hardened tool, use truffleHog or gitleaks. If you want a tool you can read end-to-end, audit, and modify without setting up a Go toolchain, vault-scan fits. The rule set is small enough to review in 20 minutes, and adding a new detector is a four-line YAML block.

---

## Limits and known gaps

**False positives are still possible.** The entropy gate handles placeholders well, but a base64-encoded config blob that happens to look like a token will occasionally trip the generic rules. The `.vaultscanignore` file handles the common cases (test fixtures, vendor directories), but it's a manual step.

**Performance on large repos is slow.** Walking every commit diff via GitPython's Python-layer diff is not fast. A repository with 50,000 commits and large diffs will take minutes. The `--max-commits` flag addresses this for practical use, but a proper index or native C backend would be the right long-term fix.

**No live validation.** vault-scan doesn't know if a found key is still active. An AWS key found in a five-year-old commit might already be revoked. TruffleHog has begun adding live API verification for some credential types — that's the direction this would eventually go.

**Packed objects and shallow clones.** GitPython's diff relies on objects being fully unpacked. Shallow clones (`fetch-depth: 1`) or repos with many packed objects can produce incomplete diffs. The CI usage docs call out `fetch-depth: 0` explicitly for this reason, but it's easy to miss.

**Binary and minified files are skipped.** The extension-based skip list covers most cases, but a credential embedded in a minified JS bundle or a compiled config won't be caught. This is a deliberate tradeoff — scanning binary blobs generates more noise than signal.

---

## What I'd do differently

**Add pre-commit hook scaffolding from day one.** The most valuable deployment of a secret scanner is the one that runs before the secret ever reaches the remote. Retrofitting this is straightforward, but it should have been the first-class interface, not a roadmap item.

**Write a benchmark suite early.** It was hard to know if a regex change was making things slower without a baseline. A simple "scan this 1,000-commit repo, measure wall time and finding count" test would've caught a few unintentional regressions.

**Consider a rules-as-code approach sooner.** YAML is readable, but it can't express logic — the entropy gating is embedded in the Python and referenced by a flag in the rule. A proper rules DSL or at least a richer YAML schema would make complex detection logic (e.g., "this pattern only in Python files, this severity if in a commit older than 30 days") easier to express without touching the core scanner.

---

## Resources

- The repo: [github.com/B0bTheSkull/vault-scan](https://github.com/B0bTheSkull/vault-scan)
- [truffleHog](https://github.com/trufflesecurity/trufflehog) — production-grade, 700+ detectors, live verification
- [gitleaks](https://github.com/gitleaks/gitleaks) — fast Go binary, SARIF output, widely used in CI
- [Shannon entropy primer](https://en.wikipedia.org/wiki/Entropy_(information_theory)) — the math behind why random-looking strings score higher
- [GitPython docs](https://gitpython.readthedocs.io/) — the library powering vault-scan's history walking
