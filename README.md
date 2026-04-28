# vault-scan

> **Secret scanner for git repositories — finds API keys, credentials, and other secrets in your code and history before they leak.**

![Python](https://img.shields.io/badge/python-3.9%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![CI Friendly](https://img.shields.io/badge/CI-friendly-success?style=flat-square)

---

## What It Does

vault-scan walks your git history (or just your working tree) and surfaces leaked secrets using two complementary detection strategies:

- **Pattern matching** — vendor-specific regexes for ~30 services where the format is distinctive enough that a match is almost always real (AWS, GitHub, Stripe, Slack, Google, SendGrid, Twilio, NPM, PyPI, DigitalOcean, Shopify, Mailchimp, etc.)
- **Entropy gating** — for broad patterns like `API_KEY=...` or `password=...`, the captured value is scored with Shannon entropy to filter out placeholders like `password=changeme` or `API_KEY=YOUR_KEY_HERE`

Findings are deduplicated, severity-tagged, and redacted by default so you can paste output safely into a chat or a ticket.

---

## What It Catches

| Category | Examples |
|---|---|
| **Cloud / Infra** | AWS access key + secret, DigitalOcean PAT, Google API + OAuth secret |
| **Source forges** | GitHub PAT (classic, fine-grained, OAuth, App), GitLab PAT |
| **Comms** | Slack bot/user tokens |
| **Payments** | Stripe live/test secret + publishable keys |
| **SaaS** | SendGrid, Twilio, Shopify, Mailchimp, NPM, PyPI |
| **Private keys** | RSA, EC, OpenSSH, PGP, generic PKCS8 |
| **JWTs** | Standard 3-segment JSON Web Tokens |
| **DB connection strings** | MongoDB, Postgres, MySQL, Redis, AMQP/RabbitMQ |
| **Generic** | `api_key=`, `secret=`, `password=`, `token=` (entropy-gated) |

Full rule list with patterns and severities lives in [`rules.yaml`](rules.yaml).

---

## Installation

```bash
git clone https://github.com/B0bTheSkull/vault-scan.git
cd vault-scan
pip install -r requirements.txt
```

---

## Usage

```bash
# Scan current dir — full history + working tree
python main.py

# Scan a specific repo
python main.py --path /path/to/repo

# Working tree only (skip history)
python main.py --no-history

# JSON output for a CI pipeline
python main.py --output json --no-color

# Filter to high-severity and above
python main.py --severity high

# Only the last 50 commits (for huge histories)
python main.py --max-commits 50

# Show unredacted secret values (be careful)
python main.py --show-secrets

# Lower the entropy threshold (more recall, more false positives)
python main.py --entropy-threshold 3.8
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No findings |
| `1` | Findings present (use this in CI to fail the build) |
| `2` | Usage / configuration error |

### Drop into GitHub Actions

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0  # need full history
- run: pip install -r path/to/vault-scan/requirements.txt
- run: python path/to/vault-scan/main.py --output json --no-color
```

---

## Example Output

```
vault-scan  /home/me/projects/myapp
Commits scanned: 47  |  Files touched: 3

Found 2 finding(s):
────────────────────────────────────────────────────────────────────────
[CRITICAL] AWS Access Key ID
  file  : terraform/dev.tfvars:7
  commit: 4f8b3c2a  Alice <alice@example.com>  2024-08-12T10:42:11
  match : AKIA****************AB12
  ctx   : aws_access_key = "AKIAIOSFODNN7EXAMPLE_AB12"
────────────────────────────────────────────────────────────────────────
[HIGH] Slack Bot Token
  file  : scripts/notify.py:23
  commit: 9e1d4f06  Alice <alice@example.com>  2024-09-01T14:08:55
  match : xoxb-****************************************-uVWxYz0123456789Abc
  ctx   :     slack_token = "xoxb-1234567890-1234567890-..."
────────────────────────────────────────────────────────────────────────

Summary: [CRITICAL] 1 [HIGH] 1
```

---

## Ignore File

Drop a `.vaultscanignore` at the repo root. Same syntax as `.gitignore`:

```
# Test fixtures
tests/fixtures/**

# Vendored dependencies
vendor/
node_modules/

# Specific files
docs/example-tokens.md
```

---

## Why This Exists

GitLeaks and TruffleHog already do this — and they do it well. vault-scan is intentionally smaller. It's a single-file Python script with one YAML rules file and zero compiled dependencies, which makes it:

- Easy to read end-to-end (it's ~500 lines)
- Easy to drop into a CI pipeline that already has Python
- Easy to extend with custom rules (just edit `rules.yaml`)

If you need maximum coverage, run TruffleHog. If you want a tool you can reason about, audit, and tweak in 10 minutes, run this.

---

## Roadmap

- [ ] `--scan-secrets-from-stdin` mode (scan a single text blob, not a repo)
- [ ] Pre-commit hook integration
- [ ] SARIF output format for GitHub code scanning
- [ ] Validation against vendor APIs (is this AWS key actually live?)
- [ ] Bulk scan across a list of remote repos

---

## License

MIT — see [LICENSE](LICENSE)
