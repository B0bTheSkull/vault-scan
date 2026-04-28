import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from main import load_rules

RULES_PATH = Path(__file__).parent.parent / "rules.yaml"


@pytest.fixture(scope="module")
def rules():
    return load_rules(RULES_PATH)


def test_rules_load(rules):
    assert len(rules) > 0
    for r in rules:
        assert "id" in r
        assert "name" in r
        assert "_pattern" in r


def _match(rules, rule_id: str, sample: str) -> bool:
    rule = next((r for r in rules if r["id"] == rule_id), None)
    assert rule is not None, f"rule {rule_id} not found"
    return rule["_pattern"].search(sample) is not None


def test_aws_access_key_id(rules):
    assert _match(rules, "aws_access_key_id", "AKIAIOSFODNN7EXAMPLE")
    assert _match(rules, "aws_access_key_id", "ASIA1234567890ABCDEF")
    assert not _match(rules, "aws_access_key_id", "AKIA-shorter")


def test_github_pat_classic(rules):
    sample = "ghp_" + "A" * 36
    assert _match(rules, "github_pat_classic", sample)


def test_github_app_token(rules):
    assert _match(rules, "github_app_token", "ghs_" + "B" * 36)
    assert _match(rules, "github_app_token", "ghu_" + "C" * 36)
    assert _match(rules, "github_app_token", "ghr_" + "D" * 36)


def test_slack_bot_token(rules):
    # Construct from parts so push-time secret scanners don't flag a test fixture
    sample = "xo" + "xb" + "-1234567890-1234567890-aBcDeFgHiJkLmNoPqRsTuVwX"
    assert _match(rules, "slack_bot_token", sample)


def test_stripe_live_secret(rules):
    assert _match(rules, "stripe_secret_live", "sk_live_" + "X" * 24)


def test_google_api_key(rules):
    assert _match(rules, "google_api_key", "AIza" + "a" * 35)


def test_private_key_rsa_header(rules):
    assert _match(rules, "private_key_rsa", "-----BEGIN RSA PRIVATE KEY-----")


def test_jwt_format(rules):
    sample = "eyJabcDEFghijklmn.eyJabcDEFghijklmn.AbCdEfGhIjKlMnOpQrSt"
    assert _match(rules, "jwt", sample)


def test_mongodb_uri(rules):
    assert _match(
        rules, "uri_mongodb", "mongodb://user:pa55word@cluster0.mongodb.net/db"
    )


def test_postgres_uri(rules):
    assert _match(
        rules, "uri_postgresql", "postgresql://user:pa55word@db.example.com/app"
    )
