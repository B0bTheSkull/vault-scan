import io
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from main import Finding, ScanResult, print_json, print_text

RAW_SECRET = "AKIAIOSFODNN7EXAMPLEKEY1234567890"


def _finding() -> Finding:
    return Finding(
        rule_id="aws_key",
        rule_name="AWS Access Key",
        severity="high",
        commit="HEAD",
        author="",
        date="",
        file="config.py",
        line=10,
        match=RAW_SECRET,
        context=f'AWS_SECRET = "{RAW_SECRET}"  # do not commit',
    )


def test_redacted_context_does_not_leak_secret():
    redacted = _finding().redacted()
    assert RAW_SECRET not in redacted.context
    assert RAW_SECRET not in redacted.match


def test_text_output_never_contains_raw_secret():
    result = ScanResult(repo_path="/tmp/repo", findings=[_finding()])
    buf = io.StringIO()
    with redirect_stdout(buf):
        print_text(result, redact=True, color=False)
    assert RAW_SECRET not in buf.getvalue()


def test_json_output_never_contains_raw_secret():
    result = ScanResult(repo_path="/tmp/repo", findings=[_finding()])
    buf = io.StringIO()
    with redirect_stdout(buf):
        print_json(result, redact=True)
    out = buf.getvalue()
    assert RAW_SECRET not in out
    # And it must still be valid JSON.
    json.loads(out)


def test_show_secrets_still_reveals_when_requested():
    result = ScanResult(repo_path="/tmp/repo", findings=[_finding()])
    buf = io.StringIO()
    with redirect_stdout(buf):
        print_text(result, redact=False, color=False)
    assert RAW_SECRET in buf.getvalue()
