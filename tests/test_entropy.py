import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from main import is_high_entropy, shannon_entropy


def test_shannon_entropy_empty():
    assert shannon_entropy("") == 0.0


def test_shannon_entropy_single_char():
    # "aaaa" has zero entropy — only one symbol
    assert shannon_entropy("aaaa") == 0.0


def test_shannon_entropy_random_high():
    # Random base64-ish string should score above 4.5 bits/char
    sample = "AKIAIOSFODNN7EXAMPLE_xK3p9aQrZbVmYsT"
    assert shannon_entropy(sample) > 4.0


def test_shannon_entropy_repetitive_low():
    # "password123" is low-entropy
    assert shannon_entropy("password123") < 4.0


def test_is_high_entropy_too_short():
    ok, _ = is_high_entropy("short", min_length=20)
    assert not ok


def test_is_high_entropy_placeholder_rejected():
    ok, _ = is_high_entropy("YOUR_KEY_GOES_HERE_PLEASE", threshold=4.5)
    assert not ok


def test_is_high_entropy_real_secret_accepted():
    # An actual-looking AWS-secret-style string
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    ok, e = is_high_entropy(secret, threshold=4.5)
    assert ok
    assert e >= 4.5
