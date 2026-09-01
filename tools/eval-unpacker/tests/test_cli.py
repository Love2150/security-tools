import os
import subprocess
import sys
from pathlib import Path

import pytest
from eval_unpacker.cli import _encode_output
from eval_unpacker.core import LimitExceeded

ROOT = Path(__file__).parents[1]
ENV = {**os.environ, "PYTHONPATH": str(ROOT)}


def run_cli(*args: str, input_bytes: bytes = b"") -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, "-m", "eval_unpacker.cli", *args],
        input=input_bytes,
        capture_output=True,
        cwd=ROOT,
        env=ENV,
        check=False,
    )


def test_final_output_encoding_preserves_surrogates_visibly_and_enforces_limit():
    assert _encode_output("ok\ud800", 8) == b"ok\\ud800"
    with pytest.raises(LimitExceeded, match="output size"):
        _encode_output("ok\ud800", 7)
    assert _encode_output("ok", 3, include_newline=True) == b"ok\n"
    with pytest.raises(LimitExceeded, match="output size"):
        _encode_output("ok", 2, include_newline=True)


def test_cli_documents_and_accepts_safety_limit_overrides():
    result = run_cli("--help")
    help_text = result.stdout.decode()
    assert result.returncode == 0
    assert "--max-input-bytes" in help_text
    assert "--max-tokens" in help_text
    assert "--max-replacements" in help_text
    assert "--max-recursion-depth" in help_text


def test_cli_rejects_unreasonable_numeric_overrides():
    assert run_cli("-", "--indent", "17").returncode == 2
    assert run_cli("-", "--wrap", "-1").returncode == 2
    assert run_cli("-", "--max-input-bytes", "50000001").returncode == 2


def test_cli_rejects_input_that_exceeds_byte_limit():
    result = run_cli("-", "--max-input-bytes", "8", input_bytes=b"0123456789")
    assert result.returncode == 2
    assert b"input size" in result.stderr


def test_cli_warns_and_replaces_invalid_utf8_instead_of_silently_dropping_bytes(
    tmp_path,
):
    packed = b"\xffeval(function(p,a,c,k,e,d){return p}('ok',10,0,''.split('|')))"
    sample = tmp_path / "invalid.js"
    sample.write_bytes(packed)
    result = run_cli(str(sample))
    assert result.returncode == 0
    assert result.stdout.strip() == b"ok"
    assert b"invalid UTF-8" in result.stderr
    assert b"replaced" in result.stderr

    exact_limit = run_cli(
        "-", "--max-input-bytes", str(len(packed)), input_bytes=packed
    )
    assert exact_limit.returncode == 2
    assert b"decoded input size" in exact_limit.stderr


def test_cli_explicitly_processes_only_the_first_packer():
    packed = (
        b"eval(function(p,a,c,k,e,d){return p}('first',10,0,''.split('|')));"
        b"eval(function(p,a,c,k,e,d){return p}('second',10,0,''.split('|')))"
    )
    result = run_cli("-", input_bytes=packed)
    assert result.returncode == 0
    assert result.stdout.strip() == b"first"
