import tracemalloc

import pytest
from eval_unpacker.core import (
    DEFAULT_LIMITS,
    LimitExceeded,
    UnpackLimits,
    find_eval_function_calls,
    num_to_base,
    parse_top_level_args,
    two_pass_replace,
    unpack_payload_from_call_args,
    unpack_text,
)


def packer(payload: str, base: int = 10, count: int = 0, tokens: str = "") -> str:
    escaped = payload.replace("\\", "\\\\").replace('"', '\\"')
    return (
        "eval(function(p,a,c,k,e,d){return p}"
        f'("{escaped}",{base},{count},"{tokens}".split("|")))'
    )


def test_num_to_base_rejects_negative_numbers_and_invalid_bases():
    with pytest.raises(ValueError, match="non-negative"):
        num_to_base(-1, 10)
    with pytest.raises(ValueError, match="between 2 and 36"):
        num_to_base(0, 1)


def test_argument_parser_handles_nested_values_and_escaped_quotes():
    args = parse_top_level_args("'a,\\'b', 10, fn([1, 2], {x: '}'})")
    assert args == ["'a,\\'b'", "10", "fn([1, 2], {x: '}'})"]


def test_finder_ignores_braces_in_strings_and_comments():
    source = (
        "eval(function(p,a,c,k,e,d){"
        "/* } ignored */ var s='{'; // } ignored\nreturn p}"
        "('0',10,1,'ok'.split('|')))"
    )
    assert len(find_eval_function_calls(source)) == 1


def test_finder_ignores_packer_text_inside_top_level_strings_and_comments():
    fake = "eval(function(p,a,c,k,e,d){return p}('fake',10,0,''.split('|')))"
    real = packer("real")
    source = f'"{fake}"; /* {fake} */ // {fake}\n{real}'
    matches = find_eval_function_calls(source)
    assert len(matches) == 1
    assert unpack_text(source) == "real"


def test_finder_distinguishes_postfix_and_object_division_from_regex():
    sources = [
        "x++ / 2;" + packer("real"),
        "const x = {} / 2;" + packer("real"),
        "const x = function(){} / 2;" + packer("real"),
        "const x = class {} / 2;" + packer("real"),
        "obj.function(); const x = {} / 2;" + packer("real"),
        "obj.class; const x = {} / 2;" + packer("real"),
    ]
    assert all(unpack_text(source) == "real" for source in sources)


def test_finder_fails_closed_without_rescanning_unbalanced_candidates(monkeypatch):
    original = __import__("eval_unpacker.core", fromlist=["_find_balanced"])
    calls = 0
    real_find_balanced = original._find_balanced

    def counted(*args, **kwargs):
        nonlocal calls
        calls += 1
        return real_find_balanced(*args, **kwargs)

    monkeypatch.setattr(original, "_find_balanced", counted)
    assert find_eval_function_calls("eval(function{" * 100) == []
    assert calls <= 1


def test_finder_handles_braces_inside_javascript_regex_literals():
    sources = [
        (
            "eval(function(p,a,c,k,e,d){return /[})]/.test(p) ? p : ''}"
            "('ok',10,0,''.split('|')))"
        ),
        (
            "eval(function(p,a,c,k,e,d){if (p) /}/.test(p); return p}"
            "('ok',10,0,''.split('|')))"
        ),
        (
            "eval(function(p,a,c,k,e,d){if (Boolean(p)) /}/.test(p); return p}"
            "('ok',10,0,''.split('|')))"
        ),
        (
            "eval(function(p,a,c,k,e,d){if ((p)) /}/.test(p); return p}"
            "('ok',10,0,''.split('|')))"
        ),
        (
            "eval(function(p,a,c,k,e,d){if (p) {} /}/.test(p); return p}"
            "('ok',10,0,''.split('|')))"
        ),
        (
            "eval(function(p,a,c,k,e,d){{} /}/.test(p); return p}"
            "('ok',10,0,''.split('|')))"
        ),
    ]
    assert all(len(find_eval_function_calls(source)) == 1 for source in sources)


def test_malformed_calls_are_not_reported():
    assert find_eval_function_calls("eval(function(p){return '}')('x'") == []
    with pytest.raises(ValueError, match="unterminated"):
        parse_top_level_args("'unterminated")
    with pytest.raises(ValueError, match="newline"):
        parse_top_level_args("'raw\nnewline'")
    with pytest.raises(LimitExceeded, match="argument count"):
        unpack_payload_from_call_args("'x',10,0,''.split('|'),0,0,0")


def test_unpack_handles_escaped_quotes_and_empty_tokens():
    assert (
        unpack_payload_from_call_args(r"'say \'hi\' 1',10,2,'|there'.split('|')")
        == "say 'hi' there"
    )


def test_unpack_rejects_unsupported_token_syntax_and_base_bounds():
    assert unpack_payload_from_call_args("'0',1,1,'x'.split('|')") is None
    assert unpack_payload_from_call_args("'0',10,1,makeTokens()") is None


def test_multiple_packers_use_the_first_supported_occurrence():
    text = packer("first") + ";" + packer("second")
    assert unpack_text(text) == "first"

    unsupported = "eval(function(p,a,c,k,e,d){return p}('x',10,1,makeTokens()))"
    assert unpack_text(unsupported + ";" + packer("valid")) == "valid"


def test_recursive_unpacking_is_bounded_and_uses_hashes_for_cycle_detection():
    nested = packer(packer("done"))
    assert unpack_text(nested, recursive=True) == "done"
    with pytest.raises(LimitExceeded, match="recursion depth"):
        unpack_text(nested, recursive=True, limits=UnpackLimits(max_recursion_depth=1))

    unsupported = "eval(function(p,a,c,k,e,d){return p}('x',10,1,makeTokens()))"
    assert (
        unpack_text(
            packer(unsupported),
            recursive=True,
            limits=UnpackLimits(max_recursion_depth=1),
        )
        == unsupported
    )


def test_input_token_replacement_and_output_limits_are_enforced():
    with pytest.raises(LimitExceeded, match="input size"):
        find_eval_function_calls("x" * 20, limits=UnpackLimits(max_input_bytes=10))
    with pytest.raises(LimitExceeded, match="token count"):
        unpack_text(
            packer("0 1", count=2, tokens="a|b"), limits=UnpackLimits(max_tokens=1)
        )
    with pytest.raises(LimitExceeded, match="token count"):
        unpack_text(
            packer("0", count=1, tokens="a|b"), limits=UnpackLimits(max_tokens=1)
        )
    with pytest.raises(LimitExceeded, match="replacement count"):
        unpack_text(
            packer("0 0", count=1, tokens="a"), limits=UnpackLimits(max_replacements=1)
        )
    with pytest.raises(LimitExceeded, match="output size"):
        unpack_text(
            packer("0", count=1, tokens="long-value"),
            limits=UnpackLimits(max_output_bytes=4),
        )


def test_output_limit_stops_expansion_before_allocating_the_full_result():
    payload = " ".join(["0"] * 100)
    token = "x" * 100_000
    tracemalloc.start()
    try:
        with pytest.raises(LimitExceeded, match="output size"):
            two_pass_replace(
                payload,
                10,
                1,
                [token],
                UnpackLimits(max_output_bytes=1_000),
            )
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 2_000_000


def test_token_limit_is_checked_before_split_allocates_a_large_dictionary():
    dictionary = "|".join(["a"] * 100_000)
    call_args = f"'0',10,1,'{dictionary}'.split('|')"
    tracemalloc.start()
    try:
        with pytest.raises(LimitExceeded, match="token count"):
            unpack_payload_from_call_args(call_args, limits=UnpackLimits(max_tokens=10))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 1_000_000


def test_default_limits_are_conservative():
    assert DEFAULT_LIMITS.max_input_bytes <= 5_000_000
    assert DEFAULT_LIMITS.max_tokens <= 10_000
    assert DEFAULT_LIMITS.max_replacements <= 100_000
    assert DEFAULT_LIMITS.max_recursion_depth <= 10
