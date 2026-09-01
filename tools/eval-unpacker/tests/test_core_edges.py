import pytest
from eval_unpacker import core


def test_string_unescape_supports_control_hex_unicode_and_unknown_escapes():
    assert core.unescape_js_string(r"a\n\t\x41\u0042\q\\") == "a\n\tABq\\"
    assert core.unescape_js_string("trailing\\") == "trailing\\"
    assert core.unescape_js_string(r"\uD83D\uDE00") == "😀"
    assert core.unescape_js_string(r"\uD800") == "\ud800"
    assert core.unescape_js_string(r"\uDC00") == "\udc00"
    assert core.unescape_js_string(r"a\0b") == "a\0b"
    assert core.unescape_js_string("a\\\nb") == "ab"
    assert core.unescape_js_string("a\\\r\nb") == "ab"


def test_argument_parser_rejects_malformed_nesting_and_comments():
    with pytest.raises(ValueError, match="mismatched"):
        core.parse_top_level_args("(]")
    with pytest.raises(ValueError, match="nested"):
        core.parse_top_level_args("([")
    with pytest.raises(ValueError, match="block comment"):
        core.parse_top_level_args("/* never closed")


def test_finder_skips_incomplete_and_non_invoked_functions():
    assert core.find_eval_function_calls("eval(function(p) no_body") == []
    assert core.find_eval_function_calls("eval(function(p){ /* open") == []
    assert core.find_eval_function_calls("eval(function(p){return p})") == []
    assert core.find_eval_function_calls("eval(function garbage {return p}('x'))") == []


def test_literal_array_dictionary_is_supported():
    args = "'0 1',10,2,['hello','w\\u006frld']"
    assert core.unpack_payload_from_call_args(args) == "hello world"


def test_empty_split_separator_uses_javascript_utf16_code_units():
    assert core.unpack_payload_from_call_args("'0 1',10,2,'ab'.split('')") == "a b"
    assert (
        core.unpack_payload_from_call_args("'0 1 2',10,3,'😀x'.split('')")
        == r"\uD83D \uDE00 x"
    )
    assert (
        core.unpack_payload_from_call_args(r"'0',10,1,'\uD800'.split('')") == r"\uD800"
    )


def test_invalid_call_arguments_fail_closed(capsys):
    assert core.unpack_payload_from_call_args("'x',10,0", debug=True) is None
    assert "parsed 3 args" in capsys.readouterr().err
    assert core.unpack_payload_from_call_args("dynamic,10,0,''.split('|')") is None
    assert core.unpack_payload_from_call_args("'x',dynamic,0,''.split('|')") is None
    assert core.unpack_payload_from_call_args("'x',10,-1,''.split('|')") is None
    assert core.unpack_payload_from_call_args("'x' + suffix,10,0,''.split('|')") is None
    assert core.unpack_payload_from_call_args("'x',10,0,['ok', dynamic]") is None


def test_replacement_pattern_size_does_not_scale_with_dictionary(monkeypatch):
    real_compile = core.re.compile

    def bounded_compile(pattern, *args, **kwargs):
        assert len(pattern) < 200
        return real_compile(pattern, *args, **kwargs)

    monkeypatch.setattr(core.re, "compile", bounded_compile)
    assert core.two_pass_replace("0 999", 10, 1_000, []) == "0 999"


def test_direct_replacement_rejects_negative_count():
    with pytest.raises(ValueError, match="non-negative"):
        core.two_pass_replace("x", 10, -1, [])


def test_recursive_mode_stops_when_nested_call_is_unsupported():
    nested = "eval(function(p,a,c,k,e,d){return p}('x',10,1,makeTokens()))"
    outer = (
        'eval(function(p,a,c,k,e,d){return p}("'
        + nested.replace('"', '\\"')
        + '",10,0,"".split("|")))'
    )
    assert core.unpack_text(outer, recursive=True) == nested


def test_header_repair_is_disabled_to_preserve_untrusted_javascript_verbatim():
    samples = [
        "x.setRequestHeader('Authorization: old', 'Bearer token')",
        "const s=\"setRequestHeader('X: y', 'z')\";",
        r"setRequestHeader('X: y', 'b\'c')",
        "setRequestHeader('Accept', 'text/plain')",
    ]
    for source in samples:
        assert core.fix_malformed_setrequestheader(source) == source


def test_beautifier_is_optional_and_receives_options(monkeypatch):
    monkeypatch.setattr(core, "jsbeautifier", None)
    assert core.maybe_beautify("x", 2, 0) == "x"

    class Options:
        indent_size = 0
        wrap_line_length = 0

    class FakeBeautifier:
        @staticmethod
        def default_options():
            return Options()

        @staticmethod
        def beautify(text, options):
            return f"{text}:{options.indent_size}:{options.wrap_line_length}"

    monkeypatch.setattr(core, "jsbeautifier", FakeBeautifier())
    assert core.maybe_beautify("x", 4, 80) == "x:4:80"
