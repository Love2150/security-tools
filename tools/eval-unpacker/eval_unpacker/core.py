# eval_unpacker/core.py
from __future__ import annotations

import re
from dataclasses import dataclass
from hashlib import sha256

try:
    import jsbeautifier  # type: ignore
except ImportError:
    jsbeautifier = None

_DIGITS = "0123456789abcdefghijklmnopqrstuvwxyz"


class LimitExceeded(ValueError):
    """Raised when hostile or unexpectedly large input exceeds a safety limit."""


@dataclass(frozen=True)
class UnpackLimits:
    max_input_bytes: int = 5_000_000
    max_tokens: int = 10_000
    max_replacements: int = 100_000
    max_recursion_depth: int = 10
    max_output_bytes: int = 5_000_000

    def __post_init__(self) -> None:
        for name, value in vars(self).items():
            if value < 1:
                raise ValueError(f"{name} must be positive")


DEFAULT_LIMITS = UnpackLimits()


def _utf8_bytes(text: str) -> bytes:
    return text.encode("utf-8", errors="backslashreplace")


def num_to_base(n: int, base: int) -> str:
    if base < 2 or base > 36:
        raise ValueError("base must be between 2 and 36")
    if n < 0:
        raise ValueError("number must be non-negative")
    if n == 0:
        return "0"
    out = []
    while n:
        out.append(_DIGITS[n % base])
        n //= base
    return "".join(reversed(out))


def unescape_js_string(value: str) -> str:
    if "\\" not in value:
        return value
    out: list[str] = []
    i = 0
    simple = {"b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v"}
    while i < len(value):
        if value[i] != "\\":
            out.append(value[i])
            i += 1
            continue
        if i + 1 >= len(value):
            out.append("\\")
            break
        esc = value[i + 1]
        if esc == "0" and (i + 2 >= len(value) or not value[i + 2].isdigit()):
            out.append("\0")
            i += 2
        elif esc == "\r":
            i += 3 if i + 2 < len(value) and value[i + 2] == "\n" else 2
        elif esc == "\n":
            i += 2
        elif esc in simple:
            out.append(simple[esc])
            i += 2
        elif esc in "\\'\"/":
            out.append(esc)
            i += 2
        elif esc == "x" and re.fullmatch(r"[0-9a-fA-F]{2}", value[i + 2 : i + 4]):
            out.append(chr(int(value[i + 2 : i + 4], 16)))
            i += 4
        elif esc == "u" and re.fullmatch(r"[0-9a-fA-F]{4}", value[i + 2 : i + 6]):
            codepoint = int(value[i + 2 : i + 6], 16)
            if 0xD800 <= codepoint <= 0xDBFF:
                following = value[i + 6 : i + 12]
                if re.fullmatch(r"\\u[0-9a-fA-F]{4}", following):
                    low = int("0x" + following[2:], 0)
                    if 0xDC00 <= low <= 0xDFFF:
                        combined = (
                            0x10000 + ((codepoint - 0xD800) << 10) + (low - 0xDC00)
                        )
                        out.append(chr(combined))
                        i += 12
                        continue
                out.append(chr(codepoint))
            elif 0xDC00 <= codepoint <= 0xDFFF:
                out.append(chr(codepoint))
            else:
                out.append(chr(codepoint))
            i += 6
        else:
            out.append(esc)
            i += 2
    return "".join(out)


def _scan_quoted(text: str, start: int) -> int:
    quote = text[start]
    i = start + 1
    while i < len(text):
        if text[i] in "\r\n" and quote != "`":
            raise ValueError("raw newline in string literal")
        if text[i] == "\\":
            i += 2
        elif text[i] == quote:
            return i + 1
        else:
            i += 1
    raise ValueError("unterminated string literal")


def _skip_comment(text: str, start: int) -> int | None:
    if text.startswith("//", start):
        end = text.find("\n", start + 2)
        return len(text) if end == -1 else end + 1
    if text.startswith("/*", start):
        end = text.find("*/", start + 2)
        return None if end == -1 else end + 2
    return start


def _scan_regex_literal(text: str, start: int) -> int | None:
    i = start + 1
    in_class = False
    while i < len(text):
        ch = text[i]
        if ch in "\r\n":
            return None
        if ch == "\\":
            i += 2
            continue
        if ch == "[":
            in_class = True
        elif ch == "]" and in_class:
            in_class = False
        elif ch == "/" and not in_class:
            i += 1
            while i < len(text) and text[i].isalpha():
                i += 1
            return i
        i += 1
    return None


def parse_top_level_args(text: str, max_args: int | None = None) -> list[str]:
    args: list[str] = []
    buf: list[str] = []
    stack: list[str] = []
    pairs = {")": "(", "]": "[", "}": "{"}
    i = 0
    while i < len(text):
        ch = text[i]
        if ch in "'\"`":
            end = _scan_quoted(text, i)
            buf.append(text[i:end])
            i = end
            continue
        comment_end = _skip_comment(text, i)
        if comment_end is None:
            raise ValueError("unterminated block comment")
        if comment_end != i:
            buf.append(text[i:comment_end])
            i = comment_end
            continue
        if ch in "([{":
            stack.append(ch)
        elif ch in ")]}":
            if not stack or stack[-1] != pairs[ch]:
                raise ValueError("mismatched delimiter")
            stack.pop()
        elif ch == "," and not stack:
            args.append("".join(buf).strip())
            if max_args is not None and len(args) > max_args:
                raise LimitExceeded(f"token count exceeds {max_args}")
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    if stack:
        raise ValueError("unterminated nested expression")
    if buf or args:
        args.append("".join(buf).strip())
        if max_args is not None and len(args) > max_args:
            raise LimitExceeded(f"token count exceeds {max_args}")
    return args


def _find_balanced(text: str, start: int, opener: str, closer: str) -> int | None:
    depth = 0
    i = start
    regex_allowed = True
    pending_control = False
    block_expected = False
    object_expected = False
    pending_body_block: bool | None = None
    after_dot = False
    control_parens: list[bool] = []
    brace_blocks: list[bool] = []
    control_words = {"if", "while", "for", "with", "switch", "catch"}
    regex_prefix_words = {
        "await",
        "case",
        "delete",
        "do",
        "else",
        "in",
        "new",
        "of",
        "return",
        "throw",
        "typeof",
        "void",
        "yield",
    }

    while i < len(text):
        ch = text[i]
        if ch.isspace():
            i += 1
            continue
        if ch in "'\"`":
            try:
                i = _scan_quoted(text, i)
            except ValueError:
                return None
            regex_allowed = False
            pending_control = False
            block_expected = False
            object_expected = False
            continue
        comment_end = _skip_comment(text, i)
        if comment_end is None:
            return None
        if comment_end != i:
            i = comment_end
            continue
        if ch.isalpha() or ch in "_$":
            end = i + 1
            while end < len(text) and (text[end].isalnum() or text[end] in "_$"):
                end += 1
            word = text[i:end]
            if (
                word in {"function", "class"}
                and not after_dot
                and pending_body_block is None
            ):
                pending_body_block = not object_expected
            after_dot = False
            pending_control = word in control_words
            block_expected = word in {"do", "else", "finally", "try"}
            object_expected = word in regex_prefix_words and not block_expected
            regex_allowed = pending_control or word in regex_prefix_words
            i = end
            continue
        if ch.isdigit():
            i += 1
            while i < len(text) and (text[i].isalnum() or text[i] in ".xX_"):
                i += 1
            regex_allowed = False
            pending_control = False
            block_expected = False
            object_expected = False
            continue
        if ch in "+-" and i + 1 < len(text) and text[i + 1] == ch:
            i += 2
            pending_control = False
            block_expected = False
            object_expected = False
            continue
        if ch == "/" and regex_allowed:
            regex_end = _scan_regex_literal(text, i)
            if regex_end is None:
                return None
            i = regex_end
            regex_allowed = False
            pending_control = False
            block_expected = False
            object_expected = False
            continue

        if ch == "(":
            control_parens.append(pending_control)
            pending_control = False
            block_expected = False
            object_expected = True
            regex_allowed = True
        elif ch == ")":
            was_control = control_parens.pop() if control_parens else False
            regex_allowed = was_control
            block_expected = was_control
            object_expected = False
            pending_control = False
        elif ch == "{":
            if pending_body_block is not None:
                is_block = pending_body_block
                pending_body_block = None
            else:
                is_block = (
                    block_expected
                    or (i == start and opener == "{")
                    or not object_expected
                )
            brace_blocks.append(is_block)
            regex_allowed = True
            block_expected = False
            object_expected = False
            pending_control = False
        elif ch == "}":
            regex_allowed = brace_blocks.pop() if brace_blocks else False
            block_expected = False
            object_expected = False
            pending_control = False
        else:
            pending_control = False
            block_expected = False
            after_dot = ch == "."
            if ch == ";":
                pending_body_block = None
            if ch in "[,;:=!?&|+-*%^~<>":
                regex_allowed = True
                object_expected = ch != ";"
            elif ch in "].":
                regex_allowed = False
                object_expected = False
            elif ch == "/":
                regex_allowed = True
                object_expected = True
            else:
                object_expected = False

        if ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return i
            if depth < 0:
                return None
        i += 1
    return None


def _find_next_code_occurrence(text: str, needle: str, start: int) -> int:
    i = start
    opener = "{"  # An initial top-level brace starts a statement block.
    regex_allowed = True
    pending_control = False
    block_expected = False
    object_expected = False
    pending_body_block: bool | None = None
    after_dot = False
    control_parens: list[bool] = []
    brace_blocks: list[bool] = []
    control_words = {"if", "while", "for", "with", "switch", "catch"}
    regex_prefix_words = {
        "await",
        "case",
        "delete",
        "do",
        "else",
        "in",
        "new",
        "of",
        "return",
        "throw",
        "typeof",
        "void",
        "yield",
    }

    while i < len(text):
        if text.startswith(needle, i):
            return i
        ch = text[i]
        if ch.isspace():
            i += 1
            continue
        if ch in "'\"`":
            try:
                i = _scan_quoted(text, i)
            except ValueError:
                return -1
            regex_allowed = False
            pending_control = False
            block_expected = False
            object_expected = False
            continue
        comment_end = _skip_comment(text, i)
        if comment_end is None:
            return -1
        if comment_end != i:
            i = comment_end
            continue
        if ch.isalpha() or ch in "_$":
            end = i + 1
            while end < len(text) and (text[end].isalnum() or text[end] in "_$"):
                end += 1
            word = text[i:end]
            if (
                word in {"function", "class"}
                and not after_dot
                and pending_body_block is None
            ):
                pending_body_block = not object_expected
            after_dot = False
            pending_control = word in control_words
            block_expected = word in {"do", "else", "finally", "try"}
            object_expected = word in regex_prefix_words and not block_expected
            regex_allowed = pending_control or word in regex_prefix_words
            i = end
            continue
        if ch.isdigit():
            i += 1
            while i < len(text) and (text[i].isalnum() or text[i] in ".xX_"):
                i += 1
            regex_allowed = False
            pending_control = False
            block_expected = False
            object_expected = False
            continue
        if ch in "+-" and i + 1 < len(text) and text[i + 1] == ch:
            i += 2
            pending_control = False
            block_expected = False
            object_expected = False
            continue
        if ch == "/" and regex_allowed:
            regex_end = _scan_regex_literal(text, i)
            if regex_end is None:
                return -1
            i = regex_end
            regex_allowed = False
            pending_control = False
            block_expected = False
            object_expected = False
            continue
        if ch == "(":
            control_parens.append(pending_control)
            pending_control = False
            block_expected = False
            object_expected = True
            regex_allowed = True
        elif ch == ")":
            was_control = control_parens.pop() if control_parens else False
            regex_allowed = was_control
            block_expected = was_control
            object_expected = False
            pending_control = False
        elif ch == "{":
            if pending_body_block is not None:
                is_block = pending_body_block
                pending_body_block = None
            else:
                is_block = (
                    block_expected
                    or (i == start and opener == "{")
                    or not object_expected
                )
            brace_blocks.append(is_block)
            regex_allowed = True
            block_expected = False
            object_expected = False
            pending_control = False
        elif ch == "}":
            regex_allowed = brace_blocks.pop() if brace_blocks else False
            block_expected = False
            object_expected = False
            pending_control = False
        else:
            pending_control = False
            block_expected = False
            after_dot = ch == "."
            if ch == ";":
                pending_body_block = None
            if ch in "[,;:=!?&|+-*%^~<>":
                regex_allowed = True
                object_expected = ch != ";"
            elif ch in "].":
                regex_allowed = False
                object_expected = False
            elif ch == "/":
                regex_allowed = True
                object_expected = True
            else:
                object_expected = False
        i += 1
    return -1


def _check_input_size(text: str, limits: UnpackLimits) -> None:
    if len(_utf8_bytes(text)) > limits.max_input_bytes:
        raise LimitExceeded(f"input size exceeds {limits.max_input_bytes} bytes")


def find_eval_function_calls(
    text: str, limits: UnpackLimits = DEFAULT_LIMITS
) -> list[tuple[int, int, str]]:
    _check_input_size(text, limits)
    results: list[tuple[int, int, str]] = []
    idx = 0
    while True:
        pos = _find_next_code_occurrence(text, "eval(function", idx)
        if pos == -1:
            return results
        func_pos = pos + len("eval(")
        params_start = func_pos + len("function")
        while params_start < len(text) and text[params_start].isspace():
            params_start += 1
        if params_start >= len(text) or text[params_start] != "(":
            idx = params_start
            continue
        params_end = _find_balanced(text, params_start, "(", ")")
        if params_end is None:
            return results
        brace_pos = params_end + 1
        while brace_pos < len(text) and text[brace_pos].isspace():
            brace_pos += 1
        if brace_pos >= len(text) or text[brace_pos] != "{":
            idx = brace_pos
            continue
        body_end = _find_balanced(text, brace_pos, "{", "}")
        if body_end is None:
            return results
        invocation = body_end + 1
        while invocation < len(text) and text[invocation].isspace():
            invocation += 1
        if invocation >= len(text) or text[invocation] != "(":
            idx = invocation
            continue
        args_end = _find_balanced(text, invocation, "(", ")")
        if args_end is None:
            return results
        results.append((pos, args_end + 1, text[invocation + 1 : args_end]))
        idx = args_end + 1


def _parse_string_literal(expression: str) -> tuple[str, str] | None:
    expression = expression.strip()
    if not expression or expression[0] not in "'\"":
        return None
    try:
        end = _scan_quoted(expression, 0)
    except ValueError:
        return None
    return unescape_js_string(expression[1 : end - 1]), expression[end:].strip()


def _split_js_utf16_units(body: str, max_tokens: int) -> list[str]:
    units: list[str] = []
    for char in body:
        codepoint = ord(char)
        if codepoint <= 0xFFFF:
            unit = f"\\u{codepoint:04X}" if 0xD800 <= codepoint <= 0xDFFF else char
            units.append(unit)
        else:
            value = codepoint - 0x10000
            units.extend(
                [
                    f"\\u{0xD800 + (value >> 10):04X}",
                    f"\\u{0xDC00 + (value & 0x3FF):04X}",
                ]
            )
        if len(units) > max_tokens:
            raise LimitExceeded(f"token count exceeds {max_tokens}")
    return units


def _parse_tokens(
    expression: str, limits: UnpackLimits = DEFAULT_LIMITS
) -> list[str] | None:
    expression = expression.strip()
    if expression.startswith("[") and expression.endswith("]"):
        try:
            parts = parse_top_level_args(expression[1:-1], max_args=limits.max_tokens)
        except LimitExceeded:
            raise
        except ValueError:
            return None
        tokens: list[str] = []
        for part in parts:
            parsed = _parse_string_literal(part)
            if parsed is None or parsed[1]:
                return None
            tokens.append(parsed[0])
        return tokens

    parsed = _parse_string_literal(expression)
    if parsed is None:
        return None
    body, tail = parsed
    match = re.fullmatch(r"\.split\s*\(\s*(['\"])(.*?)\1\s*\)", tail, re.DOTALL)
    if not match:
        return None
    separator = unescape_js_string(match.group(2))
    if not body:
        return []
    if separator == "":
        return _split_js_utf16_units(body, limits.max_tokens)
    token_count = body.count(separator) + 1
    if token_count > limits.max_tokens:
        raise LimitExceeded(f"token count exceeds {limits.max_tokens}")
    return body.split(separator)


def two_pass_replace(
    payload: str,
    base: int,
    count: int,
    tokens: list[str],
    limits: UnpackLimits = DEFAULT_LIMITS,
) -> str:
    num_to_base(0, base)
    if count < 0:
        raise ValueError("token count must be non-negative")
    if count > limits.max_tokens:
        raise LimitExceeded(f"token count exceeds {limits.max_tokens}")
    if count == 0:
        if len(_utf8_bytes(payload)) > limits.max_output_bytes:
            raise LimitExceeded(f"output size exceeds {limits.max_output_bytes} bytes")
        return payload

    replacements = {
        num_to_base(i, base): (
            tokens[i] if i < len(tokens) and tokens[i] else num_to_base(i, base)
        )
        for i in range(count)
    }
    pattern = re.compile(r"(?<![A-Za-z0-9_])([A-Za-z0-9]+)(?![A-Za-z0-9_])")
    pieces: list[str] = []
    output_bytes = 0
    last_end = 0

    def append_bounded(piece: str) -> None:
        nonlocal output_bytes
        output_bytes += len(_utf8_bytes(piece))
        if output_bytes > limits.max_output_bytes:
            raise LimitExceeded(f"output size exceeds {limits.max_output_bytes} bytes")
        pieces.append(piece)

    eligible_matches = (
        match for match in pattern.finditer(payload) if match.group(1) in replacements
    )
    for replacements_seen, match in enumerate(eligible_matches, start=1):
        if replacements_seen > limits.max_replacements:
            raise LimitExceeded(f"replacement count exceeds {limits.max_replacements}")
        append_bounded(payload[last_end : match.start()])
        append_bounded(replacements[match.group(1)])
        last_end = match.end()
    append_bounded(payload[last_end:])
    return "".join(pieces)


def unpack_payload_from_call_args(
    call_args: str, debug: bool = False, limits: UnpackLimits = DEFAULT_LIMITS
) -> str | None:
    import sys

    try:
        args = parse_top_level_args(call_args, max_args=6)
    except LimitExceeded as error:
        raise LimitExceeded("argument count exceeds 6") from error
    except ValueError:
        return None
    if debug:
        print(f"[debug] parsed {len(args)} args", file=sys.stderr)
    if len(args) < 4:
        return None
    payload_literal = _parse_string_literal(args[0])
    if payload_literal is None or payload_literal[1]:
        return None
    try:
        base = int(args[1], 10)
        count = int(args[2], 10)
        num_to_base(0, base)
    except ValueError:
        return None
    if count < 0:
        return None
    tokens = _parse_tokens(args[3], limits)
    if tokens is None:
        return None
    if len(tokens) > limits.max_tokens:
        raise LimitExceeded(f"token count exceeds {limits.max_tokens}")
    return two_pass_replace(payload_literal[0], base, count, tokens, limits)


def unpack_text(
    text: str,
    *,
    recursive: bool = False,
    debug: bool = False,
    limits: UnpackLimits = DEFAULT_LIMITS,
) -> str | None:
    matches = find_eval_function_calls(text, limits)
    output = None
    for _, _, call_args in matches:
        output = unpack_payload_from_call_args(call_args, debug=debug, limits=limits)
        if output is not None:
            break
    if output is None or not recursive:
        return output

    depth = 1
    seen_hashes = {sha256(_utf8_bytes(output)).digest()}
    while True:
        nested = find_eval_function_calls(output, limits)
        if not nested:
            return output
        deeper = None
        for _, _, nested_args in nested:
            deeper = unpack_payload_from_call_args(
                nested_args, debug=debug, limits=limits
            )
            if deeper is not None:
                break
        if deeper is None:
            return output
        if depth >= limits.max_recursion_depth:
            raise LimitExceeded(f"recursion depth exceeds {limits.max_recursion_depth}")
        digest = sha256(_utf8_bytes(deeper)).digest()
        if digest in seen_hashes:
            return output
        seen_hashes.add(digest)
        output = deeper
        depth += 1


def fix_malformed_setrequestheader(js_text: str) -> str:
    """Return unpacked JavaScript unchanged.

    Earlier releases attempted to repair malformed ``setRequestHeader`` calls
    with a context-free regular expression. That could rewrite string literals,
    corrupt escaped quotes, and take quadratic time on hostile input. Preserving
    analyst evidence verbatim is safer than guessing at executable syntax.
    """
    return js_text


def maybe_beautify(js_text: str, indent_size: int, wrap_line_length: int) -> str:
    if jsbeautifier is None:
        return js_text
    opts = jsbeautifier.default_options()
    opts.indent_size = indent_size
    opts.wrap_line_length = max(0, wrap_line_length)
    return jsbeautifier.beautify(js_text, opts)
