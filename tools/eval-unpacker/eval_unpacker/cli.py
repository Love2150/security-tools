# eval_unpacker/cli.py
import argparse
import sys

from .core import (
    DEFAULT_LIMITS,
    LimitExceeded,
    UnpackLimits,
    fix_malformed_setrequestheader,
    maybe_beautify,
    unpack_text,
)

_BEAUTIFY_MAX_INPUT_BYTES = 1_000_000


def _bounded_int(minimum: int, maximum: int):
    def parse(value: str) -> int:
        parsed = int(value)
        if not minimum <= parsed <= maximum:
            raise argparse.ArgumentTypeError(f"must be between {minimum} and {maximum}")
        return parsed

    return parse


def _encode_output(
    text: str, max_bytes: int, *, include_newline: bool = False
) -> bytes:
    data = text.encode("utf-8", errors="backslashreplace")
    if include_newline:
        data += b"\n"
    if len(data) > max_bytes:
        raise LimitExceeded(f"output size exceeds {max_bytes} bytes")
    return data


def _decode_input(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as error:
        print(
            "Warning: input contains invalid UTF-8; invalid bytes were replaced "
            f"(first error at byte {error.start}).",
            file=sys.stderr,
        )
        return data.decode("utf-8", errors="replace")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="eval-unpack",
        description=(
            "Safely unpack the first eval(function(p,a,c,k,e,d){...})(...) "
            "packer occurrence without executing JavaScript"
        ),
    )
    parser.add_argument("input", help="input file path or '-' for stdin")
    parser.add_argument(
        "--beautify", action="store_true", help="beautify with jsbeautifier (optional)"
    )
    parser.add_argument(
        "--indent",
        type=_bounded_int(1, 16),
        default=2,
        help="beautify indent size, 1-16 (default: 2)",
    )
    parser.add_argument(
        "--wrap",
        type=_bounded_int(0, 10_000),
        default=0,
        help="beautify wrap length, 0-10000 (0 = no wrap)",
    )
    parser.add_argument(
        "--recursive", action="store_true", help="recursively unpack nested packers"
    )
    parser.add_argument("--debug", action="store_true", help="debug output (to stderr)")
    parser.add_argument(
        "--max-input-bytes",
        type=_bounded_int(1, 50_000_000),
        default=DEFAULT_LIMITS.max_input_bytes,
        help=f"maximum input and intermediate size (default: {DEFAULT_LIMITS.max_input_bytes})",
    )
    parser.add_argument(
        "--max-tokens",
        type=_bounded_int(1, 100_000),
        default=DEFAULT_LIMITS.max_tokens,
        help=f"maximum declared token count (default: {DEFAULT_LIMITS.max_tokens})",
    )
    parser.add_argument(
        "--max-replacements",
        type=_bounded_int(1, 1_000_000),
        default=DEFAULT_LIMITS.max_replacements,
        help=f"maximum replacements per layer (default: {DEFAULT_LIMITS.max_replacements})",
    )
    parser.add_argument(
        "--max-recursion-depth",
        type=_bounded_int(1, 100),
        default=DEFAULT_LIMITS.max_recursion_depth,
        help=f"maximum unpacked layers (default: {DEFAULT_LIMITS.max_recursion_depth})",
    )
    args = parser.parse_args()

    if args.input == "-":
        data = sys.stdin.buffer.read(args.max_input_bytes + 1)
    else:
        try:
            with open(args.input, "rb") as handle:
                data = handle.read(args.max_input_bytes + 1)
        except OSError as error:
            parser.error(f"cannot read input: {error}")

    if len(data) > args.max_input_bytes:
        parser.error(f"input size exceeds {args.max_input_bytes} bytes")
    text = _decode_input(data)
    decoded_input_bytes = len(text.encode("utf-8"))
    if decoded_input_bytes > args.max_input_bytes:
        parser.error(
            f"decoded input size exceeds {args.max_input_bytes} bytes after UTF-8 replacement"
        )
    limits = UnpackLimits(
        max_input_bytes=args.max_input_bytes,
        max_tokens=args.max_tokens,
        max_replacements=args.max_replacements,
        max_recursion_depth=args.max_recursion_depth,
        max_output_bytes=args.max_input_bytes,
    )

    try:
        output = unpack_text(
            text, recursive=args.recursive, debug=args.debug, limits=limits
        )
    except LimitExceeded as error:
        parser.error(str(error))
    if output is None:
        print("No supported packer pattern could be unpacked.", file=sys.stderr)
        raise SystemExit(1)

    output = fix_malformed_setrequestheader(output)
    if args.beautify:
        try:
            _encode_output(
                output, min(limits.max_output_bytes, _BEAUTIFY_MAX_INPUT_BYTES)
            )
        except LimitExceeded as error:
            parser.error(f"beautifier {error}")
        output = maybe_beautify(output, args.indent, args.wrap)
    try:
        encoded_output = _encode_output(
            output, limits.max_output_bytes, include_newline=True
        )
    except LimitExceeded as error:
        parser.error(str(error))
    sys.stdout.buffer.write(encoded_output)


if __name__ == "__main__":
    main()
