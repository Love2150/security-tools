# eval-unpacker

[![Eval-Unpacker CI](https://github.com/Love2150/security-tools/actions/workflows/eval-unpacker-ci.yml/badge.svg)](https://github.com/Love2150/security-tools/actions/workflows/eval-unpacker-ci.yml)

A defensive command-line tool that reconstructs classic
`eval(function(p,a,c,k,e,d){...})(...)` JavaScript packer payloads **without
executing JavaScript**.

## Installation

From the repository:

```bash
cd tools/eval-unpacker
python -m pip install .
```

Optional formatting support:

```bash
python -m pip install '.[beautify]'
```

## Usage

```bash
eval-unpack packed.js
eval-unpack packed.js --recursive --beautify
eval-unpack - < packed.js
python -m eval_unpacker.cli packed.js
```

The tool intentionally processes the **first supported packer occurrence** in
the input. With `--recursive`, it follows the first nested occurrence at each
layer. It does not evaluate unsupported JavaScript expressions.

### Safety limits

Hostile input is bounded by conservative defaults:

| Option | Default | Purpose |
|---|---:|---|
| `--max-input-bytes` | 5,000,000 | Input, output, and intermediate payload bytes |
| `--max-tokens` | 10,000 | Declared dictionary entries per layer |
| `--max-replacements` | 100,000 | Token substitutions per layer |
| `--max-recursion-depth` | 10 | Unpacked layers |

CLI overrides are bounded to prevent accidental or hostile extreme allocations: input
bytes up to 50,000,000, tokens up to 100,000, replacements up to 1,000,000,
and recursion depth up to 100. Raising defaults can increase CPU and memory use,
so only do so for trusted samples. Beautification accepts inputs up to 1,000,000
bytes and the final UTF-8 output is checked again after all post-processing.

Input is decoded as UTF-8. Invalid byte sequences are replaced with the Unicode
replacement character and a warning identifying the first invalid byte is
written to stderr; bytes are never silently discarded.

### Other options

- `--beautify`: format output with the optional `jsbeautifier` dependency
- `--indent N`: beautifier indentation, 1–16 (default: 2)
- `--wrap N`: beautifier line length, 0–10,000; 0 disables wrapping
- `--recursive`: unpack nested supported packers within the configured limit
- `--debug`: write parser details to stderr

## Supported syntax and limitations

The parser supports classic packer calls with:

- a quoted payload string;
- integer base values from 2 through 36;
- a non-negative token count;
- a quoted token dictionary followed by `.split(...)`, or a literal string array.

Malformed calls, dynamic token expressions such as function calls, and other
JavaScript packer families are rejected. For `.split('')`, dictionaries are
split using JavaScript UTF-16 code units; non-BMP surrogate units are emitted as
visible `\\uXXXX` escapes so output remains valid UTF-8. Treat unpacked output as
potentially malicious evidence: do not execute it on a production system.

## Development

```bash
python -m pip install -e . pytest coverage
pytest -q
coverage run -m pytest -q
coverage report --include='eval_unpacker/core.py' --fail-under=85
```

CI tests every Python version declared by the package (3.9 through 3.13), runs
the suite, enforces at least 85% core coverage, and smoke-tests the installed
CLI.

## Project layout

```text
tools/eval-unpacker/
├── eval_unpacker/
│   ├── __init__.py
│   ├── cli.py
│   └── core.py
├── tests/
├── LICENSE
├── pyproject.toml
└── README.md
```

## License

MIT License. See [LICENSE](LICENSE).
