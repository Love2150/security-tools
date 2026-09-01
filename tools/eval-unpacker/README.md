# Eval Unpacker

A defensive command-line tool that reconstructs the first classic `eval(function(p,a,c,k,e,d){...})(...)` JavaScript packer payload without executing JavaScript.

[![Repository CI](https://github.com/Love2150/security-tools/actions/workflows/repository-ci.yml/badge.svg)](https://github.com/Love2150/security-tools/actions/workflows/repository-ci.yml)

## Prerequisites

- Python 3.9 or newer
- Optional `jsbeautifier` support through the `beautify` extra

Install from the repository root:

```bash
python -m pip install ./tools/eval-unpacker
python -m pip install "./tools/eval-unpacker[beautify]"
```

## Usage

```bash
eval-unpack packed.js
eval-unpack packed.js --recursive --beautify
eval-unpack - < packed.js
python -m eval_unpacker.cli packed.js
```

The tool processes the first supported packer occurrence. With `--recursive`, it follows the first nested supported occurrence at each layer.

Options:

| Option | Default | Meaning |
| --- | ---: | --- |
| `--beautify` | off | Format with the optional `jsbeautifier` dependency |
| `--indent N` | 2 | Beautifier indentation from 1 through 16 |
| `--wrap N` | 0 | Wrap length from 0 through 10,000; 0 disables wrapping |
| `--recursive` | off | Unpack nested supported layers |
| `--debug` | off | Write parser diagnostics to standard error |
| `--max-input-bytes N` | 5,000,000 | Input, intermediate, and output byte ceiling |
| `--max-tokens N` | 10,000 | Declared dictionary entries per layer |
| `--max-replacements N` | 100,000 | Token substitutions per layer |
| `--max-recursion-depth N` | 10 | Unpacked layers |

CLI overrides are themselves bounded: 50,000,000 input bytes, 100,000 tokens, 1,000,000 replacements, and 100 layers. Beautification accepts no more than 1,000,000 input bytes.

## Output schema

Successful output is reconstructed JavaScript text written as UTF-8 to standard output with one trailing newline. The command does not create report files and does not wrap output in JSON.

Diagnostics, debug details, decoding warnings, and errors are written to standard error. Invalid UTF-8 bytes are replaced with the Unicode replacement character and the first invalid byte offset is reported; bytes are never silently discarded.

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | A supported payload was reconstructed and written successfully |
| `1` | No supported packer occurrence was found |
| `2` | Invalid arguments, unreadable input, exceeded resource limit, or invalid option range |

Unexpected interpreter or operating-system failures can also produce a non-zero status.

## Supported syntax

The parser accepts classic packer calls with:

- a quoted payload string;
- an integer base from 2 through 36;
- a non-negative token count;
- a quoted token dictionary followed by `.split(...)`, or a literal string array.

For `.split('')`, dictionary strings use JavaScript UTF-16 code units. Non-BMP surrogate units are emitted as visible `\\uXXXX` escapes so output remains valid UTF-8.

## Limitations

- Only the first supported packer occurrence is processed at each layer.
- Other JavaScript packer families and dynamic token expressions are rejected.
- Reconstruction is not proof that the recovered program is safe or complete.
- Beautification is formatting only and can change presentation.
- Recovered source may be malicious. Do not execute it on a production or trusted system.

This tool is for triage and analyst inspection, not sandboxing or malware classification.

## Development

```bash
cd tools/eval-unpacker
python -m pip install -e . pytest coverage
pytest -q
coverage run -m pytest -q
coverage report --include='eval_unpacker/core.py' --fail-under=85
```

Repository CI tests Python 3.9–3.13, enforces at least 85% core coverage, and smoke-tests the installed CLI.

## License

MIT. See the package [LICENSE](LICENSE) and repository [license](../../LICENSE).
