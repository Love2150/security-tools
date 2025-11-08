# eval-unpacker  
![Eval-Unpacker CI](https://github.com/Love2150/security-tools/actions/workflows/eval-unpacker-ci.yml/badge.svg)

A robust Python tool to automatically unpack obfuscated JavaScript built with `eval(function(p,a,c,k,e,d){...})(...)` packers.

---

## Overview
`eval-unpacker` is a command-line tool for analysts, malware researchers, and reverse engineers who need to deobfuscate JavaScript payloads packed with the classic `eval(function(p,a,c,k,e,d){...})(...)` pattern.

It safely reconstructs the original code while avoiding cascading substitutions, and includes optional beautification for readability.

---

## Features
- Detects and extracts `eval(function(...))` packer calls
- Two-pass token replacement prevents mis-substitution
- Handles empty tokens gracefully
- Optional `--beautify` output using `jsbeautifier`
- Recursive unpacking with `--recursive`
- Heuristic fix for malformed `setRequestHeader` arguments
- Tested via GitHub Actions (Python 3.9–3.11)

---

## Installation

### Local install
```bash
pip install .

With optional beautifier
pip install .[beautify]

Development mode
pip install -e .[beautify]

Usage
Unpack a file
eval-unpack packed.js --beautify --recursive

From standard input
cat packed.js | eval-unpack -

On Windows PowerShell
pip install -e .[beautify]
eval-unpack .\packed.js --beautify --recursive
Get-Content .\packed.js | eval-unpack -


If eval-unpack isn’t recognized, make sure Python Scripts is on your PATH, or use:

python -m eval_unpacker.cli .\packed.js --beautify --recursive

Example

Input:

eval(function(p,a,c,k,e,d){return p}('abc',10,2,'a|b'))


Output:

abc

Command-line Options
Option	Description
--beautify	Beautify output using jsbeautifier
--indent <n>	Indentation size (default: 2)
--wrap <n>	Line wrap length (default: 0)
--recursive	Unpack nested eval(function(...)) layers
--debug	Show debug details
Example Screenshot

Example terminal output:

(Optional: save a screenshot of your terminal after unpacking and upload it to /docs.)

CI Workflow

GitHub Actions automatically tests:

Package install

CLI availability

Basic unpacking output

Optional pytest tests

Contributing

Contributions are welcome!

Fork the repository

Clone your fork

Create a new branch

Test your changes

Commit and open a pull request

Example:

git clone https://github.com/YOUR-USERNAME/security-tools.git
cd tools/eval-unpacker
git checkout -b feature/new-parser
pytest -q
git commit -am "Improve token parser"
git push origin feature/new-parser

Project Structure
tools/eval-unpacker/
├── eval_unpacker/
│   ├── __init__.py
│   ├── cli.py
│   └── core.py
├── tests/
│   └── test_basic.py
├── pyproject.toml
└── README.md

License

MIT License © 2025 Brandon Love

Author

Brandon Love
Cybersecurity Engineer • Blue-Team Analyst • DFIR Automation Builder
GitHub: https://github.com/Love2150

LinkedIn: https://www.linkedin.com/in/brandon-love-85b247261

“Security through clarity — unpack, analyze, and understand the code behind the chaos.”
