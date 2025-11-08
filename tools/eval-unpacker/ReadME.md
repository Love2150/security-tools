# eval-unpacker

Robust unpacker for `eval(function(p,a,c,k,e,d){...})(...)` JavaScript packers.

## Install (local)
```bash
pip install .
# or with beautifier support
pip install .[beautify]
Run locally (macOS/Linux/WSL/PowerShell)

Install the tool (from your project folder):

pip install -e .[beautify]


Run on a packed file:

eval-unpack packed.js --beautify --recursive


Or pipe from stdin:

cat packed.js | eval-unpack -

Windows tips

PowerShell:

pip install -e .[beautify]
eval-unpack .\packed.js --beautify --recursive
Get-Content .\packed.js | eval-unpack -


If eval-unpack isn’t found, your Python Scripts folder may not be on PATH. Try:

python -m eval_unpacker.cli .\packed.js --beautify --recursive
Features

Finds eval(function(...)) packer calls (paren/brace-aware)

Extracts p, a, c, k arguments and performs safe two-pass token replacement

Handles empty tokens by falling back to the token text

Optional --beautify (jsbeautifier)

--recursive nested unpacking

Heuristic fix for malformed setRequestHeader("Name: value", "val")
