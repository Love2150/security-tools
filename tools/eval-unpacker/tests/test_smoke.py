# tests/test_smoke.py
from eval_unpacker.core import find_eval_function_calls

def test_detects_packer_call():
    js = "eval(function(p,a,c,k,e,d){return p}('abc',10,2,'a|b'))"
    matches = find_eval_function_calls(js)
    assert len(matches) == 1
