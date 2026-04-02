import os
import sys
import json

py_dir = r"c:\Projects\github\speakeasy\speakeasy"
rs_dir = r"c:\Projects\github\speakeasy\rust\src"

not_ported = []
not_fully_implemented = []

for root, _, files in os.walk(py_dir):
    for f in files:
        if not f.endswith(".py"): continue
        if f in ("__init__.py", "__main__.py"): continue
        
        full_path = os.path.join(root, f)
        if "\\tests\\" in full_path or "tests.py" in f: continue
        
        rel_path = os.path.relpath(full_path, py_dir)
        rs_rel_path = rel_path.replace(".py", ".rs")
        rs_path = os.path.join(rs_dir, rs_rel_path)
        
        if not os.path.exists(rs_path):
            rs_mod_dir = os.path.join(rs_dir, rs_rel_path.replace(".rs", "\\mod.rs"))
            if os.path.exists(rs_mod_dir):
                rs_path = rs_mod_dir
            elif "api" in rel_path:
                winenv_usermode = rs_rel_path.replace("windows\\api", "winenv\\api\\usermode")
                winenv_kernel = rs_rel_path.replace("windows\\api", "winenv\\api\\kernelmode")
                if os.path.exists(os.path.join(rs_dir, winenv_usermode)):
                    rs_path = os.path.join(rs_dir, winenv_usermode)
                elif os.path.exists(os.path.join(rs_dir, winenv_kernel)):
                    rs_path = os.path.join(rs_dir, winenv_kernel)
                else:
                    not_ported.append(rel_path)
                    continue
            else:
                not_ported.append(rel_path)
                continue
                
        with open(full_path, "r", encoding="utf-8", errors="ignore") as pf:
            py_lines = len(pf.readlines())
        with open(rs_path, "r", encoding="utf-8", errors="ignore") as rf:
            rs_content = rf.read()
            rs_lines = len(rs_content.splitlines())
            
        is_stub = False
        reason = ""
        
        if "unimplemented!()" in rs_content:
            is_stub = True
            reason = "contains unimplemented!()"
        elif "fn call(&mut self" in rs_content and "{ 0 }" in rs_content.replace("\n", "").replace(" ", ""):
            is_stub = True
            reason = "stub API handler returning 0"
        elif rs_lines <= 35 and py_lines > 150:
            is_stub = True
            reason = "significantly smaller size"
            
        if is_stub:
            not_fully_implemented.append(f"{rel_path} (Python: {py_lines} lines, Rust: {rs_lines} lines) - {reason}")

res = {
    "not_ported": sorted(not_ported),
    "not_fully_implemented": sorted(not_fully_implemented)
}

with open("compare.json", "w") as jf:
    json.dump(res, jf, indent=2)
