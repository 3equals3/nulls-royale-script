import json
import re

with open(r'disasm_qjsc.py', encoding='utf-8') as f:
    code = f.read()

exec(code, globals())
offset_to_idx = {f['offset']: i for i, f in enumerate(all_functions)}

import sys
sys.stdout.reconfigure(encoding='utf-8')

def build_tree(idx, prefix="", is_last=True):
    f = all_functions[idx]
    branch = "\\-- " if is_last else "|-- "
    name_display = f['name']
    if name_display.startswith('atom:'):
        name_display = name_display[5:]
    if name_display in ('""', 'null', '<init>', '<eval>'):
        name_display = f"<anon_{idx}>"
        
    line = f"{prefix}{branch}[{idx:2d}] {name_display:25s} (args={f['arg_count']}, vars={f['var_count']}, closures={f['closure_var_count']}, cpool={f['cpool_count']}, bc_len={f['byte_code_len']:3d})"
    print(line)
    
    # Children in cpool that are functions
    children = []
    for ci, cp in enumerate(f['cpool']):
        if isinstance(cp, dict):
            c_idx = offset_to_idx[cp['offset']]
            children.append((ci, c_idx))
            
    new_prefix = prefix + ("    " if is_last else "|   ")
    for i, (ci, c_idx) in enumerate(children):
        build_tree(c_idx, new_prefix, i == len(children) - 1)

print("=== DEFINITION HIERARCHY (CPOOL NESTING) ===")
build_tree(36, "", True)
