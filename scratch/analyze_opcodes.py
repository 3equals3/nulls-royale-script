import json

with open(r'output.txt') as f:
    text = f.read()

obj = json.loads(text)
table = json.loads(obj['stdout'].strip())
print(f"Loaded {len(table)} opcode entries")

fmts = sorted(set(x['fmt'] for x in table))
for fmt in fmts:
    matching = [x for x in table if x['fmt'] == fmt]
    sizes = sorted(set(x['size'] for x in matching))
    idxs = [x['idx'] for x in matching[:5]]
    print(f"fmt {fmt:2d}: count={len(matching):2d}, sizes={sizes}, sample idxs={idxs}")
