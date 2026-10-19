import sys

with open('downloaded_script.qjsc', 'rb') as f:
    data = f.read()

pos = 0
def get_u8():
    global pos
    b = data[pos]
    pos += 1
    return b

def get_leb128():
    global pos
    val = 0
    shift = 0
    while True:
        b = data[pos]
        pos += 1
        val |= (b & 0x7f) << shift
        if (b & 0x80) == 0:
            break
        shift += 7
    return val

version = get_u8()
atom_count = get_leb128()
print(f'Version: {version}, Atom count: {atom_count}')

atoms = []
for i in range(atom_count):
    v = get_leb128()
    is_wide = (v & 1)
    strlen = v >> 1
    if is_wide:
        s = data[pos:pos+strlen*2].decode('utf-16le', errors='replace')
        pos += strlen*2
    else:
        s = data[pos:pos+strlen].decode('utf-8', errors='replace')
        pos += strlen
    atoms.append(s)

def get_atom():
    v = get_leb128()
    if (v & 1):
        return f"[int {v >> 1}]"
    idx = v >> 1
    if idx < 228:
        return f"[predefined_atom_{idx}]"
    return atoms[idx - 228]

print(f'Parsed {len(atoms)} atoms. Current offset: {pos}')
tag = get_u8()
print(f'Root tag: {tag} (0x{tag:02x})')

module_name = get_atom()
print(f'Module name: "{module_name}"')

req_module_count = get_leb128()
print(f'req_module_count: {req_module_count}')
for i in range(req_module_count):
    req_name = get_atom()
    print(f'  req_module[{i}]: "{req_name}"')

export_count = get_leb128()
print(f'export_count: {export_count}')
for i in range(export_count):
    exp_type = get_u8()
    local_idx = get_leb128()
    if exp_type:
        req_idx = get_leb128()
    exp_name = get_atom()
    print(f'  export[{i}]: type={exp_type}, local_idx={local_idx}, name="{exp_name}"')

star_export_count = get_leb128()
print(f'star_export_count: {star_export_count}')
for i in range(star_export_count):
    req_idx = get_leb128()
    print(f'  star_export[{i}]: req_idx={req_idx}')

import_count = get_leb128()
print(f'import_count: {import_count}')
for i in range(import_count):
    var_idx = get_leb128()
    imp_name = get_atom()
    req_idx = get_leb128()
    print(f'  import[{i}]: var_idx={var_idx}, name="{imp_name}", req_idx={req_idx}')

has_tla = get_u8()
print(f'has_tla: {has_tla}, pos={pos}')
func_tag = get_u8()
print(f'func_tag: {func_tag} (0x{func_tag:02x})')

# Parse function bytecode (0x0e)
js_mode = get_u8() | (get_u8() << 8)
has_prototype = get_u8()
func_name = get_atom()
arg_count = get_leb128()
var_count = get_leb128()
defined_arg_count = get_leb128()
stack_size = get_leb128()
closure_var_count = get_leb128()
cpool_count = get_leb128()
byte_code_len = get_leb128()

print(f'''Function:
  js_mode: 0x{js_mode:04x}
  has_prototype: {has_prototype}
  name: "{func_name}"
  arg_count: {arg_count}
  var_count: {var_count}
  defined_arg_count: {defined_arg_count}
  stack_size: {stack_size}
  closure_var_count: {closure_var_count}
  cpool_count: {cpool_count}
  byte_code_len: {byte_code_len}
''')

