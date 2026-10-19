import json
import struct
import os

with open('c:/Users/User/Desktop/arm64-v8a/libwildcat.so', 'rb') as f:
    so_data = f.read()

idx = 0x3abff6
curr = idx
predef_atoms = ['<null_0>']
for i in range(1, 228):
    end = so_data.find(b'\x00', curr)
    s = so_data[curr:end].decode('latin1')
    predef_atoms.append(s)
    curr = end + 1

opcodes = {}
with open(r'c:\Users\User\Desktop\arm64-v8a\ida_test\frida-quickjs-opcode.h', 'r') as f:
    for line in f:
        line = line.strip()
        if line.startswith('DEF('):
            m = line[4:-1].split(',')
            if len(m) >= 4:
                op_id = int(m[1].strip())
                op_name = m[0].strip()
                size = int(m[2].strip())
                n_pop = int(m[3].strip())
                n_push = int(m[4].strip())
                opcodes[op_id] = {
                    'name': op_name,
                    'size': size,
                    'n_pop': n_pop,
                    'n_push': n_push,
                }

with open(r'c:\Users\User\Desktop\arm64-v8a\downloaded_script.qjsc', 'rb') as f:
    data = f.read()

pos = 0

def get_u8():
    global pos
    b = data[pos]
    pos += 1
    return b

def get_leb128():
    global pos
    res = 0
    shift = 0
    while True:
        b = data[pos]
        pos += 1
        res |= (b & 0x7f) << shift
        if (b & 0x80) == 0:
            break
        shift += 7
    return res

def get_sleb128():
    global pos
    res = 0
    shift = 0
    while True:
        b = data[pos]
        pos += 1
        res |= (b & 0x7f) << shift
        shift += 7
        if (b & 0x80) == 0:
            if shift < 32 and (b & 0x40) != 0:
                res |= (~0 << shift)
            break
    return res

atom_count = get_leb128()
dynamic_atoms = []
for i in range(atom_count):
    v = get_leb128()
    is_wide = (v & 1)
    slen = v >> 1
    if is_wide:
        s = data[pos:pos+slen*2].decode('utf-16le', errors='replace')
        pos += slen*2
    else:
        s = data[pos:pos+slen].decode('utf-8', errors='replace')
        pos += slen
    dynamic_atoms.append(s)

def resolve_atom(v):
    if v & 1:
        return f"[int {v >> 1}]"
    aid = v >> 1
    if aid < len(predef_atoms):
        return predef_atoms[aid]
    idx = aid - 228
    if 0 <= idx < len(dynamic_atoms):
        return dynamic_atoms[idx]
    return f"<err_atom_{aid}>"

tag = get_u8()
assert tag == 15 # MODULE

module_name = resolve_atom(get_leb128())
req_module_count = get_leb128()
req_modules = [resolve_atom(get_leb128()) for _ in range(req_module_count)]

export_count = get_leb128()
exports = []
for _ in range(export_count):
    etype = get_u8()
    lidx = get_leb128()
    ridx = get_leb128() if etype else None
    ename = resolve_atom(get_leb128())
    exports.append({'type': etype, 'lidx': lidx, 'ridx': ridx, 'name': ename})

star_export_count = get_leb128()
star_exports = [get_leb128() for _ in range(star_export_count)]
import_count = get_leb128()
imports = []
for _ in range(import_count):
    imports.append({'var_name': resolve_atom(get_leb128()), 'req_idx': get_leb128(), 'entry_name': resolve_atom(get_leb128())})

all_functions = []

def read_function():
    global pos
    func_start = pos
    tag = get_u8()
    assert tag == 14, f"Expected 14, got {tag} at pos {pos-1}"
    
    js_mode = struct.unpack('<H', data[pos:pos+2])[0]; pos += 2
    has_prototype = get_u8()
    name = resolve_atom(get_leb128())
    arg_count = get_leb128()
    var_count = get_leb128()
    defined_arg_count = get_leb128()
    stack_size = get_leb128()
    closure_var_count = get_leb128()
    cpool_count = get_leb128()
    byte_code_len = get_leb128()
    vardefs_count = get_leb128()
    
    vardefs = []
    for _ in range(vardefs_count):
        vname = resolve_atom(get_leb128())
        scope_level = get_leb128()
        scope_next = get_sleb128()
        vflags = get_u8()
        vardefs.append((vname, scope_level, scope_next, vflags))
        
    closure_vars = []
    for _ in range(closure_var_count):
        cname = resolve_atom(get_leb128())
        var_idx = get_leb128()
        var_flags = get_u8()
        closure_vars.append((cname, var_idx, var_flags))
        
    bytecode_offset = pos
    bytecode = data[pos:pos+byte_code_len]
    pos += byte_code_len
    
    # skip debug info
    if js_mode & 0x20:
        dbg_len = get_leb128()
        pos += dbg_len
        
    cpool_offset = pos
    cpool = []
    for _ in range(cpool_count):
        cp_tag = get_u8()
        if cp_tag == 14:
            pos -= 1
            fn = read_function()
            cpool.append(fn)
        elif cp_tag == 1:
            val = struct.unpack('<i', data[pos:pos+4])[0]; pos += 4
            cpool.append(val)
        elif cp_tag == 6:
            val = struct.unpack('<d', data[pos:pos+8])[0]; pos += 8
            cpool.append(val)
        elif cp_tag == 7:
            slen = get_leb128()
            s = data[pos:pos+slen].decode('utf-8', errors='replace'); pos += slen
            cpool.append(s)
        else:
            raise ValueError(f"Unknown cpool tag {cp_tag}")
            
    f_dict = {
        'offset': func_start,
        'name': name,
        'js_mode': js_mode,
        'has_prototype': has_prototype,
        'arg_count': arg_count,
        'var_count': var_count,
        'defined_arg_count': defined_arg_count,
        'stack_size': stack_size,
        'closure_var_count': closure_var_count,
        'cpool_count': cpool_count,
        'byte_code_len': byte_code_len,
        'bytecode_offset': bytecode_offset,
        'cpool_offset': cpool_offset,
        'closure_vars': closure_vars,
        'vardefs': vardefs,
        'cpool': cpool,
        'bytecode': bytecode,
    }
    all_functions.append(f_dict)
    return f_dict

root_func = read_function()

# мap offsets to function IDs 0..36
fn_id_by_offset = {f['offset']: i for i, f in enumerate(all_functions)}

print(f"Loaded {len(all_functions)} functions. Root is [{fn_id_by_offset[root_func['offset']]}]")

# вecode instructions for each function
def decode_insns(f):
    bc = f['bytecode']
    pc = 0
    insns = []
    while pc < len(bc):
        ipc = pc
        op = bc[pc]
        pc += 1
        iop = op if op <= 181 else op + 19
        info = opcodes.get(iop, {'name': f'OP_UNKNOWN_{op}', 'size': 1, 'n_pop': 0, 'n_push': 0})
        name = info['name']
        size = info['size']
        operands = {}
        
        # Parse operands
        if 'atom' in name:
            atom_id = struct.unpack('<I', bc[pc:pc+4])[0]
            operands['atom'] = resolve_atom(atom_id << 1)
        elif name in ('OP_push_i32',):
            val = struct.unpack('<i', bc[pc:pc+4])[0]
            operands['val'] = val
        elif name in ('OP_push_i16',):
            val = struct.unpack('<h', bc[pc:pc+2])[0]
            operands['val'] = val
        elif name in ('OP_push_i8', 'OP_push_const8', 'OP_fclosure8'):
            val = bc[pc]
            operands['val'] = val
            if name == 'OP_fclosure8':
                operands['target_fn_idx'] = fn_id_by_offset[f['cpool'][val]['offset']]
        elif name in ('OP_fclosure',):
            val = struct.unpack('<I', bc[pc:pc+4])[0]
            operands['val'] = val
            operands['target_fn_idx'] = fn_id_by_offset[f['cpool'][val]['offset']]
        elif name in ('OP_get_loc8', 'OP_put_loc8', 'OP_set_loc_uninitialized', 'OP_put_loc_check', 'OP_get_loc_check', 'OP_close_loc'):
            operands['loc'] = bc[pc]
        elif name in ('OP_get_var_ref_check', 'OP_put_var_ref_check', 'OP_put_var_ref'):
            operands['var_ref'] = bc[pc]
        elif name in ('OP_call_method', 'OP_call_constructor', 'OP_tail_call_method'):
            operands['argc'] = bc[pc]
        elif name in ('OP_call',):
            operands['argc'] = struct.unpack('<H', bc[pc:pc+2])[0]
        elif name in ('OP_array_from',):
            operands['count'] = struct.unpack('<H', bc[pc:pc+2])[0]
        elif name in ('OP_if_true8', 'OP_if_false8', 'OP_goto8'):
            diff = struct.unpack('<b', bc[pc:pc+1])[0]
            operands['target'] = pc + 1 + diff
        elif name in ('OP_if_true', 'OP_if_false', 'OP_goto'):
            diff = struct.unpack('<i', bc[pc:pc+4])[0]
            operands['target'] = pc + 4 + diff
        elif name in ('OP_goto16',):
            diff = struct.unpack('<h', bc[pc:pc+2])[0]
            operands['target'] = pc + 2 + diff
        elif name in ('OP_catch',):
            diff = struct.unpack('<i', bc[pc:pc+4])[0]
            operands['target'] = pc + 4 + diff
            
        pc = ipc + size
        insns.append({
            'pc': ipc,
            'op': op,
            'iop': iop,
            'name': name,
            'size': size,
            'operands': operands,
            'n_pop': info['n_pop'],
            'n_push': info['n_push'],
        })
    return insns

for f in all_functions:
    f['insns'] = decode_insns(f)

print("Decoded all instructions.")
