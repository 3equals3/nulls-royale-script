import struct
import json
import re

# Load opcode definitions from frida-quickjs-opcode.h
with open('frida-quickjs-opcode.h', encoding='utf-8') as f:
    lines = f.readlines()

opcodes_def = []
for line in lines:
    m = re.match(r'\s*DEF\s*\(\s*(\w+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\w+)\s*\)', line)
    if m:
        name, size, n_pop, n_push, fmt = m.groups()
        opcodes_def.append({
            'name': 'OP_' + name,
            'size': int(size),
            'pop': int(n_pop),
            'push': int(n_push),
            'fmt': fmt
        })

with open('downloaded_script.qjsc', 'rb') as f:
    data = f.read()

pos = 0

def get_u8():
    global pos
    b = data[pos]
    pos += 1
    return b

def get_u16():
    global pos
    v = struct.unpack_from('<H', data, pos)[0]
    pos += 2
    return v

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
atoms = []
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
    atoms.append(s)

tag = get_u8()
module_name_idx = get_leb128()
req_count = get_leb128()
for _ in range(req_count):
    get_leb128()
exp_count = get_leb128()
for _ in range(exp_count):
    etype = get_u8()
    get_leb128()
    if etype:
        get_leb128()
    get_leb128()
star_count = get_leb128()
for _ in range(star_count):
    get_leb128()
imp_count = get_leb128()
for _ in range(imp_count):
    get_leb128()
    get_leb128()
    get_leb128()
has_tla = get_u8()

all_functions = []

def parse_func():
    global pos
    start_offset = pos
    tag = get_u8()
    assert tag == 14
    
    js_mode = get_u16()
    has_prototype = get_u8()
    name_atom = get_leb128()
    arg_count = get_leb128()
    var_count = get_leb128()
    defined_arg_count = get_leb128()
    stack_size = get_leb128()
    closure_var_count = get_leb128()
    cpool_count = get_leb128()
    byte_code_len = get_leb128()
    vardefs_count = get_leb128()
    
    header_end = pos
    
    # vardefs
    for _ in range(vardefs_count):
        get_leb128()
        get_leb128()
        get_leb128()
        get_u8()
    vardefs_end = pos
    
    # closure vars
    for _ in range(closure_var_count):
        get_leb128()
        get_leb128()
        get_u8()
    closures_end = pos
    
    bytecode_offset = pos
    bytecode = data[pos:pos+byte_code_len]
    pos += byte_code_len
    bytecode_end = pos
    
    # debug info
    if js_mode & 0x0400:
        get_leb128()
        get_leb128()
        pc2line_len = get_leb128()
        pos += pc2line_len
    debug_end = pos
    
    cpool_offset = pos
    cpool_entries = []
    for ci in range(cpool_count):
        cptag = data[pos]
        cp_start = pos
        if cptag == 14:
            subf = parse_func()
            cpool_entries.append(('func', cp_start, pos, subf))
        elif cptag == 7: # string
            pos += 1
            v = get_leb128()
            sl = (v >> 1) * (2 if (v & 1) else 1)
            pos += sl
            cpool_entries.append(('string', cp_start, pos, None))
        elif cptag == 6: # float64
            pos += 9
            cpool_entries.append(('float64', cp_start, pos, None))
        elif cptag == 5: # int32
            pos += 5
            cpool_entries.append(('int32', cp_start, pos, None))
        else:
            raise ValueError(f"Unknown cptag {cptag} at {pos}")
            
    total_end = pos
    
    info = {
        'id': len(all_functions),
        'start': start_offset,
        'header_end': header_end,
        'vardefs_end': vardefs_end,
        'closures_end': closures_end,
        'bc_offset': bytecode_offset,
        'bc_len': byte_code_len,
        'bc_end': bytecode_end,
        'debug_end': debug_end,
        'cp_offset': cpool_offset,
        'cp_count': cpool_count,
        'total_end': total_end,
        'bytecode': bytecode,
        'cpool_entries': cpool_entries
    }
    all_functions.append(info)
    return info

root = parse_func()
print(f"Total parsed: {len(all_functions)} functions")
print(f"File size: {len(data)}, pos after parsing: {pos}")
assert pos == len(data), "File not consumed completely!"

# Verify instructions for each function
instruction_stats = []
for f in all_functions:
    bc = f['bytecode']
    pc = 0
    f_insns = []
    while pc < len(bc):
        start_pc = pc
        op = bc[pc]
        int_op = op if op <= 181 else op + 19
        odefp = opcodes_def[op]
        name = odefp['name']
        size = odefp['size']
        fmt = odefp['fmt']
        
        # Check boundary
        next_pc = pc + size
        assert next_pc <= len(bc), f"Function {f['id']} at {start_pc}: op {op} size {size} exceeds bytecode len {len(bc)}!"
        
        f_insns.append({
            'pc': start_pc,
            'op': op,
            'int_op': int_op,
            'mnemonic': name,
            'size': size,
            'fmt': fmt,
            'raw': bc[pc:next_pc].hex()
        })
        pc = next_pc
        
    assert pc == len(bc), f"Function {f['id']} last insn ended at {pc}, but bc_len is {len(bc)}!"
    instruction_stats.append(len(f_insns))

print(f"Instruction verification passed for ALL {len(all_functions)} functions!")
print(f"Total instructions across all functions: {sum(instruction_stats)}")
