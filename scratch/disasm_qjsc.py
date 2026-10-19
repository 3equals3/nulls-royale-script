import struct
import json
import re

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

def get_u32():
    global pos
    v = struct.unpack_from('<I', data, pos)[0]
    pos += 4
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
assert version == 2, f"Expected BC_VERSION == 2, got {version}"

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

# Predefined atoms dictionary from QuickJS
PREDEFINED_ATOMS = {
    0: "null", 1: "false", 2: "true", 3: "if", 4: "else", 5: "return", 6: "var", 7: "this",
    8: "delete", 9: "void", 10: "typeof", 11: "new", 12: "in", 13: "instanceof", 14: "do",
    15: "while", 16: "for", 17: "break", 18: "continue", 19: "switch", 20: "case", 21: "default",
    22: "throw", 23: "try", 24: "catch", 25: "finally", 26: "function", 27: "debugger", 28: "with",
    29: "class", 30: "const", 31: "enum", 32: "export", 33: "extends", 34: "import", 35: "super",
    36: "implements", 37: "interface", 38: "let", 39: "package", 40: "private", 41: "protected",
    42: "public", 43: "static", 44: "yield", 45: "await", 46: "empty", 47: "length", 48: "fileName",
    49: "lineNumber", 50: "message", 51: "stack", 52: "name", 53: "toString", 54: "toLocaleString",
    55: "valueOf", 56: "eval", 57: "prototype", 58: "constructor", 59: "configurable", 60: "writable",
    61: "enumerable", 62: "value", 63: "get", 64: "set", 65: "of", 66: "__proto__", 67: "undefined",
    68: "number", 69: "boolean", 70: "string", 71: "object", 72: "symbol", 73: "integer",
    74: "unknown", 75: "arguments", 76: "callee", 77: "caller", 78: "<eval>", 79: "<ret>",
    80: "<var>", 81: "<arg_var>", 82: "<init>", 83: "<with>", 84: "<match>", 85: "<iter>",
}

def resolve_atom_raw(aid):
    if aid in PREDEFINED_ATOMS:
        return f"atom:{PREDEFINED_ATOMS[aid]}"
    if aid < 228:
        return f"atom:<predef_{aid}>"
    idx = aid - 228
    if idx < len(atoms):
        return f"atom:{json.dumps(atoms[idx])}"
    return f"atom:<err_{aid}>"

def resolve_atom(v):
    if v & 1:
        return f"[int {v >> 1}]"
    return resolve_atom_raw(v >> 1)

tag = get_u8()
assert tag == 15, f"Expected BC_TAG_MODULE (15), got {tag}"

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
    exports.append((etype, lidx, ridx, ename))

star_export_count = get_leb128()
star_exports = [get_leb128() for _ in range(star_export_count)]

import_count = get_leb128()
imports = []
for _ in range(import_count):
    vidx = get_leb128()
    iname = resolve_atom(get_leb128())
    ridx = get_leb128()
    imports.append((vidx, iname, ridx))

has_tla = get_u8()

all_functions = []

def parse_function(func_name_override=None):
    global pos
    func_start_offset = pos
    ftag = get_u8()
    assert ftag == 14, f"Expected BC_TAG_FUNCTION_BYTECODE (14) at {func_start_offset}, got {ftag}"
    
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
    
    raw_name = resolve_atom(name_atom)
    func_name = raw_name
    if func_name_override and raw_name in ('atom:<init>', 'atom:""', 'atom:"<eval>"'):
        func_name = func_name_override

    # Vardefs
    vardefs = []
    for _ in range(vardefs_count):
        vname = resolve_atom(get_leb128())
        slevel = get_leb128()
        snext = get_leb128()
        vflags = get_u8()
        vardefs.append((vname, slevel, snext, vflags))

    # Closure vars
    closure_vars = []
    for _ in range(closure_var_count):
        cvname = resolve_atom(get_leb128())
        cvidx = get_leb128()
        cvflags = get_u8()
        closure_vars.append((cvname, cvidx, cvflags))

    # Bytecode
    bytecode_offset = pos
    bytecode_raw = data[pos:pos+byte_code_len]
    pos += byte_code_len

    # Debug info
    debug_info = None
    if js_mode & 0x0400: # JS_MODE_HAS_DEBUG
        dbg_file = resolve_atom(get_leb128())
        dbg_line = get_leb128()
        pc2line_len = get_leb128()
        pc2line_buf = data[pos:pos+pc2line_len]
        pos += pc2line_len
        debug_info = (dbg_file, dbg_line, pc2line_len)

    # Cpool
    cpool_offset = pos
    cpool = []
    for ci in range(cpool_count):
        cp_tag = data[pos]
        if cp_tag == 14: # Sub-function
            sub_func = parse_function(f"sub_{ci}_of_{func_name}")
            cpool.append(sub_func)
        elif cp_tag == 7: # String
            pos += 1
            v = get_leb128()
            is_w = (v & 1)
            sl = v >> 1
            if is_w:
                st = data[pos:pos+sl*2].decode('utf-16le', errors='replace')
                pos += sl*2
            else:
                st = data[pos:pos+sl].decode('utf-8', errors='replace')
                pos += sl
            cpool.append(st)
        elif cp_tag == 6: # Float64
            pos += 1
            fval = struct.unpack_from('<d', data, pos)[0]
            pos += 8
            cpool.append(fval)
        elif cp_tag == 5: # Int32
            pos += 1
            ival = struct.unpack_from('<i', data, pos)[0]
            pos += 4
            cpool.append(ival)
        elif cp_tag == 10: # BigInt
            pos += 1
            blen = get_leb128()
            bbytes = data[pos:pos+blen]
            pos += blen
            cpool.append(f"<bigint len={blen}>")
        else:
            raise ValueError(f"Unknown cpool tag {cp_tag} at {pos}")

    func_obj = {
        'offset': func_start_offset,
        'name': func_name,
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
        'vardefs': vardefs,
        'closure_vars': closure_vars,
        'debug_info': debug_info,
        'bytecode': bytecode_raw,
        'cpool': cpool
    }
    all_functions.append(func_obj)
    return func_obj

root_func = parse_function("<root_module>")

def disasm_function(f):
    bc = f['bytecode']
    pc = 0
    lines = []
    while pc < len(bc):
        start_pc = pc
        op = bc[pc]
        odefp = opcodes_def[op]
        name = odefp['name']
        fmt = odefp['fmt']
        size = odefp['size']
        
        operands = ''
        if fmt in ('none', 'none_int', 'none_loc', 'none_arg', 'none_var_ref', 'npopx'):
            operands = ''
        elif fmt == 'u8':
            operands = f"{bc[pc+1]}"
        elif fmt == 'i8':
            val = struct.unpack_from('<b', bc, pc+1)[0]
            operands = f"{val}"
        elif fmt == 'loc8':
            operands = f"loc_{bc[pc+1]}"
        elif fmt == 'const8':
            cidx = bc[pc+1]
            cval = f['cpool'][cidx] if cidx < len(f['cpool']) else '?'
            if isinstance(cval, dict):
                cval = f"<func {cval['name']}>"
            elif isinstance(cval, str):
                cval = json.dumps(cval)
            operands = f"cpool[{cidx}] ({cval})"
        elif fmt == 'label8':
            rel = struct.unpack_from('<b', bc, pc+1)[0]
            target = pc + 2 + rel
            operands = f"{target:04x} (offset {rel:+d})"
        elif fmt == 'u16':
            val = struct.unpack_from('<H', bc, pc+1)[0]
            operands = f"{val}"
        elif fmt == 'i16':
            val = struct.unpack_from('<h', bc, pc+1)[0]
            operands = f"{val}"
        elif fmt == 'label16':
            rel = struct.unpack_from('<h', bc, pc+1)[0]
            target = pc + 3 + rel
            operands = f"{target:04x} (offset {rel:+d})"
        elif fmt == 'npop':
            argc = struct.unpack_from('<H', bc, pc+1)[0]
            operands = f"argc={argc}"
        elif fmt == 'loc':
            val = struct.unpack_from('<H', bc, pc+1)[0]
            operands = f"loc_{val}"
        elif fmt == 'arg':
            val = struct.unpack_from('<H', bc, pc+1)[0]
            operands = f"arg_{val}"
        elif fmt == 'var_ref':
            val = struct.unpack_from('<H', bc, pc+1)[0]
            vdesc = f"var_ref_{val}"
            if val < len(f['closure_vars']):
                cv = f['closure_vars'][val]
                vdesc += f" ({cv[0]})"
            operands = vdesc
        elif fmt == 'u32':
            val = struct.unpack_from('<I', bc, pc+1)[0]
            operands = f"{val}"
        elif fmt == 'i32':
            val = struct.unpack_from('<i', bc, pc+1)[0]
            operands = f"{val}"
        elif fmt == 'const':
            cidx = struct.unpack_from('<I', bc, pc+1)[0]
            cval = f['cpool'][cidx] if cidx < len(f['cpool']) else '?'
            if isinstance(cval, dict):
                cval = f"<func {cval['name']}>"
            elif isinstance(cval, str):
                cval = json.dumps(cval)
            operands = f"cpool[{cidx}] ({cval})"
        elif fmt == 'label':
            rel = struct.unpack_from('<i', bc, pc+1)[0]
            target = pc + 5 + rel
            operands = f"{target:04x} (offset {rel:+d})"
        elif fmt == 'atom':
            aid = struct.unpack_from('<I', bc, pc+1)[0]
            operands = resolve_atom_raw(aid)
        elif fmt == 'atom_u8':
            aid = struct.unpack_from('<I', bc, pc+1)[0]
            u8 = bc[pc+5]
            operands = f"{resolve_atom_raw(aid)}, {u8}"
        elif fmt == 'atom_u16':
            aid = struct.unpack_from('<I', bc, pc+1)[0]
            u16 = struct.unpack_from('<H', bc, pc+5)[0]
            operands = f"{resolve_atom_raw(aid)}, {u16}"
        else:
            operands = f"raw={bc[pc+1:pc+size].hex()}"
            
        lines.append(f"{start_pc:04x}: {name:20s} {operands}".rstrip())
        pc += size
    return lines


output_path = r'disassembly_output.txt'
with open(output_path, 'w', encoding='utf-8') as out:
    out.write(f"MODULE: {module_name}\n")
    out.write(f"Total functions: {len(all_functions)}\n\n")
    for idx, f in enumerate(all_functions):
        out.write(f"================================================================================\n")
        out.write(f"FUNCTION [{idx}] {f['name']}\n")
        out.write(f"  file offset:        {f['offset']} (0x{f['offset']:04x})\n")
        out.write(f"  js_mode:            0x{f['js_mode']:04x}\n")
        out.write(f"  has_prototype:      {f['has_prototype']}\n")
        out.write(f"  arg_count:          {f['arg_count']}\n")
        out.write(f"  var_count:          {f['var_count']}\n")
        out.write(f"  defined_arg_count:  {f['defined_arg_count']}\n")
        out.write(f"  stack_size:         {f['stack_size']}\n")
        out.write(f"  closure_var_count:  {f['closure_var_count']}\n")
        out.write(f"  cpool_count:        {f['cpool_count']}\n")
        out.write(f"  byte_code_len:      {f['byte_code_len']}\n")
        out.write(f"  bytecode offset:    {f['bytecode_offset']} (0x{f['bytecode_offset']:04x})\n")
        out.write(f"  cpool offset:       {f['cpool_offset']} (0x{f['cpool_offset']:04x})\n")
        if f['closure_vars']:
            out.write("  closure_vars:\n")
            for cvi, cv in enumerate(f['closure_vars']):
                out.write(f"    [{cvi}] {cv[0]} (var_idx={cv[1]}, flags=0x{cv[2]:02x})\n")
        if f['cpool']:
            out.write("  cpool entries:\n")
            for cpi, cpv in enumerate(f['cpool']):
                if isinstance(cpv, dict):
                    out.write(f"    [{cpi}] <func {cpv['name']} at offset 0x{cpv['offset']:04x}>\n")
                elif isinstance(cpv, str):
                    out.write(f"    [{cpi}] (str) {json.dumps(cpv[:60])}\n")
                else:
                    out.write(f"    [{cpi}] ({type(cpv).__name__}) {cpv}\n")
        out.write("  bytecode disassembly:\n")
        for line in disasm_function(f):
            out.write(f"    {line}\n")
        out.write("\n")

print(f"Disassembled all {len(all_functions)} functions to scratch/disassembly_output.txt")
