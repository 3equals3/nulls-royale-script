import struct
import json
import re
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

with open(r'c:\Users\User\Desktop\arm64-v8a\ida_test\frida-quickjs-opcode.h', encoding='utf-8') as f:
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

script_path = r'c:\Users\User\Desktop\arm64-v8a\ida_test\downloaded_script.qjsc'
if not os.path.exists(script_path):
    script_path = r'c:\Users\User\Desktop\arm64-v8a\downloaded_script.qjsc'
with open(script_path, 'rb') as f:
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

version = get_u8()
assert version == 2

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
assert tag == 15

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
    vidx = get_leb128()
    iname = resolve_atom(get_leb128())
    ridx = get_leb128()
    imports.append((vidx, iname, ridx))

has_tla = get_u8()

all_functions = []

def read_function():
    global pos
    func_start = pos
    tag = get_u8()
    assert tag == 14
    
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
    
    # Debug info
    if js_mode & 0x0400: # JS_MODE_HAS_DEBUG
        dbg_file = resolve_atom(get_leb128())
        dbg_line = get_leb128()
        pc2line_len = get_leb128()
        pc2line_buf = data[pos:pos+pc2line_len]
        pos += pc2line_len

    # Cpool
    cpool_offset = pos
    cpool = []
    for ci in range(cpool_count):
        cp_tag = data[pos]
        if cp_tag == 14: # Sub-function
            sub_func = read_function()
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
fn_id_by_offset = {f['offset']: i for i, f in enumerate(all_functions)}

for idx, f in enumerate(all_functions):
    f['id'] = idx

print(f"Loaded {len(all_functions)} functions.")

for f in all_functions:
    bc = f['bytecode']
    pc = 0
    insns = []
    while pc < len(bc):
        ipc = pc
        op = bc[pc]
        info = opcodes_def[op]
        name = info['name']
        size = info['size']
        fmt = info['fmt']
        operands = {}
        
        if fmt == 'u8':
            operands['val'] = bc[pc+1]
        elif fmt == 'i8':
            operands['val'] = struct.unpack_from('<b', bc, pc+1)[0]
        elif fmt == 'loc8':
            operands['loc'] = bc[pc+1]
        elif fmt == 'const8':
            cidx = bc[pc+1]
            operands['val'] = cidx
            if 'fclosure' in name:
                operands['target_fn_idx'] = fn_id_by_offset[f['cpool'][cidx]['offset']]
        elif fmt == 'label8':
            rel = struct.unpack_from('<b', bc, pc+1)[0]
            operands['target'] = pc + 2 + rel
        elif fmt == 'u16':
            operands['val'] = struct.unpack_from('<H', bc, pc+1)[0]
        elif fmt == 'i16':
            operands['val'] = struct.unpack_from('<h', bc, pc+1)[0]
        elif fmt == 'label16':
            rel = struct.unpack_from('<h', bc, pc+1)[0]
            operands['target'] = pc + 3 + rel
        elif fmt == 'npop':
            argc = struct.unpack_from('<H', bc, pc+1)[0]
            operands['argc'] = argc
            operands['count'] = argc
        elif fmt == 'loc':
            operands['loc'] = struct.unpack_from('<H', bc, pc+1)[0]
        elif fmt == 'arg':
            operands['arg'] = struct.unpack_from('<H', bc, pc+1)[0]
        elif fmt == 'var_ref':
            operands['var_ref'] = struct.unpack_from('<H', bc, pc+1)[0]
        elif fmt == 'u32':
            operands['val'] = struct.unpack_from('<I', bc, pc+1)[0]
        elif fmt == 'i32':
            operands['val'] = struct.unpack_from('<i', bc, pc+1)[0]
        elif fmt == 'const':
            cidx = struct.unpack_from('<I', bc, pc+1)[0]
            operands['val'] = cidx
            if 'fclosure' in name:
                operands['target_fn_idx'] = fn_id_by_offset[f['cpool'][cidx]['offset']]
        elif fmt == 'label':
            rel = struct.unpack_from('<i', bc, pc+1)[0]
            operands['target'] = pc + 5 + rel
        elif fmt == 'atom':
            aid = struct.unpack_from('<I', bc, pc+1)[0]
            operands['atom'] = predef_atoms[aid] if aid < len(predef_atoms) else dynamic_atoms[aid - 228]
        elif fmt == 'atom_u8':
            aid = struct.unpack_from('<I', bc, pc+1)[0]
            operands['atom'] = predef_atoms[aid] if aid < len(predef_atoms) else dynamic_atoms[aid - 228]
            operands['u8'] = bc[pc+5]
        elif fmt == 'atom_u16':
            aid = struct.unpack_from('<I', bc, pc+1)[0]
            operands['atom'] = predef_atoms[aid] if aid < len(predef_atoms) else dynamic_atoms[aid - 228]
            operands['u16'] = struct.unpack_from('<H', bc, pc+5)[0]
            
        pc += size
        insns.append({
            'pc': ipc,
            'op': op,
            'name': name,
            'size': size,
            'operands': operands,
            'fmt': fmt,
            'pop': info['pop'],
            'push': info['push'],
        })
    f['insns'] = insns


# emulate stack & build IR
def analyze_ir(f):
    insns = f['insns']
    # Track branch targets to find basic blocks
    branch_targets = set()
    branch_targets.add(0)
    for insn in insns:
        if 'target' in insn['operands']:
            branch_targets.add(insn['operands']['target'])
            
    # Symbolic execution of stack
    # Each stack element is a string expression
    # Each local variable is an expression
    stack = []
    ir_lines = []
    
    # State mapping: pc -> stack snapshot
    pc_to_stack = {}
    
    var_names = [f"loc_{i}" for i in range(f['var_count'])]
    # If vardefs exist, give real names
    if f['vardefs']:
        for i, vd in enumerate(f['vardefs']):
            if i < len(var_names):
                var_names[i] = vd[0]
                
    closure_names = [cv[0] for cv in f['closure_vars']]
    
    for insn in insns:
        pc = insn['pc']
        name = insn['name']
        ops = insn['operands']
        
        # Format stack before
        stack_before = list(stack)
        action = ""
        
        # Helpers
        def pop():
            return stack.pop() if stack else "<underflow>"
            
        def push(val):
            stack.append(val)
            
        if name == 'OP_push_i32' or name == 'OP_push_i16' or name == 'OP_push_i8':
            val = ops['val']
            push(f"{val}")
            action = f"push {val}"
        elif name == 'OP_push_const8':
            cidx = ops['val']
            val = f['cpool'][cidx]
            push(f"{val}")
            action = f"push const:{val}"
        elif name == 'OP_push_atom_value':
            at = ops['atom']
            push(f"{json.dumps(at)}")
            action = f"push {json.dumps(at)}"
        elif name == 'OP_push_0':
            push("0")
            action = "push 0"
        elif name == 'OP_push_1':
            push("1")
            action = "push 1"
        elif name == 'OP_push_2':
            push("2")
            action = "push 2"
        elif name == 'OP_push_3':
            push("3")
            action = "push 3"
        elif name == 'OP_push_4':
            push("4")
            action = "push 4"
        elif name == 'OP_push_7':
            push("7")
            action = "push 7"
        elif name == 'OP_push_true':
            push("true")
            action = "push true"
        elif name == 'OP_push_false':
            push("false")
            action = "push false"
        elif name == 'OP_null':
            push("null")
            action = "push null"
        elif name == 'OP_undefined':
            push("undefined")
            action = "push undefined"
        elif name == 'OP_push_this':
            push("this")
            action = "push this"
        elif name == 'OP_object':
            push("{}")
            action = "new Object()"
        elif name == 'OP_drop':
            v = pop()
            action = f"drop ({v})"
        elif name == 'OP_dup':
            v = stack[-1] if stack else "<underflow>"
            push(v)
            action = f"dup ({v})"
        elif name == 'OP_get_arg0':
            push("arg0")
            action = "push arg0"
        elif name == 'OP_get_arg1':
            push("arg1")
            action = "push arg1"
        elif name == 'OP_get_arg2':
            push("arg2")
            action = "push arg2"
        elif name == 'OP_get_arg3':
            push("arg3")
            action = "push arg3"
        elif name == 'OP_get_loc0':
            push(var_names[0] if len(var_names) > 0 else "loc_0")
            action = f"push {var_names[0] if len(var_names) > 0 else 'loc_0'}"
        elif name == 'OP_get_loc1':
            push(var_names[1] if len(var_names) > 1 else "loc_1")
            action = f"push {var_names[1] if len(var_names) > 1 else 'loc_1'}"
        elif name == 'OP_get_loc2':
            push(var_names[2] if len(var_names) > 2 else "loc_2")
            action = f"push {var_names[2] if len(var_names) > 2 else 'loc_2'}"
        elif name == 'OP_get_loc3':
            push(var_names[3] if len(var_names) > 3 else "loc_3")
            action = f"push {var_names[3] if len(var_names) > 3 else 'loc_3'}"
        elif name in ('OP_get_loc8', 'OP_get_loc_check'):
            li = ops['loc']
            lname = var_names[li] if li < len(var_names) else f"loc_{li}"
            push(lname)
            action = f"push {lname}"
        elif name == 'OP_put_loc0':
            v = pop()
            lname = var_names[0] if len(var_names) > 0 else "loc_0"
            action = f"{lname} = {v}"
        elif name == 'OP_put_loc1':
            v = pop()
            lname = var_names[1] if len(var_names) > 1 else "loc_1"
            action = f"{lname} = {v}"
        elif name == 'OP_put_loc2':
            v = pop()
            lname = var_names[2] if len(var_names) > 2 else "loc_2"
            action = f"{lname} = {v}"
        elif name == 'OP_put_loc3':
            v = pop()
            lname = var_names[3] if len(var_names) > 3 else "loc_3"
            action = f"{lname} = {v}"
        elif name in ('OP_put_loc8', 'OP_put_loc_check'):
            li = ops['loc']
            lname = var_names[li] if li < len(var_names) else f"loc_{li}"
            v = pop()
            action = f"{lname} = {v}"
        elif name == 'OP_set_loc_uninitialized':
            li = ops['loc']
            lname = var_names[li] if li < len(var_names) else f"loc_{li}"
            action = f"var {lname};"
        elif name == 'OP_get_var_ref0':
            cname = closure_names[0] if len(closure_names) > 0 else "closure_0"
            push(cname)
            action = f"push {cname}"
        elif name == 'OP_get_var_ref1':
            cname = closure_names[1] if len(closure_names) > 1 else "closure_1"
            push(cname)
            action = f"push {cname}"
        elif name == 'OP_get_var_ref2':
            cname = closure_names[2] if len(closure_names) > 2 else "closure_2"
            push(cname)
            action = f"push {cname}"
        elif name in ('OP_get_var_ref_check',):
            ci = ops['var_ref']
            cname = closure_names[ci] if ci < len(closure_names) else f"closure_{ci}"
            push(cname)
            action = f"push {cname}"
        elif name == 'OP_put_var_ref0':
            v = pop()
            cname = closure_names[0] if len(closure_names) > 0 else "closure_0"
            action = f"{cname} = {v}"
        elif name == 'OP_put_var_ref1':
            v = pop()
            cname = closure_names[1] if len(closure_names) > 1 else "closure_1"
            action = f"{cname} = {v}"
        elif name in ('OP_put_var_ref', 'OP_put_var_ref_check'):
            ci = ops['var_ref']
            cname = closure_names[ci] if ci < len(closure_names) else f"closure_{ci}"
            v = pop()
            action = f"{cname} = {v}"
        elif name == 'OP_set_var_ref0':
            v = stack[-1] if stack else "<underflow>"
            cname = closure_names[0] if len(closure_names) > 0 else "closure_0"
            action = f"{cname} = {v}"
        elif name == 'OP_set_var_ref1':
            v = stack[-1] if stack else "<underflow>"
            cname = closure_names[1] if len(closure_names) > 1 else "closure_1"
            action = f"{cname} = {v}"
        elif name == 'OP_get_var':
            at = ops['atom']
            push(at)
            action = f"push {at}"
        elif name == 'OP_get_field':
            obj = pop()
            at = ops['atom']
            push(f"{obj}.{at}")
            action = f"get {obj}.{at}"
        elif name == 'OP_get_field2':
            obj = pop()
            at = ops['atom']
            push(obj)
            push(f"{obj}.{at}")
            action = f"get_method {obj}.{at}"
        elif name == 'OP_put_field':
            val = pop()
            obj = pop()
            at = ops['atom']
            action = f"{obj}.{at} = {val}"
        elif name == 'OP_define_field':
            val = pop()
            obj = stack[-1] if stack else "<obj>"
            at = ops['atom']
            action = f"{obj}.{at} = {val} [define]"
        elif name == 'OP_get_array_el':
            idx_expr = pop()
            obj = pop()
            push(f"{obj}[{idx_expr}]")
            action = f"get {obj}[{idx_expr}]"
        elif name == 'OP_get_array_el2':
            idx_expr = pop()
            obj = pop()
            push(obj)
            push(f"{obj}[{idx_expr}]")
            action = f"get_method {obj}[{idx_expr}]"
        elif name == 'OP_put_array_el':
            val = pop()
            idx_expr = pop()
            obj = pop()
            action = f"{obj}[{idx_expr}] = {val}"
        elif name in ('OP_fclosure8', 'OP_fclosure'):
            target_id = ops['target_fn_idx']
            push(f"Function[{target_id}]")
            action = f"create Function[{target_id}]"
        elif name == 'OP_call0':
            fn = pop()
            push(f"{fn}()")
            action = f"call {fn}()"
        elif name == 'OP_call1':
            arg0 = pop()
            fn = pop()
            push(f"{fn}({arg0})")
            action = f"call {fn}({arg0})"
        elif name == 'OP_call2':
            arg1 = pop()
            arg0 = pop()
            fn = pop()
            push(f"{fn}({arg0}, {arg1})")
            action = f"call {fn}({arg0}, {arg1})"
        elif name == 'OP_call3':
            arg2 = pop()
            arg1 = pop()
            arg0 = pop()
            fn = pop()
            push(f"{fn}({arg0}, {arg1}, {arg2})")
            action = f"call {fn}({arg0}, {arg1}, {arg2})"
        elif name == 'OP_call_method' or name == 'OP_tail_call_method':
            argc = ops['argc']
            cargs = [pop() for _ in range(argc)][::-1]
            fn = pop()
            this_obj = pop()
            args_str = ", ".join(cargs)
            if name == 'OP_tail_call_method':
                action = f"return {fn}({args_str})"
            else:
                push(f"{fn}({args_str})")
                action = f"call {fn}({args_str})"
        elif name == 'OP_call_constructor':
            argc = ops['argc']
            cargs = [pop() for _ in range(argc)][::-1]
            new_target = pop()
            ctor = pop()
            args_str = ", ".join(cargs)
            push(f"new {ctor}({args_str})")
            action = f"new {ctor}({args_str})"
        elif name == 'OP_array_from':
            cnt = ops['count']
            elts = [pop() for _ in range(cnt)][::-1]
            push(f"[{', '.join(elts)}]")
            action = f"make array [{', '.join(elts)}]"
        elif name == 'OP_return':
            ret = pop()
            action = f"return {ret}"
        elif name == 'OP_return_undef':
            action = "return"
        elif name == 'OP_return_async':
            ret = pop()
            action = f"return async {ret}"
        elif name in ('OP_eq', 'OP_strict_eq'):
            r = pop()
            l = pop()
            op_sym = "===" if 'strict' in name else "=="
            push(f"({l} {op_sym} {r})")
            action = f"cmp ({l} {op_sym} {r})"
        elif name in ('OP_neq', 'OP_strict_neq'):
            r = pop()
            l = pop()
            op_sym = "!==" if 'strict' in name else "!="
            push(f"({l} {op_sym} {r})")
            action = f"cmp ({l} {op_sym} {r})"
        elif name == 'OP_add':
            r = pop()
            l = pop()
            push(f"({l} + {r})")
            action = f"add ({l} + {r})"
        elif name == 'OP_lnot':
            v = pop()
            push(f"(!{v})")
            action = f"lnot (!{v})"
        elif name == 'OP_typeof_is_function':
            v = pop()
            push(f"(typeof {v} === 'function')")
            action = f"is_function ({v})"
        elif name in ('OP_if_true8', 'OP_if_true'):
            cond = pop()
            tgt = ops['target']
            action = f"if ({cond}) goto {tgt:04x}"
        elif name in ('OP_if_false8', 'OP_if_false'):
            cond = pop()
            tgt = ops['target']
            action = f"if (!{cond}) goto {tgt:04x}"
        elif name in ('OP_goto8', 'OP_goto', 'OP_goto16'):
            tgt = ops['target']
            action = f"goto {tgt:04x}"
        elif name == 'OP_catch':
            tgt = ops['target']
            action = f"setup catch -> {tgt:04x}"
        elif name == 'OP_throw':
            v = pop()
            action = f"throw {v}"
        elif name == 'OP_set_name':
            action = f"set_name {ops.get('atom', '')}"
        elif name == 'OP_to_propkey2':
            action = "to_propkey"
        elif name == 'OP_for_in_start':
            v = pop()
            action = f"for..in start on {v}"
            push(f"iter({v})")
        elif name == 'OP_for_in_next':
            action = "for..in next"
            push("next_val")
        elif name == 'OP_close_loc':
            action = f"close_loc {ops['loc']}"
        else:
            action = f"{name}"
            
        ir_lines.append({
            'pc': pc,
            'mnemonic': name,
            'action': action,
            'stack_after': list(stack)
        })
    return ir_lines

output_ir_path = r'all_functions_ir.txt'
with open(output_ir_path, 'w', encoding='utf-8') as out:
    out.write("================================================================================\n")
    out.write("INTERMEDIATE REPRESENTATION (STACK / SSA IR) FOR ALL 37 FUNCTIONS\n")
    out.write("================================================================================\n\n")
    
    for idx, f in enumerate(all_functions):
        out.write(f"================================================================================\n")
        out.write(f"FUNCTION [{idx}] name={json.dumps(f['name'])} (args={f['arg_count']}, vars={f['var_count']}, closures={f['closure_var_count']}, cpool={f['cpool_count']})\n")
        if f['closure_vars']:
            cv_desc = [f"[{i}] {cv[0]} (flags=0x{cv[2]:02x})" for i, cv in enumerate(f['closure_vars'])]
            out.write(f"  Closure Vars: {', '.join(cv_desc)}\n")
        if f['vardefs']:
            vd_desc = [f"[{i}] {vd[0]}" for i, vd in enumerate(f['vardefs'])]
            out.write(f"  Var Names: {', '.join(vd_desc)}\n")
        out.write("  IR Trace (PC, Instruction, Action, Virtual Stack):\n")
        ir = analyze_ir(f)
        for step in ir:
            stack_str = " | ".join(step['stack_after'])
            out.write(f"    {step['pc']:04x}: {step['mnemonic']:25s} -> {step['action']:45s} [stack: {stack_str}]\n")
        out.write("\n")

print(f"IR successfully generated to {output_ir_path}")

