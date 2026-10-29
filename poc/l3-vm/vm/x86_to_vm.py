"""L3 翻译器: 选定函数的 x86 算术指令 → VM 字节码 (vm.c 执行)。

现支持子集: mov/add/sub/imul/xor/and/or (reg,reg 或 reg,imm) + lea(base+index*scale+disp)
+ shl/shr(reg,imm) + ret。遇不支持指令抛异常(=该函数暂不能虚拟化, 回落 L1/L2)。
对拍纪律: 产物 bytecode 必须 VM 执行结果==原生 (vm_test.c)。
"""
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM

OP = dict(MOV=1, MOVI=2, ADD=3, SUB=4, IMUL=5, IMULI=6, ADDI=7,
          XOR=8, AND=9, OR=10, SHLI=11, SHRI=12, LEA=13,
          CMP=14, CMPI=15, TEST=16, JMP=17, JCC=18,
          SUBI=19, ANDI=20, ORI=21, XORI=22, CMOV=23,
          NEG=24, NOT=25, SARI=26, SHL=27, SHR=28, SAR=29, MOVZX=30, MOVSX=31,
          RET=0xFF)
_SZ = {}   # 子寄存器名 → 字节数 (movzx/movsx 源)
for nm in ("al", "bl", "cl", "dl", "sil", "dil", "bpl", "spl"):
    _SZ[nm] = 1
for i in range(8, 16):
    _SZ[f"r{i}b"] = 1
    _SZ[f"r{i}w"] = 2
for nm in ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp"):
    _SZ[nm] = 2
# cmovCC → 条件码
CMOVCC = {f"cmov{k[1:]}": v for k, v in {
    "je": 0, "jz": 0, "jne": 1, "jnz": 1, "jl": 2, "jge": 3, "jg": 4,
    "jle": 5, "jb": 6, "jae": 7, "ja": 8, "jbe": 9}.items()}
# x86 条件跳转 → JCC 条件码 (E NE L GE G LE B AE A BE)
CC = dict(je=0, jz=0, jne=1, jnz=1, jl=2, jnge=2, jge=3, jnl=3,
          jg=4, jnle=4, jle=5, jng=5, jb=6, jc=6, jnae=6,
          jae=7, jnc=7, jnb=7, ja=8, jnbe=8, jbe=9, jna=9)

# x86 寄存器名 → VM 寄存器索引 (32/64/16/8 位同索引)
_R = {}
for idx, names in enumerate([
        ("rax", "eax", "ax", "al"), ("rcx", "ecx", "cx", "cl"),
        ("rdx", "edx", "dx", "dl"), ("rbx", "ebx", "bx", "bl"),
        ("rsp", "esp"), ("rbp", "ebp"), ("rsi", "esi"), ("rdi", "edi")]):
    for nm in names:
        _R[nm] = idx
for i in range(8, 16):
    for suf in ("", "d", "w", "b"):
        _R[f"r{i}{suf}"] = i


def _ri(name):
    if name not in _R:
        raise NotImplementedError(f"未映射寄存器 {name}")
    return _R[name]


def translate(code: bytes, va: int = 0) -> bytes:
    """x86 → VM 字节码 (含控制流两趟解析跳转目标)。遇不支持指令抛 NotImplementedError。"""
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    RR = {"add": OP["ADD"], "sub": OP["SUB"], "imul": OP["IMUL"],
          "xor": OP["XOR"], "and": OP["AND"], "or": OP["OR"], "mov": OP["MOV"],
          "cmp": OP["CMP"], "test": OP["TEST"]}
    RI = {"add": OP["ADDI"], "imul": OP["IMULI"], "mov": OP["MOVI"], "cmp": OP["CMPI"],
          "sub": OP["SUBI"], "and": OP["ANDI"], "or": OP["ORI"], "xor": OP["XORI"]}

    out = bytearray()
    addr2off = {}                 # x86 地址 → VM 字节码偏移
    fixups = []                   # (out里u16位置, x86目标地址)
    for ins in md.disasm(code, va):
        m, ops = ins.mnemonic, ins.operands
        addr2off[ins.address] = len(out)
        if m == "int3":
            break                 # 函数尾对齐填充
        if m == "nop":
            continue
        if m == "ret":
            out += bytes([OP["RET"], 0])
            continue
        if m == "jmp" and ops[0].type == X86_OP_IMM:
            out += bytes([OP["JMP"]]); fixups.append((len(out), ops[0].imm)); out += b"\x00\x00"
            continue
        if m in CC and ops[0].type == X86_OP_IMM:
            out += bytes([OP["JCC"], CC[m]]); fixups.append((len(out), ops[0].imm)); out += b"\x00\x00"
            continue
        if m in CMOVCC and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG:
            d = _ri(ins.reg_name(ops[0].reg)); s = _ri(ins.reg_name(ops[1].reg))
            out += bytes([OP["CMOV"], CMOVCC[m], (d << 4) | s])
            continue
        if m in ("inc", "dec") and ops[0].type == X86_OP_REG:
            d = _ri(ins.reg_name(ops[0].reg))
            out += bytes([OP["ADDI"], d]) + struct.pack("<i", 1 if m == "inc" else -1)
            continue
        if m == "lea":
            d = _ri(ins.reg_name(ops[0].reg))
            mem = ops[1].mem
            base = 0xFF if mem.base == 0 else _ri(ins.reg_name(mem.base))
            idx = 0xFF if mem.index == 0 else _ri(ins.reg_name(mem.index))
            out += bytes([OP["LEA"], d, base, idx, mem.scale & 0xFF]) + struct.pack("<i", mem.disp)
            continue
        if m in ("neg", "not") and ops[0].type == X86_OP_REG:
            out += bytes([OP["NEG"] if m == "neg" else OP["NOT"], _ri(ins.reg_name(ops[0].reg))])
            continue
        if m in ("shl", "shr", "sal", "sar"):
            d = _ri(ins.reg_name(ops[0].reg))
            imm_op = {"shl": "SHLI", "sal": "SHLI", "shr": "SHRI", "sar": "SARI"}[m]
            reg_op = {"shl": "SHL", "sal": "SHL", "shr": "SHR", "sar": "SAR"}[m]
            if ops[1].type == X86_OP_IMM:
                out += bytes([OP[imm_op], d, ops[1].imm & 0xFF])
                continue
            if ops[1].type == X86_OP_REG:          # 变量移位 (cl)
                out += bytes([OP[reg_op], (d << 4) | _ri(ins.reg_name(ops[1].reg))])
                continue
        if m in ("movzx", "movsx") and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG:
            sn = ins.reg_name(ops[1].reg)
            sz = _SZ.get(sn)
            if sz:
                out += bytes([OP["MOVZX"] if m == "movzx" else OP["MOVSX"],
                              (_ri(ins.reg_name(ops[0].reg)) << 4) | _ri(sn), sz])
                continue
        if m in RR and ops[0].type == X86_OP_REG:
            d = _ri(ins.reg_name(ops[0].reg))
            if ops[1].type == X86_OP_REG:
                out += bytes([RR[m], (d << 4) | _ri(ins.reg_name(ops[1].reg))])
                continue
            if ops[1].type == X86_OP_IMM and m in RI:
                # 无符号打包(掩到32位): 两补码对有/无符号 imm 都正确(VM 按 op 读 i32/u32)
                out += bytes([RI[m], d]) + struct.pack("<I", ops[1].imm & 0xFFFFFFFF)
                continue
        raise NotImplementedError(f"不支持: {m} {ins.op_str}")

    for pos, tgt in fixups:       # 第二趟: 回填跳转目标
        if tgt not in addr2off:
            raise NotImplementedError(f"跳转目标 0x{tgt:x} 不在函数内/非指令边界")
        struct.pack_into("<H", out, pos, addr2off[tgt])
    return bytes(out)


def to_c_array(bc: bytes, name="f_bc") -> str:
    body = ", ".join(f"0x{b:02x}" for b in bc)
    return f"static const unsigned char {name}[] = {{ {body} }};\n"
