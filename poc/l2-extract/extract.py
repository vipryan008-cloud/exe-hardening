"""L2 抽取壳 — 分析种子。

现阶段: 反汇编目标 .text, 依据运行时函数表(.pdata)切出函数边界, 报告
"可抽取函数集"与抽取表 (RVA, size)。这是把机器码搬进加密侧表 + 原位置桩
之前的离线分析步 (同 app-hardening L2 先 scan 再 surgery 的思路)。

后续: 依此表实际改字节(桩=int3/jmp回填器) + 生成 AES 侧表 + SEH/VEH 回填器,
再真机验证(行为一致 + dump 时该函数为空)。见 docs/03。
"""
import sys

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64


def functions_from_pdata(pe):
    """从 .pdata (RUNTIME_FUNCTION[]) 取函数边界: 每项 12 字节 = begin,end,unwind (RVA)。"""
    pdata = next((s for s in pe.sections
                  if s.Name.rstrip(b"\x00") == b".pdata"), None)
    if not pdata:
        return []
    raw = pdata.get_data()
    funcs = []
    import struct
    for off in range(0, len(raw) - 11, 12):
        begin, end, _unwind = struct.unpack_from("<III", raw, off)
        if begin and end > begin:
            funcs.append((begin, end - begin))
    return funcs


def analyze(path):
    pe = pefile.PE(path)
    base = pe.OPTIONAL_HEADER.ImageBase
    text = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text")
    code = text.get_data()
    text_rva = text.VirtualAddress
    md = Cs(CS_ARCH_X86, CS_MODE_64)

    funcs = functions_from_pdata(pe)
    print(f"[L2-analyze] {path}")
    print(f"  ImageBase=0x{base:X}  .text RVA=0x{text_rva:X} size={len(code)}")
    print(f"  .pdata 函数数 = {len(funcs)}")
    total = 0
    print(f"  {'RVA':>10} {'size':>6}  首指令")
    for rva, size in funcs[:20]:
        off = rva - text_rva
        if off < 0 or off + 1 > len(code):
            continue
        first = next(md.disasm(code[off:off + 16], base + rva), None)
        ins = f"{first.mnemonic} {first.op_str}" if first else "?"
        print(f"  0x{rva:08X} {size:6}  {ins}")
        total += size
    more = max(0, len(funcs) - 20)
    print(f"  ...(+{more} 更多)  可抽取字节合计(前20)={total}")
    print(f"  → 抽取表候选: {len(funcs)} 个函数可搬进加密侧表并置桩")


if __name__ == "__main__":
    analyze(sys.argv[1] if len(sys.argv) > 1 else "../../samples/sample.exe")
