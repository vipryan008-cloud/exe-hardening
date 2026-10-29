"""L3 代码虚拟化 — 分析种子 (对应 app-hardening L3 的 scan.py 覆盖率报告)。

反汇编选定函数, 按"当前 VM 起步子集(Gate1 算术/传送)"分类每条指令 可虚拟化 / 未支持,
输出覆盖率。先量化能虚拟化多少, 再谈实现 VM 解释器 + 翻译器。见 docs/05。
"""
import sys
from collections import Counter

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

# Gate1 起步子集: 纯寄存器/立即数的算术与传送
GATE1 = {
    "mov", "lea", "add", "sub", "xor", "and", "or", "shl", "shr", "sar",
    "imul", "inc", "dec", "neg", "not", "movzx", "movsx", "nop", "cmp", "test",
}
CTRL = {"jmp", "je", "jne", "jz", "jnz", "jg", "jl", "jge", "jle", "ja", "jb",
        "call", "ret", "push", "pop", "leave"}


def analyze(path, max_ins=400):
    pe = pefile.PE(path)
    base = pe.OPTIONAL_HEADER.ImageBase
    text = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text")
    code = text.get_data()
    md = Cs(CS_ARCH_X86, CS_MODE_64)

    ok = ctrl = other = 0
    other_mn = Counter()
    for i, ins in enumerate(md.disasm(code, base + text.VirtualAddress)):
        if i >= max_ins:
            break
        if ins.mnemonic in GATE1:
            ok += 1
        elif ins.mnemonic in CTRL:
            ctrl += 1
        else:
            other += 1
            other_mn[ins.mnemonic] += 1
    tot = ok + ctrl + other or 1
    print(f"[L3-analyze] {path}  (前 {tot} 条指令)")
    print(f"  Gate1 可虚拟化(算术/传送) : {ok:4} ({ok/tot:.1%})")
    print(f"  控制流(Gate3/4 待做)      : {ctrl:4} ({ctrl/tot:.1%})")
    print(f"  其它(未支持)              : {other:4} ({other/tot:.1%})")
    if other_mn:
        print(f"  其它 top: {dict(other_mn.most_common(8))}")
    print("  → 起步靶子应挑 Gate1 占比高的纯算术函数, 先证 VM 结果==原生 再扩 Gate。")


if __name__ == "__main__":
    analyze(sys.argv[1] if len(sys.argv) > 1 else "../../samples/sample.exe")
