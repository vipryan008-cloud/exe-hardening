"""L3 覆盖率扫描器 (对标 app-hardening 的 scan.py)。

对目标 exe 逐 .pdata 函数试翻译成 VM 字节码, 诚实统计:
  - 能虚拟化的函数数/占比 (当前 VM 子集: 纯寄存器算术+控制流)
  - bail 原因分布 (卡在哪些指令 → 指导下一步 Gate2/4 投入)

用法: python scan.py <exe> [--show N]
"""
import struct
import sys
from collections import Counter

import pefile

sys.path.insert(0, __file__.rsplit("scan.py", 1)[0] + "vm")
import x86_to_vm  # noqa: E402


def pdata_funcs(pe, text):
    pd = next((s for s in pe.sections if s.Name.rstrip(b"\x00") == b".pdata"), None)
    if not pd:
        return []
    raw = pd.get_data()
    lo, hi = text.VirtualAddress, text.VirtualAddress + max(text.Misc_VirtualSize, text.SizeOfRawData)
    out = []
    for off in range(0, len(raw) - 11, 12):
        b, e, _ = struct.unpack_from("<III", raw, off)
        if b and e > b and lo <= b < hi:
            out.append((b, e - b))
    return out


def bail_key(msg):
    """把 bail 消息归一成指令类别 (便于统计)。"""
    if msg.startswith("不支持: "):
        mn = msg.split()[1]
        if mn.startswith(("mov", "movdq", "movq", "movd", "pshuf", "padd", "pmul", "psub", "pand", "por", "pxor", "psll", "psrl", "psrldq", "pslldq", "xorps", "movaps", "movups", "cvt", "unpck")):
            if mn in ("mov", "movsxd"):
                return f"内存/mov: {mn}"
            if mn.startswith(("movdq", "movq", "movd", "pshuf", "padd", "pmul", "psub", "pand", "por", "pxor", "psll", "psrl", "xorps", "movaps", "movups", "cvt", "unpck")):
                return "SIMD"
            return f"内存/mov: {mn}"
        if mn in ("call", "jmp"):
            return f"调用/间接跳转: {mn}"
        if mn in ("div", "idiv", "mul"):
            return f"除法/宽乘: {mn}"
        return f"指令: {mn}"
    if "跳转目标" in msg:
        return "跳转目标越界(尾调用/表跳)"
    if "format requires" in msg or "index out of range" in msg:
        return "翻译器边界(操作数形态)"
    return "其它"


def scan(path, show=12):
    pe = pefile.PE(path)
    text = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text")
    base = pe.OPTIONAL_HEADER.ImageBase
    code = text.get_data()
    funcs = pdata_funcs(pe, text)

    ok = 0
    ok_bytes = 0
    bails = Counter()
    ok_examples = []
    for rva, ln in funcs:
        off = rva - text.VirtualAddress
        if off < 0 or off + ln > len(code):
            continue
        sub = code[off:off + ln]
        try:
            bc = x86_to_vm.translate(sub, base + rva)
            ok += 1
            ok_bytes += ln
            if len(ok_examples) < 8:
                ok_examples.append((rva, ln, len(bc)))
        except Exception as ex:
            bails[bail_key(str(ex))] += 1

    n = len(funcs) or 1
    print(f"L3 覆盖率扫描: {path}")
    print(f"  .pdata 函数总数     : {len(funcs)}")
    print(f"  当前 VM 可虚拟化    : {ok} ({ok/n:.1%})  [纯寄存器算术+控制流]")
    print(f"  bail(需更多 Gate)   : {len(funcs)-ok} ({(len(funcs)-ok)/n:.1%})")
    print(f"  bail 原因 TOP:")
    for k, c in bails.most_common(show):
        print(f"    {c:5}  {k}")
    if ok_examples:
        print(f"  可虚拟化样例(RVA/x86B/字节码B): " +
              ", ".join(f"0x{r:X}/{l}/{b}" for r, l, b in ok_examples[:6]))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit("usage: scan.py <exe> [showN]")
    scan(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 12)
