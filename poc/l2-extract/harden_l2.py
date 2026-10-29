"""L2 抽取壳加壳器 (单文件部署)。

对选定函数: 原机器码存进加密侧表 + 原位覆盖 int3 → 内存/磁盘 dump 拿到垃圾。
嵌入 l2deploy blob (自解析 API + VEH) 到新段 .l2rt, 设为入口; 运行时 blob 装好
VEH 后跳原 OEP, 被抽函数首次执行触发 int3 → VEH 从侧表解密回填。保留 ASLR
(blob 是 PIC, 从 PEB 取基址)。见 docs/03。
"""
import os
import struct
import sys

import pefile

HERE = os.path.dirname(os.path.abspath(__file__))
BLOB = os.path.join(HERE, "rt", "l2deploy.bin")
STASH_XOR = 0xA7
OEP_PH = b"\x44" * 8        # P_OEPRVA
TEXTRVA_PH = b"\x11" * 8    # P_TEXTRVA (L1)
LEN_PH = b"\x22" * 8        # P_LEN    (L1; 0=不解密=纯L2)
SEED_PH = b"\x33" * 4       # P_SEED   (L1)
ANTIDBG_PH = b"\x55" * 4    # P_ANTIDBG (1=开反调试)
CALLGATE_PH = b"\x66" * 4   # P_CALLGATE (1=用完即擦: 函数返回后重抽 int3)
LCG_A, LCG_C = 0x343FD, 0x269EC3


def align(v, a):
    return (v + a - 1) & ~(a - 1)


def l1_encrypt(buf, seed):
    """LCG 密钥流加密 (与 l2deploy.asm 的 L1 解密循环一致)。"""
    out = bytearray(buf)
    st = seed & 0xFFFFFFFF
    for i in range(len(out)):
        st = (st * LCG_A + LCG_C) & 0xFFFFFFFF
        out[i] ^= (st >> 16) & 0xFF
    return bytes(out)


def _patch1(blob, pat, val):
    i = blob.find(pat)
    assert i != -1 and blob.find(pat, i + 1) == -1, f"占位 {pat.hex()} 缺失/不唯一"
    blob[i:i + len(val)] = val


def pdata_funcs(pe, text):
    """从 .pdata 取落在 .text 内的 (begin_rva, len)。"""
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


def list_funcs(in_path):
    """列出 .pdata 函数 (RVA/len/首指令), 供 --funcs 精确选择保护对象。"""
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    pe = pefile.PE(in_path)
    text = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text")
    base = pe.OPTIONAL_HEADER.ImageBase
    code = text.get_data()
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    funcs = pdata_funcs(pe, text)
    print(f"{in_path}: {len(funcs)} 个 .pdata 函数 (RVA / len / 首指令)")
    for rva, ln in funcs:
        off = rva - text.VirtualAddress
        first = next(md.disasm(code[off:off + 16], base + rva), None)
        ins = f"{first.mnemonic} {first.op_str}" if first else "?"
        helper = " [栈辅助:callgate自动排除]" if looks_like_stack_helper(code[off:off + ln]) else ""
        print(f"  0x{rva:06X}  {ln:5}  {ins}{helper}")


def _has_tls_cb(pe) -> bool:
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"]])
    except Exception:
        return False
    t = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
    return bool(t and t.struct.AddressOfCallBacks)


def _imports_threads(pe) -> bool:
    """目标是否导入线程创建 API (判断疑似多线程)。"""
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    except Exception:
        pass
    names = {b"CreateThread", b"_beginthreadex", b"_beginthread", b"CreateRemoteThread"}
    for imp in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        for f in imp.imports:
            if f.name and f.name in names:
                return True
    return False


def looks_like_stack_helper(code: bytes) -> bool:
    """检测 __chkstk 类栈探测辅助: 读 gs:[0x10](栈限)。这类函数在序言中途被调、
    栈逼近 guard page, 不能被 call-gate 的返回 hook (额外栈开销触未探测页)。"""
    i = code.find(b"\x25\x10\x00\x00\x00")   # ... [abs disp32=0x10] (SIB, base=none)
    return i >= 4 and b"\x65" in code[max(0, i - 6):i]  # 前方有 gs 段前缀


def pack_l2(in_path, out_path, limit=None, l1_seed=None, antidbg=False,
            callgate=False, rvas=None):
    """l1_seed=None纯L2/给seed则L1×L2组合; antidbg=反调试; callgate=用完即擦;
    rvas=None则按limit/全部选函数, 否则只保护指定 RVA 集(精确保护敏感函数)。"""
    pe = pefile.PE(in_path)
    if pe.OPTIONAL_HEADER.Magic != 0x20B:
        raise SystemExit("只支持 PE32+ (x64)")
    e_lfanew = pe.DOS_HEADER.e_lfanew
    file_align = pe.OPTIONAL_HEADER.FileAlignment
    sect_align = pe.OPTIONAL_HEADER.SectionAlignment
    orig_oep = pe.OPTIONAL_HEADER.AddressOfEntryPoint

    if _has_tls_cb(pe):
        print("[!] 警告: 目标有 TLS 回调 —— 回调在 VEH 装载/L1 解密之前由 OS 运行, 若被保护函数是 TLS 回调会崩。")
    text = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text")
    t_raw0, t_rawsz = text.PointerToRawData, text.SizeOfRawData
    funcs = pdata_funcs(pe, text)
    if rvas is not None:                      # 精确保护指定 RVA
        want = {r & 0xFFFFFFFF for r in rvas}
        funcs = [f for f in funcs if f[0] in want]
        miss = want - {f[0] for f in funcs}
        if miss:
            print(f"[!] 这些 RVA 未在 .pdata 找到, 跳过: {[hex(x) for x in miss]}")
    elif limit:
        funcs = funcs[:limit]

    if callgate and _imports_threads(pe):
        print("[!] 警告: 目标疑似多线程(导入线程API)。call-gate 用完即擦 与【并发调用同一被保护函数】"
              "不兼容——重抽 int3 会与其它线程执行竞争而崩溃。仅在单线程/非并发被保护函数时用 --call-gate。")

    data = bytearray(open(in_path, "rb").read())

    # ---- 抽取: 覆盖 int3, 原码存侧表 ----
    entries, stash = [], bytearray()
    n = skipped = 0
    for rva, ln in funcs:
        foff = t_raw0 + (rva - text.VirtualAddress)
        if foff < t_raw0 or foff + ln > t_raw0 + t_rawsz:
            continue
        orig = bytes(data[foff:foff + ln])
        if callgate and looks_like_stack_helper(orig):  # call-gate 不能 hook 栈探测辅助
            skipped += 1
            continue
        entries.append((rva, ln, len(stash)))          # stash_off 暂存"相对stash起点"
        stash += bytes(b ^ STASH_XOR for b in orig)
        data[foff:foff + ln] = b"\xCC" * ln
        n += 1

    # ---- L1×L2 组合: int3 抽取后, 整体加密 .text ----
    if l1_seed is not None:
        n_enc = min(text.Misc_VirtualSize, text.SizeOfRawData)
        data[t_raw0:t_raw0 + n_enc] = l1_encrypt(bytes(data[t_raw0:t_raw0 + n_enc]), l1_seed)

    # ---- 组装 blob + 侧表 ----
    blob = bytearray(open(BLOB, "rb").read())
    _patch1(blob, OEP_PH, struct.pack("<Q", orig_oep))
    if l1_seed is not None:
        _patch1(blob, TEXTRVA_PH, struct.pack("<Q", text.VirtualAddress))
        _patch1(blob, LEN_PH, struct.pack("<Q", n_enc))
        _patch1(blob, SEED_PH, struct.pack("<I", l1_seed & 0xFFFFFFFF))
    else:
        _patch1(blob, LEN_PH, struct.pack("<Q", 0))     # P_LEN=0 → 跳过 L1 解密
    _patch1(blob, ANTIDBG_PH, struct.pack("<I", 1 if antidbg else 0))
    _patch1(blob, CALLGATE_PH, struct.pack("<I", 1 if callgate else 0))

    tbl_start = len(blob)                                # 侧表紧接 blob (= g_tbl)
    entries_sz = 8 + n * 24
    table = bytearray()
    table += struct.pack("<Q", n)
    for rva, ln, soff in entries:
        table += struct.pack("<QQQ", rva, ln, entries_sz + soff)  # stash_off 从"表起点"算
    table += stash
    section = bytes(blob) + bytes(table)

    # ---- 新增 .l2rt 段 (RWX) ----
    last = max(pe.sections, key=lambda s: s.VirtualAddress)
    new_rva = align(last.VirtualAddress + last.Misc_VirtualSize, sect_align)
    new_praw = align(len(data), file_align)
    new_vsize = len(section)
    new_rawsize = align(new_vsize, file_align)

    num_sec = pe.FILE_HEADER.NumberOfSections
    opt_sz = pe.FILE_HEADER.SizeOfOptionalHeader
    sec_tab = e_lfanew + 4 + 20 + opt_sz
    new_hdr = sec_tab + num_sec * 40
    if new_hdr + 40 > pe.OPTIONAL_HEADER.SizeOfHeaders:
        raise SystemExit("头部无空间新增段")

    CHAR_RWX_CODE = 0xE0000020
    hdr = struct.pack("<8sIIIIIIHHI", b".l2rt\x00\x00\x00", new_vsize, new_rva,
                      new_rawsize, new_praw, 0, 0, 0, 0, CHAR_RWX_CODE)
    data[new_hdr:new_hdr + 40] = hdr
    data.extend(b"\x00" * (new_praw - len(data)))
    data.extend(section)
    data.extend(b"\x00" * (new_rawsize - new_vsize))

    opt = e_lfanew + 24
    struct.pack_into("<H", data, e_lfanew + 6, num_sec + 1)                 # NumberOfSections
    struct.pack_into("<I", data, opt + 16, new_rva)                         # AddressOfEntryPoint
    struct.pack_into("<I", data, opt + 56, align(new_rva + new_vsize, sect_align))  # SizeOfImage

    # 组合模式: .text 改可写, 供 blob 入口的 L1 解密循环就地写回
    if l1_seed is not None:
        th = sec_tab + list(pe.sections).index(text) * 40
        ch = struct.unpack_from("<I", data, th + 36)[0]
        struct.pack_into("<I", data, th + 36, ch | 0x80000000)

    # 剥离 CFG (99% 真实 exe 带 CFG; 否则加壳后 __fastfail 0xC0000409)
    dc = struct.unpack_from("<H", data, opt + 70)[0]
    if dc & 0x4000:
        struct.pack_into("<H", data, opt + 70, dc & ~0x4000)
        print("    [i] 已剥离目标 CFG")

    open(out_path, "wb").write(data)
    mode = f"L1×L2 组合 (seed=0x{l1_seed:08X})" if l1_seed is not None else "纯 L2"
    if antidbg:
        mode += " +反调试"
    if callgate:
        mode += " +用完即擦"
    print(f"[+] {mode} packed -> {out_path}")
    sk = f", 自动排除栈辅助 {skipped}" if skipped else ""
    print(f"    保护函数数     = {n} (int3 抽取, 密文 {len(stash)} bytes{sk})")
    if l1_seed is not None:
        print(f"    .text 整体加密 = {n_enc} bytes (抗静态) + 函数 int3 抽取 (抗dump)")
    print(f"    orig OEP RVA   = 0x{orig_oep:X}")
    print(f"    .l2rt RVA/size = 0x{new_rva:X} / {new_vsize} bytes (新入口, ASLR 保留)")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        raise SystemExit("usage: harden_l2.py <in.exe> <out.exe> [limit] [l1seedhex]")
    lim = int(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3] != "-" else None
    sd = int(sys.argv[4], 16) if len(sys.argv) > 4 and sys.argv[4] != "-" else None
    adbg = len(sys.argv) > 5 and sys.argv[5] in ("1", "antidbg", "true")
    cg = len(sys.argv) > 6 and sys.argv[6] in ("1", "callgate", "true")
    rv = [int(x, 16) for x in sys.argv[7].split(",")] if len(sys.argv) > 7 else None
    pack_l2(sys.argv[1], sys.argv[2], lim, sd, adbg, cg, rv)
