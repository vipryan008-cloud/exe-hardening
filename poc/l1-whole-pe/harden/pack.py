"""L1 整体壳加壳器 (Windows PE, x64 PE32+ 与 x86 PE32 皆支持)。

做法(经典 section-encryption packer, 全流程可真机验证):
  1. 读目标 exe, 定位 .text 段。
  2. 用 LCG 密钥流加密 .text 段的磁盘原始字节 (静态反汇编只看到密文)。
  3. 把 .text 段标记为可写 (让 stub 能就地解密, 不需调 VirtualProtect)。
  4. 追加新段 .vault, 内含解密 stub, 把 4 个占位常量按真实 VA/长度补丁进去。
  5. 入口点改指向 stub; strip relocations + 固定 ImageBase (保证 stub 里
     baked 的绝对 VA 成立)。
  6. 运行时: OS 正常解析导入表(IAT在.rdata, 未动) → 跳 stub → 解密 .text
     → 跳原 OEP → 原程序照常跑。产物与原 exe 行为一致。

x86 移植(2026-07): x86 PE32 也支持。x86 差异——(1) 32位 stub(stub_x86.bin, 4字节VA占位);
(2) x86 .text 常内含加载器【入口前就读】的结构(Load Config=SafeSEH/GS, TLS 目录+回调数组),
加密它们会崩(0xC000007B/0xC0000005)→ 加密区避开这些结构(算 floor, 只加密 [floor, text_end),
头部留明文); (3) x86 .text 多有 reloc → 用 strip-relocs 模式(固定基址)。

限制(诚实边界): 有【真 TLS 回调】(回调数组非空)的目标仍不支持(回调在解密前跑); strip relocs
让主模块失去 ASLR(x64 无 .text reloc 时走 ASLR 保留模式); x86 目前仅 L1(L2/L3 桩为 x64 专用)。
"""
import os
import struct
import sys

import pefile

HERE = os.path.dirname(os.path.abspath(__file__))
STUB_BIN = os.path.join(HERE, "..", "stub", "stub.bin")            # x64 strip-relocs 版
STUB_ASLR_BIN = os.path.join(HERE, "..", "stub", "stub_aslr.bin")  # x64 保留 ASLR 版
STUB_X86_BIN = os.path.join(HERE, "..", "stub", "stub_x86.bin")    # x86 strip-relocs 版


def count_text_relocs(pe, text) -> int:
    """.text 段内的 base relocation 数量。x64 exe 通常为 0 (RIP-relative),
    为 0 才能安全用 ASLR 模式(加密 .text 不会被 loader 的 reloc 修正破坏)。"""
    if not hasattr(pe, "DIRECTORY_ENTRY_BASERELOC"):
        return 0
    lo = text.VirtualAddress
    hi = lo + max(text.Misc_VirtualSize, text.SizeOfRawData)
    n = 0
    for blk in pe.DIRECTORY_ENTRY_BASERELOC:
        for r in blk.entries:
            if r.type != 0 and lo <= r.rva < hi:  # type 0 = ABSOLUTE padding
                n += 1
    return n

# LCG 参数 (MSVC rand 同款) —— 必须与 stub.asm 完全一致
LCG_A = 0x343FD
LCG_C = 0x269EC3


def keystream_byte(state: int) -> tuple[int, int]:
    """推进一步 LCG, 返回 (新state, 密钥字节)。镜像 stub 的 imul/add/shr16。"""
    state = (state * LCG_A + LCG_C) & 0xFFFFFFFF
    return state, (state >> 16) & 0xFF


def encrypt(buf: bytes, seed: int) -> bytes:
    out = bytearray(buf)
    state = seed & 0xFFFFFFFF
    for i in range(len(out)):
        state, k = keystream_byte(state)
        out[i] ^= k
    return bytes(out)


def align(v: int, a: int) -> int:
    return (v + a - 1) & ~(a - 1)


def patch_first(blob: bytearray, pattern: bytes, value: bytes):
    idx = blob.find(pattern)
    assert idx != -1, f"placeholder {pattern.hex()} not found in stub"
    assert blob.find(pattern, idx + 1) == -1, f"placeholder {pattern.hex()} not unique"
    blob[idx:idx + len(value)] = value


def has_tls_callbacks(pe) -> bool:
    """目标是否有 TLS 回调 (回调在解密 stub 之前由 OS 运行 → L1 加密 .text 会崩)。"""
    try:
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"]])
    except Exception:
        return False
    tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
    if not tls:
        return False
    cbs = tls.struct.AddressOfCallBacks
    if not cbs:
        return False
    # AddressOfCallBacks 指向一个以空指针结尾的数组; 首项为 0 = 空数组 = 无真回调(常见)。
    try:
        ib = pe.OPTIONAL_HEADER.ImageBase
        is64 = pe.OPTIONAL_HEADER.Magic == 0x20B
        first = pe.get_dword_at_rva(cbs - ib) if not is64 else pe.get_qword_at_rva(cbs - ib)
        return bool(first)   # 首个回调指针非零才是真有回调
    except Exception:
        return True          # 读不到就保守警告


def pack(in_path: str, out_path: str, seed: int = 0xC0DEFACE, mode: str = "auto"):
    """mode: auto(默认, .text无reloc则保ASLR否则strip) / aslr(强制保ASLR) / strip(强制固定基址)"""
    pe = pefile.PE(in_path)
    is64 = pe.OPTIONAL_HEADER.Magic == 0x20B
    if pe.OPTIONAL_HEADER.Magic not in (0x10B, 0x20B):
        raise SystemExit("非 PE32/PE32+ 目标")
    if has_tls_callbacks(pe):
        print("[!] 警告: 目标有 TLS 回调 —— 回调在解密 stub 之前由 OS 运行, L1 加密 .text 会崩溃。"
              "完整支持需把解密做成首个 TLS 回调(未实现)。")

    image_base = pe.OPTIONAL_HEADER.ImageBase
    orig_oep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    file_align = pe.OPTIONAL_HEADER.FileAlignment
    sect_align = pe.OPTIONAL_HEADER.SectionAlignment
    e_lfanew = pe.DOS_HEADER.e_lfanew

    text = next((s for s in pe.sections
                 if s.Name.rstrip(b"\x00") == b".text"), None)
    if text is None:
        raise SystemExit(".text 段未找到")

    text_rva = text.VirtualAddress
    n_text = min(text.Misc_VirtualSize, text.SizeOfRawData)  # 磁盘+内存都存在的字节
    text_end = text_rva + n_text

    # ---- 加密区默认=整个 .text; 但【加载器在入口点之前要读的结构】若在 .text 内(x86 常见,
    #      x64 多在 .rdata)必须留明文, 否则加密它们 → 加载器读乱码 →
    #      STATUS_INVALID_IMAGE_FORMAT(0xC000007B, Load Config) 或访问违规(0xC0000005, TLS)。
    #      涉及: Load Config(SafeSEH/GS cookie) + TLS(目录结构 + 回调指针数组)。
    #      这些结构 MSVC 都放 .text 头部 → 算出"明文下限"floor, 加密 [floor, text_end)。
    floor = text_rva
    W_ptr = 8 if is64 else 4
    fdata = open(in_path, "rb").read()
    lc = pe.OPTIONAL_HEADER.DATA_DIRECTORY[10]                        # Load Config
    if lc.VirtualAddress and text_rva <= lc.VirtualAddress < text_end:
        floor = max(floor, lc.VirtualAddress + lc.Size)
    tls = pe.OPTIONAL_HEADER.DATA_DIRECTORY[9]                        # TLS
    if tls.VirtualAddress and text_rva <= tls.VirtualAddress < text_end:
        floor = max(floor, tls.VirtualAddress + (0x28 if is64 else 0x18))  # TLS 目录结构
        # TLS 回调指针数组(AddressOfCallBacks)也在 .text 就要留明文(它是绝对 VA)
        try:
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"]])
            cb_va = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks
            cb_rva = cb_va - image_base if cb_va else 0
            if cb_rva and text_rva <= cb_rva < text_end:
                off = text.PointerToRawData + (cb_rva - text_rva)     # 走到数组末尾(空指针止)
                end = cb_rva
                while True:
                    p = struct.unpack_from("<Q" if is64 else "<I", fdata, off)[0]
                    end += W_ptr; off += W_ptr
                    if p == 0:
                        break
                floor = max(floor, end)
        except Exception:
            floor = text_end     # 保守: 拿不准 TLS 回调范围就整段不加密(退化但安全)
    enc_rva = align(floor, 16)
    n_enc = max(0, text_end - enc_rva)
    skipped = enc_rva - text_rva

    # ---- 读原始文件字节, 加密 .text 选定区([floor, text_end), 避开加载关键结构) ----
    data = bytearray(fdata)
    enc_off = text.PointerToRawData + (enc_rva - text_rva)
    plain = bytes(data[enc_off:enc_off + n_enc])
    data[enc_off:enc_off + n_enc] = encrypt(plain, seed)

    # ---- 选模式: 目标带 ASLR + .text 无 reloc → 保留 ASLR; 否则 strip-relocs ----
    has_aslr = bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x40)
    has_relocs = hasattr(pe, "DIRECTORY_ENTRY_BASERELOC")
    text_relocs = count_text_relocs(pe, text)
    # x86 目前只有 strip 版 stub(baked 绝对 VA); x64 有 ASLR(PEB取基址)+strip 两版。
    aslr_mode = is64 and (mode == "aslr" or (mode == "auto" and has_aslr and has_relocs
                                             and text_relocs == 0))
    if mode == "aslr" and not is64:
        raise SystemExit("x86 暂无 ASLR 版 stub, 用 strip 模式(默认)")
    if mode == "aslr" and text_relocs:
        raise SystemExit(f".text 内有 {text_relocs} 个 reloc, 无法用 ASLR 模式 (会破坏密文)")

    # ---- 组装 stub, 补丁占位常量 (x64=8字节VA, x86=4字节VA) ----
    W = 8 if is64 else 4
    PK = (lambda v: struct.pack("<Q", v)) if is64 else (lambda v: struct.pack("<I", v & 0xFFFFFFFF))
    if aslr_mode:
        stub = bytearray(open(STUB_ASLR_BIN, "rb").read())      # x64 运行时 PEB 取真基址
        patch_first(stub, b"\x11" * W, PK(enc_rva))                    # P_TEXTRVA (加密区起点)
        patch_first(stub, b"\x44" * W, PK(orig_oep_rva))              # P_OEPRVA
    else:
        stub = bytearray(open(STUB_BIN if is64 else STUB_X86_BIN, "rb").read())   # baked 绝对 VA
        patch_first(stub, b"\x11" * W, PK(image_base + enc_rva))                  # P_TEXTVA (加密区起点)
        patch_first(stub, b"\x44" * W, PK(image_base + orig_oep_rva))             # P_OEPVA
    patch_first(stub, b"\x22" * W, PK(n_enc))                                     # P_LEN
    patch_first(stub, b"\x33" * 4, struct.pack("<I", seed & 0xFFFFFFFF))          # P_SEED

    # ---- 计算新段布局 ----
    last = max(pe.sections, key=lambda s: s.VirtualAddress)
    new_rva = align(last.VirtualAddress + last.Misc_VirtualSize, sect_align)
    new_praw = align(len(data), file_align)
    new_vsize = len(stub)
    new_rawsize = align(new_vsize, file_align)

    # section header 落点: 段表末尾, 必须仍在 SizeOfHeaders 区内
    num_sec = pe.FILE_HEADER.NumberOfSections
    opt_sz = pe.FILE_HEADER.SizeOfOptionalHeader
    sec_tab = e_lfanew + 4 + 20 + opt_sz
    new_hdr_off = sec_tab + num_sec * 40
    if new_hdr_off + 40 > pe.OPTIONAL_HEADER.SizeOfHeaders:
        raise SystemExit("头部无空间新增段表项 (需重排头, 本 PoC 未实现)")

    VAULT = b".vault\x00\x00"
    CHAR_CODE_EXEC_READ = 0x60000020
    hdr = struct.pack("<8sIIIIIIHHI", VAULT, new_vsize, new_rva,
                      new_rawsize, new_praw, 0, 0, 0, 0, CHAR_CODE_EXEC_READ)
    data[new_hdr_off:new_hdr_off + 40] = hdr

    # 追加 stub 原始数据 (先补齐到新段 PointerToRawData, 再补齐 rawsize)
    data.extend(b"\x00" * (new_praw - len(data)))
    data.extend(stub)
    data.extend(b"\x00" * (new_rawsize - new_vsize))

    # ---- 打补丁到各头字段 (直接改 bytearray) ----
    def u16(off, v): struct.pack_into("<H", data, off, v)
    def u32(off, v): struct.pack_into("<I", data, off, v)

    opt = e_lfanew + 24  # optional header 起点 (PE sig 4 + COFF 20)
    u16(e_lfanew + 6, num_sec + 1)                    # NumberOfSections
    u32(opt + 16, new_rva)                            # AddressOfEntryPoint -> stub
    u32(opt + 56, align(new_rva + new_vsize, sect_align))  # SizeOfImage

    # .text 段改可写 (Characteristics |= MEM_WRITE 0x80000000)
    text_hdr_off = sec_tab + list(pe.sections).index(text) * 40
    old_char = struct.unpack_from("<I", data, text_hdr_off + 36)[0]
    u32(text_hdr_off + 36, old_char | 0x80000000)

    if not aslr_mode:
        # strip relocations: 固定 ImageBase, 让 baked 绝对 VA 成立 (代价: 失 ASLR)
        fchar = struct.unpack_from("<H", data, e_lfanew + 22)[0]
        u16(e_lfanew + 22, fchar | 0x0001)            # IMAGE_FILE_RELOCS_STRIPPED
        dllchar = struct.unpack_from("<H", data, opt + 70)[0]
        u16(opt + 70, dllchar & ~0x0040)              # 去 DYNAMIC_BASE
        # BASERELOC 数据目录(index 5)偏移: PE32+=opt+152, PE32=opt+136 (数据目录基址不同)
        reloc_dir = (152 if is64 else 136)
        u32(opt + reloc_dir, 0)                        # BASERELOC dir RVA = 0
        u32(opt + reloc_dir + 4, 0)                    # BASERELOC dir Size = 0
    # ASLR 模式: 保留 relocs + DYNAMIC_BASE 不动, stub 运行时 PEB 取真基址

    # 剥离 CFG: 清 GUARD_CF 位, 否则加壳后 CFG 校验 __fastfail(0xC0000409) 崩。
    # (99% 真实 Windows exe 带 CFG; 加壳的保护取代其控制流完整性)
    dc = struct.unpack_from("<H", data, opt + 70)[0]
    had_cfg = bool(dc & 0x4000)
    if had_cfg:
        u16(opt + 70, dc & ~0x4000)

    # (Load Config 不清零/不加密 —— 加密区已在上面避开它, 目录保持有效, 加载器正常解析)

    open(out_path, "wb").write(data)
    if had_cfg:
        print("    [i] 已剥离目标 CFG (GUARD_CF)")
    if skipped:
        print(f"    [i] 加密区避开加载关键结构(Load Config/TLS), 留明文头部 {skipped} 字节")
    print(f"[+] packed -> {out_path}")
    print(f"    ImageBase       = 0x{image_base:X}")
    print(f"    .text  RVA/enc  = 0x{text_rva:X} / {n_enc} bytes encrypted")
    print(f"    orig OEP RVA    = 0x{orig_oep_rva:X}")
    print(f"    .vault RVA/size = 0x{new_rva:X} / {new_vsize} bytes (new entry)")
    print(f"    LCG seed        = 0x{seed:08X}")
    print(f"    mode            = {'ASLR-preserving' if aslr_mode else 'strip-relocs (fixed base)'}"
          f"  (.text relocs={text_relocs})")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        raise SystemExit("usage: pack.py <in.exe> <out.exe> [seedhex] [mode:auto|aslr|strip]")
    sd = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0xC0DEFACE
    md = sys.argv[4] if len(sys.argv) > 4 else "auto"
    pack(sys.argv[1], sys.argv[2], sd, md)
