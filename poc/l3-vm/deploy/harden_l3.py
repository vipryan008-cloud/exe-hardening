"""L3 代码虚拟化加壳器 (运行时 DLL 方案, 双文件: 加壳exe + l3rt.dll)。

把指定函数(RVA)的 x86 翻译成 VM 字节码, 嵌进新段 .l3, 并把函数入口改写成跳到
一段 thunk —— thunk 经 g_vmrun 槽调 vm_run(字节码, a, b)。启动 stub(l3stub.bin)
自解析 LoadLibrary("l3rt.dll")+GetProcAddress("vm_run") 填槽, 再跳原 OEP。
=> 被虚拟化函数不再有原生 x86, 由 l3rt.dll 里的 VM 解释执行。固定基址(strip relocs)。

用法: python harden_l3.py <in.exe> <out.exe> <rva1[,rva2...]>
装机: 把 l3rt.dll 放在 out.exe 同目录。
"""
import os
import struct
import sys

import pefile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "vm"))
import x86_to_vm  # noqa: E402

STUB = os.path.join(HERE, "rt", "l3stub.bin")
G_VMRUN_OFF = 328            # g_vmrun 槽在 stub blob 内的偏移 (见 l3stub 提取)
OEP_PH = b"\x44" * 8
THUNK_LEN = 27


def align(v, a):
    return (v + a - 1) & ~(a - 1)


def func_len(pe, text, code_from_rva, rva):
    """函数长度: 先查 .pdata; leaf 函数无 .pdata 时反汇编到首个 ret。"""
    pd = next((s for s in pe.sections if s.Name.rstrip(b"\x00") == b".pdata"), None)
    if pd:
        raw = pd.get_data()
        for off in range(0, len(raw) - 11, 12):
            b, e, _ = struct.unpack_from("<III", raw, off)
            if b == rva:
                return e - b
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for ins in md.disasm(code_from_rva, rva):
        if ins.mnemonic == "ret":
            return ins.address - rva + ins.size
    return None


def pack_l3(in_path, out_path, rvas):
    pe = pefile.PE(in_path)
    if pe.OPTIONAL_HEADER.Magic != 0x20B:
        raise SystemExit("只支持 PE32+ (x64)")
    e_lfanew = pe.DOS_HEADER.e_lfanew
    file_align = pe.OPTIONAL_HEADER.FileAlignment
    sect_align = pe.OPTIONAL_HEADER.SectionAlignment
    image_base = pe.OPTIONAL_HEADER.ImageBase
    orig_oep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    text = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text")
    t_raw0, t_rawsz = text.PointerToRawData, text.SizeOfRawData
    data = bytearray(open(in_path, "rb").read())

    # ---- 翻译各函数 → 字节码 ----
    jobs = []   # (func_rva, func_len, bytecode)
    for rva in rvas:
        foff = t_raw0 + (rva - text.VirtualAddress)
        ln = func_len(pe, text, bytes(data[foff:foff + 256]), rva)
        if ln is None:
            raise SystemExit(f"RVA 0x{rva:x} 找不到函数长度 (无 .pdata 且无 ret)")
        code = bytes(data[foff:foff + ln])
        try:
            bc = x86_to_vm.translate(code)
        except NotImplementedError as ex:
            raise SystemExit(f"函数 0x{rva:x} 含不支持指令, 无法虚拟化: {ex}")
        if ln < 12:
            raise SystemExit(f"函数 0x{rva:x} 太小({ln}B), 放不下 12B 重定向")
        jobs.append((rva, ln, bc))

    # ---- 计算 .l3 段布局 ----
    last = max(pe.sections, key=lambda s: s.VirtualAddress)
    L3RVA = align(last.VirtualAddress + last.Misc_VirtualSize, sect_align)

    stub = bytearray(open(STUB, "rb").read())
    i = stub.find(OEP_PH)
    assert i != -1 and stub.find(OEP_PH, i + 1) == -1
    stub[i:i + 8] = struct.pack("<Q", image_base + orig_oep)   # P_OEP 绝对 VA

    slot_abs = image_base + L3RVA + G_VMRUN_OFF
    sec = bytearray(stub)
    thunks_off = len(sec)
    sec += b"\x00" * (THUNK_LEN * len(jobs))                   # 占位, 稍后填
    bc_offs = []
    for (rva, ln, bc) in jobs:
        bc_offs.append(len(sec))
        sec += bc
    # 填 thunks + 改函数入口
    for k, (rva, ln, bc) in enumerate(jobs):
        toff = thunks_off + k * THUNK_LEN
        thunk_abs = image_base + L3RVA + toff
        bc_abs = image_base + L3RVA + bc_offs[k]
        thunk = (b"\x41\x89\xD0" + b"\x89\xCA" +
                 b"\x48\xB9" + struct.pack("<Q", bc_abs) +
                 b"\x48\xA1" + struct.pack("<Q", slot_abs) +
                 b"\xFF\xE0")
        assert len(thunk) == THUNK_LEN
        sec[toff:toff + THUNK_LEN] = thunk
        # 函数入口改写: mov rax, thunk_abs ; jmp rax
        foff = t_raw0 + (rva - text.VirtualAddress)
        data[foff:foff + 12] = b"\x48\xB8" + struct.pack("<Q", thunk_abs) + b"\xFF\xE0"

    # ---- 新增 .l3 段 (RX) + 改入口 + strip relocs ----
    num_sec = pe.FILE_HEADER.NumberOfSections
    opt_sz = pe.FILE_HEADER.SizeOfOptionalHeader
    sec_tab = e_lfanew + 4 + 20 + opt_sz
    new_hdr = sec_tab + num_sec * 40
    if new_hdr + 40 > pe.OPTIONAL_HEADER.SizeOfHeaders:
        raise SystemExit("头部无空间新增段")
    new_praw = align(len(data), file_align)
    new_vsize = len(sec)
    new_rawsize = align(new_vsize, file_align)
    hdr = struct.pack("<8sIIIIIIHHI", b".l3\x00\x00\x00\x00\x00", new_vsize, L3RVA,
                      new_rawsize, new_praw, 0, 0, 0, 0, 0xE0000020)  # CODE|EXEC|READ|WRITE(g_vmrun槽)
    data[new_hdr:new_hdr + 40] = hdr
    data.extend(b"\x00" * (new_praw - len(data)))
    data.extend(sec)
    data.extend(b"\x00" * (new_rawsize - new_vsize))

    opt = e_lfanew + 24
    struct.pack_into("<H", data, e_lfanew + 6, num_sec + 1)
    struct.pack_into("<I", data, opt + 16, L3RVA)                       # 入口 = l3_entry
    struct.pack_into("<I", data, opt + 56, align(L3RVA + new_vsize, sect_align))
    # strip relocs (固定基址, thunk/槽用绝对 VA)
    fchar = struct.unpack_from("<H", data, e_lfanew + 22)[0]
    struct.pack_into("<H", data, e_lfanew + 22, fchar | 0x0001)
    dllchar = struct.unpack_from("<H", data, opt + 70)[0]
    struct.pack_into("<H", data, opt + 70, dllchar & ~0x0040)
    struct.pack_into("<I", data, opt + 176, 0)
    struct.pack_into("<I", data, opt + 180, 0)
    # 剥离 CFG (99% 真实 exe 带 CFG; 否则加壳后 __fastfail 0xC0000409)
    dc = struct.unpack_from("<H", data, opt + 70)[0]
    if dc & 0x4000:
        struct.pack_into("<H", data, opt + 70, dc & ~0x4000)

    open(out_path, "wb").write(data)
    print(f"[+] L3 虚拟化 {len(jobs)} 函数 -> {out_path}")
    for (rva, ln, bc) in jobs:
        print(f"    0x{rva:X}: x86 {ln}B → VM 字节码 {len(bc)}B (入口改 thunk→vm_run)")
    print(f"    .l3 RVA=0x{L3RVA:X} size={new_vsize}  (固定基址)")
    print(f"    ⚠️ 装机: 把 l3rt.dll 放在 {os.path.basename(out_path)} 同目录")


if __name__ == "__main__":
    if len(sys.argv) < 4:
        raise SystemExit("usage: harden_l3.py <in.exe> <out.exe> <rva1[,rva2...]>")
    rr = [int(x, 16) for x in sys.argv[3].split(",")]
    pack_l3(sys.argv[1], sys.argv[2], rr)
