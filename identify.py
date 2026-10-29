#!/usr/bin/env python3
"""加固目标分诊工具 —— 给任意文件, 判断它是什么 + 该用哪条加固线 + 已加壳吗。

三条加固线:
  app-hardening    : Android APK / Dalvik
  exe-hardening    : Windows 原生 PE (x64)  —— L1整体壳/L2抽取壳/L3虚拟化/运行时反调试
  dotnet-hardening : .NET 托管程序集 (IL)   —— L1整体壳+反调试/反篡改/key混淆

用法: python identify.py <文件...>
"""
import struct
import sys
import zipfile


def sniff(path):
    try:
        head = open(path, "rb").read(4096)
    except OSError as e:
        return ("读不了", None, str(e))
    # ---- APK / ZIP ----
    if head[:2] == b"PK":
        try:
            z = zipfile.ZipFile(path)
            names = z.namelist()
            if "AndroidManifest.xml" in names and any(n.startswith("classes") and n.endswith(".dex") for n in names):
                dexn = [n for n in names if n.startswith("classes") and n.endswith(".dex")]
                packers = {"libjiagu": "360加固", "libshell": "腾讯乐固/自制", "libDexHelper": "爱加密",
                           "libprotectClass": "娜迦", "libexec.so": "阿里"}
                sos = [n for n in names if n.endswith(".so")]
                hit = [v for k, v in packers.items() if any(k in s for s in sos)]
                note = f"; ⚠️疑似已加壳({hit[0]})" if hit else ""
                return (f"Android APK ({len(dexn)} dex{note})", "app-hardening",
                        "⚠️已加壳=别重复打壳" if hit else "L1整体壳/L2抽取壳/L3虚拟化 都适用")
            return ("ZIP (非APK)", None, "不是加固目标")
        except zipfile.BadZipFile:
            pass
    # ---- PE ----
    if head[:2] == b"MZ":
        e_lfanew = struct.unpack_from("<I", head, 0x3C)[0]
        if head[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return ("MZ 但非 PE", None, "?")
        magic = struct.unpack_from("<H", head, e_lfanew + 24)[0]
        arch = "x64 (PE32+)" if magic == 0x20B else "x86 (PE32)" if magic == 0x10B else f"?{magic:#x}"
        opt = e_lfanew + 24
        subsys = struct.unpack_from("<H", head, opt + (68 if magic == 0x20B else 68))[0]
        gui = " GUI" if subsys == 2 else " console" if subsys == 3 else ""
        # .NET? 需读 COM descriptor 目录 (需完整解析, 用 pefile 更稳)
        try:
            import pefile
            pe = pefile.PE(path, fast_load=True)
            pe.parse_data_directories()
            clr = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress
            dotnet = bool(clr)
            # 已加壳判别(原生): 段极少+可疑段名 / 高熵
            secs = [s.Name.rstrip(b"\x00").decode(errors="replace") for s in pe.sections]
            packed = None
            for p in ("UPX", ".vmp", ".themida", ".enigma", ".aspack", ".stub"):
                if any(p.lower() in s.lower() for s in secs):
                    packed = p
            imports = []
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                imports = [i.dll.decode(errors="replace").lower() for i in pe.DIRECTORY_ENTRY_IMPORT]
            pe.close()
        except Exception:
            dotnet = False; packed = None; imports = []; secs = []

        if dotnet:
            reason = ".NET 是 IL 非原生码 → 原生PE加壳无效, 用 .NET 专线"
            if magic == 0x10B:
                reason += " (32位, dotnet-hardening loader 用 /platform:x86 匹配)"
            return (f"Windows .NET 托管程序集 ({arch}{gui})", "dotnet-hardening", reason)
        if packed:
            return (f"Windows 原生 PE ({arch}{gui}); ⚠️疑似已加壳({packed})", None, "已加壳=别重复打壳")
        if magic == 0x20B:
            return (f"Windows 原生 PE ({arch}{gui})", "exe-hardening",
                    "L1整体壳(ASLR保留+CFG剥离)/L2抽取壳/L3虚拟化/运行时反调试 适用")
        if magic == 0x10B:
            return (f"Windows 原生 PE ({arch}{gui})", "exe-hardening",
                    "L1整体壳(x86: strip-relocs+避开LoadConfig/TLS); L2/L3 目前仅x64")
        return (f"Windows 原生 PE ({arch}{gui})", None, "未知 PE optional magic")
    return ("未知格式", None, "?")


def main(paths):
    for p in paths:
        what, line, reason = sniff(p)
        print(f"■ {p}")
        print(f"    是什么 : {what}")
        print(f"    用哪条 : {line if line else '(不适用/别打)'}")
        print(f"    说明   : {reason}")
        print()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit("usage: identify.py <文件...>")
    main(sys.argv[1:])
