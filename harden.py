#!/usr/bin/env python3
"""EXE 加固工具 — 根 CLI。

当前后端: L1 整体壳 (poc/l1-whole-pe/harden/pack.py)。
用法:
    python harden.py <目标.exe> -o <输出.exe> [--seed HEX]

后续: --mode l2 / l3 接抽取壳与代码虚拟化 (见 docs/03,05)。加固后请用
客户 Authenticode 证书 signtool 重签, 否则 SmartScreen 会拦。
"""
import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "poc", "l1-whole-pe", "harden"))
sys.path.insert(0, os.path.join(HERE, "poc", "l2-extract"))
import pack as l1        # noqa: E402
import harden_l2 as l2   # noqa: E402


def main():
    ap = argparse.ArgumentParser(description="Windows PE 加固工具 (L1 整体壳)")
    ap.add_argument("input", help="待加固 exe (x64 PE32+ 全功能; x86 PE32 仅 L1)")
    ap.add_argument("-o", "--output", help="输出 exe (默认 <name>_packed.exe)")
    ap.add_argument("--seed", default="C0DEFACE", help="LCG 密钥种子 (hex, 默认 C0DEFACE)")
    ap.add_argument("--mode", default="l1", choices=["l1", "l2", "l1l2"],
                    help="l1=整体壳(.text加密,抗静态); l2=抽取壳(函数int3抽取+惰性回填,抗dump); "
                         "l1l2=组合(双层, 单文件)")
    ap.add_argument("--limit", type=int, default=None, help="L2/L1L2: 只保护前 N 个函数 (默认全部)")
    ap.add_argument("--anti-debug", action="store_true",
                    help="启动反调试: 命中调试器即 ExitProcess (l2/l1l2 模式)")
    ap.add_argument("--call-gate", action="store_true",
                    help="用完即擦: 函数返回后重抽 int3 (抗主动dump)。__chkstk 类栈辅助自动排除")
    ap.add_argument("--funcs", help="精确保护的函数 RVA 集, 逗号分隔 hex (如 0x1420,0x14a0)")
    ap.add_argument("--funcs-file", help="精确保护: 每行一个 RVA(hex) 的文件")
    ap.add_argument("--list-funcs", action="store_true", help="只列出 .pdata 函数(RVA/len/首指令)不加固")
    a = ap.parse_args()

    if a.list_funcs:
        l2.list_funcs(a.input)
        return

    rvas = None
    if a.funcs:
        rvas = [int(x, 16) for x in a.funcs.split(",")]
    elif a.funcs_file:
        rvas = [int(l.split("#")[0], 16) for l in open(a.funcs_file)
                if l.split("#")[0].strip()]

    out = a.output or os.path.splitext(a.input)[0] + "_packed.exe"
    print(f"[*] mode={a.mode}  in={a.input}  out={out}")
    if a.call_gate and a.limit is None and rvas is None:
        print("[!] --call-gate 建议配 --limit 或 --funcs 精确保护应用函数(非全CRT)")
    if a.mode == "l2":
        l2.pack_l2(a.input, out, a.limit, None, a.anti_debug, a.call_gate, rvas)
    elif a.mode == "l1l2":
        l2.pack_l2(a.input, out, a.limit, int(a.seed, 16), a.anti_debug, a.call_gate, rvas)
    else:
        if a.anti_debug:
            print("[!] L1 模式暂不含反调试, 用 --mode l1l2 --anti-debug")
        l1.pack(a.input, out, int(a.seed, 16))
    print("[*] 完成。请用客户证书重签: signtool sign /f cert.pfx /p <pwd> "
          f"/fd sha256 /tr <ts_url> /td sha256 {out}")


if __name__ == "__main__":
    main()
