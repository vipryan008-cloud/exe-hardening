#!/usr/bin/env python3
"""加固套件跨线回归验证 —— 把三条加固线的核心能力真跑一遍, 报 PASS/FAIL。

用预置样本(不重新编译), 逐项: 加固 → 运行 → 校验行为/退出码。防回归, 给信心。
用法: python verify_suite.py
"""
import os
import subprocess
import sys

EXE = r"D:\workspaces\exe-hardening"
NET = r"D:\workspaces\dotnet-hardening"
PY = sys.executable
results = []


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def exitcode(path, args=None):
    return run([path] + (args or [])).returncode


def check(name, fn):
    try:
        ok, detail = fn()
    except Exception as e:
        ok, detail = False, f"异常 {type(e).__name__}: {e}"
    results.append((name, ok, detail))
    print(f"  [{'✓' if ok else '✗'}] {name}  {detail}")


def harden_exe(mode_args, sample="samples\\sample_aslr.exe"):
    src = os.path.join(EXE, sample)
    out = os.path.join(EXE, "samples", "_verify.exe")
    r = run([PY, os.path.join(EXE, "harden.py"), src, "-o", out] + mode_args)
    if not os.path.exists(out):
        return False, "加固未产出: " + (r.stdout + r.stderr)[-120:]
    rc = exitcode(out)
    os.remove(out)
    return rc == 7, f"exit={rc}(期望7)"


def harden_net(flags):
    src = os.path.join(NET, "samples", "hello.exe")
    out = os.path.join(NET, "samples", "_verify.exe")
    if not os.path.exists(src):
        return False, "缺 dotnet-hardening/samples/hello.exe"
    r = run([PY, os.path.join(NET, "harden_net.py"), src, "-o", out] + flags)
    if not os.path.exists(out):
        return False, "加固未产出: " + (r.stdout + r.stderr)[-120:]
    o = run([src, "x"]).stdout
    h = run([out, "x"]).stdout
    nv = os.path.join(NET, "samples", "netvmrt.dll")
    os.remove(out)
    if os.path.exists(nv):
        os.remove(nv)
    return o == h and o != "", "行为==原始" if o == h else f"行为不一致"


def poc(rel):
    p = os.path.join(EXE, rel)
    if not os.path.exists(p):
        return False, "缺 " + rel
    return exitcode(p) == 0, "PoC exit=0"


CSC = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"


def net_oracle_all():
    """严格: 编译分支密集 int 靶子 → --all(含IL虚拟化/CFO/常量) → 输出必==原始。"""
    if not os.path.exists(CSC):
        return True, "跳过(无 csc)"
    import tempfile
    d = tempfile.mkdtemp()
    src = os.path.join(d, "o.cs")
    exe = os.path.join(d, "o.exe")
    hardened = os.path.join(d, "o_h.exe")
    open(src, "w").write(
        "using System;class P{"
        "static int f(int x){int s=0;for(int i=0;i<(x&15);i++){if((i&1)==0)s+=i*x;else s-=i;}return s;}"
        "static int g(int a,int b){while(b!=0){int t=b;b=a%b;a=t;}return a<0?-a:a;}"
        "static int Main(){int acc=0;for(int k=-9;k<30;k++)acc=acc*31+f(k)+g(k*7+50,36);"
        "Console.WriteLine(acc);return acc&0x7f;}}")
    if run([CSC, "-nologo", "-optimize", "-out:" + exe, src]).returncode != 0:
        return False, "csc 编译靶子失败"
    r = run([PY, os.path.join(NET, "harden_net.py"), exe, "-o", hardened, "--all"])
    if not os.path.exists(hardened):
        return False, "加固失败: " + (r.stdout + r.stderr)[-100:]
    import shutil
    nv = os.path.join(NET, "poc", "l5-ilvm", "rt", "netvmrt.dll")
    if os.path.exists(nv):
        shutil.copy(nv, os.path.join(d, "netvmrt.dll"))
    o = run([exe]).stdout
    h = run([hardened]).stdout
    shutil.rmtree(d, ignore_errors=True)
    return o == h and o != "", "IL虚拟化/CFO/常量 语义==原始" if o == h else "语义不一致!"


def _overlay(path):
    import pefile
    pe = pefile.PE(path, fast_load=True)
    end = max(s.PointerToRawData + s.SizeOfRawData for s in pe.sections)
    pe.close()
    return max(0, os.path.getsize(path) - end)


def net_bundle_dropper():
    """自解压单文件包(魔兽启动器, 2.1MB overlay): harden_net --all 必须自动走 dropper 壳,
    且分发产物里 PowerShell 源码被 AES 加密不再明文。防回归:
      - L1整体壳会破坏自解压引导(实测退化成'缺WebView2');
      - no-shell 能跑但 PS 源码仍明文(没保护到真东西);
      - dropper 全文件加密 → 源码消失 + 自解压落临时exe照常跑(真机已验窗口'魔兽世界 · 启动器')。"""
    src = os.path.join(EXE, "魔兽启动器.exe")
    if not os.path.exists(src):
        return True, "跳过(无 魔兽启动器.exe)"
    if _overlay(src) < 256 * 1024:
        return False, f"样本 overlay 太小, 非 bundle"
    out = os.path.join(EXE, "samples", "_bundle_verify.exe")
    r = run([PY, os.path.join(NET, "harden_net.py"), src, "-o", out, "--all"])
    if not os.path.exists(out):
        return False, "加固未产出: " + (r.stdout + r.stderr)[-120:]
    auto = "自动改用 --dropper" in r.stdout
    data = open(out, "rb").read()
    # PS 源码关键明文串必须全部消失(被加密)
    leaks = [s for s in ["New-Object Windows.Forms.Form", "RunspaceFactory", "$form.Text"]
             if s.encode("utf-8") in data]
    os.remove(out)
    ok = auto and not leaks
    return ok, f"自动dropper={auto}, 源码明文残留={leaks or '无(已加密)'}"


def exe_x86_l1():
    """x86(32位)原生 L1: 真实 SysWOW64\\hostname.exe 加固后输出==原始。
    防回归 x86 移植: strip-relocs + 避开 Load Config/TLS(加载关键结构留明文)。
    基线用改同名的原始副本(抵消 MUI/路径), 对比 stdout。"""
    src = r"C:\Windows\SysWOW64\hostname.exe"
    if not os.path.exists(src):
        return True, "跳过(无 SysWOW64\\hostname.exe)"
    import shutil, tempfile
    pack = os.path.join(EXE, "poc", "l1-whole-pe", "harden", "pack.py")
    out = os.path.join(EXE, "samples", "_x86_verify.exe")
    r = run([PY, pack, src, out])
    if not os.path.exists(out):
        return False, "x86 加固未产出: " + (r.stdout + r.stderr)[-100:]
    d = tempfile.mkdtemp(); base = os.path.join(d, "hostname.exe"); shutil.copy(src, base)
    o = run([base]).stdout
    h = run([out]).stdout
    os.remove(out); shutil.rmtree(d, ignore_errors=True)
    return (o == h and o != ""), (f"x86 输出==原始" if o == h else "x86 行为不一致")


def net_resenc_script():
    """资源加密(ResEnc): PS2EXE的PowerShell脚本存内嵌资源, --resenc加密它+注入内存解密代理。
    验证: 加密后输出里脚本明文消失(密文), 且 GetManifestResourceStream 被重定向(内存解密)。
    真机已验: resenc后app正常跑(魔兽世界·启动器)+dropper落盘临时文件里脚本也是密文。"""
    src = os.path.join(EXE, "魔兽启动器.exe")
    resenc = os.path.join(NET, "poc", "l2-resenc", "ResEnc.exe")
    if not (os.path.exists(src) and os.path.exists(resenc)):
        return True, "跳过(缺 魔兽启动器.exe 或 ResEnc.exe)"
    out = os.path.join(EXE, "samples", "_resenc_verify.exe")
    r = run([resenc, src, out])
    if not os.path.exists(out):
        return False, "ResEnc 未产出: " + (r.stdout + r.stderr)[-120:]
    data = open(out, "rb").read()
    os.remove(out)
    leaks = [s for s in ["New-Object Windows.Forms.Form", "$form.Text"]
             if s.encode("utf-8") in data]
    redir = "重定向 GetManifestResourceStream" in r.stdout and "1 处" in r.stdout
    return (not leaks and redir), f"脚本明文残留={leaks or '无(密文)'}, 重定向={redir}"


def net_dropper_selfcheck():
    """dropper 自完整性: 关键方法(反调试/解密/Main)IL 哈希烘焙, patch 即 FailFast。
    验证: (1)正常 dropper 行为==原始 payload(自检不误报); (2)烘焙错哈希的 dropper→FailFast(不跑payload)。
    真机已验: 真实目标改 DebuggerDetected→return false(中和反调试)被自完整性拦截, 且签名后仍不误报(签名安全)。"""
    payload = os.path.join(NET, "samples", "hello.exe")
    dropdir = os.path.join(NET, "poc", "l1-dropper")
    if not (os.path.exists(payload) and os.path.exists(os.path.join(dropdir, "ILHash.exe"))):
        return True, "跳过(缺 hello.exe 或 ILHash.exe)"
    good = os.path.join(EXE, "samples", "_si_good.exe")
    bad = os.path.join(EXE, "samples", "_si_bad.exe")
    # 子进程: 正常打一个 + monkeypatch _il_hash 返回错值打一个(模拟"IL被patch但烘焙哈希不符")
    script = (
        "import sys; sys.path.insert(0, r'%s'); import dropper\n"
        "m=dropper.pack(r'%s', r'%s'); print('SI_ON', m is not None)\n"
        "dropper._il_hash=lambda p: b'\\xAA'*32\n"
        "dropper.pack(r'%s', r'%s')\n" % (dropdir, payload, good, payload, bad)
    )
    r = run([PY, "-c", script])
    if not (os.path.exists(good) and os.path.exists(bad)):
        return False, "dropper 未产出: " + (r.stdout + r.stderr)[-140:]
    si_on = "SI_ON True" in r.stdout
    base = run([payload])                      # 原始 payload 行为基线
    g = run([good])                            # 正常 dropper: 自检过→跑payload
    b = run([bad])                             # 错哈希 dropper: 自检失败→FailFast, 不跑payload
    os.remove(good); os.remove(bad)
    normal_ok = si_on and g.returncode == base.returncode and g.stdout == base.stdout
    tamper_ok = b.returncode != base.returncode and base.stdout not in b.stdout
    return (normal_ok and tamper_ok), \
        f"自检开={si_on}, 正常行为=={'原始' if normal_ok else '不符'}, 篡改={'被拦(FailFast)' if tamper_ok else '未拦!'}"


def main():
    print("═══ exe-hardening (原生 PE x64) ═══")
    check("L1 整体壳", lambda: harden_exe(["--mode", "l1"]))
    check("L2 抽取壳", lambda: harden_exe(["--mode", "l2"]))
    check("L1×L2+反调试", lambda: harden_exe(["--mode", "l1l2", "--anti-debug"]))
    check("x86(32位) L1 (真实SysWOW64 exe)", exe_x86_l1)
    check("L2 自解析shellcode PoC", lambda: poc(r"poc\l2-extract\rt\test_resolve.exe"))
    check("L2 用完即擦 PoC", lambda: poc(r"poc\l2-extract\rt\test_restub.exe"))
    check("运行时反调试(clean)", lambda: poc(r"poc\runtime-anti\antidemo.exe"))

    print("═══ dotnet-hardening (.NET IL) ═══")
    check("L1 整体壳", lambda: harden_net([]))
    check("全套 --all (7层含IL虚拟化)", lambda: harden_net(["--all"]))
    check("严格oracle: --all 语义保持(分支int靶子)", net_oracle_all)
    check("自解压包自动dropper(全文件加密藏PS源码)", net_bundle_dropper)
    check("资源加密ResEnc(PS脚本→密文,内存解密)", net_resenc_script)
    check("dropper自完整性(关键方法IL哈希,patch即FailFast)", net_dropper_selfcheck)

    print("═══ identify 分诊 ═══")
    check("识别 .NET → dotnet线", lambda: _idcheck(os.path.join(EXE, "魔兽启动器.exe"), "dotnet"))
    check("识别 原生x64 → exe线", lambda: _idcheck(os.path.join(EXE, "samples", "sample_aslr.exe"), "exe"))

    n = sum(1 for _, ok, _ in results if ok)
    print(f"\n═══ 总计: {n}/{len(results)} PASS ═══")
    sys.exit(0 if n == len(results) else 1)


def _idcheck(path, expect):
    sys.path.insert(0, EXE)
    import importlib
    idmod = importlib.import_module("identify")
    _, line, _ = idmod.sniff(path)
    return line is not None and expect in line, f"路由={line}"


if __name__ == "__main__":
    main()
