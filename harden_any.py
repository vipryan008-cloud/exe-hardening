#!/usr/bin/env python3
"""加固套件统一入口 —— 丢任意文件, 自动识别 + 路由 + 加固 + 【自验证(冒烟测试)】。

商用铁律: 要么正确加固, 要么明确拒绝 —— 绝不悄悄产出跑不起来的 exe。
加固后自动冒烟测试(对比产物 vs 原始在探针参数下的行为); 不通过则自动回退到更兼容的模式;
仍不通过则【拒绝出货】(删掉坏产物, 报清原因), 而不是把坏 exe 丢给用户。

三条加固线:
  app-hardening    : Android APK / Dalvik (GUI 工具)
  exe-hardening    : Windows 原生 PE (x64; x86 暂不支持→优雅拒绝)
  dotnet-hardening : .NET 托管程序集 (IL; 自解压包→dropper; 路径敏感工具→自动回退 no-shell)

用法:
  python harden_any.py <文件> [-o 输出]              # 识别+加固+自验证(默认探针 /?)
  python harden_any.py <文件> --probe "--version"    # 自定义冒烟探针参数
  python harden_any.py <文件> --gui-probe            # 目标是GUI: 冒烟=启动存活3秒不崩
  python harden_any.py <文件> --no-verify            # 跳过自验证(自担风险)
  python harden_any.py <文件> --dry                  # 只识别+推荐, 不加固
"""
import argparse
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from identify import sniff  # noqa: E402

EXE_HARDEN = os.path.join(HERE, "harden.py")
NET_HARDEN = r"D:\workspaces\dotnet-hardening\harden_net.py"


def run(cmd):
    print("  $ " + " ".join(cmd))
    return subprocess.run([sys.executable] + cmd).returncode


def is64_pe(path):
    """PE optional header Magic==0x20B → x64。"""
    try:
        with open(path, "rb") as f:
            d = f.read(0x400)
        pe = struct.unpack_from("<I", d, 0x3c)[0]
        return struct.unpack_from("<H", d, pe + 24)[0] == 0x20B
    except Exception:
        return True


def is_gui(path):
    """PE Subsystem==2 → GUI 子系统。"""
    try:
        with open(path, "rb") as f:
            d = f.read(0x400)
        pe = struct.unpack_from("<I", d, 0x3c)[0]
        magic = struct.unpack_from("<H", d, pe + 24)[0]
        sub = struct.unpack_from("<H", d, pe + 24 + (0x44 if magic == 0x10b else 0x44))[0]
        return sub == 2
    except Exception:
        return False


def _cap(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout
    except subprocess.TimeoutExpired:
        return "timeout", ""
    except Exception as e:
        return "err:" + type(e).__name__, ""


def verify(original, hardened, probe_args, gui_probe):
    """冒烟测试: 产物是否与原始行为一致。
    - GUI(或 --gui-probe): 启动产物, 3秒不崩(退出码非崩溃) = 过。
    - 控制台: 用【改同名的原始副本】做基线(抵消 MUI/路径), 对比 stdout+退出码。
    返回 (ok, detail)。"""
    gui = gui_probe or is_gui(hardened)
    if gui:
        try:
            p = subprocess.Popen([hardened] + probe_args)
        except Exception as e:
            return False, f"启动失败 {type(e).__name__}"
        time.sleep(3)
        alive = p.poll() is None
        rc = None
        if alive:
            p.terminate()
        else:
            rc = p.returncode
        # 崩溃码(高位0xC0000000/0xE0000000)= 崩; 正常退出也可能是启动即完成的合法程序
        crashed = rc is not None and (rc & 0xFFFFFFFF) >= 0xC0000000
        return (not crashed), ("GUI存活3s" if alive else f"启动即退出 exit={rc}{'(崩溃码)' if crashed else ''}")
    # 控制台: 公平基线
    tmpd = tempfile.mkdtemp()
    base = os.path.join(tmpd, os.path.basename(original))
    shutil.copy(original, base)
    orc, oout = _cap([base] + probe_args)
    hrc, hout = _cap([hardened] + probe_args)
    shutil.rmtree(tmpd, ignore_errors=True)
    ok = (orc == hrc and oout == hout)
    return ok, (f"行为一致(exit={hrc})" if ok else
                f"行为不一致 orig(exit={orc}) vs hard(exit={hrc}), 输出{'同' if oout==hout else '异'}")


def harden_once(line, inp, out, mode):
    """按 line+mode 执行一次加固; 返回 rc。mode: 'default'|'fallback'。"""
    if line == "dotnet-hardening":
        if mode == "fallback":   # 路径敏感/壳不兼容 → 只混淆不套壳(保留磁盘正常程序集)
            cmd = [NET_HARDEN, inp, "-o", out, "--no-shell", "--rename", "--strings"]
        else:
            cmd = [NET_HARDEN, inp, "-o", out, "--strings", "--rename"]
    elif line == "exe-hardening":
        # x86 原生目前只有 L1(L2/L3 桩是 x64 专用) → x86 直接用 l1; x64 默认 l1l2
        if mode == "fallback" or not is64_pe(inp):
            cmd = [EXE_HARDEN, inp, "-o", out, "--mode", "l1"]
        else:
            cmd = [EXE_HARDEN, inp, "-o", out, "--mode", "l1l2", "--anti-debug"]
    else:
        return 1
    return run(cmd)


def main():
    ap = argparse.ArgumentParser(description="加固套件统一入口 (识别+路由+自验证)")
    ap.add_argument("input")
    ap.add_argument("-o", "--output")
    ap.add_argument("--dry", action="store_true", help="只识别+推荐, 不加固")
    ap.add_argument("--no-verify", action="store_true", help="跳过加固后自验证(自担风险)")
    ap.add_argument("--probe", default="/?", help="控制台冒烟探针参数(默认 /?)")
    ap.add_argument("--gui-probe", action="store_true", help="目标是GUI: 冒烟=启动存活3秒不崩")
    a = ap.parse_args()

    what, line, reason = sniff(a.input)
    print(f"■ 目标: {a.input}")
    print(f"    识别: {what}")
    print(f"    路由: {line if line else '(不加固)'} — {reason}")

    if line is None:
        print("→ 不处理: 不支持或已加壳 (见上原因)。这是【优雅拒绝】, 非失败。")
        return 0
    if line == "app-hardening":
        print("→ APK 用 app-hardening: python D:\\workspaces\\app-hardening\\加固工具.py (GUI) 选 L1/L2/L3")
        return 0

    out = a.output or os.path.splitext(a.input)[0] + "_加固" + os.path.splitext(a.input)[1]
    probe_args = a.probe.split() if a.probe else []

    if a.dry:
        print("  (dry) 将执行默认加固 + 自验证; 见 harden_once() 的命令。")
        return 0

    # 1) 默认加固
    print("→ 加固(默认方案):")
    rc = harden_once(line, a.input, out, "default")
    if rc != 0 or not os.path.exists(out):
        print(f"✗ 加固失败 (rc={rc})"); return 1

    if a.no_verify:
        print(f"✓ 完成 -> {out}  (⚠️跳过了自验证)"); return 0

    # 2) 自验证
    print("→ 自验证(冒烟测试)...")
    ok, detail = verify(a.input, out, probe_args, a.gui_probe)
    if ok:
        print(f"✓ 完成并验证通过 -> {out}  [{detail}]"); return 0
    print(f"⚠ 默认方案自验证未过: {detail}")

    # 3) 自动回退到更兼容的模式
    print("→ 回退到更兼容模式重加固...")
    if harden_once(line, a.input, out, "fallback") == 0 and os.path.exists(out):
        ok2, detail2 = verify(a.input, out, probe_args, a.gui_probe)
        if ok2:
            print(f"✓ 回退方案验证通过 -> {out}  [{detail2}]")
            print("  (注: 用了更兼容的回退模式, 保护强度低于默认 —— 该 exe 与最强模式不兼容)")
            return 0
        print(f"⚠ 回退方案也未过: {detail2}")

    # 4) 拒绝出货(不产出坏 exe)
    try:
        if os.path.exists(out):
            os.remove(out)
    except OSError:
        pass
    print("✗ 【拒绝出货】: 此 exe 加固后验证未通过(会崩/行为变), 已删除坏产物。")
    print("  可能原因: 路径敏感/自校验/特殊运行时。手动排查请逐层试 (见各线文档)。")
    return 2


if __name__ == "__main__":
    sys.exit(main())
