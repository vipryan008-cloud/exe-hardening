# -*- coding: utf-8 -*-
"""商用覆盖矩阵 —— 一批多样真实 exe 走 harden_any.py(识别+加固+自验证+自动回退+拒绝出货坏exe)。
量"什么exe都能加固"的真实边界。★商用铁律: 【出货坏exe】必须=0(要么正确加固/回退, 要么优雅拒绝)。
用法: python coverage_test.py   (需系统自带这些 exe; 缺的自动跳过)
"""
import os, sys, subprocess, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ANY = os.path.join(HERE, "harden_any.py")
PY = sys.executable
TMP = tempfile.mkdtemp(prefix="covtest_")

# (路径, 冒烟探针参数, 是否GUI)
CORPUS = [
    (r"C:\Windows\System32\hostname.exe", "/?", False),
    (r"C:\Windows\System32\whoami.exe", "/?", False),
    (r"C:\Windows\System32\where.exe", "where", False),
    (r"C:\Windows\System32\ipconfig.exe", "/?", False),
    (r"C:\Windows\System32\tasklist.exe", "/?", False),
    (r"C:\Windows\System32\find.exe", "/?", False),
    (r"C:\Windows\SysWOW64\hostname.exe", "/?", False),   # x86 原生 → 优雅拒绝
    (r"C:\Windows\SysWOW64\whoami.exe", "/?", False),     # x86 原生 → 优雅拒绝
    (r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe", "/?", False),  # 路径敏感 → 自动回退
    (r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe", "/?", False),
    (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "/?", False),
    (os.path.join(HERE, "魔兽启动器.exe"), "", True),        # GUI 自解压 PS2EXE 包
]


def classify(rc, out):
    if "优雅拒绝" in out or "不处理" in out: return "◯ 优雅拒绝"
    if "回退方案验证通过" in out: return "⤵ 回退过(保护稍弱)"
    if "完成并验证通过" in out: return "✓ 验证过"
    if "拒绝出货" in out: return "⊘ 拒绝出货(已删坏产物)"
    if rc == 1: return "✗ 加固器报错"
    return f"? rc={rc}"


def main():
    print(f"{'文件':30} {'结果'}")
    print("-" * 70)
    tally, broken_shipped, tested = {}, 0, 0
    for path, probe, gui in CORPUS:
        name = os.path.basename(path)
        tag = "[x86]" if ("SysWOW64" in path or r"Framework\v" in path) else ""
        if not os.path.exists(path):
            print(f"{name+tag:30} SKIP(缺失)"); continue
        tested += 1
        out = os.path.join(TMP, "_ccov_" + name)
        cmd = [PY, ANY, path, "-o", out, "--probe", probe] + (["--gui-probe"] if gui else [])
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=180,
                               encoding="utf-8", errors="replace")
            res = classify(r.returncode, r.stdout + r.stderr)
        except Exception as e:
            res = f"✗ 异常 {type(e).__name__}"
        if os.path.exists(out) and res.startswith(("⊘", "✗", "◯")):
            broken_shipped += 1; res += " ⚠残留坏产物!"
        for junk in (out, os.path.join(TMP, "netvmrt.dll")):
            try: os.remove(junk)
            except OSError: pass
        print(f"{name+tag:30} {res}")
        tally[res.split()[0]] = tally.get(res.split()[0], 0) + 1
    print("-" * 70)
    print("汇总:", "  ".join(f"{k}×{v}" for k, v in tally.items()))
    print(f"★商用铁律【出货坏exe】= {broken_shipped}  (必须=0)")
    subprocess.run(["powershell", "-NoProfile", "-Command",
        "Get-Process app -EA SilentlyContinue|Stop-Process -Force -EA SilentlyContinue; "
        "Get-ChildItem $env:TEMP -Directory -Filter '._*' -EA SilentlyContinue|Remove-Item -Recurse -Force -EA SilentlyContinue"],
        capture_output=True)
    import shutil; shutil.rmtree(TMP, ignore_errors=True)
    sys.exit(0 if broken_shipped == 0 else 1)


if __name__ == "__main__":
    main()
