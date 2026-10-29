#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""加固套件 图形界面 —— 丢文件 → 自动识别 → 选加固线对应选项 → 一键加固。

覆盖三条线: app-hardening(APK) / exe-hardening(原生PE x64) / dotnet-hardening(.NET)。
依赖: Python3 + tkinter(自带) + pefile。各线的加固工具在各自工程目录。
运行: python harden_gui.py  (或双击 启动加固GUI.bat)
"""
import json
import os
import subprocess
import sys
import threading

# 自愈: (1) 某些 Python 安装 tcl 库在 /tcl 而非 /lib; (2) 环境里可能残留别的
# 打包程序(PyInstaller _MEI)污染的 TCL_LIBRARY 指向已删目录 → 强制覆盖成真实 init.tcl。
def _fix_tcl():
    cur = os.environ.get("TCL_LIBRARY")
    if cur and os.path.isfile(os.path.join(cur, "init.tcl")):
        return  # 现有的有效, 不动
    roots = [os.path.dirname(os.path.abspath(sys.executable)),
             sys.prefix, getattr(sys, "base_prefix", sys.prefix)]
    for r in roots:
        for sub in ("tcl", "lib", "library", ""):
            base = os.path.join(r, sub) if sub else r
            for ver in ("tcl8.6", "tcl8.7", "tcl9.0"):
                tcl = os.path.join(base, ver)
                if os.path.isfile(os.path.join(tcl, "init.tcl")):
                    os.environ["TCL_LIBRARY"] = tcl  # 强制覆盖污染值
                    tk = os.path.join(base, ver.replace("tcl", "tk"))
                    if os.path.isdir(tk):
                        os.environ["TK_LIBRARY"] = tk
                    return
_fix_tcl()

import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from identify import sniff  # noqa: E402

EXE_HARDEN = os.path.join(HERE, "harden.py")
NET_HARDEN = r"D:\workspaces\dotnet-hardening\harden_net.py"
APK_GUI = r"D:\workspaces\app-hardening\加固工具.py"
CFG = os.path.join(HERE, ".harden_gui.cfg")


def overlay_size(path):
    """PE 尾部 overlay 字节数。>256KB 多为自解压单文件包(PS2EXE/内嵌依赖),
    这类不能套 L1 整体壳(壳会破坏自解压引导)。0/读取失败返回 0。"""
    try:
        import pefile
        pe = pefile.PE(path, fast_load=True)
        end = max(s.PointerToRawData + s.SizeOfRawData for s in pe.sections)
        pe.close()
        return max(0, os.path.getsize(path) - end)
    except Exception:
        return 0

BG = "#1e1e2e"; FG = "#cdd6f4"; ACC = "#89b4fa"; OK = "#a6e3a1"; WARN = "#f9e2af"; ERR = "#f38ba8"
PANEL = "#313244"; BTN = "#45475a"


class App:
    def __init__(self, root):
        self.root = root
        root.title("加固套件 · 三线一体 (APK / 原生PE / .NET)")
        root.geometry("820x640")
        root.configure(bg=BG)
        self.line = None
        self.vars = {}
        self._busy = False
        self._build()
        self._load_cfg()

    # ---------- UI ----------
    def _build(self):
        top = tk.Frame(self.root, bg=BG); top.pack(fill=tk.X, padx=14, pady=(12, 6))
        tk.Label(top, text="加固套件", font=("Microsoft YaHei", 16, "bold"),
                 bg=BG, fg=ACC).pack(side=tk.LEFT)
        tk.Label(top, text="  给合法授权软件做防逆向/防篡改 · 丢文件自动识别路由",
                 font=("Microsoft YaHei", 9), bg=BG, fg="#9399b2").pack(side=tk.LEFT, pady=(6, 0))

        # 文件选择
        f = tk.Frame(self.root, bg=BG); f.pack(fill=tk.X, padx=14, pady=6)
        tk.Label(f, text="待加固文件", width=10, bg=BG, fg=FG,
                 font=("Microsoft YaHei", 10)).pack(side=tk.LEFT)
        self.path_var = tk.StringVar()
        tk.Entry(f, textvariable=self.path_var, bg=PANEL, fg=FG, insertbackground=FG,
                 relief=tk.FLAT, font=("Consolas", 10)).pack(side=tk.LEFT, fill=tk.X,
                 expand=True, padx=6, ipady=4)
        self._btn(f, "选择…", self.pick).pack(side=tk.LEFT)

        # 识别结果
        idf = tk.Frame(self.root, bg=PANEL); idf.pack(fill=tk.X, padx=14, pady=6)
        self.id_label = tk.Label(idf, text="  （选个文件, 我来识别它是什么 + 该用哪条加固线）",
                                 bg=PANEL, fg="#9399b2", font=("Microsoft YaHei", 10),
                                 justify=tk.LEFT, anchor="w")
        self.id_label.pack(fill=tk.X, padx=10, pady=8)

        # 选项区(按线动态)
        self.opt_wrap = tk.LabelFrame(self.root, text=" 加固选项 ", bg=BG, fg=ACC,
                                      font=("Microsoft YaHei", 10, "bold"))
        self.opt_wrap.pack(fill=tk.X, padx=14, pady=6)
        self.opt_frame = tk.Frame(self.opt_wrap, bg=BG)
        self.opt_frame.pack(fill=tk.X, padx=8, pady=8)
        tk.Label(self.opt_frame, text="（先选文件）", bg=BG, fg="#9399b2").pack(anchor="w")

        # 输出 + 加固按钮
        o = tk.Frame(self.root, bg=BG); o.pack(fill=tk.X, padx=14, pady=6)
        tk.Label(o, text="输出到", width=10, bg=BG, fg=FG,
                 font=("Microsoft YaHei", 10)).pack(side=tk.LEFT)
        self.out_var = tk.StringVar()
        tk.Entry(o, textvariable=self.out_var, bg=PANEL, fg=FG, insertbackground=FG,
                 relief=tk.FLAT, font=("Consolas", 10)).pack(side=tk.LEFT, fill=tk.X,
                 expand=True, padx=6, ipady=4)
        self.go_btn = self._btn(o, "★ 一键加固", self.harden, big=True)
        self.go_btn.pack(side=tk.LEFT)

        # 日志
        self.log = scrolledtext.ScrolledText(self.root, bg="#11111b", fg=FG, height=12,
                                             relief=tk.FLAT, font=("Consolas", 9),
                                             insertbackground=FG)
        self.log.pack(fill=tk.BOTH, expand=True, padx=14, pady=(6, 12))
        for tag, col in [("ok", OK), ("warn", WARN), ("err", ERR), ("acc", ACC)]:
            self.log.tag_config(tag, foreground=col)
        self._log("加固套件 GUI 就绪。红线: 只加固自有或客户书面授权的合法软件。\n", "acc")

    def _btn(self, parent, text, cmd, big=False):
        b = tk.Button(parent, text=text, command=cmd, bg=ACC if big else BTN,
                      fg="#1e1e2e" if big else FG, relief=tk.FLAT, activebackground=OK,
                      font=("Microsoft YaHei", 10, "bold" if big else "normal"),
                      padx=14 if big else 10, pady=4, cursor="hand2")
        return b

    def _log(self, msg, tag=None):
        self.log.insert(tk.END, msg, tag or "")
        self.log.see(tk.END)
        self.root.update_idletasks()

    # ---------- 逻辑 ----------
    def pick(self):
        p = filedialog.askopenfilename(
            title="选择待加固文件",
            filetypes=[("可加固", "*.exe *.dll *.apk"), ("所有", "*.*")])
        if not p:
            return
        self.path_var.set(p)
        base, ext = os.path.splitext(p)
        self.out_var.set(base + "_加固" + ext)
        self.identify(p)

    def identify(self, p):
        try:
            what, line, reason = sniff(p)
        except Exception as e:
            what, line, reason = "识别失败", None, str(e)
        self.line = line
        # 自解压单文件包检测(大 overlay): 这类 .NET 程序不能套 L1 整体壳
        self.is_bundle = line == "dotnet-hardening" and overlay_size(p) > 256 * 1024
        color = OK if line else ERR
        extra = ""
        if self.is_bundle:
            extra = (f"\n  ⚠ 检测到 {overlay_size(p)//1024}KB overlay → 自解压单文件包(PS2EXE/内嵌依赖);"
                     f"\n     已自动改用 dropper 壳(全文件AES加密藏PS源码+运行时解密落临时exe, 自解压照常跑)")
            color = WARN
        self.id_label.config(
            text=f"  ■ {what}\n  ■ 用哪条: {line or '(不加固)'}  —  {reason}{extra}", fg=color)
        self.build_options(line)

    def build_options(self, line):
        for w in self.opt_frame.winfo_children():
            w.destroy()
        self.vars = {}

        def chk(text, key, default):
            v = tk.BooleanVar(value=default)
            self.vars[key] = v
            tk.Checkbutton(self.opt_frame, text=text, variable=v, bg=BG, fg=FG,
                           selectcolor=PANEL, activebackground=BG, activeforeground=ACC,
                           font=("Microsoft YaHei", 9)).pack(anchor="w")

        if line == "dotnet-hardening":
            tk.Label(self.opt_frame, text=".NET 混淆/加固层 (推荐全开):", bg=BG,
                     fg=ACC, font=("Microsoft YaHei", 9, "bold")).pack(anchor="w")
            chk("IL 虚拟化 (纯int方法→VM字节码; 产物旁带 netvmrt.dll)", "ilvm", True)
            chk("符号重命名 (类/方法/字段名→乱名) ⚠️反射风险,加固后交互测", "rename", True)
            chk("控制流混淆 (方法体扁平化成状态机)", "cfo", True)
            chk("常量加密 (数值字面量→密文)", "const", True)
            chk("字符串加密 (ldstr→密文, 运行时解密)", "strings", True)
            if getattr(self, "is_bundle", False):
                chk("dropper 壳 (全文件AES加密→藏PS源码/资源/overlay; 自解压包专用)", "dropper", True)
            else:
                chk("L1 整体壳 (Assembly.Load AES 加密整个程序集)", "shell", True)
            chk("反调试/看门狗/反篡改 (运行时对抗; 随壳)", "antidbg", True)
            chk("兼容模式 --loadfrom (依赖Location的程序集; 削弱anti-dump)", "loadfrom", False)
        elif line == "exe-hardening":
            tk.Label(self.opt_frame, text="原生 PE 加固模式:", bg=BG, fg=ACC,
                     font=("Microsoft YaHei", 9, "bold")).pack(anchor="w")
            self.mode = tk.StringVar(value="l1l2")
            for txt, val in [("L1 整体壳 (.text加密, 抗静态)", "l1"),
                             ("L2 抽取壳 (函数int3抽取+惰性回填, 抗dump)", "l2"),
                             ("L1×L2 组合双层 (推荐)", "l1l2")]:
                tk.Radiobutton(self.opt_frame, text=txt, variable=self.mode, value=val,
                               bg=BG, fg=FG, selectcolor=PANEL, activebackground=BG,
                               activeforeground=ACC, font=("Microsoft YaHei", 9)).pack(anchor="w")
            chk("反调试 (调试器下自杀)", "antidbg", True)
            chk("用完即擦 call-gate (⚠️选择性,勿全CRT; 见文档)", "callgate", False)
        elif line == "app-hardening":
            tk.Label(self.opt_frame,
                     text="APK 加固请用 app-hardening 的专用工具:\n"
                          "  python D:\\workspaces\\app-hardening\\加固工具.py  (它有自己的 L1/L2/L3 GUI)",
                     bg=BG, fg=WARN, justify=tk.LEFT,
                     font=("Microsoft YaHei", 9)).pack(anchor="w")
            self._btn(self.opt_frame, "打开 APK 加固工具", self.open_apk_gui).pack(anchor="w", pady=4)
        else:
            tk.Label(self.opt_frame, text="此文件不加固 (见上方识别说明: 不支持/已加壳)。",
                     bg=BG, fg=ERR, font=("Microsoft YaHei", 9)).pack(anchor="w")

    def open_apk_gui(self):
        if os.path.exists(APK_GUI):
            subprocess.Popen([sys.executable, APK_GUI])
        else:
            messagebox.showwarning("未找到", APK_GUI)

    def build_cmd(self):
        src, out = self.path_var.get(), self.out_var.get()
        if self.line == "dotnet-hardening":
            cmd = [sys.executable, NET_HARDEN, src, "-o", out]
            for k, fl in [("ilvm", "--ilvm"), ("rename", "--rename"), ("cfo", "--cfo"),
                          ("const", "--const"), ("strings", "--strings"),
                          ("loadfrom", "--loadfrom")]:
                if self.vars.get(k) and self.vars[k].get():
                    cmd.append(fl)
            if getattr(self, "is_bundle", False):
                # 自解压包: dropper 壳(勾)加密全文件藏源码; 不勾则仅IL混淆(源码仍明文)
                cmd.append("--dropper" if (self.vars.get("dropper") and self.vars["dropper"].get())
                           else "--no-shell")
            elif not (self.vars.get("shell") and self.vars["shell"].get()):
                cmd.append("--no-shell")   # 普通exe 关 L1 整体壳
            if not (self.vars.get("antidbg") and self.vars["antidbg"].get()):
                cmd.append("--no-anti-debug")
            return cmd
        if self.line == "exe-hardening":
            cmd = [sys.executable, EXE_HARDEN, src, "-o", out, "--mode", self.mode.get()]
            if self.vars.get("antidbg") and self.vars["antidbg"].get():
                cmd.append("--anti-debug")
            if self.vars.get("callgate") and self.vars["callgate"].get():
                cmd.append("--call-gate")
            return cmd
        return None

    def harden(self):
        if self._busy:
            return
        src = self.path_var.get()
        if not src or not os.path.exists(src):
            messagebox.showwarning("提示", "先选一个存在的文件")
            return
        cmd = self.build_cmd()
        if cmd is None:
            messagebox.showinfo("提示", "此文件不走自动加固 (见识别说明)。")
            return
        self._busy = True
        self.go_btn.config(state=tk.DISABLED, text="加固中…")
        self._log("\n$ " + " ".join(cmd[1:]) + "\n", "acc")
        threading.Thread(target=self._run, args=(cmd,), daemon=True).start()

    def _run(self, cmd):
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 text=True, encoding="utf-8", errors="replace")
            for line in p.stdout:
                self.root.after(0, self._log, line)
            rc = p.wait()
        except Exception as e:
            rc, _ = 1, self.root.after(0, self._log, f"[异常] {e}\n", "err")
        self.root.after(0, self._done, rc)

    def _done(self, rc):
        self._busy = False
        self.go_btn.config(state=tk.NORMAL, text="★ 一键加固")
        out = self.out_var.get()
        if rc == 0 and os.path.exists(out):
            self._log(f"✓ 完成 → {out}\n", "ok")
            self._log("  提醒: 加固后建议用客户证书重签 (signtool / keystore)。\n", "warn")
            self._save_cfg()
        else:
            self._log(f"✗ 加固失败 (rc={rc})\n", "err")

    def _load_cfg(self):
        try:
            d = json.load(open(CFG, encoding="utf-8"))
            if d.get("last"):
                os.chdir(os.path.dirname(d["last"]))
        except Exception:
            pass

    def _save_cfg(self):
        try:
            json.dump({"last": self.path_var.get()}, open(CFG, "w", encoding="utf-8"))
        except Exception:
            pass


if __name__ == "__main__":
    root = tk.Tk()
    App(root)
    root.mainloop()
