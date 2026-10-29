# EXE 加固产品（Windows PE 保护 / 类 VMProtect · Themida · Enigma）

给**合法授权的 Windows 软件**做 IP 保护 / 防逆向 / 防篡改的加固产品。
与 `../app-hardening`（Android APK 加固）同源思路，目标平台换成 Windows PE(x64)。

> ⚠️ 红线：只加固自有或客户书面授权的合法软件。给恶意软件加壳逃避查杀 = 帮凶，不做。
> 参考正规竞品：VMProtect、Themida/WinLicense、Enigma Protector、ASProtect、Obsidium、VProtect。

---

## 四层加固能力（对标 app-hardening 的 L1/L2/L3/运行时）

| 层 | 做什么 | 挡谁 | 状态 |
|---|---|---|---|
| **L1 整体壳** | 原 `.text` 段 LCG 密钥流加密，运行期 stub 就地解密后跳原 OEP | 静态反汇编（IDA/Ghidra 看到密文） | ✅ **真机验证**（默认保留 ASLR：stub 从 PEB 取真基址；有 reloc 才回退固定基址） |
| **L2 抽取壳** | 逐函数抽走机器码换 int3 桩，惰性回填（首次调用触发 VEH 回填）；可选**用完即擦**(返回即重抽) | 静态磁盘分析 / 被动内存 dump（用完即擦抗主动） | ✅ **真机验证（单文件, 402 函数, 磁盘 93.4% 桩, ASLR 保留；用完即擦选择性已部署）** |
| **L3 代码虚拟化** | 关键函数 x86 → 自定义 VM 字节码，无原生机器码 | 反汇编 + 动态跟踪 | 🌱 **算术+控制流 VM + 运行时DLL部署真机跑通**；诚实覆盖: 现只能虚拟化**纯寄存器函数**(真实exe仅~1%,需按需编写)；通用需 Gate2内存+栈帧(大arc) |
| **运行时对抗** | native 反调试(PEB/NtGlobalFlag/硬件断点/timing) + 反VM(CPUID) + 反dump，命中即处置 | 调试器 / 沙箱 / 内存 dump | ✅ **真机验证 + 已部署进加壳exe**（`--anti-debug`，调试器下 ExitProcess(42)） |

签名：Windows 用 Authenticode。加固后需用客户证书重签（`signtool`），否则失去签名/被 SmartScreen 拦。

**真实 exe 兼容性**（实测 System32：99% 带 CFG、17% 带 TLS）：加壳器**自动剥离 CFG**（否则加壳后
`__fastfail 0xC0000409` 崩）；有 **TLS 回调**的 exe 会**检测并警告**（TLS 回调在解密 stub 前运行，完整支持未做）。

---

## 一键使用（CLI）

```
python harden.py <目标.exe> -o <输出.exe>              # L1 整体壳(.text加密, 抗静态)
python harden.py <目标.exe> -o <输出.exe> --mode l2    # L2 抽取壳(函数int3抽取+惰性回填, 抗dump)
python harden.py <目标.exe> -o <输出.exe> --mode l1l2  # L1×L2 组合双层(单文件, 抗静态×抗dump)
python harden.py <目标.exe> -o <输出.exe> --mode l1l2 --anti-debug  # 组合双层 + 反调试(命中即退)
python harden.py <目标.exe> -o <输出.exe> --mode l1l2 --anti-debug --call-gate --limit 50  # 全料(用完即擦:选择性)
python harden.py <目标.exe> --list-funcs                        # 列出函数 RVA (挑选保护对象)
python harden.py <目标.exe> -o <输出.exe> --mode l1l2 --call-gate --funcs 0x1420,0x14a0  # 精确保护指定敏感函数
python harden.py <目标.exe> -o <输出.exe> --mode l2 --limit 50   # 只保护前50个函数
```

需要：Python 3 + `pip install pefile` + MSVC BuildTools 2022（stub 已预编译进 repo，
仅改 stub 时才需重装编译；`.sdk/`/`tools/vcvars.bat` 记录工具链入口）。

---

## 目录

```
harden.py / 启动加固.bat        一键 CLI（L1）
docs/    01技术路线 02 L1整体壳 03 L2抽取壳 04抗dump与运行时 05 L3代码虚拟化
research/ 脱壳/去壳工具与对抗点（要防的对象）
poc/
  l1-whole-pe/   stub(MASM解密stub) + harden(pack.py 加壳器 + coff.py)
  l2-extract/    L2 抽取壳: harden_l2.py(加壳器) + rt/(自解析shellcode+PIC VEH runtime) + 机制验证
  l3-vm/         L3 x86→VM 字节码翻译器（seed）
  runtime-anti/  反调试/反VM/反dump 模块 + 自检 demo + 自写调试器验证器
tools/   vcvars.bat（MSVC 环境入口）
samples/ 验证靶子 sample.c + 加壳产物
```

## 已验证结论（真机 · 本机 Win10 x64 + MSVC 14.44）

- **L1**：`sample.exe` 加壳后行为逐字节一致（输出/退出码 7 都对）；磁盘 `.text` 熵
  6.50→8.00（=随机=密文），dumpbin 反汇编入口段全是垃圾。
- **L1 ASLR 模式**：auto 加壳的 ASLR exe 加载到随机高址 `0x7FF6…`（ASLR 存活）且 `.text` 熵 8.00；
  strip 对照固定在首选基址 `0x1400…`。依据：实测 5 个真实 x64 exe 的 `.text` reloc 全为 0。
- **L2 单文件抽取壳**：保护全部 402 函数，磁盘 `.text` 93.4% 是 int3（原 2.1%）；程序行为一致（exit 7）；
  ASLR 保留（载到 `0x7FF6…`）。自解析 API shellcode 用真 `GetProcAddress` oracle 对拍全 MATCH。
- **L1×L2 组合（单文件双层）**：`.text` 磁盘熵 8.00（密文,抗静态）+ 离线解密后 94% 是 int3（L2 桩藏在 L1
  加密之下,抗dump）；行为一致（exit 7）；ASLR 保留。运行链：L1 解密 → 现 int3 桩 → L2 VEH 装载 → 调用时回填。
- **★ 真实第三方程序端到端验证**（收官, 对标 APK 在真生产 App 验证）：
  - `hostname.exe`/`where.exe`（真 System32 工具, 带 CFG）：L1 & L2 加固后输出 == 原始 ✓。
  - `python.exe`（真解释器 105KB）：L1×L2+反调试加固后跑脚本(sum→5050)/--version 均 == 原始；
    `.text` 熵 6.05→7.95（密文）；调试器下 ExitProcess(42)。行为完全保留 + 保护生效 + 反调试命中。
- **运行时**：正常运行反调试全 0；用自写调试器（`DEBUG_ONLY_THIS_PROCESS`）拉起后
  PEB.BeingDebugged / NtGlobalFlag / IsDebuggerPresent 全部翻 1，进程按处置退出（码 1）。

## 诚实边界

- **L1 取舍**：为让 stub 里 baked 的绝对 VA 成立，加壳器 strip 了 relocations →
  主模块失去 ASLR；且不处理 `.text` 里的 TLS 回调、不支持 CFG(/guard:cf) 目标。
  这些是 L1 层已知取舍，属"挡静态"性价比方案；抗内存 dump 靠 L2，抗反汇编靠 L3。
- **L2/L3 现状**：设计 + 种子，非成品。x86 全指令→VM 是团队级多月工程（同 APK 的 L3 DEX2C）。
- **定位**：L1 + 运行时对抗已挡住绝大多数脚本小子与普通逆向；对抗职业逆向需把 L2/L3 做完整。

## 构建提醒

重 native 构建吃内存；MSVC 环境统一走 `tools/vcvars.bat`。keystone 离线装不上，
stub 改用 MASM `ml64` 汇编（`poc/l1-whole-pe/stub/build 说明见该目录`）。
