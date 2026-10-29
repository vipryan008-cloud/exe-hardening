# L3 部署 —— 机制验证

`l3_deploy_mech.c`：证明"真实函数替换成 VM 执行"的核心机制(进程内, 同 L2 mechanism-check)。
运行时把 `secret()` 入口改写成 `mov rax,tramp; jmp rax`，trampoline 调 `vm_run(secret的字节码,a,b)`
→ secret 不再走原生 x86, 由 VM 解释执行。

## 复现
```bash
VC=tools/vcvars.bat            # 从 repo 根; 下面在 poc/l3-vm/deploy/
cmd //c "$VC" cl //nologo //O2 //c secret.c
python ../vm/gen_bc.py secret.obj secret_bc      # → secret_bc.h
cmd //c "$VC" cl //nologo //O2 l3_deploy_mech.c ../vm/vm.c //Fe:l3dep.exe
./l3dep.exe        # secret 原始首字节 89 54..(真序言) → 改写 48 b8..(thunk); via VM=30==原生 PASS
```

## 诚实边界: 为何还不是单文件加壳
`vm_run`(C 编译)的 opcode 派发被 MSVC 编成 **image-relative 跳转表**(引用 `__ImageBase` + `$LN` 标签,
IMAGE_REL_AMD64_ADDR32NB)。跳转表绑定模块布局, 把 `.text` 抽出放到别处即失效 →
**C 解释器无法直接当 PIC blob 嵌入**(试过 switch/if-else/`#pragma optimize off` 都挡不住 MSVC 建表)。

## ✅ 运行时 DLL 部署已跑通 (双文件: 加壳exe + l3rt.dll)
`harden_l3.py` + `rt/l3stub.asm` + `rt/l3rt.dll`:
- `l3rt.dll`: 导出 `vm_run` (跳转表在它自己正常加载的模块里没问题)。
- `l3stub.asm`(PIC): 加壳 exe 新入口, 自解析 LoadLibrary("l3rt.dll")+GetProcAddress("vm_run")→存 g_vmrun 槽 → jmp 原 OEP。
- `harden_l3.py`: 翻译函数→字节码, 加 `.l3` 段(RWX)[stub][thunks][字节码], 函数入口改写成
  `mov rax,thunk;jmp rax`; thunk 经 `[g_vmrun]` 调 `vm_run(字节码,a,b)`。固定基址(strip relocs)。
- **真机验证**: `secret()` 虚拟化后, 加壳 exe 多输入(A/B/C/z/0) VM 结果==原生 全 ✓;
  secret 磁盘首字节 `48 b8`(thunk, 无原生 x86)。装机需 l3rt.dll 与 exe 同目录。

### 复现
```bash
VC=tools/vcvars.bat            # 从 repo 根; 下面在 poc/l3-vm/deploy/
cmd //c "$VC" cl //nologo //O2 l3target.c //Fe:l3target.exe //link //MAP:l3target.map
# 从 map 取 secret 的 RVA (VA-0x140000000)
python harden_l3.py l3target.exe l3t.exe <secret_rva_hex>
cp rt/l3rt.dll .; ./l3t.exe A       # => secret 由 VM 执行, 结果与原生一致
```
构建 l3rt.dll / l3stub.bin 见 `rt/`(l3rt: cl /LD vm.c /link /EXPORT:vm_run; l3stub: ml64→link DLL→抽.text)。

## 剩余: 真单文件 (未做)
把 vm_run 也嵌进 exe 免 DLL, 需绕过 MSVC 的 image-relative 跳转表:
1. **手写 asm 解释器** + 自相对跳转表 → 真 PIC(VMProtect 做法)。
2. vm_run 的 `.text`+`.rdata`+重定位并入目标 PE 的 `.reloc`, 交 OS loader 重定位。
