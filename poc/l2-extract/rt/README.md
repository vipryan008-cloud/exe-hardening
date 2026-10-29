# L2 运行时 (自解析 shellcode + 可嵌入 PIC VEH 引擎)

```
resolve.asm    自解析 API: get_kernel32_base(PEB走模块表ror13哈希) + get_proc(解析导出表)
test_resolve.c 用真 GetProcAddress oracle 对拍 resolve (base+GPA+LoadLibraryA 全 MATCH)
l2rt.asm       可嵌入 L2 引擎: l2_install(table,base) 自解析+装VEH + l2_handler(回填)
test_l2rt.c    进程内验证 l2rt: 多函数抽取(int3)+自解析+VEH回填
restub_tramp.asm 用完即擦返回蹦床 + test_restub.c 机制验证(嵌套+递归, 返回即擦回int3)
l2deploy.asm   单文件部署 blob: 入口stub(反调试+L1解密) + l2_install + handler + resolve, 全 _TEXT/PIC
l2deploy.bin   已链接抽取的 blob (harden_l2.py 读它); 改 asm 才需重生成
l2deploy.dll   链接中间产物 (抽 .text 用)
```

## 重新生成 l2deploy.bin（改了 asm 才需要）
```bash
VC=tools/vcvars.bat            # 从 repo 根, 下面在 poc/l2-extract/rt/
cmd //c "$VC" ml64 //c //nologo //Fo l2deploy.obj l2deploy.asm
# 关键: 必须链接! .obj 里 16 个 REL32 重定位(lea/引用数据符号)未解析, 裸抽必崩。
cmd //c "$VC" link //DLL //NOENTRY //NODEFAULTLIB //FIXED //BASE:0x180000000 l2deploy.obj //OUT:l2deploy.dll
# 从链接后的 DLL 抽 .text (位移已解析), 截到 g_tbl(侧表落点):
python - <<'PY'
import pefile
def al(v,a): return (v+a-1)&~(a-1)
pe=pefile.PE("l2deploy.dll"); t=next(s for s in pe.sections if s.Name.rstrip(b"\0")==b".text")
b=t.get_data()[:t.Misc_VirtualSize]; p=b.find(b"ExitProcess\x00")   # 最后一个字符串
open("l2deploy.bin","wb").write(b[:al(p+12,8)])
PY
```

## blob 布局（harden_l2.py 依赖）
- 入口 `l2_entry` @ offset 0（packer 设为新入口）。占位(唯一, packer patch):
  `P_TEXTRVA`=0x11*8, `P_LEN`=0x22*8(0=不解密=纯L2), `P_SEED`=0x33*4, `P_OEPRVA`=0x44*8,
  `P_ANTIDBG`=0x55*4(1=开反调试)。
- 入口流程: 取PEB基址 → [反调试:BeingDebugged|NtGlobalFlag命中则 ExitProcess(42)] →
  [L1解密.text if P_LEN] → l2_install(装VEH) → jmp 原OEP。
- `g_tbl` @ blob 末尾（= len）→ packer 从此追加侧表 `[count][entries(rva,len,stash_off)][stash]`。
- 段标记 RWX（blob 内有可写 slot: g_table/g_base/p_VP/p_Flush）。

## 验证命令
```bash
cmd //c "$VC" cl //nologo //O2 test_resolve.c resolve.obj //Fe:test_resolve.exe && ./test_resolve.exe
cmd //c "$VC" cl //nologo //O2 test_l2rt.c l2rt.obj resolve.obj //Fe:test_l2rt.exe && ./test_l2rt.exe
```
