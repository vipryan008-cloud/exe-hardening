# L1 整体壳 (PE section 加密)

已真机验证的 L1 加固后端。原理与流程见 `docs/02-L1-整体壳.md`。

```
stub/
  stub.asm        解密 stub 源 (MASM x64, 64 字节, 纯 PIC 无 API)
  stub.bin        已汇编的 shellcode (加壳器读它, patch 占位常量)
  README.md       stub 构建 + 占位常量 + 反汇编核对
harden/
  pack.py         加壳器: 加密 .text + 追加 .vault stub + strip relocs + 改入口
  coff.py         从 ml64 .obj 抽 .text 字节 (生成 stub.bin 用)
```

## 快速验证
```bash
# 从 repo 根
python harden.py samples/sample.exe -o samples/out.exe
samples/out.exe        # 行为与原 exe 一致 (退出码 7)
# 证 .text 已密文: dumpbin /disasm:bytes /section:.text samples/out.exe  → 入口段全垃圾
```

## 直接调用加壳器
```bash
python poc/l1-whole-pe/harden/pack.py <in.exe> <out.exe> [seedhex]
```
