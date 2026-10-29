# L1 解密 stub 构建

`stub.asm`（MASM x64）→ `ml64` 汇编 → `coff.py` 抽 `.text` 字节 → `stub.bin`（64B）。
`stub.bin` 已提交；仅在**修改 stub.asm** 时才需重新生成：

```bash
# 从 repo 根:
VC="tools/vcvars.bat"
cd poc/l1-whole-pe/stub
cmd //c "$VC" ml64 //c //nologo //Fo stub.obj stub.asm
python ../harden/coff.py stub.obj > stub.bin   # 写回 64 字节 shellcode
```

## 占位常量（加壳器按唯一字节模式 patch）
| 名 | 占位 | 汇编指令 | 加壳期填入 |
|---|---|---|---|
| P_TEXTVA | `11..×8` | `mov rsi,imm64` | ImageBase + .text RVA |
| P_LEN    | `22..×8` | `mov rcx,imm64` | min(VirtualSize, RawSize) |
| P_SEED   | `33..×4` | `mov edx,imm32` | LCG 初始 state |
| P_OEPVA  | `44..×8` | `mov rax,imm64` | ImageBase + 原始 OEP |

反汇编核对（`stub.bin`）：`48be…`(mov rsi) `48b9…`(mov rcx) `ba…`(mov edx)
`69 d2 fd430300`(imul edx,edx,343FD) `81 c2 c39e2600`(add edx,269EC3)
`8b c2`(mov eax,edx) `c1 e8 10`(shr eax,16) `30 06`(xor [rsi],al)
`48 ffc6`(inc rsi) `48 ffc9`(dec rcx) `75 e5`(jnz) `48b8…`(mov rax) `ff e0`(jmp rax)。
