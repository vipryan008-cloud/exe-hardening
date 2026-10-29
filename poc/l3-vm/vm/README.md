# L3 Gate1 算术 VM (翻译器 + 解释器 + 对拍)

```
vm.c          寄存器式 VM 解释器 (16 虚拟寄存器映射 x86 GPR; 算术子集)
x86_to_vm.py  x86 → VM 字节码翻译器 (capstone; 遇不支持指令抛异常)
gen_bc.py     编译 f.c → 反汇编 f() → 翻译 → 写 f_bc.h
vm_test.c     对拍: 原生 f() vs VM(字节码), 边界+2万伪随机
f.c           例子函数 f(a,b)=a*a+b*3-7
```

## 复现对拍
```bash
VC=tools/vcvars.bat          # 从 repo 根; 下面在 poc/l3-vm/vm/
cmd //c "$VC" cl //nologo //O2 //c f.c
python gen_bc.py f.obj       # 生成 f_bc.h + 打印 x86/字节码
cmd //c "$VC" cl //nologo //O2 vm_test.c vm.c //Fe:vm_test.exe
./vm_test.exe                # => PASS (VM==原生)
```

## 已验证 (每个 40000 用例 0 失配)
算术 `a*a+b*3-7` / 分支 `if(a>b)a-b:b-a` / 三元 `a>b?a:b`(cmov) / 循环 popcount / 有界 for 累加 / 位运算 `(a^b)+(a&b)*2-(a|b)`。

## 支持子集 / 边界
支持: mov/lea + add/sub/imul/and/or/xor(reg,reg|reg,imm) + inc/dec + neg/not + shl/shr/sar(立即或变量cl)
+ movzx/movsx(子寄存器扩展) + cmp/test + jmp/jcc(条件跳转) + cmov + ret。flags 用"存比较操作数"模型(见 vm.c 注释)。
不支持(→抛异常回落 L1/L2): **内存访问(load/store)/SIMD/call/`%`div/间接跳转**。见 `docs/05`。
(修过两 bug: sar 曾错映射成逻辑右移; and/or/xor 大立即数曾因有符号打包溢出。)
