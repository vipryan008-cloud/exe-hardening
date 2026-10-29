/* ==========================================================================
 * L3 部署 —— 机制验证 (进程内, 同 L2 的 mechanism-check 节奏)。
 *
 * 证明"把真实函数替换成 VM 执行"这一核心机制: 运行时把 secret() 的入口改写成
 * 一段 trampoline, 它调用 vm_run(secret 的字节码, a, b) —— secret 从此不再走
 * 原生 x86, 而由 VM 解释器执行字节码。验证结果与原生一致。
 *
 * secret_bc.h 由 gen_bc.py 从编译出的 secret() 翻译得到 (x86 → VM 字节码)。
 * 诚实: 这是机制证明(vm_run 正常链接在同进程)。单文件嵌入需 table-free 的 PIC
 * 解释器(手写 asm 派发/自相对跳转表) 或运行时 DLL —— 见 docs/05。
 * ========================================================================== */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "secret_bc.h"                 /* secret_bc[] : secret() 的 VM 字节码 */

extern int vm_run(const uint8_t *bc, int a, int b);

/* 被虚拟化的目标函数 (与 gen_bc 所用 secret.c 一致) */
#pragma optimize("", off)
__declspec(noinline) int secret(int a, int b) { return a * a + b * 3 - 7; }
#pragma optimize("", on)

static void wr(uint8_t **p, const void *src, int n) { memcpy(*p, src, n); *p += n; }

int main(void) {
    volatile int x = 5, y = 4;
    int expect = secret(x, y);         /* 原生真值 (patch 前) */

    uint8_t *s = (uint8_t *)secret;
    printf("secret 原始首字节: %02x %02x %02x %02x\n", s[0], s[1], s[2], s[3]);

    /* 1) 造 trampoline (RWX): 参数重排 + 调 vm_run(bytecode, a, b) */
    uint8_t *tr = (uint8_t *)VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    uint8_t *t = tr;
    uint64_t bc = (uint64_t)secret_bc, vr = (uint64_t)vm_run;
    wr(&t, "\x41\x89\xD0", 3);          /* mov r8d, edx   (b) */
    wr(&t, "\x89\xCA", 2);              /* mov edx, ecx   (a) */
    wr(&t, "\x48\xB9", 2); wr(&t, &bc, 8);   /* mov rcx, &bytecode */
    wr(&t, "\x48\xB8", 2); wr(&t, &vr, 8);   /* mov rax, &vm_run   */
    wr(&t, "\xFF\xE0", 2);              /* jmp rax  (尾调用, vm_run 返回给 secret 的调用者) */

    /* 2) 把 secret 入口改写成 "mov rax, tramp; jmp rax" (12B) —— 原生代码从此不执行 */
    DWORD old;
    VirtualProtect(s, 16, PAGE_EXECUTE_READWRITE, &old);
    uint8_t *q = s;
    uint64_t trv = (uint64_t)tr;
    wr(&q, "\x48\xB8", 2); wr(&q, &trv, 8);  /* mov rax, tramp */
    wr(&q, "\xFF\xE0", 2);                    /* jmp rax */
    VirtualProtect(s, 16, old, &old);
    FlushInstructionCache(GetCurrentProcess(), s, 16);
    printf("secret 改写后首字节: %02x %02x %02x %02x (48 b8=mov rax,imm)\n", s[0], s[1], s[2], s[3]);

    /* 3) 调 secret → 走 trampoline → vm_run(字节码) → 结果 */
    int got = secret(x, y);
    printf("secret(%d,%d) via VM = %d, 原生期望 = %d  => %s\n",
           x, y, got, expect, got == expect ? "PASS (函数由 VM 执行, 无原生 x86)" : "FAIL");
    return got == expect ? 0 : 1;
}
